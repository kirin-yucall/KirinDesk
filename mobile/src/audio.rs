//! jitter 排序 → JNI 回调（Kotlin `AudioTrack` 低延迟播放）。
//!
//! # 复用边界（不复制逻辑）
//!
//! - 解码：`media::decoder::audio::OpusDecoder`（FFmpeg avcodec，与桌面同栈；
//!   本仓 P1-B-0 重构建的 `libavcodec.so` 已含 `opus` 内置解码器——LGPL，
//!   无 libopus 外部依赖）；
//! - 抗抖动：`media::decoder::audio::AudioJitterBuffer`（深度 3 帧 = 60ms，
//!   乱序排序/缺帧静音补帧/迟到丢弃，与桌面 WASAPI 播放路径同款）；
//! - 播放：Android 无 WASAPI/PipeWire——播放端即 JNI 回调
//!   （[`AudioSink`]→`onAudio([FII)V`），Kotlin 侧 AudioTrack
//!   `PERFORMANCE_MODE_LOW_LATENCY` 写 float32 PCM。
//!
//! # 接线（orchestration.rs 最小钩子）
//!
//! `run_session` 接收循环 Audio tag → [`AudioSession::forward`]（本模块持有
//! 解码线程与 sink 注册表；orchestration 仅 1 字段 + 1 spawn + 4 行 tag
//! AudioTrack pause/volume 实现，Rust 侧不改码流消费——关闭时仍解码但
//! 丢弃投递（保持时间轴，重开即续）。
//!
//! # 故障隔离
//!
//! 解码器创建失败（FFmpeg 缺 opus 等）→ [`AudioSession::spawn`] 返回禁用
//! 实例（`forward` no-op），视频/键鼠不受影响（音频独立线程原则，与桌面
//! `AudioDecodePipeline` 一致）。

use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use kirin_desk_media::decoder::audio::{
    AudioJitterBuffer, AudioPcm, OpusDecoder, CHANNELS, SAMPLE_RATE,
};
use kirin_desk_media::decoder::AudioPacket;

/// jitter 深度（帧）：3 帧 = 60ms 抗抖动（对齐桌面 `AudioDecodePipeline::new`
/// 的深度 3；P1-B 移动端同口径，见 pin 测试）。
pub const AUDIO_JITTER_DEPTH_FRAMES: usize = 3;

/// PCM 回调抽象（音频解码线程调用——实现方须尽快返回，播放缓冲由 Kotlin
/// AudioTrack 内部队列承担）。JNI 实现 = GlobalRef + `onAudio([FII)V`；
/// 宿主机测试实现 = 采集器。
pub trait AudioSink: Send + Sync {
    /// `pcm` = interleaved stereo float32（48kHz，20ms/帧 = 1920 样本）。
    fn on_audio(&self, pcm: &[f32], sample_rate: u32, channels: u16);
}

/// 会话音频子系统（解码线程 + sink 注册表；orchestration `SessionHandle`
/// 持有一个实例，接收循环 Clone 一份投递——`mpsc::Sender` 克隆指向同一线程）。
///
/// `tx = None` = 解码器不可用（禁用态：`forward` no-op，`set_sink` 仍可
/// 调用但不会有投递）——音频禁用不影响视频/键鼠。
#[derive(Clone)]
pub struct AudioSession {
    tx: Option<mpsc::Sender<AudioPacket>>,
    sink: Arc<Mutex<Option<Arc<dyn AudioSink>>>>,
}

impl AudioSession {
    /// 启动音频解码线程（解码器创建失败 → 禁用态实例，不报错不阻断连接）。
    pub fn spawn() -> Self {
        let sink: Arc<Mutex<Option<Arc<dyn AudioSink>>>> = Arc::new(Mutex::new(None));
        Self {
            tx: spawn_audio_thread(sink.clone()),
            sink,
        }
    }

    /// 接收循环投递口（`ChannelTag::Audio`：PTS 来自帧头 + Opus 载荷）。
    /// 解码线程已退出（会话结束）→ no-op（`send` 失败静默）。
    pub fn forward(&self, pts: u64, data: Vec<u8>) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(AudioPacket { pts, data });
        }
    }

    /// 注册 PCM 回调（连接前后皆可，对既有会话即时生效；None = 解除）。
    pub fn set_sink(&self, sink: Option<Arc<dyn AudioSink>>) {
        *self.sink.lock().unwrap() = sink;
    }
}

/// 解码线程主体：recv → OpusDecoder → jitter → sink（未注册时帧丢弃，
/// 与视频帧口径一致）。发送端（接收循环）关闭 → 线程退出。
fn spawn_audio_thread(
    sink: Arc<Mutex<Option<Arc<dyn AudioSink>>>>,
) -> Option<mpsc::Sender<AudioPacket>> {
    // FFmpeg 解码器创建在音频线程外做（失败 → None，调用方落禁用态）。
    let mut decoder = match OpusDecoder::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("mobile: audio disabled (opus decoder init failed: {e})");
            return None;
        }
    };
    let (tx, rx) = mpsc::channel::<AudioPacket>();
    std::thread::Builder::new()
        .name("kirin-mobile-audio".into())
        .spawn(move || {
            let mut jitter = AudioJitterBuffer::new(AUDIO_JITTER_DEPTH_FRAMES);
            while let Ok(pkt) = rx.recv() {
                match decoder.decode(&pkt) {
                    // 损坏包 → 空输出（跳过，时间轴由 jitter 静音补帧）。
                    Ok(pcm) if !pcm.is_empty() => {
                        jitter.push(AudioPcm { pts: pkt.pts, samples: pcm });
                        // 投递全部就绪帧；sink 未注册 → 帧丢弃（不缓冲）。
                        while let Some(out) = jitter.pop() {
                            if let Some(sink) = sink.lock().unwrap().as_ref() {
                                sink.on_audio(&out.samples, SAMPLE_RATE, CHANNELS);
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("mobile: audio decode error: {e}"),
                }
            }
            tracing::info!("mobile: audio decode thread exited");
        })
        .map(|_| tx)
        .ok() // 线程创建失败（资源耗尽）→ 禁用态。
}

// ════════════════════════════════════════════════════════════════
// Tests（宿主机）
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use kirin_desk_media::AudioEncoder as _;
    use std::time::{Duration, Instant};

    /// 采集 sink（单测断言投递）。
    #[derive(Default)]
    struct CollectSink {
        frames: Mutex<Vec<usize>>, // 每帧样本数
    }

    impl AudioSink for CollectSink {
        fn on_audio(&self, pcm: &[f32], sample_rate: u32, channels: u16) {
            assert_eq!(sample_rate, SAMPLE_RATE);
            assert_eq!(channels, CHANNELS);
            self.frames.lock().unwrap().push(pcm.len());
        }
    }

    /// FFmpeg + opus 编解码器可用才跑（media 同款 skip 口径；宿主无 DLL 时
    /// 跳过不失败）。
    fn opus_available() -> bool {
        OpusDecoder::new().is_ok()
    }

    /// jitter 深度与桌面一致（pin：改深度须同步桌面 AudioDecodePipeline）。
    #[test]
    fn test_audio_jitter_depth_parity_with_desktop() {
        assert_eq!(AUDIO_JITTER_DEPTH_FRAMES, 3, "桌面 AudioDecodePipeline 深度 3");
        assert_eq!(SAMPLE_RATE, 48_000);
        assert_eq!(CHANNELS, 2);
    }

    /// 编码正弦 → forward → sink 收到 20ms/1920 样本帧（skip-guard：
    /// 宿主无 FFmpeg/opus 时跳过）。
    #[test]
    fn test_audio_session_forwards_decoded_pcm() {
        if !opus_available() {
            eprintln!("opus not available on host; audio forward test skipped");
            return;
        }
        use kirin_desk_media::encoder::audio::OpusEncoder;
        use kirin_desk_media::encoder::types::Timestamp;

        let collector = Arc::new(CollectSink::default());
        let session = AudioSession::spawn();
        assert!(session.tx.is_some(), "opus 可用 → 音频线程应启动");
        session.set_sink(Some(collector.clone() as Arc<dyn AudioSink>));

        // 编 8 帧正弦（160ms；jitter depth 3 → 预热后顺序弹出）。
        let mut enc = OpusEncoder::new().unwrap();
        let frame = kirin_desk_media::decoder::audio::FRAME_INTERLEAVED * 8;
        let pcm: Vec<f32> = (0..frame)
            .map(|i| {
                let t = i as f32 / SAMPLE_RATE as f32;
                (t * 440.0 * std::f32::consts::PI * 2.0).sin() * 0.3
            })
            .collect();
        let pkts = enc.encode_pcm(&pcm, Timestamp::now()).unwrap();
        assert!(pkts.len() >= 8, "8 帧 20ms → ≥8 opus 包");
        for (i, p) in pkts.iter().enumerate() {
            session.forward(p.ts.pts + i as u64, p.data.clone());
        }
        // 音频线程异步消费：轮询至收到 ≥1 帧（上限 5s）。
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let n = collector.frames.lock().unwrap().len();
            if n > 0 || Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let frames = collector.frames.lock().unwrap().clone();
        assert!(!frames.is_empty(), "sink 必须收到解码 PCM 帧");
        for len in frames {
            assert_eq!(
                len,
                kirin_desk_media::decoder::audio::FRAME_INTERLEAVED,
                "每帧 20ms interleaved stereo = 1920 样本"
            );
        }
    }

    /// set_sink(None) 后投递停止（解除回调；帧丢弃不缓冲）。
    #[test]
    fn test_audio_session_sink_detach() {
        if !opus_available() {
            eprintln!("opus not available on host; sink detach test skipped");
            return;
        }
        use kirin_desk_media::encoder::audio::OpusEncoder;
        use kirin_desk_media::encoder::types::Timestamp;

        let collector = Arc::new(CollectSink::default());
        let session = AudioSession::spawn();
        session.set_sink(Some(collector.clone() as Arc<dyn AudioSink>));
        session.set_sink(None);

        let mut enc = OpusEncoder::new().unwrap();
        let pcm = vec![0.1f32; kirin_desk_media::decoder::audio::FRAME_INTERLEAVED * 4];
        let pkts = enc.encode_pcm(&pcm, Timestamp::now()).unwrap();
        for p in &pkts {
            session.forward(p.ts.pts, p.data.clone());
        }
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            collector.frames.lock().unwrap().is_empty(),
            "解除回调后不再投递"
        );
    }
}
