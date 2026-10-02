//!
//! # 定位（方案研究 §5 workspace 集成）
//!
//! `crate-type = ["cdylib", "rlib"]`：cdylib 产出 `libkirin_desk_mobile.so`
//! （cargo-ndk → APK jniLibs/arm64-v8a/）；rlib 供宿主机单测（编排层纯函数）。
//!
//! **不复制任何逻辑**——连接/握手走 `kirin-desk-core::connection::client`
//! （`resolve_peer` + `connect_peer`，与桌面 CLI/GUI 同一库层入口）；
//! 收发/解码走 `kirin-desk-media`（SecureChannelSender/Receiver +
//! `decoder::factory::create_video_decoder`）；输入 wire 复用
//! `kirin-desk-input::capture::InputEvent`（服务端零改动）。
//! 本 crate 只做**薄编排层**（[`orchestration`]）+ JNI 导出（android 门控，
//! [`jni`] 模块）。
//!
//! # JNI 桥面（Kotlin 侧 `com.kirindesk.mobile.NativeBridge`）
//!
//! 见 `jni.rs` 模块注释的签名清单（T05 波 Kotlin 工程按此对接）。
//!
//! # LGPL 合规
//!
//! FFmpeg 三件套由 Kotlin 侧 `System.loadLibrary` 预载、Rust 侧
//! `media::ffmpeg::dlls` 动态 dlsym（不静态链接、不修改），与桌面动态加载
//! DLL 口径一致。

pub mod audio;
/// B2 岗 JNI 只薄封装 `start_send`/`respond_offer`/`cancel`/`snapshot` 四语义）。
pub mod file_transfer;
pub mod orchestration;
/// ID 注册。与 [`orchestration`]（控制端）互为镜像；既有控制端路径零改动。
pub mod server;

/// JNI 导出（Java 包 `com.kirindesk.mobile`，类 `NativeBridge`）。
/// 仅 Android target 编译；宿主机（Windows 测试/桌面）零 JNI 依赖。
#[cfg(target_os = "android")]
pub mod jni;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};

/// 全局 tokio Runtime（JNI_OnLoad / 首次使用时建立；进程生命周期持有）。
///
/// Android 上没有 `#[tokio::main]` 入口，由本函数手动建多线程 runtime
/// （方案研究 §2 tokio 条目）。宿主机单测也可复用。
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build global tokio runtime")
    })
}

/// 会话句柄表（JNI `jlong` handle → 活动会话）。
pub struct Sessions {
    inner: Mutex<std::collections::HashMap<i64, orchestration::SessionHandle>>,
    next: AtomicI64,
}

impl Sessions {
    pub fn global() -> &'static Sessions {
        static S: OnceLock<Sessions> = OnceLock::new();
        S.get_or_init(|| Sessions {
            inner: Mutex::new(std::collections::HashMap::new()),
            next: AtomicI64::new(1),
        })
    }

    /// 注册新会话，分配句柄。
    pub fn insert(&self, handle: orchestration::SessionHandle) -> i64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().unwrap().insert(id, handle);
        id
    }

    /// 取句柄对应会话的输入发送端（克隆），无句柄返回 None。
    pub fn input_tx(&self, id: i64) -> Option<tokio::sync::mpsc::UnboundedSender<orchestration::InputCommand>> {
        self.inner
            .lock()
            .unwrap()
            .get(&id)
            .map(|s| s.input_tx.clone())
    }

    /// 接收循环从 EncodedWindow.base_w/base_h 跟踪；未知 = (0, 0)）。
    pub fn server_resolution(&self, id: i64) -> (u32, u32) {
        self.inner
            .lock()
            .unwrap()
            .get(&id)
            .map(|s| *s.server_res.lock().unwrap())
            .unwrap_or((0, 0))
    }

    /// 注册帧回调（连接前后皆可调用；对既有会话即时生效）。
    pub fn set_frame_sink(&self, id: i64, sink: std::sync::Arc<dyn orchestration::FrameSink>) -> bool {
        match self.inner.lock().unwrap().get(&id) {
            Some(s) => {
                *s.frame_sink.lock().unwrap() = Some(sink);
                true
            }
            None => false,
        }
    }

    /// 注册音频 PCM 回调（P1-B；连接前后皆可，对既有会话即时生效）。
    pub fn set_audio_sink(&self, id: i64, sink: Option<std::sync::Arc<dyn audio::AudioSink>>) -> bool {
        match self.inner.lock().unwrap().get(&id) {
            Some(s) => {
                s.audio.set_sink(sink);
                true
            }
            None => false,
        }
    }

    /// JNI 四语义寻址：句柄 = `start_send`/`respond_offer`/`cancel`/`snapshot`
    /// 输入，peer_id = 按 B1 salt 口径预派生 `transfer_id`；无句柄 = None）。
    pub fn file_transfer_session(
        &self,
        id: i64,
    ) -> Option<(crate::file_transfer::FileTransferHandle, String)> {
        self.inner
            .lock()
            .unwrap()
            .get(&id)
            .map(|s| (s.files.clone(), s.peer_id.clone()))
    }

    /// 断开并移除会话（drop 输入通道 → 发送任务退出 → writer 关闭 →
    /// 接收循环退出 → 解码线程退出；与会话尾部清理路径一致）。
    pub fn disconnect(&self, id: i64) -> bool {
        match self.inner.lock().unwrap().remove(&id) {
            Some(s) => {
                s.stop.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }
}

/// 库版本（JNI `nativeVersion` 返回值；与 workspace 版本同步）。
pub fn version() -> &'static str {
    concat!(env!("CARGO_PKG_VERSION"), "-kirin-mobile")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_string() {
        assert!(version().contains("kirin-mobile"));
    }

    #[test]
    fn test_runtime_shared_instance() {
        let a = runtime() as *const _;
        let b = runtime() as *const _;
        assert_eq!(a, b, "runtime 必须是进程级单例");
    }
}
