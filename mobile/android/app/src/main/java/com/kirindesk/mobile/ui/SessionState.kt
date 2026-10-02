package com.kirindesk.mobile.ui

import android.graphics.Bitmap
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.kirindesk.mobile.NativeBridge

/**
 * 会话与应用状态（Compose 状态 + native 句柄）。
 *
 * 帧路径：Rust 解码线程回调 → 这里只做 Bitmap 组装并写入 [frameBitmap]
 * （StateFlow 语义天然 conflate——仅保留最新一帧，丢帧保新）；渲染侧
 * collectAsState 上屏。
 *
 * P1-A：TOFU 首连指纹确认——[connect] 的后台线程阻塞在 nativeConnect 时，
 * UI 侧经 [pollPendingTrust]（ConnectScreen 轮询驱动）读取待确认指纹，
 * [pendingFingerprint] 非空 → 弹确认对话框 → [resolveTrust] 回传决策。
 */
class SessionState {
    var handle by mutableStateOf(0L)
    var connecting by mutableStateOf(false)
    var error by mutableStateOf<String?>(null)
    var frameBitmap by mutableStateOf<Bitmap?>(null)
    var frameCount by mutableStateOf(0L)
    var frameSize by mutableStateOf("—")
    var disconnected by mutableStateOf(false)

    /** 待确认指纹（TOFU 首连；非空 = 应展示确认对话框）。 */
    var pendingFingerprint by mutableStateOf<String?>(null)

    /** 音频开关（P1-B，默认开；会话页切换，关 = AudioTrack 暂停清缓冲）。
     *  private set + [toggleAudio]：属性自动 setter 与同名 fun 会撞 JVM
     *  签名（setAudioEnabled(Z)V），故切换统一走 toggleAudio。 */
    var audioEnabled by mutableStateOf(true)
        private set
    private val audioPlayer = AudioPlayer()

    /** 连接历史（Connect 页下拉；nativeHistory = devices.json+known_hosts）。 */
    var history by mutableStateOf<List<NativeBridge.HistoryEntry>>(emptyList())

    /** 重载连接历史（进入连接页/会话结束后调用；异常 fail-soft 空列表）。 */
    fun reloadHistory() {
        runCatching { history = NativeBridge.parseHistory(NativeBridge.nativeHistory()) }
    }

    /**
     * TOFU 轮询（UI 侧 200ms 驱动）：nativeConnect 阻塞期间读取待确认指纹。
     * 已有 pending 或不在连接中 → no-op（避免覆盖未处理请求）。
     */
    fun pollPendingTrust() {
        if (!connecting || pendingFingerprint != null) return
        runCatching {
            NativeBridge.nativePeekPendingTrust()?.let { pendingFingerprint = it }
        }
    }

    /** TOFU 决策回传（对话框按钮调用；同时清本地 pending 态）。 */
    fun resolveTrust(accept: Boolean) {
        pendingFingerprint = null
        runCatching { NativeBridge.nativeResolveTrust(accept) }
    }

    /**
     * id/token/serverPubkey 不用；mode 1 = ID 模式——id=目标设备、serverAddr=
     * relay 地址 + token + serverPubkey）。设备 ID 仅 trim——归一化（指纹/
     * 短码）在 Rust 侧同源完成（自定义 ID 大小写敏感，不做字符级改写）。
     */
    fun connect(
        mode: Int, id: String, nickname: String, challenge: String,
        serverAddr: String, token: String, serverPubkey: String, onOk: () -> Unit,
    ) {
        connecting = true
        error = null
        disconnected = false
        frameBitmap = null
        frameCount = 0
        pendingFingerprint = null
        Thread {
            try {
                val h = NativeBridge.nativeConnect2(
                    mode, id.trim(), nickname.trim(), challenge,
                    serverAddr.trim(), token.trim(), serverPubkey.trim(),
                )
                NativeBridge.nativeOnFrameCallback(h, NativeBridge.FrameCallback { w, hh, _, rgba ->
                    val bmp = rgbaToBitmap(w, hh, rgba)
                    if (bmp != null) {
                        frameBitmap = bmp
                        frameCount += 1
                        frameSize = "${w}x${hh}"
                    }
                })
                // P1-B：音频 PCM 回调（Rust 解码线程上调用 → AudioTrack 写）。
                NativeBridge.nativeOnAudioCallback(h, NativeBridge.AudioCallback { pcm, sr, ch ->
                    audioPlayer.feed(pcm, sr, ch)
                })
                handle = h
                connecting = false
                reloadHistory()
                onOk()
            } catch (e: Throwable) {
                connecting = false
                pendingFingerprint = null
                error = e.message ?: e.toString()
            }
        }.apply { isDaemon = true }.start()
    }

    fun disconnect() {
        val h = handle
        if (h != 0L) {
            NativeBridge.nativeDisconnect(h)
            handle = 0L
        }
        audioPlayer.release()
        disconnected = true
    }

    /** 会话页音频开关（P1-B；切换 AudioTrack 播放/暂停）。 */
    fun toggleAudio() {
        setAudioEnabledImpl(!audioEnabled)
    }

    private fun setAudioEnabledImpl(enabled: Boolean) {
        audioEnabled = enabled
        audioPlayer.setEnabled(enabled)
    }

    /**
     * 音频播放器（P1-B）：AudioTrack float32 低延迟流写。
     *
     * - 惰性建轨（首个 PCM 帧到达时按其实际采样率/声道数建 48k/stereo 轨；
     *   PERFORMANCE_MODE_LOW_LATENCY + USAGE_MEDIA）；
     * - 开关关闭：投递丢弃 + 轨暂停清缓冲（重开即续播，Rust 侧解码时间轴
     *   持续推进不受影响）；
     * - 阻塞写在 Rust 音频解码回调线程（专用线程，不占 UI/解码）。
     */
    private class AudioPlayer {
        private var track: AudioTrack? = null

        @Volatile
        private var enabled = true

        fun feed(pcm: FloatArray, sampleRate: Int, channels: Int) {
            if (!enabled) return
            val t = track ?: createTrack(sampleRate, channels)?.also {
                it.play()
                track = it
            } ?: return
            if (t.playState != AudioTrack.PLAYSTATE_PLAYING) return
            t.write(pcm, 0, pcm.size, AudioTrack.WRITE_BLOCKING)
        }

        fun setEnabled(on: Boolean) {
            enabled = on
            val t = track ?: return
            runCatching {
                if (on) t.play() else {
                    t.pause()
                    t.flush()
                }
            }
        }

        fun release() {
            track?.let {
                runCatching { it.pause() }
                runCatching { it.release() }
            }
            track = null
        }

        private fun createTrack(sampleRate: Int, channels: Int): AudioTrack? = runCatching {
            val channelMask = if (channels >= 2) {
                AudioFormat.CHANNEL_OUT_STEREO
            } else {
                AudioFormat.CHANNEL_OUT_MONO
            }
            val minBuf = AudioTrack.getMinBufferSize(sampleRate, channelMask, AudioFormat.ENCODING_PCM_FLOAT)
            AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_MOVIE)
                        .build(),
                )
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setEncoding(AudioFormat.ENCODING_PCM_FLOAT)
                        .setSampleRate(sampleRate)
                        .setChannelMask(channelMask)
                        .build(),
                )
                .setTransferMode(AudioTrack.MODE_STREAM)
                .setBufferSizeInBytes(maxOf(minBuf * 2, 8192))
                .setPerformanceMode(AudioTrack.PERFORMANCE_MODE_LOW_LATENCY)
                .build()
        }.getOrNull()
    }

    // 解码回调线程独占访问（Rust onFrame 串行上调）；尺寸不变时 in-place
    // copyPixelsFromBuffer，消除逐帧 Bitmap.createBitmap 分配（720p RGBA
    // 单帧 ~3.7MB、30fps 下 >100MB/s 的 GC 压力 = 用户实测「不流畅」的
    // 安卓侧因素之一）。尺寸变化（服务端降档/切显示器）自动重建。
    // 不 recycle（Compose 可能仍持有绘制引用，交 GC）。
    private var reusableFrame: Bitmap? = null

    /** RGBA 字节 → Bitmap（ARGB_8888 缓冲区原生即 RGBA 字节序，直拷；
    private fun rgbaToBitmap(w: Int, h: Int, rgba: ByteArray): Bitmap? {
        if (w <= 0 || h <= 0 || rgba.size < w * h * 4) return null
        val buf = java.nio.ByteBuffer.wrap(rgba)
        val existing = reusableFrame
        if (existing != null && existing.width == w && existing.height == h &&
            !existing.isRecycled
        ) {
            return runCatching {
                existing.copyPixelsFromBuffer(buf)
                existing
            }.getOrNull()
        }
        return runCatching {
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            bmp.copyPixelsFromBuffer(buf)
            reusableFrame = bmp
            bmp
        }.getOrNull()
    }
}
