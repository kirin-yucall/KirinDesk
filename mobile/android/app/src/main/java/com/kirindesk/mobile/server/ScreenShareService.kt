package com.kirindesk.mobile.server

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import com.kirindesk.mobile.NativeBridge
import com.kirindesk.mobile.R

/**
 * `ImageReader(RGBA_8888, maxImages=3)` → `NativeBridge.nativeServerFeedFrame`
 * 热路径喂帧；Rust 服务端（监听 59990/握手/帧泵/ID 注册）经
 * `nativeServerStart/Stop` 驱动（契约 = mobile/src/jni.rs :39-73）。
 *
 * **顺序纪律**（Android 14 mediaProjection FGS 要求，`onStartCommand` 内固定）：
 * ① `startForeground`（系统 5s 时限内，**必须先于**投影启动/捕获启动）→
 * ② `nativeServerStart`（**喂帧前完成**；失败记人话原因到 SharedPreferences
 *    后全停自毁，页面 1s 轮询展示）→ ③ 投影启动 + `createVirtualDisplay`
 *    （捕获启动，监听器开始喂帧）。
 *
 * **停止路径**（页面「停止共享」按钮 / 通知栏停止 / 系统撤销授权
 * `MediaProjection.Callback.onStop` / 进程终止）一律收敛 [teardown]：
 * `virtualDisplay.release` → `imageReader.close` → `projection.stop` →
 * `nativeServerStop()`（幂等）；页面状态经 `nativeServerStatus` 1s 轮询同步
 * （发现 running=false 即回「未共享」）。
 *
 * 授权数据（系统对话框结果）一次性：Activity 经 [start] 传入
 * resultCode+data，此处只消费一次，不得复用。
 */
class ScreenShareService : Service() {

    private var projection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var captureThread: HandlerThread? = null

    @Volatile
    private var tornDown = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        // 回收/崩溃后，本服务被 AMS 自动重启时运行的是**新进程**，不经过
        // MainActivity.onCreate 的 nativeInit——缺 KIRIN_DATA_DIR 时
        // nativeServerStart 的身份加载以 "identity: config dir: No
        // 重设（同一路径，重复 set_var 语义无冲突）堵住重启路径。
        runCatching { NativeBridge.nativeInit(filesDir.absolutePath) }
        // 通知渠道常驻（低重要级：通知栏可见、无声音）。API 33+ 用户拒绝
        // POST_NOTIFICATIONS 时通知不可见，但 FGS 与共享本身正常运行。
        getSystemService(NotificationManager::class.java)
            .createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.server_notif_channel),
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 停止（页面 stopService / 通知栏「停止」动作）。
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (projection != null) {
            // 重复启动（已有共享在跑）——忽略，保持现有会话。
            return START_NOT_STICKY
        }
        val resultCode = intent?.getIntExtra(EXTRA_RESULT_CODE, -1) ?: -1
        val data = intent?.getParcelableExtra<Intent>(EXTRA_RESULT_DATA)
        if (data == null) {
            // 异常路径（无授权数据）——不进前台，直接自毁。
            stopSelf()
            return START_NOT_STICKY
        }
        // ① startForeground 先行（Android 14：必须先于投影启动/捕获启动）。
        startForeground(NOTIF_ID, buildNotification())
        // ② 服务端启动 → ③ 捕获启动（同线程串行，顺序固定）。
        try {
            startServer()
            startCapture(resultCode, data)
        } catch (e: Exception) {
            failStart(e.message ?: e.toString())
        }
        return START_NOT_STICKY
    }

    /**
     * ② 服务端启动（喂帧前完成）。凭据取自 SharedPreferences 单一数据源
     * （页面落盘后拉起本服务）；`deviceId` 传空 = 公钥指纹派生（jni.rs 契约：
     * 服务端身份由 Rust IdentityManager 自管）。
     */
    private fun startServer() {
        val prefs = getSharedPreferences("server", MODE_PRIVATE)
        val relay = getSharedPreferences("relay", MODE_PRIVATE)
        val port = prefs.getString("port", null)
            ?.trim()?.toIntOrNull()?.coerceIn(0, 65535)
            ?: DEFAULT_PORT
        if (!NativeBridge.nativeServerStart(
                port = port,
                nickname = prefs.getString("nickname", "")?.trim().orEmpty(),
                challenge = prefs.getString("challenge", "")?.trim().orEmpty(),
                relayServerAddr = relay.getString("server_addr", "")?.trim().orEmpty(),
                relayToken = relay.getString("token", "")?.trim().orEmpty(),
                relayServerPubkey = relay.getString("server_pubkey", "")?.trim().orEmpty(),
                deviceId = "",
            )
        ) {
            failStart("nativeServerStart returned false")
        }
    }

    /** ③ 捕获启动：MediaProjection（系统授权）→ ImageReader(RGBA_8888×3) → VirtualDisplay。 */
    private fun startCapture(resultCode: Int, data: Intent) {
        val mpm = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val proj = mpm.getMediaProjection(resultCode, data)
            ?: throw IllegalStateException("getMediaProjection returned null")
        projection = proj

        // 捕获专用线程：ImageReader 回调与投影回调均派发于此（不占主线程，
        // 喂帧热路径零 UI 依赖）。
        val handlerThread = HandlerThread("kirin-screen-capture").apply { start() }
        captureThread = handlerThread
        val handler = Handler(handlerThread.looper)

        // 系统撤销授权（用户在系统设置/授权界面停止共享）→ onStop 回调 →
        // 全停（onDestroy → teardown，与其余停止路径收敛同一点）。
        proj.registerCallback(object : MediaProjection.Callback() {
            override fun onStop() {
                stopSelf()
            }
        }, handler)

        // 屏幕尺寸/密度取当前显示（服务进程 resources）；方向变化后画面经
        // AUTO_MIRROR 镜像跟随（初始 surface 尺寸不重建——一期口径）。
        val metrics = resources.displayMetrics
        val w = metrics.widthPixels
        val h = metrics.heightPixels
        val dpi = metrics.densityDpi
        val reader = ImageReader.newInstance(w, h, PixelFormat.RGBA_8888, MAX_IMAGES)
        imageReader = reader
        reader.setOnImageAvailableListener({ r -> onFrameAvailable(r) }, handler)

        // Android 14 时序要求 = startForeground 先于投影启动（createVirtualDisplay
        // 隐式启动）——上方 ① 已满足；显式 startProjection() 为 API 36+ 接口，
        // compileSdk 35 不可引用，不引入版本门。
        val display = proj.createVirtualDisplay(
            DISPLAY_NAME, w, h, dpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            reader.surface, null, handler,
        ) ?: throw IllegalStateException("createVirtualDisplay returned null")
        virtualDisplay = display
    }

    /**
     * 喂帧热路径（捕获线程）：`acquireLatestImage`（天然 latest-wins，与
     * Rust 喂入槽同构）→ plane 0 拷出 byte[]（row-stride 兼容）→
     * `nativeServerFeedFrame`（Rust 热路径不抛异常）→ 立即 `close`
     * （防 ImageReader 槽耗尽阻塞采集）。
     */
    private fun onFrameAvailable(reader: ImageReader) {
        val image = reader.acquireLatestImage() ?: return
        try {
            val w = image.width
            val h = image.height
            val rowBytes = w * 4
            val plane = image.planes[0]
            val buf = plane.buffer
            val out = ByteArray(h * rowBytes)
            if (plane.rowStride == rowBytes) {
                buf.get(out)
            } else {
                // 非常规行距（部分厂商硬件 stride 对齐）——逐行拷贝。
                for (y in 0 until h) {
                    buf.position(y * plane.rowStride)
                    buf.get(out, y * rowBytes, rowBytes)
                }
            }
            NativeBridge.nativeServerFeedFrame(out, w, h, System.currentTimeMillis())
        } catch (_: Exception) {
            // fail-soft：喂帧路径任何异常不堵采集（Rust 侧该路径本不抛）。
        } finally {
            image.close()
        }
    }

    /** 启动失败：记人话原因（页面 1s 轮询拾取展示）+ 全停 + 自毁。 */
    private fun failStart(reason: String) {
        getSharedPreferences("server", MODE_PRIVATE).edit()
            .putString("start_error", reason)
            .apply()
        teardown()
        stopSelf()
    }

    /** 统一拆除（幂等）：先停捕获（display/reader/projection）→ 停服务端
     *  （`nativeServerStop` 幂等，停监听/帧泵/ID 注册/清观众）。 */
    private fun teardown() {
        if (tornDown) return
        tornDown = true
        runCatching { virtualDisplay?.release() }
        virtualDisplay = null
        runCatching { imageReader?.close() }
        imageReader = null
        runCatching { projection?.stop() }
        projection = null
        runCatching { captureThread?.quitSafely() }
        captureThread = null
        runCatching { NativeBridge.nativeServerStop() }
    }

    override fun onDestroy() {
        teardown()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    /** 常驻通知（含「停止共享」动作 → ACTION_STOP 服务 intent → stopSelf）。 */
    private fun buildNotification(): Notification {
        val stopPi = PendingIntent.getService(
            this, 0,
            Intent(this, ScreenShareService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.server_notif_title))
            .setContentText(getString(R.string.server_notif_text))
            .setSmallIcon(android.R.drawable.ic_media_play)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(
                Notification.Action.Builder(
                    android.R.drawable.ic_media_pause,
                    getString(R.string.server_notif_stop),
                    stopPi,
                ).build(),
            )
            .build()
    }

    companion object {
        /** 通知栏「停止共享」动作（服务 intent action）。 */
        const val ACTION_STOP = "com.kirindesk.mobile.action.STOP_SHARE"

        private const val EXTRA_RESULT_CODE = "result_code"
        private const val EXTRA_RESULT_DATA = "result_data"
        private const val CHANNEL_ID = "screen_share"
        private const val NOTIF_ID = 1
        private const val DISPLAY_NAME = "KirinDesk-Share"
        private const val MAX_IMAGES = 3
        private const val DEFAULT_PORT = 59990

        /**
         * 拉起共享服务（Activity 系统授权成功后调用）。授权数据一次性——
         * 勿复用/重试同一份 resultCode+data。
         */
        fun start(context: Context, resultCode: Int, resultData: Intent) {
            context.startForegroundService(
                Intent(context, ScreenShareService::class.java).apply {
                    putExtra(EXTRA_RESULT_CODE, resultCode)
                    putExtra(EXTRA_RESULT_DATA, resultData)
                },
            )
        }
    }
}
