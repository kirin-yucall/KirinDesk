package com.kirindesk.mobile

import android.Manifest
import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.*
import com.kirindesk.mobile.server.ScreenShareService
import com.kirindesk.mobile.ui.ConnectScreen
import com.kirindesk.mobile.ui.FileTransferManager
import com.kirindesk.mobile.ui.SettingsScreen
import com.kirindesk.mobile.ui.ServerScreen
import com.kirindesk.mobile.ui.SessionScreen
import com.kirindesk.mobile.ui.SessionState
import java.util.Locale

class MainActivity : ComponentActivity() {
    private lateinit var state: SessionState

    //    「开始屏幕共享」驱动）：授权成功 → 前台服务（授权数据一次性，
    //    启动/喂帧顺序纪律在 ScreenShareService 内固定）；拒绝 → 记错供
    //    页面 1s 轮询展示。 ──
    private val screenCaptureLauncher: ActivityResultLauncher<Intent> =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val data = result.data
            if (result.resultCode == Activity.RESULT_OK && data != null) {
                ScreenShareService.start(this, result.resultCode, data)
            } else {
                getSharedPreferences("server", MODE_PRIVATE).edit()
                    .putString("start_error", getString(R.string.server_err_denied))
                    .apply()
            }
        }

    // API 33+ 通知权限（链式：授权/拒绝后继续挂起动作，避免两系统弹窗叠加；
    // 文件传输终态通知共用本 launcher 与「权限后挂起动作」语义（既有模式
    // 复用，零新权限声明）。
    private var pendingNotifResume: (() -> Unit)? = null
    private val notifPermLauncher: ActivityResultLauncher<String> =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            val next = pendingNotifResume
            pendingNotifResume = null
            next?.invoke()
        }

    private lateinit var fileTransfer: FileTransferManager

    /** SAF 文档选择器（任意类型；读权限按 URI 粒度授予，免存储权限）
     *  ——「发送文件」入口，选择结果交 [FileTransferManager.onFilePicked]
     *  （先暂存拷贝后交 Rust 引擎，生命周期见该类注释）。 */
    private val filePickLauncher: ActivityResultLauncher<Array<String>> =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            fileTransfer.onFilePicked(uri)
        }

    /** 「发送文件」按钮入口（目标会话由 FileTransferManager.prepareSend 先行指定）。 */
    fun pickTransferFile() {
        runCatching { filePickLauncher.launch(arrayOf("*/*")) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 配置目录 = filesDir（KIRIN_DATA_DIR；known_hosts/identity/
        // devices.json 落此——P1-A：TOFU 首连指纹确认 + 连接历史均读写该目录）。
        runCatching { NativeBridge.nativeInit(filesDir.absolutePath) }
        // 设置页保存时即时再写，此处兜底冷启动路径）。
        runCatching {
            val w = getSharedPreferences("settings", Context.MODE_PRIVATE)
                .getInt("requested_width", 1280)
            NativeBridge.nativeSetRequestedWidth(w)
        }
        state = SessionState()
        fileTransfer = FileTransferManager(this)
        // 文件传输通知渠道（importance 对齐既有屏幕共享 FGS 口径：LOW——
        // 通知栏可见、无声音；API 33+ 拒绝 POST_NOTIFICATIONS 时不可见，
        // 传输功能不受影响）。
        runCatching {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(
                    FileTransferManager.NOTIF_CHANNEL_ID,
                    getString(R.string.ft_notif_channel),
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                var inSession by remember { mutableStateOf(false) }
                var inSettings by remember { mutableStateOf(false) }
                var inServer by remember { mutableStateOf(false) }
                when {
                    inSession && state.handle != 0L ->
                        SessionScreen(state, fileTransfer) { inSession = false }
                    inServer -> ServerScreen(fileTransfer) { inServer = false }
                    inSettings -> SettingsScreen { inSettings = false }
                    else -> ConnectScreen(
                        state,
                        onConnected = { inSession = true },
                        onOpenSettings = { inSettings = true },
                        onOpenServer = { inServer = true },
                    )
                }
            }
        }
    }

    /**
     * 式请求 POST_NOTIFICATIONS（授予/拒绝后继续），再弹 MediaProjection
     * 系统授权弹窗；授权成功 → [ScreenShareService.start]（前台服务）。
     * 顺序纪律（startForeground → nativeServerStart → 捕获启动）在服务内。
     */
    fun launchScreenShareFlow() {
        val mpm = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val mpIntent = mpm.createScreenCaptureIntent()
        requestNotifPermissionThen { screenCaptureLauncher.launch(mpIntent) }
    }

    /**
     * launcher、同「权限后挂起动作」语义）：已授予（或 <API 33）→ 立即
     * 执行 [then]；未授予 → 弹系统权限框，授予/拒绝后执行（拒绝 = 通知
     * 不可见，功能不受影响，[then] 仍执行以保流程不挂起）。
     */
    fun requestNotifPermissionThen(then: () -> Unit) {
        if (Build.VERSION.SDK_INT < 33 ||
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            then()
        } else {
            pendingNotifResume = then
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    // attachBaseContext 按 settings.language 包 locale（system = 不包，随
    // 系统）；设置页切换后 recreate() 重建即生效（Compose 资源随 Activity
    // locale 解析）。API 33+ 有系统级 LocaleManager，本口径全版本一致。

    override fun attachBaseContext(newBase: Context) {
        val lang = runCatching {
            newBase.getSharedPreferences("settings", Context.MODE_PRIVATE)
                .getString("language", "system")
        }.getOrNull() ?: "system"
        super.attachBaseContext(if (lang == "system") newBase else wrapLocale(newBase, lang))
    }

    private fun wrapLocale(context: Context, tag: String): Context {
        val locale = Locale.forLanguageTag(tag)
        val config = Configuration(context.resources.configuration)
        config.setLocale(locale)
        return context.createConfigurationContext(config)
    }

    //    DisposableEffect 驱动；Manifest configChanges 拦截转向重建防断连）──

    /** 进入会话显示模式：sensorLandscape（双侧横屏随传感器）+ 沉浸式
     *  全屏（隐藏状态栏/导航栏，滑动暂现）+ 横屏刘海延伸（shortEdges）。 */
    fun enterSessionDisplay() {
        requestedOrientation = android.content.pm.ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE
        val w = window
        // 刘海屏横屏全屏：画面延伸进刘海区（API 27+；minSdk 26 守卫）。
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            w.attributes.layoutInDisplayCutoutMode =
                WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            w.setDecorFitsSystemWindows(false)
            w.insetsController?.apply {
                hide(WindowInsets.Type.systemBars())
                systemBarsBehavior =
                    WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            }
        } else {
            @Suppress("DEPRECATION")
            w.decorView.systemUiVisibility = (View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                or View.SYSTEM_UI_FLAG_FULLSCREEN
                or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION)
        }
    }

    /** 退出会话显示模式：恢复竖屏（连接页口径）+ 系统栏常驻。 */
    fun exitSessionDisplay() {
        requestedOrientation = android.content.pm.ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        val w = window
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            w.attributes.layoutInDisplayCutoutMode =
                WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_DEFAULT
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            w.insetsController?.show(WindowInsets.Type.systemBars())
            // insets 行为复原（BEHAVIOR_DEFAULT = 依赖系统手势动画）。
            w.insetsController?.systemBarsBehavior =
                WindowInsetsController.BEHAVIOR_DEFAULT
            w.setDecorFitsSystemWindows(true)
        } else {
            @Suppress("DEPRECATION")
            w.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_VISIBLE
        }
    }

    override fun onDestroy() {
        // 离开 Activity 主动断开会话（nativeDisconnect 幂等）。
        if (::state.isInitialized) runCatching { state.disconnect() }
        super.onDestroy()
    }
}
