package com.kirindesk.mobile.server

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.Context
import android.content.Intent
import android.graphics.Path
import android.graphics.Point
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.kirindesk.mobile.NativeBridge

/**
 * 键鼠 wire 事件经 Rust viewer 会话上抛（`NativeBridge.onServerInputEvent`，
 * 契约 = mobile/src/jni.rs :97-166「被控端输入上抛」节）后由本服务落地为
 * Android 动作。
 *
 * **生命周期 ↔ 上抛开关**：[onServiceConnected] 真正就绪 →
 * `nativeSetInputCallbackEnabled(true)`（Rust 侧一次性缓存类引用+静态方法
 * 句柄）；[onUnbind]/[onDestroy] → false。未置 true 时 Rust 静默丢事件
 * （fail-soft，红线⑤）。
 *
 * **鼠标映射**（全量，`dispatchGesture`）：
 *
 * | wire 事件 | Android 动作 |
 * |---|---|
 * | 左键按下（key=1 无 bit7） | 记录按下点+时间（不注入） |
 * | 左键抬起（key=0x81） | 位移 < [TAP_DISTANCE_PX] 且未超 [LONG_PRESS_MIN_MS] → **tap**（原地 100ms stroke）；位移 ≥ 阈值 → **drag**（按下点→抬起点单指 stroke，时长=实际间隔、最低 [MIN_STROKE_MS]）；位移 < 阈值且间隔 ≥ [LONG_PRESS_MIN_MS] → **long press**（stroke 停留原地，时长=实际间隔） |
 * | 右键（key=2）按下 | `GLOBAL_ACTION_BACK`（Android 远控惯例） |
 * | 中键（key=4）按下 | `GLOBAL_ACTION_RECENTS` |
 * | 滚轮（kind=2，±120/格，正=上） | **双指同向垂直滑动**（位移 = \|delta\|×[WHEEL_PX_PER_UNIT] 封顶 [WHEEL_MAX_PX]；MVP 单次 stroke） |
 * | MOUSE_MOVE（kind=0） | 仅更新当前触点缓存（供滚轮中心），不产生手势（Android 无悬停概念） |
 *
 * 坐标换算（契约定案）：`screenPx = (nx * screenWidth).toInt()`——屏幕真实
 * 尺寸经 [screenSize]（API 30+ `maximumWindowMetrics` / 26-29
 * `Display.getRealSize`，含系统栏的真实显示区）。`baseW/baseH`（编码
 * 分辨率基数）参与判定不参与换算：`baseW == 0` = 服务端尚无帧，鼠标
 * 事件坐标恒 0 → 左键事件安全忽略（右键/中键/滚轮不依赖坐标，照常处理）。
 *
 * **键盘 MVP**：
 * - kind=6 TEXT / KEY_DOWN 可打印键（HID 字母数字 + Shift 位，纯修饰组合
 *   Ctrl/Alt/Super 不注入）→ **焦点可编辑节点追加文本**：
 *   `rootInActiveWindow?.findFocus(FOCUS_INPUT)`，节点 `isEditable` →
 *   `ACTION_SET_TEXT`（现有 text + 追加；TEXT 事件整段追加）；找不到可
 *   编辑焦点 / 节点拒绝 → 静默丢（[droppedTextEvents] 计数）；
 * - Backspace（HID 0x2A）→ 可编辑焦点末尾删一字符（`ACTION_SET_TEXT` 截短）；
 * - Enter（HID 0x28）→ 不注入换行（提交语义复杂），MVP 忽略；
 * - 特殊键（kind=7 SpecialCombo 判别式）：WinD(1)→`GLOBAL_ACTION_HOME`、
 *   AltTab(4)→`GLOBAL_ACTION_RECENTS`、LockScreen(8)→
 *   `GLOBAL_ACTION_LOCK_SCREEN`；Esc（HID 0x1B）→`GLOBAL_ACTION_BACK`；
 * - 其余（方向键/F1-F12/修饰组合/KEY_UP/KEY_REPEAT）→ 遗留不实现。
 *
 * **回调纪律**（jni.rs 契约）：事件到达于 Rust tokio 线程（非主线程）；
 * 单事件处理不阻塞 >50ms（[dispatchGesture]/[performGlobalAction] 均异步
 * 派发、线程无关；文本提交经 [mainHandler] 投递主线程——
 * AccessibilityNodeInfo 非线程安全）；全程 try-catch 吞异常（异常不回传
 * Rust 栈）。
 *
 * **隐私口径**：不监听任何 [AccessibilityEvent]（[onAccessibilityEvent]
 * 空实现，配置 eventTypes 通配仅为兼容各 ROM，零消费）；
 * `canRetrieveWindowContent` 仅用于向当前焦点输入框读取现有文本以做
 * 「追加/删尾」提交，不读取、不上报、不落盘任何屏幕内容（服务描述文案
 * 同口径，见 res/xml/accessibility_service_config.xml 的
 * `@string/accessibility_service_description`）。
 */
class AccessibilityInputService : AccessibilityService() {

    // ── 生命周期 ↔ 上抛开关 ─────────────────────────────────────────────

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
        runCatching { NativeBridge.nativeSetInputCallbackEnabled(true) }
    }

    override fun onUnbind(intent: Intent?): Boolean {
        disableInputCallback()
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        disableInputCallback()
        super.onDestroy()
    }

    /** 摘除单例 + 关闭上抛（幂等；onUnbind/onDestroy 双保险收敛同一点）。 */
    private fun disableInputCallback() {
        if (instance === this) instance = null
        runCatching { NativeBridge.nativeSetInputCallbackEnabled(false) }
    }

    /** 隐私口径：不监听任何 AccessibilityEvent（空实现，零消费）。 */
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // 故意留空——本服务只做动作注入与焦点文本提交，不读取事件内容。
    }

    override fun onInterrupt() {
        // 无进行中需打断的自有任务（dispatchGesture 回调为 null，无悬挂状态）。
    }

    // ── 输入事件入口（Rust 会话线程；整体 try-catch，异常不回传）────────

    fun onInputEvent(
        kind: Int, key: Int, nx: Float, ny: Float,
        modifiers: Int, text: String, baseW: Int, baseH: Int,
    ) {
        try {
            when (kind) {
                NativeBridge.SERVER_EV_MOUSE_MOVE -> onMove(nx, ny)
                NativeBridge.SERVER_EV_MOUSE_BUTTON -> onButton(key, nx, ny, baseW)
                NativeBridge.SERVER_EV_MOUSE_WHEEL -> onWheel(key)
                NativeBridge.SERVER_EV_KEY_DOWN,
                NativeBridge.SERVER_EV_KEY_UP,
                NativeBridge.SERVER_EV_KEY_REPEAT -> onKey(kind, key, modifiers)
                NativeBridge.SERVER_EV_TEXT -> onText(text)
                NativeBridge.SERVER_EV_SPECIAL_KEY -> onSpecialKey(key)
                else -> { /* 未知 kind：静默丢（fail-soft） */ }
            }
        } catch (_: Exception) {
            // 回调纪律：异常不回传 Rust（Rust 侧 exception_clear + 首次 warn）。
        }
    }

    // ── 鼠标 ─────────────────────────────────────────────────────────────

    /** MOUSE_MOVE：仅更新当前触点缓存（归一化），不产生手势。 */
    private fun onMove(nx: Float, ny: Float) {
        synchronized(mouseLock) {
            lastMoveX = nx
            lastMoveY = ny
            hasMove = true
        }
    }

    private fun onButton(key: Int, nx: Float, ny: Float, baseW: Int) {
        val pressed = key and BTN_RELEASED == 0
        when (key and 0x7F) {
            BTN_LEFT -> {
                if (!pressed) {
                    onLeftRelease(nx, ny, baseW)
                    return
                }
                if (baseW <= 0) return // 服务端尚无帧：坐标恒 0，安全忽略
                synchronized(mouseLock) {
                    downX = nx
                    downY = ny
                    leftDown = true
                    downTimeMs = System.currentTimeMillis()
                }
            }
            BTN_RIGHT -> if (pressed) performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
            BTN_MIDDLE ->
                if (pressed) performGlobalAction(AccessibilityService.GLOBAL_ACTION_RECENTS)
            else -> { /* 未知按钮位：静默丢 */ }
        }
    }

    /** 一次左键按下的记录（归一化坐标 + 按下时刻）。 */
    private data class Press(val x: Float, val y: Float, val timeMs: Long)

    /**
     * 左键抬起 → tap / drag / long press 判定：
     * 位移 < [TAP_DISTANCE_PX] 且间隔 < [LONG_PRESS_MIN_MS] = tap（原地
     * 100ms stroke）；位移 ≥ 阈值 = drag（按下点→抬起点，时长=实际间隔、
     * 最低 [MIN_STROKE_MS]）；位移 < 阈值且间隔 ≥ [LONG_PRESS_MIN_MS] =
     * long press（stroke 停留原地，时长=实际间隔）。无按下记录时收到抬起
     * （孤儿抬起，如服务半路连接）→ 按抬起点单 tap 兜底（fail-soft）。
     */
    private fun onLeftRelease(nx: Float, ny: Float, baseW: Int) {
        if (baseW <= 0) {
            synchronized(mouseLock) { leftDown = false }
            return
        }
        val press: Press? = synchronized(mouseLock) {
            val p = if (leftDown) Press(downX, downY, downTimeMs) else null
            leftDown = false
            p
        }
        val (sw, sh) = screenSize()
        val upPx = nx * sw to ny * sh
        if (press == null) {
            dispatchStrokes(listOf(pathAt(upPx)), TAP_STROKE_MS)
            return
        }
        val downPx = press.x * sw to press.y * sh
        val dist = kotlin.math.hypot(upPx.first - downPx.first, upPx.second - downPx.second)
        val durationMs = (System.currentTimeMillis() - press.timeMs).coerceAtLeast(0L)
        when {
            dist < TAP_DISTANCE_PX && durationMs >= LONG_PRESS_MIN_MS ->
                dispatchStrokes(
                    listOf(pathAt(upPx)),
                    durationMs.coerceAtLeast(MIN_STROKE_MS),
                )
            dist < TAP_DISTANCE_PX ->
                dispatchStrokes(listOf(pathAt(upPx)), TAP_STROKE_MS)
            else ->
                dispatchStrokes(
                    listOf(pathBetween(downPx, upPx)),
                    durationMs.coerceAtLeast(MIN_STROKE_MS),
                )
        }
    }

    /**
     * 滚轮 → 双指同向垂直滑动（MVP 单次 stroke）：`wheel_delta` 正 = 滚上
     * → 内容上移 → 手指下移（dy > 0）；负 = 滚动 → 手指上移。中心 = 触点
     * 缓存（无缓存时屏幕中心），位移 = |delta| × [WHEEL_PX_PER_UNIT]
     * （120/格 → 240px）封顶 [WHEEL_MAX_PX]。
     */
    private fun onWheel(wheelDelta: Int) {
        if (wheelDelta == 0) return
        val (sw, sh) = screenSize()
        val (cxN, cyN) = synchronized(mouseLock) {
            if (hasMove) lastMoveX to lastMoveY else 0.5f to 0.5f
        }
        val cx = (cxN * sw).toInt().coerceIn(0, sw - 1)
        val cy = (cyN * sh).toInt().coerceIn(0, sh - 1)
        val distPx = (kotlin.math.abs(wheelDelta) * WHEEL_PX_PER_UNIT).toInt()
            .coerceAtMost(WHEEL_MAX_PX)
        val dy = if (wheelDelta > 0) distPx else -distPx
        val y0 = cy.coerceIn(0, sh)
        val y1 = (y0 + dy).coerceIn(0, sh)
        val dur = (distPx / 2L).coerceIn(WHEEL_MIN_DURATION_MS, WHEEL_MAX_DURATION_MS)
        val spread = (sw * 0.08f).toInt().coerceIn(24, 80) // 双指水平间距
        val x1 = (cx - spread).coerceIn(8, sw - 8)
        val x2 = (cx + spread).coerceIn(8, sw - 8)
        // 两指同向位移（平行 = 纯滚动，非捏合）。
        dispatchStrokes(
            listOf(
                pathBetween(x1.toFloat() to y0.toFloat(), x1.toFloat() to y1.toFloat()),
                pathBetween(x2.toFloat() to y0.toFloat(), x2.toFloat() to y1.toFloat()),
            ),
            dur,
        )
    }

    // ── 键盘（MVP） ─────────────────────────────────────────────────────

    /**
     * KEY_DOWN/KEY_UP/KEY_REPEAT：仅消费 KEY_DOWN（UP/REPEAT 忽略——
     * Windows 自动重复若逐次注入会刷屏）。可打印键 = HID 字母数字 +
     * Shift 位（字母→大写）；纯修饰组合（Ctrl/Alt/Super 参与）不注入
     * （遗留）；Esc → BACK；Enter 忽略（遗留）；其余键遗留不实现。
     */
    private fun onKey(kind: Int, key: Int, modifiers: Int) {
        if (kind != NativeBridge.SERVER_EV_KEY_DOWN) return
        if (modifiers and
            (NativeBridge.MOD_CTRL or NativeBridge.MOD_ALT or NativeBridge.MOD_SUPER) != 0
        ) {
            return // 修饰组合（Ctrl+C 类）→ 遗留不实现
        }
        val shift = modifiers and NativeBridge.MOD_SHIFT != 0
        when (key) {
            HID_ESCAPE -> performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
            HID_ENTER -> {
                // MVP：不向节点注入换行（提交语义复杂），遗留。
            }
            HID_BACKSPACE -> postToMain { appendToEditable { it.dropLast(1) } }
            HID_SPACE -> postToMain { appendToEditable { it + " " } }
            in HID_A..HID_Z -> {
                val c = ('a'.code + (key - HID_A)).toChar()
                val out = if (shift) c.uppercaseChar() else c
                postToMain { appendToEditable { it + out } }
            }
            in HID_1..HID_9 -> {
                val c = ('1' + (key - HID_1)).toChar()
                postToMain { appendToEditable { it + c } }
            }
            HID_0 -> postToMain { appendToEditable { it + '0' } }
            else -> {
                // 方向键（0x50-0x53）/F1-F12/Tab 等 → 遗留不实现，静默丢。
            }
        }
    }

    /** kind=6 TEXT：整段追加到焦点可编辑节点（中文/emoji 同路径）。 */
    private fun onText(text: String) {
        if (text.isEmpty()) return
        postToMain { appendToEditable { it + text } }
    }

    /**
     * kind=7 SPECIAL_KEY（SpecialCombo 判别式）→ Android 全局动作映射：
     * WinD(1)→HOME、AltTab(4)→RECENTS、LockScreen(8)→LOCK_SCREEN；
     * 其余组合（WinE/WinL/WinR/CtrlShiftEsc/AltF4/CtrlEsc）遗留不实现。
     */
    private fun onSpecialKey(combo: Int) {
        when (combo) {
            SPECIAL_WIN_D -> performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME)
            SPECIAL_ALT_TAB ->
                performGlobalAction(AccessibilityService.GLOBAL_ACTION_RECENTS)
            SPECIAL_LOCK_SCREEN ->
                performGlobalAction(AccessibilityService.GLOBAL_ACTION_LOCK_SCREEN)
            else -> { /* 遗留：静默丢 */ }
        }
    }

    // ── 文本提交（主线程；焦点可编辑节点 ACTION_SET_TEXT）───────────────

    /**
     * 焦点可编辑节点提交：`findFocus(FOCUS_INPUT)` → `isEditable` →
     * `ACTION_SET_TEXT`（现有 text + 追加 / 删尾）。找不到可编辑焦点、
     * 节点非可编辑或拒绝 ACTION_SET_TEXT → 静默丢 + [droppedTextEvents]
     * 计数（不上抛、不记日志期待 warn）。
     */
    private fun appendToEditable(transform: (String) -> String) {
        val root = rootInActiveWindow ?: run {
            droppedTextEvents++
            return
        }
        val node = root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
        if (node == null || !node.isEditable) {
            droppedTextEvents++
            return
        }
        val current = node.text?.toString() ?: ""
        val updated = transform(current)
        if (updated == current) return
        val ok = runCatching {
            node.performAction(
                AccessibilityNodeInfo.ACTION_SET_TEXT,
                Bundle().apply {
                    putCharSequence(
                        AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                        updated,
                    )
                },
            )
        }.getOrDefault(false)
        if (!ok) droppedTextEvents++
        node.recycle()
    }

    /** 文本提交投递主线程（AccessibilityNodeInfo 非线程安全；投递本身非阻塞）。 */
    private fun postToMain(block: () -> Unit) {
        mainHandler.post {
            try {
                block()
            } catch (_: Exception) {
                // fail-soft：节点操作异常不扩散（事件已消费）。
            }
        }
    }

    // ── 手势合成（dispatchGesture 线程无关，Rust 会话线程可直接调）─────

    /** 单点原地 stroke 路径（tap / long press 停留原地）。 */
    private fun pathAt(p: Pair<Float, Float>): Path = Path().apply {
        moveTo(p.first, p.second)
        lineTo(p.first, p.second)
    }

    /** 两点间单指 stroke 路径（drag / 滚轮单指位移）。 */
    private fun pathBetween(a: Pair<Float, Float>, b: Pair<Float, Float>): Path =
        Path().apply {
            moveTo(a.first, a.second)
            lineTo(b.first, b.second)
        }

    /** 派发一批同参（同起始时间/时长）stroke（tap/drag/long press 单
     *  stroke；双指滚动双 stroke 同向同位移）。 */
    private fun dispatchStrokes(paths: List<Path>, durationMs: Long) {
        val builder = GestureDescription.Builder()
        for (p in paths) {
            builder.addStroke(GestureDescription.StrokeDescription(p, 0L, durationMs))
        }
        runCatching { dispatchGesture(builder.build(), null, null) }
            .onFailure { /* 手势派发失败 fail-soft：不扩散、不回传 */ }
    }

    /**
     * 屏幕真实尺寸（契约「displayMetrics real 尺寸」口径）：API 30+
     * `maximumWindowMetrics.bounds` / API 26-29 `Display.getRealSize`
     * （含状态栏/导航栏的真实显示区，随横竖屏当前取向）。
     */
    private fun screenSize(): Pair<Int, Int> {
        val wm = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        return if (Build.VERSION.SDK_INT >= 30) {
            val b = wm.maximumWindowMetrics.bounds
            b.width() to b.height()
        } else {
            @Suppress("DEPRECATION")
            val p = Point()
            @Suppress("DEPRECATION")
            wm.defaultDisplay.getRealSize(p)
            p.x to p.y
        }
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    // 鼠标状态（Rust 会话线程访问；synchronized 防多观众并发上抛竞态）。
    private val mouseLock = Any()
    private var downX = 0f
    private var downY = 0f
    private var downTimeMs = 0L
    private var leftDown = false
    private var lastMoveX = 0f
    private var lastMoveY = 0f
    private var hasMove = false

    companion object {
        /**
         * 当前服务实例（[onServiceConnected] 注册、onUnbind/onDestroy 摘除；
         * null = 未连接/未启用 → `NativeBridge.onServerInputEvent` 静默丢，
         * 与 Rust 侧 enabled=false 语义同构）。
         */
        @Volatile
        var instance: AccessibilityInputService? = null
            private set

        /** 静默丢的文本提交计数（无可编辑焦点/节点拒绝；诊断备用）。 */
        @Volatile
        var droppedTextEvents: Long = 0L
            private set

        // ── wire 按钮位（kind=1：1=左 2=右 4=中，bit7=抬起） ──
        private const val BTN_LEFT = 0x01
        private const val BTN_RIGHT = 0x02
        private const val BTN_MIDDLE = 0x04
        private const val BTN_RELEASED = 0x80

        // ── HID 用途码（kind=3-5 键码空间：A=0x04…Z=0x1D / 1=0x1E…0=0x27） ──
        private const val HID_ESCAPE = 0x1B
        private const val HID_SPACE = 0x20
        private const val HID_ENTER = 0x28
        private const val HID_BACKSPACE = 0x2A
        private const val HID_A = 0x04
        private const val HID_Z = 0x1D
        private const val HID_1 = 0x1E
        private const val HID_9 = 0x26
        private const val HID_0 = 0x27

        // ── SpecialCombo 判别式（kind=7；仅 1/4/8 实现，其余遗留） ──
        private const val SPECIAL_WIN_D = 1
        private const val SPECIAL_ALT_TAB = 4
        private const val SPECIAL_LOCK_SCREEN = 8

        // ── 手势阈值（PM 口径定案） ──
        /** tap/drag 位移分界（< 24px 视为未移动）。 */
        private const val TAP_DISTANCE_PX = 24f
        /** 长按下限（按下→抬起间隔 ≥ 800ms 且未移动 = long press）。 */
        private const val LONG_PRESS_MIN_MS = 800L
        /** tap 原地 stroke 时长。 */
        private const val TAP_STROKE_MS = 100L
        /** drag/long press stroke 最低时长（dispatchGesture 手感下限）。 */
        private const val MIN_STROKE_MS = 100L

        // ── 滚轮 → 双指滚动换算 ──
        /** 每 1 单位 wheel_delta 的指尖位移像素（120/格 → 240px/格）。 */
        private const val WHEEL_PX_PER_UNIT = 2f
        /** 单次滚动最大位移像素（防极端 delta 越屏）。 */
        private const val WHEEL_MAX_PX = 600
        private const val WHEEL_MIN_DURATION_MS = 100L
        private const val WHEEL_MAX_DURATION_MS = 400L
    }
}
