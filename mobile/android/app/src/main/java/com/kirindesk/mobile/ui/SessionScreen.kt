package com.kirindesk.mobile.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.kirindesk.mobile.MainActivity
import com.kirindesk.mobile.NativeBridge
import com.kirindesk.mobile.R
import com.kirindesk.mobile.input.KeyMap
import kotlin.math.abs

/**
 * 会话页：帧渲染 + 手势 + 功能键条 + 软键盘 + 音频开关 + 文件传输入口 +
 * 断开按钮 + 状态行。
 *
 * `nativeFileTransferStart`）+「文件 (n)」（底部面板 = 传输列表/分享/取消）；
 * 会话存续 1s 纯拉轮询 [FileTransferManager.poll]（零回调）；入向 Offer
 * 弹窗独立于面板开合（接受 → mkdirs 接收目录后 respond；关闭 = 拒绝，
 * 对齐 TOFU 弹窗口径）。
 *
 * 滑动暂现）；退出（断开/onDispose）恢复竖屏 + 系统栏——由 [MainActivity]
 * 的 enterSessionDisplay/exitSessionDisplay 承载（Activity 级窗口操作）。
 *
 * 手势映射（研究 §4）：
 * - 单指点击 = 左键；单指移动 = 鼠标移动（归一化坐标，Rust 侧按服务端
 * - 长按 500ms = 按下左键拖动（抬起释放）；
 * - 双指点击 = 右键；双指拖动 = 滚轮（约 40px/格，wire 侧 ×120）；
 * - 三指点击 = 中键。
 *
 * - 功能键条：粘滞修饰键（Shift/Ctrl/Alt/Win，锁定=高亮，可组合）**不再
 *   发独立修饰键事件**（wire 键空间无修饰键）——锁定态以 modifiers 位标志
 *   附带在每次点触键/F 键上（nativeSendKey2，对齐桌面 mod_flags 口径）；
 * - 软键盘文本：**整段走 nativeSendText**（wire Text → 服务端
 *   KEYEVENTF_UNICODE 逐码元注入）——大写/Shift 符号/标点/中文/emoji
 *   统一支持（旧 VK+Shift 包裹路径对标点无效：wire 键空间无 OEM 标点）。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SessionScreen(
    state: SessionState,
    fileTransfer: FileTransferManager,
    onExit: () -> Unit,
) {
    val handle = state.handle
    val bmp = state.frameBitmap

    val activity = LocalContext.current as? MainActivity
    DisposableEffect(activity) {
        activity?.enterSessionDisplay()
        onDispose { activity?.exitSessionDisplay() }
    }

    // manager.poll 差集清旧句簿记与暂存文件，兜底防孤儿）。
    val context = LocalContext.current
    LaunchedEffect(state.handle) {
        val h = state.handle
        if (h != 0L) {
            try {
                while (true) {
                    fileTransfer.poll(listOf(h to context.getString(R.string.ft_source_remote)))
                    kotlinx.coroutines.delay(1000)
                }
            } finally {
                fileTransfer.poll(emptyList())
            }
        } else {
            fileTransfer.poll(emptyList())
        }
    }
    var showFilesSheet by remember { mutableStateOf(false) }

    fun sendMove(nx: Float, ny: Float) {
        if (handle != 0L) NativeBridge.nativeSendInput(
            handle, NativeBridge.INPUT_MOVE,
            nx.toDouble().coerceIn(0.0, 1.0), ny.toDouble().coerceIn(0.0, 1.0),
            0, 0,
        )
    }

    /** 按键事件附带当前归一化位置（wire 完整性；服务端 Windows 注入不消费）。 */
    fun sendButton(button: Int, pressed: Boolean, nx: Float, ny: Float) {
        if (handle != 0L) NativeBridge.nativeSendInput(
            handle, NativeBridge.INPUT_BUTTON,
            nx.toDouble().coerceIn(0.0, 1.0), ny.toDouble().coerceIn(0.0, 1.0),
            button, if (pressed) 1 else 0,
        )
    }

    fun sendWheel(notches: Int) {
        if (handle != 0L && notches != 0) NativeBridge.nativeSendInput(
            handle, NativeBridge.INPUT_WHEEL, 0.0, 0.0, NativeBridge.BUTTON_LEFT, notches,
        )
    }

    fun sendKey(vk: Int, down: Boolean, mods: Int = 0) {
        if (handle != 0L && vk in 0..0xFFFF) {
            NativeBridge.nativeSendKey2(handle, vk, down, mods)
        }
    }

    Column(modifier = Modifier.fillMaxSize().background(Color.Black)) {
        // ── 状态行 ──
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "帧 ${state.frameCount} · ${state.frameSize}" +
                    if (state.disconnected) " · 已断开" else "",
                color = if (state.disconnected) Color(0xFFE57373) else Color(0xFF9E9E9E),
                style = MaterialTheme.typography.labelSmall,
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                // +「文件 (n)」（底部面板：列表/分享/取消）。
                TextButton(
                    onClick = {
                        fileTransfer.prepareSend(handle)
                        activity?.pickTransferFile()
                    },
                    enabled = handle != 0L && !fileTransfer.stagingBusy,
                ) {
                    Text(
                        stringResource(R.string.ft_send),
                        style = MaterialTheme.typography.labelMedium,
                    )
                }
                TextButton(onClick = { showFilesSheet = true }) {
                    Text(
                        stringResource(R.string.ft_files, fileTransfer.entries.size),
                        style = MaterialTheme.typography.labelMedium,
                    )
                }
                // P1-B：音频开关（默认开；关 = AudioTrack 暂停清缓冲）。
                TextButton(onClick = { state.toggleAudio() }) {
                    Text(
                        stringResource(
                            if (state.audioEnabled) R.string.session_audio_on
                            else R.string.session_audio_off,
                        ),
                        style = MaterialTheme.typography.labelMedium,
                    )
                }
                TextButton(onClick = { state.disconnect(); onExit() }) { Text("断开") }
            }
        }

        // ── 帧画面 + 手势区 ──
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .pointerInput(handle) {
                    awaitEachGesture {
                        val first = awaitFirstDown(requireUnconsumed = false)
                        val downTime = first.uptimeMillis
                        var maxPointers = 1
                        var longPressDrag = false
                        var lastWheelAvgY: Float? = null
                        // 手势收尾按键用的最后归一化位置。
                        var lastNx = 0f
                        var lastNy = 0f
                        val w = size.width.toFloat().coerceAtLeast(1f)
                        val h = size.height.toFloat().coerceAtLeast(1f)

                        // 帧渲染为 ContentScale.Fit（等比留黑边），手势坐标须
                        // 先映射进实际内容矩形再归一化，否则竖屏下点击偏移。
                        // 映射对 base/aligned 差异天然免疫（等比 Fit）。
                        val moveTo = { x: Float, y: Float ->
                            val b = state.frameBitmap
                            if (b != null && b.width > 0 && b.height > 0) {
                                val boxAspect = w / h
                                val imgAspect = b.width.toFloat() / b.height
                                var cw = w; var ch = h
                                if (imgAspect > boxAspect) ch = w / imgAspect else cw = h * imgAspect
                                val offX = (w - cw) / 2f; val offY = (h - ch) / 2f
                                val nx = ((x - offX) / cw).coerceIn(0f, 1f)
                                val ny = ((y - offY) / ch).coerceIn(0f, 1f)
                                lastNx = nx; lastNy = ny
                                sendMove(nx, ny)
                            }
                        }
                        moveTo(first.position.x, first.position.y)
                        while (true) {
                            val event = awaitPointerEvent(PointerEventPass.Initial)
                            val pressed = event.changes.filter { it.pressed }
                            if (pressed.isEmpty()) break
                            maxPointers = maxOf(maxPointers, pressed.size)

                            if (pressed.size >= 2) {
                                // 双指：滚轮（前两指平均 Y 位移 → 格数）。
                                val avgY = (pressed[0].position.y + pressed[1].position.y) / 2f
                                val prev = lastWheelAvgY
                                lastWheelAvgY = avgY
                                if (prev != null) {
                                    val dy = avgY - prev
                                    if (abs(dy) >= 40f) {
                                        sendWheel(if (dy < 0) 1 else -1)
                                        lastWheelAvgY = avgY
                                    }
                                }
                            } else {
                                val p = pressed[0].position
                                val dt = event.changes.first().uptimeMillis - downTime
                                val totalMove = abs(p.x - first.position.x) + abs(p.y - first.position.y)
                                if (!longPressDrag && dt >= 500L && totalMove < 60f) {
                                    // 长按 500ms → 按下左键进入拖动。
                                    longPressDrag = true
                                    sendButton(NativeBridge.BUTTON_LEFT, true, lastNx, lastNy)
                                }
                                moveTo(p.x, p.y)
                            }
                        }
                        // 手势收尾：抬指。
                        if (longPressDrag) {
                            sendButton(NativeBridge.BUTTON_LEFT, false, lastNx, lastNy)
                        } else when {
                            maxPointers >= 3 -> {
                                sendButton(NativeBridge.BUTTON_MIDDLE, true, lastNx, lastNy)
                                sendButton(NativeBridge.BUTTON_MIDDLE, false, lastNx, lastNy)
                            }
                            maxPointers == 2 -> {
                                sendButton(NativeBridge.BUTTON_RIGHT, true, lastNx, lastNy)
                                sendButton(NativeBridge.BUTTON_RIGHT, false, lastNx, lastNy)
                            }
                            else -> {
                                sendButton(NativeBridge.BUTTON_LEFT, true, lastNx, lastNy)
                                sendButton(NativeBridge.BUTTON_LEFT, false, lastNx, lastNy)
                            }
                        }
                    }
                },
        ) {
            if (bmp != null) {
                // 尺寸不变时 in-place 拷贝，消除逐帧 3.7MB+ 分配/GC 卡顿）。
                // gen 键控让 remember 每帧产新 ImageBitmap 包装 → Image 重建
                // painter → 保证 in-place 更新后必重绘（同实例 Bitmap 状态写
                // 不触发跳过的 composable 失效）。
                val gen = state.frameCount
                val image = remember(gen) { bmp.asImageBitmap() }
                Image(
                    bitmap = image,
                    contentDescription = "remote frame",
                    modifier = Modifier.fillMaxSize(),
                    contentScale = ContentScale.Fit,
                )
            } else {
                Text(
                    if (state.disconnected) "已断开" else "等待画面…",
                    color = Color(0xFF9E9E9E),
                    modifier = Modifier.align(Alignment.Center),
                )
            }
        }

        FunctionKeyBar(handle = handle, sendKeyWithMods = ::sendKey)

        // ── 软键盘条：整段文本走 Unicode 注入（大写/标点/中文/emoji 统一） ──
        var text by remember { mutableStateOf("") }
        var skipped by remember { mutableStateOf(0) }
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = text, onValueChange = { text = it },
                placeholder = { Text("输入文本发送（支持中文/符号）") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                if (text.isNotEmpty()) {
                    if (handle != 0L) {
                        // wire Text 事件（KEYEVENTF_UNICODE）——一条 wire 消息
                        // 携带整段文本，服务端逐 UTF-16 码元注入。
                        NativeBridge.nativeSendText(handle, text)
                        skipped = 0
                    } else {
                        skipped += text.length
                    }
                    text = ""
                }
            }) { Text("发送") }
        }
        if (skipped > 0) {
            Text(
                "已跳过 $skipped 个字符（会话未连接）",
                color = Color(0xFFE0B24C),
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(start = 12.dp, bottom = 4.dp),
            )
        }
    }

    if (showFilesSheet) {
        ModalBottomSheet(onDismissRequest = { showFilesSheet = false }) {
            FileTransferPanel(
                manager = fileTransfer,
                onSendClick = {
                    fileTransfer.prepareSend(state.handle)
                    activity?.pickTransferFile()
                },
                modifier = Modifier.padding(bottom = 32.dp),
            )
        }
    }

    FileTransferOfferDialog(fileTransfer)
}

/** 功能键条按钮数据（label → VK）。 */
private data class FnKey(val label: String, val vk: Int)

/** 点触键（按下即抬起，一次点击）。 */
private val TAP_KEYS = listOf(
    FnKey("Esc", KeyMap.VK_ESCAPE),
    FnKey("Tab", KeyMap.VK_TAB),
    FnKey("Enter", KeyMap.VK_RETURN),
    FnKey("BkSp", KeyMap.VK_BACK),
    FnKey("Del", KeyMap.VK_DELETE),
    FnKey("Home", KeyMap.VK_HOME),
    FnKey("End", KeyMap.VK_END),
    FnKey("PgUp", KeyMap.VK_PRIOR),
    FnKey("PgDn", KeyMap.VK_NEXT),
    FnKey("←", KeyMap.VK_LEFT),
    FnKey("↑", KeyMap.VK_UP),
    FnKey("↓", KeyMap.VK_DOWN),
    FnKey("→", KeyMap.VK_RIGHT),
)

/** F1–F12。 */
private val F_KEYS = (1..12).map { FnKey("F$it", KeyMap.VK_F1 + it - 1) }

/**
 * - 第一行：粘滞修饰键 Shift/Ctrl/Alt/Win（锁定 = 高亮；可多选组合，如
 *   Ctrl+Alt 锁定后点 Del → Ctrl+Alt+Del 位标志随键下发）+ 点触键；
 * - 第二行：F1–F12。
 *
 * **修饰键不再发独立按键事件**：wire 键空间（`injector::Key`）无 Shift/
 * Ctrl/Alt/Win——修饰语义 = 键事件 `modifiers` 位标志（对齐桌面 viewer
 * mod_flags 口径）。锁定/解锁只改本地 [mods] 状态，零 wire 流量。
 */
@Composable
private fun FunctionKeyBar(
    handle: Long,
    sendKeyWithMods: (vk: Int, down: Boolean, mods: Int) -> Unit,
) {
    // 粘滞修饰键位标志（NativeBridge.MOD_*，可组合）。
    var mods by remember { mutableStateOf(0) }

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // 粘滞修饰键：锁定 = 高亮（容器色调切换直观可辨）。
            StickyModButton("Shift", mods and NativeBridge.MOD_SHIFT != 0) {
                mods = mods xor NativeBridge.MOD_SHIFT
            }
            StickyModButton("Ctrl", mods and NativeBridge.MOD_CTRL != 0) {
                mods = mods xor NativeBridge.MOD_CTRL
            }
            StickyModButton("Alt", mods and NativeBridge.MOD_ALT != 0) {
                mods = mods xor NativeBridge.MOD_ALT
            }
            StickyModButton("Win", mods and NativeBridge.MOD_SUPER != 0) {
                mods = mods xor NativeBridge.MOD_SUPER
            }
            TAP_KEYS.forEach { k ->
                SmallKeyButton(k.label) {
                    sendKeyWithMods(k.vk, true, mods)
                    sendKeyWithMods(k.vk, false, mods)
                }
            }
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            F_KEYS.forEach { k ->
                SmallKeyButton(k.label) {
                    sendKeyWithMods(k.vk, true, mods)
                    sendKeyWithMods(k.vk, false, mods)
                }
            }
        }
    }
    // 句柄失效（断开）时修饰键锁定态复位（防下次会话残留按下态）。
    LaunchedEffect(handle) {
        if (handle == 0L) {
            mods = 0
        }
    }
}

/** 粘滞修饰键小按钮（锁定 = 高亮实底）。 */
@Composable
private fun StickyModButton(label: String, latched: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = Modifier.padding(horizontal = 2.dp, vertical = 1.dp),
        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
        colors = if (latched) {
            ButtonDefaults.buttonColors()
        } else {
            ButtonDefaults.buttonColors(
                containerColor = Color(0xFF2A2A2A),
                contentColor = Color(0xFFCCCCCC),
            )
        },
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall)
    }
}

/** 点触功能键小按钮。 */
@Composable
private fun SmallKeyButton(label: String, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = Modifier.padding(horizontal = 2.dp, vertical = 1.dp),
        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = Color(0xFF2A2A2A),
            contentColor = Color(0xFFCCCCCC),
        ),
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall)
    }
}
