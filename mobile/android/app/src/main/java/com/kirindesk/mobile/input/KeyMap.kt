package com.kirindesk.mobile.input

/**
 * Windows VK 虚拟键码常量（功能键条用；Rust 侧
 * `orchestration::vk_to_wire_key` 映射为 wire HID 判别式键码）。
 *
 * - **修饰键（Shift/Ctrl/Alt/Win）不再作为独立按键发送**——wire 键空间
 *   （`injector::Key`）无修饰键，修饰语义 = 键事件 modifiers 位标志
 *   （Kotlin 功能键条粘滞态 → `nativeSendKey2`）；
 * - **文本（含大写/Shift 符号/标点/中文/emoji）统一走 `nativeSendText`**
 *   （wire Text → 服务端 KEYEVENTF_UNICODE 逐码元注入）——wire 键空间
 *   无 OEM 标点，旧 VK+Shift 包裹路径对标点无效已废弃。
 */
object KeyMap {
    // ── 控制键（Windows VK；功能键条点触键用，均在 wire 键空间内） ──
    const val VK_BACK = 0x08        // Backspace
    const val VK_TAB = 0x09
    const val VK_RETURN = 0x0D      // Enter
    const val VK_CAPITAL = 0x14     // Caps Lock
    const val VK_ESCAPE = 0x1B
    const val VK_SPACE = 0x20
    const val VK_PRIOR = 0x21       // Page Up
    const val VK_NEXT = 0x22        // Page Down
    const val VK_END = 0x23
    const val VK_HOME = 0x24
    const val VK_LEFT = 0x25
    const val VK_UP = 0x26
    const val VK_RIGHT = 0x27
    const val VK_DOWN = 0x28
    const val VK_INSERT = 0x2D
    const val VK_DELETE = 0x2E
    const val VK_F1 = 0x70          // F1–F12 = 0x70..0x7B
    const val VK_F12 = 0x7B

    // 字母 A–Z = 0x41..0x5A、数字 0–9 = 0x30..0x39（与 ASCII 同值；
    // 软键盘文本路径已不走 VK——见类注释）。
}
