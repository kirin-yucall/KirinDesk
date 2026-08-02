//! 键鼠 crate：并列独立模块（不属于编码层 `media/encoder/`）。
//!
//! - [`capture`]：客户端键鼠事件捕获（客户端侧）。
//! - [`injector`]：服务端注入流水线（接收加密可靠流事件 → 平台 HID 注入）。
//! - [`windows`] / [`linux`] / [`macos`]：平台注入实现。
//! - [`lock`]：平台锁屏调用单一实现（M8-T020 特殊键 / M8-T019 隐私模式共用）。
//!
//! 安全约束：注入侧只消费已认证客户端经加密可靠流传来的事件，**不开裸 TCP/UDP 端口**。

pub mod capture;
pub mod injector;
pub mod lock;
pub mod windows;
pub mod linux;
pub mod macos;

// 客户端侧 API（保留，非破坏）。
pub use capture::InputEvent;
pub use windows::inject_input;

// 服务端注入侧 API（M8-T008_P1E / M8-T020）。
pub use injector::{InputInjector, InjectError, InputKind, Key, SpecialCombo, INPUT_PRIORITY};
pub use lock::lock_screen;
