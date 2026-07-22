use serde::{Deserialize, Serialize};

/// Remote input event types — platform-independent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputEvent {
    /// Mouse move to absolute coordinates (0.0–1.0 normalized).
    MouseMove { x: f64, y: f64 },
    /// Mouse button press/release.
    MouseButton { button: MouseButton, pressed: bool },
    /// Mouse wheel scroll.
    MouseWheel { delta: i32 },
    /// Keyboard key press/release (virtual key code).
    Key { key: u16, pressed: bool },
    /// Text input (Unicode).
    Text { chars: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}
