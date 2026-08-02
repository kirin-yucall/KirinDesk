use serde::{Deserialize, Serialize};

/// 序列化捕获事件（bincode wire 格式，M9-T001）。
///
/// 注意：客户端捕获格式（本文件）与服务端注入管线格式
/// （[`crate::injector::InputEvent`]）是两套并列结构；本函数用于客户端
/// 捕获侧（测试/本地持久化等），**线上传输统一走 injector 格式**（见
/// `task_docs/共享层/M9_远程输入注入.md` 决策说明）。
pub fn serialize_input(event: &InputEvent) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(event)
}

/// 反序列化捕获事件（与 [`serialize_input`] 配对）。
pub fn deserialize_input(data: &[u8]) -> Result<InputEvent, bincode::Error> {
    bincode::deserialize(data)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_roundtrip_all_variants() {
        let events = [
            InputEvent::MouseMove { x: 0.25, y: 0.75 },
            InputEvent::MouseButton { button: MouseButton::Left, pressed: true },
            InputEvent::MouseButton { button: MouseButton::Right, pressed: false },
            InputEvent::MouseWheel { delta: -120 },
            InputEvent::Key { key: 0x41, pressed: false },
            InputEvent::Text { chars: "麒麟远程输入".into() },
        ];
        for ev in events {
            let data = serialize_input(&ev).expect("serialize");
            let back = deserialize_input(&data).expect("deserialize");
            assert!(matches!(&back, other if std::mem::discriminant(other) == std::mem::discriminant(&ev)));
        }
    }

    #[test]
    fn test_serialize_roundtrip_values() {
        let ev = InputEvent::MouseMove { x: 0.125, y: 0.875 };
        let data = serialize_input(&ev).expect("serialize");
        let back = deserialize_input(&data).expect("deserialize");
        assert!(matches!(back, InputEvent::MouseMove { x, y } if (x - 0.125).abs() < 1e-9 && (y - 0.875).abs() < 1e-9));

        let ev = InputEvent::Text { chars: "你好, KirinDesk!".into() };
        let data = serialize_input(&ev).expect("serialize");
        assert!(matches!(deserialize_input(&data).expect("deserialize"),
            InputEvent::Text { chars } if chars == "你好, KirinDesk!"));
    }

    #[test]
    fn test_deserialize_garbage_rejected() {
        assert!(deserialize_input(&[0xFF, 0x00, 0x01]).is_err());
    }
}
