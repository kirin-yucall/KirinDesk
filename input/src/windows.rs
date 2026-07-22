use crate::capture::{InputEvent, MouseButton};

/// Inject a remote input event on Windows using SendInput.
#[cfg(target_os = "windows")]
pub fn inject_input(event: &InputEvent) -> Result<(), String> {
    use winapi::um::winuser::{
        SendInput, INPUT, INPUT_KEYBOARD, INPUT_MOUSE,
        KEYBDINPUT, MOUSEINPUT,
        MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP,
        MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
        MOUSEEVENTF_WHEEL,
        KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
        INPUT_u,
    };

    let mut inputs: Vec<INPUT> = Vec::new();

    match event {
        InputEvent::MouseMove { x, y } => {
            let abs_x = (x * 65535.0) as u32;
            let abs_y = (y * 65535.0) as u32;
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe { *u.mi_mut() = MOUSEINPUT {
                dx: abs_x as i32,
                dy: abs_y as i32,
                mouseData: 0,
                dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                time: 0,
                dwExtraInfo: 0,
            }; }
            inputs.push(INPUT { type_: INPUT_MOUSE, u });
        }
        InputEvent::MouseButton { button, pressed } => {
            let flags = match (button, pressed) {
                (MouseButton::Left, true) => MOUSEEVENTF_LEFTDOWN,
                (MouseButton::Left, false) => MOUSEEVENTF_LEFTUP,
                (MouseButton::Right, true) => MOUSEEVENTF_RIGHTDOWN,
                (MouseButton::Right, false) => MOUSEEVENTF_RIGHTUP,
                (MouseButton::Middle, true) => MOUSEEVENTF_MIDDLEDOWN,
                (MouseButton::Middle, false) => MOUSEEVENTF_MIDDLEUP,
            };
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe { *u.mi_mut() = MOUSEINPUT { dx: 0, dy: 0, mouseData: 0, dwFlags: flags, time: 0, dwExtraInfo: 0 }; }
            inputs.push(INPUT { type_: INPUT_MOUSE, u });
        }
        InputEvent::MouseWheel { delta } => {
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe { *u.mi_mut() = MOUSEINPUT { dx: 0, dy: 0, mouseData: *delta as u32, dwFlags: MOUSEEVENTF_WHEEL, time: 0, dwExtraInfo: 0 }; }
            inputs.push(INPUT { type_: INPUT_MOUSE, u });
        }
        InputEvent::Key { key, pressed } => {
            let mut u = unsafe { std::mem::zeroed::<INPUT_u>() };
            unsafe { *u.ki_mut() = KEYBDINPUT { wVk: *key, wScan: 0, dwFlags: if *pressed { 0 } else { KEYEVENTF_KEYUP }, time: 0, dwExtraInfo: 0 }; }
            inputs.push(INPUT { type_: INPUT_KEYBOARD, u });
        }
        InputEvent::Text { chars } => {
            for ch in chars.encode_utf16() {
                let mut u1 = unsafe { std::mem::zeroed::<INPUT_u>() };
                unsafe { *u1.ki_mut() = KEYBDINPUT { wVk: 0, wScan: ch, dwFlags: KEYEVENTF_UNICODE, time: 0, dwExtraInfo: 0 }; }
                inputs.push(INPUT { type_: INPUT_KEYBOARD, u: u1 });

                let mut u2 = unsafe { std::mem::zeroed::<INPUT_u>() };
                unsafe { *u2.ki_mut() = KEYBDINPUT { wVk: 0, wScan: ch, dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, time: 0, dwExtraInfo: 0 }; }
                inputs.push(INPUT { type_: INPUT_KEYBOARD, u: u2 });
            }
        }
    }

    unsafe {
        SendInput(inputs.len() as u32, inputs.as_mut_ptr(), std::mem::size_of::<INPUT>() as i32);
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn inject_input(_event: &InputEvent) -> Result<(), String> {
    Err("Input injection requires Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_serialization() {
        let event = InputEvent::MouseMove { x: 0.5, y: 0.5 };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("MouseMove"));
    }

    #[test]
    fn test_key_event() {
        let event = InputEvent::Key { key: 0x41, pressed: true };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""key":65"#));
    }

    #[test]
    fn test_mouse_button_roundtrip() {
        let event = InputEvent::MouseButton { button: MouseButton::Left, pressed: true };
        let json = serde_json::to_string(&event).unwrap();
        let deser: InputEvent = serde_json::from_str(&json).unwrap();
        match deser {
            InputEvent::MouseButton { button, pressed } => {
                assert_eq!(button, MouseButton::Left);
                assert!(pressed);
            }
            _ => panic!("Wrong variant"),
        }
    }
}
