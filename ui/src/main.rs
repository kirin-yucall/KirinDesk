//! KirinDesk — P2P Remote Desktop
//!
//! Windows GUI application (egui) with CLI fallback.
//! On Windows, compile as a GUI subsystem app to hide the console window.
//! CLI mode (--cli flag) re-allocates a console for headless/server use.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    kirin_desk_ui::run();
}
