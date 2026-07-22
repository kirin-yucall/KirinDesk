pub mod capture;
pub mod windows;
pub mod linux;

pub use windows::inject_input;
pub use capture::InputEvent;
