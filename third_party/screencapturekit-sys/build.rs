//!
//! 上游无条件 `cargo:rustc-link-lib=framework=ScreenCaptureKit`，而该框架
//! macOS 12.3+ 才随 SDK 提供 —— 在 Mojave（10.14）CLT-only 环境链接失败：
//! `ld: framework not found ScreenCaptureKit`。
//!
//! 修复：探测目标 SDK 是否含 ScreenCaptureKit.framework
//! （`SDKROOT` 或 `xcrun --sdk macosx --show-sdk-path`）：
//! - 有 → 与上游完全一致（强链接，行为零变化；现代 macOS 主路径）；
//! - 无 → 不链接 ScreenCaptureKit（其余 7 个框架 10.14 均存在，照常链接）。
//!   此时上层（media crate）以 `cfg(kirin_sck_sdk)` 门控，不引用任何
//!   SC* 符号（未引用的 rlib 对象不会被链接器拉入），链接照常成功；
//!   运行时 `is_supported()` 恒 false 走降级（屏幕捕获不可用，其余功能不受影响）。
//! - 非 macOS 宿主交叉 check（如 Windows `cargo check --target x86_64-apple-darwin`）

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rustc-link-lib=framework=CoreMedia");
    println!("cargo:rustc-link-lib=framework=CoreVideo");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=CoreGraphics");
    println!("cargo:rustc-link-lib=framework=CoreImage");
    println!("cargo:rustc-link-lib=framework=ImageIO");

    if sdk_has_sck() {
        println!("cargo:rustc-link-lib=framework=ScreenCaptureKit");
        println!("cargo:rustc-cfg=sck_sdk_present");
    } else {
        println!(
            "cargo:warning=screencapturekit-sys: ScreenCaptureKit.framework not in target SDK — not linked (runtime degrade)"
        );
    }
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
}

/// 目标 macOS SDK 是否含 ScreenCaptureKit.framework。
fn sdk_has_sck() -> bool {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return true; // 非 macOS target 不会构建本 crate；防御性返回。
    }

    let sdk: Option<PathBuf> = match env::var_os("SDKROOT") {
        Some(s) if !s.is_empty() => Some(PathBuf::from(s)),
        _ => Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| PathBuf::from(s.trim())),
    };

    match sdk {
        Some(p) => p.join("System/Library/Frameworks/ScreenCaptureKit.framework").is_dir(),
        None => true, // 非 mac 宿主交叉 check：无 SDK 概念，按存在处理（不链接）。
    }
}
