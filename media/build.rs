//! media crate build script（P1B §T2.4）。
//!
//! 职责：仅在启用 `gpu-kernel` feature 且工具链可用时，构建并链接根级
//! `libkirin_gpu/`（静态库）；否则降级为 CPU-only。
//!
//! 设计目标（与 task_docs 一致）：**默认 `cargo build` 不依赖任何 C++
//! 工具链**——`gpu-kernel` feature 关闭时本脚本几乎是空操作，仅 emit
//! `rerun-if-changed`，保证全仓构建清洁。
//!
//! # 链接条件（全部满足才 emit `kirin_gpu_linked`）
//!
//! 1. `--features gpu-kernel`（[`CARGO_FEATURE_GPU_KERNEL`]）；
//! 2. `KIRIN_GPU_SKIP != 1`（未显式跳过）；
//! 3. `cmake` 在 PATH 中（或 `KIRIN_GPU_FORCE_LINK=1`）；
//! 4. Windows 上 `CARGO_CFG_TARGET_ENV == msvc`（D3D11 SDK 头要求）。
//!
//! 任一不满足 → 不 emit `kirin_gpu_linked`，`gpu_ffi::KgpuKernel::init`
//! 恒返回 `EncodeError::GpuKernel`，`tile_diff` 走 CPU 回退路径。
//!
//! [`CARGO_FEATURE_GPU_KERNEL`]: https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // 总是 rerun：libkirin_gpu 源变化或环境变量变化都重新评估。
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()));
    let workspace_root = manifest.parent().unwrap_or(Path::new("."));
    let kgpu_dir = workspace_root.join("libkirin_gpu");
    println!("cargo:rerun-if-changed={}/CMakeLists.txt", kgpu_dir.display());
    println!("cargo:rerun-if-changed={}/include", kgpu_dir.display());
    println!("cargo:rerun-if-changed={}/src", kgpu_dir.display());
    println!("cargo:rerun-if-env-changed=KIRIN_GPU_FORCE_LINK");
    println!("cargo:rerun-if-env-changed=KIRIN_GPU_SKIP");
    println!("cargo:rerun-if-env-changed=KIRIN_GPU_FFMPEG_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=KIRIN_GPU_FFMPEG_LIB_DIR");

    if !should_attempt_link() {
        return;
    }

    match build_and_link(&kgpu_dir) {
        Ok(()) => {
            println!("cargo:rustc-cfg=kirin_gpu_linked");
            println!("cargo:warning=libkirin_gpu: linked (gpu-kernel enabled)");
        }
        Err(e) => {
            println!("cargo:warning=libkirin_gpu: build/link failed ({e}) → CPU-only fallback");
        }
    }
}

/// 是否尝试构建链接。默认 false（feature off）；feature on + 工具链可用 → true。
fn should_attempt_link() -> bool {
    let feature_on = env::var_os("CARGO_FEATURE_GPU_KERNEL").is_some();
    let force_skip = env::var("KIRIN_GPU_SKIP").map(|v| v != "0").unwrap_or(false);
    let force_link = env::var("KIRIN_GPU_FORCE_LINK").map(|v| v != "0").unwrap_or(false);

    if force_skip {
        println!("cargo:warning=libkirin_gpu: KIRIN_GPU_SKIP=1 → CPU-only fallback");
        return false;
    }
    if !feature_on {
        // 默认路径：不打印（避免每次 cargo build 噪声）。
        return false;
    }

    // Windows：D3D11 SDK 头仅在 MSVC 下可用（mingw 的 windows.h 不带 d3d11.h）。
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "msvc" || force_link || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        // 非也 OK（Linux/macOS 桩 + cmake）。Windows 非 MSVC 要求 force_link。
    } else {
        println!(
            "cargo:warning=libkirin_gpu: Windows target_env={target_env} (need msvc) → CPU-only fallback"
        );
        return false;
    }

    // 探测 cmake。
    if which("cmake").is_none() && !force_link {
        println!("cargo:warning=libkirin_gpu: cmake not found in PATH → CPU-only fallback");
        return false;
    }
    true
}

/// 构建 libkirin_gpu 静态库并 emit 链接指令。
fn build_and_link(kgpu_dir: &Path) -> Result<(), String> {
    if !kgpu_dir.join("CMakeLists.txt").exists() {
        return Err(format!(
            "CMakeLists.txt not found at {}",
            kgpu_dir.display()
        ));
    }

    let out_dir = env::var("OUT_DIR").map_err(|e| e.to_string())?;
    let build_dir = PathBuf::from(&out_dir).join("kgpu_build");

    // configure
    let mut cfg = Command::new("cmake");
    cfg.arg("-S").arg(kgpu_dir);
    cfg.arg("-B").arg(&build_dir);
    cfg.arg("-DCMAKE_BUILD_TYPE=Release");
    // FFmpeg 头（hw_bridge 真实实现，R-15b）：默认自动探测仓库内
    // ffmpeg/ffmpeg-8.1.1-full_build-shared/ 的 dev 头（与捆绑 DLL 同版本
    // 的 GyanD 8.1.1 shared build，含 include/ + lib/）；显式 env
    // KIRIN_GPU_FFMPEG_INCLUDE_DIR 优先（可指向其它路径）。
    let ffmpeg_inc: Option<PathBuf> = match env::var("KIRIN_GPU_FFMPEG_INCLUDE_DIR") {
        Ok(inc) if !inc.is_empty() => Some(PathBuf::from(inc)),
        _ => {
            // 仓库内默认：<workspace>/ffmpeg/ffmpeg-8.1.1-full_build-shared/include。
            // workspace_root 是 main() 的局部变量，build_and_link 仅接收
            // kgpu_dir（= workspace_root/libkirin_gpu）——由 kgpu_dir.parent()
            // 推导即 workspace_root（R-15b 最终修法，2026-08-04）。
            let ws_root = kgpu_dir.parent().unwrap_or(Path::new("."));
            let root = ws_root
                .join("ffmpeg")
                .join("ffmpeg-8.1.1-full_build-shared");
            let inc = root.join("include");
            if inc.join("libavutil").join("hwcontext.h").is_file() {
                Some(inc)
            } else {
                None
            }
        }
    };
    if let Some(inc) = ffmpeg_inc {
        cfg.arg(format!("-DFFMPEG_INCLUDE_DIR={}", inc.display()));
        // 同 root 的 lib/（导入库/def——仅用于 CMake 定位 DLL 目录，不静态链接）。
        if let Some(lib) = inc.parent().map(|p| p.join("lib")) {
            if lib.join("avutil-60.def").is_file() || lib.join("avutil.lib").is_file() {
                cfg.arg(format!("-DFFMPEG_LIB_DIR={}", lib.display()));
            }
        }
    } else if let Ok(lib) = env::var("KIRIN_GPU_FFMPEG_LIB_DIR") {
        if !lib.is_empty() {
            cfg.arg(format!("-DFFMPEG_LIB_DIR={lib}"));
        }
    }
    run(&mut cfg)?;

    // build
    let mut build = Command::new("cmake");
    build.arg("--build").arg(&build_dir);
    build.arg("--config").arg("Release");
    build.arg("--parallel");
    run(&mut build)?;

    // 链接搜索路径：cmake 默认产物在 build_dir 内（lib/ 或 子配置目录）。
    // 加多个候选搜索路径，覆盖 MSVC (build_dir/Release/kirin_gpu.lib) 与
    // GNU (build_dir/libkirin_gpu.a)。
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!(
        "cargo:rustc-link-search=native={}",
        build_dir.join("Release").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        build_dir.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=kirin_gpu");

    // Windows：链接 D3D11 系统库（C++ 侧 #pragma comment(lib) 在 MSVC 生效，
    // 但为稳妥这里再显式 emit）。
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=dylib=d3d11");
        println!("cargo:rustc-link-lib=dylib=dxgi");
        println!("cargo:rustc-link-lib=dylib=d3dcompiler");
    }

    Ok(())
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let status = cmd
        .status()
        .map_err(|e| format!("failed to run {:?}: {e}", cmd))?;
    if !status.success() {
        return Err(format!("command failed: {status}"));
    }
    Ok(())
}

/// 在 PATH 中查找可执行文件。
fn which(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir
            .join(name)
            .with_extension(env::consts::EXE_EXTENSION);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
