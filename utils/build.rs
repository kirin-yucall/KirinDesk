//!
//! `git rev-parse --short HEAD`（**本地仓库命令，禁止联网**）→
//! `cargo:rustc-env=KIRIN_GIT_COMMIT`；失败（非 git 检出 / 无 git 可执行
//! 文件 / 空输出）→ 回退 `"unknown"`（fail-soft，不阻断构建——打包/
//! CI 无 .git 场景仍出包）。
//!
//! 消费方：`src/logging.rs` 启动 banner
//! 日志只有 `version=0.2.0`，用户双端部署无法判定各自构建号（复测对账
//! 困难）；commit 短哈希使双端日志自证构建，version skew 排查不再依赖
//! 口头确认。双端（客户端/被控端同二进制）同值可比对。
//!
//!
//! 原实现只有 `cargo:rerun-if-changed=.git/HEAD`（cargo 按**文件 mtime**
//! 判定）。但普通分支上 `git commit` 只重写 symref 指向的
//! `.git/refs/heads/<branch>`，**不改 `.git/HEAD` 的 mtime** → 增量构建不
//! 重跑本脚本 → `KIRIN_GIT_COMMIT` 冻结在旧 commit（波末出包实证：
//! `91c59a7` 构建出 banner=4144626，需 `touch utils/build.rs` 手动绕过才
//! 刷新）。
//!
//! 修复口径（双 watch，覆盖全部 HEAD 形态）：
//! - 恒 watch `.git/HEAD` 本身——detached HEAD（文件被重写为裸 sha）、
//!   切分支（文件被重写为新 ref）等形态下其 mtime 必变；文件不存在
//!   （非检出场景）时该指令无效，按包内其它变化重跑（开销=一次 git
//!   调用，可忽略），构建号恒定；
//! - HEAD 为符号引用（symref，普通分支态 `ref: refs/heads/<branch>`）时，
//!   经纯函数 [`branch_ref_file_path`] 解析出分支 loose ref 路径并**对该
//!   文件**补发 `cargo:rerun-if-changed`——loose ref 每次 commit 都被
//!   重写（ref 被 packed 后，下一次 commit 同样会重新落盘 loose ref），
//!   mtime 必变 → 任何 commit 后首次构建必重跑本脚本、取到新 commit。
//!
//! 纯函数 [`branch_ref_file_path`] 与 `src/git_ref.rs` 单一事实源（本
//! script 不能依赖本 crate lib，故 `include!`；其单测在 lib 侧
//! `#[cfg(test)]`——cargo test 不运行 build.rs 内测试）。端到端行为
//! （commit 后增量构建刷新 banner）以波末出包验证（banner commit =
//! 当前 HEAD）。

use std::process::Command;

// `kirin-desk-utils::git_ref` 单一事实源；含 `use std::path::{…}`）。
include!("src/git_ref.rs");

fn main() {
    let manifest = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()),
    );
    let git_dir = manifest.join("../.git");
    let git_head = git_dir.join("HEAD");

    // 恒 watch HEAD 本身（detached/切分支形态覆盖；非检出场景该指令
    // 无效，见模块头注释）。
    println!("cargo:rerun-if-changed={}", git_head.display());

    // 不改 `.git/HEAD` mtime（banner 冻结根因，见模块头）→ 对解析出的
    // loose ref 补发 watch：每次 commit 被重写、mtime 必变 → 任何 commit
    // 后首次构建必重跑本脚本。
    if let Ok(head_content) = std::fs::read_to_string(&git_head) {
        if let Some(refs_path) = branch_ref_file_path(&git_dir, &head_content) {
            println!("cargo:rerun-if-changed={}", refs_path.display());
        }
    }

    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=KIRIN_GIT_COMMIT={commit}");
}
