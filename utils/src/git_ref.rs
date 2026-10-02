//
// 本文件在**两处编译**（单一事实源，防两处解析逻辑分叉）：
// - `kirin-desk-utils` crate（`lib.rs` `pub mod git_ref;`，含
//   `#[cfg(test)]` 单测——cargo test 不运行 build.rs 内测试，测试必须
//   落在 lib 侧才计入 workspace 门禁）；
// - `utils/build.rs`（`include!("src/git_ref.rs")`——build script 不能依赖
//   本 crate 的 lib（build script 先于 lib 编译执行），且其编译不启用
//   cfg(test)，测试模块在该处自动失效，仅内联函数体）。
//
// 机理（banner 冻结根因）：普通分支上 `git commit` 只重写
// `.git/refs/heads/<branch>`（symref 指向的 loose ref），**不改
// `.git/HEAD` 的 mtime** → 原 `rerun-if-changed=.git/HEAD` 不触发 →
// 增量构建不重跑 build.rs → 横幅 commit 冻结在旧值（波末出包实证：
// `91c59a7` 构建出 banner=4144626）。build.rs 对本函数解析出的 loose ref
// 补发 watch（loose ref 每次 commit 被重写、mtime 必变）→ 任何 commit
// 后首次构建必重跑。
//
// 注意：本文件被 `include!` 进 build.rs 中段（位于其它项之后），头部
// 不能用 `//!` 内层文档注释（会编译报错），故用 `//` 普通注释。

use std::path::{Component, Path, PathBuf};

/// 解析 `.git/HEAD` 文件内容。
///
/// - 符号引用（普通分支态，内容形如 `ref: refs/heads/<branch>`）→
///   返回分支 loose ref 路径 `<git_dir>/<refname>`；
/// - detached HEAD（内容为裸 sha）、未解析的 HEAD 或不可解析内容 →
///   `None`（这些形态下 `.git/HEAD` 文件本身在 checkout/切分支时被重写，
///   仅 watch HEAD 即足够）。
///
/// ref name 虽出自 git 自身写入，但该文件自磁盘读取，兜底仅解析
/// `refs/heads/<branch>` 形态（git 分支 symref 的唯一形态；tags/notes 等
/// 其它命名空间不解析——猜错会 watch 到被非 commit 操作重写的文件），
/// 并拒绝空分支名、绝对路径与 `..`/根分量（防异常内容把 watch 路径带出
/// `.git`，非真实威胁，纯防御；`RootDir` 显式判——Windows 上无盘符的
/// `/x` 不满足 `is_absolute()`）。
pub fn branch_ref_file_path(git_dir: &Path, head_content: &str) -> Option<PathBuf> {
    const BRANCH_PREFIX: &str = "refs/heads/";
    let ref_name = head_content.trim().strip_prefix("ref:")?.trim();
    if !ref_name.starts_with(BRANCH_PREFIX) || ref_name.len() == BRANCH_PREFIX.len() {
        return None;
    }
    let rel = Path::new(ref_name);
    if rel
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
        || rel.is_absolute()
    {
        return None;
    }
    Some(git_dir.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 普通分支（symref）态 → 解析到分支 loose ref 路径（含 git 实际写入
    /// 的尾部换行；多级分支名同径拼接）。
    #[test]
    fn branch_ref_symref_resolves_to_refs_path() {
        let git_dir = Path::new("/repo/.git");
        assert_eq!(
            branch_ref_file_path(git_dir, "ref: refs/heads/main\n"),
            Some(PathBuf::from("/repo/.git/refs/heads/main"))
        );
        assert_eq!(
            branch_ref_file_path(git_dir, "ref: refs/heads/feature/x"),
            Some(PathBuf::from("/repo/.git/refs/heads/feature/x"))
        );
    }

    /// detached HEAD（内容为裸 sha）→ None（checkout 时 HEAD 文件本身被
    /// 重写，仅 watch HEAD 即触发——本函数无需产出路径）。
    #[test]
    fn branch_ref_detached_head_is_none() {
        let git_dir = Path::new("/repo/.git");
        assert_eq!(
            branch_ref_file_path(git_dir, "dca2df4f33af49d07a1f80698d59587aad8e32b1\n"),
            None
        );
    }

    /// 不可解析/异常内容（空、ref name 缺失、非分支命名空间、空分支名、
    /// `..` 路径穿越、绝对/根路径）→ 一律 None，fail-soft 不影响构建。
    #[test]
    fn branch_ref_malformed_content_is_none() {
        let git_dir = Path::new("/repo/.git");
        assert_eq!(branch_ref_file_path(git_dir, ""), None);
        assert_eq!(branch_ref_file_path(git_dir, "ref:\n"), None);
        assert_eq!(branch_ref_file_path(git_dir, "ref: refs/tags/v1"), None);
        assert_eq!(branch_ref_file_path(git_dir, "ref: refs/heads/"), None);
        assert_eq!(branch_ref_file_path(git_dir, "ref: refs/heads/../../x"), None);
        assert_eq!(branch_ref_file_path(git_dir, "ref: ../../outside"), None);
        assert_eq!(branch_ref_file_path(git_dir, "ref: /abs/path"), None);
    }
}
