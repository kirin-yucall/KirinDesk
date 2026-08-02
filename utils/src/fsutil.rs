//! S-07（F-8）：私密文件写入工具 — 全仓敏感落盘点统一入口。
//!
//! [`write_private`] 是敏感数据（config / 身份密钥 / relay 私钥 / known_hosts /
//! 设备表 / 日志等）落盘的标准路径，保证：
//!
//! - **Unix**：新建文件 `mode(0o600)`（创建时 + 显式重设，免疫 umask）、
//!   父目录 `0700`、`O_NOFOLLOW`（经 `libc`，绝不跟随符号链接写入）；
//! - **Windows**：`std::fs::rename` = `MoveFileExW(MOVEFILE_REPLACE_EXISTING)`，
//!   同卷原子替换（S-15 起统一，不再先删旧文件）；
//!   权限依赖用户目录 ACL —— 所有敏感落点均在 `~/.kirin_desk` 用户目录内，
//!   系统级 ACL 收紧不在本任务范围（见 S-07 任务文档 §4）。
//!
//! 写入采用「同目录随机名临时文件 → `fsync`（Unix）→ `rename` 原子替换」：
//! 崩溃不产生半截目标文件，已确认数据（含 0600 元数据）先落盘再替换，断电
//! 也不会出现「rename 已生效但内容为空」；`create_new` + `O_NOFOLLOW`
//! 组合保证绝不触碰既有条目或符号链接目标（防 symlink 欺骗导致截断任意
//! 用户文件）。
//!
//! 收口：S-05 遗留的 `core/src/crypto/keystore.rs::write_private_file` /
//! `set_private_permissions`（占位实现，注释"待 S-07 write_private 收口"）
//! 在 S-07 合并后薄封装到本模块（见 keystore.rs）。

use std::io::{Read, Write};
use std::path::Path;

/// 私密文件写入（S-07a）：Unix `0600` + 父目录 `0700` + `O_NOFOLLOW`；
/// Windows 依赖用户目录 ACL（见模块文档）。
///
/// 原子替换语义：先写同目录随机名临时文件（0600），**Unix 下 `fsync` 落盘后**
/// （S-15 / F-20）再 `rename` 到目标路径——既有文件被原子替换，读取方永远
/// 看不到半截内容，且目标文件内容已持久化后才生效。
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            tighten_dir_0700(parent)?;
        }
    }
    let tmp = temp_sibling(path);
    let result = (|| -> std::io::Result<()> {
        let mut file = open_tmp_exclusive(&tmp)?;
        file.write_all(data)?;
        file.flush()?;
        // 显式 0600（免疫 umask 对 mode(0o600) 的位掩码；Windows 无操作）。
        set_private_permissions(&tmp)?;
        // S-15 (F-20): fsync 临时文件——数据（含 0600 元数据）落盘后再 rename，
        // 断电/崩溃不会出现「rename 已生效但内容未落盘」的空目标文件。
        // Unix 专用；Windows 保持现状（依赖系统缓冲，无此保证，见模块文档）。
        #[cfg(unix)]
        file.sync_all()?;
        // 原子替换：Unix 为 rename(2)；Windows 上 std::fs::rename 对应
        // MoveFileExW + MOVEFILE_REPLACE_EXISTING，同卷直接原子覆盖——
        // 无需先删旧文件（先删后换存在「目标短暂缺失」窗口，读方可见 torn；
        // 2026-08-02 S-15 并发原子性测试暴露后移除）。
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// 私密文件读取（S-23 / F-28）：Unix 下 `O_NOFOLLOW` 打开——**绝不跟随
/// 符号链接**读取（日志/配置可被 symlink 指向任意文件 → 拒绝打开）；
/// Windows 无等价打开标志（依赖用户目录 ACL，见模块文档）。
///
/// 写入侧已由 [`write_private`] 的 O_NOFOLLOW + 原子替换覆盖；本函数补
/// 读侧漏洞（S-07 后补漏项）。
pub fn read_private(path: &Path) -> std::io::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).custom_flags(libc::O_NOFOLLOW);
        let mut file = opts.open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        return Ok(buf);
    }
    #[cfg(not(unix))]
    {
        std::fs::read(path)
    }
}

/// 同目录随机名临时文件（`<name>.tmp.<16 位十六进制>`）——随机后缀使攻击者
/// 无法预置条目，配合 `create_new` 保证打开即独占（崩溃残留不阻塞重试）。
fn temp_sibling(path: &Path) -> std::path::PathBuf {
    use rand::Rng;
    let suffix: u64 = rand::rngs::OsRng.gen();
    let name = path
        .file_name()
        .map(|n| format!("{}.tmp.{:016x}", n.to_string_lossy(), suffix))
        .unwrap_or_else(|| format!("tmp.{:016x}", suffix));
    path.with_file_name(name)
}

/// 独占创建临时文件：`create_new`（既有项——含符号链接——直接拒绝）+
/// Unix `O_NOFOLLOW`（双保险，经 libc）。
#[cfg(unix)]
fn open_tmp_exclusive(tmp: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    opts.open(tmp)
}

#[cfg(not(unix))]
fn open_tmp_exclusive(tmp: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    opts.open(tmp)
}

/// Unix：父目录收紧 `0700`（尽力而为——非自有目录（如 `/tmp`）写入场景
/// 不因 chmod 失败而中断；应用自有目录（`~/.kirin_desk` 等）恒可收紧）。
#[cfg(unix)]
fn tighten_dir_0700(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(e) => Err(e),
    }
}

/// 显式 `0600` 权限（Unix）；Windows 无操作（用户目录 ACL 依赖，见模块文档）。
#[cfg(unix)]
pub fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn set_private_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 每测试独立根目录（并行测试互不干扰）。
    fn temp_root(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "kirin_desk_fsutil_{}_{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn write_private_roundtrip_and_creates_parent() {
        let root = temp_root("roundtrip");
        let path = root.join("nested/deep/file.key");
        write_private(&path, b"secret-bytes").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"secret-bytes");
        // 无临时文件残留（成功路径 rename 已清走）
        let leftovers: Vec<_> = std::fs::read_dir(root.join("nested/deep"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "no tmp leftovers after success");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_private_overwrites_existing() {
        let root = temp_root("overwrite");
        let path = root.join("file.key");
        write_private(&path, b"first").unwrap();
        write_private(&path, b"second-longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-longer");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_private_empty_data() {
        let root = temp_root("empty");
        let path = root.join("empty.key");
        write_private(&path, b"").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_unix_perms_0600_0700() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root("perms");
        // 父目录由 write_private 新建（而非预建）→ 收紧 0700 可断言。
        let path = root.join("private_dir/key");
        write_private(&path, b"data").unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600, "file must be 0600");
        let dir_mode = std::fs::metadata(root.join("private_dir"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "parent dir must be 0700");

        // 覆盖写后权限保持 0600（rename 换入的新 inode 同样 0600）
        write_private(&path, b"data2").unwrap();
        let mode2 = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode2 & 0o777, 0o600, "overwrite keeps 0600");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn set_private_permissions_sets_0600() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root("setperm");
        let path = root.join("file.key");
        std::fs::write(&path, b"x").unwrap();
        // 初始为 umask 默认（非 0600）→ 收紧后必须 0600
        set_private_permissions(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// S-23 (F-28)：`read_private` O_NOFOLLOW —— symlink 指向任意文件 →
    /// 拒绝打开（不跟随）；普通文件正常读取。
    #[cfg(unix)]
    #[test]
    fn read_private_rejects_symlink() {
        let root = temp_root("nofollow");
        let target = root.join("victim.txt");
        std::fs::write(&target, b"secret").unwrap();
        let link = root.join("config.link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // symlink → 拒绝（O_NOFOLLOW）。
        let err = read_private(&link).expect_err("symlink must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        // 普通文件 → 正常读取。
        assert_eq!(read_private(&target).unwrap(), b"secret");
        let _ = std::fs::remove_dir_all(&root);
    }
}
