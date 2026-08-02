//! 密钥存储后端抽象（S-05 / F-4 身份密钥存储改造，S-05a-1/3、S-05b-3）。
//!
//! # 背景（审计 F-4）
//!
//! 原 `ed25519.rs` 用 `SHA-256("kirindesk-identity-key:" ‖ device_id)` 派生
//! 加密密钥（device_id 公开 → 拿到文件即解出私钥，伪加密），且文件默认 0644。
//! S-05 改为**系统钥匙串优先**的统一后端抽象：
//!
//! ```text
//! Windows: DPAPI CryptProtectData（crypt32.dll，dlopen 方式，见 windows_dpapi.rs）
//! macOS:   已有 macos_keychain.rs（M12-MAC MAC-T006，本任务接线）
//! Linux:   secret-tool（libsecret CLI），失败自动降级到文件主密钥兜底
//! 兜底:    随机 32B 主密钥落盘 `identity.masterkey`（0600）——
//!          仅作无系统钥匙串环境的降级，明文语义见 `MasterKeyFileStore` 文档
//! ```
//!
//! # 与 R-13 的关系（跨计划）
//!
//! R13-S2（配置加密，M15-T005 密钥来源分层）将复用本模块的 [`KeyStore`] trait
//! ——trait 签名定稿于 S-05，R-13 合并后按 trait 接入即可。

use std::path::{Path, PathBuf};

use chacha20poly1305::KeyInit;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// 密钥存储后端错误。
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// 后端不可用 / 操作被系统拒绝（钥匙串锁、DPAPI 失败等）。
    #[error("keystore backend error: {0}")]
    Backend(String),
    /// 存储介质损坏（blob 被篡改、主密钥文件损坏等）。
    #[error("keystore storage corrupt: {0}")]
    Corrupt(String),
    /// 底层 I/O 错误。
    #[error("keystore I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// 统一密钥存储后端抽象（S-05a-1）。
///
/// 后端只做**存储介质**：以 `label` 为键存储/读取不透明密文（如 Ed25519
/// 私钥原始字节），不实现任何加密算法（加密统一走 `core/crypto/`）。
///
/// - [`set`](KeyStore::set)：幂等覆盖语义（已存在同 label 条目时覆盖）。
/// - [`get`](KeyStore::get)：条目不存在 → `Ok(None)`；存在但损坏 → `Err`。
/// - [`delete`](KeyStore::delete)：幂等（条目不存在也返回 `Ok`）。
///
/// 调用方（`IdentityManager::load_or_generate`）约定：**任何 `Err` 都视为
/// fail-closed**——不得据此静默生成新身份（F-4 修复要点）。
pub trait KeyStore: Send + Sync {
    /// 存储 `secret` 到 `label`（幂等覆盖）。
    fn set(&self, label: &str, secret: &[u8]) -> Result<(), KeyStoreError>;
    /// 读取 `label` 下的密文；不存在 → `Ok(None)`；损坏 → `Err`。
    fn get(&self, label: &str) -> Result<Option<Vec<u8>>, KeyStoreError>;
    /// 删除 `label` 条目（幂等）。
    fn delete(&self, label: &str) -> Result<(), KeyStoreError>;
}

/// 默认后端选择（优先级：DPAPI → Keychain → secret-tool → 文件主密钥兜底）。
///
/// `base_dir` 供文件类后端（DPAPI blob / 主密钥兜底）定位身份目录
/// （如 `~/.kirin_desk/identity/`）。
#[allow(unreachable_code)] // 平台分支 return 后，兜底行在当前平台不可达（Linux/macOS）
pub fn default_backend(base_dir: &Path) -> Box<dyn KeyStore> {
    #[cfg(target_os = "windows")]
    {
        if crate::crypto::windows_dpapi::DpapiKeyStore::available() {
            return Box::new(crate::crypto::windows_dpapi::DpapiKeyStore::new(
                base_dir.to_path_buf(),
            ));
        }
        tracing::warn!(
            target: "keystore",
            "Windows DPAPI unavailable; falling back to file-backed master-key store (degraded mode)"
        );
    }
    #[cfg(target_os = "macos")]
    {
        if crate::crypto::macos_keychain::MacosKeychain::available() {
            return Box::new(crate::crypto::macos_keychain::MacosKeychain);
        }
        tracing::warn!(
            target: "keystore",
            "macOS Keychain unavailable; falling back to file-backed master-key store (degraded mode)"
        );
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // secret-tool 内部按操作自动降级到文件主密钥兜底（见 LinuxKeyStore 文档）。
        return Box::new(linux_secret_tool::LinuxKeyStore::new(base_dir.to_path_buf()));
    }
    Box::new(MasterKeyFileStore::new(base_dir.to_path_buf()))
}

/// 私密文件写入（S-07 收口）：薄封装 `kirin_desk_utils::fsutil::write_private`
/// ——Unix 0600 + 父目录 0700 + O_NOFOLLOW + 原子替换（原占位实现已上收到
/// utils/src/fsutil.rs，本函数保留签名供 core 内既有调用点使用）。
pub(crate) fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    kirin_desk_utils::fsutil::write_private(path, data)
}

/// 0600 私有权限（S-05 兜底 / 备份文件用；S-07 收口到 utils）。
#[cfg(unix)]
pub(crate) fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    kirin_desk_utils::fsutil::set_private_permissions(path)
}

#[cfg(not(unix))]
pub(crate) fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    kirin_desk_utils::fsutil::set_private_permissions(path)
}

/// 将 label 清洗为安全文件名（非 `[A-Za-z0-9._-]` 字符替换为 `_`）。
pub(crate) fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ════════════════════════════════════════════════════════════════
// 兜底后端：文件主密钥（S-05a-3）
// ════════════════════════════════════════════════════════════════

/// 密文 blob 文件格式（JSON `{nonce, ciphertext}`，ChaCha20Poly1305，
/// 密钥 = `identity.masterkey` 中的随机 32B 主密钥）。
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedBlob {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// 纯本地兜底后端（S-05a-3）：**仅作无系统钥匙串环境的降级**。
///
/// 语义（计划原文"兜底路径边界"）：
/// - 随机 32B 主密钥落盘 `identity.masterkey`（0600）——主密钥是**随机**的，
///   不再由公开的 device_id 派生（F-4 伪加密根因消除）；
/// - 密文落盘 `identity.keystore.<label>.json`（0600，ChaCha20Poly1305
///   用主密钥加密）；
/// - 主密钥文件损坏（长度≠32B）→ `KeyStoreError::Corrupt`（调用方 fail-closed，
///   不得静默换身份）；blob 解密失败（篡改/主密钥失配）同理。
///
/// 降级语义：本后端比系统钥匙串弱（密钥材料以文件形式存在），但满足
/// "随机主密钥 + 0600" 的审计要求；有系统钥匙串的环境（DPAPI / Keychain /
/// secret-tool）不应走到本后端。
pub struct MasterKeyFileStore {
    dir: PathBuf,
}

impl MasterKeyFileStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn masterkey_path(&self) -> PathBuf {
        self.dir.join("identity.masterkey")
    }

    fn blob_path(&self, label: &str) -> PathBuf {
        self.dir
            .join(format!("identity.keystore.{}.json", sanitize_label(label)))
    }

    /// 读取主密钥（必须已存在；缺失说明存储不完整 → Corrupt）。
    fn read_masterkey(&self) -> Result<[u8; 32], KeyStoreError> {
        let bytes = std::fs::read(self.masterkey_path())?;
        bytes.try_into().map_err(|_| {
            KeyStoreError::Corrupt(
                "identity.masterkey damaged (expected 32 bytes); identity unrecoverable".into(),
            )
        })
    }

    /// 读取主密钥；不存在则生成随机 32B 并落盘（0600）。
    fn load_or_create_masterkey(&self) -> Result<[u8; 32], KeyStoreError> {
        match std::fs::read(self.masterkey_path()) {
            Ok(bytes) => bytes.try_into().map_err(|_| {
                KeyStoreError::Corrupt(
                    "identity.masterkey damaged (expected 32 bytes); refusing to overwrite".into(),
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                write_private_file(&self.masterkey_path(), &key)?;
                Ok(key)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn encrypt(&self, secret: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        let masterkey = self.load_or_create_masterkey()?;
        let key = Key::from_slice(&masterkey);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = secret.to_vec();
        cipher
            .encrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|e| KeyStoreError::Backend(format!("encrypt failed: {e}")))?;

        let blob = EncryptedBlob {
            nonce: nonce_bytes,
            ciphertext: buffer,
        };
        serde_json::to_vec(&blob)
            .map_err(|e| KeyStoreError::Backend(format!("serialize blob failed: {e}")))
    }
}

impl KeyStore for MasterKeyFileStore {
    fn set(&self, label: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        let blob = self.encrypt(secret)?;
        write_private_file(&self.blob_path(label), &blob)?;
        Ok(())
    }

    fn get(&self, label: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let path = self.blob_path(label);
        let blob_bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let blob: EncryptedBlob = serde_json::from_slice(&blob_bytes)
            .map_err(|e| KeyStoreError::Corrupt(format!("blob unreadable: {e}")))?;

        let masterkey = self.read_masterkey()?;
        let key = Key::from_slice(&masterkey);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&blob.nonce);

        let mut buffer = blob.ciphertext;
        cipher.decrypt_in_place(nonce, b"", &mut buffer).map_err(|_| {
            KeyStoreError::Corrupt(
                "identity.keystore blob undecryptable (tampered or masterkey mismatch); \
                 identity unrecoverable — do NOT regenerate"
                    .into(),
            )
        })?;
        Ok(Some(buffer))
    }

    fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        match std::fs::remove_file(self.blob_path(label)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

// ════════════════════════════════════════════════════════════════
// Linux：secret-tool（libsecret CLI）+ 文件主密钥降级（S-05b-3）
// ════════════════════════════════════════════════════════════════

/// Linux 后端：`secret-tool`（libsecret CLI）优先，**按操作自动降级**到
/// [`MasterKeyFileStore`]（"无环时降级路径可用，警告不阻断"）。
///
/// 为什么按操作降级而不是启动时探测：钥匙串状态会变化（解锁/锁定/守护进程
/// 启停），启动时探测出的结论在首次读写时可能已失效。因此：
/// - `get`：secret-tool 失败/找不到 → 回退文件兜底；
/// - `set`：secret-tool 失败 → 回退文件兜底（警告一次）；
/// - `delete`：两处都清。
///
/// 机密以 **base64** 编码存入 secret-tool（`lookup` 输出到 stdout，base64
/// 无换行歧义，`store` 从 stdin 读取）。
///
/// 说明：任务文档 §4 S-05b-3 的"强口令 + Argon2id"为可选项（"或"）；
/// 本实现走 libsecret CLI（计划原文"如走 libsecret 则无新依赖"），
/// 兜底即 §3 边界内的文件主密钥降级——不新增 argon2 依赖。
#[cfg(all(unix, not(target_os = "macos")))]
pub mod linux_secret_tool {
    use super::*;
    use base64::Engine as _;
    use std::io::Read;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// secret-tool 单次调用超时（防钥匙串解锁提示挂起启动流程）。
    const SECRET_TOOL_TIMEOUT: Duration = Duration::from_secs(10);

    /// 属性对：`kirindesk <label>`。
    fn attribute_args(label: &str) -> [&str; 2] {
        ["kirindesk", label]
    }

    /// 运行 `secret-tool`；成功 → `Ok(Some(stdout))`；退出码非零/超时/无法
    /// 启动 → `Err(原因)`（调用方据此降级，不阻断）。
    fn run_secret_tool(args: &[&str], stdin_data: Option<&[u8]>) -> Result<Option<Vec<u8>>, String> {
        let mut child = Command::new("secret-tool")
            .args(args)
            .stdin(if stdin_data.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn secret-tool: {e}"))?;

        if let (Some(mut stdin), Some(data)) = (child.stdin.take(), stdin_data) {
            // 写 stdin 后关闭（EOF）→ secret-tool 完成读取。
            let _ = stdin.write_all(data);
            let _ = stdin.flush();
        }

        // 后台线程排空 stdout/stderr（避免管道缓冲阻塞子进程）。
        let mut out_h = child.stdout.take().ok_or("no stdout")?;
        let mut err_h = child.stderr.take().ok_or("no stderr")?;
        let (tx, rx) = mpsc::channel::<(Vec<u8>, Vec<u8>)>();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let _ = out_h.read_to_end(&mut out);
            let _ = err_h.read_to_end(&mut err);
            let _ = tx.send((out, err));
        });

        // 轮询 try_wait 实现超时；超时后 kill（Child 句柄仍在主线程）。
        let deadline = Instant::now() + SECRET_TOOL_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    return Err("secret-tool timed out (keyring unlock prompt?)".into());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(format!("wait secret-tool: {e}")),
            }
        };

        let (out, err) = rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default();
        if !status.success() {
            return Err(format!(
                "secret-tool exit={:?}: {}",
                status.code(),
                String::from_utf8_lossy(&err).trim()
            ));
        }
        Ok(Some(out))
    }

    fn secret_tool_store(label: &str, secret: &[u8]) -> Result<(), String> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret);
        let mut args = vec!["store", "--label", "kirindesk-identity"];
        args.extend_from_slice(&attribute_args(label));
        run_secret_tool(&args, Some(b64.as_bytes()))?;
        Ok(())
    }

    fn secret_tool_lookup(label: &str) -> Result<Option<Vec<u8>>, String> {
        let mut args = vec!["lookup"];
        args.extend_from_slice(&attribute_args(label));
        match run_secret_tool(&args, None)? {
            Some(out) if out.is_empty() => Ok(None),
            Some(out) => {
                // 去掉工具可能追加的尾部换行后再 base64 解码。
                let trimmed = out
                    .strip_suffix(b"\n")
                    .or_else(|| out.strip_suffix(b"\r\n"))
                    .unwrap_or(&out);
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(trimmed)
                    .map_err(|e| format!("decode secret-tool output: {e}"))?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }

    fn secret_tool_clear(label: &str) {
        let mut args = vec!["clear"];
        args.extend_from_slice(&attribute_args(label));
        // 尽力而为：条目不存在 / 钥匙串锁定时忽略错误（delete 幂等语义）。
        let _ = run_secret_tool(&args, None);
    }

    /// Linux 后端（secret-tool 优先 + 文件主密钥降级）。
    pub struct LinuxKeyStore {
        file: MasterKeyFileStore,
    }

    impl LinuxKeyStore {
        pub fn new(dir: PathBuf) -> Self {
            Self {
                file: MasterKeyFileStore::new(dir),
            }
        }
    }

    impl KeyStore for LinuxKeyStore {
        fn set(&self, label: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
            match secret_tool_store(label, secret) {
                Ok(_) => Ok(()),
                Err(e) => {
                    tracing::warn!(
                        target: "keystore",
                        "secret-tool store failed ({e}); degrading to file-backed master-key store"
                    );
                    self.file.set(label, secret)
                }
            }
        }

        fn get(&self, label: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
            match secret_tool_lookup(label) {
                Ok(Some(secret)) => Ok(Some(secret)),
                Ok(None) => self.file.get(label),
                Err(e) => {
                    tracing::warn!(
                        target: "keystore",
                        "secret-tool lookup failed ({e}); degrading to file-backed master-key store"
                    );
                    self.file.get(label)
                }
            }
        }

        fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
            secret_tool_clear(label);
            self.file.delete(label)
        }
    }
}

// ════════════════════════════════════════════════════════════════
// 测试
// ════════════════════════════════════════════════════════════════

/// 内存 mock 后端（S-05c：trait 单测；也供 ed25519.rs 的 fail-closed /
/// 迁移单测驱动确定性后端）。
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryKeyStore {
    entries: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

#[cfg(test)]
impl MemoryKeyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl KeyStore for MemoryKeyStore {
    fn set(&self, label: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        self.entries
            .lock()
            .unwrap()
            .insert(label.to_string(), secret.to_vec());
        Ok(())
    }

    fn get(&self, label: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
        Ok(self.entries.lock().unwrap().get(label).cloned())
    }

    fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        self.entries.lock().unwrap().remove(label);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kirin_desk_keystore_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn memory_keystore_trait_ops() {
        let ks = MemoryKeyStore::new();
        assert!(ks.get("label-1").unwrap().is_none());
        ks.set("label-1", b"secret-bytes").unwrap();
        assert_eq!(ks.get("label-1").unwrap().unwrap(), b"secret-bytes");
        ks.set("label-1", b"overwritten").unwrap();
        assert_eq!(ks.get("label-1").unwrap().unwrap(), b"overwritten");
        ks.delete("label-1").unwrap();
        assert!(ks.get("label-1").unwrap().is_none());
        // 幂等删除
        ks.delete("label-1").unwrap();
    }

    #[test]
    fn masterkey_store_roundtrip() {
        let dir = temp_dir("roundtrip");
        let store = MasterKeyFileStore::new(dir.clone());
        assert!(store.get("dev-1").unwrap().is_none());

        let secret: Vec<u8> = (0..32u8).collect();
        store.set("dev-1", &secret).unwrap();
        assert_eq!(store.get("dev-1").unwrap().unwrap(), secret);

        // 主密钥文件存在且为 32 字节
        let mk = std::fs::read(dir.join("identity.masterkey")).unwrap();
        assert_eq!(mk.len(), 32);

        // 覆盖（幂等）
        store.set("dev-1", b"other").unwrap();
        assert_eq!(store.get("dev-1").unwrap().unwrap(), b"other");

        store.delete("dev-1").unwrap();
        assert!(store.get("dev-1").unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn masterkey_store_reuses_same_masterkey() {
        let dir = temp_dir("samekey");
        let store = MasterKeyFileStore::new(dir.clone());
        store.set("a", b"one").unwrap();
        let mk1 = std::fs::read(dir.join("identity.masterkey")).unwrap();
        store.set("b", b"two").unwrap();
        let mk2 = std::fs::read(dir.join("identity.masterkey")).unwrap();
        assert_eq!(mk1, mk2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn masterkey_store_corrupt_masterkey_fails_closed() {
        let dir = temp_dir("corruptmk");
        let store = MasterKeyFileStore::new(dir.clone());
        store.set("dev-1", b"secret").unwrap();

        // 破坏主密钥（长度≠32B）→ get 必须报 Corrupt（调用方 fail-closed）
        std::fs::write(dir.join("identity.masterkey"), b"too-short").unwrap();
        match store.get("dev-1") {
            Err(KeyStoreError::Corrupt(_)) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn masterkey_store_tampered_blob_fails_closed() {
        let dir = temp_dir("tamper");
        let store = MasterKeyFileStore::new(dir.clone());
        store.set("dev-1", b"secret").unwrap();

        let blob_path = dir.join(format!("identity.keystore.{}.json", sanitize_label("dev-1")));
        let mut blob = std::fs::read(&blob_path).unwrap();
        let mid = blob.len() / 2;
        blob[mid] ^= 0xff;
        std::fs::write(&blob_path, blob).unwrap();

        match store.get("dev-1") {
            Err(KeyStoreError::Corrupt(_)) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn masterkey_store_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let store = MasterKeyFileStore::new(dir.clone());
        store.set("dev-1", b"secret").unwrap();

        for name in ["identity.masterkey", &format!("identity.keystore.{}.json", sanitize_label("dev-1"))] {
            let mode = std::fs::metadata(dir.join(name)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{name} should be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_label_replaces_unsafe_chars() {
        assert_eq!(sanitize_label("kirindesk.identity.dev-1"), "kirindesk.identity.dev-1");
        assert_eq!(sanitize_label("a/b\\c d:e"), "a_b_c_d_e");
    }

    #[test]
    fn default_backend_constructs() {
        // 任何平台都应能构造默认后端（Windows=DPAPI / macOS=Keychain /
        // Linux=secret-tool+降级 / 其它=文件主密钥），不 panic、不 I/O。
        let dir = temp_dir("default_backend");
        let _ks = default_backend(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
