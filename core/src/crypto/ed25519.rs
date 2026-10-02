use chacha20poly1305::AeadInPlace;
use chacha20poly1305::KeyInit;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::crypto::keystore::{default_backend, KeyStore, KeyStoreError};

/// Error types for Ed25519 operations.
#[derive(Debug, thiserror::Error)]
pub enum Ed25519Error {
    #[error("Failed to generate key pair")]
    GenerationFailed,
    #[error("Invalid private key data")]
    InvalidPrivateKey,
    #[error("Invalid public key data: {0}")]
    InvalidPublicKey(String),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    /// S-05 (F-4) fail-closed：身份存储存在但损坏/不可解密，或曾配发的
    /// 身份存储丢失——**拒绝启动，不静默生成新身份**。
    #[error("Identity storage corrupt or missing: {0} — refusing to start with a new identity (no silent regeneration)")]
    CorruptIdentity(String),
    /// S-05 (F-4)：密钥存储后端失败（钥匙串/DPAPI/兜底后端）。
    #[error("Key store error: {0}")]
    KeyStore(#[from] KeyStoreError),
}

/// 自定义加密存储格式（R-20b：**非 PKCS#8**，宣称与实现一致）。
///
/// 这是本项目自有的「自定义加密存储（AEAD + AAD 上下文）」格式，**不实现
/// 真 PKCS#8**（避免无谓复杂度，审计方案①）：
/// - JSON `{nonce, ciphertext}`：ChaCha20Poly1305 AEAD 加密后的 Ed25519 私钥
///   原始字节（32B）；当前 AAD 为空字节串（`b""`，见 `save`/`load`），
///   密钥由 `derive_identity_key`（SHA-256(device_id)）派生；
/// - 该格式现仅作 **legacy 迁移源**（`try_migrate_legacy`）——新存储走
///   [`KeyStore`](crate::crypto::keystore) 后端（DPAPI / Keychain / secret-tool）。
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedPrivateKey {
    /// Nonce used for ChaCha20Poly1305 encryption.
    nonce: [u8; 12],
    /// Encrypted private key bytes.
    ciphertext: Vec<u8>,
}

/// Identity key manager for Ed25519 long-term identity keys.
///
/// Each device generates one Ed25519 key pair at first boot.
/// The private key is stored via the [`KeyStore`] backend（S-05：系统钥匙串 /
/// DPAPI / secret-tool，兜底为随机主密钥文件）；`key_path` 保留为旧格式
/// 文件路径（迁移检测与配发标记定位用）。公钥上传至 DNS TXT 记录供对端验证。
// R-03 (R03-S1): Clone 供重连上下文（Arc<IdentityManager>）与原连接路径复用。
#[derive(Clone)]
pub struct IdentityManager {
    /// Ed25519 signing key (private key).
    signing_key: SigningKey,
    /// Ed25519 verifying key (public key).
    verifying_key: VerifyingKey,
    /// Legacy 加密文件路径（S-05 迁移/标记定位；密钥本体在 KeyStore 后端）。
    key_path: PathBuf,
}

impl std::fmt::Debug for IdentityManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityManager")
            .field("verifying_key", &self.verifying_key.to_bytes())
            .field("key_path", &self.key_path)
            .finish_non_exhaustive()
    }
}

impl IdentityManager {
    /// Generate a new Ed25519 identity key pair.
    pub fn generate(key_path: PathBuf) -> Result<Self, Ed25519Error> {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        secret_bytes.zeroize();

        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
            key_path,
        })
    }

    /// Save the private key encrypted to disk using ChaCha20Poly1305.
    pub fn save(&self, encryption_key: &[u8; 32]) -> Result<(), Ed25519Error> {
        let key_bytes = self.signing_key.to_bytes();

        let key = Key::from_slice(encryption_key);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut buffer = key_bytes.to_vec();
        cipher
            .encrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|e| Ed25519Error::Encryption(e.to_string()))?;

        let encrypted = EncryptedPrivateKey {
            nonce: nonce_bytes,
            ciphertext: buffer,
        };

        let json = serde_json::to_string(&encrypted)
            .map_err(|e| Ed25519Error::Serialization(e.to_string()))?;

        // S-07 (F-8): 经 write_private 落盘（0600/0700/O_NOFOLLOW + 原子替换）。
        crate::crypto::keystore::write_private_file(&self.key_path, json.as_bytes())?;

        Ok(())
    }

    /// Load the private key from encrypted disk storage.
    pub fn load(key_path: PathBuf, encryption_key: &[u8; 32]) -> Result<Self, Ed25519Error> {
        let json = std::fs::read_to_string(&key_path)?;
        let encrypted: EncryptedPrivateKey =
            serde_json::from_str(&json).map_err(|e| Ed25519Error::Serialization(e.to_string()))?;

        let key = Key::from_slice(encryption_key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let mut buffer = encrypted.ciphertext;
        cipher
            .decrypt_in_place(nonce, b"", &mut buffer)
            .map_err(|_| Ed25519Error::Encryption("decryption failed".to_string()))?;

        let key_array: [u8; 32] = buffer
            .try_into()
            .map_err(|_| Ed25519Error::InvalidPrivateKey)?;
        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
            key_path,
        })
    }

    /// Sign a message with the private key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against the public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(message, signature).is_ok()
    }

    /// Verify a signature for a given public key (static method).
    pub fn verify_with_key(
        public_key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> bool {
        public_key.verify(message, signature).is_ok()
    }

    /// Get the public key (VerifyingKey).
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the public key encoded as Base64 (for DNS TXT records).
    pub fn public_key_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.verifying_key.to_bytes())
    }

    /// Parse a Base64-encoded Ed25519 public key.
    pub fn parse_public_key(base64_key: &str) -> Result<VerifyingKey, Ed25519Error> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|e| Ed25519Error::InvalidPublicKey(e.to_string()))?;

        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Ed25519Error::InvalidPublicKey("expected 32 bytes".to_string()))?;

        VerifyingKey::from_bytes(&array).map_err(|e| Ed25519Error::InvalidPublicKey(e.to_string()))
    }

    /// Get the signing key reference.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Load the device identity, or generate + persist if this is a fresh install.
    ///
    /// S-05 (F-4) fail-closed 语义：
    /// - 旧格式文件 `ed25519.json` 存在 → 自动迁移到系统钥匙串后端
    ///   （DPAPI / Keychain / secret-tool），**先写新后端并读回验证、再备份原文件**
    ///   （失败回退不覆盖，计划 §5 风险 3）；
    /// - 文件存在但损坏 / 不可解密 → **M8-T031 未配发残留恢复**：仅当后端无
    ///   身份且从未配发（无 `identity.provisioned` 标记）时，备份损坏文件为
    ///   `ed25519.json.corrupt.<ts>` 后全新生成（与"全新安装"同语义）；
    ///   曾配发或后端已有身份 → 维持 fail-closed / 后端优先（S-05 不放松）；
    /// - 存储全部丢失但曾配发过身份（`identity.provisioned` 标记）→ 拒绝启动；
    /// - 全新安装（无文件、无后端条目、无标记）→ 生成并持久化。
    pub fn load_or_generate(key_path: PathBuf, device_id: &str) -> Result<Self, Ed25519Error> {
        let base_dir = key_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let keystore = default_backend(&base_dir);
        Self::load_or_generate_with(keystore.as_ref(), key_path, device_id)
    }

    /// fail-closed 加载（内部；测试用内存 mock 后端驱动，全平台确定性）。
    fn load_or_generate_with(
        keystore: &dyn KeyStore,
        key_path: PathBuf,
        device_id: &str,
    ) -> Result<Self, Ed25519Error> {
        let label = identity_label(device_id);
        let marker = provision_marker_path(&key_path);

        // 1) 旧格式文件存在。
        if key_path.exists() {
            if !key_path.is_file() {
                return Err(fail_corrupt(format!(
                    "identity path {key_path:?} exists but is not a regular file"
                )));
            }
            match Self::try_migrate_legacy(&key_path, device_id, keystore, &label) {
                // 迁移成功 → 既有路径（原文件已备份，密钥已入后端）。
                Ok(secret) => {
                    ensure_marker_has_label(&marker, &label)?;
                    return Self::from_secret(secret, key_path);
                }
                // M8-T031: 迁移失败（损坏/不可解密）→ 评估"未配发残留恢复"：
                // 后端已有身份 → 忽略损坏旧文件，用后端身份继续（警告 + 审计）；
                // 曾配发过 → 保持 fail-closed，不生成；
                // 从未配发（无后端条目 + 无标记）→ 备份残留文件后走全新生成路径
                // （与"全新安装"同语义）。安全边界（S-05 不放松）：恢复只对
                // "从未配发 + 文件不可用"的残留生效，攻击者植入垃圾文件最多
                // 触发重新生成新身份（同全新安装），不会绕过任何凭据校验。
                Err(migrate_err) => {
                    tracing::warn!(
                        target: "identity",
                        "legacy identity migration failed for {key_path:?}: {migrate_err}"
                    );
                    match keystore.get(&label) {
                        Ok(Some(secret)) => {
                            tracing::warn!(
                                target: "identity",
                                "legacy identity file {key_path:?} is unusable but keystore \
                                 backend already holds {label:?}; ignoring stale legacy file \
                                 (M8-T031)"
                            );
                            audit_identity_recovered(&format!(
                                "path={key_path:?} label={label:?} action=used_keystore_identity"
                            ));
                            if let Err(e) = ensure_marker_has_label(&marker, &label) {
                                tracing::warn!(
                                    target: "identity",
                                    "identity recovered from keystore but provision marker could \
                                     not be updated: {e}"
                                );
                            }
                            return Self::from_secret(secret, key_path);
                        }
                        Ok(None) => {}
                        // fail-closed：后端故障不得作为换身份的理由。
                        Err(e) => return Err(e.into()),
                    }
                    if marker_has_label(&marker, &label)? {
                        return Err(fail_corrupt(format!(
                            "legacy identity file {key_path:?} exists but cannot be decrypted \
                             (device_id changed or file damaged) and identity {label:?} was \
                             previously provisioned; refusing to generate a new identity"
                        )));
                    }
                    // 从未配发 = 过期残留：备份损坏文件（0600）后走全新生成路径
                    // （生成 + 落 keystore + 标记，与"全新安装"同语义）。
                    if let Err(e) = crate::crypto::keystore::set_private_permissions(&key_path) {
                        tracing::warn!(
                            target: "identity",
                            "cannot set private permissions on {key_path:?} before backup: {e}"
                        );
                    }
                    let backup = corrupt_backup_path(&key_path);
                    std::fs::rename(&key_path, &backup)?;
                    tracing::warn!(
                        target: "identity",
                        "undecryptable legacy identity file {key_path:?} is an unprovisioned \
                         leftover (M8-T031); backed up to {backup:?} and generating a new identity"
                    );
                    audit_identity_recovered(&format!(
                        "path={key_path:?} label={label:?} action=generated_new backup={backup:?}"
                    ));
                }
            }
        }

        // 2) 后端已有身份 → 直接使用（并补齐配发标记，幂等）。
        match keystore.get(&label) {
            Ok(Some(secret)) => {
                if let Err(e) = ensure_marker_has_label(&marker, &label) {
                    tracing::warn!(
                        target: "identity",
                        "identity recovered from keystore but provision marker could not be updated: {}",
                        e
                    );
                }
                return Self::from_secret(secret, key_path);
            }
            Ok(None) => {}
            // fail-closed：后端故障不得作为换身份的理由。
            Err(e) => return Err(e.into()),
        }

        // 3) 曾配发过身份但存储全部丢失 → 拒绝启动，不静默换身份。
        if marker_has_label(&marker, &label)? {
            return Err(fail_corrupt(format!(
                "identity storage for {label:?} is missing or deleted (provision marker present); \
                 refusing to generate a new identity"
            )));
        }

        // 4) 全新安装：生成 + 落库（成功才返回）+ 配发标记。
        let id = Self::generate(key_path)?;
        keystore.set(&label, &id.signing_key().to_bytes())?;
        ensure_marker_has_label(&marker, &label)?;
        Ok(id)
    }

    /// 迁移向导：检测旧格式（JSON `{nonce,ciphertext}`，ChaCha20Poly1305 +
    /// device_id 派生密钥，R-20 命名：自定义加密存储）并迁移到新后端，
    /// 返回解出的私钥字节。
    ///
    /// 顺序（计划 §5 风险 3：失败回退不覆盖原文件）：
    /// 1. 读 + 解密旧文件（不落盘）；
    /// 2. `keystore.set` 写入新后端并读回验证；
    /// 3. 原文件先置 0600 再改名为 `ed25519.json.bak.<ts>`（备份保留，可删）。
    /// 任何一步失败 → 原文件原样保留，下次启动重试。
    ///
    /// M8-T031: 失败返回**普通错误**（不在此 fail-closed）——是否 fail-closed
    /// 由 `load_or_generate_with` 依据"是否曾配发"统一裁决。
    fn try_migrate_legacy(
        key_path: &Path,
        device_id: &str,
        keystore: &dyn KeyStore,
        label: &str,
    ) -> Result<Vec<u8>, Ed25519Error> {
        let enc_key = derive_identity_key(device_id);
        let legacy = Self::load(key_path.to_path_buf(), &enc_key).map_err(|e| {
            Ed25519Error::Encryption(format!(
                "legacy identity file {key_path:?} exists but cannot be decrypted \
                 (device_id changed or file damaged): {e}"
            ))
        })?;
        let key_array = legacy.signing_key().to_bytes();

        // 先写新后端，读回验证通过后才动原文件。
        keystore.set(label, &key_array)?;
        match keystore.get(label) {
            Ok(Some(verify)) if verify == key_array => {}
            Ok(_) => {
                return Err(Ed25519Error::Encryption(format!(
                    "migration read-back verification failed for {label:?}; \
                     original file {key_path:?} left untouched"
                )))
            }
            Err(e) => return Err(Ed25519Error::KeyStore(e)),
        }

        // 备份（改名保留，0600），随后原路径不再保存可逆私钥。
        crate::crypto::keystore::set_private_permissions(key_path)?;
        let backup = legacy_backup_path(key_path);
        std::fs::rename(key_path, &backup)?;
        tracing::info!(
            target: "identity",
            "identity migrated to keystore backend {label}; legacy file backed up to {backup:?} \
             (can be deleted once the new backend is verified)"
        );
        Ok(key_array.to_vec())
    }

    /// 从后端返回的私钥字节构造身份（长度非法 → fail-closed）。
    fn from_secret(secret: Vec<u8>, key_path: PathBuf) -> Result<Self, Ed25519Error> {
        let key_array: [u8; 32] = secret
            .try_into()
            .map_err(|_| fail_corrupt("keystore returned key material of invalid length".into()))?;
        let signing_key = SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
            key_path,
        })
    }

    /// Default identity file path: ~/.kirin_desk/identity/ed25519.json
    pub fn default_path() -> Result<PathBuf, Ed25519Error> {
        let home = dirs_next::home_dir().ok_or_else(|| {
            Ed25519Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no home dir",
            ))
        })?;
        Ok(home
            .join(".kirin_desk")
            .join("identity")
            .join("ed25519.json"))
    }
}

/// Derive a 32-byte encryption key from a device ID.
/// 仅用于旧格式（legacy）文件读取/迁移（S-05：新存储走 KeyStore 后端，
/// 不再用 device_id 派生密钥——F-4 伪加密根因）。
fn derive_identity_key(device_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"kirindesk-identity-key:");
    hasher.update(device_id.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// ════════════════════════════════════════════════════════════════
// S-05 (F-4)：KeyStore 接线辅助
// ════════════════════════════════════════════════════════════════

/// S-05：身份在后端中的 label（macOS Keychain 的 service+account 亦用此键）。
fn identity_label(device_id: &str) -> String {
    format!("kirindesk.identity.{device_id}")
}

/// 配发标记：`<identity_dir>/identity.provisioned`，JSON
/// `{"labels":["<label>", ...]}`。用于区分"全新安装"与"身份存储被删除"
/// （fail-closed：拒绝启动，不静默换身份）。
fn provision_marker_path(key_path: &Path) -> PathBuf {
    key_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("identity.provisioned")
}

/// 迁移备份路径：`<name>.bak.<unix_ts>`（时间戳避免覆盖历史备份）。
fn legacy_backup_path(key_path: &Path) -> PathBuf {
    backup_path(key_path, "bak")
}

/// M8-T031: 未配发残留备份路径：`<name>.corrupt.<unix_ts>`（损坏文件备份
/// 保留，可删；时间戳避免覆盖历史备份）。
fn corrupt_backup_path(key_path: &Path) -> PathBuf {
    backup_path(key_path, "corrupt")
}

/// 共享备份路径构造：`<name>.<tag>.<unix_ts>`。
fn backup_path(key_path: &Path, tag: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = key_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "ed25519.json".to_string());
    key_path.with_file_name(format!("{name}.{tag}.{ts}"))
}

/// M8-T031: 身份凭证恢复审计（AuditLogger 独立打开；失败仅 warn，
/// 不影响主流程——恢复是罕见一次性事件，开销可忽略）。
fn audit_identity_recovered(detail: &str) {
    use kirin_desk_utils::audit::{AuditEvent, AuditLogger};
    if let Ok(mut logger) = AuditLogger::open_default() {
        if let Err(e) = logger.record(AuditEvent::IdentityRecovered, detail) {
            tracing::warn!(target: "identity", "identity recovery audit write failed: {e}");
        }
    }
}

/// fail-closed 告警 + 错误构造（审计告警走 tracing::error，身份不可静默更换）。
fn fail_corrupt(msg: String) -> Ed25519Error {
    tracing::error!(
        target: "identity",
        "S-05 fail-closed: {} — refusing to generate a new identity",
        msg
    );
    Ed25519Error::CorruptIdentity(msg)
}

/// 配发标记是否包含该 label（文件不存在 → false；解析失败 → fail-closed）。
fn marker_has_label(marker: &Path, label: &str) -> Result<bool, Ed25519Error> {
    let content = match std::fs::read_to_string(marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(Ed25519Error::Io(e)),
        Ok(c) => c,
    };
    let data: ProvisionMarker = serde_json::from_str(&content)
        .map_err(|e| fail_corrupt(format!("provision marker {marker:?} malformed: {e}")))?;
    Ok(data.labels.iter().any(|l| l == label))
}

/// 确保配发标记包含该 label（缺失则追加；幂等）。
fn ensure_marker_has_label(marker: &Path, label: &str) -> Result<(), Ed25519Error> {
    let mut data = match std::fs::read_to_string(marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ProvisionMarker { labels: Vec::new() }
        }
        Err(e) => return Err(Ed25519Error::Io(e)),
        Ok(content) => serde_json::from_str(&content)
            .map_err(|e| fail_corrupt(format!("provision marker {marker:?} malformed: {e}")))?,
    };
    if data.labels.iter().any(|l| l == label) {
        return Ok(());
    }
    data.labels.push(label.to_string());
    let json =
        serde_json::to_string(&data).map_err(|e| Ed25519Error::Serialization(e.to_string()))?;
    crate::crypto::keystore::write_private_file(marker, json.as_bytes())?;
    Ok(())
}

/// 配发标记内容（S-05）。
#[derive(Debug, Serialize, Deserialize)]
struct ProvisionMarker {
    labels: Vec<String>,
}

/// 公钥指纹（M15 / SRV-SEC-KH-003）：base64 公钥 → SHA-256 → 小写十六进制、
/// 每 4 字符冒号分组（如 `a1b2:c3d4:...`，64 位十六进制 = 16 组）。
///
/// 与 `kirin-desk-utils::known_hosts::fingerprint` 算法一致（两侧均以
/// base64 公钥为输入），用于服务端返回指纹（`HandshakeResponse.server_fingerprint`）
/// 与客户端 known_hosts 指纹比对。
pub fn fingerprint(public_key_base64: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key_base64.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join(":")
}

impl Drop for IdentityManager {
    fn drop(&mut self) {
        let mut bytes = self.signing_key.to_bytes();
        bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encryption_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_generate_key_pair() {
        let path = std::env::temp_dir().join("kirin_desk_test_ed25519");
        let manager = IdentityManager::generate(path).unwrap();
        let pub_key = manager.public_key();
        assert_eq!(pub_key.to_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let path = std::env::temp_dir().join("kirin_desk_test_sign");
        let manager = IdentityManager::generate(path).unwrap();

        let message = b"Hello, KirinDesk!";
        let signature = manager.sign(message);
        assert!(manager.verify(message, &signature));
        assert!(!manager.verify(b"Tampered message", &signature));
    }

    #[test]
    fn test_save_and_load() {
        let path = std::env::temp_dir().join("kirin_desk_test_save_load.json");
        let _ = std::fs::remove_file(&path);

        let encryption_key = test_encryption_key();
        let pub_key_base64;

        {
            let manager = IdentityManager::generate(path.clone()).unwrap();
            pub_key_base64 = manager.public_key_base64();
            manager.save(&encryption_key).unwrap();
        }

        {
            let loaded = IdentityManager::load(path.clone(), &encryption_key).unwrap();
            assert_eq!(loaded.public_key_base64(), pub_key_base64);

            let message = b"Round trip test";
            let signature = loaded.sign(message);
            assert!(loaded.verify(message, &signature));
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_public_key_base64_roundtrip() {
        let path = std::env::temp_dir().join("kirin_desk_test_base64");
        let manager = IdentityManager::generate(path).unwrap();

        let b64 = manager.public_key_base64();
        let parsed = IdentityManager::parse_public_key(&b64).unwrap();
        assert_eq!(manager.public_key().to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn test_invalid_public_key() {
        let result = IdentityManager::parse_public_key("invalid-base64!!!");
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════════════════════════
    // S-05 (F-4) fail-closed & 迁移（S-05c 单测收口）
    // 全部用内存 mock 后端驱动 `load_or_generate_with`，平台无关确定性。
    // ════════════════════════════════════════════════════════════════

    use crate::crypto::keystore::MemoryKeyStore;

    fn s05_temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kirin_desk_s05_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn load_with(
        keystore: &MemoryKeyStore,
        dir: &Path,
        device_id: &str,
    ) -> Result<IdentityManager, Ed25519Error> {
        IdentityManager::load_or_generate_with(keystore, dir.join("ed25519.json"), device_id)
    }

    /// 恒失败后端：验证"后端故障 → fail-closed，不换身份"。
    struct FailingKeyStore;
    impl KeyStore for FailingKeyStore {
        fn set(&self, _label: &str, _secret: &[u8]) -> Result<(), KeyStoreError> {
            Err(KeyStoreError::Backend("test failure".into()))
        }
        fn get(&self, _label: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
            Err(KeyStoreError::Backend("test failure".into()))
        }
        fn delete(&self, _label: &str) -> Result<(), KeyStoreError> {
            Err(KeyStoreError::Backend("test failure".into()))
        }
    }

    #[test]
    fn s05_fresh_boot_generates_and_reuses() {
        let dir = s05_temp_dir("fresh");
        let ks = MemoryKeyStore::new();

        let id = load_with(&ks, &dir, "dev-1").unwrap();
        // 已持久化到后端 + 配发标记
        assert_eq!(ks.get(&identity_label("dev-1")).unwrap().unwrap().len(), 32);
        assert!(dir.join("identity.provisioned").exists());

        // 二次加载（无文件、后端有）→ 同一身份
        let id2 = load_with(&ks, &dir, "dev-1").unwrap();
        assert_eq!(id.public_key_base64(), id2.public_key_base64());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_garbage_file_unprovisioned_recovers() {
        // M8-T031: 垃圾文件 + 从未配发（无后端条目、无标记）= 过期残留 →
        // 恢复（备份损坏文件后全新生成），不再 fail-closed。
        let dir = s05_temp_dir("garbage");
        let path = dir.join("ed25519.json");
        let garbage = b"not a json file at all";
        std::fs::write(&path, garbage).unwrap();

        let ks = MemoryKeyStore::new();
        let _ = load_with(&ks, &dir, "dev-1").unwrap();
        // 新身份已落 keystore + 配发标记
        assert_eq!(ks.get(&identity_label("dev-1")).unwrap().unwrap().len(), 32);
        assert!(dir.join("identity.provisioned").exists());
        // 损坏文件已备份为 ed25519.json.corrupt.<ts>（原路径不再覆盖）
        assert!(!path.exists());
        let corrupt: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("ed25519.json.corrupt."))
            .collect();
        assert_eq!(corrupt.len(), 1, "expected exactly one corrupt backup");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_undecryptable_legacy_unprovisioned_recovers() {
        // M8-T031: 旧格式文件不可解密（device_id 变动）+ 从未配发 → 恢复：
        // 备份损坏文件 → 全新生成身份（等价全新安装），不再 fail-closed。
        let dir = s05_temp_dir("undecryptable");
        let path = dir.join("ed25519.json");
        // 用另一 device_id 的密钥写旧格式 → 当前 device_id 解不开
        let id = IdentityManager::generate(path.clone()).unwrap();
        id.save(&derive_identity_key("other-device")).unwrap();

        let ks = MemoryKeyStore::new();
        let loaded = load_with(&ks, &dir, "dev-1").unwrap();
        // 新身份已持久化（keystore + 标记）
        assert_eq!(ks.get(&identity_label("dev-1")).unwrap().unwrap().len(), 32);
        assert!(dir.join("identity.provisioned").exists());
        // 原文件已备份为 ed25519.json.corrupt.<ts>（不覆盖）
        assert!(!path.exists());
        let corrupt: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("ed25519.json.corrupt."))
            .collect();
        assert_eq!(corrupt.len(), 1, "expected exactly one corrupt backup");

        // 二次加载 → 同一身份
        let again = load_with(&ks, &dir, "dev-1").unwrap();
        assert_eq!(loaded.public_key_base64(), again.public_key_base64());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_undecryptable_legacy_provisioned_fails_closed() {
        // M8-T031 安全边界: 曾配发过（marker 含 label）+ 后端条目丢失 + 旧文件
        // 不可解密 → 维持 fail-closed（不生成新身份、不动损坏文件）。
        let dir = s05_temp_dir("provisioned");
        let ks = MemoryKeyStore::new();

        // 先正常配发（生成标记）
        let _ = load_with(&ks, &dir, "dev-1").unwrap();
        assert!(dir.join("identity.provisioned").exists());
        // 模拟身份存储丢失 + 残留损坏旧文件
        ks.delete(&identity_label("dev-1")).unwrap();
        let path = dir.join("ed25519.json");
        let id = IdentityManager::generate(path.clone()).unwrap();
        id.save(&derive_identity_key("other-device")).unwrap();
        let before = std::fs::read(&path).unwrap();

        let err = load_with(&ks, &dir, "dev-1").unwrap_err();
        assert!(
            matches!(err, Ed25519Error::CorruptIdentity(_)),
            "expected CorruptIdentity, got {err:?}"
        );
        // 原文件原样保留（fail-closed 不产生 corrupt 备份）
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let corrupt: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("ed25519.json.corrupt."))
            .collect();
        assert!(corrupt.is_empty(), "fail-closed must not back up the file");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_keystore_entry_with_corrupt_legacy_uses_backend() {
        // M8-T031: 后端已有身份 + 旧文件损坏 → 忽略损坏文件，用后端身份继续。
        let dir = s05_temp_dir("ks_backend");
        let ks = MemoryKeyStore::new();

        let first = load_with(&ks, &dir, "dev-1").unwrap();
        // 植入损坏旧文件（后端条目与标记保留）
        let path = dir.join("ed25519.json");
        std::fs::write(&path, b"not a json file at all").unwrap();

        let loaded = load_with(&ks, &dir, "dev-1").unwrap();
        // 后端身份优先，公钥一致；标记保持
        assert_eq!(first.public_key_base64(), loaded.public_key_base64());
        assert!(dir.join("identity.provisioned").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_legacy_migration_to_keystore() {
        let dir = s05_temp_dir("migrate");
        let path = dir.join("ed25519.json");

        // 构造旧格式文件（R-20 格式：JSON nonce+ciphertext）
        let original = IdentityManager::generate(path.clone()).unwrap();
        let orig_pub = original.public_key_base64();
        original.save(&derive_identity_key("dev-1")).unwrap();

        let ks = MemoryKeyStore::new();
        let migrated = load_with(&ks, &dir, "dev-1").unwrap();
        assert_eq!(migrated.public_key_base64(), orig_pub);

        // 密钥已进新后端
        assert_eq!(
            ks.get(&identity_label("dev-1")).unwrap().unwrap(),
            original.signing_key().to_bytes().to_vec()
        );

        // 原文件已改名备份（先备份再改写：不覆盖、不删除）
        assert!(!path.exists());
        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("ed25519.json.bak."))
            .collect();
        assert_eq!(backups.len(), 1, "expected exactly one migration backup");

        // 再次加载 → 走 keystore 路径，身份一致
        let again = load_with(&ks, &dir, "dev-1").unwrap();
        assert_eq!(again.public_key_base64(), orig_pub);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_deleted_storage_fails_closed() {
        let dir = s05_temp_dir("deleted");
        let ks = MemoryKeyStore::new();

        // 配发身份（生成标记）
        let _ = load_with(&ks, &dir, "dev-1").unwrap();
        assert!(dir.join("identity.provisioned").exists());

        // 模拟身份存储被删除（keystore 条目 + 文件都不在，标记仍在）
        ks.delete(&identity_label("dev-1")).unwrap();

        let err = load_with(&ks, &dir, "dev-1").unwrap_err();
        assert!(
            matches!(err, Ed25519Error::CorruptIdentity(_)),
            "expected CorruptIdentity, got {err:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_device_id_change_generates_new_identity() {
        // 文档化行为：更换 device_id = 新设备身份（标记按 label 记录，
        // 旧 label 的身份仍保留在后端；不构成"静默换身份"）。
        let dir = s05_temp_dir("device_change");
        let ks = MemoryKeyStore::new();

        let id1 = load_with(&ks, &dir, "dev-1").unwrap();
        let id2 = load_with(&ks, &dir, "dev-2").unwrap();
        assert_ne!(id1.public_key_base64(), id2.public_key_base64());
        assert!(ks.get(&identity_label("dev-1")).unwrap().is_some());
        assert!(ks.get(&identity_label("dev-2")).unwrap().is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_keystore_failure_fails_closed() {
        let dir = s05_temp_dir("ks_fail");
        // 后端故障（全新路径）→ 不得静默生成
        let err = IdentityManager::load_or_generate_with(
            &FailingKeyStore,
            dir.join("ed25519.json"),
            "dev-1",
        )
        .unwrap_err();
        assert!(
            matches!(err, Ed25519Error::KeyStore(_)),
            "expected KeyStore error, got {err:?}"
        );
        assert!(!dir.join("identity.provisioned").exists());

        // 后端故障（旧格式文件存在）→ 迁移失败，原文件保留
        let path = dir.join("ed25519.json");
        let id = IdentityManager::generate(path.clone()).unwrap();
        id.save(&derive_identity_key("dev-1")).unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = IdentityManager::load_or_generate_with(
            &FailingKeyStore,
            dir.join("ed25519.json"),
            "dev-1",
        )
        .unwrap_err();
        assert!(
            matches!(err, Ed25519Error::KeyStore(_)),
            "expected KeyStore error, got {err:?}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_marker_corrupt_fails_closed() {
        let dir = s05_temp_dir("marker_corrupt");
        std::fs::write(dir.join("identity.provisioned"), b"not json").unwrap();

        let ks = MemoryKeyStore::new();
        let err = load_with(&ks, &dir, "dev-1").unwrap_err();
        assert!(
            matches!(err, Ed25519Error::CorruptIdentity(_)),
            "expected CorruptIdentity, got {err:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn s05_public_load_or_generate_roundtrip() {
        // 端到端走真实默认后端（本机 Windows=DPAPI / Linux CI=文件兜底 /
        // macOS=Keychain）：生成 → 二次加载同一身份。
        let dir = s05_temp_dir("public");
        let path = dir.join("ed25519.json");

        let id = IdentityManager::load_or_generate(path.clone(), "dev-1").unwrap();
        let pub1 = id.public_key_base64();

        let id2 = IdentityManager::load_or_generate(path.clone(), "dev-1").unwrap();
        assert_eq!(pub1, id2.public_key_base64());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
