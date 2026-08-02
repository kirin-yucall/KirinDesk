use crate::godaddy::{GoDaddyClient, GoDaddyError, Record};
use crate::validate::{self, MAX_PUBLIC_KEY_LEN, MAX_RECORD_DATA_LEN};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

/// Kirin-style device metadata stored as a JSON TXT record on the device's subdomain root.
///
/// Each device has its own subdomain: `{device_id}.{domain}`
/// The TXT record holds the device's Ed25519 public key and protocol info.
/// **Port is published via SRV record** (standard DNS service discovery).
///
/// # DNS Layout (Kirin + SRV hybrid)
///
/// ```text
/// device-id.example.com        TXT   →  {"key":"ed25519:base64...","proto":"ip6desk","ver":"1","type":"server"}
/// device-id.example.com        AAAA  →  2001:db8::1
/// _remote._tcp.device-id.example.com  SRV  →  0 1 3389 device-id.example.com.
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMeta {
    /// Ed25519 public key in format `ed25519:<base64>`.
    pub key: String,
    /// Protocol identifier (always "ip6desk").
    #[serde(default = "default_proto")]
    pub proto: String,
    /// Metadata format version.
    #[serde(default = "default_version")]
    pub ver: String,
    /// Device type: "desktop" (Windows GUI) or "server" (headless Linux).
    #[serde(default = "default_device_type")]
    pub device_type: String,
}

fn default_proto() -> String { "ip6desk".to_string() }
fn default_version() -> String { "1".to_string() }
fn default_device_type() -> String { "desktop".to_string() }

impl DeviceMeta {
    /// Create new device metadata.
    pub fn new(public_key_base64: &str) -> Self {
        Self {
            key: format!("ed25519:{}", public_key_base64),
            proto: default_proto(),
            ver: default_version(),
            device_type: default_device_type(),
        }
    }

    /// Create metadata for a headless server (remote shell mode).
    pub fn new_server(public_key_base64: &str) -> Self {
        Self {
            key: format!("ed25519:{}", public_key_base64),
            proto: default_proto(),
            ver: default_version(),
            device_type: "server".to_string(),
        }
    }

    /// Returns true if this device is a headless server (remote shell).
    pub fn is_server(&self) -> bool { self.device_type == "server" }
    /// Returns true if this device is a desktop (remote GUI).
    pub fn is_desktop(&self) -> bool { self.device_type == "desktop" || self.device_type.is_empty() }

    /// Serialize to JSON string for DNS TXT record.
    pub fn to_txt(&self) -> String {
        serde_json::to_string(self).expect("DeviceMeta serialization should not fail")
    }

    /// Parse from JSON string (from DNS TXT record).
    pub fn from_txt(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }

    /// Extract the raw base64 public key (strip "ed25519:" prefix).
    pub fn raw_public_key(&self) -> Option<&str> {
        self.key.strip_prefix("ed25519:")
    }
}

/// S-27（F-32）：TXT 公钥 base64 校验 —— Ed25519 公钥必须**恰为 32 字节**
/// （标准 base64 编码长度恒为 44）。DNS TXT 数据来自外部（攻击者可写入
/// 任意长度字符串），解码失败/长度不符 → 拒绝（防脏数据撑爆后续握手、
/// 防解析歧义）。
pub fn is_valid_ed25519_pubkey_b64(public_key_base64: &str) -> bool {
    use base64::Engine as _;
    match base64::engine::general_purpose::STANDARD.decode(public_key_base64) {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

/// Manage device metadata via TXT records on the device's subdomain root.
///
/// Each device gets its own subdomain (`{device_id}.{domain}`).
/// The TXT record at the subdomain root stores device metadata (public key).
pub struct TxtManager<'a> {
    client: &'a GoDaddyClient,
    domain: &'a str,
}

impl<'a> TxtManager<'a> {
    pub fn new(client: &'a GoDaddyClient, domain: &'a str) -> Self {
        Self { client, domain }
    }

    /// Register or update the device metadata TXT record.
    ///
    /// Writes to the subdomain root: `{device_id}.{domain}` TXT record.
    ///
    /// 校验（S-14b/F-18 device_id；S-14c/F-19 公钥长度上限）。
    pub async fn register(
        &self,
        device_id: &str,
        meta: &DeviceMeta,
        ttl: u32,
    ) -> Result<(), GoDaddyError> {
        validate_device_and_key(device_id, meta)?;
        debug!("TXT register: device={}, device_type={}, ttl={}", device_id, meta.device_type, ttl);
        trace!("TXT register: device={}, full_key={}", device_id, meta.key);
        let records = vec![Record {
            data: meta.to_txt(),
            ttl,
        }];

        self.client
            .put_records(self.domain, "TXT", device_id, &records)
            .await
    }

    /// Query the device metadata from its subdomain TXT record.
    pub async fn query(&self, device_id: &str) -> Result<DeviceMeta, GoDaddyError> {
        if !validate::validate_device_id(device_id) {
            return Err(GoDaddyError::InvalidParameters {
                body: format!(
                    "invalid device_id '{}' (charset [a-zA-Z0-9:_-], len 1..=128, no '.' allowed)",
                    device_id
                ),
            });
        }
        debug!("TXT query: device={}", device_id);
        let records = self
            .client
            .get_records(self.domain, "TXT", device_id)
            .await?;

        let record = records.first().ok_or_else(|| GoDaddyError::NotFound {
            name: device_id.to_string(),
            record_type: "TXT".to_string(),
        })?;

        let meta = DeviceMeta::from_txt(&record.data).ok_or_else(|| GoDaddyError::InvalidParameters {
            body: format!("Failed to parse device metadata from TXT: {}", record.data),
        })?;

        // S-14c / F-19: 读侧公钥长度上限（防脏数据撑爆后续握手）。
        if meta.raw_public_key().map_or(true, |k| k.len() > MAX_PUBLIC_KEY_LEN) {
            return Err(GoDaddyError::InvalidParameters {
                body: format!(
                    "public key exceeds {} chars (got {})",
                    MAX_PUBLIC_KEY_LEN,
                    meta.raw_public_key().map_or(0, |k| k.len())
                ),
            });
        }
        // S-27 (F-32): 读侧公钥 base64 **恰为 32 字节**（Ed25519）——DNS 数据
        // 可被外部写入任意长度/畸形字符串，长度不符直接拒绝。
        if meta.raw_public_key().map_or(true, |k| !is_valid_ed25519_pubkey_b64(k)) {
            return Err(GoDaddyError::InvalidParameters {
                body: format!(
                    "public key is not a valid Ed25519 key (base64 must decode to 32 bytes, got '{}')",
                    meta.raw_public_key().unwrap_or("")
                ),
            });
        }
        Ok(meta)
    }

    /// Delete the device metadata TXT record (device offline).
    pub async fn remove(&self, device_id: &str) -> Result<(), GoDaddyError> {
        if !validate::validate_device_id(device_id) {
            return Err(GoDaddyError::InvalidParameters {
                body: format!(
                    "invalid device_id '{}' (charset [a-zA-Z0-9:_-], len 1..=128, no '.' allowed)",
                    device_id
                ),
            });
        }
        self.client
            .delete_record(self.domain, "TXT", device_id)
            .await
    }
}

/// device_id + 公钥长度校验（TXT 写侧；S-14b/F-18 + S-14c/F-19）。
fn validate_device_and_key(device_id: &str, meta: &DeviceMeta) -> Result<(), GoDaddyError> {
    if !validate::validate_device_id(device_id) {
        return Err(GoDaddyError::InvalidParameters {
            body: format!(
                "invalid device_id '{}' (charset [a-zA-Z0-9:_-], len 1..=128, no '.' allowed)",
                device_id
            ),
        });
    }
    if meta.raw_public_key().map_or(true, |k| k.len() > MAX_PUBLIC_KEY_LEN) {
        return Err(GoDaddyError::InvalidParameters {
            body: format!("public key exceeds {} chars (got {})", MAX_PUBLIC_KEY_LEN, meta.key.len()),
        });
    }
    if meta.to_txt().len() > MAX_RECORD_DATA_LEN {
        return Err(GoDaddyError::InvalidParameters {
            body: format!("TXT record data exceeds {} bytes", MAX_RECORD_DATA_LEN),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_meta_roundtrip() {
        let meta = DeviceMeta::new("ABC123base64key");
        let json = meta.to_txt();
        let parsed = DeviceMeta::from_txt(&json).unwrap();

        assert_eq!(parsed.key, "ed25519:ABC123base64key");
        assert_eq!(parsed.proto, "ip6desk");
        assert_eq!(parsed.ver, "1");
    }

    #[test]
    fn test_raw_public_key_extraction() {
        let meta = DeviceMeta::new("base64key123");
        assert_eq!(meta.raw_public_key(), Some("base64key123"));
    }

    #[test]
    fn test_no_port_in_meta() {
        let meta = DeviceMeta::new("testkey");
        let json = meta.to_txt();
        // Port should NOT be in TXT — it's in SRV
        assert!(!json.contains("port"));
        assert!(json.contains("\"key\""));
        assert!(json.contains("\"proto\""));
    }

    #[test]
    fn test_json_format() {
        let meta = DeviceMeta::new("testkey");
        let json = meta.to_txt();
        assert!(json.contains("\"key\":\"ed25519:testkey\""));
        assert!(json.contains("\"proto\":\"ip6desk\""));
        assert!(json.contains("\"ver\":\"1\""));
    }

    /// S-27（F-32）：TXT 公钥 base64 == 32 字节校验 —— 合法 44 字符 key 通过；
    /// 长度不符/畸形 base64/空串拒绝（读写侧同规则）。
    #[test]
    fn test_ed25519_pubkey_b64_validation() {
        use base64::Engine as _;
        // 32 字节全零 → base64 恰 44 字符。
        let valid = base64::engine::general_purpose::STANDARD
            .encode([0u8; 32]);
        assert_eq!(valid.len(), 44);
        assert!(is_valid_ed25519_pubkey_b64(&valid), "32-byte key must pass");

        // 长度不符：31/33 字节。
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 31]);
        assert!(!is_valid_ed25519_pubkey_b64(&short), "31-byte key must fail");
        let long = base64::engine::general_purpose::STANDARD.encode([1u8; 33]);
        assert!(!is_valid_ed25519_pubkey_b64(&long), "33-byte key must fail");

        // 畸形 base64 / 空串 / 非 base64 文本。
        assert!(!is_valid_ed25519_pubkey_b64("not-base64!!!"));
        assert!(!is_valid_ed25519_pubkey_b64(""));
        assert!(!is_valid_ed25519_pubkey_b64("AAA="), "AAA= decodes to 2 bytes");

        // 44 字符但非 32 字节：33 字节 → 44 字符无填充；43 字符（非法长度）。
        assert_eq!(base64::engine::general_purpose::STANDARD.encode([1u8; 33]).len(), 44);
        assert!(!is_valid_ed25519_pubkey_b64("A".repeat(43).as_str()), "43 chars cannot be 32 bytes");
    }

    /// S-27（F-32）：`DeviceMeta::raw_public_key` 与校验函数联动（带
    /// `ed25519:` 前缀解析）。
    #[test]
    fn test_raw_key_validation_roundtrip() {
        use base64::Engine as _;
        let valid = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let meta = DeviceMeta::new(&valid);
        assert_eq!(meta.raw_public_key(), Some(valid.as_str()));
        assert!(is_valid_ed25519_pubkey_b64(meta.raw_public_key().unwrap()));
    }
}
