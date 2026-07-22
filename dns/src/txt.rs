use crate::godaddy::{GoDaddyClient, GoDaddyError, Record};
use serde::{Deserialize, Serialize};

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
    pub async fn register(
        &self,
        device_id: &str,
        meta: &DeviceMeta,
        ttl: u32,
    ) -> Result<(), GoDaddyError> {
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
        let records = self
            .client
            .get_records(self.domain, "TXT", device_id)
            .await?;

        let record = records.first().ok_or_else(|| GoDaddyError::NotFound {
            name: device_id.to_string(),
            record_type: "TXT".to_string(),
        })?;

        DeviceMeta::from_txt(&record.data).ok_or_else(|| GoDaddyError::InvalidParameters {
            body: format!("Failed to parse device metadata from TXT: {}", record.data),
        })
    }

    /// Delete the device metadata TXT record (device offline).
    pub async fn remove(&self, device_id: &str) -> Result<(), GoDaddyError> {
        self.client
            .delete_record(self.domain, "TXT", device_id)
            .await
    }
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
}
