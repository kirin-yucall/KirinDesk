use serde::{Deserialize, Serialize};

/// Supported DNS record types for KirinDesk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    /// SRV record — service location (port + target).
    SRV,
    /// AAAA record — IPv6 address.
    AAAA,
    /// TXT record — arbitrary text data (device public key).
    TXT,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::SRV => write!(f, "SRV"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::TXT => write!(f, "TXT"),
        }
    }
}

/// A single DNS record as returned by the GoDaddy API.
///
/// GoDaddy API response format:
/// ```json
/// {
///   "type": "A",
///   "name": "@",
///   "data": "192.168.1.1",
///   "ttl": 600
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Record data (e.g., IP address for AAAA, port+target for SRV, text for TXT).
    pub data: String,

    /// Time-to-live in seconds.
    pub ttl: u32,
}

/// SRV record specific data.
///
/// GoDaddy SRV format: `{priority} {weight} {port} {target}.`
/// Example: `0 1 3389 my-device.example.com.`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrvData {
    /// Priority (lower = higher priority).
    pub priority: u16,
    /// Weight for load balancing.
    pub weight: u16,
    /// Service port number.
    pub port: u16,
    /// Target hostname (FQDN with trailing dot).
    pub target: String,
}

impl SrvData {
    /// Parse SRV data from GoDaddy's string format.
    ///
    /// Format: `{priority} {weight} {port} {target}.`
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() >= 4 {
            let priority = parts[0].parse().ok()?;
            let weight = parts[1].parse().ok()?;
            let port = parts[2].parse().ok()?;
            let target = parts[3..].join(" ");
            Some(Self {
                priority,
                weight,
                port,
                target,
            })
        } else {
            None
        }
    }

    /// Serialize SRV data to GoDaddy's string format.
    pub fn to_string(&self) -> String {
        format!("{} {} {} {}.", self.priority, self.weight, self.port, self.target.trim_end_matches('.'))
    }
}

/// Parsed TXT record data for device public keys.
///
/// Format: `v=ed25519;k=<base64_public_key>`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxtKeyData {
    /// Key version/type (e.g., "ed25519").
    pub version: String,
    /// Base64-encoded public key.
    pub public_key: String,
}

impl TxtKeyData {
    /// Parse TXT record data from GoDaddy's format.
    ///
    /// Expected format: `v=ed25519;k=<base64_public_key>`
    pub fn from_string(s: &str) -> Option<Self> {
        let mut version = None;
        let mut public_key = None;

        for part in s.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("v=") {
                version = Some(value.to_string());
            } else if let Some(value) = part.strip_prefix("k=") {
                public_key = Some(value.to_string());
            }
        }

        Some(Self {
            version: version?,
            public_key: public_key?,
        })
    }

    /// Serialize TXT key data to GoDaddy's string format.
    pub fn to_string(&self) -> String {
        format!("v={};k={}", self.version, self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_display() {
        assert_eq!(RecordType::SRV.to_string(), "SRV");
        assert_eq!(RecordType::AAAA.to_string(), "AAAA");
        assert_eq!(RecordType::TXT.to_string(), "TXT");
    }

    #[test]
    fn test_srv_data_parse() {
        let srv = SrvData::from_string("0 1 3389 my-device.example.com.").unwrap();
        assert_eq!(srv.priority, 0);
        assert_eq!(srv.weight, 1);
        assert_eq!(srv.port, 3389);
        assert_eq!(srv.target, "my-device.example.com.");
    }

    #[test]
    fn test_srv_data_roundtrip() {
        let original = SrvData {
            priority: 0,
            weight: 1,
            port: 9000,
            target: "test.example.com.".to_string(),
        };
        let stringified = original.to_string();
        let parsed = SrvData::from_string(&stringified).unwrap();
        assert_eq!(original.priority, parsed.priority);
        assert_eq!(original.weight, parsed.weight);
        assert_eq!(original.port, parsed.port);
        assert_eq!(original.target, parsed.target);
    }

    #[test]
    fn test_txt_key_data_parse() {
        let txt = TxtKeyData::from_string("v=ed25519;k=FWfJ7Zx7K8xBase64Example").unwrap();
        assert_eq!(txt.version, "ed25519");
        assert_eq!(txt.public_key, "FWfJ7Zx7K8xBase64Example");
    }

    #[test]
    fn test_txt_key_data_roundtrip() {
        let original = TxtKeyData {
            version: "ed25519".to_string(),
            public_key: "TestBase64Key123".to_string(),
        };
        let stringified = original.to_string();
        let parsed = TxtKeyData::from_string(&stringified).unwrap();
        assert_eq!(original.version, parsed.version);
        assert_eq!(original.public_key, parsed.public_key);
    }
}
