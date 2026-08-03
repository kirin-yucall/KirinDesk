use serde::{Deserialize, Serialize};

/// Supported DNS record types for KirinDesk.
///
/// M9-DNS000 (DNS-MNT-006): 域名维护客户端需覆盖 A/AAAA/CNAME/MX/TXT/SRV/NS
/// 全类型——扩展于原 SRV/A/AAAA/TXT 四型（SRV+AAAA+TXT 仍为设备注册三件套）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    /// SRV record — service location (port + target).
    SRV,
    /// A record — IPv4 address（M8-T025-P1 IPv4 发现）。
    A,
    /// AAAA record — IPv6 address.
    AAAA,
    /// TXT record — arbitrary text data (device public key).
    TXT,
    /// CNAME record — canonical name alias.
    CNAME,
    /// MX record — mail exchanger（GoDaddy data 形如 `10 mail.example.com`）。
    MX,
    /// NS record — authoritative name server.
    NS,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::SRV => write!(f, "SRV"),
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::MX => write!(f, "MX"),
            RecordType::NS => write!(f, "NS"),
        }
    }
}

/// M9-DNS000 (UI-DNS-006): 域名维护视图用完整记录模型——域名下全量记录查询
/// （`GET /v1/domains/{domain}/records`）返回每条含 类型/名称/数据/TTL 的记录，
/// 与现有 `{type}/{name}` 端点返回的 `Record{data,ttl}` 互为补充。
///
/// GoDaddy API 返回格式：
/// ```json
/// { "type": "A", "name": "@", "data": "192.168.1.1", "ttl": 600 }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedRecord {
    /// 记录类型（大写，如 "A" / "SRV" / "TXT"）。
    #[serde(rename = "type")]
    pub rtype: String,
    /// 记录名（相对名，如 `my-pc`；根记录为 `@`）。
    pub name: String,
    /// 记录数据（A=IP、SRV=`0 1 3389 target.`、MX=`10 mail.host` 等）。
    pub data: String,
    /// 生存时间（秒）。
    pub ttl: u32,
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
        assert_eq!(RecordType::A.to_string(), "A");
        assert_eq!(RecordType::AAAA.to_string(), "AAAA");
        assert_eq!(RecordType::TXT.to_string(), "TXT");
        assert_eq!(RecordType::CNAME.to_string(), "CNAME");
        assert_eq!(RecordType::MX.to_string(), "MX");
        assert_eq!(RecordType::NS.to_string(), "NS");
    }

    /// M9-DNS000: ManagedRecord serde 往返（GoDaddy 全量记录端点 JSON 形状）。
    #[test]
    fn test_managed_record_serde() {
        let rec = ManagedRecord {
            rtype: "A".to_string(),
            name: "@".to_string(),
            data: "203.0.113.7".to_string(),
            ttl: 600,
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert_eq!(json, r#"{"type":"A","name":"@","data":"203.0.113.7","ttl":600}"#);
        let back: ManagedRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
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
