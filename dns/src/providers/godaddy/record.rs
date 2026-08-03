//! GoDaddy wire 记录模型 与 统一 Record 互转（M9-DNS001 §二/§三）。
//!
//! GoDaddy API 两种记录形态：
//! - 全表端点 `GET /v1/domains/{domain}/records` → `ManagedRecord{type,name,data,ttl}`
//!   （type/name 都在响应里）；
//! - 精确端点 `GET/PUT /v1/domains/{domain}/records/{type}/{name}` →
//!   `WireRecord{data,ttl}`（无 type/name，由请求上下文补全）。
//!
//! 统一模型约定（M9-DNS000 §二）：
//! - `Record.name` 为**相对名**（"" = 根），与 GoDaddy 的 `@` 根名互转；
//! - SRV data 为单字符串 `0 1 {port} {target}.`，与 `RecordData::Srv` 互转
//!   （复用旧 `dns/src/godaddy/record.rs` 的 SrvData 解析/格式化逻辑，复制进本模块）；
//! - MX data 为 `{priority} {exchange}`，与 `RecordData::Mx` 互转。

use crate::provider::{ProviderError, Record, RecordData, RecordType};
use serde::{Deserialize, Serialize};

/// GoDaddy 全表端点返回的完整记录（含 type/name）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedRecord {
    /// 记录类型（大写，如 "A" / "SRV" / "TXT"）。
    #[serde(rename = "type")]
    pub rtype: String,
    /// GoDaddy 记录名（相对名；根记录为 `@`）。
    pub name: String,
    /// 记录数据字符串（A=IP；SRV=`0 1 3389 target.`；MX=`10 mail.host`）。
    pub data: String,
    /// TTL（秒）。
    pub ttl: u32,
}

/// GoDaddy `{type}/{name}` 端点与 PUT body 的记录形态（无 type/name）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRecord {
    pub data: String,
    pub ttl: u32,
}

/// SRV 结构化数据（旧 godaddy/record.rs 的 `SrvData` 复制）。
///
/// GoDaddy SRV 字符串形态：`{priority} {weight} {port} {target}.`
/// 示例：`0 1 3389 my-device.example.com.`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrvData {
    /// 优先级（越小越优先）。
    pub priority: u16,
    /// 负载均衡权重。
    pub weight: u16,
    /// 服务端口。
    pub port: u16,
    /// 目标主机（FQDN，尾部带点）。
    pub target: String,
}

impl SrvData {
    /// 解析 GoDaddy SRV data 字符串：`{priority} {weight} {port} {target}.`。
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

    /// 序列化为 GoDaddy 字符串形态（target 归一为尾部带点）。
    pub fn to_string(&self) -> String {
        format!(
            "{} {} {} {}.",
            self.priority,
            self.weight,
            self.port,
            self.target.trim_end_matches('.')
        )
    }
}

/// 相对名 → GoDaddy wire 名（"" → "@"；"@" 透传）。
pub(crate) fn wire_name(name: &str) -> String {
    if name.is_empty() {
        "@".to_string()
    } else {
        name.to_string()
    }
}

/// GoDaddy wire 名 → 相对名（"@" → ""）。
pub(crate) fn rel_name(name: &str) -> String {
    if name == "@" {
        String::new()
    } else {
        name.to_string()
    }
}

/// 由 GoDaddy 字段组（类型/相对名/数据/TTL）构造统一 Record。
///
/// SRV/MX 做结构化解析（失败 → `InvalidParameter`）；其余类型承载为 `Plain`。
pub(crate) fn build_record(
    rtype: RecordType,
    name: String,
    data: &str,
    ttl: u32,
) -> Result<Record, ProviderError> {
    let rdata = match rtype {
        RecordType::SRV => {
            let srv = SrvData::from_string(data).ok_or_else(|| ProviderError::InvalidParameter {
                detail: format!("SRV data 非法: '{data}'"),
            })?;
            RecordData::Srv {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                target: srv.target,
            }
        }
        RecordType::MX => {
            let (priority, exchange) = parse_mx(data).ok_or_else(|| {
                ProviderError::InvalidParameter {
                    detail: format!("MX data 非法: '{data}'"),
                }
            })?;
            RecordData::Mx { priority, exchange }
        }
        _ => RecordData::Plain(data.to_string()),
    };
    Ok(Record {
        name,
        rtype,
        ttl,
        data: rdata,
    })
}

/// `ManagedRecord`（全表端点）→ 统一 Record（name 转为相对名）。
pub(crate) fn managed_to_record(mr: &ManagedRecord) -> Result<Record, ProviderError> {
    let rtype: RecordType = mr.rtype.parse().map_err(|_| ProviderError::InvalidParameter {
        detail: format!("未知记录类型: '{}'", mr.rtype),
    })?;
    build_record(rtype, rel_name(&mr.name), &mr.data, mr.ttl)
}

/// `WireRecord`（精确端点）→ 统一 Record（name/rtype 由请求上下文补全，
/// name 为相对名）。
pub(crate) fn wire_to_record(
    w: &WireRecord,
    rtype: RecordType,
    name: &str,
) -> Result<Record, ProviderError> {
    build_record(rtype, name.to_string(), &w.data, w.ttl)
}

/// 统一 Record → `WireRecord`（GoDaddy PUT body 元素）。
pub(crate) fn record_to_wire(rec: &Record) -> WireRecord {
    let data = match &rec.data {
        RecordData::Plain(s) => s.clone(),
        RecordData::Mx { priority, exchange } => format!("{priority} {exchange}"),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => SrvData {
            priority: *priority,
            weight: *weight,
            port: *port,
            target: target.clone(),
        }
        .to_string(),
    };
    WireRecord { data, ttl: rec.ttl }
}

/// 现有 WireRecord 与目标统一 Record 是否为同一条（按 wire data 字符串比较，
/// SRV target 结尾点等差异由 `record_to_wire` 归一）：同 data → upsert 时替换
/// （更新 TTL），否则追加。
pub(crate) fn wire_matches_rec(w: &WireRecord, rec: &Record) -> bool {
    w.data == record_to_wire(rec).data
}

/// 解析 GoDaddy MX data：`{priority} {exchange}`。
fn parse_mx(s: &str) -> Option<(u16, String)> {
    let mut parts = s.split_whitespace();
    let priority = parts.next()?.parse().ok()?;
    let exchange: String = parts.collect::<Vec<_>>().join(" ");
    if exchange.is_empty() {
        None
    } else {
        Some((priority, exchange))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(original, parsed);
        // 无尾点 target → to_string 归一为带点。
        let no_dot = SrvData {
            priority: 0,
            weight: 1,
            port: 9000,
            target: "test.example.com".to_string(),
        };
        assert_eq!(no_dot.to_string(), "0 1 9000 test.example.com.");
    }

    #[test]
    fn test_srv_data_invalid() {
        assert!(SrvData::from_string("").is_none());
        assert!(SrvData::from_string("0 1").is_none());
        assert!(SrvData::from_string("x y z t").is_none());
    }

    #[test]
    fn test_name_conversion() {
        // 相对名 "" ↔ wire "@"。
        assert_eq!(wire_name(""), "@");
        assert_eq!(wire_name("my-pc"), "my-pc");
        assert_eq!(rel_name("@"), "");
        assert_eq!(rel_name("my-pc"), "my-pc");
    }

    #[test]
    fn test_managed_record_to_unified_plain() {
        // 根记录 "@" → 相对名 ""。
        let mr = ManagedRecord {
            rtype: "A".to_string(),
            name: "@".to_string(),
            data: "203.0.113.7".to_string(),
            ttl: 600,
        };
        let r = managed_to_record(&mr).unwrap();
        assert_eq!(r.name, "");
        assert_eq!(r.rtype, RecordType::A);
        assert_eq!(r.ttl, 600);
        assert_eq!(r.data, RecordData::Plain("203.0.113.7".into()));
    }

    #[test]
    fn test_managed_record_to_unified_srv() {
        let mr = ManagedRecord {
            rtype: "SRV".to_string(),
            name: "_remote._tcp.my-pc".to_string(),
            data: "0 1 3389 my-pc.example.com.".to_string(),
            ttl: 600,
        };
        let r = managed_to_record(&mr).unwrap();
        match &r.data {
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                assert_eq!((*priority, *weight, *port), (0, 1, 3389));
                assert_eq!(target, "my-pc.example.com.");
            }
            other => panic!("expected Srv data, got {other:?}"),
        }
    }

    #[test]
    fn test_managed_record_to_unified_mx() {
        let mr = ManagedRecord {
            rtype: "MX".to_string(),
            name: "@".to_string(),
            data: "10 mail.example.com".to_string(),
            ttl: 600,
        };
        let r = managed_to_record(&mr).unwrap();
        assert_eq!(
            r.data,
            RecordData::Mx {
                priority: 10,
                exchange: "mail.example.com".into()
            }
        );
    }

    #[test]
    fn test_managed_record_unknown_type_rejected() {
        let mr = ManagedRecord {
            rtype: "SOA".to_string(),
            name: "@".to_string(),
            data: "x".to_string(),
            ttl: 600,
        };
        assert!(matches!(
            managed_to_record(&mr),
            Err(ProviderError::InvalidParameter { .. })
        ));
    }

    #[test]
    fn test_managed_record_bad_srv_data_rejected() {
        let mr = ManagedRecord {
            rtype: "SRV".to_string(),
            name: "_remote._tcp.my-pc".to_string(),
            data: "not-a-srv".to_string(),
            ttl: 600,
        };
        assert!(matches!(
            managed_to_record(&mr),
            Err(ProviderError::InvalidParameter { .. })
        ));
    }

    #[test]
    fn test_record_to_wire_format() {
        // SRV：target 无尾点 → wire data 归一为带点。
        let rec = Record {
            name: "_remote._tcp.my-pc".to_string(),
            rtype: RecordType::SRV,
            ttl: 600,
            data: RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target: "my-pc.example.com".to_string(),
            },
        };
        let w = record_to_wire(&rec);
        assert_eq!(w.data, "0 1 3389 my-pc.example.com.");
        assert_eq!(w.ttl, 600);

        // MX。
        let rec = Record {
            name: "@".to_string(),
            rtype: RecordType::MX,
            ttl: 600,
            data: RecordData::Mx {
                priority: 10,
                exchange: "mail.example.com".to_string(),
            },
        };
        assert_eq!(record_to_wire(&rec).data, "10 mail.example.com");

        // Plain 透传。
        let rec = Record {
            name: "my-pc".to_string(),
            rtype: RecordType::TXT,
            ttl: 300,
            data: RecordData::Plain("v=ed25519;k=abc".to_string()),
        };
        assert_eq!(record_to_wire(&rec).data, "v=ed25519;k=abc");
    }

    #[test]
    fn test_wire_matches_rec() {
        let rec = Record {
            name: "my-pc".to_string(),
            rtype: RecordType::A,
            ttl: 300,
            data: RecordData::Plain("203.0.113.7".to_string()),
        };
        // 同 data → 匹配（upsert 替换）。
        assert!(wire_matches_rec(
            &WireRecord {
                data: "203.0.113.7".to_string(),
                ttl: 600,
            },
            &rec
        ));
        // 不同 data → 不匹配（追加）。
        assert!(!wire_matches_rec(
            &WireRecord {
                data: "198.51.100.9".to_string(),
                ttl: 600,
            },
            &rec
        ));
    }
}
