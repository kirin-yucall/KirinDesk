//! M9-DNS003: 阿里云云解析记录模型互转
//!
//! 统一模型（`provider::record`）↔ Alidns wire 格式：
//! - 记录名：统一模型为**相对名**（`""` = 根）；Alidns 的 RR 字段根用 `@` 表示。
//!   `@` → `""`（读），`""` → `@`（写）。
//! - SRV：Alidns 的 `Value` 为 `"优先级 权重 端口 目标"` 空格分隔串
//!   （官方样例 `0 5 5060 sipserver.example.com`，目标域名系统自动补尾点），
//!   `Priority` 参数仅 MX 使用。
//! - MX：`Priority` 独立字段 + `Value` = 邮件服务器（exchange）。

use crate::provider::{Record, RecordData, RecordType};
use serde::Deserialize;

/// DescribeDomainRecords 返回的单条记录（wire 格式，字段名与官方一致）。
#[derive(Debug, Clone, Deserialize)]
pub struct RawRecord {
    #[serde(rename = "RecordId")]
    pub record_id: String,
    #[serde(rename = "RR")]
    pub rr: String,
    #[serde(rename = "Type")]
    pub rtype: String,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    /// MX 优先级（仅 MX 有）。
    #[serde(rename = "Priority")]
    pub priority: Option<u32>,
}

/// 相对名 → Alidns RR（根 `""` → `@`）。
pub fn to_vendor_rr(name: &str) -> String {
    if name.is_empty() {
        "@".to_string()
    } else {
        name.to_string()
    }
}

/// Alidns RR → 相对名（`@` → `""`）。
pub fn to_relative_name(rr: &str) -> String {
    if rr == "@" {
        String::new()
    } else {
        rr.to_string()
    }
}

/// 统一记录 → wire 形态的记录值（`Value` 字段）。
///
/// - `Plain` → 原值（A/AAAA/CNAME/TXT/NS）；
/// - `Mx` → exchange（优先级走独立 `Priority` 参数）；
/// - `Srv` → `"priority weight port target"`（官方格式，不强制尾点）。
pub fn to_vendor_value(rec: &Record) -> String {
    match &rec.data {
        RecordData::Plain(v) => v.clone(),
        RecordData::Mx { exchange, .. } => exchange.clone(),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
    }
}

/// wire 记录 → 统一记录；类型未知或字段无法解析时返回 `None`（该条跳过）。
///
/// SRV 的 `Value` 解析为结构化 `RecordData::Srv`；解析失败则退化为 `Plain`，
/// 保证记录不丢。
pub fn from_raw(raw: RawRecord) -> Option<Record> {
    let rtype = raw.rtype.parse::<RecordType>().ok()?;
    let data = match rtype {
        RecordType::SRV => parse_srv_value(&raw.value)
            .map(|(p, w, port, t)| RecordData::Srv {
                priority: p,
                weight: w,
                port,
                target: t,
            })
            .unwrap_or(RecordData::Plain(raw.value.clone())),
        RecordType::MX => RecordData::Mx {
            priority: raw.priority.unwrap_or(0) as u16,
            exchange: raw.value.clone(),
        },
        _ => RecordData::Plain(raw.value.clone()),
    };
    Some(Record {
        name: to_relative_name(&raw.rr),
        rtype,
        ttl: raw.ttl,
        data,
    })
}

/// 解析 Alidns SRV 值 `"priority weight port target"` → `(priority, weight, port, target)`。
fn parse_srv_value(value: &str) -> Option<(u16, u16, u16, String)> {
    let mut it = value.split_whitespace();
    let priority = it.next()?.parse().ok()?;
    let weight = it.next()?.parse().ok()?;
    let port = it.next()?.parse().ok()?;
    let target = it.next()?.to_string();
    Some((priority, weight, port, target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rr_root_conversion() {
        assert_eq!(to_vendor_rr(""), "@");
        assert_eq!(to_vendor_rr("my-pc"), "my-pc");
        assert_eq!(to_relative_name("@"), "");
        assert_eq!(to_relative_name("_remote._tcp"), "_remote._tcp");
    }

    #[test]
    fn srv_roundtrip() {
        let rec = Record {
            name: "_remote._tcp".into(),
            rtype: RecordType::SRV,
            ttl: 600,
            data: RecordData::Srv {
                priority: 0,
                weight: 5,
                port: 5060,
                target: "sipserver.example.com".into(),
            },
        };
        assert_eq!(to_vendor_value(&rec), "0 5 5060 sipserver.example.com");
        let raw = RawRecord {
            record_id: "id-1".into(),
            rr: "@".into(),
            rtype: "SRV".into(),
            value: "0 5 5060 sipserver.example.com.".into(),
            ttl: 600,
            priority: None,
        };
        let back = from_raw(raw).unwrap();
        assert_eq!(back.name, "");
        assert_eq!(
            back.data,
            RecordData::Srv {
                priority: 0,
                weight: 5,
                port: 5060,
                target: "sipserver.example.com.".into(),
            }
        );
    }

    #[test]
    fn mx_uses_priority_field() {
        let rec = Record {
            name: "".into(),
            rtype: RecordType::MX,
            ttl: 600,
            data: RecordData::Mx {
                priority: 5,
                exchange: "mail1.hichina.com".into(),
            },
        };
        assert_eq!(to_vendor_value(&rec), "mail1.hichina.com");
        let raw = RawRecord {
            record_id: "id-2".into(),
            rr: "@".into(),
            rtype: "MX".into(),
            value: "mail1.hichina.com".into(),
            ttl: 600,
            priority: Some(5),
        };
        assert_eq!(
            from_raw(raw).unwrap().data,
            RecordData::Mx {
                priority: 5,
                exchange: "mail1.hichina.com".into(),
            }
        );
    }

    #[test]
    fn unknown_type_skipped() {
        let raw = RawRecord {
            record_id: "id-3".into(),
            rr: "x".into(),
            rtype: "CAA".into(),
            value: "0 issue \"ca.example\"".into(),
            ttl: 600,
            priority: None,
        };
        assert!(from_raw(raw).is_none());
    }

    #[test]
    fn plain_roundtrip() {
        let rec = Record {
            name: "my-pc".into(),
            rtype: RecordType::A,
            ttl: 600,
            data: RecordData::Plain("203.0.113.7".into()),
        };
        assert_eq!(to_vendor_value(&rec), "203.0.113.7");
        let raw = RawRecord {
            record_id: "id-4".into(),
            rr: "my-pc".into(),
            rtype: "A".into(),
            value: "203.0.113.7".into(),
            ttl: 600,
            priority: None,
        };
        assert_eq!(from_raw(raw).unwrap(), rec);
    }
}
