//! M9-DNS016: 百度智能云记录模型互转
//!
//! 统一模型（`provider::record`）↔ 百度 wire 格式：
//! - 记录名：统一模型为相对名（`""` = 根）；百度 `rr` 字段根用 `@` 表示
//!   （控制台惯例），`@` ↔ `""` 互转。
//! - SRV：`value` 为 `"优先级 权重 端口 目标"` 空格分隔串
//!   （官方样例 `0 6 8080 vipserver.test.com`）。
//! - MX：`priority` 独立字段（[0,50]，MX 必选）+ `value` = exchange；
//!   读取时若响应不含 priority 字段，则尝试从 value 前缀解析。
//! - 列表查询接口不提供 type 过滤参数（仅 rr/id/marker/maxKeys），
//!   类型过滤由调用方在内存完成。

use crate::provider::{Record, RecordData, RecordType};
use serde::{Deserialize, Serialize};

/// 记录列表返回的单条记录（wire 格式）。
#[derive(Debug, Clone, Deserialize)]
pub struct RawRecord {
    pub id: String,
    pub rr: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub value: String,
    pub ttl: u32,
    /// MX 优先级（存在与否因接口而异，做 Option）。
    pub priority: Option<u32>,
}

/// 添加/更新记录请求体（wire 格式）。
#[derive(Debug, Clone, Serialize)]
pub struct RecordBody {
    pub rr: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
}

/// 相对名 → 百度 rr（根 `""` → `@`）。
pub fn to_vendor_rr(name: &str) -> String {
    if name.is_empty() {
        "@".to_string()
    } else {
        name.to_string()
    }
}

/// 百度 rr → 相对名（`@` → `""`）。
pub fn to_relative_name(rr: &str) -> String {
    if rr == "@" {
        String::new()
    } else {
        rr.to_string()
    }
}

/// 统一记录 → 请求体。
///
/// - `Plain` → 原值；`Mx` → value=exchange + priority；`Srv` → `"p w port target"`。
/// - ttl=0 表示使用服务商默认 → 不传 ttl 字段。
pub fn to_body(rec: &Record) -> RecordBody {
    let (value, priority) = match &rec.data {
        RecordData::Plain(v) => (v.clone(), None),
        RecordData::Mx { priority, exchange } => (exchange.clone(), Some(*priority as u32)),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => (format!("{priority} {weight} {port} {target}"), None),
    };
    RecordBody {
        rr: to_vendor_rr(&rec.name),
        rtype: rec.rtype.as_str().to_string(),
        value,
        ttl: if rec.ttl > 0 { Some(rec.ttl) } else { None },
        priority,
    }
}

/// wire 记录 → 统一记录；类型未知 → `None`（跳过）。
///
/// SRV 解析为结构化 `RecordData::Srv`（失败退化 `Plain`）；
/// MX 优先用 `priority` 字段，缺失时从 value 前缀 `"N exchange"` 解析。
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
        RecordType::MX => {
            let (priority, exchange) = match raw.priority {
                Some(p) => (p as u16, raw.value.clone()),
                // 响应未带 priority 字段：尝试从 value 前缀 `"N exchange"` 拆分。
                None => split_mx_value(&raw.value),
            };
            RecordData::Mx { priority, exchange }
        }        _ => RecordData::Plain(raw.value.clone()),
    };
    Some(Record {
        name: to_relative_name(&raw.rr),
        rtype,
        ttl: raw.ttl,
        data,
    })
}

/// 解析 SRV 值 `"priority weight port target"`。
fn parse_srv_value(value: &str) -> Option<(u16, u16, u16, String)> {
    let mut it = value.split_whitespace();
    let priority = it.next()?.parse().ok()?;
    let weight = it.next()?.parse().ok()?;
    let port = it.next()?.parse().ok()?;
    let target = it.next()?.to_string();
    Some((priority, weight, port, target))
}

/// 从 value 前缀拆分 MX 优先级与 exchange（`"10 mail.example.com"` → (10, "mail.example.com")；
/// 无数字前缀 → (0, 原值)）。
fn split_mx_value(value: &str) -> (u16, String) {
    let mut it = value.splitn(2, char::is_whitespace);
    match (it.next(), it.next()) {
        (Some(head), Some(rest)) => match head.parse::<u32>() {
            Ok(p) => (p as u16, rest.trim().to_string()),
            Err(_) => (0, value.to_string()),
        },
        _ => (0, value.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rr_root_conversion() {
        assert_eq!(to_vendor_rr(""), "@");
        assert_eq!(to_vendor_rr("www"), "www");
        assert_eq!(to_relative_name("@"), "");
        assert_eq!(to_relative_name("_sip._tcp"), "_sip._tcp");
    }

    #[test]
    fn srv_roundtrip() {
        let rec = Record {
            name: "_sip._tcp".into(),
            rtype: RecordType::SRV,
            ttl: 600,
            data: RecordData::Srv {
                priority: 0,
                weight: 6,
                port: 8080,
                target: "vipserver.test.com".into(),
            },
        };
        assert_eq!(to_body(&rec).value, "0 6 8080 vipserver.test.com");
        let raw = RawRecord {
            id: "r1".into(),
            rr: "@".into(),
            rtype: "SRV".into(),
            value: "0 6 8080 vipserver.test.com".into(),
            ttl: 600,
            priority: None,
        };
        let back = from_raw(raw).unwrap();
        assert_eq!(back.name, "");
        assert_eq!(
            back.data,
            RecordData::Srv {
                priority: 0,
                weight: 6,
                port: 8080,
                target: "vipserver.test.com".into(),
            }
        );
    }

    #[test]
    fn mx_priority_field_or_prefix() {
        let rec = Record {
            name: "".into(),
            rtype: RecordType::MX,
            ttl: 300,
            data: RecordData::Mx {
                priority: 10,
                exchange: "mail.example.com".into(),
            },
        };
        let body = to_body(&rec);
        assert_eq!(body.value, "mail.example.com");
        assert_eq!(body.priority, Some(10));
        // 响应带 priority 字段。
        let raw = RawRecord {
            id: "r2".into(),
            rr: "@".into(),
            rtype: "MX".into(),
            value: "mail.example.com".into(),
            ttl: 300,
            priority: Some(10),
        };
        assert!(matches!(
            from_raw(raw).unwrap().data,
            RecordData::Mx { priority: 10, .. }
        ));
        // 响应不带 priority：从 value 前缀解析。
        let raw = RawRecord {
            id: "r3".into(),
            rr: "@".into(),
            rtype: "MX".into(),
            value: "10 mail.example.com".into(),
            ttl: 300,
            priority: None,
        };
        assert!(matches!(
            from_raw(raw).unwrap().data,
            RecordData::Mx { priority: 10, exchange } if exchange == "mail.example.com"
        ));
    }

    #[test]
    fn plain_and_ttl_default() {
        let rec = Record {
            name: "my-pc".into(),
            rtype: RecordType::A,
            ttl: 0,
            data: RecordData::Plain("203.0.113.7".into()),
        };
        let body = to_body(&rec);
        assert_eq!(body.value, "203.0.113.7");
        assert_eq!(body.ttl, None, "ttl=0 → 不传，使用默认");
        let raw = RawRecord {
            id: "r4".into(),
            rr: "my-pc".into(),
            rtype: "A".into(),
            value: "203.0.113.7".into(),
            ttl: 0,
            priority: None,
        };
        assert_eq!(from_raw(raw).unwrap(), rec);
    }
}
