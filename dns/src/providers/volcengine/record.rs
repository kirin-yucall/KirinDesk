//! M9-DNS017: 火山引擎云解析记录模型互转
//!
//! 统一模型（`provider::record`）↔ 火山 wire 格式（记录集 RecordSet）：
//! - 记录名：统一模型为相对名（`""` = 根）；火山 `Host` 字段根用 `@` 表示
//!   （控制台惯例），`@` ↔ `""` 互转。
//! - 记录集以 `RecordSetId` 定位（CreateRecord 返回 / ListRecordSets 返回）。
//! - SRV：`Value` 为 `"优先级 权重 端口 目标"` 空格分隔串；
//! - MX：`Priority` 独立参数 + `Value` = exchange；读取时若无 Priority 字段，
//!   尝试从 value 前缀 `"N exchange"` 解析。
//! - 字段名兼容：读取时 `Host`/`RR`、`RecordSetId`/`ID` 均接受（serde alias）。

use crate::provider::{Record, RecordData, RecordType};
use serde::Deserialize;
use std::collections::BTreeMap;

/// ListRecordSets 返回的记录集（wire 格式，字段名与官方一致，兼容别名）。
#[derive(Debug, Clone, Deserialize)]
pub struct RawRecordSet {
    #[serde(rename = "RecordSetId", alias = "ID", alias = "Id", alias = "id")]
    pub record_set_id: String,
    #[serde(rename = "Host", alias = "RR", alias = "rr")]
    pub host: String,
    #[serde(rename = "Type")]
    pub rtype: String,
    #[serde(rename = "Value")]
    pub value: Option<String>,
    #[serde(rename = "TTL")]
    pub ttl: Option<u32>,
    #[serde(rename = "Priority")]
    pub priority: Option<u32>,
}

/// 相对名 → 火山 Host（根 `""` → `@`）。
pub fn to_vendor_host(name: &str) -> String {
    if name.is_empty() {
        "@".to_string()
    } else {
        name.to_string()
    }
}

/// 火山 Host → 相对名（`@` → `""`）。
pub fn to_relative_name(host: &str) -> String {
    if host == "@" {
        String::new()
    } else {
        host.to_string()
    }
}

/// 统一记录 → CreateRecord/UpdateRecord 请求参数表。
///
/// - `Plain` → Value 原值；`Mx` → Value=exchange + Priority；`Srv` → `"p w port target"`；
/// - ttl=0 表示使用服务商默认 → 不传 TTL。
pub fn to_params(rec: &Record) -> BTreeMap<String, String> {
    let mut params = BTreeMap::new();
    params.insert("Host".into(), to_vendor_host(&rec.name));
    params.insert("Type".into(), rec.rtype.as_str().to_string());
    match &rec.data {
        RecordData::Plain(v) => {
            params.insert("Value".into(), v.clone());
        }
        RecordData::Mx { priority, exchange } => {
            params.insert("Value".into(), exchange.clone());
            params.insert("Priority".into(), priority.to_string());
        }
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            params.insert(
                "Value".into(),
                format!("{priority} {weight} {port} {target}"),
            );
        }
    }
    if rec.ttl > 0 {
        params.insert("TTL".into(), rec.ttl.to_string());
    }
    params
}

/// wire 记录集 → 统一记录；类型未知 → `None`（跳过）。
///
/// SRV 解析为结构化 `RecordData::Srv`（失败退化 `Plain`）；
/// MX 优先用 `Priority` 字段，缺失时从 value 前缀解析；value 缺失 → `Plain("")`。
pub fn from_raw(raw: RawRecordSet) -> Option<Record> {
    let rtype = raw.rtype.parse::<RecordType>().ok()?;
    let value = raw.value.unwrap_or_default();
    let data = match rtype {
        RecordType::SRV => parse_srv_value(&value)
            .map(|(p, w, port, t)| RecordData::Srv {
                priority: p,
                weight: w,
                port,
                target: t,
            })
            .unwrap_or(RecordData::Plain(value)),
        RecordType::MX => {
            let (priority, exchange) = match raw.priority {
                Some(p) => (p as u16, value.clone()),
                // 响应未带 Priority 字段：尝试从 value 前缀 `"N exchange"` 拆分。
                None => split_mx_value(&value),
            };
            RecordData::Mx { priority, exchange }
        }
        _ => RecordData::Plain(value),
    };
    Some(Record {
        name: to_relative_name(&raw.host),
        rtype,
        ttl: raw.ttl.unwrap_or(0),
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
    fn host_root_conversion() {
        assert_eq!(to_vendor_host(""), "@");
        assert_eq!(to_vendor_host("www"), "www");
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
                weight: 1,
                port: 5060,
                target: "sip.example.com".into(),
            },
        };
        let params = to_params(&rec);
        assert_eq!(params["Value"], "0 1 5060 sip.example.com");
        assert_eq!(params["TTL"], "600");
        let raw = RawRecordSet {
            record_set_id: "rs-1".into(),
            host: "@".into(),
            rtype: "SRV".into(),
            value: Some("0 1 5060 sip.example.com".into()),
            ttl: Some(600),
            priority: None,
        };
        let back = from_raw(raw).unwrap();
        assert_eq!(back.name, "");
        assert_eq!(
            back.data,
            RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 5060,
                target: "sip.example.com".into(),
            }
        );
    }

    #[test]
    fn mx_priority_param_or_prefix() {
        let rec = Record {
            name: "".into(),
            rtype: RecordType::MX,
            ttl: 300,
            data: RecordData::Mx {
                priority: 10,
                exchange: "mail.example.com".into(),
            },
        };
        let params = to_params(&rec);
        assert_eq!(params["Value"], "mail.example.com");
        assert_eq!(params["Priority"], "10");
        // 响应带 Priority。
        let raw = RawRecordSet {
            record_set_id: "rs-2".into(),
            host: "@".into(),
            rtype: "MX".into(),
            value: Some("mail.example.com".into()),
            ttl: Some(300),
            priority: Some(10),
        };
        assert!(matches!(
            from_raw(raw).unwrap().data,
            RecordData::Mx { priority: 10, .. }
        ));
        // 响应不带 Priority：从 value 前缀解析。
        let raw = RawRecordSet {
            record_set_id: "rs-3".into(),
            host: "@".into(),
            rtype: "MX".into(),
            value: Some("10 mail.example.com".into()),
            ttl: Some(300),
            priority: None,
        };
        assert!(matches!(
            from_raw(raw).unwrap().data,
            RecordData::Mx { priority: 10, exchange } if exchange == "mail.example.com"
        ));
    }

    #[test]
    fn plain_and_missing_value() {
        let rec = Record {
            name: "my-pc".into(),
            rtype: RecordType::A,
            ttl: 0,
            data: RecordData::Plain("203.0.113.7".into()),
        };
        let params = to_params(&rec);
        assert_eq!(params["Value"], "203.0.113.7");
        assert!(!params.contains_key("TTL"), "ttl=0 → 不传");
        // value 缺失 → Plain("")，记录不丢。
        let raw = RawRecordSet {
            record_set_id: "rs-4".into(),
            host: "my-pc".into(),
            rtype: "A".into(),
            value: None,
            ttl: None,
            priority: None,
        };
        let back = from_raw(raw).unwrap();
        assert_eq!(back.data, RecordData::Plain(String::new()));
    }

    #[test]
    fn unknown_type_skipped() {
        let raw = RawRecordSet {
            record_set_id: "rs-5".into(),
            host: "x".into(),
            rtype: "CAA".into(),
            value: Some("0 issue ca".into()),
            ttl: Some(600),
            priority: None,
        };
        assert!(from_raw(raw).is_none());
    }
}
