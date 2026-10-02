//! Azure 记录集 JSON ↔ 统一 Record 模型转换（M9-DNS006）
//!
//! 记录集响应形如：
//! ```json
//! {"name":"my-pc","type":"Microsoft.Network/dnsZones/A",
//!  "properties":{"TTL":600,"ARecords":[{"ipv4Address":"1.2.3.4"}]}}
//! ```
//! - 根记录集 name 为 `"@"` → 统一模型 `""`；
//! - 类型取 `type` 最后一段（`A`/`AAAA`/`CNAME`/`MX`/`TXT`/`SRV`/`NS`；SOA 等跳过）；
//! - A/AAAA/NS/SRV/MX 记录集内多条 → 统一模型同 name+rtype 多条 Record；
//! - TXT：`TxtRecords[].value[]` 数组拼接为单值（TXT 分段语义）；
//! - CNAME：`CNAMERecord.cname` 单对象。

use crate::provider::{Record, RecordData, RecordType};
use serde_json::Value;

/// 记录集级 TTL 默认值（properties.TTL 缺失或 ttl=0 时使用）。
pub const DEFAULT_TTL: u32 = 600;

/// 解析一个记录集 JSON → 统一 Record 列表（未知类型如 SOA → 空）。
pub fn parse_record_set(item: &Value) -> Vec<Record> {
    let name_raw = item.get("name").and_then(Value::as_str).unwrap_or("");
    // Azure 根记录集名称为 "@"；统一模型根为 ""。
    let name = if name_raw == "@" {
        String::new()
    } else {
        name_raw.to_string()
    };
    let type_raw = item.get("type").and_then(Value::as_str).unwrap_or("");
    let rtype_str = type_raw.rsplit('/').next().unwrap_or("");
    let Ok(rtype) = rtype_str.parse::<RecordType>() else {
        return Vec::new(); // SOA 等不在统一模型 → 跳过
    };
    let props = item.get("properties");
    let ttl = props
        .and_then(|p| p.get("TTL"))
        .and_then(Value::as_u64)
        .map(|t| t as u32)
        .unwrap_or(DEFAULT_TTL);

    let values: Vec<RecordData> = match rtype {
        RecordType::A => arr_values(props, "ARecords", "ipv4Address"),
        RecordType::AAAA => arr_values(props, "AAAARecords", "ipv6Address"),
        RecordType::NS => arr_values(props, "NSRecords", "nsdname"),
        RecordType::CNAME => {
            props
                .and_then(|p| p.get("CNAMERecord"))
                .and_then(|c| c.get("cname"))
                .and_then(Value::as_str)
                .map(|v| vec![RecordData::Plain(v.to_string())])
                .unwrap_or_default()
        }
        RecordType::TXT => {
            let mut out = Vec::new();
            if let Some(arr) = props.and_then(|p| p.get("TXTRecords")).and_then(Value::as_array) {
                for rec in arr {
                    // TxtRecords[].value[] 数组 → 拼接为单值。
                    let joined: String = rec
                        .get("value")
                        .and_then(Value::as_array)
                        .map(|vs| {
                            vs.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join("")
                        })
                        .unwrap_or_default();
                    out.push(RecordData::Plain(joined));
                }
            }
            out
        }
        RecordType::MX => {
            let mut out = Vec::new();
            if let Some(arr) = props.and_then(|p| p.get("MXRecords")).and_then(Value::as_array) {
                for rec in arr {
                    let (Some(priority), Some(exchange)) = (
                        rec.get("preference").and_then(Value::as_u64),
                        rec.get("exchange").and_then(Value::as_str),
                    ) else {
                        continue;
                    };
                    out.push(RecordData::Mx {
                        priority: priority as u16,
                        exchange: exchange.to_string(),
                    });
                }
            }
            out
        }
        RecordType::SRV => {
            let mut out = Vec::new();
            if let Some(arr) = props.and_then(|p| p.get("SRVRecords")).and_then(Value::as_array) {
                for rec in arr {
                    let (Some(priority), Some(weight), Some(port), Some(target)) = (
                        rec.get("priority").and_then(Value::as_u64),
                        rec.get("weight").and_then(Value::as_u64),
                        rec.get("port").and_then(Value::as_u64),
                        rec.get("target").and_then(Value::as_str),
                    ) else {
                        continue;
                    };
                    out.push(RecordData::Srv {
                        priority: priority as u16,
                        weight: weight as u16,
                        port: port as u16,
                        target: target.to_string(),
                    });
                }
            }
            out
        }
    };

    values
        .into_iter()
        .map(|data| Record {
            name: name.clone(),
            rtype,
            ttl,
            data,
        })
        .collect()
}

/// A/AAAA/NS 类：数组中取指定字段字符串。
fn arr_values(props: Option<&Value>, field: &str, key: &str) -> Vec<RecordData> {
    let mut out = Vec::new();
    if let Some(arr) = props.and_then(|p| p.get(field)).and_then(Value::as_array) {
        for e in arr {
            if let Some(v) = e.get(key).and_then(Value::as_str) {
                out.push(RecordData::Plain(v.to_string()));
            }
        }
    }
    out
}

/// 统一 Record 列表 → ARM 记录集 `properties` JSON（PUT body 的 properties）。
///
/// 记录集语义：同 name+rtype 的整组替换；`ttl` 为记录集级 TTL。
pub fn records_to_properties(recs: &[Record], ttl: u32) -> Value {
    let rtype = recs.first().map(|r| r.rtype).unwrap_or(RecordType::A);
    let ttl = if ttl == 0 { DEFAULT_TTL } else { ttl };
    let mut props = serde_json::Map::new();
    props.insert("TTL".to_string(), Value::from(ttl));

    match rtype {
        RecordType::A => {
            let items: Vec<Value> = recs
                .iter()
                .filter_map(|r| plain_data(&r.data))
                .map(|v| serde_json::json!({ "ipv4Address": v }))
                .collect();
            props.insert("ARecords".to_string(), Value::Array(items));
        }
        RecordType::AAAA => {
            let items: Vec<Value> = recs
                .iter()
                .filter_map(|r| plain_data(&r.data))
                .map(|v| serde_json::json!({ "ipv6Address": v }))
                .collect();
            props.insert("AAAARecords".to_string(), Value::Array(items));
        }
        RecordType::NS => {
            let items: Vec<Value> = recs
                .iter()
                .filter_map(|r| plain_data(&r.data))
                .map(|v| serde_json::json!({ "nsdname": v }))
                .collect();
            props.insert("NSRecords".to_string(), Value::Array(items));
        }
        RecordType::CNAME => {
            if let Some(v) = recs.first().and_then(|r| plain_data(&r.data)) {
                props.insert("CNAMERecord".to_string(), serde_json::json!({ "cname": v }));
            }
        }
        RecordType::TXT => {
            let items: Vec<Value> = recs
                .iter()
                .filter_map(|r| plain_data(&r.data))
                .map(|v| serde_json::json!({ "value": [v] }))
                .collect();
            props.insert("TXTRecords".to_string(), Value::Array(items));
        }
        RecordType::MX => {
            let items: Vec<Value> = recs
                .iter()
                .filter_map(|r| match &r.data {
                    RecordData::Mx { priority, exchange } => Some(serde_json::json!({
                        "preference": priority,
                        "exchange": exchange,
                    })),
                    _ => None,
                })
                .collect();
            props.insert("MXRecords".to_string(), Value::Array(items));
        }
        RecordType::SRV => {
            let items: Vec<Value> = recs
                .iter()
                .filter_map(|r| match &r.data {
                    RecordData::Srv { priority, weight, port, target } => Some(serde_json::json!({
                        "priority": priority,
                        "weight": weight,
                        "port": port,
                        "target": target,
                    })),
                    _ => None,
                })
                .collect();
            props.insert("SRVRecords".to_string(), Value::Array(items));
        }
    }
    Value::Object(props)
}

fn plain_data(data: &RecordData) -> Option<String> {
    match data {
        RecordData::Plain(v) => Some(v.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_a_multi_value_set() {
        let item = serde_json::json!({
            "name": "my-pc",
            "type": "Microsoft.Network/dnsZones/A",
            "properties": {
                "TTL": 600,
                "ARecords": [
                    {"ipv4Address": "192.0.2.1"},
                    {"ipv4Address": "192.0.2.2"}
                ]
            }
        });
        let recs = parse_record_set(&item);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].name, "my-pc");
        assert_eq!(recs[0].rtype, RecordType::A);
        assert_eq!(recs[0].ttl, 600);
        assert_eq!(recs[0].data, RecordData::Plain("192.0.2.1".into()));
        assert_eq!(recs[1].data, RecordData::Plain("192.0.2.2".into()));
    }

    #[test]
    fn parse_root_at_and_soa_skip() {
        let root = serde_json::json!({
            "name": "@",
            "type": "Microsoft.Network/dnsZones/CNAME",
            "properties": {"TTL": 300, "CNAMERecord": {"cname": "target.example.com"}}
        });
        let recs = parse_record_set(&root);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].name, "", "根 '@' → 统一模型空串");
        assert_eq!(recs[0].data, RecordData::Plain("target.example.com".into()));

        let soa = serde_json::json!({
            "name": "@",
            "type": "Microsoft.Network/dnsZones/SOA",
            "properties": {"TTL": 3600, "SoaRecord": {"host": "ns1"}}
        });
        assert!(parse_record_set(&soa).is_empty(), "SOA 不在统一模型");
    }

    #[test]
    fn parse_txt_join_and_mx_srv_structured() {
        let txt = serde_json::json!({
            "name": "my-pc",
            "type": "Microsoft.Network/dnsZones/TXT",
            "properties": {"TTL": 300, "TXTRecords": [{"value": ["seg1", "seg2"]}]}
        });
        let recs = parse_record_set(&txt);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].data, RecordData::Plain("seg1seg2".into()), "TXT 数组拼接为单值");

        let mx = serde_json::json!({
            "name": "@",
            "type": "Microsoft.Network/dnsZones/MX",
            "properties": {"TTL": 300, "MXRecords": [{"preference": 10, "exchange": "mail.example.com"}]}
        });
        let recs = parse_record_set(&mx);
        assert_eq!(
            recs[0].data,
            RecordData::Mx { priority: 10, exchange: "mail.example.com".into() }
        );

        let srv = serde_json::json!({
            "name": "_sip._tcp",
            "type": "Microsoft.Network/dnsZones/SRV",
            "properties": {"TTL": 60, "SRVRecords": [{"priority": 0, "weight": 5, "port": 5060, "target": "sip.example.com"}]}
        });
        let recs = parse_record_set(&srv);
        assert_eq!(
            recs[0].data,
            RecordData::Srv { priority: 0, weight: 5, port: 5060, target: "sip.example.com".into() }
        );
    }

    #[test]
    fn records_to_properties_shape() {
        let recs = vec![
            Record { name: "my-pc".into(), rtype: RecordType::A, ttl: 600, data: RecordData::Plain("192.0.2.1".into()) },
            Record { name: "my-pc".into(), rtype: RecordType::A, ttl: 600, data: RecordData::Plain("192.0.2.2".into()) },
        ];
        let props = records_to_properties(&recs, 300);
        assert_eq!(props["TTL"], 300);
        assert_eq!(props["ARecords"][0]["ipv4Address"], "192.0.2.1");
        assert_eq!(props["ARecords"][1]["ipv4Address"], "192.0.2.2");

        // SRV 结构化写入。
        let srv = vec![Record {
            name: "_sip._tcp".into(),
            rtype: RecordType::SRV,
            ttl: 60,
            data: RecordData::Srv { priority: 0, weight: 5, port: 5060, target: "sip.example.com".into() },
        }];
        let props = records_to_properties(&srv, 0);
        assert_eq!(props["TTL"], DEFAULT_TTL, "ttl=0 → 默认");
        assert_eq!(props["SRVRecords"][0]["priority"], 0);
        assert_eq!(props["SRVRecords"][0]["weight"], 5);
        assert_eq!(props["SRVRecords"][0]["port"], 5060);
        assert_eq!(props["SRVRecords"][0]["target"], "sip.example.com");
    }
}
