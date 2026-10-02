//! M9-DNS000: 统一 Record 模型（`M9-DNS000_Provider抽象接口规范.md` §二）
//!
//! 覆盖 20 家服务商全部能力的统一记录模型。`name` 一律为**相对名**
//! （如 "my-pc"，根为 ""），适配层负责与厂商格式互转（FQDN / @ / 空）。
//! `data` 类型化（`RecordData`），避免 SRV/MX 这类结构化记录退化为字符串拼接。

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// 统一记录类型（覆盖 20 家服务商全部能力）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    SRV,
    NS,
}

impl RecordType {
    /// 服务商 API 使用的类型字符串（A/AAAA/CNAME/MX/TXT/SRV/NS）。
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::SRV => "SRV",
            RecordType::NS => "NS",
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RecordType {
    type Err = ();

    /// 大小写不敏感解析（"a"/"AAAA" 均可）；未知类型返回 Err。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "SRV" => Ok(RecordType::SRV),
            "NS" => Ok(RecordType::NS),
            _ => Err(()),
        }
    }
}

/// 统一记录。`name` 为相对名（"" = 根/@），适配层负责互转。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// 相对名；"" 表示根（@）。
    pub name: String,
    pub rtype: RecordType,
    /// 秒；0 = 使用服务商默认。
    pub ttl: u32,
    pub data: RecordData,
}

/// 类型化数据，避免 SRV/MX 这类结构化记录退化为字符串拼接。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecordData {
    /// A/AAAA/CNAME/TXT/NS 的值。
    Plain(String),
    Mx {
        priority: u16,
        exchange: String,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
}

impl RecordData {
    /// 服务商通用的字符串形态：
    /// - `Plain` → 原值；
    /// - `Mx` → `{priority} {exchange}`；
    /// - `Srv` → `{priority} {weight} {port} {target}.`（末尾点，GoDaddy 惯例）。
    /// 具体服务商 wire 格式差异由各自适配层转换，此形态供上层（srv/txt 等）
    /// 构造/展示用。
    pub fn to_display_string(&self) -> String {
        match self {
            RecordData::Plain(s) => s.clone(),
            RecordData::Mx { priority, exchange } => format!("{priority} {exchange}"),
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                let target = if target.ends_with('.') {
                    target.clone()
                } else {
                    format!("{target}.")
                };
                format!("{priority} {weight} {port} {target}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_roundtrip() {
        for t in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::MX,
            RecordType::TXT,
            RecordType::SRV,
            RecordType::NS,
        ] {
            assert_eq!(t.to_string().parse::<RecordType>(), Ok(t));
            assert_eq!(t.to_string().to_lowercase().parse::<RecordType>(), Ok(t));
        }
        assert!("SOA".parse::<RecordType>().is_err());
        assert!("".parse::<RecordType>().is_err());
    }

    #[test]
    fn record_type_serde_uppercase() {
        let v = serde_json::to_value(RecordType::SRV).unwrap();
        assert_eq!(v, serde_json::json!("SRV"));
        let t: RecordType = serde_json::from_value(v).unwrap();
        assert_eq!(t, RecordType::SRV);
    }

    #[test]
    fn srv_display_string_appends_trailing_dot() {
        let srv = RecordData::Srv {
            priority: 0,
            weight: 1,
            port: 3389,
            target: "my-pc.example.com".to_string(),
        };
        assert_eq!(srv.to_display_string(), "0 1 3389 my-pc.example.com.");
        // 已带结尾点 → 不重复追加。
        let srv2 = RecordData::Srv {
            priority: 0,
            weight: 1,
            port: 3389,
            target: "my-pc.example.com.".to_string(),
        };
        assert_eq!(srv2.to_display_string(), "0 1 3389 my-pc.example.com.");
    }

    #[test]
    fn mx_display_string() {
        let mx = RecordData::Mx {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        };
        assert_eq!(mx.to_display_string(), "10 mail.example.com");
    }
}
