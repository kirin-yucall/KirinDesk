use crate::provider::{Provider, ProviderError, Record, RecordData, RecordType};
use crate::validate;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// SRV record name format: `_remote._tcp.{device_id}.{domain}`
///
/// The SRV record lives on the device's subdomain, under the standard
/// `_remote._tcp` prefix. This follows the Kirin protocol convention
/// where each device owns its subdomain.
fn srv_record_name(device_id: &str) -> String {
    format!("_remote._tcp.{}", device_id)
}

/// SRV record data (兼容结构，保留 `from_string`/`to_string` 供既有调用方使用；
/// 服务层新代码路径统一走 `RecordData::Srv`，不再做字符串拼接/解析)。
///
/// SRV data 格式：`{priority} {weight} {port} {target}.`
/// 示例：`0 1 3389 my-device.example.com.`
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
    /// Parse SRV data from string format.
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

    /// Serialize SRV data to string format（`{priority} {weight} {port} {target}.`）。
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

/// 入参校验（S-14b / F-18）：`device_id` 与 relay 侧规则对齐；
/// `domain`/`target` 必须是 RFC 1123 主机名（target 容忍 FQDN 结尾点）。
fn validate_context(device_id: &str, domain: &str) -> Result<(), ProviderError> {
    if !validate::validate_device_id(device_id) {
        return Err(ProviderError::InvalidParameter {
            detail: format!(
                "invalid device_id '{}' (charset [a-zA-Z0-9:_-], len 1..=128, no '.' allowed)",
                device_id
            ),
        });
    }
    if !validate::validate_hostname(domain) {
        return Err(ProviderError::InvalidParameter {
            detail: format!("invalid domain '{}' (must be an RFC 1123 hostname)", domain),
        });
    }
    Ok(())
}

/// Manage SRV records for service discovery.
///
/// SRV records store the port and target hostname for a device's remote desktop service.
/// These are optional — the primary metadata source is the TXT `DeviceMeta` JSON record
/// on the device's subdomain root.
///
/// M9-DNS000：多服务商化——只依赖 `&dyn Provider`，不感知厂商差异。
pub struct SrvManager<'a> {
    provider: &'a dyn Provider,
    domain: &'a str,
}

impl<'a> SrvManager<'a> {
    pub fn new(provider: &'a dyn Provider, domain: &'a str) -> Self {
        Self { provider, domain }
    }

    /// Register or update an SRV record for a device.
    ///
    /// The record is placed at `_remote._tcp.{device_id}.{domain}`.
    ///
    /// 校验（S-14b / F-18）：`device_id`/`domain`/`target` 统一字符集 + 长度校验，
    /// 非法入参返回 `InvalidParameter`（不做任何 API 调用）。
    pub async fn register(
        &self,
        device_id: &str,
        port: u16,
        target: &str,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        validate_context(device_id, self.domain)?;
        if !validate::validate_hostname(target) {
            return Err(ProviderError::InvalidParameter {
                detail: format!(
                    "invalid SRV target '{}' (must be an RFC 1123 hostname)",
                    target
                ),
            });
        }
        let name = srv_record_name(device_id);
        debug!(
            "SRV register: device={}, name={}, port={}, target={}, ttl={}",
            device_id, name, port, target, ttl
        );
        let rec = Record {
            name,
            rtype: RecordType::SRV,
            ttl,
            data: RecordData::Srv {
                priority: 0,
                weight: 1,
                port,
                target: target.to_string(),
            },
        };
        self.provider.upsert_record(self.domain, &rec).await
    }

    /// Query SRV records for a device.
    ///
    /// 解析 `RecordData::Srv` → `Vec<SrvData>`（`SrvData` 为兼容视图，字段
    /// 与 `RecordData::Srv` 一一对应）。
    pub async fn query(&self, device_id: &str) -> Result<Vec<SrvData>, ProviderError> {
        validate_context(device_id, self.domain)?;
        let name = srv_record_name(device_id);
        debug!("SRV query: device={}, record_name={}", device_id, name);
        let records = self
            .provider
            .query_records(self.domain, Some(&name), Some(RecordType::SRV))
            .await?;

        records
            .iter()
            .map(|r| match &r.data {
                RecordData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                } => Ok(SrvData {
                    priority: *priority,
                    weight: *weight,
                    port: *port,
                    target: target.clone(),
                }),
                other => Err(ProviderError::InvalidParameter {
                    detail: format!("Failed to parse SRV data: {}", other.to_display_string()),
                }),
            })
            .collect()
    }

    /// Get the port from the first SRV record for a device.
    pub async fn get_port(&self, device_id: &str) -> Result<u16, ProviderError> {
        let srv_list = self.query(device_id).await?;
        srv_list
            .first()
            .map(|s| s.port)
            .ok_or_else(|| ProviderError::NotFound {
                what: format!("SRV _remote._tcp.{}.{}", device_id, self.domain),
            })
    }

    /// Delete SRV records for a device.
    pub async fn remove(&self, device_id: &str) -> Result<(), ProviderError> {
        validate_context(device_id, self.domain)?;
        let name = srv_record_name(device_id);
        self.provider
            .delete_record(self.domain, &name, RecordType::SRV)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::mock::MockProvider;

    #[test]
    fn test_srv_record_name_format() {
        let name = srv_record_name("my-pc");
        // Under Kirin protocol: _remote._tcp.my-pc → resolves on domain as _remote._tcp.my-pc.example.com
        assert_eq!(name, "_remote._tcp.my-pc");
    }

    #[test]
    fn test_srv_record_name_with_special_chars() {
        let name = srv_record_name("device-123");
        assert_eq!(name, "_remote._tcp.device-123");
    }

    // ---- S-14b / F-18: 入参校验拒绝 ----

    #[tokio::test]
    async fn test_register_rejects_invalid_target() {
        let provider = MockProvider::new("mock");
        let mgr = SrvManager::new(&provider, "example.com");
        let err = mgr
            .register("my-pc", 3389, "not a hostname!!", 600)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProviderError::InvalidParameter { .. }),
            "invalid SRV target must be rejected, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_query_rejects_invalid_device_id() {
        let provider = MockProvider::new("mock");
        let mgr = SrvManager::new(&provider, "example.com");
        // '.' 是 F-18 子域注入点，必须在任何 API 调用前拒绝。
        let err = mgr.query("a.b.c").await.unwrap_err();
        assert!(
            matches!(err, ProviderError::InvalidParameter { .. }),
            "device_id containing '.' must be rejected, got {:?}",
            err
        );
    }

    // ---- MockProvider 往返（M9-DNS000 抽象层语义） ----

    #[tokio::test]
    async fn test_register_and_query_roundtrip() {
        let provider = MockProvider::new("mock");
        let mgr = SrvManager::new(&provider, "example.com");

        mgr.register("my-pc", 3389, "my-pc.example.com.", 600)
            .await
            .unwrap();

        // MockProvider 内存态：SRV 结构化存储（RecordData::Srv）。
        let stored = provider.records_of("example.com", RecordType::SRV, "_remote._tcp.my-pc");
        assert_eq!(stored.len(), 1);
        assert!(matches!(
            &stored[0].data,
            RecordData::Srv {
                priority: 0,
                weight: 1,
                port: 3389,
                target
            } if target == "my-pc.example.com."
        ));

        let srv_list = mgr.query("my-pc").await.unwrap();
        assert_eq!(srv_list.len(), 1);
        assert_eq!(srv_list[0].priority, 0);
        assert_eq!(srv_list[0].weight, 1);
        assert_eq!(srv_list[0].port, 3389);
        assert_eq!(srv_list[0].target, "my-pc.example.com.");

        assert_eq!(mgr.get_port("my-pc").await.unwrap(), 3389);
    }

    #[tokio::test]
    async fn test_query_parses_invalid_data_as_error() {
        let provider = MockProvider::new("mock");
        // 种子数据为字符串形态（模拟适配层失职/脏数据）→ 读侧解析失败。
        provider.seed_record(
            "example.com",
            Record {
                name: "_remote._tcp.my-pc".to_string(),
                rtype: RecordType::SRV,
                ttl: 600,
                data: RecordData::Plain("not-an-srv-data".to_string()),
            },
        );
        let mgr = SrvManager::new(&provider, "example.com");
        let err = mgr.query("my-pc").await.unwrap_err();
        assert!(matches!(err, ProviderError::InvalidParameter { .. }));
    }

    #[tokio::test]
    async fn test_get_port_not_found() {
        let provider = MockProvider::new("mock");
        let mgr = SrvManager::new(&provider, "example.com");
        let err = mgr.get_port("ghost").await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    #[tokio::test]
    async fn test_remove_deletes() {
        let provider = MockProvider::new("mock");
        let mgr = SrvManager::new(&provider, "example.com");

        mgr.register("my-pc", 3389, "my-pc.example.com.", 600)
            .await
            .unwrap();
        mgr.remove("my-pc").await.unwrap();

        assert!(
            provider
                .records_of("example.com", RecordType::SRV, "_remote._tcp.my-pc")
                .is_empty()
        );
        assert_eq!(provider.delete_count(), 1);
    }

    // ---- SrvData 兼容结构 ----

    #[test]
    fn test_srv_data_compat_roundtrip() {
        let srv = SrvData {
            priority: 0,
            weight: 1,
            port: 3389,
            target: "my-device.example.com.".to_string(),
        };
        let s = srv.to_string();
        assert_eq!(s, "0 1 3389 my-device.example.com.");
        assert_eq!(SrvData::from_string(&s).unwrap().port, 3389);
        assert_eq!(SrvData::from_string(&s).unwrap().target, "my-device.example.com.");
        // 与 RecordData::Srv 一一对应。
        let rec_data = RecordData::Srv {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: srv.target.clone(),
        };
        assert_eq!(rec_data.to_display_string(), format!("{}.", s.trim_end_matches('.')));
    }
}
