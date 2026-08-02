use crate::godaddy::{GoDaddyClient, GoDaddyError, Record, SrvData};
use crate::validate;
use tracing::debug;

/// SRV record name format: `_remote._tcp.{device_id}.{domain}`
///
/// The SRV record lives on the device's subdomain, under the standard
/// `_remote._tcp` prefix. This follows the Kirin protocol convention
/// where each device owns its subdomain.
fn srv_record_name(device_id: &str) -> String {
    format!("_remote._tcp.{}", device_id)
}

/// 入参校验（S-14b / F-18）：`device_id` 与 relay 侧规则对齐；
/// `domain`/`target` 必须是 RFC 1123 主机名（target 容忍 FQDN 结尾点）。
fn validate_context(device_id: &str, domain: &str) -> Result<(), GoDaddyError> {
    if !validate::validate_device_id(device_id) {
        return Err(GoDaddyError::InvalidParameters {
            body: format!(
                "invalid device_id '{}' (charset [a-zA-Z0-9:_-], len 1..=128, no '.' allowed)",
                device_id
            ),
        });
    }
    if !validate::validate_hostname(domain) {
        return Err(GoDaddyError::InvalidParameters {
            body: format!("invalid domain '{}' (must be an RFC 1123 hostname)", domain),
        });
    }
    Ok(())
}

/// Manage SRV records for service discovery.
///
/// SRV records store the port and target hostname for a device's remote desktop service.
/// These are optional — the primary metadata source is the TXT `DeviceMeta` JSON record
/// on the device's subdomain root.
pub struct SrvManager<'a> {
    client: &'a GoDaddyClient,
    domain: &'a str,
}

impl<'a> SrvManager<'a> {
    pub fn new(client: &'a GoDaddyClient, domain: &'a str) -> Self {
        Self { client, domain }
    }

    /// Register or update an SRV record for a device.
    ///
    /// The record is placed at `_remote._tcp.{device_id}.{domain}`.
    ///
    /// 校验（S-14b / F-18）：`device_id`/`domain`/`target` 统一字符集 + 长度校验，
    /// 非法入参返回 `InvalidParameters`（不做任何 API 调用）。
    pub async fn register(
        &self,
        device_id: &str,
        port: u16,
        target: &str,
        ttl: u32,
    ) -> Result<(), GoDaddyError> {
        validate_context(device_id, self.domain)?;
        if !validate::validate_hostname(target) {
            return Err(GoDaddyError::InvalidParameters {
                body: format!(
                    "invalid SRV target '{}' (must be an RFC 1123 hostname)",
                    target
                ),
            });
        }
        let name = srv_record_name(device_id);
        debug!("SRV register: device={}, name={}, port={}, target={}, ttl={}", device_id, name, port, target, ttl);
        let data = SrvData {
            priority: 0,
            weight: 1,
            port,
            target: target.to_string(),
        };

        let records = vec![Record {
            data: data.to_string(),
            ttl,
        }];

        self.client
            .put_records(self.domain, "SRV", &name, &records)
            .await
    }

    /// Query SRV records for a device.
    pub async fn query(&self, device_id: &str) -> Result<Vec<SrvData>, GoDaddyError> {
        validate_context(device_id, self.domain)?;
        let name = srv_record_name(device_id);
        debug!("SRV query: device={}, record_name={}", device_id, name);
        let records = self
            .client
            .get_records(self.domain, "SRV", &name)
            .await?;

        records
            .iter()
            .map(|r| SrvData::from_string(&r.data).ok_or_else(|| GoDaddyError::InvalidParameters {
                body: format!("Failed to parse SRV data: {}", r.data),
            }))
            .collect()
    }

    /// Get the port from the first SRV record for a device.
    pub async fn get_port(&self, device_id: &str) -> Result<u16, GoDaddyError> {
        let srv_list = self.query(device_id).await?;
        srv_list
            .first()
            .map(|s| s.port)
            .ok_or_else(|| GoDaddyError::NotFound {
                name: device_id.to_string(),
                record_type: "SRV".to_string(),
            })
    }

    /// Delete SRV records for a device.
    pub async fn remove(&self, device_id: &str) -> Result<(), GoDaddyError> {
        validate_context(device_id, self.domain)?;
        let name = srv_record_name(device_id);
        self.client
            .delete_record(self.domain, "SRV", &name)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MockDns;

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
        let mock = MockDns::start().await;
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let mgr = SrvManager::new(&client, "example.com");
        let err = mgr
            .register("my-pc", 3389, "not a hostname!!", 600)
            .await
            .unwrap_err();
        assert!(
            matches!(err, GoDaddyError::InvalidParameters { .. }),
            "invalid SRV target must be rejected, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_query_rejects_invalid_device_id() {
        let mock = MockDns::start().await;
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let mgr = SrvManager::new(&client, "example.com");
        // '.' 是 F-18 子域注入点，必须在任何 API 调用前拒绝。
        let err = mgr.query("a.b.c").await.unwrap_err();
        assert!(
            matches!(err, GoDaddyError::InvalidParameters { .. }),
            "device_id containing '.' must be rejected, got {:?}",
            err
        );
    }
}
