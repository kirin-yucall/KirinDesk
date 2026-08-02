use crate::godaddy::{GoDaddyClient, GoDaddyError, Record, SrvData};
use tracing::debug;

/// SRV record name format: `_remote._tcp.{device_id}.{domain}`
///
/// The SRV record lives on the device's subdomain, under the standard
/// `_remote._tcp` prefix. This follows the Kirin protocol convention
/// where each device owns its subdomain.
fn srv_record_name(device_id: &str) -> String {
    format!("_remote._tcp.{}", device_id)
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
    pub async fn register(
        &self,
        device_id: &str,
        port: u16,
        target: &str,
        ttl: u32,
    ) -> Result<(), GoDaddyError> {
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
        let name = srv_record_name(device_id);
        self.client
            .delete_record(self.domain, "SRV", &name)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
