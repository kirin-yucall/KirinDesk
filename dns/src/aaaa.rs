use crate::godaddy::{GoDaddyClient, GoDaddyError, Record};
use crate::validate;
use std::net::Ipv6Addr;
use tracing::debug;

/// Manage AAAA (IPv6 address) records.
pub struct AaaaManager<'a> {
    client: &'a GoDaddyClient,
    domain: &'a str,
}

impl<'a> AaaaManager<'a> {
    pub fn new(client: &'a GoDaddyClient, domain: &'a str) -> Self {
        Self { client, domain }
    }

    /// S-14b / F-18: device_id 统一校验（拒绝 '.' 子域注入等非法字符）。
    fn check_device_id(&self, device_id: &str) -> Result<(), GoDaddyError> {
        if !validate::validate_device_id(device_id) {
            return Err(GoDaddyError::InvalidParameters {
                body: format!(
                    "invalid device_id '{}' (charset [a-zA-Z0-9:_-], len 1..=128, no '.' allowed)",
                    device_id
                ),
            });
        }
        Ok(())
    }

    /// Register or update an AAAA record for a device.
    pub async fn register(
        &self,
        device_id: &str,
        ipv6_addr: Ipv6Addr,
        ttl: u32,
    ) -> Result<(), GoDaddyError> {
        self.check_device_id(device_id)?;
        debug!("AAAA register: device={}, ipv6={}, ttl={}", device_id, ipv6_addr, ttl);
        let records = vec![Record {
            data: ipv6_addr.to_string(),
            ttl,
        }];

        self.client
            .put_records(self.domain, "AAAA", device_id, &records)
            .await
    }

    /// Query AAAA records for a device.
    pub async fn query(&self, device_id: &str) -> Result<Vec<Ipv6Addr>, GoDaddyError> {
        self.check_device_id(device_id)?;
        debug!("AAAA query: device={}", device_id);
        let records = self
            .client
            .get_records(self.domain, "AAAA", device_id)
            .await?;

        records
            .iter()
            .map(|r| {
                r.data
                    .parse::<Ipv6Addr>()
                    .map_err(|e| GoDaddyError::InvalidParameters {
                        body: format!("Failed to parse IPv6 address '{}': {}", r.data, e),
                    })
            })
            .collect()
    }

    /// Get the first IPv6 address from the AAAA records.
    pub async fn get_ipv6(&self, device_id: &str) -> Result<Ipv6Addr, GoDaddyError> {
        let addrs = self.query(device_id).await?;
        addrs.first().copied().ok_or_else(|| GoDaddyError::NotFound {
            name: device_id.to_string(),
            record_type: "AAAA".to_string(),
        })
    }

    /// Delete AAAA records for a device.
    pub async fn remove(&self, device_id: &str) -> Result<(), GoDaddyError> {
        self.check_device_id(device_id)?;
        self.client
            .delete_record(self.domain, "AAAA", device_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_roundtrip() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(addr.to_string(), "2001:db8::1");
    }

    #[test]
    fn test_ipv6_global_unicast() {
        let addr: Ipv6Addr = "2001:db8:85a3::8a2e:370:7334".parse().unwrap();
        assert!(addr.octets()[0] == 0x20 && addr.octets()[1] == 0x01);
    }
}
