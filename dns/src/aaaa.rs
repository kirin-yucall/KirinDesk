use crate::godaddy::{GoDaddyClient, GoDaddyError, Record};
use std::net::Ipv6Addr;

/// Manage AAAA (IPv6 address) records.
pub struct AaaaManager<'a> {
    client: &'a GoDaddyClient,
    domain: &'a str,
}

impl<'a> AaaaManager<'a> {
    pub fn new(client: &'a GoDaddyClient, domain: &'a str) -> Self {
        Self { client, domain }
    }

    /// Register or update an AAAA record for a device.
    pub async fn register(
        &self,
        device_id: &str,
        ipv6_addr: Ipv6Addr,
        ttl: u32,
    ) -> Result<(), GoDaddyError> {
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
