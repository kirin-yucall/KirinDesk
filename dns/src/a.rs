use crate::godaddy::{GoDaddyClient, GoDaddyError, Record};
use crate::validate;
use std::net::Ipv4Addr;
use tracing::debug;

/// Manage A (IPv4 address) records.
pub struct AManager<'a> {
    client: &'a GoDaddyClient,
    domain: &'a str,
}

impl<'a> AManager<'a> {
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

    /// Register or update an A record for a device.
    pub async fn register(
        &self,
        device_id: &str,
        ipv4_addr: Ipv4Addr,
        ttl: u32,
    ) -> Result<(), GoDaddyError> {
        self.check_device_id(device_id)?;
        debug!(
            "A register: device={}, ipv4={}, ttl={}",
            device_id, ipv4_addr, ttl
        );
        let records = vec![Record {
            data: ipv4_addr.to_string(),
            ttl,
        }];

        self.client
            .put_records(self.domain, "A", device_id, &records)
            .await
    }

    /// Query A records for a device.
    pub async fn query(&self, device_id: &str) -> Result<Vec<Ipv4Addr>, GoDaddyError> {
        self.check_device_id(device_id)?;
        debug!("A query: device={}", device_id);
        let records = self.client.get_records(self.domain, "A", device_id).await?;

        records
            .iter()
            .map(|r| {
                r.data
                    .parse::<Ipv4Addr>()
                    .map_err(|e| GoDaddyError::InvalidParameters {
                        body: format!("Failed to parse IPv4 address '{}': {}", r.data, e),
                    })
            })
            .collect()
    }

    /// Get the first IPv4 address from the A records.
    pub async fn get_ipv4(&self, device_id: &str) -> Result<Ipv4Addr, GoDaddyError> {
        let addrs = self.query(device_id).await?;
        addrs
            .first()
            .copied()
            .ok_or_else(|| GoDaddyError::NotFound {
                name: device_id.to_string(),
                record_type: "A".to_string(),
            })
    }

    /// Delete A records for a device.
    pub async fn remove(&self, device_id: &str) -> Result<(), GoDaddyError> {
        self.check_device_id(device_id)?;
        self.client.delete_record(self.domain, "A", device_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::MockDns;

    #[tokio::test]
    async fn test_a_roundtrip() {
        let mock = MockDns::start().await;
        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let mgr = AManager::new(&client, "example.com");

        let ip: Ipv4Addr = "203.0.113.7".parse().unwrap();
        mgr.register("my-pc", ip, 600).await.unwrap();

        assert_eq!(mgr.query("my-pc").await.unwrap(), vec![ip]);
        assert_eq!(mgr.get_ipv4("my-pc").await.unwrap(), ip);
    }

    #[tokio::test]
    async fn test_a_parses_invalid_data_as_error() {
        let mock = MockDns::start().await;
        mock.set_records("A", "bad-device", &["not-an-ip"], 600);

        let client = GoDaddyClient::new("k", "s", mock.base_url());
        let mgr = AManager::new(&client, "example.com");

        let err = mgr.query("bad-device").await.unwrap_err();
        assert!(matches!(err, GoDaddyError::InvalidParameters { .. }));
    }

    #[test]
    fn test_ipv4_roundtrip() {
        let addr: Ipv4Addr = "203.0.113.9".parse().unwrap();
        assert_eq!(addr.to_string(), "203.0.113.9");
    }

    #[test]
    fn test_ipv4_global_unicast() {
        // 203.0.113.x (TEST-NET-3) — global unicast range, none of the filtered classes
        let addr: Ipv4Addr = "203.0.113.10".parse().unwrap();
        assert!(
            !addr.is_loopback()
                && !addr.is_link_local()
                && !addr.is_multicast()
                && !addr.is_unspecified()
        );
    }
}
