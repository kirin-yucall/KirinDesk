use crate::provider::{Provider, ProviderError, Record, RecordData, RecordType};
use crate::validate;
use std::net::Ipv4Addr;
use tracing::debug;

/// Manage A (IPv4 address) records.
///
/// M9-DNS000：多服务商化——只依赖 `&dyn Provider`，不感知厂商差异。
pub struct AManager<'a> {
    provider: &'a dyn Provider,
    domain: &'a str,
}

impl<'a> AManager<'a> {
    pub fn new(provider: &'a dyn Provider, domain: &'a str) -> Self {
        Self { provider, domain }
    }

    /// S-14b / F-18: device_id 统一校验（拒绝 '.' 子域注入等非法字符）。
    fn check_device_id(&self, device_id: &str) -> Result<(), ProviderError> {
        if !validate::validate_device_id(device_id) {
            return Err(ProviderError::InvalidParameter {
                detail: format!(
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
    ) -> Result<(), ProviderError> {
        self.check_device_id(device_id)?;
        debug!(
            "A register: device={}, ipv4={}, ttl={}",
            device_id, ipv4_addr, ttl
        );
        let rec = Record {
            name: device_id.to_string(),
            rtype: RecordType::A,
            ttl,
            data: RecordData::Plain(ipv4_addr.to_string()),
        };
        self.provider.upsert_record(self.domain, &rec).await
    }

    /// Query A records for a device.
    pub async fn query(&self, device_id: &str) -> Result<Vec<Ipv4Addr>, ProviderError> {
        self.check_device_id(device_id)?;
        debug!("A query: device={}", device_id);
        let records = self
            .provider
            .query_records(self.domain, Some(device_id), Some(RecordType::A))
            .await?;

        records
            .iter()
            .map(|r| match &r.data {
                RecordData::Plain(data) => data.parse::<Ipv4Addr>().map_err(|e| {
                    ProviderError::InvalidParameter {
                        detail: format!("Failed to parse IPv4 address '{}': {}", data, e),
                    }
                }),
                other => Err(ProviderError::InvalidParameter {
                    detail: format!(
                        "Failed to parse IPv4 address '{}': unexpected data shape",
                        other.to_display_string()
                    ),
                }),
            })
            .collect()
    }

    /// Get the first IPv4 address from the A records.
    pub async fn get_ipv4(&self, device_id: &str) -> Result<Ipv4Addr, ProviderError> {
        let addrs = self.query(device_id).await?;
        addrs
            .first()
            .copied()
            .ok_or_else(|| ProviderError::NotFound {
                what: format!("A {}.{}", device_id, self.domain),
            })
    }

    /// Delete A records for a device.
    pub async fn remove(&self, device_id: &str) -> Result<(), ProviderError> {
        self.check_device_id(device_id)?;
        self.provider
            .delete_record(self.domain, device_id, RecordType::A)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::mock::MockProvider;

    // ---- MockProvider 往返（M9-DNS000 抽象层语义） ----

    #[tokio::test]
    async fn test_a_roundtrip() {
        let provider = MockProvider::new("mock");
        let mgr = AManager::new(&provider, "example.com");

        let ip: Ipv4Addr = "203.0.113.7".parse().unwrap();
        mgr.register("my-pc", ip, 600).await.unwrap();

        assert_eq!(mgr.query("my-pc").await.unwrap(), vec![ip]);
        assert_eq!(mgr.get_ipv4("my-pc").await.unwrap(), ip);

        mgr.remove("my-pc").await.unwrap();
        assert!(
            provider
                .records_of("example.com", RecordType::A, "my-pc")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_a_parses_invalid_data_as_error() {
        let provider = MockProvider::new("mock");
        provider.seed_record(
            "example.com",
            Record {
                name: "bad-device".to_string(),
                rtype: RecordType::A,
                ttl: 600,
                data: RecordData::Plain("not-an-ip".to_string()),
            },
        );
        let mgr = AManager::new(&provider, "example.com");

        let err = mgr.query("bad-device").await.unwrap_err();
        assert!(matches!(err, ProviderError::InvalidParameter { .. }));
    }

    #[tokio::test]
    async fn test_get_ipv4_not_found() {
        let provider = MockProvider::new("mock");
        let mgr = AManager::new(&provider, "example.com");
        let err = mgr.get_ipv4("ghost").await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
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
