use crate::provider::{Provider, ProviderError, Record, RecordData, RecordType};
use crate::validate;
use std::net::Ipv6Addr;
use tracing::debug;

/// Manage AAAA (IPv6 address) records.
///
/// M9-DNS000：多服务商化——只依赖 `&dyn Provider`，不感知厂商差异。
pub struct AaaaManager<'a> {
    provider: &'a dyn Provider,
    domain: &'a str,
}

impl<'a> AaaaManager<'a> {
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

    /// Register or update an AAAA record for a device.
    pub async fn register(
        &self,
        device_id: &str,
        ipv6_addr: Ipv6Addr,
        ttl: u32,
    ) -> Result<(), ProviderError> {
        self.check_device_id(device_id)?;
        debug!(
            "AAAA register: device={}, ipv6={}, ttl={}",
            device_id, ipv6_addr, ttl
        );
        let rec = Record {
            name: device_id.to_string(),
            rtype: RecordType::AAAA,
            ttl,
            data: RecordData::Plain(ipv6_addr.to_string()),
        };
        self.provider.upsert_record(self.domain, &rec).await
    }

    /// Query AAAA records for a device.
    pub async fn query(&self, device_id: &str) -> Result<Vec<Ipv6Addr>, ProviderError> {
        self.check_device_id(device_id)?;
        debug!("AAAA query: device={}", device_id);
        let records = self
            .provider
            .query_records(self.domain, Some(device_id), Some(RecordType::AAAA))
            .await?;

        records
            .iter()
            .map(|r| match &r.data {
                RecordData::Plain(data) => data.parse::<Ipv6Addr>().map_err(|e| {
                    ProviderError::InvalidParameter {
                        detail: format!("Failed to parse IPv6 address '{}': {}", data, e),
                    }
                }),
                other => Err(ProviderError::InvalidParameter {
                    detail: format!(
                        "Failed to parse IPv6 address '{}': unexpected data shape",
                        other.to_display_string()
                    ),
                }),
            })
            .collect()
    }

    /// Get the first IPv6 address from the AAAA records.
    pub async fn get_ipv6(&self, device_id: &str) -> Result<Ipv6Addr, ProviderError> {
        let addrs = self.query(device_id).await?;
        addrs.first().copied().ok_or_else(|| ProviderError::NotFound {
            what: format!("AAAA {}.{}", device_id, self.domain),
        })
    }

    /// Delete AAAA records for a device.
    pub async fn remove(&self, device_id: &str) -> Result<(), ProviderError> {
        self.check_device_id(device_id)?;
        self.provider
            .delete_record(self.domain, device_id, RecordType::AAAA)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::mock::MockProvider;

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

    // ---- MockProvider 往返（M9-DNS000 抽象层语义） ----

    #[tokio::test]
    async fn test_register_and_query_roundtrip() {
        let provider = MockProvider::new("mock");
        let mgr = AaaaManager::new(&provider, "example.com");

        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        mgr.register("my-pc", ip, 600).await.unwrap();

        assert_eq!(mgr.query("my-pc").await.unwrap(), vec![ip]);
        assert_eq!(mgr.get_ipv6("my-pc").await.unwrap(), ip);

        mgr.remove("my-pc").await.unwrap();
        assert!(
            provider
                .records_of("example.com", RecordType::AAAA, "my-pc")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_query_parses_invalid_data_as_error() {
        let provider = MockProvider::new("mock");
        provider.seed_record(
            "example.com",
            Record {
                name: "bad-device".to_string(),
                rtype: RecordType::AAAA,
                ttl: 600,
                data: RecordData::Plain("not-an-ip".to_string()),
            },
        );
        let mgr = AaaaManager::new(&provider, "example.com");

        let err = mgr.query("bad-device").await.unwrap_err();
        assert!(matches!(err, ProviderError::InvalidParameter { .. }));
    }

    #[tokio::test]
    async fn test_get_ipv6_not_found() {
        let provider = MockProvider::new("mock");
        let mgr = AaaaManager::new(&provider, "example.com");
        let err = mgr.get_ipv6("ghost").await.unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    #[tokio::test]
    async fn test_query_rejects_invalid_device_id() {
        let provider = MockProvider::new("mock");
        let mgr = AaaaManager::new(&provider, "example.com");
        // '.' 是 F-18 子域注入点，必须在任何 API 调用前拒绝。
        let err = mgr.query("a.b.c").await.unwrap_err();
        assert!(matches!(err, ProviderError::InvalidParameter { .. }));
    }
}
