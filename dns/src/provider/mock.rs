//! M9-DNS000: 契约测试 mock（`M9-DNS000_Provider抽象接口规范.md` §七）
//!
//! `MockProvider` 为内存实现，行为对齐统一语义（upsert 幂等 / delete /
//! 过滤 / SRV 结构化 / Unsupported 能力降级），供全部上层单测
//! （srv/aaaa/txt/discovery/heartbeat）与各服务商契约测试模板复用。

use super::record::{Record, RecordData, RecordType};
use super::{Provider, ProviderCapabilities, ProviderError};
use std::collections::HashMap;
use std::sync::Mutex;

/// 内存存储状态。
#[derive(Default)]
struct MockState {
    domains: Vec<String>,
    /// (domain, rtype, name) → 记录列表（同 name+rtype 可多条）。
    records: HashMap<(String, RecordType, String), Vec<Record>>,
    /// 统计（契约断言用）。
    upserts: usize,
    deletes: usize,
}

/// 内存 DNS 实现（契约测试 + 上层单测用）。
///
/// `capabilities` 可配置（`srv(false)` 模拟西部数码/新网类能力缺失）。
pub struct MockProvider {
    name: &'static str,
    state: Mutex<MockState>,
    caps: ProviderCapabilities,
}

impl MockProvider {
    /// 全能力 mock（`ProviderCapabilities::all`）。
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            state: Mutex::new(MockState::default()),
            caps: ProviderCapabilities::all(),
        }
    }

    /// 指定能力（关闭 SRV 等，测降级路径）。
    pub fn with_capabilities(name: &'static str, caps: ProviderCapabilities) -> Self {
        Self {
            name,
            state: Mutex::new(MockState::default()),
            caps,
        }
    }

    /// 预设域名列表。
    pub fn set_domains(&self, domains: &[&str]) {
        self.state
            .lock()
            .unwrap()
            .domains
            .extend(domains.iter().map(|d| d.to_string()));
    }

    /// 预设一条记录（name 为相对名；"" = 根）。
    pub fn seed_record(&self, domain: &str, rec: Record) {
        let mut state = self.state.lock().unwrap();
        let key = (domain.to_string(), rec.rtype, rec.name.clone());
        let list = state.records.entry(key).or_default();
        if !list.iter().any(|r| r.data == rec.data) {
            list.push(rec);
        }
    }

    /// 查询指定 (rtype, name) 的原始记录（测试断言用）。
    pub fn records_of(&self, domain: &str, rtype: RecordType, name: &str) -> Vec<Record> {
        let state = self.state.lock().unwrap();
        state
            .records
            .get(&(domain.to_string(), rtype, name.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// 写入次数统计。
    pub fn upsert_count(&self) -> usize {
        self.state.lock().unwrap().upserts
    }

    /// 删除次数统计。
    pub fn delete_count(&self) -> usize {
        self.state.lock().unwrap().deletes
    }
}

#[async_trait::async_trait]
impl Provider for MockProvider {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn test_connection(&self) -> Result<(), ProviderError> {
        Ok(())
    }

    async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        Ok(self.state.lock().unwrap().domains.clone())
    }

    async fn query_records(
        &self,
        domain: &str,
        name: Option<&str>,
        rtype: Option<RecordType>,
    ) -> Result<Vec<Record>, ProviderError> {
        let state = self.state.lock().unwrap();
        let mut out: Vec<Record> = state
            .records
            .iter()
            .filter(|((d, r, n), _)| {
                d == domain
                    && rtype.map(|t| t == *r).unwrap_or(true)
                    && name.map(|n2| n.as_str() == n2).unwrap_or(true)
            })
            .flat_map(|(_, recs)| recs.clone())
            .collect();
        out.sort_by(|a, b| {
            (&a.rtype, &a.name, a.data.to_display_string()).cmp(&(&b.rtype, &b.name, b.data.to_display_string()))
        });
        Ok(out)
    }

    async fn upsert_record(&self, domain: &str, rec: &Record) -> Result<(), ProviderError> {
        if !self.caps.srv && rec.rtype == RecordType::SRV {
            return Err(ProviderError::Unsupported("SRV"));
        }
        let mut state = self.state.lock().unwrap();
        state.upserts += 1;
        let key = (domain.to_string(), rec.rtype, rec.name.clone());
        let list = state.records.entry(key).or_default();
        match &rec.data {
            // 同 name+rtype 同 data → 更新 TTL/数据（幂等，不产生重复）。
            RecordData::Plain(data) => {
                if let Some(existing) = list
                    .iter_mut()
                    .find(|r| matches!(&r.data, RecordData::Plain(d) if d == data))
                {
                    existing.ttl = rec.ttl;
                    existing.data = rec.data.clone();
                } else {
                    list.push(rec.clone());
                }
            }
            RecordData::Mx { priority, exchange } => {
                if let Some(existing) = list.iter_mut().find(|r| {
                    matches!(&r.data, RecordData::Mx { priority: p, exchange: e } if p == priority && e == exchange)
                }) {
                    existing.ttl = rec.ttl;
                    existing.data = rec.data.clone();
                } else {
                    list.push(rec.clone());
                }
            }
            RecordData::Srv { priority, weight, port, target } => {
                if let Some(existing) = list.iter_mut().find(|r| {
                    matches!(&r.data, RecordData::Srv { priority: p, weight: w, port: pt, target: t }
                        if p == priority && w == weight && pt == port && t == target)
                }) {
                    existing.ttl = rec.ttl;
                    existing.data = rec.data.clone();
                } else {
                    list.push(rec.clone());
                }
            }
        }
        Ok(())
    }

    async fn delete_record(
        &self,
        domain: &str,
        name: &str,
        rtype: RecordType,
    ) -> Result<(), ProviderError> {
        let mut state = self.state.lock().unwrap();
        state.deletes += 1;
        let key = (domain.to_string(), rtype, name.to_string());
        match state.records.remove(&key) {
            Some(_) => Ok(()),
            None => Err(ProviderError::NotFound {
                what: format!("{rtype} {name}.{domain}"),
            }),
        }
    }

    fn capabilities(&self) -> ProviderCapabilities {
        self.caps.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, rtype: RecordType, data: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype,
            ttl,
            data: RecordData::Plain(data.to_string()),
        }
    }

    fn srv(name: &str, target: &str, port: u16, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: RecordType::SRV,
            ttl,
            data: RecordData::Srv {
                priority: 0,
                weight: 1,
                port,
                target: target.to_string(),
            },
        }
    }

    #[tokio::test]
    async fn upsert_new_record_is_visible() {
        let p = MockProvider::new("mock");
        p.upsert_record("example.com", &rec("my-pc", RecordType::A, "203.0.113.7", 600))
            .await
            .unwrap();
        let found = p
            .query_records("example.com", Some("my-pc"), Some(RecordType::A))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data, RecordData::Plain("203.0.113.7".into()));
        assert_eq!(found[0].ttl, 600);
    }

    #[tokio::test]
    async fn upsert_existing_updates_without_duplicate() {
        let p = MockProvider::new("mock");
        p.upsert_record("example.com", &rec("my-pc", RecordType::A, "203.0.113.7", 600))
            .await
            .unwrap();
        p.upsert_record("example.com", &rec("my-pc", RecordType::A, "203.0.113.7", 1200))
            .await
            .unwrap();
        p.upsert_record("example.com", &rec("my-pc", RecordType::A, "198.51.100.9", 600))
            .await
            .unwrap();
        let found = p
            .query_records("example.com", Some("my-pc"), Some(RecordType::A))
            .await
            .unwrap();
        assert_eq!(found.len(), 2, "同 data 不重复，不同 data 并存");
        let ip7 = found.iter().find(|r| r.data.to_display_string() == "203.0.113.7").unwrap();
        assert_eq!(ip7.ttl, 1200, "已存在同 data → 更新 TTL");
        // 幂等：重复 upsert 不新增记录。
        p.upsert_record("example.com", &rec("my-pc", RecordType::A, "203.0.113.7", 1200))
            .await
            .unwrap();
        assert_eq!(
            p.query_records("example.com", Some("my-pc"), Some(RecordType::A))
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn delete_removes_and_not_found_errors() {
        let p = MockProvider::new("mock");
        p.upsert_record("example.com", &rec("my-pc", RecordType::A, "203.0.113.7", 600))
            .await
            .unwrap();
        p.delete_record("example.com", "my-pc", RecordType::A)
            .await
            .unwrap();
        assert!(
            p.query_records("example.com", Some("my-pc"), Some(RecordType::A))
                .await
                .unwrap()
                .is_empty()
        );
        // 删不存在的 → NotFound。
        let err = p
            .delete_record("example.com", "my-pc", RecordType::A)
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::NotFound { .. }));
    }

    #[tokio::test]
    async fn query_filters_by_name_and_type() {
        let p = MockProvider::new("mock");
        p.upsert_record("example.com", &rec("my-pc", RecordType::A, "203.0.113.7", 600))
            .await
            .unwrap();
        p.upsert_record("example.com", &rec("my-pc", RecordType::AAAA, "2001:db8::1", 600))
            .await
            .unwrap();
        p.upsert_record("example.com", &rec("other", RecordType::A, "198.51.100.9", 600))
            .await
            .unwrap();
        // 全表（无过滤）。
        let all = p.query_records("example.com", None, None).await.unwrap();
        assert_eq!(all.len(), 3);
        // 按 name。
        let by_name = p
            .query_records("example.com", Some("my-pc"), None)
            .await
            .unwrap();
        assert_eq!(by_name.len(), 2);
        // 按 type。
        let by_type = p
            .query_records("example.com", None, Some(RecordType::A))
            .await
            .unwrap();
        assert_eq!(by_type.len(), 2);
        // 两者组合。
        let both = p
            .query_records("example.com", Some("my-pc"), Some(RecordType::AAAA))
            .await
            .unwrap();
        assert_eq!(both.len(), 1);
        assert!(matches!(both[0].data, RecordData::Plain(ref d) if d == "2001:db8::1"));
    }

    #[tokio::test]
    async fn srv_structured_roundtrip() {
        let p = MockProvider::new("mock");
        let rec = srv("_remote._tcp.my-pc", "my-pc.example.com.", 3389, 600);
        p.upsert_record("example.com", &rec).await.unwrap();
        let found = p
            .query_records("example.com", Some("_remote._tcp.my-pc"), Some(RecordType::SRV))
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        match &found[0].data {
            RecordData::Srv { priority, weight, port, target } => {
                assert_eq!((*priority, *weight, *port), (0, 1, 3389));
                assert_eq!(target, "my-pc.example.com.");
            }
            other => panic!("expected Srv data, got {other:?}"),
        }
        // 往返一致：upsert 同值 → 更新而非新增。
        p.upsert_record("example.com", &rec).await.unwrap();
        assert_eq!(
            p.query_records("example.com", Some("_remote._tcp.my-pc"), Some(RecordType::SRV))
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn unsupported_capability_returns_unsupported() {
        let p = MockProvider::with_capabilities(
            "westcn-like",
            ProviderCapabilities {
                srv: false,
                ..ProviderCapabilities::all()
            },
        );
        // SRV 写入 → Unsupported（DNS-MNT-013 降级路径）。
        let err = p
            .upsert_record("example.com", &srv("_remote._tcp.my-pc", "tgt.", 3389, 600))
            .await
            .unwrap_err();
        assert!(matches!(err, ProviderError::Unsupported(_)));
        // 非 SRV 不受影响。
        p.upsert_record("example.com", &rec("my-pc", RecordType::A, "203.0.113.7", 600))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_domains_and_stats() {
        let p = MockProvider::new("mock");
        p.set_domains(&["example.com", "kirin.dev"]);
        assert_eq!(p.list_domains().await.unwrap(), vec!["example.com", "kirin.dev"]);
        p.upsert_record("example.com", &rec("x", RecordType::A, "1.2.3.4", 600))
            .await
            .unwrap();
        p.delete_record("example.com", "x", RecordType::A).await.unwrap();
        assert_eq!(p.upsert_count(), 1);
        assert_eq!(p.delete_count(), 1);
    }
}
