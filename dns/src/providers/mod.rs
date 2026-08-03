//! M9-DNS000: 各服务商 Provider 实现（M9-DNS001~020）
//!
//! 每服务商一个自包含子目录（HTTP 客户端 + 认证/签名 + 序列化 + 错误映射 +
//! `impl Provider`），模块内自带 `#[cfg(test)]` mock HTTP 契约测试。
//! 上层（discovery/heartbeat/srv/aaaa/txt/UI/CLI）只依赖 `provider` 抽象层，
//! 禁止直接引用具体服务商类型（架构红线，总体需求 §七.1）。
//!
//! 注册：`register_all()` 由集成者（Stage 3）填充各 `register` 调用——
//! 各模块自行暴露 `pub fn register(registry: &mut ProviderRegistry)`。

pub mod aliyun;
pub mod azure;
pub mod baidu;
pub mod cloudflare;
pub mod digitalocean;
pub mod dnspod;
pub mod godaddy;
pub mod google;
pub mod hetzner;
pub mod huawei;
pub mod jdcloud;
pub mod linode;
pub mod namecheap;
pub mod ovh;
pub mod porkbun;
pub mod route53;
pub mod volcengine;
pub mod vultr;
pub mod westcn;
pub mod xinnet;

use crate::provider::ProviderRegistry;

/// 注册全部已实现服务商（`crate::provider_registry()` 初始化时调用）。
///
/// 20 家全量注册（M9-DNS001~020 分批开发完成）；新增服务商 = 新目录 +
/// 这里加一行，上层零改动。
pub fn register_all(registry: &mut ProviderRegistry) {
    // ── P0（M9-DNS001~005）──
    godaddy::register(registry);
    cloudflare::register(registry);
    aliyun::register(registry);
    dnspod::register(registry);
    route53::register(registry);
    // ── P1（M9-DNS006~011）──
    azure::register(registry);
    google::register(registry);
    huawei::register(registry);
    namecheap::register(registry);
    digitalocean::register(registry);
    vultr::register(registry);
    // ── P2（M9-DNS012~020）──
    linode::register(registry);
    hetzner::register(registry);
    ovh::register(registry);
    porkbun::register(registry);
    baidu::register(registry);
    volcengine::register(registry);
    jdcloud::register(registry);
    westcn::register(registry);
    xinnet::register(registry);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_all_registers_20_providers() {
        let mut r = ProviderRegistry::new();
        register_all(&mut r);
        let names = r.names();
        assert_eq!(names.len(), 20, "M9-DNS001~020 全部注册");
        for expected in [
            "aliyun", "azure", "baidu", "cloudflare", "digitalocean", "dnspod", "godaddy",
            "google", "hetzner", "huawei", "jdcloud", "linode", "namecheap", "ovh", "porkbun",
            "route53", "volcengine", "vultr", "westcn", "xinnet",
        ] {
            assert!(r.has(expected), "{expected} 未注册");
        }
    }
}
