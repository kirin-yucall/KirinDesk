//! M8-T035: DNS 域名维护服务商注册表（需求 10-12）
//!
//! 「已实现的 DNS 域名维护客户端列表」的唯一事实源——UI（Settings → DNS 组）
//! 只从这里渲染服务商列表与动态字段表单；新增服务商 = 在 `dns_provider_defs()`
//! 注册条目 + 实现客户端 + 字段映射，UI 自动适配（无需改 UI 代码）。
//!
//! 注意：本注册表**不**改变 `[godaddy]` 配置段结构——CLI（setup/register/
//! discover/heartbeat）与 dns crate 全部直接读写 `cfg.godaddy.*`，行为零变化。

/// 动态表单的一个字段定义（label 上置输入框；`secret` 密文 + 👁；`mono` 等宽）。
pub struct DnsFieldDef {
    /// 字段 key（provider 内部映射到配置/App 字段，如 "domain" / "api_key"）。
    pub key: &'static str,
    /// UI 展示标签（含冒号）。
    pub label: &'static str,
    /// 是否密文输入（圆点遮蔽 + 👁 切换）。
    pub secret: bool,
    /// 是否等宽字体（Domain/IP 等）。
    pub mono: bool,
}

/// 一个已实现的 DNS 域名维护服务商。
pub struct DnsProviderDef {
    /// 配置 `[dns] provider` 存的值（如 "godaddy"）。
    pub id: &'static str,
    /// UI 展示名称（ComboBox 项文本）。
    pub name: &'static str,
    /// 该服务商所需的字段（UI 按此动态渲染表单）。
    pub fields: &'static [DnsFieldDef],
}

/// GoDaddy：Domain / API Key / API Secret（对称旧 Settings「GoDaddy API」组；
/// API Key 明文、API Secret 密文，行为与迁移前一致）。
const GODADDY: DnsProviderDef = DnsProviderDef {
    id: "godaddy",
    name: "GoDaddy",
    fields: &[
        DnsFieldDef {
            key: "domain",
            label: "Domain:",
            secret: false,
            mono: true,
        },
        DnsFieldDef {
            key: "api_key",
            label: "API Key:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "api_secret",
            label: "API Secret:",
            secret: true,
            mono: false,
        },
    ],
};

/// 已实现的 DNS 域名维护服务商列表（当前仅 GoDaddy）。
static DNS_PROVIDERS: &[DnsProviderDef] = &[GODADDY];

/// 已实现的 DNS 域名维护服务商列表（当前仅 GoDaddy）。
pub fn dns_provider_defs() -> &'static [DnsProviderDef] {
    DNS_PROVIDERS
}

/// 按 id 查服务商定义（未知 id → `None`，调用方回退 "godaddy"）。
pub fn dns_provider_def(id: &str) -> Option<&'static DnsProviderDef> {
    dns_provider_defs().iter().find(|p| p.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_godaddy_with_expected_fields() {
        let defs = dns_provider_defs();
        assert!(!defs.is_empty(), "至少一个已实现服务商");
        let godaddy = dns_provider_def("godaddy").expect("godaddy 必须已注册");
        assert_eq!(godaddy.name, "GoDaddy");
        let keys: Vec<&str> = godaddy.fields.iter().map(|f| f.key).collect();
        assert_eq!(keys, vec!["domain", "api_key", "api_secret"]);
        let secret = godaddy.fields.iter().find(|f| f.key == "api_secret").unwrap();
        assert!(secret.secret, "API Secret 必须密文输入");
    }

    #[test]
    fn unknown_provider_returns_none() {
        assert!(dns_provider_def("cloudflare").is_none());
        assert!(dns_provider_def("").is_none());
    }

    #[test]
    fn provider_ids_unique() {
        let defs = dns_provider_defs();
        let mut ids: Vec<&str> = defs.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), defs.len(), "服务商 id 必须唯一");
    }
}
