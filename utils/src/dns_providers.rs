//! M8-T035 + M9-DNS000: DNS 域名维护服务商注册表（需求 10-12 / UI-DNS-001）
//!
//! 「已实现的 DNS 域名维护客户端列表」的唯一事实源——UI（Domain 页「服务商」
//! 卡下拉框）只从这里渲染服务商列表与动态字段表单；新增服务商 = 在
//! `dns_provider_defs()` 注册条目 + 实现客户端 + 字段映射，UI 自动适配
//! （无需改 UI 代码）。
//!
//! 服务商 id 与 `dns` crate 的 `Credential` 枚举变体 / `[dns.providers.*]`
//! 配置段键一致（kebab-case）。字段 key 与 `Credential` 变体字段一致。

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

// ────────────────────────────────────────────────────────────────
// 20 家服务商定义（M9-DNS001~020；字段按各适配文档 §凭据）
// ────────────────────────────────────────────────────────────────

/// GoDaddy（M9-DNS001）：Domain（设备域，兼容旧 `[godaddy]`）+ API Key/Secret。
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

/// Cloudflare（M9-DNS002）。
const CLOUDFLARE: DnsProviderDef = DnsProviderDef {
    id: "cloudflare",
    name: "Cloudflare",
    fields: &[DnsFieldDef {
        key: "api_token",
        label: "API Token:",
        secret: true,
        mono: false,
    }],
};

/// 阿里云云解析（M9-DNS003）。
const ALIYUN: DnsProviderDef = DnsProviderDef {
    id: "aliyun",
    name: "阿里云云解析",
    fields: &[
        DnsFieldDef {
            key: "access_key_id",
            label: "AccessKey ID:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "access_key_secret",
            label: "AccessKey Secret:",
            secret: true,
            mono: false,
        },
    ],
};

/// 腾讯云 DNSPod（M9-DNS004）。
const DNSPOD: DnsProviderDef = DnsProviderDef {
    id: "dnspod",
    name: "腾讯云 DNSPod",
    fields: &[
        DnsFieldDef {
            key: "secret_id",
            label: "SecretId:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "secret_key",
            label: "SecretKey:",
            secret: true,
            mono: false,
        },
    ],
};

/// AWS Route 53（M9-DNS005）。
const ROUTE53: DnsProviderDef = DnsProviderDef {
    id: "route53",
    name: "AWS Route 53",
    fields: &[
        DnsFieldDef {
            key: "access_key_id",
            label: "Access Key ID:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "secret_access_key",
            label: "Secret Access Key:",
            secret: true,
            mono: false,
        },
        DnsFieldDef {
            key: "region",
            label: "Region:",
            secret: false,
            mono: true,
        },
    ],
};

/// Azure DNS（M9-DNS006）。
const AZURE: DnsProviderDef = DnsProviderDef {
    id: "azure",
    name: "Azure DNS",
    fields: &[
        DnsFieldDef {
            key: "tenant_id",
            label: "Tenant ID:",
            secret: false,
            mono: true,
        },
        DnsFieldDef {
            key: "client_id",
            label: "Client ID:",
            secret: false,
            mono: true,
        },
        DnsFieldDef {
            key: "client_secret",
            label: "Client Secret:",
            secret: true,
            mono: false,
        },
        DnsFieldDef {
            key: "subscription_id",
            label: "Subscription ID:",
            secret: false,
            mono: true,
        },
        DnsFieldDef {
            key: "resource_group",
            label: "Resource Group:",
            secret: false,
            mono: false,
        },
    ],
};

/// Google Cloud DNS（M9-DNS007）。
const GOOGLE: DnsProviderDef = DnsProviderDef {
    id: "google",
    name: "Google Cloud DNS",
    fields: &[
        DnsFieldDef {
            key: "project",
            label: "Project:",
            secret: false,
            mono: true,
        },
        DnsFieldDef {
            key: "service_account_json",
            label: "Service Account JSON:",
            secret: true,
            mono: false,
        },
    ],
};

/// 华为云 DNS（M9-DNS008）。
const HUAWEI: DnsProviderDef = DnsProviderDef {
    id: "huawei",
    name: "华为云 DNS",
    fields: &[
        DnsFieldDef {
            key: "access_key",
            label: "Access Key:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "secret_key",
            label: "Secret Key:",
            secret: true,
            mono: false,
        },
        DnsFieldDef {
            key: "region",
            label: "Region:",
            secret: false,
            mono: true,
        },
    ],
};

/// Namecheap（M9-DNS009）。
const NAMECHEAP: DnsProviderDef = DnsProviderDef {
    id: "namecheap",
    name: "Namecheap",
    fields: &[
        DnsFieldDef {
            key: "api_user",
            label: "API User:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "api_key",
            label: "API Key:",
            secret: true,
            mono: false,
        },
        DnsFieldDef {
            key: "user_name",
            label: "Username:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "client_ip",
            label: "Client IP:",
            secret: false,
            mono: true,
        },
    ],
};

/// DigitalOcean（M9-DNS010）。
const DIGITALOCEAN: DnsProviderDef = DnsProviderDef {
    id: "digitalocean",
    name: "DigitalOcean",
    fields: &[DnsFieldDef {
        key: "token",
        label: "API Token:",
        secret: true,
        mono: false,
    }],
};

/// Vultr（M9-DNS011）。
const VULTR: DnsProviderDef = DnsProviderDef {
    id: "vultr",
    name: "Vultr",
    fields: &[DnsFieldDef {
        key: "token",
        label: "API Token:",
        secret: true,
        mono: false,
    }],
};

/// Linode（Akamai）（M9-DNS012）。
const LINODE: DnsProviderDef = DnsProviderDef {
    id: "linode",
    name: "Linode (Akamai)",
    fields: &[DnsFieldDef {
        key: "token",
        label: "API Token:",
        secret: true,
        mono: false,
    }],
};

/// Hetzner DNS（M9-DNS013）。
const HETZNER: DnsProviderDef = DnsProviderDef {
    id: "hetzner",
    name: "Hetzner DNS",
    fields: &[DnsFieldDef {
        key: "token",
        label: "API Token:",
        secret: true,
        mono: false,
    }],
};

/// OVH（M9-DNS014）。
const OVH: DnsProviderDef = DnsProviderDef {
    id: "ovh",
    name: "OVH",
    fields: &[
        DnsFieldDef {
            key: "app_key",
            label: "Application Key:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "app_secret",
            label: "Application Secret:",
            secret: true,
            mono: false,
        },
        DnsFieldDef {
            key: "consumer_key",
            label: "Consumer Key:",
            secret: true,
            mono: false,
        },
    ],
};

/// Porkbun（M9-DNS015）。
const PORKBUN: DnsProviderDef = DnsProviderDef {
    id: "porkbun",
    name: "Porkbun",
    fields: &[
        DnsFieldDef {
            key: "api_key",
            label: "API Key:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "secret_key",
            label: "Secret Key:",
            secret: true,
            mono: false,
        },
    ],
};

/// 百度智能云（M9-DNS016）。
const BAIDU: DnsProviderDef = DnsProviderDef {
    id: "baidu",
    name: "百度智能云",
    fields: &[
        DnsFieldDef {
            key: "access_key_id",
            label: "AccessKey ID:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "secret_access_key",
            label: "Secret AccessKey:",
            secret: true,
            mono: false,
        },
    ],
};

/// 火山引擎云解析（M9-DNS017）。
const VOLCENGINE: DnsProviderDef = DnsProviderDef {
    id: "volcengine",
    name: "火山引擎云解析",
    fields: &[
        DnsFieldDef {
            key: "access_key_id",
            label: "AccessKey ID:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "secret_access_key",
            label: "Secret AccessKey:",
            secret: true,
            mono: false,
        },
        DnsFieldDef {
            key: "region",
            label: "Region:",
            secret: false,
            mono: true,
        },
    ],
};

/// 京东云解析（M9-DNS018）。
const JDCLOUD: DnsProviderDef = DnsProviderDef {
    id: "jdcloud",
    name: "京东云解析",
    fields: &[
        DnsFieldDef {
            key: "access_key",
            label: "AccessKey:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "secret_key",
            label: "SecretKey:",
            secret: true,
            mono: false,
        },
        DnsFieldDef {
            key: "region",
            label: "Region:",
            secret: false,
            mono: true,
        },
    ],
};

/// 西部数码（M9-DNS019；SRV/NS 不支持 → 能力降级）。
const WESTCN: DnsProviderDef = DnsProviderDef {
    id: "westcn",
    name: "西部数码",
    fields: &[
        DnsFieldDef {
            key: "username",
            label: "Username:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "api_password",
            label: "API Password:",
            secret: true,
            mono: false,
        },
        DnsFieldDef {
            key: "domain_key",
            label: "Domain Key:",
            secret: true,
            mono: false,
        },
    ],
};

/// 新网（M9-DNS020；SRV 不支持 → 能力降级）。
const XINNET: DnsProviderDef = DnsProviderDef {
    id: "xinnet",
    name: "新网",
    fields: &[
        DnsFieldDef {
            key: "api_key",
            label: "API Key:",
            secret: false,
            mono: false,
        },
        DnsFieldDef {
            key: "secret_key",
            label: "Secret Key:",
            secret: true,
            mono: false,
        },
        DnsFieldDef {
            key: "client_ip",
            label: "Client IP:",
            secret: false,
            mono: true,
        },
    ],
};

/// 已实现的 DNS 域名维护服务商列表（20 家，M9-DNS001~020 全量）。
static DNS_PROVIDERS: &[DnsProviderDef] = &[
    GODADDY, CLOUDFLARE, ALIYUN, DNSPOD, ROUTE53, AZURE, GOOGLE, HUAWEI, NAMECHEAP,
    DIGITALOCEAN, VULTR, LINODE, HETZNER, OVH, PORKBUN, BAIDU, VOLCENGINE, JDCLOUD, WESTCN,
    XINNET,
];

/// 已实现的 DNS 域名维护服务商列表（20 家）。
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
    fn registry_contains_all_20_providers() {
        let defs = dns_provider_defs();
        assert_eq!(defs.len(), 20, "M9-DNS001~020 全部 20 家");
        // 每个服务商至少一个凭据字段（无字段的服务商无法配置）。
        for def in defs {
            assert!(!def.fields.is_empty(), "{} 缺少凭据字段", def.id);
            assert!(!def.name.is_empty());
        }
    }

    #[test]
    fn provider_ids_unique() {
        let defs = dns_provider_defs();
        let mut ids: Vec<&str> = defs.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), defs.len(), "服务商 id 必须唯一");
    }

    #[test]
    fn godaddy_registered_with_expected_fields() {
        let godaddy = dns_provider_def("godaddy").expect("godaddy 必须已注册");
        assert_eq!(godaddy.name, "GoDaddy");
        let keys: Vec<&str> = godaddy.fields.iter().map(|f| f.key).collect();
        assert_eq!(keys, vec!["domain", "api_key", "api_secret"]);
        let secret = godaddy.fields.iter().find(|f| f.key == "api_secret").unwrap();
        assert!(secret.secret, "API Secret 必须密文输入");
    }

    #[test]
    fn token_providers_are_secret() {
        for (id, key) in [
            ("cloudflare", "api_token"),
            ("digitalocean", "token"),
            ("vultr", "token"),
            ("linode", "token"),
            ("hetzner", "token"),
        ] {
            let def = dns_provider_def(id).unwrap_or_else(|| panic!("{id} 未注册"));
            let token = def.fields.iter().find(|f| f.key == key).unwrap();
            assert!(token.secret, "{id} {key} 必须密文输入");
        }
    }

    #[test]
    fn unknown_provider_returns_none() {
        assert!(dns_provider_def("nonexistent-provider").is_none());
        assert!(dns_provider_def("").is_none());
    }
}
