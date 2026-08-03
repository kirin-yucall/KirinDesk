//! M9-DNS009: Namecheap HTTP 客户端
//!
//! - 端点：`https://api.namecheap.com/xml.response`（GET 表单，XML 响应手写解析）
//! - 公共参数：ApiUser / ApiKey / UserName / ClientIp / Command（IP 白名单认证）
//! - 接口：`getList`（域名列表，分页）、`dns.getHosts` / `dns.setHosts`（整组替换
//!   ≤20 条/次）、SRV 经未公开命令 `dns.getsrvrecords` / `dns.setsrvrecords`
//!   （DNSControl 验证过的可行路径；官方 setHosts 不接受 RecordType=SRV）
//! - 表单编码为手写 percent-encoding（不新增依赖）；30s 超时；
//!   User-Agent `KirinDesk/0.1.0`；凭据只进请求参数，不落日志。

use super::error::{map_api_error, map_http_error};
use super::xml::{parse_api_response, NcApiResponse, NcHost, NcSrvRecord};
use crate::provider::ProviderError;
use std::time::Duration;

/// 官方端点（测试经 `NamecheapClient::new` 的 base_url 指向 127.0.0.1 mock）。
pub(crate) const PROD_BASE_URL: &str = "https://api.namecheap.com/xml.response";
const USER_AGENT: &str = "KirinDesk/0.1.0";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// setHosts 单次最多提交 20 条 host（官方限制；超出由适配层提示，见 mod.rs）。
pub(crate) const MAX_HOSTS_PER_SET: usize = 20;
/// Namecheap TTL 最小值（官方限制 60 秒；写入时收敛，避免读写振荡）。
pub(crate) const TTL_MIN: u32 = 60;
/// Namecheap TTL 默认值（官方默认 1800；ttl=0 时使用）。
pub(crate) const TTL_DEFAULT: u32 = 1800;
/// getList 每页条数（官方最大 100）。
const PAGE_SIZE: u32 = 100;
/// getList 分页防御上限（官方账户不可能超过）。
const MAX_PAGES: u32 = 200;

/// Namecheap API 客户端。
#[derive(Clone)]
pub(crate) struct NamecheapClient {
    http: reqwest::Client,
    api_user: String,
    api_key: String,
    user_name: String,
    client_ip: String,
    base_url: String,
}

impl NamecheapClient {
    /// 构建客户端。`base_url` 生产传 [`PROD_BASE_URL`]，测试传 127.0.0.1 mock。
    pub fn new(
        api_user: String,
        api_key: String,
        user_name: String,
        client_ip: String,
        base_url: String,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .expect("构建 Namecheap reqwest 客户端失败");
        Self {
            http,
            api_user,
            api_key,
            user_name,
            client_ip,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// 执行一次命令（GET 表单 + XML 响应）。
    ///
    /// 公共认证参数（ApiUser/ApiKey/UserName/ClientIp）自动附加，
    /// 请求体不回显（凭据不落日志）。
    async fn call(&self, params: &[(String, String)]) -> Result<NcApiResponse, ProviderError> {
        let mut all: Vec<(String, String)> = vec![
            ("ApiUser".to_string(), self.api_user.clone()),
            ("ApiKey".to_string(), self.api_key.clone()),
            ("UserName".to_string(), self.user_name.clone()),
            ("ClientIp".to_string(), self.client_ip.clone()),
        ];
        all.extend(params.iter().cloned());
        let query = Self::form_encode(&all);
        let url = format!("{}?{}", self.base_url, query);
        let resp = self.http.get(&url).send().await?;
        let status = resp.status().as_u16();
        let body = resp.text().await?;
        if status != 200 {
            return Err(map_http_error(status, &body));
        }
        let parsed = parse_api_response(&body)?;
        if parsed.status.is_empty() {
            return Err(ProviderError::Other(
                "Namecheap 响应缺少 Status 属性（可能非 XML 响应）".to_string(),
            ));
        }
        if parsed.status.eq_ignore_ascii_case("ERROR") {
            return Err(map_api_error(&parsed.errors));
        }
        Ok(parsed)
    }

    /// namecheap.domains.getList：分页拉取全部域名。
    pub async fn list_domains(&self) -> Result<Vec<String>, ProviderError> {
        let mut all = Vec::new();
        let mut page: u32 = 1;
        loop {
            let resp = self
                .call(&[
                    ("Command".to_string(), "namecheap.domains.getList".to_string()),
                    ("Page".to_string(), page.to_string()),
                    ("PageSize".to_string(), PAGE_SIZE.to_string()),
                ])
                .await?;
            let before = all.len();
            all.extend(resp.domains);
            let total = resp.total_items;
            // 终止条件：空页 / 达到 TotalItems（官方分页计数）/ 防御上限。
            if all.len() == before || page >= MAX_PAGES {
                break;
            }
            if total > 0 && all.len() as u32 >= total {
                break;
            }
            page += 1;
        }
        Ok(all)
    }

    /// namecheap.domains.dns.getHosts：当前全部 host 记录（不含 SRV）。
    pub async fn get_hosts(&self, domain: &str) -> Result<Vec<NcHost>, ProviderError> {
        let (sld, tld) = split_domain(domain)?;
        let resp = self
            .call(&[
                ("Command".to_string(), "namecheap.domains.dns.getHosts".to_string()),
                ("SLD".to_string(), sld.to_string()),
                ("TLD".to_string(), tld.to_string()),
            ])
            .await?;
        Ok(resp.hosts)
    }

    /// namecheap.domains.dns.getsrvrecords：查询全部 SRV。
    ///
    /// 注意：官方公开文档未收录该命令；`RecordType=SRV` 在 setHosts 中不被接受，
    /// 本命令 + `setsrvrecords` 是 DNSControl 等在生产验证的可行路径。
    pub async fn get_srv_records(&self, domain: &str) -> Result<Vec<NcSrvRecord>, ProviderError> {
        let (sld, tld) = split_domain(domain)?;
        let resp = self
            .call(&[
                ("Command".to_string(), "namecheap.domains.dns.getsrvrecords".to_string()),
                ("SLD".to_string(), sld.to_string()),
                ("TLD".to_string(), tld.to_string()),
            ])
            .await?;
        Ok(resp.srv_records)
    }

    /// namecheap.domains.dns.setHosts：整组替换（≤20 条/次，超出直接报错提示）。
    ///
    /// 参数组：HostName{n} / RecordType{n} / Address{n} / MXPref{n}（仅 MX）/
    /// TTL{n}；含 MX 时附加 `EmailType=MX`（go-namecheap 同款行为）。
    pub async fn set_hosts(&self, domain: &str, hosts: &[NcHost]) -> Result<(), ProviderError> {
        if hosts.len() > MAX_HOSTS_PER_SET {
            return Err(ProviderError::Other(format!(
                "Namecheap setHosts 单次最多提交 {MAX_HOSTS_PER_SET} 条记录，\
                 当前域名共 {} 条，无法整组写入（请先在 Namecheap 控制台精简记录数）",
                hosts.len()
            )));
        }
        let (sld, tld) = split_domain(domain)?;
        let mut params: Vec<(String, String)> = vec![
            ("Command".to_string(), "namecheap.domains.dns.setHosts".to_string()),
            ("SLD".to_string(), sld.to_string()),
            ("TLD".to_string(), tld.to_string()),
        ];
        let mut has_mx = false;
        for (i, h) in hosts.iter().enumerate() {
            let n = i + 1;
            params.push((format!("HostName{n}"), h.name.clone()));
            params.push((format!("RecordType{n}"), h.rtype.clone()));
            params.push((format!("Address{n}"), h.address.clone()));
            if h.rtype == "MX" {
                params.push((format!("MXPref{n}"), h.mxpref.to_string()));
                has_mx = true;
            }
            params.push((format!("TTL{n}"), h.ttl.to_string()));
        }
        if has_mx {
            params.push(("EmailType".to_string(), "MX".to_string()));
        }
        let resp = self.call(&params).await?;
        if !resp.set_hosts_ok {
            return Err(ProviderError::Other(
                "Namecheap setHosts 返回 IsSuccess=false".to_string(),
            ));
        }
        Ok(())
    }

    /// namecheap.domains.dns.setsrvrecords：整组替换 SRV。
    ///
    /// 参数组：SrvCount + Service{n}/Protocol{n}/Priority{n}/Port{n}/Target{n}/Weight{n}
    /// （与 `getsrvrecords` 配套的未公开命令，DNSControl 同款）。
    pub async fn set_srv_records(
        &self,
        domain: &str,
        records: &[NcSrvRecord],
    ) -> Result<(), ProviderError> {
        let (sld, tld) = split_domain(domain)?;
        let mut params: Vec<(String, String)> = vec![
            ("Command".to_string(), "namecheap.domains.dns.setsrvrecords".to_string()),
            ("SLD".to_string(), sld.to_string()),
            ("TLD".to_string(), tld.to_string()),
            ("SrvCount".to_string(), records.len().to_string()),
        ];
        for (i, r) in records.iter().enumerate() {
            let n = i + 1;
            params.push((format!("Service{n}"), r.service.clone()));
            params.push((format!("Protocol{n}"), r.protocol.clone()));
            params.push((format!("Priority{n}"), r.priority.to_string()));
            params.push((format!("Port{n}"), r.port.to_string()));
            params.push((format!("Target{n}"), r.target.clone()));
            params.push((format!("Weight{n}"), r.weight.to_string()));
        }
        // Status=OK 即成功（响应含 <Result><Inserted/>... 或空 zone 无 <Result>）。
        let _resp = self.call(&params).await?;
        Ok(())
    }

    /// 表单编码（手写 percent-encoding；空格 → %20）。
    fn form_encode(pairs: &[(String, String)]) -> String {
        let mut out = String::new();
        for (i, (k, v)) in pairs.iter().enumerate() {
            if i > 0 {
                out.push('&');
            }
            out.push_str(&Self::encode_component(k));
            out.push('=');
            out.push_str(&Self::encode_component(v));
        }
        out
    }

    /// percent-encode：仅保留 RFC 3986 unreserved 字符。
    fn encode_component(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}

/// 域名 → (SLD, TLD)：以第一个 "." 拆分。
///
/// example.com → ("example", "com")；example.co.uk → ("example", "co.uk")
/// （与 Namecheap API 文档一致：SLD=第二级域名、TLD=其余部分）。
pub(crate) fn split_domain(domain: &str) -> Result<(&str, &str), ProviderError> {
    match domain.find('.') {
        Some(i) if i > 0 && i + 1 < domain.len() => Ok((&domain[..i], &domain[i + 1..])),
        _ => Err(ProviderError::InvalidParameter {
            detail: format!("域名格式非法（需为含 . 的注册域名，如 example.com）: {domain}"),
        }),
    }
}
