//! M9-DNS000 / M9-DNS022 (UI-DNS-001~011): 域名维护客户端页面（Dashboard 右侧
//! 「Domain」标签页）——全面支持 20 家服务商。
//!
//! 按 `M9-DNS000_DNS域名维护客户端_总体需求.md` 实现的功能子集：
//! - UI-DNS-001 服务商下拉：由 `dns_provider_defs()` 注册表驱动，选中显示
//!   def.name；
//! - UI-DNS-002 凭据动态表单：字段由服务商定义 `fields` 驱动（label/secret/
//!   mono），值映射到 `cred_values`，密文 👁 切换记入 `show_secret`；
//! - UI-DNS-003 测试连接：`test_connection()`；
//! - UI-DNS-004 文案泛化：不出现任何厂商字样（GoDaddy 仅保留配置层兼容）；
//! - UI-DNS-005 域名列表：`list_domains()` + 本地手动添加；
//! - UI-DNS-006/007 记录查询与编辑：`query_records` / `upsert_record` /
//!   `delete_record`，SRV/MX 结构化（RecordData）；
//! - UI-DNS-009 能力降级：`caps.srv`/`caps.ns` 为 false 时记录卡顶部警示 +
//!   编辑弹窗类型下拉禁用对应项；
//! - UI-DNS-010 未适配服务商：注册表未注册 → 凭据表单不渲染，显示指引；
//! - UI-DNS-011 配置签名回填：签名 = (provider, 凭据表序列化) + godaddy
//!   旧字段，签名变化才回填表单，避免覆盖正在编辑的输入。
//!
//! 状态机约定：`KirinDeskApp` 持有本页状态；所有 API 调用在后台线程执行
//! （`std::thread::spawn` + tokio runtime，与 Connect 页同模式），结果经
//! 共享槽回填，GUI 每帧 `poll()` 一次——不阻塞 UI 线程。

use eframe::egui;
use kirin_desk_dns::provider_registry;
use kirin_desk_dns::{Provider, ProviderCapabilities, ProviderError};
use kirin_desk_dns::{Record, RecordData, RecordType};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::theme::Theme;
use crate::t;
use crate::tf;
use crate::widgets::{
    action_button, badge, labeled_input, status_dot, BadgeKind, ButtonKind, ButtonState, Validity,
};

/// 维护面板支持的全部记录类型（DNS-MNT-006：A/AAAA/CNAME/MX/TXT/SRV/NS）。
pub const RECORD_TYPES: [&str; 7] = ["A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT"];

/// 类型筛选下拉项（"" = 全部；首项按当前语言翻译，M8-T038 P5）。
fn filter_items() -> [&'static str; 8] {
    [t!("domain.record.filter_all"), "A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT"]
}

// ════════════════════════════════════════════════════════════════
// 后台任务协议
// ════════════════════════════════════════════════════════════════

/// 一条后台任务：worker 线程自行 `Config::load()` 并构建当前激活服务商
/// （凭据只存在于配置层，M9-DNS000 §七.3）。
enum DomainOp {
    /// DNS-MNT-003 测试连接（最小查询）。
    TestConnection,
    /// DNS-MNT-004 拉取域名列表。
    ListDomains,
    /// DNS-MNT-005 拉取指定域名全部记录（类型筛选在客户端侧 `visible_records`）。
    LoadRecords {
        domain: String,
    },
    /// DNS-MNT-006/007 新增或更新记录（统一模型按 name+rtype 幂等 upsert；
    /// `old_name`/`old_rtype` = 更新模式定位原记录，名称/类型变化时清理旧记录）。
    SaveRecord {
        domain: String,
        rtype: RecordType,
        name: String,
        data: RecordData,
        ttl: u32,
        old_name: Option<String>,
        old_rtype: Option<RecordType>,
    },
    /// DNS-MNT-006 删除该 name+rtype 下的全部记录（统一模型语义）。
    DeleteRecord {
        domain: String,
        rtype: RecordType,
        name: String,
    },
}

/// 后台任务结果。
enum DomainOpResult {
    /// 测试连接。
    Test(Result<(), String>),
    /// 域名列表。
    Domains(Result<Vec<String>, String>),
    /// 记录列表。
    Records {
        domain: String,
        result: Result<Vec<Record>, String>,
    },
    /// 写操作（新增/更新/删除）。
    Write(Result<(), String>),
}

/// 共享结果槽（worker 写，GUI `poll()` 读；同时只允许一个任务在跑）。
fn worker_slot() -> &'static Mutex<Option<DomainOpResult>> {
    static S: OnceLock<Mutex<Option<DomainOpResult>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(None))
}

/// 是否有后台任务在跑（GUI 据此禁用按钮防并发）。
fn worker_busy() -> &'static AtomicBool {
    static B: AtomicBool = AtomicBool::new(false);
    &B
}

/// 从配置构建当前激活服务商（worker 线程内调用）。
///
/// 顺序判定（UI-DNS-010 / UI-DNS-004）：注册表未注册 → 明确「适配尚未实现」
/// 指引；已注册但无凭据 → 「DNS 服务商未配置」（引导 Domain 页「服务商」卡）。
fn provider_from_config() -> Result<Box<dyn Provider>, String> {
    let cfg = kirin_desk_utils::config::Config::load()
        .map_err(|e| tf!("domain.error.config_load", e))?;
    let provider = cfg.dns.provider.clone();
    let provider_name = kirin_desk_utils::dns_providers::dns_provider_def(&provider)
        .map(|p| p.name.to_string())
        .unwrap_or_else(|| provider.clone());
    if !provider_registry().has(&provider) {
        return Err(tf!(
            "domain.error.provider_unsupported",
            provider_name
        ));
    }
    if cfg
        .dns_provider_credentials(&provider)
        .map_or(true, |m| m.is_empty())
    {
        return Err(t!("domain.error.not_configured").to_string());
    }
    kirin_desk_dns::default_provider(&provider, &cfg.dns.providers)
        .map_err(|e| tf!("domain.error.client_init", e))
}

/// 统一错误文案（DNS-MNT-011：上层不感知厂商原始细节，分类到认证/参数/
/// 未找到/限流/服务端/网络/不支持；原始串只进日志）。
fn fmt_provider_error(e: &ProviderError) -> String {
    match e {
        ProviderError::Auth { .. } => t!("domain.error.auth_failed").to_string(),
        ProviderError::InvalidParameter { detail } => {
            tf!("domain.error.invalid_params", truncate(detail))
        }
        ProviderError::NotFound { .. } => t!("domain.error.not_found").to_string(),
        ProviderError::RateLimited { .. } => t!("domain.error.rate_limited").to_string(),
        ProviderError::Server { status, .. } => tf!("domain.error.server_error", status),
        ProviderError::Network(_) => t!("domain.error.network").to_string(),
        ProviderError::Json(_) => t!("domain.error.json").to_string(),
        ProviderError::Unsupported(what) => tf!("domain.error.unsupported_type", what),
        ProviderError::Other(msg) => tf!("domain.error.config", truncate(msg)),
    }
}

fn truncate(s: &str) -> String {
    const MAX: usize = 120;
    if s.chars().count() > MAX {
        let t: String = s.chars().take(MAX).collect();
        format!("{t}…")
    } else {
        s.to_string()
    }
}

/// 启动一条后台任务（已有任务在跑则忽略并返回 false）。
fn launch_worker(op: DomainOp) -> bool {
    if worker_busy().swap(true, Ordering::SeqCst) {
        return false;
    }
    std::thread::spawn(move || {
        let result = run_op(op);
        *worker_slot().lock().unwrap() = Some(result);
        worker_busy().store(false, Ordering::SeqCst);
    });
    true
}

/// 在 worker 线程内执行任务（tokio runtime 一次性，与 Connect 页同模式）。
fn run_op(op: DomainOp) -> DomainOpResult {
    let rt = tokio::runtime::Runtime::new().expect("domain panel runtime");
    rt.block_on(async move {
        // 服务商构建失败（未配置/未注册/凭据不完整）→ 直接回错误。
        let provider = match provider_from_config() {
            Ok(p) => p,
            Err(e) => {
                return match op {
                    DomainOp::TestConnection => DomainOpResult::Test(Err(e)),
                    DomainOp::ListDomains => DomainOpResult::Domains(Err(e)),
                    DomainOp::LoadRecords { domain } => {
                        DomainOpResult::Records { domain, result: Err(e) }
                    }
                    _ => DomainOpResult::Write(Err(e)),
                };
            }
        };
        match op {
            DomainOp::TestConnection => match provider.test_connection().await {
                Ok(()) => DomainOpResult::Test(Ok(())),
                Err(e) => DomainOpResult::Test(Err(fmt_provider_error(&e))),
            },
            DomainOp::ListDomains => match provider.list_domains().await {
                Ok(domains) => DomainOpResult::Domains(Ok(domains)),
                Err(e) => DomainOpResult::Domains(Err(fmt_provider_error(&e))),
            },
            DomainOp::LoadRecords { domain } => {
                match provider.query_records(&domain, None, None).await {
                    Ok(records) => DomainOpResult::Records {
                        domain,
                        result: Ok(records),
                    },
                    Err(e) => DomainOpResult::Records {
                        domain,
                        result: Err(fmt_provider_error(&e)),
                    },
                }
            }
            DomainOp::SaveRecord {
                domain,
                rtype,
                name,
                data,
                ttl,
                old_name,
                old_rtype,
            } => {
                let result = save_record(
                    &*provider,
                    &domain,
                    rtype,
                    &name,
                    data,
                    ttl,
                    old_name.as_deref(),
                    old_rtype,
                )
                .await;
                DomainOpResult::Write(result)
            }
            DomainOp::DeleteRecord {
                domain,
                rtype,
                name,
            } => {
                let result = provider
                    .delete_record(&domain, &name, rtype)
                    .await
                    .map_err(|e| fmt_provider_error(&e));
                DomainOpResult::Write(result)
            }
        }
    })
}

/// DNS-MNT-006/007：统一模型写入——幂等 upsert（存在则更新、不存在则创建，
/// 适配层消化厂商语义）；更新且名称/类型变化时清理旧 name+rtype 记录。
async fn save_record(
    provider: &dyn Provider,
    domain: &str,
    rtype: RecordType,
    name: &str,
    data: RecordData,
    ttl: u32,
    old_name: Option<&str>,
    old_rtype: Option<RecordType>,
) -> Result<(), String> {
    let rec = Record {
        name: name.to_string(),
        rtype,
        ttl,
        data,
    };
    provider
        .upsert_record(domain, &rec)
        .await
        .map_err(|e| fmt_provider_error(&e))?;
    if let (Some(old_name), Some(old_rtype)) = (old_name, old_rtype) {
        if old_name != name || old_rtype != rtype {
            provider
                .delete_record(domain, old_name, old_rtype)
                .await
                .map_err(|e| fmt_provider_error(&e))?;
        }
    }
    Ok(())
}

// ════════════════════════════════════════════════════════════════
// 页面状态
// ════════════════════════════════════════════════════════════════

/// 记录编辑弹窗状态。
#[derive(Default, Clone)]
pub struct RecordEditState {
    pub domain: String,
    /// true = 新增；false = 更新（`old_name`/`old_rtype` 定位原记录）。
    pub is_new: bool,
    pub old_name: Option<String>,
    pub old_rtype: Option<RecordType>,
    pub rtype: String,
    pub name: String,
    pub data: String,
    pub ttl: String,
    /// SRV 拆分字段（UI-DNS-007：类型切换动态渲染）。
    pub srv_priority: String,
    pub srv_weight: String,
    pub srv_port: String,
    pub srv_target: String,
}

/// 配置签名（UI-DNS-011）：(provider, 凭据表序列化, godaddy 兼容 api_key,
/// api_secret, domain)——任一变化才回填表单，避免覆盖正在编辑的输入。
type CredSig = (String, String, String, String, String);

/// 计算配置签名（`sync_provider` 与 `save_credentials` 共用同一口径）。
fn cred_sig_of(cfg: &kirin_desk_utils::config::Config) -> CredSig {
    let provider = cfg.dns.provider.clone();
    let legacy = if provider == "godaddy" {
        (
            cfg.godaddy.api_key.clone(),
            cfg.godaddy.api_secret.clone(),
            cfg.godaddy.domain.clone(),
        )
    } else {
        (String::new(), String::new(), String::new())
    };
    (
        provider,
        serde_json::to_string(&cfg.dns.providers.get(&cfg.dns.provider)).unwrap_or_default(),
        legacy.0,
        legacy.1,
        legacy.2,
    )
}

/// 域名维护页面状态（KirinDeskApp 持有；GUI 帧内 `poll()` 回填后台结果）。
#[derive(Default)]
pub struct DomainPanelState {
    /// 配置中已保存的服务商 id（每次进入页面刷新展示）。
    pub provider_id: String,
    /// 服务商展示名。
    pub provider_name: String,
    /// 凭据是否已配置（注册表已注册 + 凭据表非空）。
    pub configured: bool,

    // —— 服务商选择与凭据（UI-DNS-001/002；M9-DNS022 迁自 Settings → DNS 组）——
    /// ComboBox 当前选中服务商 id。
    pub provider: String,
    /// 凭据表单值（key = 服务商定义字段 key，UI-DNS-002 动态渲染）。
    pub cred_values: HashMap<String, String>,
    /// 已点 👁 的 secret 字段 key（明文展示）。
    pub show_secret: HashSet<String>,
    /// 保存凭据结果反馈。
    pub cred_status: String,
    pub cred_ok: bool,
    /// 能力声明（UI-DNS-009：provider 构建时读取；构建失败用全开默认）。
    pub caps: ProviderCapabilities,
    /// 上次回填的配置签名（变化才回填表单）。
    cred_sig: Option<CredSig>,

    // —— 测试连接（DNS-MNT-003）——
    pub test_busy: bool,
    pub test_ok: Option<bool>,
    pub test_status: String,

    // —— 域名列表（DNS-MNT-004，UI-DNS-005）——
    pub domains: Vec<String>,
    /// 「添加域名」手动缓存（API 列表之外，会话级）。
    pub manual_domains: Vec<String>,
    pub selected: String,
    pub domains_busy: bool,
    pub add_input: String,

    // —— 记录（DNS-MNT-005/006，UI-DNS-006/007）——
    pub records: Vec<Record>,
    pub records_busy: bool,
    pub filter: String,

    /// 记录编辑弹窗（None = 关闭）。
    pub editing: Option<RecordEditState>,

    /// 页面状态行。
    pub status: String,
    pub status_ok: bool,
}

impl DomainPanelState {
    /// 进入页面/切换服务商时刷新展示信息（不触发网络请求）。
    pub fn sync_provider(&mut self) {
        let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
        let sig = cred_sig_of(&cfg);
        if self.cred_sig.as_ref() != Some(&sig) {
            let provider = cfg.dns.provider.clone();
            self.provider = provider.clone();
            // 回填表单值（仅回填该服务商定义中的字段 key）。
            self.cred_values.clear();
            if let Some(def) =
                kirin_desk_utils::dns_providers::dns_provider_def(&provider)
            {
                for field in def.fields {
                    let v = cfg
                        .dns_provider_credentials(&provider)
                        .and_then(|m| m.get(field.key))
                        .cloned()
                        .unwrap_or_default();
                    self.cred_values.insert(field.key.to_string(), v);
                }
            }
            self.show_secret.clear();
            self.cred_ok = false;
            self.cred_status.clear();
            // UI-DNS-009：能力声明——provider 构建时读取（构建失败 → 全开默认）。
            self.caps = kirin_desk_dns::default_provider(&provider, &cfg.dns.providers)
                .map(|p| p.capabilities())
                .unwrap_or_else(|_| ProviderCapabilities::all());
            self.cred_sig = Some(sig);
        }
        self.provider_id = cfg.dns.provider.clone();
        let def = kirin_desk_utils::dns_providers::dns_provider_def(&self.provider_id);
        self.provider_name = def.map(|p| p.name.to_string()).unwrap_or_else(|| {
            if self.provider_id.is_empty() {
                "godaddy".to_string()
            } else {
                self.provider_id.clone()
            }
        });
        self.configured = provider_registry().has(&self.provider_id)
            && cfg
                .dns_provider_credentials(&self.provider_id)
                .map_or(false, |m| !m.is_empty());
    }

    /// UI-DNS-002: 保存服务商选择 + 凭据到配置（即时落盘，模式同 Dashboard
    /// 服务端设置小保存按钮）。返回 true = 保存成功——调用方据此同步
    /// App 内存凭据（Connect 页 / 状态栏即时生效）。
    pub fn save_credentials(&mut self) -> bool {
        // 防御性回退：非法服务商 id → "godaddy"（注册表唯一事实源）。
        let provider = if kirin_desk_utils::dns_providers::dns_provider_def(&self.provider)
            .is_some()
        {
            self.provider.clone()
        } else {
            "godaddy".to_string()
        };
        let Some(def) = kirin_desk_utils::dns_providers::dns_provider_def(&provider) else {
            self.cred_ok = false;
            self.cred_status = tf!("domain.error.provider_unsupported", provider).to_string();
            return false;
        };
        // 按服务商定义字段校验：全部非空（secret 字段只展示 label，不打印值）。
        for field in def.fields {
            let v = self
                .cred_values
                .get(field.key)
                .map(String::as_str)
                .unwrap_or("");
            if v.trim().is_empty() {
                self.cred_ok = false;
                self.cred_status = tf!("domain.cred.required_field", field.label);
                return false;
            }
            // domain 字段（godaddy 设备域）保持主机名校验。
            if field.key == "domain"
                && !kirin_desk_dns::validate::validate_hostname(v.trim())
            {
                self.cred_ok = false;
                self.cred_status = t!("domain.cred.domain_invalid").to_string();
                return false;
            }
        }
        let Ok(mut cfg) = kirin_desk_utils::config::Config::load() else {
            self.cred_ok = false;
            self.cred_status = t!("domain.cred.config_load_failed").to_string();
            return false;
        };
        // 写入 `[dns] provider` + `[dns.providers.{provider}]`（仅已渲染的字段 key）。
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        for field in def.fields {
            let v = self
                .cred_values
                .get(field.key)
                .map(String::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            fields.insert(field.key.to_string(), v);
        }
        cfg.dns.provider = provider.clone();
        cfg.dns.providers.insert(provider.clone(), fields);
        // godaddy 兼容：同步写 `[godaddy]`（api_url 默认生产地址；表单含
        // domain 字段时同步设备域，供 CLI / Connect 页旧路径读取）。
        if provider == "godaddy" {
            cfg.godaddy.api_key = self
                .cred_values
                .get("api_key")
                .cloned()
                .unwrap_or_default()
                .trim()
                .to_string();
            cfg.godaddy.api_secret = self
                .cred_values
                .get("api_secret")
                .cloned()
                .unwrap_or_default()
                .trim()
                .to_string();
            cfg.godaddy.api_url = self
                .cred_values
                .get("api_url")
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "https://api.godaddy.com".to_string());
            if def.fields.iter().any(|f| f.key == "domain") {
                cfg.godaddy.domain = self
                    .cred_values
                    .get("domain")
                    .cloned()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
            }
        }
        match cfg.save() {
            Ok(()) => {
                // 签名同步为刚保存值，避免下一帧 sync_provider 覆盖。
                self.cred_sig = Some(cred_sig_of(&cfg));
                self.provider_id = provider;
                self.configured = true;
                self.cred_ok = true;
                self.cred_status = t!("domain.cred.saved").to_string();
                true
            }
            Err(e) => {
                self.cred_ok = false;
                self.cred_status = tf!("domain.cred.save_failed", e);
                false
            }
        }
    }

    /// 每帧回填后台任务结果（必须在渲染前调用一次）。
    pub fn poll(&mut self) {
        let result = worker_slot().lock().unwrap().take();
        let Some(result) = result else { return };
        match result {
            DomainOpResult::Test(Ok(())) => {
                self.test_ok = Some(true);
                self.test_status = t!("domain.test.ok").to_string();
            }
            DomainOpResult::Test(Err(e)) => {
                self.test_ok = Some(false);
                self.test_status = tf!("domain.test.failed", e);
            }
            DomainOpResult::Domains(Ok(mut domains)) => {
                domains.sort();
                self.domains = domains;
                self.domains_busy = false;
                // 已选域名失效 → 自动落到第一个。
                if !self.domains.contains(&self.selected) && !self.selected.is_empty() {
                    self.selected.clear();
                }
                if self.selected.is_empty() {
                    if let Some(first) = self.domains.first() {
                        self.selected = first.clone();
                    }
                }
                self.status_ok = true;
                self.status = tf!("domain.status.domains_loaded", self.domains.len());
            }
            DomainOpResult::Domains(Err(e)) => {
                self.domains_busy = false;
                self.status_ok = false;
                self.status = e;
            }
            DomainOpResult::Records { domain, result } => {
                self.records_busy = false;
                if domain == self.selected {
                    match result {
                        Ok(mut records) => {
                            // 稳定排序：类型 → 名称 → 数据（展示形态）。
                            records.sort_by(|a, b| {
                                (
                                    &a.rtype,
                                    &a.name,
                                    a.data.to_display_string(),
                                )
                                    .cmp(&(
                                        &b.rtype,
                                        &b.name,
                                        b.data.to_display_string(),
                                    ))
                            });
                            self.records = records;
                            self.status_ok = true;
                            self.status = tf!("domain.status.records_loaded", domain, self.records.len());
                        }
                        Err(e) => {
                            self.records.clear();
                            self.status_ok = false;
                            self.status = tf!("domain.status.records_error", domain, e);
                        }
                    }
                }
            }
            DomainOpResult::Write(Ok(())) => {
                self.status_ok = true;
                self.status = t!("domain.status.saved_refresh").to_string();
                // 写操作后自动重载当前域名记录（含筛选）。
                self.trigger_load_records();
            }
            DomainOpResult::Write(Err(e)) => {
                self.status_ok = false;
                self.status = e;
            }
        }
    }

    // ── 触发后台任务（各自前置防并发 + busy 态）──

    /// DNS-MNT-003 测试连接。
    pub fn trigger_test(&mut self) {
        if self.test_busy || worker_busy().load(Ordering::SeqCst) {
            return;
        }
        self.test_busy = true;
        self.test_ok = None;
        self.test_status = t!("domain.test.testing").to_string();
        launch_worker(DomainOp::TestConnection);
    }

    /// DNS-MNT-004 刷新域名列表。
    pub fn trigger_refresh_domains(&mut self) {
        if self.domains_busy || worker_busy().load(Ordering::SeqCst) {
            return;
        }
        self.domains_busy = true;
        self.status = t!("domain.status.fetching_domains").to_string();
        self.status_ok = true;
        launch_worker(DomainOp::ListDomains);
    }

    /// DNS-MNT-005 加载当前选中域名全部记录（类型筛选在客户端侧过滤）。
    pub fn trigger_load_records(&mut self) {
        if self.selected.is_empty() || self.records_busy || worker_busy().load(Ordering::SeqCst) {
            return;
        }
        self.records_busy = true;
        self.status = tf!("domain.status.loading_records", self.selected);
        self.status_ok = true;
        launch_worker(DomainOp::LoadRecords {
            domain: self.selected.clone(),
        });
    }

    /// 「添加域名」：校验后加入手动缓存并选中（本地操作，无网络请求）。
    pub fn add_domain(&mut self) -> bool {
        let input = self.add_input.trim().to_lowercase();
        if input.is_empty() || !kirin_desk_dns::validate::validate_hostname(&input) {
            self.status_ok = false;
            self.status = t!("domain.cred.domain_invalid").to_string();
            return false;
        }
        if !self.domains.contains(&input) {
            self.domains.push(input.clone());
            self.domains.sort();
        }
        if !self.manual_domains.contains(&input) {
            self.manual_domains.push(input.clone());
        }
        self.selected = input;
        self.add_input.clear();
        self.status_ok = true;
        self.status = t!("domain.status.domain_added").to_string();
        true
    }

    /// 打开新增记录弹窗。
    pub fn open_add_record(&mut self) {
        self.editing = Some(RecordEditState {
            domain: self.selected.clone(),
            is_new: true,
            rtype: "A".to_string(),
            name: "@".to_string(),
            ttl: "600".to_string(),
            ..Default::default()
        });
    }

    /// 打开编辑弹窗（SRV/MX 从结构化 RecordData 拆分）。
    pub fn open_edit_record(&mut self, rec: &Record) {
        let mut state = RecordEditState {
            domain: self.selected.clone(),
            is_new: false,
            old_name: Some(rec.name.clone()),
            old_rtype: Some(rec.rtype),
            rtype: rec.rtype.as_str().to_string(),
            name: if rec.name.is_empty() {
                "@".to_string()
            } else {
                rec.name.clone()
            },
            ttl: rec.ttl.to_string(),
            ..Default::default()
        };
        match &rec.data {
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                state.srv_priority = priority.to_string();
                state.srv_weight = weight.to_string();
                state.srv_port = port.to_string();
                state.srv_target = target.clone();
            }
            RecordData::Mx { priority, exchange } => {
                state.data = format!("{priority} {exchange}");
            }
            RecordData::Plain(s) => state.data = s.clone(),
        }
        self.editing = Some(state);
    }

    /// 删除单条记录（统一模型：删除该 name+rtype 下全部记录）。
    pub fn trigger_delete_record(&mut self, rec: &Record) {
        if self.records_busy || worker_busy().load(Ordering::SeqCst) {
            return;
        }
        self.records_busy = true;
        self.status_ok = true;
        self.status = tf!("domain.status.deleting", rec.rtype, rec.name);
        launch_worker(DomainOp::DeleteRecord {
            domain: self.selected.clone(),
            rtype: rec.rtype,
            name: rec.name.clone(),
        });
    }

    /// 弹窗「保存」：校验 → 组装 RecordData（SRV 拆分字段 / MX 结构化，
    /// 失败回退 Plain）→ 后台写。
    pub fn save_edit(&mut self) -> bool {
        let Some(edit) = self.editing.take() else {
            return false;
        };
        // —— 校验 ——
        let rtype: RecordType = match edit.rtype.parse() {
            Ok(t) => t,
            Err(_) => {
                self.status_ok = false;
                self.status = t!("domain.edit.data_empty").to_string();
                return false;
            }
        };
        let raw_name = edit.name.trim().to_string();
        // 统一模型相对名："" = 根；UI 用 "@" 表达根。
        let name = if raw_name == "@" { String::new() } else { raw_name.clone() };
        let valid_name = name.is_empty()
            || name == "*"
            || kirin_desk_dns::validate::validate_record_name(&name);
        if !valid_name {
            self.status_ok = false;
            self.status = t!("domain.edit.name_invalid").to_string();
            return false;
        }
        let ttl: u32 = match edit.ttl.trim().parse() {
            Ok(t) if t >= 600 => t,
            _ => {
                self.status_ok = false;
                self.status = t!("domain.edit.ttl_invalid").to_string();
                return false;
            }
        };
        let data = if rtype == RecordType::SRV {
            let priority: u16 = match edit.srv_priority.trim().parse() {
                Ok(v) => v,
                Err(_) => {
                    self.status_ok = false;
                    self.status = t!("domain.edit.srv_priority_invalid").to_string();
                    return false;
                }
            };
            let weight: u16 = match edit.srv_weight.trim().parse() {
                Ok(v) => v,
                Err(_) => {
                    self.status_ok = false;
                    self.status = t!("domain.edit.srv_weight_invalid").to_string();
                    return false;
                }
            };
            let port: u16 = match edit.srv_port.trim().parse() {
                Ok(v) if v > 0 => v,
                _ => {
                    self.status_ok = false;
                    self.status = t!("domain.edit.srv_port_invalid").to_string();
                    return false;
                }
            };
            let target = edit.srv_target.trim().to_string();
            if !kirin_desk_dns::validate::validate_hostname(&target) {
                self.status_ok = false;
                self.status = t!("domain.edit.srv_target_invalid").to_string();
                return false;
            }
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            }
        } else if rtype == RecordType::MX {
            // MX：尝试结构化解析 "u16 exchange" → Mx；失败回退 Plain。
            let text = edit.data.trim().to_string();
            if text.is_empty() {
                self.status_ok = false;
                self.status = t!("domain.edit.data_empty").to_string();
                return false;
            }
            match parse_mx_data(&text) {
                Some((priority, exchange)) => RecordData::Mx { priority, exchange },
                None => RecordData::Plain(text),
            }
        } else {
            let data = edit.data.trim().to_string();
            if data.is_empty() {
                self.status_ok = false;
                self.status = t!("domain.edit.data_empty").to_string();
                return false;
            }
            RecordData::Plain(data)
        };
        if worker_busy().load(Ordering::SeqCst) {
            self.status_ok = false;
            self.status = t!("domain.edit.busy").to_string();
            return false;
        }
        self.records_busy = true;
        self.status_ok = true;
        self.status = if edit.is_new {
            tf!("domain.edit.adding", rtype, name)
        } else {
            tf!("domain.edit.updating", rtype, name)
        };
        launch_worker(DomainOp::SaveRecord {
            domain: edit.domain.clone(),
            rtype,
            name,
            data,
            ttl,
            old_name: if edit.is_new { None } else { edit.old_name },
            old_rtype: if edit.is_new { None } else { edit.old_rtype },
        });
        true
    }

    /// 按筛选/类型过滤后的记录视图（返回自有副本——渲染闭包内需可变借用
    /// `state` 触发操作，不能持有对 `self.records` 的借用）。
    pub fn visible_records(&self) -> Vec<Record> {
        self.records
            .iter()
            .filter(|r| self.filter.is_empty() || r.rtype.as_str() == self.filter)
            .cloned()
            .collect()
    }
}

/// 解析 MX 记录数据 "u16 exchange"（失败 → None，调用方回退 Plain）。
fn parse_mx_data(s: &str) -> Option<(u16, String)> {
    let mut parts = s.split_whitespace();
    let priority: u16 = parts.next()?.parse().ok()?;
    let exchange: String = parts.collect::<Vec<_>>().join(" ");
    if exchange.is_empty() {
        None
    } else {
        Some((priority, exchange))
    }
}

// ════════════════════════════════════════════════════════════════
// 页面渲染
// ════════════════════════════════════════════════════════════════

/// Domain 标签页主入口（lib.rs `show_domain` 调用）。
///
/// 返回 `true` = 本帧保存了服务商凭据（调用方据此同步 App 内存凭据，
/// Connect 页 / 状态栏即时生效）。
/// M8-T040 (WBS 6.1)：Domain 页入口。`ddns` 为 DDNS 卡控制器
/// （KirinDeskApp 持有，状态共享槽 + worker 句柄）。
pub fn show_domain_page(
    ui: &mut egui::Ui,
    theme: &Theme,
    state: &mut DomainPanelState,
    ddns: &mut DdnsUi,
) -> bool {
    state.poll();
    state.sync_provider();
    let mut saved = false;
    ui.heading(t!("domain.title"));
    ui.separator();
    egui::ScrollArea::vertical().show(ui, |ui| {
        saved |= show_provider_card(ui, theme, state);
        ui.add_space(theme.spacing);
        // M8-T040：DDNS 维护卡（记录管理区上方，需求 §七 草图）。
        show_ddns_card(ui, theme, state, ddns);
        ui.add_space(theme.spacing);
        show_domain_card(ui, theme, state);
        ui.add_space(theme.spacing);
        show_records_card(ui, theme, state);
        ui.add_space(theme.spacing);
        if !state.status.is_empty() {
            ui.horizontal(|ui| {
                status_dot(
                    ui,
                    if state.status_ok { theme.success } else { theme.danger },
                    &state.status,
                );
            });
        }
    });
    // 编辑弹窗（独立于滚动区）。
    if state.editing.is_some() {
        show_edit_window(ui, theme, state);
    }
    saved
}

/// UI-DNS-002: 凭据动态表单——字段来自 `dns_providers` 注册表定义
/// （label/secret/mono 由定义驱动），值映射到 `cred_values`（key = 字段 key）。
/// secret 字段密文输入 + 👁 切换（M15-T008 模式），切换状态记入 `show_secret`。
fn render_cred_fields(
    ui: &mut egui::Ui,
    theme: &Theme,
    state: &mut DomainPanelState,
    def: &kirin_desk_utils::dns_providers::DnsProviderDef,
) {
    for field in def.fields {
        let value = state.cred_values.entry(field.key.to_string()).or_default();
        let mut show = state.show_secret.contains(field.key);
        // placeholder = label 去冒号（如 "API Key:" → "API Key"）。
        let placeholder = field.label.trim_end_matches(':');
        labeled_input(
            ui,
            theme,
            field.label,
            value,
            placeholder,
            Validity::None,
            if field.secret { Some(&mut show) } else { None },
            field.mono,
        );
        if field.secret {
            if show {
                state.show_secret.insert(field.key.to_string());
            } else {
                state.show_secret.remove(field.key);
            }
        }
    }
}

/// ① 服务商卡：服务商选择（UI-DNS-001）+ 凭据表单（UI-DNS-002，密文 + 👁）
/// + 保存按钮（即时落盘）+ 测试连接（DNS-MNT-003，UI-DNS-003）。
/// 迁自 Settings → DNS 组（M9-DNS022 决策：DNS 配置集中到 Domain 页）。
/// 返回 `true` = 本帧保存了凭据。
fn show_provider_card(ui: &mut egui::Ui, theme: &Theme, state: &mut DomainPanelState) -> bool {
    let mut saved = false;
    crate::widgets::card(ui, theme, t!("domain.provider.title"), |ui| {
        ui.horizontal(|ui| {
            // R-27：移除服务商名 Info 徽标（品牌蓝观感误认 logo；服务商名已展示于
            // ComboBox 选中文本与卡片标题，无需徽标强调）。仅保留配置状态徽标。
            if state.configured {
                badge(ui, theme, t!("domain.provider.configured"), BadgeKind::Success);
            } else {
                badge(ui, theme, t!("domain.provider.not_configured"), BadgeKind::Warning);
            }
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.provider.hint"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
        });
        ui.add_space(4.0);
        // —— 服务商选择（UI-DNS-001：注册表驱动，20 家全部列出）——
        ui.horizontal(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.provider.label"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            let defs = kirin_desk_utils::dns_providers::dns_provider_defs();
            let sel_name = kirin_desk_utils::dns_providers::dns_provider_def(&state.provider)
                .map(|p| p.name)
                .unwrap_or(state.provider.as_str());
            let mut provider = state.provider.clone();
            egui::ComboBox::from_id_source("dns_provider_sel")
                .selected_text(sel_name)
                .width(220.0)
                .show_ui(ui, |ui| {
                    for def in defs {
                        ui.selectable_value(&mut provider, def.id.to_string(), def.name);
                    }
                });
            if provider != state.provider {
                // 切换服务商：清空凭据编辑态（不同服务商字段不同；配置签名未变，
                // sync_provider 不会回填覆盖）。
                state.provider = provider;
                state.cred_values.clear();
                state.show_secret.clear();
                state.cred_ok = false;
            }
        });
        ui.add_space(4.0);
        // —— 凭据表单（UI-DNS-002：按注册表 fields 动态渲染；UI-DNS-010：
        //    注册表未注册 → 不渲染表单，显示指引文案）——
        if provider_registry().has(&state.provider) {
            if let Some(def) = kirin_desk_utils::dns_providers::dns_provider_def(&state.provider) {
                render_cred_fields(ui, theme, state, def);
            }
        } else {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.provider.unsupported"))
                        .size(theme.small_size)
                        .color(theme.warning),
                )
                .selectable(false),
            );
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if action_button(
                ui,
                theme,
                ButtonKind::Primary,
                t!("domain.provider.save_credentials"),
                ButtonState::Enabled,
            )
            .clicked()
            {
                saved = state.save_credentials();
            }
            if !state.cred_status.is_empty() {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&state.cred_status)
                            .size(theme.small_size)
                            .color(if state.cred_ok { theme.success } else { theme.danger }),
                    )
                    .selectable(true),
                );
            }
        });
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        // —— 测试连接（DNS-MNT-003，UI-DNS-003）——
        ui.horizontal(|ui| {
            let can_test = state.configured
                && !state.test_busy
                && !worker_busy().load(Ordering::SeqCst);
            if action_button(
                ui,
                theme,
                ButtonKind::Secondary,
                t!("domain.provider.test_connection"),
                if can_test { ButtonState::Enabled } else { ButtonState::Disabled },
            )
            .clicked()
            {
                state.trigger_test();
            }
            if !state.test_status.is_empty() {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(&state.test_status)
                            .size(theme.small_size)
                            .color(if state.test_ok == Some(true) {
                                theme.success
                            } else if state.test_ok == Some(false) {
                                theme.danger
                            } else {
                                theme.fg_weak
                            }),
                    )
                    .selectable(true),
                );
            }
        });
    });
    saved
}

/// ② 域名列表卡（DNS-MNT-004，UI-DNS-005）：刷新 / 添加域名 / 列表选择。
fn show_domain_card(ui: &mut egui::Ui, theme: &Theme, state: &mut DomainPanelState) {
    crate::widgets::card(ui, theme, t!("domain.list.title"), |ui| {
        ui.horizontal(|ui| {
            let can_refresh =
                state.configured && !state.domains_busy && !worker_busy().load(Ordering::SeqCst);
            if action_button(
                ui,
                theme,
                ButtonKind::Primary,
                t!("domain.list.refresh"),
                if can_refresh {
                    ButtonState::Enabled
                } else {
                    ButtonState::Disabled
                },
            )
            .clicked()
            {
                state.trigger_refresh_domains();
            }
            ui.add_space(4.0);
            let add_w = (ui.available_width() - 130.0).max(160.0);
            ui.vertical(|ui| {
                ui.set_width(add_w);
                labeled_input(
                    ui,
                    theme,
                    t!("domain.list.add_label"),
                    &mut state.add_input,
                    t!("domain.list.add_placeholder"),
                    Validity::None,
                    None,
                    true,
                );
            });
            if action_button(
                ui,
                theme,
                ButtonKind::Secondary,
                t!("domain.list.add_button"),
                ButtonState::Enabled,
            )
            .clicked()
            {
                state.add_domain();
            }
        });
        ui.add_space(4.0);
        if state.domains.is_empty() {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.list.empty"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            return;
        }
        egui::ScrollArea::horizontal().show(ui, |ui| {
            // 先克隆列表再迭代：点击回调内可变借用 `state` 与迭代借用冲突。
            let domains = state.domains.clone();
            egui::Grid::new("domain_grid")
                .striped(true)
                .min_col_width(60.0)
                .show(ui, |ui| {
                    for d in &domains {
                        let selected = state.selected == *d;
                        if ui
                            .selectable_label(selected, d)
                            .on_hover_text(t!("domain.list.load_hint"))
                            .clicked()
                        {
                            state.selected = d.clone();
                            state.trigger_load_records();
                        }
                        ui.end_row();
                    }
                });
        });
    });
}

/// ③ 解析记录卡（DNS-MNT-005/006/007，UI-DNS-006/007）：类型筛选 + 表格 + 操作。
fn show_records_card(ui: &mut egui::Ui, theme: &Theme, state: &mut DomainPanelState) {
    crate::widgets::card(ui, theme, t!("domain.record.title"), |ui| {
        // UI-DNS-009：能力降级——记录卡顶部黄色警示（SRV/NS 不支持时）。
        if !state.caps.srv {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.provider.caps_srv_warning"))
                        .size(theme.small_size)
                        .color(theme.warning),
                )
                .selectable(false),
            );
        }
        if !state.caps.ns {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.provider.caps_ns_warning"))
                        .size(theme.small_size)
                        .color(theme.warning),
                )
                .selectable(false),
            );
        }
        if state.selected.is_empty() {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.record.select_hint"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            return;
        }
        ui.horizontal(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.record.filter_label"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            let filter_items = filter_items();
            let filter_idx = filter_items
                .iter()
                .position(|f| *f == state.filter)
                .unwrap_or(0);
            let mut selected_idx = filter_idx;
            egui::ComboBox::from_id_source("record_type_filter")
                .selected_text(filter_items[filter_idx])
                .width(110.0)
                .show_ui(ui, |ui| {
                    for (i, item) in filter_items.iter().enumerate() {
                        ui.selectable_value(&mut selected_idx, i, *item);
                    }
                });
            if selected_idx != filter_idx {
                state.filter = filter_items[selected_idx].to_string();
                state.trigger_load_records();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if action_button(
                    ui,
                    theme,
                    ButtonKind::Primary,
                    t!("domain.record.add"),
                    if state.records_busy || worker_busy().load(Ordering::SeqCst) {
                        ButtonState::Disabled
                    } else {
                        ButtonState::Enabled
                    },
                )
                .clicked()
                {
                    state.open_add_record();
                }
            });
        });
        ui.add_space(4.0);
        let records = state.visible_records();
        if records.is_empty() {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(if state.records_busy {
                        t!("domain.record.loading")
                    } else {
                        t!("domain.record.empty")
                    })
                    .size(theme.small_size)
                    .color(theme.fg_weak),
                )
                .selectable(false),
            );
            return;
        }
        egui::ScrollArea::horizontal().show(ui, |ui| {
            egui::Grid::new("record_grid")
                .striped(true)
                .spacing(egui::vec2(16.0, 6.0))
                .min_col_width(60.0)
                .show(ui, |ui| {
                    for col in [
                        t!("domain.record.table.type"),
                        t!("domain.record.table.name"),
                        t!("domain.record.table.data"),
                        "TTL",
                        t!("domain.record.table.actions"),
                    ] {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(col)
                                    .size(theme.small_size)
                                    .strong()
                                    .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                    }
                    ui.end_row();
                    for rec in &records {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(rec.rtype.as_str())
                                    .size(theme.small_size)
                                    .strong()
                                    .color(theme.fg),
                            )
                            .selectable(false),
                        );
                        // 相对名 "" = 根 → 展示 "@"。
                        let name_disp = if rec.name.is_empty() { "@" } else { rec.name.as_str() };
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(name_disp)
                                    .size(theme.mono_size)
                                    .color(theme.fg),
                            )
                            .selectable(true),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(rec.data.to_display_string())
                                    .monospace()
                                    .size(theme.mono_size)
                                    .color(theme.fg),
                            )
                            .selectable(true),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(rec.ttl.to_string())
                                    .size(theme.small_size)
                                    .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                        ui.horizontal(|ui| {
                            if ui.small_button(t!("domain.record.edit")).clicked() {
                                state.open_edit_record(rec);
                            }
                            if ui.small_button(t!("domain.record.delete")).clicked() {
                                state.trigger_delete_record(rec);
                            }
                        });
                        ui.end_row();
                    }
                });
        });
    });
}

/// 记录编辑弹窗（UI-DNS-007）：类型切换动态渲染字段；SRV 拆分
/// priority/weight/port/target，其余类型自由数据文本。
///
/// UI-DNS-009：能力降级——`caps.srv`/`caps.ns` 为 false 时类型下拉禁用
/// 对应项，并提示设备注册降级。
///
/// 借用说明：弹窗编辑的是 `state.editing` 的**本地副本**——窗口闭包内还需
/// 可变借用 `state`（`save_edit` 校验/触发任务），不能同时持有 `&mut editing`。
/// 「保存」时先把副本写回 `state.editing` 再提交。
fn show_edit_window(ui: &mut egui::Ui, theme: &Theme, state: &mut DomainPanelState) {
    let ctx = ui.ctx().clone();
    let Some(mut edit) = state.editing.clone() else { return };
    let mut closed = false;
    egui::Window::new(if edit.is_new {
        t!("domain.record.add")
    } else {
        t!("domain.record.edit")
    })
    .collapsible(false)
    .resizable(false)
    .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
    .show(&ctx, |ui| {
        let saved_style: egui::Style = ui.style().as_ref().clone();
        {
            let s = ui.style_mut();
            s.text_styles.insert(
                egui::TextStyle::Body,
                egui::FontId::new(theme.small_size, egui::FontFamily::Proportional),
            );
        }
        ui.add(
            egui::Label::new(
                egui::RichText::new(tf!("domain.edit.domain_label", edit.domain))
                    .monospace()
                    .size(theme.mono_size)
                    .color(theme.fg),
            )
            .selectable(true),
        );
        ui.add_space(6.0);
        // 类型选择（UI-DNS-009：能力缺失的类型禁用）。
        ui.horizontal(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.edit.type_label"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            let mut rtype = edit.rtype.clone();
            egui::ComboBox::from_id_source("record_type_edit")
                .selected_text(&edit.rtype)
                .width(110.0)
                .show_ui(ui, |ui| {
                    for t in RECORD_TYPES {
                        let disabled = (t == "SRV" && !state.caps.srv)
                            || (t == "NS" && !state.caps.ns);
                        ui.add_enabled_ui(!disabled, |ui| {
                            ui.selectable_value(&mut rtype, t.to_string(), t);
                        });
                    }
                });
            if rtype != edit.rtype {
                // 类型切换：保留数据字段（SRV 拆分字段独立持有）。
                edit.rtype = rtype;
            }
        });
        if !state.caps.srv {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("domain.provider.srv_degraded"))
                        .size(theme.small_size)
                        .color(theme.warning),
                )
                .selectable(false),
            );
        }
        ui.add_space(6.0);
        labeled_input(
            ui,
            theme,
            t!("domain.edit.name_label"),
            &mut edit.name,
            t!("domain.edit.name_placeholder"),
            Validity::None,
            None,
            true,
        );
        ui.add_space(6.0);
        // SRV → priority/weight/port/target 四字段；其余 → 数据文本。
        if edit.rtype == "SRV" {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    labeled_input(ui, theme, t!("domain.edit.srv_priority"), &mut edit.srv_priority, "0", Validity::None, None, true);
                });
                ui.vertical(|ui| {
                    labeled_input(ui, theme, t!("domain.edit.srv_weight"), &mut edit.srv_weight, "1", Validity::None, None, true);
                });
            });
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    labeled_input(ui, theme, t!("domain.edit.srv_port"), &mut edit.srv_port, "3389", Validity::None, None, true);
                });
                ui.vertical(|ui| {
                    labeled_input(ui, theme, t!("domain.edit.srv_target"), &mut edit.srv_target, "my-pc.example.com", Validity::None, None, true);
                });
            });
        } else {
            let placeholder = match edit.rtype.as_str() {
                "A" => t!("domain.edit.ph_a"),
                "AAAA" => t!("domain.edit.ph_aaaa"),
                "CNAME" => "target.example.com",
                "MX" => t!("domain.edit.ph_mx"),
                "NS" => "ns1.example.com",
                _ => t!("domain.edit.ph_data"),
            };
            labeled_input(
                ui,
                theme,
                t!("domain.edit.data_label"),
                &mut edit.data,
                placeholder,
                Validity::None,
                None,
                true,
            );
        }
        ui.add_space(6.0);
        labeled_input(ui, theme, t!("domain.edit.ttl_label"), &mut edit.ttl, t!("domain.record.ttl_hint"), Validity::None, None, true);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if action_button(
                ui,
                theme,
                ButtonKind::Primary,
                t!("domain.edit.save"),
                if state.records_busy || worker_busy().load(Ordering::SeqCst) {
                    ButtonState::Disabled
                } else {
                    ButtonState::Enabled
                },
            )
            .clicked()
            {
                // 副本写回 → 提交（校验失败时弹窗保持，展示状态行原因）。
                state.editing = Some(edit.clone());
                if state.save_edit() {
                    closed = true;
                }
            }
            if action_button(
                ui,
                theme,
                ButtonKind::Secondary,
                t!("common.cancel"),
                ButtonState::Enabled,
            )
            .clicked()
            {
                closed = true;
            }
        });
        *ui.style_mut() = saved_style;
    });
    if closed {
        state.editing = None;
    }
}

// ════════════════════════════════════════════════════════════════
// M8-T040 (W3-A / WBS 6.1~6.2): DDNS 维护卡
// ════════════════════════════════════════════════════════════════

/// DDNS 维护卡控制器（`KirinDeskApp` 持有；生命周期 + 表单 + 状态共享槽）。
///
/// 设计（并行计划 §3.2 / WBS 6.2）：状态槽 `Mutex<Option<DdnsStatus>>` +
/// worker 句柄，仿 DomainOp 共享槽模式；`DdnsService` 在后台线程（自带
/// tokio runtime）运行，状态经 watch channel 回填，GUI 每帧 `poll()` 一次。
/// 开关/模式切换即时生效不落盘（DDNS-UI-005），「保存」才写 `[ddns]` 段。
#[derive(Default)]
pub struct DdnsUi {
    /// 运行中的服务句柄（`update_now` / `shutdown`）。
    service: Option<std::sync::Arc<kirin_desk_dns::DdnsService>>,
    /// 状态共享槽（worker 写，UI 帧读）。
    status: std::sync::Arc<std::sync::Mutex<Option<kirin_desk_dns::DdnsStatus>>>,
    /// watch 接收端（worker 发布 → 本槽）。
    watch_rx: Option<tokio::sync::watch::Receiver<kirin_desk_dns::DdnsStatus>>,
    /// 「立即更新」结果槽（后台线程写）。
    update_slot: std::sync::Arc<std::sync::Mutex<Option<Result<(), String>>>>,
    /// 表单态（进入页面首次从配置回填；之后以用户编辑为准）。
    pub enabled: bool,
    pub interval: String,
    pub ipv4_mode: kirin_desk_dns::DdnsMode,
    pub ipv4_manual: String,
    pub ipv6_mode: kirin_desk_dns::DdnsMode,
    pub ipv6_manual: String,
    /// 表单是否已从配置回填。
    synced: bool,
    /// 「立即更新」忙碌（防并发）。
    pub busy: bool,
    /// 卡片瞬态提示（保存/更新结果）。
    pub notice: String,
    pub notice_ok: bool,
}

impl DdnsUi {
    /// 每帧调用：watch → 共享槽 + 立即更新结果 → 提示。
    pub fn poll(&mut self) {
        if let Some(rx) = &mut self.watch_rx {
            if rx.has_changed().unwrap_or(false) {
                let st = rx.borrow().clone();
                *self.status.lock().unwrap() = Some(st);
            }
        }
        if let Some(r) = self.update_slot.lock().unwrap().take() {
            self.busy = false;
            self.notice_ok = r.is_ok();
            self.notice = match r {
                Ok(()) => t!("ddns.updated").to_string(),
                Err(e) => tf!("ddns.update_failed", e),
            };
        }
    }

    /// 首次进入页面时从配置回填表单（后续编辑不覆盖）。
    fn sync_from_cfg(&mut self, cfg: &kirin_desk_utils::config::Config) {
        if self.synced {
            return;
        }
        self.synced = true;
        self.enabled = cfg.ddns.enabled;
        self.interval = cfg
            .ddns
            .interval_secs
            .unwrap_or(cfg.network.heartbeat_interval)
            .to_string();
        self.ipv4_mode = match cfg.ddns.ipv4_mode {
            kirin_desk_utils::config::DdnsMode::Auto => kirin_desk_dns::DdnsMode::Auto,
            kirin_desk_utils::config::DdnsMode::Manual => kirin_desk_dns::DdnsMode::Manual,
        };
        self.ipv4_manual = cfg.ddns.ipv4_manual.clone();
        self.ipv6_mode = match cfg.ddns.ipv6_mode {
            kirin_desk_utils::config::DdnsMode::Auto => kirin_desk_dns::DdnsMode::Auto,
            kirin_desk_utils::config::DdnsMode::Manual => kirin_desk_dns::DdnsMode::Manual,
        };
        self.ipv6_manual = cfg.ddns.ipv6_manual.clone();
    }

    /// 状态快照（无 → None；未运行 → enabled=false 初始态）。
    pub fn status_snapshot(&self) -> Option<kirin_desk_dns::DdnsStatus> {
        self.status.lock().unwrap().clone()
    }

    /// 按当前表单重启后台服务（`persist=true` 时先落盘 `[ddns]` 段）。
    /// 模式/开关切换即时生效不落盘（DDNS-UI-005）。
    fn apply_and_restart(&mut self, base: &kirin_desk_utils::config::Config, persist: bool) {
        use kirin_desk_utils::config::DdnsMode as CfgMode;
        let mut cfg = base.clone();
        cfg.ddns.enabled = self.enabled;
        cfg.ddns.interval_secs = self.interval.trim().parse::<u64>().ok();
        cfg.ddns.ipv4_mode = match self.ipv4_mode {
            kirin_desk_dns::DdnsMode::Auto => CfgMode::Auto,
            kirin_desk_dns::DdnsMode::Manual => CfgMode::Manual,
        };
        cfg.ddns.ipv4_manual = self.ipv4_manual.trim().to_string();
        cfg.ddns.ipv6_mode = match self.ipv6_mode {
            kirin_desk_dns::DdnsMode::Auto => CfgMode::Auto,
            kirin_desk_dns::DdnsMode::Manual => CfgMode::Manual,
        };
        cfg.ddns.ipv6_manual = self.ipv6_manual.trim().to_string();
        if persist {
            if let Err(e) = cfg.save() {
                self.notice_ok = false;
                self.notice = tf!("ddns.update_failed", e);
                return;
            }
            self.notice_ok = true;
            self.notice = t!("ddns.saved").to_string();
        }
        self.restart(&cfg);
    }

    /// 重启后台服务：停旧 → 按配置启新（enabled=false 只停不启）。
    fn restart(&mut self, cfg: &kirin_desk_utils::config::Config) {
        // 停旧服务（DDNS-REC-007：不删除已发布记录）。
        if let Some(svc) = self.service.take() {
            svc.shutdown();
        }
        self.watch_rx = None;
        self.status = std::sync::Arc::new(std::sync::Mutex::new(None));
        if !cfg.ddns.enabled {
            let mut st = kirin_desk_dns::DdnsStatus::initial();
            st.enabled = false;
            *self.status.lock().unwrap() = Some(st);
            return;
        }
        let Some(pubkey) = device_public_key(cfg) else {
            self.notice_ok = false;
            self.notice = tf!("ddns.update_failed", "身份加载失败（ed25519.json）");
            return;
        };
        let (watch_tx, watch_rx) =
            tokio::sync::watch::channel(kirin_desk_dns::DdnsStatus::initial());
        self.watch_rx = Some(watch_rx);
        let cfg2 = cfg.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        // 后台线程自带 runtime（与 DomainOp worker 同模式）；任务运行至 shutdown。
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("ddns worker runtime");
            rt.block_on(async move {
                let (svc, handle) = kirin_desk_dns::DdnsService::start(&cfg2, &pubkey, watch_tx);
                let _ = tx.send(svc);
                let _ = handle.await;
            });
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(svc) => {
                self.service = Some(svc);
            }
            Err(_) => {
                self.notice_ok = false;
                self.notice = tf!("ddns.update_failed", "后台服务启动超时");
            }
        }
    }

    /// 「立即更新」/「重新检测」：后台线程触发一轮全量发布（含公网 IP 重新探测）。
    pub fn trigger_update_now(&mut self) {
        if self.busy {
            return;
        }
        let Some(svc) = self.service.clone() else {
            self.notice_ok = false;
            self.notice = tf!("ddns.update_failed", "DDNS 未运行（请先开启总开关）");
            return;
        };
        self.busy = true;
        self.notice = t!("ddns.update_busy").to_string();
        let slot = self.update_slot.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("ddns update runtime");
            let r = rt.block_on(async move { svc.update_now().await.map_err(|e| e.to_string()) });
            *slot.lock().unwrap() = Some(r);
        });
    }
}

/// 本机 Ed25519 公钥（TXT DeviceMeta 用；与 CLI `load_identity` 同解析语义）。
fn device_public_key(cfg: &kirin_desk_utils::config::Config) -> Option<String> {
    use kirin_desk_core::crypto::ed25519::IdentityManager;
    let device_id = kirin_desk_utils::device::effective_device_id(&cfg.device.id);
    let path = dirs_next::home_dir()?
        .join(".kirin_desk")
        .join("identity")
        .join("ed25519.json");
    let im = IdentityManager::load_or_generate(path, &device_id).ok()?;
    Some(im.public_key_base64())
}

/// 倒计时展示（hh:mm:ss / mm:ss）。
fn format_countdown(secs: i64) -> String {
    let secs = secs.max(0);
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h:02}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

/// 时间展示（HH:MM:SS 本地时区）。
fn format_clock(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.with_timezone(&chrono::Local)
        .format("%H:%M:%S")
        .to_string()
}

/// DDNS 维护卡（DDNS-UI-001~006；位于记录管理区上方）。
/// 服务商未配置 → 整卡禁用 + 指引（DDNS-UI-006，复用 UI-DNS-004 文案体系）。
fn show_ddns_card(
    ui: &mut egui::Ui,
    theme: &Theme,
    state: &DomainPanelState,
    ddns: &mut DdnsUi,
) {
    use kirin_desk_dns::DdnsMode;
    let cfg = kirin_desk_utils::config::Config::load().unwrap_or_default();
    ddns.sync_from_cfg(&cfg);
    ddns.poll();

    crate::widgets::card(ui, theme, t!("ddns.card.title"), |ui| {
        // ── 禁用态（DDNS-UI-006） ──
        if !state.configured {
            ui.horizontal(|ui| {
                status_dot(ui, theme.danger, t!("ddns.status.disabled"));
            });
            return;
        }

        // ── 总开关（DDNS-UI-001；即时生效不落盘） ──
        ui.horizontal(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("ddns.card.desc"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut en = ddns.enabled;
                if ui.checkbox(&mut en, t!("ddns.enabled")).changed() {
                    ddns.enabled = en;
                    ddns.apply_and_restart(&cfg, false);
                }
            });
        });

        // ── 更新周期 + TTL 展示（DDNS-UI-001 / DDNS-REC-004） ──
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("ddns.interval"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            let mut te = egui::TextEdit::singleline(&mut ddns.interval)
                .desired_width(48.0)
                .hint_text("300");
            te = te.font(egui::TextStyle::Monospace);
            ui.add(te);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("ddns.interval_unit"))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
            ui.add_space(12.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(format!("{}: {}", t!("ddns.ttl"), cfg.network.dns_ttl))
                        .size(theme.small_size)
                        .color(theme.fg_weak),
                )
                .selectable(false),
            );
        });

        let st = ddns.status_snapshot();

        // ── IPv4 行（DDNS-UI-002） ──
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("ddns.ipv4"))
                        .size(theme.small_size)
                        .strong(),
                )
                .selectable(false),
            );
            if ui
                .radio_value(&mut ddns.ipv4_mode, DdnsMode::Auto, t!("ddns.mode.auto"))
                .changed()
            {
                ddns.apply_and_restart(&cfg, false);
            }
            if ui
                .radio_value(&mut ddns.ipv4_mode, DdnsMode::Manual, t!("ddns.mode.manual"))
                .changed()
            {
                ddns.apply_and_restart(&cfg, false);
            }
        });
        match ddns.ipv4_mode {
            DdnsMode::Auto => {
                // 只读展示当前公网 IP + 获取时间 + 重新检测（DDNS-IPV4-005）。
                let (current, at) = st
                    .as_ref()
                    .map(|s| (s.ipv4_current, s.ipv4_at))
                    .unwrap_or((None, None));
                ui.horizontal(|ui| {
                    let text = match current {
                        Some(ip) => tf!("ddns.auto.ipv4", ip),
                        None => t!("ddns.auto.none").to_string(),
                    };
                    ui.add(
                        egui::Label::new(egui::RichText::new(text).size(theme.small_size))
                            .selectable(false),
                    );
                    if let Some(at) = at {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(tf!("ddns.detected_at", format_clock(at)))
                                    .size(theme.small_size)
                                    .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                    }
                    if action_button(
                        ui,
                        theme,
                        ButtonKind::Secondary,
                        t!("ddns.redetect"),
                        if ddns.busy { ButtonState::Busy } else { ButtonState::Enabled },
                    )
                    .clicked()
                    {
                        ddns.trigger_update_now();
                    }
                });
            }
            DdnsMode::Manual => {
                labeled_input(
                    ui,
                    theme,
                    t!("ddns.mode.manual"),
                    &mut ddns.ipv4_manual,
                    t!("ddns.manual.hint_v4"),
                    Validity::None,
                    None,
                    true,
                );
            }
        }

        // ── IPv6 行（DDNS-UI-003） ──
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add(
                egui::Label::new(
                    egui::RichText::new(t!("ddns.ipv6"))
                        .size(theme.small_size)
                        .strong(),
                )
                .selectable(false),
            );
            if ui
                .radio_value(&mut ddns.ipv6_mode, DdnsMode::Auto, t!("ddns.mode.auto"))
                .changed()
            {
                ddns.apply_and_restart(&cfg, false);
            }
            if ui
                .radio_value(&mut ddns.ipv6_mode, DdnsMode::Manual, t!("ddns.mode.manual"))
                .changed()
            {
                ddns.apply_and_restart(&cfg, false);
            }
        });
        match ddns.ipv6_mode {
            DdnsMode::Auto => {
                let (current, at) = st
                    .as_ref()
                    .map(|s| (s.ipv6_current, s.ipv6_at))
                    .unwrap_or((None, None));
                ui.horizontal(|ui| {
                    let text = match current {
                        Some(ip) => tf!("ddns.auto.ipv6", ip),
                        None => t!("ddns.auto.none").to_string(),
                    };
                    ui.add(
                        egui::Label::new(egui::RichText::new(text).size(theme.small_size))
                            .selectable(false),
                    );
                    if let Some(at) = at {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(tf!("ddns.detected_at", format_clock(at)))
                                    .size(theme.small_size)
                                    .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                    }
                });
            }
            DdnsMode::Manual => {
                labeled_input(
                    ui,
                    theme,
                    t!("ddns.mode.manual"),
                    &mut ddns.ipv6_manual,
                    t!("ddns.manual.hint_v6"),
                    Validity::None,
                    None,
                    true,
                );
            }
        }

        // ── 自动公布预览（DDNS-UI-004） ──
        ui.add_space(6.0);
        if let Some(s) = &st {
            let pub_ok = |ok: bool| {
                if ok {
                    egui::RichText::new("✓")
                        .color(theme.success)
                        .size(theme.small_size)
                } else {
                    egui::RichText::new("✗")
                        .color(theme.danger)
                        .size(theme.small_size)
                }
            };
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(t!("ddns.publish.title"))
                            .size(theme.small_size)
                            .color(theme.fg_weak),
                    )
                    .selectable(false),
                );
                let srv = match s.published.srv_port {
                    Some(p) => tf!("ddns.publish.srv", p),
                    None => t!("ddns.publish.off").to_string(),
                };
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!("{} ", srv)).size(theme.small_size),
                    )
                    .selectable(false),
                );
                ui.add(egui::Label::new(pub_ok(s.published.srv)));
                let txt = match &s.published.txt_fingerprint {
                    Some(f) => tf!("ddns.publish.txt", f),
                    None => t!("ddns.publish.off").to_string(),
                };
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!("  {} ", txt)).size(theme.small_size),
                    )
                    .selectable(false),
                );
                ui.add(egui::Label::new(pub_ok(s.published.txt)));
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!("  {} ", t!("ddns.publish.a")))
                            .size(theme.small_size),
                    )
                    .selectable(false),
                );
                ui.add(egui::Label::new(pub_ok(s.published.a)));
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!("  {} ", t!("ddns.publish.aaaa")))
                            .size(theme.small_size),
                    )
                    .selectable(false),
                );
                ui.add(egui::Label::new(pub_ok(s.published.aaaa)));
            });
        }

        // ── 状态行（DDNS-UI-004：上次结果/原因/倒计时/暂停） ──
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let status_text = match &st {
                Some(s) if !s.enabled => t!("ddns.status.off").to_string(),
                Some(s) => {
                    if let Some(err) = &s.last_error {
                        tf!("ddns.status.last_fail", err)
                    } else if let Some(t) = s.last_update {
                        let n = [s.published.srv, s.published.txt, s.published.a, s.published.aaaa]
                            .iter()
                            .filter(|b| **b)
                            .count();
                        tf!("ddns.status.last_ok", format_clock(t), n, 4)
                    } else {
                        t!("ddns.status.never").to_string()
                    }
                }
                None if ddns.enabled => t!("ddns.update_busy").to_string(),
                None => t!("ddns.status.off").to_string(),
            };
            let ok = match &st {
                Some(s) => s.last_error.is_none(),
                None => !ddns.enabled,
            };
            status_dot(
                ui,
                if ok { theme.success } else { theme.danger },
                &status_text,
            );
        });
        // 倒计时 / 暂停提示
        if let Some(s) = &st {
            if s.enabled {
                if let Some(next) = s.next_update_at {
                    let remain = (next - chrono::Utc::now()).num_seconds();
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(tf!(
                                    "ddns.status.next",
                                    format_countdown(remain)
                                ))
                                .size(theme.small_size)
                                .color(theme.fg_weak),
                            )
                            .selectable(false),
                        );
                    });
                } else if s.last_error.is_some() {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(t!("ddns.status.paused"))
                                    .size(theme.small_size)
                                    .color(theme.danger),
                            )
                            .selectable(false),
                        );
                    });
                }
            }
        }

        // ── 立即更新 + 保存（DDNS-UI-005） ──
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if action_button(
                ui,
                theme,
                ButtonKind::Success,
                t!("ddns.update_now"),
                if ddns.busy { ButtonState::Busy } else { ButtonState::Enabled },
            )
            .clicked()
            {
                ddns.trigger_update_now();
            }
            if action_button(
                ui,
                theme,
                ButtonKind::Primary,
                t!("ddns.save"),
                ButtonState::Enabled,
            )
            .clicked()
            {
                // 校验（interval ≥60 / 手动地址合法性）后落盘 + 重启。
                let interval_ok = ddns
                    .interval
                    .trim()
                    .parse::<u64>()
                    .map(|v| v >= 60)
                    .unwrap_or(false);
                let v4_ok = ddns.ipv4_mode != DdnsMode::Manual
                    || ddns
                        .ipv4_manual
                        .trim()
                        .parse::<std::net::Ipv4Addr>()
                        .is_ok();
                let v6_ok = ddns.ipv6_mode != DdnsMode::Manual
                    || ddns
                        .ipv6_manual
                        .trim()
                        .parse::<std::net::Ipv6Addr>()
                        .is_ok();
                if !interval_ok {
                    ddns.notice_ok = false;
                    ddns.notice = t!("ddns.interval_invalid").to_string();
                } else if !v4_ok {
                    ddns.notice_ok = false;
                    ddns.notice = t!("ddns.manual_invalid_v4").to_string();
                } else if !v6_ok {
                    ddns.notice_ok = false;
                    ddns.notice = t!("ddns.manual_invalid_v6").to_string();
                } else {
                    ddns.apply_and_restart(&cfg, true);
                }
            }
        });
        if !ddns.notice.is_empty() {
            ui.horizontal(|ui| {
                status_dot(
                    ui,
                    if ddns.notice_ok { theme.success } else { theme.danger },
                    &ddns.notice,
                );
            });
        }
    });
}

