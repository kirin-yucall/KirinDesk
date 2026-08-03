//! M9-DNS000 (UI-DNS-001~009): 域名维护客户端页面（Dashboard 右侧「Domain」标签页）
//!
//! 按 `M9-DNS000_DNS域名维护客户端_总体需求.md` 实现的功能子集（服务商适配
//! M9-DNS001~020 分批开发中，当前唯一已实现客户端为 GoDaddy）：
//! - DNS-MNT-003 测试连接：`list_domains()` 最小查询，区分认证/限流/网络/未找到
//! - DNS-MNT-004 域名列表：拉取当前账号可管理域名 + 「添加域名」（本地缓存，
//!   域名注册/购买属注册局业务，Out of scope）
//! - DNS-MNT-005 记录查询：按域名 + 可选类型筛选（`get_all_records`）
//! - DNS-MNT-006/007 记录增删改：A/AAAA/CNAME/MX/TXT/SRV/NS 全类型；GoDaddy
//!   PUT 整组替换语义由适配层统一为「幂等写入目标状态」（读取现组 → 合并 → PUT）
//! - UI-DNS-004 文案泛化：未配置提示不再出现 GoDaddy 字样
//! - UI-DNS-006 记录表格：类型/名称/数据/TTL 列 + 按类型筛选
//! - UI-DNS-007 记录编辑弹窗：类型切换动态渲染字段（SRV 渲染 priority/weight/
//!   port/target）
//!
//! 状态机约定：`KirinDeskApp` 持有本页状态；所有 API 调用在后台线程执行
//! （`std::thread::spawn` + tokio runtime，与 Connect 页同模式），结果经
//! 共享槽回填，GUI 每帧 `poll()` 一次——不阻塞 UI 线程。

use eframe::egui;
use kirin_desk_dns::godaddy::{GoDaddyClient, GoDaddyError, ManagedRecord, Record, SrvData};
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

/// 一条后台任务：携带构造客户端所需的全部凭据（凭据只存在于配置层，
/// M9-DNS000 §七.3；由 worker 线程自行 `Config::load()`）。
enum DomainOp {
    /// DNS-MNT-003 测试连接（最小查询：域名列表）。
    TestConnection,
    /// DNS-MNT-004 拉取域名列表。
    ListDomains,
    /// DNS-MNT-005 拉取指定域名记录（filter="" = 全部）。
    LoadRecords {
        domain: String,
        filter: String,
    },
    /// DNS-MNT-006/007 新增或更新记录（`old_data` = 更新时定位原记录的 data；
    /// None = 新增）。GoDaddy PUT 整组替换 → 读取现组合并后写回。
    SaveRecord {
        domain: String,
        rtype: String,
        name: String,
        data: String,
        ttl: u32,
        old_data: Option<String>,
    },
    /// DNS-MNT-006 删除单条记录：读取现组 → 剔除目标 → 余组非空 PUT 写回，
    /// 余组为空走 DELETE（整组删除，GoDaddy 语义）。
    DeleteRecord {
        domain: String,
        rtype: String,
        name: String,
        data: String,
    },
}

/// 后台任务结果。
enum DomainOpResult {
    /// 测试连接：Ok = 可管理域名数。
    Test(Result<usize, String>),
    /// 域名列表。
    Domains(Result<Vec<String>, String>),
    /// 记录列表。
    Records {
        domain: String,
        result: Result<Vec<ManagedRecord>, String>,
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

/// 从配置构造 GoDaddy 客户端；返回 (provider 名称, 客户端或错误)。
///
/// 凭据来自 `Config::load()`（Settings → DNS 保存后生效，UI-DNS-004 泛化
/// 文案在此统一：不再出现 GoDaddy 字样）。provider 非 godaddy 时返回明确提示
/// （M9-DNS001~020 服务商适配分批开发中，当前仅 GoDaddy 有客户端实现）。
fn client_from_config() -> Result<(String, GoDaddyClient), String> {
    let cfg = kirin_desk_utils::config::Config::load()
        .map_err(|e| tf!("domain.error.config_load", e))?;
    let provider = cfg.dns.provider.clone();
    let provider_name = kirin_desk_utils::dns_providers::dns_provider_def(&provider)
        .map(|p| p.name.to_string())
        .unwrap_or_else(|| provider.clone());
    if provider != "godaddy" {
        return Err(tf!(
            "domain.error.provider_unsupported",
            provider_name
        ));
    }
    if cfg.godaddy.api_key.trim().is_empty() || cfg.godaddy.api_secret.trim().is_empty() {
        return Err(t!("domain.error.not_configured").to_string());
    }
    let client = GoDaddyClient::try_new(
        cfg.godaddy.api_key.trim(),
        cfg.godaddy.api_secret.trim(),
        cfg.godaddy.api_url.trim(),
    )
    .map_err(|e| tf!("domain.error.client_init", e))?;
    Ok((provider_name, client))
}

/// 统一错误文案（DNS-MNT-011：上层不感知厂商原始细节，分类到限流/认证/
/// 未找到/参数/网络/服务端）。
fn fmt_godaddy_error(e: &GoDaddyError) -> String {
    match e {
        GoDaddyError::RateLimited { .. } => t!("domain.error.rate_limited").to_string(),
        GoDaddyError::InvalidParameters { body } => {
            tf!("domain.error.invalid_params", truncate(body))
        }
        GoDaddyError::ClientError { status, body } if *status == 401 || *status == 403 => {
            tf!("domain.error.auth_failed", status)
        }
        GoDaddyError::ClientError { status, body } => {
            tf!("domain.error.client_error", status, truncate(body))
        }
        GoDaddyError::ServerError { status, .. } => {
            tf!("domain.error.server_error", status)
        }
        GoDaddyError::Network(_) => t!("domain.error.network").to_string(),
        GoDaddyError::Configuration(msg) => tf!("domain.error.config", msg),
        GoDaddyError::ResponseTooLarge { .. } => t!("domain.error.response_too_large").to_string(),
        GoDaddyError::Json(_) => t!("domain.error.json").to_string(),
        GoDaddyError::NotFound { .. } => t!("domain.error.not_found").to_string(),
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
        // 客户端构造失败（未配置/未知服务商）→ 直接回错误。
        let (_, client) = match client_from_config() {
            Ok(c) => c,
            Err(e) => {
                return match op {
                    DomainOp::TestConnection => DomainOpResult::Test(Err(e)),
                    DomainOp::ListDomains => DomainOpResult::Domains(Err(e)),
                    DomainOp::LoadRecords { domain, .. } => {
                        DomainOpResult::Records { domain, result: Err(e) }
                    }
                    _ => DomainOpResult::Write(Err(e)),
                };
            }
        };
        match op {
            DomainOp::TestConnection => match client.list_domains().await {
                Ok(domains) => DomainOpResult::Test(Ok(domains.len())),
                Err(e) => DomainOpResult::Test(Err(fmt_godaddy_error(&e))),
            },
            DomainOp::ListDomains => match client.list_domains().await {
                Ok(domains) => DomainOpResult::Domains(Ok(domains)),
                Err(e) => DomainOpResult::Domains(Err(fmt_godaddy_error(&e))),
            },
            DomainOp::LoadRecords { domain, filter } => {
                let filter = if filter.is_empty() { None } else { Some(filter) };
                match client.get_all_records(&domain, filter.as_deref()).await {
                    Ok(records) => DomainOpResult::Records {
                        domain,
                        result: Ok(records),
                    },
                    Err(e) => DomainOpResult::Records {
                        domain,
                        result: Err(fmt_godaddy_error(&e)),
                    },
                }
            }
            DomainOp::SaveRecord {
                domain,
                rtype,
                name,
                data,
                ttl,
                old_data,
            } => {
                let result = save_record(&client, &domain, &rtype, &name, &data, ttl, old_data)
                    .await;
                DomainOpResult::Write(result)
            }
            DomainOp::DeleteRecord {
                domain,
                rtype,
                name,
                data,
            } => {
                let result = delete_record(&client, &domain, &rtype, &name, &data).await;
                DomainOpResult::Write(result)
            }
        }
    })
}

/// DNS-MNT-006/007：幂等写入目标状态——读取 (type, name) 现组 → 合并新记录
/// （或替换 `old_data` 定位的原记录）→ PUT 整组写回。
async fn save_record(
    client: &GoDaddyClient,
    domain: &str,
    rtype: &str,
    name: &str,
    data: &str,
    ttl: u32,
    old_data: Option<String>,
) -> Result<(), String> {
    let mut group = match client.get_records(domain, rtype, name).await {
        Ok(g) => g,
        // GoDaddy 对无记录的 (type, name) 返回 404——视为空组。
        Err(GoDaddyError::NotFound { .. }) => Vec::new(),
        Err(e) => return Err(fmt_godaddy_error(&e)),
    };
    let new_record = Record {
        data: data.to_string(),
        ttl,
    };
    match old_data {
        // 更新：替换 data 与目标相同的原记录（找不到则追加，幂等）。
        Some(old) => {
            if let Some(pos) = group.iter().position(|r| r.data == old) {
                group[pos] = new_record;
            } else {
                group.push(new_record);
            }
        }
        // 新增：同 (type, name) 已存在相同 data → 跳过（幂等去重）。
        None => {
            if !group.iter().any(|r| r.data == data) {
                group.push(new_record);
            }
        }
    }
    client
        .put_records(domain, rtype, name, &group)
        .await
        .map_err(|e| fmt_godaddy_error(&e))
}

/// DNS-MNT-006：删除单条记录——现组剔除目标；余组非空 PUT 写回，空组走
/// DELETE（GoDaddy 整组删除语义）。
async fn delete_record(
    client: &GoDaddyClient,
    domain: &str,
    rtype: &str,
    name: &str,
    data: &str,
) -> Result<(), String> {
    let mut group = match client.get_records(domain, rtype, name).await {
        Ok(g) => g,
        Err(GoDaddyError::NotFound { .. }) => return Ok(()),
        Err(e) => return Err(fmt_godaddy_error(&e)),
    };
    group.retain(|r| r.data != data);
    if group.is_empty() {
        client
            .delete_record(domain, rtype, name)
            .await
            .map_err(|e| fmt_godaddy_error(&e))
    } else {
        client
            .put_records(domain, rtype, name, &group)
            .await
            .map_err(|e| fmt_godaddy_error(&e))
    }
}

// ════════════════════════════════════════════════════════════════
// 页面状态
// ════════════════════════════════════════════════════════════════

/// 记录编辑弹窗状态。
#[derive(Default, Clone)]
pub struct RecordEditState {
    pub domain: String,
    /// true = 新增；false = 更新（`old_data` 定位原记录）。
    pub is_new: bool,
    pub old_data: String,
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

/// 域名维护页面状态（KirinDeskApp 持有；GUI 帧内 `poll()` 回填后台结果）。
#[derive(Default)]
pub struct DomainPanelState {
    /// 配置中已保存的服务商 id（每次进入页面刷新展示）。
    pub provider_id: String,
    /// 服务商展示名。
    pub provider_name: String,
    /// 凭据是否已配置。
    pub configured: bool,

    // —— 服务商选择与凭据（UI-DNS-001/002；M9-DNS022 迁自 Settings → DNS 组）——
    /// ComboBox 当前选中服务商 id。
    pub provider: String,
    /// 凭据表单字段（GoDaddy：Domain / API Key / API Secret 密文）。
    pub api_key: String,
    pub api_secret: String,
    pub domain: String,
    pub show_secret_api: bool,
    /// 保存凭据结果反馈。
    pub cred_status: String,
    pub cred_ok: bool,
    /// 上次回填的配置签名（(provider, api_key, api_secret, domain)）——配置
    /// 变化才回填表单，避免每帧覆盖正在编辑的输入。
    cred_sig: Option<(String, String, String, String)>,

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
    pub records: Vec<ManagedRecord>,
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
        // 凭据/服务商仅在配置签名变化时回填表单（防覆盖正在编辑的输入）。
        let sig = (
            cfg.dns.provider.clone(),
            cfg.godaddy.api_key.clone(),
            cfg.godaddy.api_secret.clone(),
            cfg.godaddy.domain.clone(),
        );
        if self.cred_sig.as_ref() != Some(&sig) {
            self.provider = cfg.dns.provider.clone();
            self.api_key = cfg.godaddy.api_key.clone();
            self.api_secret = cfg.godaddy.api_secret.clone();
            self.domain = cfg.godaddy.domain.clone();
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
        self.configured = !cfg.godaddy.api_key.trim().is_empty()
            && !cfg.godaddy.api_secret.trim().is_empty();
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
        let api_key = self.api_key.trim().to_string();
        let api_secret = self.api_secret.trim().to_string();
        let domain = self.domain.trim().to_string();
        if api_key.is_empty() || api_secret.is_empty() {
            self.cred_ok = false;
            self.cred_status = t!("domain.cred.key_empty").to_string();
            return false;
        }
        if !domain.is_empty() && !kirin_desk_dns::validate::validate_hostname(&domain) {
            self.cred_ok = false;
            self.cred_status = t!("domain.cred.domain_invalid").to_string();
            return false;
        }
        let Ok(mut cfg) = kirin_desk_utils::config::Config::load() else {
            self.cred_ok = false;
            self.cred_status = t!("domain.cred.config_load_failed").to_string();
            return false;
        };
        cfg.dns.provider = provider.clone();
        cfg.godaddy.api_key = api_key.clone();
        cfg.godaddy.api_secret = api_secret.clone();
        cfg.godaddy.domain = domain.clone();
        match cfg.save() {
            Ok(()) => {
                // 签名同步为刚保存值，避免下一帧 sync_provider 覆盖。
                self.cred_sig = Some((provider.clone(), api_key, api_secret, domain));
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
            DomainOpResult::Test(Ok(n)) => {
                self.test_ok = Some(true);
                self.test_status = tf!("domain.test.ok", n);
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
                            // 稳定排序：类型 → 名称 → 数据。
                            records.sort_by(|a, b| {
                                (&a.rtype, &a.name, &a.data).cmp(&(&b.rtype, &b.name, &b.data))
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

    /// DNS-MNT-005 加载当前选中域名记录（filter 沿用面板筛选）。
    pub fn trigger_load_records(&mut self) {
        if self.selected.is_empty() || self.records_busy || worker_busy().load(Ordering::SeqCst) {
            return;
        }
        self.records_busy = true;
        self.status = tf!("domain.status.loading_records", self.selected);
        self.status_ok = true;
        launch_worker(DomainOp::LoadRecords {
            domain: self.selected.clone(),
            filter: self.filter.clone(),
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

    /// 打开编辑弹窗（SRV 自动拆分字段）。
    pub fn open_edit_record(&mut self, rec: &ManagedRecord) {
        let mut state = RecordEditState {
            domain: self.selected.clone(),
            is_new: false,
            old_data: rec.data.clone(),
            rtype: rec.rtype.clone(),
            name: rec.name.clone(),
            ttl: rec.ttl.to_string(),
            ..Default::default()
        };
        if rec.rtype == "SRV" {
            if let Some(srv) = SrvData::from_string(&rec.data) {
                state.srv_priority = srv.priority.to_string();
                state.srv_weight = srv.weight.to_string();
                state.srv_port = srv.port.to_string();
                state.srv_target = srv.target;
            } else {
                // 无法拆分的 SRV 原文 → 退化为自由文本。
                state.data = rec.data.clone();
            }
        } else {
            state.data = rec.data.clone();
        }
        self.editing = Some(state);
    }

    /// 删除单条记录。
    pub fn trigger_delete_record(&mut self, rec: &ManagedRecord) {
        if self.records_busy || worker_busy().load(Ordering::SeqCst) {
            return;
        }
        self.records_busy = true;
        self.status_ok = true;
        self.status = tf!("domain.status.deleting", rec.rtype, rec.name);
        launch_worker(DomainOp::DeleteRecord {
            domain: self.selected.clone(),
            rtype: rec.rtype.clone(),
            name: rec.name.clone(),
            data: rec.data.clone(),
        });
    }

    /// 弹窗「保存」：校验 → 组装（SRV 拼 priority/weight/port/target）→ 后台写。
    pub fn save_edit(&mut self) -> bool {
        let Some(edit) = self.editing.take() else {
            return false;
        };
        // —— 校验 ——
        let rtype = edit.rtype.clone();
        let name = edit.name.trim().to_string();
        let root = name == "@" || name == "*";
        let valid_name = root
            || (!name.is_empty() && kirin_desk_dns::validate::validate_record_name(&name));
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
        let data = if rtype == "SRV" {
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
            SrvData {
                priority,
                weight,
                port,
                target,
            }
            .to_string()
        } else {
            let data = edit.data.trim().to_string();
            if data.is_empty() {
                self.status_ok = false;
                self.status = t!("domain.edit.data_empty").to_string();
                return false;
            }
            data
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
            old_data: if edit.is_new { None } else { Some(edit.old_data.clone()) },
        });
        true
    }

    /// 按筛选/类型过滤后的记录视图（返回自有副本——渲染闭包内需可变借用
    /// `state` 触发操作，不能持有对 `self.records` 的借用）。
    pub fn visible_records(&self) -> Vec<ManagedRecord> {
        self.records
            .iter()
            .filter(|r| self.filter.is_empty() || r.rtype == self.filter)
            .cloned()
            .collect()
    }
}

// ════════════════════════════════════════════════════════════════
// 页面渲染
// ════════════════════════════════════════════════════════════════

/// Domain 标签页主入口（lib.rs `show_domain` 调用）。
///
/// 返回 `true` = 本帧保存了服务商凭据（调用方据此同步 App 内存凭据，
/// Connect 页 / 状态栏即时生效）。
pub fn show_domain_page(ui: &mut egui::Ui, theme: &Theme, state: &mut DomainPanelState) -> bool {
    state.poll();
    state.sync_provider();
    let mut saved = false;
    ui.heading(t!("domain.title"));
    ui.separator();
    egui::ScrollArea::vertical().show(ui, |ui| {
        saved |= show_provider_card(ui, theme, state);
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
/// （label/mono/secret 由定义驱动），值映射到面板状态；未映射的字段
/// （未来服务商）暂不渲染，避免 UI 越界。GoDaddy → Domain / API Key /
/// API Secret（密文 + 👁，M15-T008 模式）。
fn render_cred_fields(
    ui: &mut egui::Ui,
    theme: &Theme,
    state: &mut DomainPanelState,
    def: &kirin_desk_utils::dns_providers::DnsProviderDef,
) {
    for field in def.fields {
        match (def.id, field.key) {
            ("godaddy", "domain") => {
                labeled_input(
                    ui,
                    theme,
                    field.label,
                    &mut state.domain,
                    "example.com",
                    Validity::None,
                    None,
                    field.mono,
                );
            }
            ("godaddy", "api_key") => {
                labeled_input(
                    ui,
                    theme,
                    field.label,
                    &mut state.api_key,
                    "required",
                    Validity::None,
                    None,
                    field.mono,
                );
            }
            ("godaddy", "api_secret") => {
                labeled_input(
                    ui,
                    theme,
                    field.label,
                    &mut state.api_secret,
                    "required",
                    Validity::None,
                    Some(&mut state.show_secret_api),
                    field.mono,
                );
            }
            _ => {}
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
            badge(ui, theme, &state.provider_name, BadgeKind::Info);
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
        // —— 服务商选择（UI-DNS-001：注册表驱动，当前仅 GoDaddy）——
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
                .unwrap_or("GoDaddy");
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
                // 切换服务商：清空凭据编辑态（不同服务商凭据字段不同）。
                state.provider = provider;
                state.api_key.clear();
                state.api_secret.clear();
                state.domain.clear();
                state.cred_ok = false;
                state.cred_status = t!("domain.provider.switched").to_string();
            }
        });
        ui.add_space(4.0);
        // —— 凭据表单（UI-DNS-002：按注册表 fields 动态渲染）——
        if let Some(def) = kirin_desk_utils::dns_providers::dns_provider_def(&state.provider) {
            render_cred_fields(ui, theme, state, def);
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
                                egui::RichText::new(&rec.rtype)
                                    .size(theme.small_size)
                                    .strong()
                                    .color(theme.fg),
                            )
                            .selectable(false),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&rec.name)
                                    .size(theme.mono_size)
                                    .color(theme.fg),
                            )
                            .selectable(true),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&rec.data)
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
        // 类型选择。
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
                        ui.selectable_value(&mut rtype, t.to_string(), t);
                    }
                });
            if rtype != edit.rtype {
                // 类型切换：保留数据字段（SRV 拆分字段独立持有）。
                edit.rtype = rtype;
            }
        });
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
