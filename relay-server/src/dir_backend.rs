//! （[`kirin_desk_relay::server::DirectoryHandler`] v2 实现）。
//!
//! 客户端 ↔ 选中 relay 的 `device_directory` v2 表 CRUD（设计 §2.2，relay
//! 面 1.3.0）——**在役五帧**：
//! - `DirList`/`DirListResp`：查询（scope v2 语义 All/Local/Peer(fp=来源
//!   pushed 行）+ `filter_device` 尾部追加；`refresh` = 运维重推触发面
//! - `DirUpsert`：增 + 改同帧（source=manual；**服务端执法**：device_id
//!   == 会话登录身份〔不符 = `auth_failed` + 会话判死口径〕+ 双 FQDN
//!   校验 + **单 IP 注册配额**（§4，事务内）；服务器 Ed25519 自签写时验）；
//! - `DirDelete`：本中继自持行 (device_id, target_domain) 删除；pushed-only
//!   行 = `not_found`（**不跨源删**）；
//! - `DirError`：六码重冻（`quota_exceeded` 新；`limit_exceeded` 废）。
//!
//! 0x90~0x94（v1 Peer* 面）= 废帧保留不复用：server.rs 分发层结构校验 +
//! 残留，设计 §7）。
//!
//! **写操作静默成功**（无 ack 帧）：客户端以「超时内无 `DirError` = 成功」
//! 口径回显；错误一律显式 `DirError{code,msg}`（红线⑤：错误必显式，
//! 不静默）。
//!
//! 校验纯函数（本模块导出，单测钉死；interconnect 复用）：
//! - [`normalize_device_id`]：指纹形态归一 canonical 79 字符；**短码不可
//!   离线展开 = 拒绝**（fail-closed 不猜，protocol.rs 同口径）；自定义
//!   分隔符空白路径不受影响，冻结口径变更于此重新冻结申报）；
//! - [`is_pure_fqdn`]：纯 FQDN（不含 `:port`——端口恒走 SRV）；
//! - [`quota_key_for_ip`]：单 IP 配额键归一（§4.4 固定语义：IPv4 = 原址
//!   /IPv4-mapped → IPv4 /IPv6 = /64 聚合前缀）。
//!
//! 签名覆盖域：
//! - 本域自签（manual 行）沿用 v1 冻结格式 [`entry_sig_message`]：
//!   `device_id || 0x1F || domain || 0x1F || updated_at(十进制串) || 0x1F || source || 0x1F || ""`；
//! - pushed 行 = A 推送时逐条新签 `entry_sig_message_v2`（interconnect，
//! `sig_verified` 可观测值 v2 = 全来源恒 true（写时验口径：manual/

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use ed25519_dalek::{Signature, SigningKey, Signer, Verifier, VerifyingKey};
use kirin_desk_relay::audit::{AuditSink, TunnelAuditEvent};
use kirin_desk_relay::protocol::{
    decode_extension, encode_extension, DirDelete, DirEntry, DirError, DirErrorCode, DirList,
    DirListResp, DirScope, DirUpsert, TYPE_DIR_DELETE, TYPE_DIR_ERROR, TYPE_DIR_LIST,
    TYPE_DIR_LIST_RESP, TYPE_DIR_UPSERT,
};
use kirin_desk_relay::server::{DirectoryFrameOutcome, DirectoryHandler};

use crate::dir_store::{now_unix_secs, DirListScope, DirStore};

/// 0 = 不限 + 启动 WARN）。
pub const DEFAULT_DIR_IP_QUOTA: usize = 500;

/// 超频提交 = 忽略 refresh 臂（**列表照常应答**，查询面零弱化），推送
/// 触发面按 60s/IP 收敛——绕过 outbox 退避调度的全量重推风暴封堵。
pub(crate) const REFRESH_MIN_INTERVAL_SECS: u64 = 60;
/// 满表先剔间隔外陈旧项、仍满逐出最旧一桶，表体积零无界增长）。
pub(crate) const REFRESH_TABLE_CAP: usize = 4096;

/// 桶容量 [`DIRLIST_BURST`]、回填 1 token/秒（[`DIRLIST_REFILL_PER_SEC`]）。
/// list throttled` 审计行（fail-closed：查询面资源收敛，不再零成本无限
/// 拉取）。取值依据：客户端「写后回读双保险」每次写操作随附一次 List、
/// UI 发现列表手动刷新偶发连查——突发 6 + 持续 1/s 覆盖全部合法形态，
/// 洪泛拉表（百次/秒级）进节流臂。
pub(crate) const DIRLIST_BURST: u32 = 6;
pub(crate) const DIRLIST_REFILL_PER_SEC: u32 = 1;
/// 满表先剔间隔外陈旧项、仍满逐出最旧一桶，表体积零无界增长）。
pub(crate) const DIRLIST_TABLE_CAP: usize = 4096;

/// `is_pure_fqdn` 字节口径一致）。**上限值冻结申报**：512B。超限 =
/// 显式 [`DirErrorCode::QuotaExceeded`] 拒写（wire 六码冻结零改：同类位
/// 「只拒不挤」口径）。note 仅落库不回传（DirEntry 不含 note），风险纯
/// 存储面：封堵单行膨胀（盘满/锁持有延长/列表放大）。
pub const MAX_DIR_NOTE_BYTES: usize = 512;

/// （`device_id, domain, target_domain, note, ix_token`）先试，失败回退
/// 旧 4 字段结构（`ix_token` = 空 = 不更新转发凭证缓存）。旧 home 收新
/// 客户端带 token 帧 = 解码失败走既有 DirError 路径（混合版本自限制，
/// 双向零半信）。extension decode 先例 = 0x90 废帧结构校验面。
pub(crate) fn decode_dir_upsert_flex(payload: &[u8]) -> Option<DirUpsert> {
    if let Ok(new5) = bincode::deserialize::<DirUpsert>(payload) {
        return Some(new5);
    }
    #[derive(serde::Deserialize)]
    struct DirUpsertV2Wire {
        device_id: String,
        domain: String,
        target_domain: String,
        #[serde(default)]
        note: Option<String>,
    }
    bincode::deserialize::<DirUpsertV2Wire>(payload).map(|old4| DirUpsert {
        device_id: old4.device_id,
        domain: old4.domain,
        target_domain: old4.target_domain,
        note: old4.note,
        ix_token: String::new(),
    })
    .ok()
}

/// 目录信令后端 v2（sqlite 存储 + 服务器密钥自签 + 单 IP 配额 + 审计）。
pub struct DirBackend {
    store: Arc<DirStore>,
    server_key: Arc<SigningKey>,
    audit: Arc<dyn AuditSink>,
    /// 执法点 = [`Self::handle_dir_upsert`] 写路径事务内（store 侧）。
    ip_quota: usize,
    /// 手动同源）：`trigger_all` = `DirList{refresh:true}` 异步一轮全量
    /// 重推（T3）；`trigger_target` = 变更即推（T1/T2，异步非阻塞）。
    push_trigger: Option<Arc<dyn crate::interconnect::PushTrigger>>,
    /// 启用〔target ≠ 自域 = 同事务 outbox + 变更即推〕，`None` = 未挂
    /// 互联面〔测试/库内独立形态〕）。
    own_domain: Option<String>,
    /// （`refresh_allow` 执法；有界 [`REFRESH_TABLE_CAP`] 桶 + 惰性清理）。
    refresh_seen: Arc<tokio::sync::Mutex<std::collections::HashMap<IpAddr, std::time::Instant>>>,
    /// 连接）查询节流表（`list_allow` 执法；令牌桶 [`ListBucket`]；有界
    list_seen: Arc<tokio::sync::Mutex<std::collections::HashMap<SocketAddr, ListBucket>>>,
}

/// [`DIRLIST_BURST`]；`last` = 上次裁决时刻，供按 [`DIRLIST_REFILL_PER_SEC`]
/// 线性回填）。
#[derive(Clone, Copy)]
struct ListBucket {
    tokens: f64,
    last: std::time::Instant,
}

impl std::fmt::Debug for DirBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirBackend")
            .field("store", &self.store)
            .field("ip_quota", &self.ip_quota)
            .field("audit", &self.audit)
            .field("push_trigger", &self.push_trigger.is_some())
            .field("own_domain", &self.own_domain)
            .finish()
    }
}

impl DirBackend {
    pub fn new(
        store: Arc<DirStore>,
        server_key: Arc<SigningKey>,
        audit: Arc<dyn AuditSink>,
        ip_quota: usize,
    ) -> Self {
        Self {
            store,
            server_key,
            audit,
            ip_quota,
            push_trigger: None,
            own_domain: None,
            refresh_seen: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            list_seen: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// 挂推送触发源（通常 = `Arc<InterconnectService>`；周期与手动同源；
    pub fn with_push_trigger<T: crate::interconnect::PushTrigger + 'static>(
        mut self,
        t: Arc<T>,
    ) -> Self {
        self.push_trigger = Some(t); // Arc<T> → Arc<dyn PushTrigger> 非泛化强转
        self
    }

    /// 本 relay 自身 FQDN（推送钩子口径：target ≠ 自域 = 同事务 outbox +
    pub fn with_own_domain(mut self, domain: impl Into<String>) -> Self {
        self.own_domain = Some(domain.into());
        self
    }

    /// 目录 epoch（`DirListResp` 携带；本地成功写入 +1）。
    pub async fn epoch(&self) -> u64 {
        self.store.get_epoch().await.unwrap_or(0)
    }

    /// 本域条目自签（sig 覆盖域见模块头冻结格式；manual 行）。
    pub fn sign_local_entry(
        &self,
        device_id: &str,
        domain: &str,
        updated_at: u64,
        source: &str,
    ) -> Vec<u8> {
        let msg = entry_sig_message(device_id, domain, updated_at, source, "");
        self.server_key.sign(msg.as_bytes()).to_bytes().to_vec()
    }

    fn dir_error(
        &self,
        client: SocketAddr,
        device_id: &str,
        code: DirErrorCode,
        msg: impl Into<String>,
    ) -> Option<Vec<u8>> {
        let msg = msg.into();
        self.audit.record(TunnelAuditEvent::DirWriteRejected {
            client,
            device_id: device_id.to_string(),
            code: code.as_str().to_string(),
            detail: msg.clone(),
        });
        encode_extension(
            TYPE_DIR_ERROR,
            &DirError {
                code,
                msg,
            },
        )
        .ok()
    }

    // ── 逐帧处理（server.rs 已做结构校验；此处独立再解码 = 纵深防御） ──

    /// `true` = 本次 refresh 触发放行（登记时间戳）；`false` = 间隔内超频
    /// （**不登记刷新**，调用方忽略 refresh 臂——列表照常应答）。有界表：
    /// 满 [`REFRESH_TABLE_CAP`] 桶 → 惰性清理（先剔间隔外陈旧项）→ 仍满
    /// = 逐出最旧一桶（保界，攻击面零增长）。
    async fn refresh_allow(&self, ip: IpAddr, now: std::time::Instant) -> bool {
        let win = std::time::Duration::from_secs(REFRESH_MIN_INTERVAL_SECS);
        let mut tab = self.refresh_seen.lock().await;
        if let Some(t) = tab.get(&ip) {
            if now.duration_since(*t) < win {
                return false;
            }
        }
        if tab.len() >= REFRESH_TABLE_CAP {
            tab.retain(|_, t| now.duration_since(*t) >= win);
            if tab.len() >= REFRESH_TABLE_CAP {
                if let Some(oldest) = tab.iter().min_by_key(|(_, t)| *t).map(|(k, _)| *k) {
                    tab.remove(&oldest);
                }
            }
        }
        tab.insert(ip, now);
        true
    }

    /// 直覆盖）。令牌桶：容量 [`DIRLIST_BURST`]、按 [`DIRLIST_REFILL_PER_SEC`]
    /// 线性回填——`true` = 放行（扣 1 token）；`false` = 桶空超限（调用方
    /// 以显式 `Busy` 错误帧应答）。有界表：满 [`DIRLIST_TABLE_CAP`] 桶且为
    /// 新会话 → 惰性清理（先剔满桶空闲会话）→ 仍满 = 逐出最旧一桶（保界，
    /// 攻击面零增长）。
    async fn list_allow(&self, client: SocketAddr, now: std::time::Instant) -> bool {
        const BURST: f64 = DIRLIST_BURST as f64;
        let rate = f64::from(DIRLIST_REFILL_PER_SEC);
        let mut tab = self.list_seen.lock().await;
        let mut b = tab
            .get(&client)
            .copied()
            .unwrap_or(ListBucket { tokens: BURST, last: now });
        let refill = now.duration_since(b.last).as_secs_f64() * rate;
        b.tokens = (b.tokens + refill).min(BURST);
        b.last = now;
        let ok = b.tokens >= 1.0;
        if ok {
            b.tokens -= 1.0;
        }
        if tab.len() >= DIRLIST_TABLE_CAP && !tab.contains_key(&client) {
            tab.retain(|_, b| b.tokens < BURST); // 剔满桶空闲会话（久未查询）
            if tab.len() >= DIRLIST_TABLE_CAP {
                if let Some(oldest) = tab.iter().min_by_key(|(_, b)| b.last).map(|(k, _)| *k) {
                    tab.remove(&oldest);
                }
            }
        }
        tab.insert(client, b);
        ok
    }

    async fn handle_dir_list(&self, client: SocketAddr, payload: &[u8]) -> Result<DirectoryFrameOutcome, ()> {
        let req = decode_extension::<DirList>(TYPE_DIR_LIST, payload, TYPE_DIR_LIST).map_err(|_| ())?;
        // 每会话查询限速 + 全表查询审计升级）。超限 = 显式 `Busy` 错误帧
        // 整帧拒——含 refresh 臂，超限连接不触发任何推送面）。
        if !self.list_allow(client, std::time::Instant::now()).await {
            tracing::debug!(
                "DirList: throttled (per-session token bucket burst={DIRLIST_BURST} refill={DIRLIST_REFILL_PER_SEC}/s)"
            );
            self.audit
                .record(TunnelAuditEvent::DirListThrottled { client });
            return Ok(DirectoryFrameOutcome::Reply(
                self.dir_error(
                    client,
                    "",
                    DirErrorCode::Busy,
                    format!(
                        "list rate limited (per-session token bucket burst={DIRLIST_BURST}, refill={DIRLIST_REFILL_PER_SEC}/s)"
                    ),
                )
                .unwrap_or_default(),
            ));
        }
        // 阻塞：列表应答不被对端可达性拖慢；失败口径 = 引擎侧
        // `push failed` 审计 + outbox 同态重试）。
        if req.refresh {
            // refresh 臂，列表照常应答 + debug 行 + 专用审计行——推送风暴
            // 面收敛，查询面零弱化，fail-closed 不弱化口径 = 节流只挡触发
            // 不拒列表）。
            if self.refresh_allow(client.ip(), std::time::Instant::now()).await {
                match &self.push_trigger {
                    Some(t) => {
                        let t = Arc::clone(t);
                        tokio::spawn(async move {
                            let ok = t.trigger_all().await;
                            tracing::debug!("DirList refresh: push cycle fired ({ok} targets ok)");
                        });
                    }
                    None => {
                        tracing::debug!("DirList refresh: no interconnect attached, plain list");
                    }
                }
            } else {
                tracing::debug!(
                    "DirList refresh: throttled (per-ip min {REFRESH_MIN_INTERVAL_SECS}s), plain list"
                );
                self.audit
                    .record(TunnelAuditEvent::DirRefreshThrottled { client });
            }
        }
        let scope = match &req.scope {
            DirScope::All => DirListScope::All,
            DirScope::Local => DirListScope::Local,
            DirScope::Peer(fp) => DirListScope::Peer(fp.clone()),
        };
        let rows = match self.store.list(scope, req.filter_device.as_deref()).await {
            Ok(rows) => rows,
            Err(e) => {
                return Ok(DirectoryFrameOutcome::Reply(
                    self.dir_error(
                        client,
                        "",
                        DirErrorCode::Busy,
                        format!("list failed: {e}"),
                    )
                    .unwrap_or_default(),
                ))
            }
        };
        // `filter_device` 外的整表拉取恒留痕——设备名单 = ZD-01 接管链
        // 「选靶第一环」，可见性面升级为每拉必记，`rows` = 应答条目数）。
        if matches!(req.scope, DirScope::All) && req.filter_device.is_none() {
            self.audit
                .record(TunnelAuditEvent::DirListAllQueried { client, rows: rows.len() });
        }
        // 可观测值 = **全来源恒 true**（manual/registered/pushed 全部
        // 验签通过后落库——pushed = A 推送时逐条新签、B 应用时双验；
        // 热路径零验签）。
        let entries = rows
            .iter()
            .map(|r| DirEntry {
                device_id: r.device_id.clone(),
                device_domain: r.device_domain.clone(),
                target_domain: r.target_domain.clone(),
                source: r.source.clone(),
                source_fp: r.source_fp.clone().unwrap_or_default(),
                updated_at: r.updated_at,
                sig_verified: true,
            })
            .collect();
        let epoch = self.epoch().await;
        let resp = DirListResp {
            entries,
            server_ts: now_unix_secs(),
            epoch,
        };
        encode_extension(TYPE_DIR_LIST_RESP, &resp)
            .map(DirectoryFrameOutcome::Reply)
            .map_err(|e| {
                tracing::error!("DirListResp encode failed: {e}");
            })
    }

    async fn handle_dir_upsert(
        &self,
        client: SocketAddr,
        session_device_id: Option<String>,
        payload: &[u8],
    ) -> Result<DirectoryFrameOutcome, ()> {
        // （token = 空）——旧客户端零破坏，双向零半信。
        let req = decode_dir_upsert_flex(payload).ok_or(())?;
        let device_id = match normalize_device_id(&req.device_id) {
            Ok(v) => v,
            Err(code) => {
                return Ok(DirectoryFrameOutcome::Reply(
                    self.dir_error(
                        client,
                        &req.device_id,
                        code,
                        format!("device_id invalid: {}", esc(&req.device_id)),
                    )
                    .unwrap_or_default(),
                ))
            }
        };
        // 身份执法（设计 §5 点位 8）：device_id 必须 == 会话登录身份
        // （不符 = auth_failed + 会话判死口径——先应答后判死）。
        match &session_device_id {
            Some(id) if id == &device_id => {}
            _ => {
                return Ok(DirectoryFrameOutcome::AuthViolation {
                    reply: self
                        .dir_error(
                            client,
                            &device_id,
                            DirErrorCode::AuthFailed,
                            "device_id != session identity (protocol violation)".to_string(),
                        )
                        .unwrap_or_default(),
                })
            }
        }
        // 双 FQDN（§5 点位 9）：domain（设备自身域）+ target_domain
        // （被允许发现本机的中继域）均纯 FQDN（冻结口径继承）。
        let domain = normalize_domain(&req.domain);
        if !is_pure_fqdn(&domain) {
            return Ok(DirectoryFrameOutcome::Reply(
                self.dir_error(
                    client,
                    &device_id,
                    DirErrorCode::InvalidDomain,
                    format!("domain not a pure FQDN: {}", esc(&req.domain)),
                )
                .unwrap_or_default(),
            ));
        }
        let target_domain = normalize_domain(&req.target_domain);
        if !is_pure_fqdn(&target_domain) {
            return Ok(DirectoryFrameOutcome::Reply(
                self.dir_error(
                    client,
                    &device_id,
                    DirErrorCode::InvalidDomain,
                    format!("target_domain not a pure FQDN: {}", esc(&req.target_domain)),
                )
                .unwrap_or_default(),
            ));
        }
        let now = now_unix_secs();
        let sig = self.sign_local_entry(
            &device_id,
            &domain,
            now,
            crate::dir_store::SOURCE_MANUAL,
        );
        // 自签须在服务器公钥下验签通过才落库（正常路径自签恒过；密钥态
        // 异常 = 拒写 + 显式 DirError，无半程态）。
        if !verify_sig(
            &self.server_key.verifying_key(),
            entry_sig_message(&device_id, &domain, now, crate::dir_store::SOURCE_MANUAL, "").as_bytes(),
            &sig,
        ) {
            return Ok(DirectoryFrameOutcome::Reply(
                self.dir_error(
                    client,
                    &device_id,
                    DirErrorCode::Busy,
                    "self-sign verify failed at write time (refuse write, fail-closed)",
                )
                .unwrap_or_default(),
            ));
        }
        // 单 IP 配额（§4.2 执法点）：配额键 = 客户端 IP 归一形态
        // （IPv4 原址 / mapped → IPv4 / IPv6 /64 聚合）；检查在 store
        // 写事务内（单写者串行下无竞态）。审计 `ip=` 记**原始**地址。
        let quota_key = quota_key_for_ip(client.ip());
        // 面**零拦截**——裁定口径：维持 500/IP 现值 + 行为可见，不误伤
        // NAT 群体）：同 device_id 在旧配额键下持行而本次写入来自不同键 =
        // 配额归属迁移（典型：键 K 配额满 → 换 IP/前缀续灌）。检测与写入
        // 非同事务（单写者串行下最坏 = 漏/重一条告警，告警面可接受）；
        // 拦截面归 `upsert_manual` 既有配额执法零变化。
        match self
            .store
            .distinct_other_owner_keys(&device_id, &quota_key)
            .await
        {
            Ok(from_keys) if !from_keys.is_empty() => {
                self.audit.record(TunnelAuditEvent::DirQuotaKeyMigrated {
                    client,
                    device_id: device_id.clone(),
                    from_key: from_keys.join(";"),
                    to_key: quota_key.clone(),
                });
            }
            Ok(_) => {}
            Err(e) => {
                // 检测读失败不阻断写入主路（告警面 fail-open 于自身，执法
                // 面仍 fail-closed）；留 debug 行备查。
            }
        }
        let note = req.note.clone().unwrap_or_default();
        // UTF-8 按字节计）——超限 = 显式 [`DirErrorCode::QuotaExceeded`]
        // 上限复用 quota_exceeded 同先例；wire 六码冻结零改）。fail-closed
        // **不截断**（截断 = 猜）；存量超限行不回溯清理（只拒不新增）。
        if note.len() > MAX_DIR_NOTE_BYTES {
            return Ok(DirectoryFrameOutcome::Reply(
                self.dir_error(
                    client,
                    &device_id,
                    DirErrorCode::QuotaExceeded,
                    format!(
                        "note exceeds {} bytes (got {}) — refuse write, no truncation",
                        MAX_DIR_NOTE_BYTES,
                        note.len()
                    ),
                )
                .unwrap_or_default(),
            ));
        }
        match self
            .store
            .upsert_manual(
                &device_id,
                &target_domain,
                &domain,
                &note,
                &quota_key,
                now,
                sig,
                self.ip_quota,
                self.own_domain.as_deref(),
            )
            .await
        {
            Ok((used_after, enqueued)) => {
                // epoch 由 store.upsert_manual 内部推进（单一事实源）。
                self.audit.record(TunnelAuditEvent::DirUpserted {
                    client,
                    device_id: device_id.clone(),
                    target_domain: target_domain.clone(),
                    domain: domain.clone(),
                    quota_used: used_after,
                    quota_limit: self.ip_quota,
                });
                // token = upsert `ix_tokens(source='device', target_domain=B)`
                // （last-writer-wins；空 token = 显式清除既有缓存行，该
                // target 推送自此 fail-closed 跳过）。缓存行仅本机推送时
                // 携带用，本机**不校验**（token 归目标中继 B 校验）。
                if req.ix_token.is_empty() {
                    match self.store.ix_clear_device_token(&target_domain).await {
                        Ok(n) if n > 0 => {
                            tracing::info!(
                                "dir: ix_token cache cleared for target {target_domain} (device resubmitted empty token)"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!("dir: ix_token cache clear failed for {target_domain}: {e}");
                        }
                    }
                } else if let Err(e) = self
                    .store
                    .ix_upsert_device_token(&target_domain, &req.ix_token, &device_id, now)
                    .await
                {
                    // UNIQUE 冲突（缓存串恰为本机 cli 权威行）等失败 =
                    // 审计 WARN + 该 target 推送 fail-closed 跳过（不回错
                    // 给设备：目录写入本身已成功）。
                    tracing::warn!("dir: ix_token cache store failed for {target_domain}: {e}");
                    self.audit.record(TunnelAuditEvent::DirWriteRejected {
                        client,
                        device_id: device_id.clone(),
                        code: "busy".to_string(),
                        detail: format!("ix_token cache store failed: {e}"),
                    });
                }
                if enqueued {
                    // 同事务 outbox 新入队（`push outbox enqueued` 行素材；
                    // 已存在行不重复审计——NOT EXISTS 幂等口径）。
                    self.audit.record(TunnelAuditEvent::PushOutboxEnqueued {
                        target_domain: target_domain.clone(),
                    });
                }
                // target 推送（B 可达性不影响用户操作成败）。
                if let (Some(own), Some(t)) = (&self.own_domain, &self.push_trigger) {
                    if &target_domain != own {
                        let t = Arc::clone(t);
                        let target = target_domain.clone();
                        tokio::spawn(async move {
                            let _ok = t.trigger_target(&target).await;
                        });
                    }
                }
                Ok(DirectoryFrameOutcome::Silent) // 静默成功
            }
            Err(crate::dir_store::DirStoreError::QuotaExceeded { used, limit }) => {
                // §5 点位 10：只拒新增不清存量；显式码 + 专用审计行。
                self.audit.record(TunnelAuditEvent::DirQuotaRejected {
                    client,
                    device_id: device_id.clone(),
                    used,
                    limit,
                });
                Ok(DirectoryFrameOutcome::Reply(
                    self.dir_error(
                        client,
                        &device_id,
                        DirErrorCode::QuotaExceeded,
                        format!("ip quota exceeded ({limit})"),
                    )
                    .unwrap_or_default(),
                ))
            }
            Err(crate::dir_store::DirStoreError::DeviceLimitExceeded { used, limit }) => {
                // quota_exceeded 码**（冻结六码零改：老客户端混版解析
                // 存活、按既有超限路径处理；msg 携设备上限专属人话供
                // 新客户端/日志辨识）。只拒新增不挤存量 + 专用审计行。
                self.audit.record(TunnelAuditEvent::DirQuotaRejected {
                    client,
                    device_id: device_id.clone(),
                    used,
                    limit,
                });
                Ok(DirectoryFrameOutcome::Reply(
                    self.dir_error(
                        client,
                        &device_id,
                        DirErrorCode::QuotaExceeded,
                        format!(
                            "device entry limit exceeded ({used}/{limit}): max {limit} discovery entries per device (delete an entry first)"
                        ),
                    )
                    .unwrap_or_default(),
                ))
            }
            Err(e) => Ok(DirectoryFrameOutcome::Reply(
                self.dir_error(
                    client,
                    &device_id,
                    DirErrorCode::Busy,
                    format!("store error: {e}"),
                )
                .unwrap_or_default(),
            )),
        }
    }

    async fn handle_dir_delete(
        &self,
        client: SocketAddr,
        session_device_id: Option<String>,
        payload: &[u8],
    ) -> Result<DirectoryFrameOutcome, ()> {
        let req = decode_extension::<DirDelete>(TYPE_DIR_DELETE, payload, TYPE_DIR_DELETE)
            .map_err(|_| ())?;
        let device_id = match normalize_device_id(&req.device_id) {
            Ok(v) => v,
            Err(code) => {
                return Ok(DirectoryFrameOutcome::Reply(
                    self.dir_error(
                        client,
                        &req.device_id,
                        code,
                        format!("device_id invalid: {}", esc(&req.device_id)),
                    )
                    .unwrap_or_default(),
                ))
            }
        };
        // 身份执法（§5 点位 8，同 upsert 口径）。
        match &session_device_id {
            Some(id) if id == &device_id => {}
            _ => {
                return Ok(DirectoryFrameOutcome::AuthViolation {
                    reply: self
                        .dir_error(
                            client,
                            &device_id,
                            DirErrorCode::AuthFailed,
                            "device_id != session identity (protocol violation)".to_string(),
                        )
                        .unwrap_or_default(),
                })
            }
        }
        let target_domain = normalize_domain(&req.target_domain);
        if !is_pure_fqdn(&target_domain) {
            return Ok(DirectoryFrameOutcome::Reply(
                self.dir_error(
                    client,
                    &device_id,
                    DirErrorCode::InvalidDomain,
                    format!("target_domain not a pure FQDN: {}", esc(&req.target_domain)),
                )
                .unwrap_or_default(),
            ));
        }
        // 只删本中继自持行 (device_id, target_domain)（source ∈
        // manual/registered）；pushed-only 行 = not_found **不跨源删**
        // （B 上的 (D,B) 行只能由 A 的推送批次删除，§2.2）。
        match self
            .store
            .delete_manual(&device_id, &target_domain, self.own_domain.as_deref())
            .await
        {
            Ok((true, enqueued)) => {
                // epoch 由 store.delete_manual 内部推进（单一事实源）。
                self.audit.record(TunnelAuditEvent::DirDeleted {
                    client,
                    device_id: device_id.clone(),
                    target_domain: target_domain.clone(),
                });
                if enqueued {
                    self.audit.record(TunnelAuditEvent::PushOutboxEnqueued {
                        target_domain: target_domain.clone(),
                    });
                }
                // （异步非阻塞，同 upsert 口径）。
                if let (Some(own), Some(t)) = (&self.own_domain, &self.push_trigger) {
                    if &target_domain != own {
                        let t = Arc::clone(t);
                        let target = target_domain.clone();
                        tokio::spawn(async move {
                            let _ok = t.trigger_target(&target).await;
                        });
                    }
                }
                Ok(DirectoryFrameOutcome::Silent) // 静默成功
            }
            Ok((false, _)) => Ok(DirectoryFrameOutcome::Reply(
                self.dir_error(
                    client,
                    &device_id,
                    DirErrorCode::NotFound,
                    "no such self-held entry (pushed rows are removed by the pusher batch only)"
                        .to_string(),
                )
                .unwrap_or_default(),
            )),
            Err(e) => Ok(DirectoryFrameOutcome::Reply(
                self.dir_error(
                    client,
                    &device_id,
                    DirErrorCode::Busy,
                    format!("store error: {e}"),
                )
                .unwrap_or_default(),
            )),
        }
    }
}

impl DirectoryHandler for DirBackend {
    fn handle_frame<'a>(
        &'a self,
        client: SocketAddr,
        session_device_id: Option<String>,
        ty: u8,
        payload: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<DirectoryFrameOutcome, ()>> + Send + 'a>> {
        let this = self;
        let session_device_id = session_device_id;
        Box::pin(async move {
            match ty {
                TYPE_DIR_LIST => this.handle_dir_list(client, payload).await,
                TYPE_DIR_UPSERT => {
                    this.handle_dir_upsert(client, session_device_id, payload).await
                }
                TYPE_DIR_DELETE => {
                    this.handle_dir_delete(client, session_device_id, payload).await
                }
                // 0x90~0x94 废帧由 server.rs 分发层丢弃（不进后端）；
                // R→C 应答帧由分发层判死。此处纵深兜底 = 坏帧。
                _ => Err(()),
            }
        })
    }
}

// ── 纯函数族（冻结校验口径；单测钉死；interconnect 复用） ──────────────

/// - 指纹形态（去冒号/空白恰 64 hex）→ canonical 79 字符（4 位 hex 冒号分组、小写）；
///   合法形态，先行消费；
/// - **短码（10 小写 hex）→ 拒绝**（离线不可展开，fail-closed 不猜）；
/// - 空 / 含 NUL / 超长(>256) → 拒绝；
///   控制字符（`\n` `\r` `\t` `\x1b` 等）= 拒——DB 落库与下游消费面
///   （客户端展示/日志）不吃控制字符；审计行既有 S-16d 转义保持不变。
pub fn normalize_device_id(raw: &str) -> Result<String, DirErrorCode> {
    use kirin_desk_relay::protocol::{is_fingerprint_device_id, is_short_code};
    if raw.is_empty() || raw.len() > 256 || raw.contains('\0') {
        return Err(DirErrorCode::InvalidDeviceId);
    }
    if is_fingerprint_device_id(raw) {
        let flat: String = raw
            .chars()
            .filter(|c| !matches!(c, ':' | ' ' | '\t' | '\r' | '\n'))
            .flat_map(|c| c.to_lowercase())
            .collect();
        // flat.len() == 64 已由 is_fingerprint_device_id 保证。
        Ok(flat
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":"))
    } else if is_short_code(raw) {
        Err(DirErrorCode::InvalidDeviceId)
    } else {
        // （fail-closed 显式错，不清洗不猜；NUL 已在上方拦截）。
        if raw.chars().any(|c| (c as u32) < 0x20) {
            return Err(DirErrorCode::InvalidDeviceId);
        }
        Ok(raw.to_string())
    }
}

/// 域名字符归一（trim + 小写；FQDN 合法性由 [`is_pure_fqdn`] 判定）。
pub fn normalize_domain(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// 纯 FQDN 判定（冻结口径，「domain 纯 FQDN（不含 :port）……非 FQDN = 拒」）：
/// - 全 ASCII、1..=253 字节、不含 `:`/空白/点首尾；
/// - 标签数 ≥ 2；每标签 1..=63 字节、字母数字与 `-`、`-` 不居首尾；
/// - TLD 纯字母（`*.com` / `*.local` 等；纯数字 TLD 非 FQDN 惯例）。
pub fn is_pure_fqdn(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || !s.chars().all(|c| c.is_ascii()) {
        return false;
    }
    if s.starts_with('.') || s.ends_with('.') || s.contains(' ') || s.contains(':') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return false;
        }
    }
    labels
        .last()
        .is_some_and(|tld| tld.chars().all(|c| c.is_ascii_alphabetic()))
}

// 拆除——v2 指纹口径 = recipient_fp 批次绑定 + HELLO fp 代码派生（fp_of_pubkey），
// 不再消费「存储的指纹字符串」，零生产调用方 = 删（设计 §7.4 P4 行）。

/// - IPv4 = 完整地址（/32，原址形态）；
/// - IPv4-mapped IPv6（`::ffff:a.b.c.d`）= 归一为 IPv4 处理（与 NAT 口径
///   一致）；
/// - 其余 IPv6 = **/64 聚合前缀**（`2001:db8:abcd:1234::/64` 形态；RFC
///   4193 隐私扩展地址逐会话轮换，按完整地址计数 = 配额可被自我绕过 +
///   计数不稳定；/64 = 网络分配单元，CGNAT/家宽 NAT66 下稳定）。
/// 审计行 `ip=` 仍记原始地址（可观测性）；配额键为内部形态不落审计。
pub fn quota_key_for_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.to_string();
            }
            let mut segs = v6.segments();
            segs[4..].fill(0); // 主机位清零 = /64 前缀
            format!("{}/64", std::net::Ipv6Addr::from(segs))
        }
    }
}

/// 签名覆盖域（v1 冻结格式，模块头；**manual 行自签沿用**）：
/// `id US domain US ts US source US peer_fp`。
pub fn entry_sig_message(
    device_id: &str,
    domain: &str,
    updated_at: u64,
    source: &str,
    peer_fp: &str,
) -> String {
    format!("{device_id}\u{1f}{domain}\u{1f}{updated_at}\u{1f}{source}\u{1f}{peer_fp}")
}

/// Ed25519 验签（sig 必须恰 64 字节；坏长 = false，fail-closed）。
pub fn verify_sig(key: &VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let Ok(signature) = Signature::from_slice(sig) else {
        return false;
    };
    key.verify(msg, &signature).is_ok()
}

/// 审计 detail 用控制字符转义（复用 utils 既有口径，零新转义实现）。
fn esc(s: &str) -> String {
    kirin_desk_utils::audit::escape_control(s)
}

// ────────────────────────────────────────────────────────────────────────
// 配额键矩阵 / 签名自洽 / 冻结口径钉死）
// ────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dir_store::{DirStore, SOURCE_MANUAL, SOURCE_PUSHED};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn test_backend(db_name: &str, ip_quota: usize) -> (DirBackend, std::path::PathBuf) {
        let i = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "kirin_r1402_backend_{}_{}_{}",
            std::process::id(),
            i,
            db_name
        ));
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let store = Arc::new(DirStore::open(&p).unwrap());
        let key = test_key();
        let backend = DirBackend::new(store, Arc::new(key), Arc::new(NoopAudit), ip_quota);
        (backend, p)
    }

    #[derive(Debug)]
    struct NoopAudit;
    impl AuditSink for NoopAudit {
        fn record(&self, _e: TunnelAuditEvent) {}
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:40000".parse().unwrap()
    }

    fn frame(_ty: u8, value: &impl serde::Serialize) -> Vec<u8> {
        // payload = bincode body（handle_frame 收的是扩展帧 payload 段）。
        bincode::serialize(value).unwrap()
    }

    fn decode_err(frame: &[u8]) -> DirError {
        // 从完整帧 [type][len][payload] 取 payload 解码。
        let payload = &frame[5..];
        bincode::deserialize(payload).unwrap()
    }

    /// 测试辅助：`Reply` 变体取帧字节（DirectoryFrameOutcome 属 relay
    /// crate，本 crate 不得扩固有 impl → 自由函数口径）。
    fn unwrap_payload(o: DirectoryFrameOutcome) -> Vec<u8> {
        match o {
            DirectoryFrameOutcome::Reply(bytes) => bytes,
            other => panic!("期望 Reply，实得 {other:?}"),
        }
    }

    fn default_list() -> DirList {
        DirList {
            scope: DirScope::All,
            refresh: false,
            filter_device: None,
        }
    }

    fn cleanup(p: &std::path::Path) {
        let _ = std::fs::remove_file(p);
    }

    const SELF_ID: &str = "dev-self";

    // ── 校验纯函数 ─────────────────────────────────────────────────────

    #[test]
    fn test_r137_12_normalize_device_id_frozen() {
        // 指纹形态：79 字符 canonical 原样、64hex 无冒号 → 归一 79 字符。
        let fp64 = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let canonical = "a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90:a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90";
        assert_eq!(normalize_device_id(canonical).unwrap(), canonical);
        assert_eq!(normalize_device_id(fp64).unwrap(), canonical);
        // 大写 → 小写归一。
        assert_eq!(normalize_device_id(&fp64.to_uppercase()).unwrap(), canonical);
        // 短码（10 小写 hex）= 拒（离线不可展开，不猜）。
        assert_eq!(
            normalize_device_id("a1b2c3d4e5").unwrap_err(),
            DirErrorCode::InvalidDeviceId
        );
        // 空 / 超长 / NUL = 拒。
        assert_eq!(normalize_device_id("").unwrap_err(), DirErrorCode::InvalidDeviceId);
        assert_eq!(
            normalize_device_id(&"a".repeat(257)).unwrap_err(),
            DirErrorCode::InvalidDeviceId
        );
        assert_eq!(
            normalize_device_id("ab\0cd").unwrap_err(),
            DirErrorCode::InvalidDeviceId
        );
        // 自定义显式 ID = 原样受理。
        assert_eq!(normalize_device_id("my-custom-id-1").unwrap(), "my-custom-id-1");
    }


    #[test]
    fn test_r182_device_id_control_chars_rejected() {
        // 自定义显式 ID 含 <0x20 控制字符 = 拒（\n \r \t \x1b \x0b \x07）。
        for bad in [
            "my\nid", "my\rid", "my\tid", "my\u{1b}id", "my\u{0b}id", "\u{7}bell",
        ] {
            assert_eq!(
                normalize_device_id(bad).unwrap_err(),
                DirErrorCode::InvalidDeviceId,
                "控制字符必须拒: {bad:?}"
            );
        }
        // 既有合法自定义 ID（字母数字 + :_-）全绿（零回归）。
        for ok in ["my-custom-id-1", "srv_2", "node:3", "A.b.C-9_0"] {
            assert_eq!(normalize_device_id(ok).unwrap(), ok, "合法 ID 零回归: {ok}");
        }
        let fp64 = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let canonical = "a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90:a1b2:c3d4:e5f6:0718:293a:4b5c:6d7e:8f90";
        let spaced = format!("{} {} {} {}", &fp64[..16], &fp64[16..32], &fp64[32..48], &fp64[48..]);
        assert_eq!(normalize_device_id(&spaced).unwrap(), canonical);
        // 短码/NUL/空/超长既有拒收面零变化（同码 InvalidDeviceId）。
        assert_eq!(normalize_device_id("a1b2c3d4e5").unwrap_err(), DirErrorCode::InvalidDeviceId);
        assert_eq!(normalize_device_id("ab\0cd").unwrap_err(), DirErrorCode::InvalidDeviceId);
    }

    #[tokio::test]
    async fn test_r182_note_limit_boundary_511_512_513() {
        let (b, p) = test_backend("r182note", 0);
        let client = addr();
        let id = Some(SELF_ID.to_string());
        let up = |note: Option<String>| {
            frame(
                kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
                &DirUpsert {
                    device_id: SELF_ID.into(),
                    domain: "alpha.example.com".into(),
                    target_domain: "b182.test.relay".into(),
                    note,
                    ix_token: String::new(),
                },
            )
        };
        // 511B / 512B = 受理（Silent；512 = 上限恰合，UTF-8 按字节计）。
        assert_eq!(
            b.handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up(Some("a".repeat(511))))
                .await
                .unwrap(),
            DirectoryFrameOutcome::Silent
        );
        assert_eq!(
            b.handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up(Some("b".repeat(512))))
                .await
                .unwrap(),
            DirectoryFrameOutcome::Silent
        );
        // 513B = 超限 → 显式 DirError（quota_exceeded 同类位），库零变化
        // （fail-closed 拒写不截断；同 (device_id, target_domain) 行 = 重写，
        //  以 store 行数与 note 内容双断言「零变化」）。
        let err = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up(Some("c".repeat(513))))
            .await
            .unwrap();
        assert_eq!(
            decode_err(&unwrap_payload(err)).code,
            DirErrorCode::QuotaExceeded,
            "超限 = quota_exceeded 同类位（wire 六码冻结零改）"
        );
        assert_eq!(b.store().count().await.unwrap(), 1, "超限拒写 = 库零变化");
        // 落库 note = 既有合法值（未被 513B 串污染/截断）。
        let row = b.store().get(SELF_ID, "b182.test.relay").await.unwrap().unwrap();
        assert_eq!(row.note, "b".repeat(512), "存量行 = 末次合法值，超限串零落库");
        // 多字节 UTF-8 按字节计：256 个『€』（每字 3B = 768B）= 超限拒。
        let err = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up(Some("€".repeat(256))))
                .await
                .unwrap();
        assert_eq!(decode_err(&unwrap_payload(err)).code, DirErrorCode::QuotaExceeded);
        // note 仅落库不回传（DirEntry 不含 note）——上限面纯存储侧。
        assert_eq!(
            b.handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up(None))
                .await
                .unwrap(),
            DirectoryFrameOutcome::Silent
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn test_r137_12_is_pure_fqdn_frozen() {
        // 合法。
        assert!(is_pure_fqdn("relay.example.com"));
        assert!(is_pure_fqdn("a-b.c-d.example.co.uk"));
        assert!(is_pure_fqdn("x.example.local"));
        // 含 :port = 拒（端口恒走 SRV）。
        assert!(!is_pure_fqdn("relay.example.com:7002"));
        // 单标签 = 拒。
        assert!(!is_pure_fqdn("localhost"));
        // 空 / 首尾点 / 双点 = 拒。
        assert!(!is_pure_fqdn(""));
        assert!(!is_pure_fqdn(".example.com"));
        assert!(!is_pure_fqdn("example.com."));
        assert!(!is_pure_fqdn("exa..mple.com"));
        // 非法字符 / 连字符首尾 = 拒。
        assert!(!is_pure_fqdn("exa mple.com"));
        assert!(!is_pure_fqdn("exa_mple.com"));
        assert!(!is_pure_fqdn("-example.com"));
        assert!(!is_pure_fqdn("exa mple-.com"));
        // 标签 > 63 / 总长 > 253 = 拒。
        assert!(!is_pure_fqdn(&format!("{}.com", "a".repeat(64))));
        assert!(!is_pure_fqdn(&format!("x.{}.com", "a".repeat(240))));
        // 纯数字 TLD = 拒；非 ASCII = 拒。
        assert!(!is_pure_fqdn("example.123"));
        assert!(!is_pure_fqdn("例子.com"));
    }

    #[test]
    fn test_r137_12_entry_sig_message_frozen() {
        // 冻结格式：US(0x1F) 分隔五字段（manual 行自签沿用）。
        let m = entry_sig_message("dev-1", "a.example.com", 123, "manual", "");
        assert_eq!(m, "dev-1\u{1f}a.example.com\u{1f}123\u{1f}manual\u{1f}");
        let m2 = entry_sig_message("dev-1", "a.example.com", 123, "pushed", "ff:ee");
        assert_eq!(m2, "dev-1\u{1f}a.example.com\u{1f}123\u{1f}pushed\u{1f}ff:ee");
    }


    #[test]
    fn test_r140_1_quota_key_for_ip_matrix() {
        // IPv4 = 原址（/32）。
        assert_eq!(
            quota_key_for_ip("203.0.113.7:9000".parse::<SocketAddr>().unwrap().ip()),
            "203.0.113.7"
        );
        // IPv4-mapped IPv6 → 归一 IPv4（与 NAT 口径一致）。
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        assert_eq!(quota_key_for_ip(mapped), "203.0.113.7");
        // IPv6 /64 聚合：同 /64 不同主机位 = 同键。
        let a: IpAddr = "2001:db8:abcd:1234::5".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1234:ffff:ffff:ffff:ffff".parse().unwrap();
        let c: IpAddr = "2001:db8:abcd:9999::5".parse().unwrap();
        assert_eq!(quota_key_for_ip(a), "2001:db8:abcd:1234::/64");
        assert_eq!(quota_key_for_ip(b), quota_key_for_ip(a), "同 /64 共享配额键");
        assert_ne!(quota_key_for_ip(c), quota_key_for_ip(a), "异 /64 独立键");
        // 形态钉死：主机位全零 + /64 后缀。
        assert!(quota_key_for_ip(a).ends_with("::/64"));
        // 默认配额常量钉。
        assert_eq!(DEFAULT_DIR_IP_QUOTA, 500);
    }

    // ── CRUD e2e v2（经 handle_frame，冻结帧面 + 身份执法 + 双 FQDN + 配额） ──

    #[tokio::test]
    async fn test_r140_1_crud_e2e_via_frames_v2() {
        let (b, p) = test_backend("crud", 0); // 0 = 不限（配额矩阵另测）
        let client = addr();
        let id = Some(SELF_ID.to_string());

        // 身份执法（§5 点位 8）：device_id != 会话身份 = auth_failed +
        // AuthViolation（先应答后判死，server.rs 执行判死）。
        let up_other = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: "dev-other".into(),
                domain: "other.example.com".into(),
                target_domain: "b.test.relay".into(),
                note: None,
                ix_token: String::new(),
            },
        );
        assert!(matches!(
            b.handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up_other)
                .await,
            Ok(DirectoryFrameOutcome::AuthViolation { ref reply })
                if !reply.is_empty()
        ));
        // 会话身份未建立（None）= 同 auth_failed 口径（fail-closed 不猜）。
        assert!(matches!(
            b.handle_frame(client, None, kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up_other)
                .await,
            Ok(DirectoryFrameOutcome::AuthViolation { .. })
        ));

        // DirUpsert（身份匹配）→ 静默成功（Silent）。
        let up = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: SELF_ID.into(),
                domain: "alpha.example.com".into(),
                target_domain: "b1.test.relay".into(),
                note: Some("n1".into()),
                ix_token: String::new(),
            },
        );
        assert_eq!(
            b.handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up)
                .await,
            Ok(DirectoryFrameOutcome::Silent)
        );

        // DirList → 回显 7 字段 v2 形态（source=manual + sig_verified 恒
        // true + note 落库 + target_domain/source_fp 在位）。
        let list = frame(kirin_desk_relay::protocol::TYPE_DIR_LIST, &default_list());
        let resp = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &list)
            .await
            .unwrap();
        let dlresp: DirListResp = bincode::deserialize(&unwrap_payload(resp)[5..]).unwrap();
        assert_eq!(dlresp.entries.len(), 1);
        assert_eq!(dlresp.entries[0].device_id, SELF_ID);
        assert_eq!(dlresp.entries[0].device_domain, "alpha.example.com");
        assert_eq!(dlresp.entries[0].target_domain, "b1.test.relay");
        assert_eq!(dlresp.entries[0].source, SOURCE_MANUAL);
        assert_eq!(dlresp.entries[0].source_fp, "");
        assert!(dlresp.entries[0].sig_verified, "v2 写时验口径：全来源恒 true");
        let epoch0 = dlresp.epoch;
        assert_eq!(b.epoch().await, epoch0);

        // 同设备多 target 行（复合 PK；filter_device 回读口径 = T7 对账用）。
        let up2 = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: SELF_ID.into(),
                domain: "alpha.example.com".into(),
                target_domain: "b2.test.relay".into(),
                note: None,
                ix_token: String::new(),
            },
        );
        assert_eq!(
            b.handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up2)
                .await,
            Ok(DirectoryFrameOutcome::Silent)
        );
        let filter_list = frame(
            kirin_desk_relay::protocol::TYPE_DIR_LIST,
            &DirList {
                scope: DirScope::Local,
                refresh: false,
                filter_device: Some(SELF_ID.to_string()),
            },
        );
        let resp = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &filter_list)
            .await
            .unwrap();
        let dlresp: DirListResp = bincode::deserialize(&unwrap_payload(resp)[5..]).unwrap();
        assert_eq!(dlresp.entries.len(), 2, "filter_device = 该设备全部 target 行");

        // 非法 ID（短码）/ 非法 domain / 非法 target_domain → DirError 显式码。
        let bad_id = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: "a1b2c3d4e5".into(), // 短码 = 拒（归一败在身份执法前）
                domain: "ok.example.com".into(),
                target_domain: "b.test.relay".into(),
                note: None,
                ix_token: String::new(),
            },
        );
        let err = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &bad_id)
            .await
            .unwrap();
        match err {
            DirectoryFrameOutcome::Reply(bytes) => {
                assert_eq!(decode_err(&bytes).code, DirErrorCode::InvalidDeviceId);
            }
            other => panic!("期望 Reply(DirError)，实得 {other:?}"),
        }
        let bad_dom = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: SELF_ID.into(),
                domain: "not-a-fqdn:7002".into(),
                target_domain: "b.test.relay".into(),
                note: None,
                ix_token: String::new(),
            },
        );
        let err = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &bad_dom)
            .await
            .unwrap();
        assert_eq!(decode_err(&unwrap_payload(err)).code, DirErrorCode::InvalidDomain);
        let bad_target = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: SELF_ID.into(),
                domain: "ok.example.com".into(),
                target_domain: "localhost".into(), // 单标签 = 拒
                note: None,
                ix_token: String::new(),
            },
        );
        let err = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &bad_target)
            .await
            .unwrap();
        assert_eq!(decode_err(&unwrap_payload(err)).code, DirErrorCode::InvalidDomain);

        // DirDelete v2：自持行可删（Silent）；再删 → not_found；
        // pushed-only 行 → not_found **不跨源删**。
        let del = frame(
            kirin_desk_relay::protocol::TYPE_DIR_DELETE,
            &DirDelete {
                device_id: SELF_ID.into(),
                target_domain: "b2.test.relay".into(),
            },
        );
        assert_eq!(
            b.handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_DELETE, &del)
                .await,
            Ok(DirectoryFrameOutcome::Silent)
        );
        let err = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_DELETE, &del)
            .await
            .unwrap();
        assert_eq!(decode_err(&unwrap_payload(err)).code, DirErrorCode::NotFound);
        // 身份执法对 delete 同口径。
        let del_other = frame(
            kirin_desk_relay::protocol::TYPE_DIR_DELETE,
            &DirDelete {
                device_id: "dev-other".into(),
                target_domain: "b1.test.relay".into(),
            },
        );
        assert!(matches!(
            b.handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_DELETE, &del_other)
                .await,
            Ok(DirectoryFrameOutcome::AuthViolation { .. })
        ));
        // pushed-only 行（test-only 直插）= 不跨源删。
        let fp = "ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00:ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11";
        b.store()
            .insert_pushed_test(SELF_ID, "self.test.relay", "p.example.com", fp, 100, vec![9u8; 64])
            .await
            .unwrap();
        let del_pushed = frame(
            kirin_desk_relay::protocol::TYPE_DIR_DELETE,
            &DirDelete {
                device_id: SELF_ID.into(),
                target_domain: "self.test.relay".into(),
            },
        );
        let err = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_DELETE, &del_pushed)
            .await
            .unwrap();
        assert_eq!(
            decode_err(&unwrap_payload(err)).code,
            DirErrorCode::NotFound,
            "pushed-only 行不得经 DirDelete 删除（不跨源删）"
        );
        assert!(
            b.store().get(SELF_ID, "self.test.relay").await.unwrap().is_some(),
            "pushed 行保留"
        );
        // Peer(fp) scope v2 语义 = 来源 fp 的 pushed 行。
        let peer_list = frame(
            kirin_desk_relay::protocol::TYPE_DIR_LIST,
            &DirList {
                scope: DirScope::Peer(fp.to_string()),
                refresh: false,
                filter_device: None,
            },
        );
        let resp = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &peer_list)
            .await
            .unwrap();
        let dlresp: DirListResp = bincode::deserialize(&unwrap_payload(resp)[5..]).unwrap();
        assert_eq!(dlresp.entries.len(), 1);
        assert_eq!(dlresp.entries[0].source, SOURCE_PUSHED);
        assert_eq!(dlresp.entries[0].source_fp, fp);

        // 坏帧（payload 结构错）= Err(())（会话判死由 server.rs 执行）。
        let garbage = vec![0u8; 3];
        assert_eq!(
            b.handle_frame(client, id, kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &garbage).await,
            Err(())
        );
        cleanup(&p);
    }


    #[tokio::test]
    async fn test_r140_1_quota_via_frames() {
        // 帧面错误码钉死：配额 1 + 预填 1 个同 IP（127.0.0.1）异设备行
        // （store 面直写，模拟他机同 NAT 出口占位）→ 该 IP 新设备 upsert
        // = quota_exceeded 帧；同设备再写 = 不增量放行。distinct 语义
        // 全矩阵由 store 层配额矩阵覆盖（dir_store 单测）。
        let (b, p) = test_backend("quota", 1);
        b.store()
            .upsert_manual(
                "dev-pre",
                "t.test.relay",
                "pre.example.com",
                "",
                "127.0.0.1", // 配额键 = 客户端 IP 归一（IPv4 原址）
                1,
                vec![0u8; 64],
                1,
                None,
            )
            .await
            .unwrap();
        // 会话 SELF_ID（新设备 for 该 IP）upsert → quota_exceeded 帧。
        let up = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: SELF_ID.into(),
                domain: "alpha.example.com".into(),
                target_domain: "b1.test.relay".into(),
                note: None,
                ix_token: String::new(),
            },
        );
        let err = b
            .handle_frame(addr(), Some(SELF_ID.to_string()), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up)
            .await
            .unwrap();
        let d = decode_err(&unwrap_payload(err));
        assert_eq!(d.code, DirErrorCode::QuotaExceeded, "{d:?}");
        assert!(d.msg.contains("ip quota exceeded"), "{d:?}");
        // 同 IP 同设备（dev-pre）再写 = 不增量放行（需会话身份 = dev-pre）。
        let up_same = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: "dev-pre".into(),
                domain: "pre2.example.com".into(),
                target_domain: "b9.test.relay".into(),
                note: None,
                ix_token: String::new(),
            },
        );
        assert_eq!(
            b.handle_frame(addr(), Some("dev-pre".to_string()), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up_same)
                .await,
            Ok(DirectoryFrameOutcome::Silent),
            "同 IP 同设备 = 不增量放行"
        );
        cleanup(&p);
    }


    #[tokio::test]
    async fn test_r139_2_sig_timing_moved_write_time_fail_closed_v2() {
        let (b, p) = test_backend("sigtiming", 0);
        let client = addr();
        let id = Some(SELF_ID.to_string());
        // ① 本域条目：写前自签验证（静默成功）→ DirList 可观测值 = true。
        let up = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: SELF_ID.into(),
                domain: "local.example.com".into(),
                target_domain: "b.test.relay".into(),
                note: None,
                ix_token: String::new(),
            },
        );
        assert_eq!(
            b.handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up).await,
            Ok(DirectoryFrameOutcome::Silent)
        );
        // v2 可观测值同样恒 true（写时验口径全来源统一）。
        b.store()
            .insert_pushed_test(
                "dev-pushed",
                "self.test.relay",
                "p.example.com",
                "ff:ee:aa",
                100,
                vec![9u8; 64],
            )
            .await
            .unwrap();
        let list = frame(kirin_desk_relay::protocol::TYPE_DIR_LIST, &default_list());
        let resp = b
            .handle_frame(client, id, kirin_desk_relay::protocol::TYPE_DIR_LIST, &list)
            .await
            .unwrap();
        let dlresp: DirListResp = bincode::deserialize(&unwrap_payload(resp)[5..]).unwrap();
        assert_eq!(dlresp.entries.len(), 2);
        assert!(
            dlresp.entries.iter().all(|e| e.sig_verified),
            "v2 写时验口径：manual/pushed 全来源可观测值恒 true"
        );
        cleanup(&p);
    }

    #[tokio::test]
    async fn test_r139_2_dirlist_read_path_no_per_row_verify_v2() {
        // 读路径免逐行验签（项②）：2000 条 store 级预填本域行（sig = 哑值——
        // 若读侧仍逐行验签，这些行全部验不过）→ DirList 全量回显且
        // 可观测值恒 true（写时验签口径；热路径零验签）。
        let (b, p) = test_backend("readpath", 0);
        b.store()
            .prefill_local_test(2000)
            .await
            .unwrap();
        let list = frame(kirin_desk_relay::protocol::TYPE_DIR_LIST, &default_list());
        let resp = b
            .handle_frame(
                addr(),
                None,
                kirin_desk_relay::protocol::TYPE_DIR_LIST,
                &list,
            )
            .await
            .unwrap();
        let dlresp: DirListResp = bincode::deserialize(&unwrap_payload(resp)[5..]).unwrap();
        assert_eq!(dlresp.entries.len(), 2000);
        assert!(
            dlresp.entries.iter().all(|e| e.sig_verified),
            "本域行可观测值恒 true（验签时点 = 写入时，读路径不重验）"
        );
        cleanup(&p);
    }


    /// 测试桩：记录触发调用（断言调用面：target 集 / 全量次数）。
    #[derive(Debug)]
    struct RecordingTrigger {
        targets: std::sync::Mutex<Vec<String>>,
        all: std::sync::atomic::AtomicUsize,
    }
    impl RecordingTrigger {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                targets: std::sync::Mutex::new(Vec::new()),
                all: std::sync::atomic::AtomicUsize::new(0),
            })
        }
        fn targets(&self) -> Vec<String> {
            self.targets.lock().unwrap().clone()
        }
    }
    #[async_trait::async_trait]
    impl crate::interconnect::PushTrigger for RecordingTrigger {
        async fn trigger_all(&self) -> usize {
            self.all
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            1
        }
        async fn trigger_target(&self, target_domain: &str) -> bool {
            self.targets
                .lock()
                .unwrap()
                .push(target_domain.to_string());
            true
        }
    }

    #[tokio::test]
    async fn test_r140_3_push_trigger_wiring() {
        let (base, p) = test_backend("trigger", 0);
        let rt = RecordingTrigger::new();
        let b = base
            .with_push_trigger(Arc::clone(&rt))
            .with_own_domain("a.test.relay");
        let id = Some(SELF_ID.to_string());
        // target ≠ 自域 → 静默成功 + 异步单 target 触发 + 同事务 outbox 行。
        let up = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: SELF_ID.into(),
                domain: "alpha.example.com".into(),
                target_domain: "b.test.relay".into(),
                note: None,
                ix_token: String::new(),
            },
        );
        assert_eq!(
            b.handle_frame(addr(), id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up)
                .await,
            Ok(DirectoryFrameOutcome::Silent)
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(rt.targets(), vec!["b.test.relay".to_string()], "变更即推 = 单 target");
        assert_eq!(
            b.store().outbox_due(i64::MAX as u64).await.unwrap().len(),
            1,
            "同事务 outbox 触发记录"
        );
        // target = 自域 → 不入队、不触发（本域行无需推给自己）。
        let up_own = frame(
            kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
            &DirUpsert {
                device_id: SELF_ID.into(),
                domain: "alpha.example.com".into(),
                target_domain: "a.test.relay".into(),
                note: None,
                ix_token: String::new(),
            },
        );
        assert_eq!(
            b.handle_frame(addr(), id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &up_own)
                .await,
            Ok(DirectoryFrameOutcome::Silent)
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(rt.targets(), vec!["b.test.relay".to_string()], "自域 target 不触发");
        assert_eq!(b.store().outbox_due(i64::MAX as u64).await.unwrap().len(), 1, "自域 target 不入队");
        // DirDelete（target ≠ 自域）→ 触发撤销重推（声明式缺行批次）。
        let del = frame(
            kirin_desk_relay::protocol::TYPE_DIR_DELETE,
            &DirDelete {
                device_id: SELF_ID.into(),
                target_domain: "b.test.relay".into(),
            },
        );
        assert_eq!(
            b.handle_frame(addr(), id.clone(), kirin_desk_relay::protocol::TYPE_DIR_DELETE, &del)
                .await,
            Ok(DirectoryFrameOutcome::Silent)
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(rt.targets().len(), 2, "删除 = 撤销重推触发");
        // DirList{refresh:true} → 异步一轮全量重推（trigger_all）。
        let mut dl = default_list();
        dl.refresh = true;
        let list = frame(kirin_desk_relay::protocol::TYPE_DIR_LIST, &dl);
        let resp = b
            .handle_frame(addr(), id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &list)
            .await
            .unwrap();
        let _ = unwrap_payload(resp);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            rt.all.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "refresh = trigger_all 一次"
        );
        cleanup(&p);
    }

    /// 测试辅助：暴露 store（仅测试用）。
    impl DirBackend {
        pub fn store(&self) -> &Arc<DirStore> {
            &self.store
        }
    }


    #[tokio::test]
    async fn test_r177_refresh_throttle_matrix() {
        let (base, p) = test_backend("r177thr", 0);
        let rt = RecordingTrigger::new();
        let b = base
            .with_push_trigger(Arc::clone(&rt))
            .with_own_domain("a.test.relay");
        let id = Some(SELF_ID.to_string());
        let mk = |ip: IpAddr| SocketAddr::new(ip, 40000);
        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();
        let mut dl = default_list();
        dl.refresh = true;
        let list = frame(kirin_desk_relay::protocol::TYPE_DIR_LIST, &dl);
        // 首刷放行（真实触发 1 次）。
        let resp = b
            .handle_frame(mk(ip1), id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &list)
            .await
            .unwrap();
        let _ = unwrap_payload(resp);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            rt.all.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "首刷放行"
        );
        // 间隔内连发 9 次 = 忽略 refresh 臂（列表照常应答，不真实触发）。
        for _ in 0..9 {
            let resp = b
                .handle_frame(mk(ip1), id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &list)
                .await
                .unwrap();
            let _ = unwrap_payload(resp);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            rt.all.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "60s 间隔内超频 refresh = 节流（10 连发仅 1 次真实触发）"
        );
        // 他 IP 首刷放行（节流按 IP 隔离）。
        let resp = b
            .handle_frame(mk(ip2), id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &list)
            .await
            .unwrap();
        let _ = unwrap_payload(resp);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            rt.all.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "他 IP 首刷放行"
        );
        assert_eq!(b.refresh_seen.lock().await.len(), 2, "节流表登记两 IP");
        cleanup(&p);
    }

    #[tokio::test]
    async fn test_r177_refresh_table_bounded() {
        let (b, p) = test_backend("r177tab", 0);
        let now = std::time::Instant::now();
        for i in 0..5000u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            let _ = b.refresh_allow(ip, now).await;
        }
        let len = b.refresh_seen.lock().await.len();
        assert!(
            len <= REFRESH_TABLE_CAP,
            "节流表有界 ≤{REFRESH_TABLE_CAP}（实测 {len}）"
        );
        // 表满逐出最旧后新 IP 仍可登记（节流面自身不可被填表 DoS）。
        assert!(b
            .refresh_allow(
                IpAddr::V4(std::net::Ipv4Addr::new(10, 9, 9, 9)),
                std::time::Instant::now()
            )
            .await);
        cleanup(&p);
    }

    /// 提交方地址；列表应答不受影响）。
    #[derive(Debug, Default)]
    struct R177Collect(std::sync::Mutex<Vec<TunnelAuditEvent>>);
    impl AuditSink for R177Collect {
        fn record(&self, e: TunnelAuditEvent) {
            self.0.lock().unwrap().push(e);
        }
    }

    #[tokio::test]
    async fn test_r177_refresh_throttle_audit_line() {
        let i = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "kirin_r1402_backend_{}_{}_{}",
            std::process::id(),
            i,
            "r177aud"
        ));
        let store = Arc::new(DirStore::open(&p).unwrap());
        let collect = Arc::new(R177Collect::default());
        let rt = RecordingTrigger::new();
        let b = DirBackend::new(
            store,
            Arc::new(test_key()),
            Arc::clone(&collect) as Arc<dyn AuditSink>,
            0,
        )
        .with_push_trigger(Arc::clone(&rt))
        .with_own_domain("a.test.relay");
        let id = Some(SELF_ID.to_string());
        let client = SocketAddr::new("127.0.0.1".parse().unwrap(), 40000);
        let mut dl = default_list();
        dl.refresh = true;
        let list = frame(kirin_desk_relay::protocol::TYPE_DIR_LIST, &dl);
        // 首刷：放行零节流行。
        let resp = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &list)
            .await
            .unwrap();
        let _ = unwrap_payload(resp);
        // 间隔内再刷：节流臂 = 专用审计行恰一行（携提交方地址）。
        let resp = b
            .handle_frame(client, id, kirin_desk_relay::protocol::TYPE_DIR_LIST, &list)
            .await
            .unwrap();
        let _ = unwrap_payload(resp);
        let got = collect.0.lock().unwrap();
        assert_eq!(
            got.iter().filter(|e| matches!(e, TunnelAuditEvent::DirRefreshThrottled { .. })).count(),
            1,
            "超频恰一行 DirRefreshThrottled"
        );
        assert!(
            got.iter().any(|e| matches!(e, TunnelAuditEvent::DirRefreshThrottled { client: c } if *c == client)),
        );
        cleanup(&p);
    }

    #[derive(Debug, Default)]
    struct R200Collect(std::sync::Mutex<Vec<TunnelAuditEvent>>);
    impl AuditSink for R200Collect {
        fn record(&self, e: TunnelAuditEvent) {
            self.0.lock().unwrap().push(e);
        }
    }

    /// 回填 [`DIRLIST_REFILL_PER_SEC`]/s）连发前 6 查放行、第 7 查（桶空）=
    /// 显式 `Busy` 错误帧 + `DirListThrottled` 审计恰一行；②scope=All 全表
    /// 查询逐查留痕 = `DirListAllQueried` 留痕行（携 rows 数，只属放行
    /// 路径）；③节流臂整帧拒（含 refresh 臂——超限连接不触发推送面）；
    /// ④Local/带 filter_device 查询 = 零全表留痕行；⑤独立会话互不牵连。
    #[tokio::test]
    async fn test_r200_dirlist_per_session_throttle_and_all_audit() {
        let i = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "kirin_r1402_backend_{}_{}_{}",
            std::process::id(),
            i,
            "r200aud"
        ));
        let store = Arc::new(DirStore::open(&p).unwrap());
        let collect = Arc::new(R200Collect::default());
        let b = DirBackend::new(
            store,
            Arc::new(test_key()),
            Arc::clone(&collect) as Arc<dyn AuditSink>,
            0,
        );
        let id = Some(SELF_ID.to_string());
        let client = SocketAddr::new("203.0.113.9".parse().unwrap(), 41000);
        let list_all = frame(
            kirin_desk_relay::protocol::TYPE_DIR_LIST,
            &default_list(),
        );
        // ① 令牌桶 burst=6：连发 6 查全放行，逐查全表留痕（rows=0 表空）。
        for n in 0..DIRLIST_BURST {
            let resp = b
                .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &list_all)
                .await
                .unwrap();
            let _ = unwrap_payload(resp);
            let got = collect.0.lock().unwrap();
            assert_eq!(
                got.iter().filter(|e| matches!(e, TunnelAuditEvent::DirListAllQueried { .. })).count(),
                n as usize + 1,
                "scope=All 放行查询逐查留痕 DirListAllQueried"
            );
        }
        {
            let got = collect.0.lock().unwrap();
            assert!(
                matches!(got.last(), Some(TunnelAuditEvent::DirListAllQueried { client: c, rows: 0 }) if *c == client),
                "留痕行携提交方地址与 rows 计数"
            );
        }
        // ② 桶空第 7 查 = Busy 错误帧 + DirListThrottled 恰一行。
        let resp = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &list_all)
            .await
            .unwrap();
        let err = decode_err(&unwrap_payload(resp));
        assert_eq!(err.code, DirErrorCode::Busy, "节流臂 = 显式 Busy 错误帧");
        {
            let got = collect.0.lock().unwrap();
            assert_eq!(
                got.iter().filter(|e| matches!(e, TunnelAuditEvent::DirListThrottled { .. })).count(),
                1,
                "超限恰一行 DirListThrottled"
            );
        }
        // ③ 节流臂整帧拒含 refresh 臂：桶空后的 refresh 查询不得触发推送面
        //    （无 push_trigger 挂载 = 无从触发；此处断言不再追加 All 留痕行）。
        let mut dl_ref = default_list();
        dl_ref.refresh = true;
        let list_ref = frame(kirin_desk_relay::protocol::TYPE_DIR_LIST, &dl_ref);
        let resp = b
            .handle_frame(client, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_LIST, &list_ref)
            .await
            .unwrap();
        let err = decode_err(&unwrap_payload(resp));
        assert_eq!(err.code, DirErrorCode::Busy, "超限查询连 refresh 臂一并拒");
        {
            let got = collect.0.lock().unwrap();
            assert_eq!(
                got.iter().filter(|e| matches!(e, TunnelAuditEvent::DirListAllQueried { .. })).count(),
                DIRLIST_BURST as usize,
                "节流行不再留痕全表查询（rows 行只属放行路径）"
            );
        }
        // ④ Local scope 放行（独立会话）= 零 DirListAllQueried 追加。
        let other = SocketAddr::new("203.0.113.9".parse().unwrap(), 41001);
        let mut dl_local = default_list();
        dl_local.scope = DirScope::Local;
        let list_local = frame(kirin_desk_relay::protocol::TYPE_DIR_LIST, &dl_local);
        let resp = b
            .handle_frame(other, id, kirin_desk_relay::protocol::TYPE_DIR_LIST, &list_local)
            .await
            .unwrap();
        let _ = unwrap_payload(resp);
        {
            let got = collect.0.lock().unwrap();
            assert_eq!(
                got.iter().filter(|e| matches!(e, TunnelAuditEvent::DirListAllQueried { .. })).count(),
                DIRLIST_BURST as usize,
                "Local scope 不产生全表留痕行（留痕行数不因本次查询增长）"
            );
            assert!(
                !got.iter().any(|e| matches!(e, TunnelAuditEvent::DirListThrottled { client: c } if *c == other)),
                "独立会话（不同 addr）不受他会话节流牵连"
            );
        }
        cleanup(&p);
    }

    /// 换配额键写入（旧键持行 → 新键 upsert）= `DirQuotaKeyMigrated` 恰
    /// 一行（from=旧键 to=新键）；③迁移后同键重写 = 零新增告警行；
    /// ④告警面零拦截——迁移行为本身照常受理（拦截只归既有配额执法）。
    #[tokio::test]
    async fn test_r202_quota_key_migration_audit_alert() {
        let i = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "kirin_r1402_backend_{}_{}_{}",
            std::process::id(),
            i,
            "r202keymig"
        ));
        let store = Arc::new(DirStore::open(&p).unwrap());
        let collect = Arc::new(R200Collect::default());
        let b = DirBackend::new(
            store,
            Arc::new(test_key()),
            Arc::clone(&collect) as Arc<dyn AuditSink>,
            0,
        );
        let id = Some(SELF_ID.to_string());
        let up = |ip: &str, port: u16, target: &str| {
            let client = SocketAddr::new(ip.parse().unwrap(), port);
            (
                client,
                frame(
                    kirin_desk_relay::protocol::TYPE_DIR_UPSERT,
                    &DirUpsert {
                        device_id: SELF_ID.into(),
                        domain: "alpha.example.com".into(),
                        target_domain: target.into(),
                        note: None,
                        ix_token: String::new(),
                    },
                ),
            )
        };
        let count_mig = |collect: &Arc<R200Collect>| {
            collect
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| matches!(e, TunnelAuditEvent::DirQuotaKeyMigrated { .. }))
                .count()
        };
        // ① 同键首写 = 零告警。
        let (c1, f1) = up("203.0.113.20", 41010, "b202a.test.relay");
        b.handle_frame(c1, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &f1)
            .await
            .unwrap();
        assert_eq!(count_mig(&collect), 0, "同键首写零告警");
        // 同键重写（幂等覆写同 target）= 零告警。
        let (c1, f1b) = up("203.0.113.20", 41010, "b202a.test.relay");
        b.handle_frame(c1, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &f1b)
            .await
            .unwrap();
        assert_eq!(count_mig(&collect), 0, "同键重写零告警");
        // ② 换键写入 = 恰一行告警（from=旧键 to=新键），且写入照常受理
        //    （owner_ip 末次写入者口径：该行配额归属随写迁移 = 换键续灌
        //    行为本体；单 target 场景迁移后旧键零残行）。
        let (c2, f2) = up("203.0.113.21", 41011, "b202a.test.relay");
        let out = b
            .handle_frame(c2, id.clone(), kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &f2)
            .await
            .unwrap();
        assert!(matches!(out, DirectoryFrameOutcome::Silent), "换键写入照常受理（告警面零拦截）");
        assert_eq!(count_mig(&collect), 1, "换键写入恰一行告警");
        {
            let got = collect.0.lock().unwrap();
            assert!(
                matches!(
                    got.iter().rev().find(|e| matches!(e, TunnelAuditEvent::DirQuotaKeyMigrated { .. })),
                    Some(TunnelAuditEvent::DirQuotaKeyMigrated { client, device_id, from_key, to_key })
                        if *client == c2 && device_id == SELF_ID
                            && from_key == "203.0.113.20" && to_key == "203.0.113.21"
                ),
                "告警行携 from=旧键 to=新键"
            );
        }
        // ③ 迁移完成后同键重写 = 零新增告警行（旧键行已随 ② 覆写迁移）。
        let (c2, f2b) = up("203.0.113.21", 41011, "b202a.test.relay");
        b.handle_frame(c2, id, kirin_desk_relay::protocol::TYPE_DIR_UPSERT, &f2b)
            .await
            .unwrap();
        assert_eq!(count_mig(&collect), 1, "迁移后同键重写零新增告警");
        cleanup(&p);
    }
}
