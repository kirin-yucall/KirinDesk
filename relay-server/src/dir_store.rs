//! v2 复合 PK + 推送补推队 + meta；schema v2，`PRAGMA user_version=2`）。
//!
//! （中继互联 token：B 侧 `tokens add` 权威登记 / A 侧设备表单上交的转发
//! 凭证缓存），v2→v3 原地建表零数据迁移。凭据口径修订：互联 token =
//! **白名单入库**（与既有 `--token` CLI 参数同保密级、与 relay.db
//! 同卷；`tokens list` 展示层一律脱敏前 8 位），其余凭据仍零入库。
//!
//! ZD-02 主项）：`ix_tokens` **cli 权威行哈希化**——B 侧门⑥只需比较不需
//! 还原，cli 行库内只存 `token_hash` = hex(sha256(token))（43 字符高熵
//! base64url 无字典面，无需加盐/KDF；摘要 = core/crypto 既有依赖面
//! `kirin_desk_core::connection::sha256_bytes`，零新原语），明文列对 cli
//! 行置 NULL（CHECK 约束执法）；`source='device'` 转发凭证缓存行按 C-6
//! 裁定**维持明文**（A 侧推送需原样取出转发）。v3→v4 = 建新表拷贝改名
//! 单事务迁移（逐行「读明文→算哈希→回写」，一次性）；门⑥比较域 =
//! 哈希（`ix_token_ct_state` 常时折算对哈希值复用，三态语义/reason 零
//! 变化）。`SCHEMA_V3_DDL` 冻结文本零触碰（历史对照），v4 DDL = 本卡
//! **重新冻结申报**。
//!
//! §2.4，**冻结面**：
//! - 三表 `device_directory`（复合 PK (device_id, target_domain)）/
//!   `push_outbox` / `meta`，schema v2 DDL 全量文本 = [`SCHEMA_V2_DDL`]
//!   （v1 DDL [`SCHEMA_V1_DDL`] 保留作迁移对照/历史冻结面）；
//! - `PRAGMA user_version` 门控迁移：v0→v2 全新 / v1→v2 四步幂等
//!   （DROP sync_peers / 清 meta peer:* 键保 epoch / v1 表改名保留不迁数
//!   据 / 建 v2 三表）；`user_version > 2` = 拒绝启动（fail-closed，
//!   不猜未来版本）；
//! - 库损坏 fail-closed：`PRAGMA quick_check` 不通过 → 改名
//!   `relay.db.corrupt-<unix ts>` **保留取证** + 重建空库 + 审计
//!   （`TunnelAuditEvent::DirDbCorruptRebuilt`）；**不静默丢数据**；
//!   改名失败 = 拒绝启动（取证保全优先）；
//!   元数据/配额键（IP 形态），设备登录 token、挑战码、私钥、会话密钥
//!   token（`ix_tokens` 表，见模块头增补说明）。
//!
//! 容量/性能：小表（用户录入 + 定向推送，量级百~千行）；**无全局行数
//! 上限**（v1 `MAX_DIRECTORY_ENTRIES=10000` 冻结废除，用户 a；防滥用面
//! = 单 IP 注册配额 §4〔写侧，[`DirStore::upsert_manual`] 事务内执法〕
//! 同一执法点：只拒新增不挤存量））；单写者（relay 主进
//! 程）；`journal_mode=WAL`（小库读多写少）。
//! 本模块**不含**签名逻辑（key 无关）：sig 由调用方（dir_backend /
//! interconnect，均持服务器密钥）计算后传入，本模块只做存储与裁决。
//!
//! - `upsert_manual`/`delete_manual` 扩 `own_domain` 参：本域成功变更且
//!   `target_domain != own_domain` 时**同事务**写 `push_outbox` 触发记录
//!   （已存在不重复，幂等）+ 更新 meta `devlast:<device_id>`（T8 liveness
//!   水位；target = 自域 = 无需推送，不入队）；
//! - 推送热路径访问器：`list_push_subset`（按接收方取声明式全量子集，
//!   pushed 行永不外推）/ `push_targets`（已知 target 集 = 自持行 ∪
//!   outbox）/ outbox 族（`outbox_due`/`outbox_prune_expired`/
//!   `outbox_register_failure`〔T4 退避单入口〕/`outbox_backoff_secs`/
//!   `outbox_clear`）；
//! - B 侧接收面：`apply_push_batch`（声明式单事务应用 = upsert +
//!   revocation-by-absence 缺行撤销 + P10 多源裁决 + `push:<fp>:{last_
//!   epoch,last_push}` 水位续约；temp 表承载批次 device 集规避 SQLite
//!   999 参数上限）+ `expired_push_sources`/`delete_pushed_by_source`
//!   （TTL 清扫）+ push 水位存取；
//! - A 侧 liveness：`liveness_stale_devices`/`delete_device_rows`（T8）。
//!
//! v1 pull 链存储面（`sync_peers` 访问器族 / `apply_peer_batch` /
//! （表随 v1→v2 迁移 DROP，§7）；裁决纯函数 `adjudicate_push_entry`
//! （v1 `adjudicate_push_entry` 更名，peer→pushed 对偶，规则/rank 零改）
//! 复用。

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row};
use thiserror::Error;
use tokio::sync::Mutex;

/// 与测试夹具用；**不再执行**）。
#[allow(dead_code)] // 本 build 仅迁移测试夹具引用（生产路径不执行 v1 DDL）
pub const SCHEMA_V1_DDL: &str = r#"
-- schema v1（PRAGMA user_version = 1；迁移 = 版本门控迁移函数, 岗内可定）
-- 容量/性能: 小表（用户录入+peer 同步, 量级百~千行）; 单写者（relay 主进程）;
-- journal_mode 默认即可, WAL 岗内可定。

CREATE TABLE IF NOT EXISTS device_directory (
  device_id   TEXT PRIMARY KEY,     -- 设备 ID; 存储归一化形态=完整 ID
                                    -- （短码/64hex 形态经既有判定 protocol.rs:104-140
                                    --   服务端归一; 短码不可展开 = 拒绝, fail-closed 不猜）
  domain      TEXT NOT NULL,        -- 设备域名, 纯 FQDN（不含 :port——端口恒走 SRV;
                                    --   形态校验复用 validate_node_server_addr host 段
                                    --   逻辑的纯函数族, 岗内定案; 非 FQDN = 拒）
  source      TEXT NOT NULL,        -- 'manual' | 'registered' | 'peer'
  peer_fp     TEXT,                 -- source='peer' 必填: 源 relay 79 字符指纹;
                                    -- source 在 manual/registered 时 NULL
  updated_at  INTEGER NOT NULL,     -- Unix 秒（写入方时钟; 冲突裁决用）
  sig         BLOB,                 -- 源 relay Ed25519 签名 over
                                    --   (device_id|domain|updated_at|source|peer_fp)
                                    --   peer 条目必填; manual/registered = relay 自签
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dd_domain  ON device_directory(domain);
CREATE INDEX IF NOT EXISTS idx_dd_updated ON device_directory(updated_at);

CREATE TABLE IF NOT EXISTS sync_peers (       -- 同步源（用户端可控面, §3e）
  domain     TEXT PRIMARY KEY,     -- 同步源 relay 域（纯 FQDN）
  pubkey     BLOB NOT NULL,        -- 该 relay Ed25519 公钥 32B（UI TOFU 确认值;
                                   -- 互认时与 DNS TXT 解析值交叉验证, 不符 = 拒 + WARN）
  fp         TEXT NOT NULL,        -- 79 字符指纹（展示 + 精确匹配）
  enabled    INTEGER NOT NULL DEFAULT 1,   -- 0 = 暂停同步（用户可控, 数据保留）
  note       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,          -- 'schema_version' | 'epoch'
                                    -- | 'peer:<fp>:last_sync' | 'peer:<fp>:last_epoch'
  value TEXT NOT NULL
);
"#;

/// **变更 = 库冻结面变更，须重新冻结。**
pub const SCHEMA_V2_DDL: &str = r#"
-- schema v2（PRAGMA user_version = 2；WAL；单写者 = relay 主进程；量级仍为百~千行小表）
CREATE TABLE IF NOT EXISTS device_directory (
  device_id      TEXT NOT NULL,      -- 设备 ID；存储归一化形态 = 完整 ID（短码/64hex 经既有判定归一，
                                      --   短码不可展开 = 拒，fail-closed 不猜——v1 口径继承）
  target_domain  TEXT NOT NULL,      -- 本行服务的目标中继域（纯 FQDN，不含 :port——端口恒走 SRV）；
                                      --   本中继自持 manual 行 = 被允许发现本设备的中继域（用户 c 的列表行）；
                                      --   pushed 行 = 本中继自身域（接收方，隐式语义，§1）
  device_domain  TEXT NOT NULL,      -- 设备自身 DNS 域（纯 FQDN；v1 device_directory.domain 更名）
  source         TEXT NOT NULL,      -- 'manual' | 'registered' | 'pushed'（v1 'peer' 值废，v2 不产生）
  source_fp      TEXT,               -- source='pushed' 必填：源 relay 79 字符指纹；manual/registered = NULL
  owner_ip       TEXT,               -- source='manual' 必填 = 末次写入客户端 IP 的**配额键形态**
                                      -- （IPv6 = /64 聚合前缀，§4.4；IPv4/IPv4-mapped = 原址）；
                                      -- pushed/registered = NULL（推送行不计入任何 IP 配额）
  note           TEXT NOT NULL DEFAULT '',   -- v1 受理不落库 → v2 落库
  updated_at     INTEGER NOT NULL,   -- Unix 秒（写入方时钟；裁决用）
                                      -- pushed = 批次条目 sig（entry_sig_message_v2，A 推送时新签）原样存储
  created_at     INTEGER NOT NULL,
  PRIMARY KEY (device_id, target_domain)     -- v1 PK(device_id) → v2 复合 PK（同设备允许多 target 行）
);
CREATE INDEX IF NOT EXISTS idx_dd_target  ON device_directory(target_domain);   -- 按接收方取子集（推送热路径）
CREATE INDEX IF NOT EXISTS idx_dd_updated ON device_directory(updated_at);
CREATE INDEX IF NOT EXISTS idx_dd_source  ON device_directory(source, source_fp); -- TTL 清扫 / 按源清行

CREATE TABLE IF NOT EXISTS push_outbox (      -- 推送方（A）接收方离线补推队（触发记录，不存载荷——
                                                -- 载荷 = 推送时现算声明式子集，天然自愈）
  id            INTEGER PRIMARY KEY,
  target_domain TEXT NOT NULL,
  enqueued_at   INTEGER NOT NULL,
  attempts      INTEGER NOT NULL DEFAULT 0,
  next_retry_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_po_target ON push_outbox(target_domain);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,      -- 'schema_version' | 'epoch'（本中继全局世代，本地行任一变更 +1）
                                -- | 'push:<fp>:last_epoch' | 'push:<fp>:last_push'（B 侧 per-source 水位/TTL 续约）
                                -- | 'devlast:<device_id>'（A 侧设备末次活跃水位，liveness 清扫用，§3.8）
  value TEXT NOT NULL
);
"#;

pub const SCHEMA_VERSION: i64 = 4;

/// 化）。`SCHEMA_V3_DDL` 冻结文本零触碰（历史对照/迁移夹具）；v3→v4 =
/// **建新表拷贝改名**（v3 `token` 列带 UNIQUE 隐式索引 = SQLite
/// `ALTER TABLE DROP COLUMN` 不可用，rusqlite bundled 3.45 同——卡内核实
/// 申报）。**变更 = 库冻结面变更，须重新冻结（本卡申报）。**
///
/// hex(sha256(token))，**全行** NOT NULL UNIQUE（cli 行 = 门⑥比较域；
/// device 行同串同哈希 = 既有 UNIQUE 判重域从明文平移到哈希，语义不变）；
/// `token` 明文列仅 `source='device'` 行保留（C-6 裁定边界），cli 行 =
/// NULL，两列互斥由 CHECK 约束执法（代码面另有写入执法）。
pub const SCHEMA_V4_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS ix_tokens (
  id            INTEGER PRIMARY KEY,   -- CLI 句柄（tokens revoke <id>；tokens list 展示）
  token         TEXT,                  -- 明文（仅 source='device' 转发凭证缓存行；
  token_hash    TEXT NOT NULL UNIQUE,  -- hex(sha256(token))（全行；门⑥比较域/UNIQUE 判重域）
  token_prefix  TEXT NOT NULL,         -- 前 8 字符（tokens list 脱敏展示用）
  label         TEXT NOT NULL,         -- 管理员备注（tokens add --label 必填）
  source        TEXT NOT NULL CHECK(source IN ('cli','device')),
                                       -- 'cli' = 本机权威登记（门⑥唯一校验源）；
                                       -- 'device' = 设备表单上交的转发凭证缓存（A 侧推送时携带）
  target_domain TEXT,                  -- 'device' 行必填 = 推送目标域；'cli' 行 = NULL（对本机全部入站推送生效）
  created_at    INTEGER NOT NULL,      -- Unix 秒
  revoked_at    INTEGER,               -- 软撤销水位（NULL = 活跃；撤销即时生效 = 下次推送被拒）
);
CREATE INDEX IF NOT EXISTS idx_ix_source_target ON ix_tokens(source, target_domain);
"#;

/// `SCHEMA_V2_DDL` 冻结文本零触碰，本 DDL 只含**新增**表/索引——v2→v3 =
/// 原地建表零数据迁移）。**变更 = 库冻结面变更，须重新冻结。**
///
/// `--token` CLI 参数同保密级、与 relay.db 同卷；`tokens list` 一律脱敏）；
/// 其余凭据（设备登录 token/挑战码/私钥/会话密钥）仍零入库。
pub const SCHEMA_V3_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS ix_tokens (
  id            INTEGER PRIMARY KEY,   -- CLI 句柄（tokens revoke <id>；tokens list 展示）
  token         TEXT NOT NULL UNIQUE,  -- 全明文（B 侧权威登记 / A 侧转发凭证缓存）
  token_prefix  TEXT NOT NULL,         -- 前 8 字符（tokens list 脱敏展示用）
  label         TEXT NOT NULL,         -- 管理员备注（tokens add --label 必填）
  source        TEXT NOT NULL CHECK(source IN ('cli','device')),
                                       -- 'cli' = 本机权威登记（门⑥唯一校验源）；
                                       -- 'device' = 设备表单上交的转发凭证缓存（A 侧推送时携带）
  target_domain TEXT,                  -- 'device' 行必填 = 推送目标域；'cli' 行 = NULL（对本机全部入站推送生效）
  created_at    INTEGER NOT NULL,      -- Unix 秒
  revoked_at    INTEGER                -- 软撤销水位（NULL = 活跃；撤销即时生效 = 下次推送被拒）
);
CREATE INDEX IF NOT EXISTS idx_ix_source_target ON ix_tokens(source, target_domain);
"#;

/// 发现条目）：服务端侧每 `device_id` 条目上限（与客户端
/// `utils::config::NODES_MAX_ENTRIES` 同值——双侧执法、值单一口径）。
/// 执法点 = [`DirStore::upsert_manual`] 写事务内（与单 IP 注册配额同风格）：
/// 既有 (device_id, target_domain) 行 = 幂等重写不增量；pushed 行
/// （他中继定向推送行，非设备自持发现条目）不计；超限**只拒新增，
/// 不静默挤掉最旧条目**（存量保留，fail-closed 显式
/// [`DirStoreError::DeviceLimitExceeded`]）。
pub const MAX_DEVICE_DIR_ENTRIES: usize = 15;

/// 来源常量（冻结口径；`source_rank` 数值 = P10 冲突裁决权重）。
/// `'peer'` 值）。
pub const SOURCE_MANUAL: &str = "manual";
pub const SOURCE_REGISTERED: &str = "registered";
pub const SOURCE_PUSHED: &str = "pushed";

/// P10 冲突裁决权重：`manual`(3) > `registered`(2) > `pushed`(1)。
/// 未知来源 = 0（只读防御，正常路径不产生）。
pub fn source_rank(source: &str) -> u8 {
    match source {
        SOURCE_MANUAL => 3,
        SOURCE_REGISTERED => 2,
        SOURCE_PUSHED => 1,
        _ => 0,
    }
}

/// = [`DirStore::ix_token_cli_state`]）。输入 = `(token, active)` 全量
/// 行侧 = 库内 `token_hash`，提交侧 = `hex(sha256(提交串))`；函数本体
/// 对哈希值原样复用零改动）；**长度不等 = 先置 diff 计数再继续遍历（不
/// 提前出口）**——避免逐行长度短路泄漏提交串长度信息（64 字符定长哈希
/// 场景恒等长，仍按规范写）；等长行 = `kirin_desk_relay::auth::
/// constant_time_eq` 逐行常时折算（单源实现，零新比较逻辑）。返回
/// `(三态, 长度不等行数)`：命中行任一 = `Some(active)`（`token_hash`
/// UNIQUE 约束下多行同串不可达）；无命中 = `None`。
fn ix_token_ct_state(rows: &[(String, bool)], submitted: &[u8]) -> (Option<bool>, usize) {
    let mut len_skips = 0usize;
    let mut state: Option<bool> = None;
    for (tok, active) in rows {
        let t = tok.as_bytes();
        if t.len() != submitted.len() {
            len_skips += 1; // 先置 diff 计数，继续遍历（不短路出口）
            continue;
        }
        if kirin_desk_relay::auth::constant_time_eq(t, submitted) {
            state = Some(*active);
        }
    }
    (state, len_skips)
}

/// 冲突裁决结果（P10 纯函数输出；单测全矩阵钉死）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adjudication {
    /// 本地无同 device_id 条目 → 插入（pushed 条目落库，source=pushed）。
    Insert,
    /// 新条目胜出 → 覆盖（pushed vs pushed：ts 新者胜 / ts 相等源指纹字典序小者胜）。
    Replace,
    /// 存量条目胜出 → 保留（manual/registered 恒遮蔽 pushed；pushed 旧 ts 保留）。
    KeepExisting,
}

/// `adjudicate_push_entry`（peer→pushed 更名复用，§7.2），规则/rank 零改）。
///
/// 入参 `existing` = 本地同 device_id 存量条目的 `(source, updated_at,
/// source_fp)`（无存量 = `None`）；入参恒为 **pushed 来源**新条目（本
/// 裁决只发生在推送落库路径，manual/registered 写入不经此函数）。
///
/// 规则（P10，逐条对表设计）：
/// 1. `manual` > 任何 pushed（本地权威；pushed 被遮蔽，不物理删）；
/// 2. `registered` > `pushed`（本域自识权威）；
/// 3. `pushed` vs `pushed`：`updated_at` 新者胜（last-writer-wins）；
///    ts 相等 = **源指纹字典序小者胜**（确定性）。
pub fn adjudicate_push_entry(
    existing: Option<(&str, u64, &str)>,
    incoming_ts: u64,
    incoming_fp: &str,
) -> Adjudication {
    let Some((src, ts, fp)) = existing else {
        return Adjudication::Insert;
    };
    // 规则 1/2：高权重来源恒遮蔽 pushed 条目（与 ts 无关——本地权威优先）。
    if source_rank(src) > source_rank(SOURCE_PUSHED) {
        return Adjudication::KeepExisting;
    }
    // 规则 3：pushed vs pushed（存量源为 pushed 或未知 0 权来源，同按 pushed 档处理）。
    if incoming_ts > ts {
        return Adjudication::Replace;
    }
    if incoming_ts < ts {
        return Adjudication::KeepExisting;
    }
    // ts 相等：源指纹字典序（byte-wise）小者胜。incoming_fp == fp 视为同源自洽。
    if incoming_fp < fp {
        Adjudication::Replace
    } else {
        Adjudication::KeepExisting
    }
}

/// 目录条目行 v2（存储形态；复合 PK (device_id, target_domain)；
/// `source_fp`/`owner_ip`/`sig` 的 `None` = SQL NULL）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirRow {
    pub device_id: String,
    /// 本行服务的目标中继域（manual = 被允许发现本设备的中继域；
    /// pushed = 本中继自身域）。
    pub target_domain: String,
    /// 设备自身 DNS 域（v1 `domain` 更名）。
    pub device_domain: String,
    pub source: String,
    /// source='pushed' 必填：源 relay 79 字符指纹；manual/registered = NULL。
    pub source_fp: Option<String>,
    /// source='manual' 必填 = 末次写入客户端 IP 的配额键形态（IPv6 /64
    /// 聚合前缀；IPv4/IPv4-mapped = 原址）；pushed/registered = NULL。
    pub owner_ip: Option<String>,
    /// 备注（v1 受理不落库 → v2 落库）。
    pub note: String,
    pub updated_at: u64,
    pub sig: Option<Vec<u8>>,
    pub created_at: u64,
}

/// replace；逐字节等价重放 = 幂等 no-op 不计〕；`removed` = revocation-
/// by-absence 删除数〔该源既有 pushed 行中不在本批次者〕；`skipped` =
/// 本地权威遮蔽/他源裁决胜出跳过数——无独立裁决事件行，计数并入
#[derive(Debug, Default)]
pub struct PushApplyResult {
    /// 批次条目数（接收方视角，含幂等重放/遮蔽跳过）。
    pub entries_in: usize,
    pub applied: usize,
    pub removed: usize,
    pub skipped: usize,
}

/// 子集，天然自愈，§2.4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    pub target_domain: String,
    pub enqueued_at: u64,
    pub attempts: u64,
    pub next_retry_at: u64,
}

#[derive(Debug, Error)]
pub enum DirStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("db corrupt rename failed (forensic preservation): {0}")]
    CorruptRebuildFailed(String),
    #[error("unsupported schema version {0} (want {SCHEMA_VERSION}) — refusing to start")]
    UnsupportedSchemaVersion(i64),
    /// distinct device 数 / 配额值；只拒新增不清存量）。替代 v1
    /// `LimitExceeded`（10k 全局上限废）。
    #[error("ip quota exceeded: {used}/{limit} distinct devices for this quota key")]
    QuotaExceeded { used: usize, limit: usize },
    /// 自持行数 / [`MAX_DEVICE_DIR_ENTRIES`]；只拒新增不挤存量——**不静默
    /// 删除最旧条目**）。帧面映射 = `DirErrorCode::QuotaExceeded`（wire
    /// 六码冻结零改；超限语义同类位）。
    #[error("device entry limit exceeded: {used}/{limit} entries for this device")]
    DeviceLimitExceeded { used: usize, limit: usize },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}


    /// ix_tokens 行（存储形态；`token`/`target_domain`/`revoked_at` 的
    /// NULL，仅 `token_hash` 在库）——`Some` 只出现在（a）device 缓存行
    /// 读取、（b）`ix_add_cli_token` 的**内存回执**（`tokens add` 全量
    /// 收紧为「device 行明文 + cli 行哈希」。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IxTokenRow {
        pub id: i64,
        /// 明文（device 行读取 / cli 行仅 add 内存回执；cli 行库读 = None）。
        pub token: Option<String>,
        /// 前 8 字符（`tokens list` 脱敏展示；落库冗余 = 展示单源）。
        pub token_prefix: String,
        pub label: String,
        /// `'cli'`（本机权威登记）/ `'device'`（转发凭证缓存）。
        pub source: String,
        /// 'device' 行必填 = 推送目标域；'cli' 行 = None。
        pub target_domain: Option<String>,
        pub created_at: u64,
        /// None = 活跃；Some(ts) = 软撤销水位。
        pub revoked_at: Option<u64>,
    }

    fn ix_prefix_of(token: &str) -> String {
        token.chars().take(8).collect()
    }

    /// = core/crypto 既有依赖面（`kirin_desk_core::connection::sha256_bytes`
    /// 单源复用，零新 crypto 原语）；token = 43 字符高熵 base64url 无字典
    /// 面，无需加盐/KDF（卡面裁定申报）。
    fn ix_token_hash_hex(token: &str) -> String {
        kirin_desk_core::connection::sha256_bytes(token.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn row_to_ix_token(row: &Row) -> rusqlite::Result<IxTokenRow> {
        // 列序 = 冻结序：id, token, token_prefix, label, source,
        Ok(IxTokenRow {
            id: row.get(0)?,
            token: row.get(1)?,
            token_prefix: row.get(2)?,
            label: row.get(3)?,
            source: row.get(4)?,
            target_domain: row.get(5)?,
            created_at: row.get::<_, i64>(6)? as u64,
            revoked_at: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
        })
    }

    const IX_COLUMNS: &str =
        "id, token, token_prefix, label, source, target_domain, created_at, revoked_at";

    impl DirStore {
        /// B 侧权威登记（`tokens add`）：生成方 CLI 调用；token 已由调用方
        /// 写 `token_hash` = hex(sha256(token))（明文列 = NULL，cli 行零
        /// 明文）；返回行 = **内存回执**（`token` = Some，全量仅此一次打印
        /// 语义不变）。UNIQUE 冲突（重复 add 同一 token 串 = 同哈希命中
        /// `token_hash` UNIQUE）= 显式错误（token 恒现场随机生成，冲突 =
        /// 程序缺陷，不静默吞）。
        pub async fn ix_add_cli_token(
            &self,
            token: &str,
            label: &str,
            now: u64,
        ) -> Result<IxTokenRow, DirStoreError> {
            let conn = self.conn.lock().await;
            conn.execute(
                "INSERT INTO ix_tokens(token_hash, token_prefix, label, source, target_domain, created_at, revoked_at)
                 VALUES(?1, ?2, ?3, 'cli', NULL, ?4, NULL)",
                params![ix_token_hash_hex(token), ix_prefix_of(token), label, now as i64],
            )?;
            let id = conn.last_insert_rowid();
            Ok(IxTokenRow {
                id,
                token: Some(token.to_string()),
                token_prefix: ix_prefix_of(token),
                label: label.to_string(),
                source: "cli".to_string(),
                target_domain: None,
                created_at: now,
                revoked_at: None,
            })
        }

        /// 全量列表（`tokens list`；id 升序）。**含全量 token 字段**——
        /// 脱敏是展示层职责（CLI 只打前缀），存储返回不裁剪。
        pub async fn ix_list_tokens(&self) -> Result<Vec<IxTokenRow>, DirStoreError> {
            let conn = self.conn.lock().await;
            let mut stmt = conn.prepare(&format!(
                "SELECT {IX_COLUMNS} FROM ix_tokens ORDER BY id"
            ))?;
            let it = stmt.query_map([], row_to_ix_token)?;
            Ok(it.collect::<rusqlite::Result<Vec<_>>>()?)
        }

        /// 软撤销（`tokens revoke <id>`；行保留，`revoked_at` 置位）。
        /// 返回 false = id 不存在**或**已撤销（幂等语义；CLI 先查行区分
        /// 两种报错文案）。撤销即时生效 = 下次推送门⑥查无活跃行即拒。
        pub async fn ix_revoke_token(&self, id: i64, now: u64) -> Result<bool, DirStoreError> {
            let conn = self.conn.lock().await;
            let n = conn
                .execute(
                    "UPDATE ix_tokens SET revoked_at = ?2 WHERE id = ?1 AND revoked_at IS NULL",
                    params![id, now as i64],
                )?;
            Ok(n == 1)
        }

        /// 按 id 取行（CLI revoke 前置存在性检查；None = 不存在）。
        pub async fn ix_get_token(&self, id: i64) -> Result<Option<IxTokenRow>, DirStoreError> {
            let conn = self.conn.lock().await;
            let mut stmt = conn.prepare(&format!(
                "SELECT {IX_COLUMNS} FROM ix_tokens WHERE id = ?1"
            ))?;
            stmt.query_row(params![id], row_to_ix_token)
                .optional()
                .map_err(DirStoreError::Sqlite)
        }

        /// A 侧转发凭证缓存 upsert（`handle_dir_upsert` 收到带 token 的
        /// DirUpsert 时调用）：同 target_domain 既有 device 行**全删后插入**
        /// （last-writer-wins——home 对单 target 只能携带一个 token）。
        /// 空 token 由调用方拦截（= 显式清除既有缓存行，`ix_clear_device_token`）。
        /// + `token_hash` 同步入库；UNIQUE 判重域从明文列平移到哈希列——
        /// 缓存串恰为本机 cli 权威行（或他 device 行同串）= 同哈希命中
        /// `token_hash` UNIQUE = 显式错误不覆盖权威行；调用方审计 WARN +
        pub async fn ix_upsert_device_token(
            &self,
            target_domain: &str,
            token: &str,
            label: &str,
            now: u64,
        ) -> Result<(), DirStoreError> {
            let conn = self.conn.lock().await;
            Self::with_tx(&conn, |conn| {
                conn.execute(
                    "DELETE FROM ix_tokens WHERE source = 'device' AND target_domain = ?1",
                    params![target_domain],
                )?;
                conn.execute(
                    "INSERT INTO ix_tokens(token, token_hash, token_prefix, label, source, target_domain, created_at, revoked_at)
                     VALUES(?1, ?2, ?3, ?4, 'device', ?5, ?6, NULL)",
                    params![token, ix_token_hash_hex(token), ix_prefix_of(token), label, target_domain, now as i64],
                )?;
                Ok(())
            })
        }

        /// A 侧凭证缓存清除（设备重交表单 token 为空 = 显式撤回转发凭证，
        /// 该 target 推送自此 fail-closed 跳过直至重新提交 token）。
        pub async fn ix_clear_device_token(&self, target_domain: &str) -> Result<usize, DirStoreError> {
            let conn = self.conn.lock().await;
            Ok(conn.execute(
                "DELETE FROM ix_tokens WHERE source = 'device' AND target_domain = ?1",
                params![target_domain],
            )?)
        }

        /// 门⑥（B 侧）三态查询：`Some(true)` = 命中**本机 cli 权威活跃行**
        /// （受理）；`Some(false)` = 命中但已撤销（拒 + revoked 审计语义）；
        /// `None` = 无此 cli 行（含 device 行——设备缓存行**永不**作为门⑥
        /// 凭据：本机 device 行是他中继签发的转发凭证，非本机签发凭据）。
        ///
        /// 全量取行（活跃 + 撤销行；`WHERE source='cli'`，行数量级 = 管理
        /// 员手加的个位数）→ 内存中逐行 [`ix_token_ct_state`] 常时折算
        /// （`kirin_desk_relay::auth::constant_time_eq` 单源）。**存储面
        /// SQL 等值比较（SQLite B-tree 字节比较 = 非常时）废除**；三态
        /// 语义与拒收矩阵（缺 token/已撤销/不匹配独立 reason）零变化。
        ///
        /// `token_hash`（cli 行库内零明文），提交串先算
        /// `hex(sha256(提交串))` 再与行哈希逐行常时比较（[`ix_token_ct_state`]
        /// 行 + 长度差行计数不短路）；哈希化只改存储形态不改认证语义——
        /// 三态/reason 串逐字节零变化。空串提交 = sha256("") 定长 hex 常量
        /// 与真实行哈希恒不等 = `None`（与既有空串四态断言逐一对齐）。
        pub async fn ix_token_cli_state(&self, token: &str) -> Result<Option<bool>, DirStoreError> {
            let conn = self.conn.lock().await;
            let mut stmt = conn.prepare(
                "SELECT token_hash, (revoked_at IS NULL) FROM ix_tokens WHERE source = 'cli'",
            )?;
            let rows: Vec<(String, bool)> = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)))?
                .collect::<Result<Vec<_>, _>>()?;
            let submitted = ix_token_hash_hex(token);
            let (state, len_skips) = ix_token_ct_state(&rows, submitted.as_bytes());
            if len_skips > 0 {
                tracing::debug!(
                    "ix_token_cli_state: {len_skips} length-mismatch row(s) folded into constant-time scan"
                );
            }
            Ok(state)
        }

        /// A 侧推送取 token（`push_one`：按 target 查活跃 device 缓存行，
        /// 最新一条；None = 该 target 本轮跳过推送 + WARN 审计，fail-closed
        /// 不推裸批）。
        pub async fn ix_lookup_device_token(
            &self,
            target_domain: &str,
        ) -> Result<Option<String>, DirStoreError> {
            let conn = self.conn.lock().await;
            let tok: Option<String> = conn
                .query_row(
                    "SELECT token FROM ix_tokens
                     WHERE source = 'device' AND target_domain = ?1 AND revoked_at IS NULL
                     ORDER BY id DESC LIMIT 1",
                    params![target_domain],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(tok)
        }
    }

    /// 当前 unix 秒（存储时钟口径：写入方本地时钟，§2.4 `updated_at` 注释）。
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn row_to_dir(row: &Row) -> rusqlite::Result<DirRow> {
    // 列序 = 各 SELECT 冻结序：
    // device_id, target_domain, device_domain, source, source_fp, owner_ip,
    // note, updated_at, sig, created_at
    let sig: Option<Vec<u8>> = row.get(8)?;
    Ok(DirRow {
        device_id: row.get(0)?,
        target_domain: row.get(1)?,
        device_domain: row.get(2)?,
        source: row.get(3)?,
        source_fp: row.get(4)?,
        owner_ip: row.get(5)?,
        note: row.get(6)?,
        updated_at: row.get::<_, i64>(7)? as u64,
        sig,
        created_at: row.get::<_, i64>(9)? as u64,
    })
}

const DIR_COLUMNS: &str =
    "device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at";

/// relay 侧目录存储（单写者；所有方法经同一 `tokio::sync::Mutex` 串行化）。
///
/// 本结构**不持有**任何密钥/凭据——签名由调用方算好传入（凭据零入库红线
/// 的存储侧兜底）。
///
/// 起事务内自增持久，同库重启不回退）；辅存 = [`Self::with_epoch_sidecar`]
/// 挂接的 sidecar 文件（生产 = server key 同卷 sibling，**不随 relay.db
/// 消失**）——换库/重装/损坏重建后启动期 [`Self::epoch_highwater_sync`]
/// 需自然追平）。sidecar 缺失/损坏/写失败均 best-effort 退回现状语义。
pub struct DirStore {
    conn: Mutex<Connection>,
    path: PathBuf,
    /// 形态逐位一致——单测/CLI 短事务默认不挂接）。
    epoch_sidecar: Option<PathBuf>,
}

impl std::fmt::Debug for DirStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirStore").field("path", &self.path).finish()
    }
}

/// 打开结果（`rebuilt` = true 时调用方必须审计 `DirDbCorruptRebuilt`）。
#[derive(Debug)]
pub struct DirStoreOpen {
    pub store: DirStore,
    /// true = 原库损坏，已改名保留取证并重建空库。
    pub rebuilt: bool,
}

// `set_private_permissions` 为 no-op 永不失败，注入臂保证 fail-open
// 语义在所有平台可断言）。生产构建零痕迹。
#[cfg(test)]
thread_local! {
    static INJECT_TIGHTEN_FAIL: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

impl DirStore {
    /// 打开（或创建）目录库（§2.4 fail-closed 全集）：
    /// 1. 文件不存在 → 新建 + v0→v4 迁移；
    /// 2. 只读 `PRAGMA quick_check` 通过 → 正常打开（迁移幂等重放 DDL）；
    /// 3. quick_check 失败 / 只读打开失败 = **损坏** → 改名
    ///    `<path>.corrupt-<unix ts>` 保留取证（改名失败 = 直接拒绝启动）
    ///    + 重建空库 + 置 `rebuilt`（调用方 WARN + 审计）；
    /// 4. `PRAGMA user_version > 4` → [`DirStoreError::UnsupportedSchemaVersion`]
    ///    拒绝启动（不猜未来版本，fail-closed）。
    ///
    /// sync_peers / 清 meta peer:* 键保 epoch / v1 表改名
    /// `device_directory_v1_retired` 保留取证**不迁数据**〔v1 行无
    /// target_domain 语义，迁移 = 猜数据，fail-closed 不猜〕/ 建 v2 三表）；
    /// `ix_tokens` 建新表拷贝改名（cli 行哈希化，单事务逐行回写）；迁移
    /// 失败 = 拒启动。
    /// 主进程并发写承接（SQLite WAL 单写者，短事务等锁后重试）。
    pub fn open_ex(path: &Path) -> Result<DirStoreOpen, DirStoreError> {
        let mut rebuilt = false;
        if path.exists() {
            match Self::quick_check_ok(path) {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    // 损坏：改名保留取证（失败 = 拒绝启动，不静默丢数据）。
                    let ts = now_unix_secs();
                    let forensic = path
                        .file_name()
                        .map(|n| n.to_os_string())
                        .unwrap_or_else(|| "relay.db".into())
                        .to_string_lossy()
                        .trim()
                        .to_string();
                    let forensic_name = format!("{forensic}.corrupt-{ts}");
                    let forensic_path = path
                        .parent()
                        .map(|p| p.join(&forensic_name))
                        .unwrap_or_else(|| PathBuf::from(forensic_name));
                    std::fs::rename(path, &forensic_path).map_err(|e| {
                        DirStoreError::CorruptRebuildFailed(format!(
                            "cannot preserve corrupt db at {:?}: {e}",
                            path
                        ))
                    })?;
                    rebuilt = true;
                }
            }
        }
        // 目录不存在则创建（~/.kirin_desk 常规存在；容器卷路径同）。
        let parent_pre_existed = path
            .parent()
            .map(|p| !p.as_os_str().is_empty() && p.exists())
            .unwrap_or(true);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
                if !parent_pre_existed {
                    if let Err(e) = kirin_desk_utils::fsutil::tighten_dir_private(parent) {
                        tracing::warn!(
                            dir = %parent.display(),
                            error = %e,
                        );
                    }
                }
            }
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        let _ = conn.busy_timeout(std::time::Duration::from_millis(5_000));
        Self::migrate(&conn)?;
        // WAL（岗内定案）：小库读多写少；best-effort（内存库等场景可忽略失败）。
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        // fsutil::set_private_permissions，免疫 umask 0644 世界可读；
        // best-effort fail-open：内存库/特殊卷/只读目录场景**不拒启**，
        // 失败仅 WARN + 交由审计）。Windows 无 std ACL API（零新依赖红线，
        // 不引 windows-rs/不启 icacls 子进程）→ 纯启动 WARN + README 部署
        // 红线收口（取舍如实申报：探测臂放弃，见 relay-server/README.md）。
        // WAL 伴生文件（relay.db-wal/-shm）同目录随库同卷，权限口径见 README。
        Self::tighten_db_file_perms(path);
        if cfg!(windows) {
            tracing::warn!(
                db = %path.display(),
            );
        }
        let store = DirStore {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
            epoch_sidecar: None,
        };
        Ok(DirStoreOpen { store, rebuilt })
    }

    /// 便捷打开（**仅单测**；损坏重建标志被忽略——生产路径必须用
    /// [`Self::open_ex`] 以便审计 `rebuilt`）。
    #[cfg(test)]
    pub fn open(path: &Path) -> Result<DirStore, DirStoreError> {
        Ok(Self::open_ex(path)?.store)
    }

    /// 链式调用）。生产 = server key 同卷 sibling `<key>.epoch_hw`——
    /// sidecar 归属**签名身份**（对端门③水位按 source fp 记账），库换
    /// （relay.db 丢失/重装/重建）身份不换 → 水位不丢。
    pub fn with_epoch_sidecar(mut self, path: PathBuf) -> Self {
        self.epoch_sidecar = Some(path);
        self
    }

    fn epoch_sidecar_read(path: &Path) -> Option<u64> {
        std::fs::read_to_string(path).ok()?.trim().parse::<u64>().ok()
    }

    /// 落后一格的代价 = 退回自然追平现状，不拒启不阻断写路径）。
    fn epoch_sidecar_write(&self, v: u64) {
        if let Some(p) = &self.epoch_sidecar {
            if let Err(e) = std::fs::write(p, format!("{v}\n")) {
                tracing::warn!(
                    path = %p.display(),
                    error = %e,
                );
            }
        }
    }

    /// conn 锁/处于写事务内）。sidecar 在 COMMIT 前回写 = 领先 DB 属
    /// **安全方向**（事务回滚 → sidecar 略高 → floor 只抬不降，凭空
    /// 跳号 = 对端门③ `==/>` 声明式幂等受理面，无序问题）。
    fn epoch_bump_locked(&self, conn: &Connection) -> Result<u64, DirStoreError> {
        let v = Self::bump_epoch_unlocked(conn)?;
        self.epoch_sidecar_write(v);
        Ok(v)
    }

    /// 由 [`Self::epoch_highwater_sync`] 调用）。单语句 upsert：无行 =
    /// 直落 floor；有行 = `MAX(现值, floor)`（含 garbage 行 CAST=0 修复
    /// 面，与 [`Self::get_epoch`] parse 失败兜底 0 同口径）。返回生效值。
    pub async fn floor_epoch(&self, floor: u64) -> Result<u64, DirStoreError> {
        let conn = self.conn.lock().await;
        let v = Self::floor_epoch_unlocked(&conn, floor)?;
        self.epoch_sidecar_write(v);
        Ok(v)
    }

    fn floor_epoch_unlocked(conn: &Connection, floor: u64) -> Result<u64, DirStoreError> {
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('epoch', ?1)
             ON CONFLICT(key) DO UPDATE SET value = MAX(CAST(value AS INTEGER), CAST(?1 AS INTEGER))",
            params![floor.to_string()],
        )?;
        let s: String =
            conn.query_row("SELECT value FROM meta WHERE key = 'epoch'", [], |r| r.get(0))?;
        Ok(s.parse::<i64>()
            .map_err(|_| DirStoreError::Sqlite(rusqlite::Error::InvalidQuery))?
            as u64)
    }

    /// 生产在 server key 挂接后、互联引擎启动前调用一次）。返回
    /// `(生效 epoch, 是否发生 floor 抬升)`：
    /// - sidecar > DB（换库/重装/损坏重建）→ DB floor 抬至 sidecar
    ///   （自愈：对端 stale epoch 拒收即刻解除，无需自然追平）；
    /// - sidecar ≤ DB 或缺失/损坏（常态/引导）→ sidecar 抬至
    ///   `max(sidecar, DB)`（只升不降；首次挂接 = 引导落盘）。
    pub async fn epoch_highwater_sync(&self) -> Result<(u64, bool), DirStoreError> {
        let db = self.get_epoch().await?;
        let hw = self
            .epoch_sidecar
            .as_deref()
            .and_then(Self::epoch_sidecar_read);
        Ok(match hw {
            Some(hw) if hw > db => {
                let v = self.floor_epoch(hw).await?;
                (v, true)
            }
            _ => {
                self.epoch_sidecar_write(hw.unwrap_or(0).max(db));
                (db, false)
            }
        })
    }

    /// 不拒启（可用性优先；与 S-07 密钥 0600 强约束分级：密钥强、数据弱化）。
    /// 单测可经 [`INJECT_TIGHTEN_FAIL`] 注入失败路径（跨平台可测，含 Windows）。
    fn tighten_db_file_perms(path: &Path) {
        #[cfg(test)]
        let res: std::io::Result<()> = {
            if INJECT_TIGHTEN_FAIL.with(std::cell::Cell::get) {
            } else {
                kirin_desk_utils::fsutil::set_private_permissions(path)
            }
        };
        #[cfg(not(test))]
        let res = kirin_desk_utils::fsutil::set_private_permissions(path);
        if let Err(e) = res {
            tracing::warn!(
                db = %path.display(),
                error = %e,
            );
        }
    }

    /// 批量预填本域行（**仅单测/微基准**：读路径基准数据准备，单事务填充；
    /// 生产数据路径恒走 `upsert_manual`）。
    #[cfg(test)]
    pub async fn prefill_local_test(&self, n: usize) -> Result<(), DirStoreError> {
        let conn = self.conn.lock().await;
        conn.execute_batch("BEGIN")?;
        let mut stmt = conn.prepare(
            "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
             VALUES(?1, 'b.test.relay', ?2, 'manual', NULL, NULL, '', 1,
                    X'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f', 1)",
        )?;
        for i in 0..n {
            stmt.execute(params![format!("dev-{i:06}"), format!("d{i}.example.com")])?;
        }
        conn.execute_batch("COMMIT")?;
        Ok(())
    }

    /// 只读 quick_check（fail-closed 损坏判定）：打开失败或结果非单行 "ok"
    /// 均视为损坏。
    fn quick_check_ok(path: &Path) -> Result<bool, DirStoreError> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| DirStoreError::Sqlite(rusqlite::Error::QueryReturnedNoRows))?;
        let rows: Vec<String> = conn
            .prepare("PRAGMA quick_check")
            .and_then(|mut s| {
                let it = s.query_map([], |r| r.get::<_, String>(0))?;
                Ok(it.collect::<rusqlite::Result<Vec<_>>>()?)
            })
            .map_err(DirStoreError::Sqlite)?;
        Ok(rows.len() == 1 && rows[0] == "ok")
    }

    /// 版本门控迁移（幂等）。v0→v4 全新（ix_tokens 直落 v4 形态）/
    /// v1→v2 四步（设计 §2.4 逐条）→ v3 ix_tokens → v4 哈希化 /
    /// `user_version > 4` = 拒启动。
    fn migrate(conn: &Connection) -> Result<(), DirStoreError> {
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(DirStoreError::UnsupportedSchemaVersion(version));
        }
        match version {
            0 => {
                // ix_tokens 直落 v4 形态（SCHEMA_V3_DDL 的 v3 形态表不建
                // ——尾部队列幂等重放对在位表 = IF NOT EXISTS 零副作用）。
                conn.execute_batch(SCHEMA_V2_DDL)?;
                conn.execute_batch(SCHEMA_V4_DDL)?;
                conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '4')",
                    [],
                )?;
            }
            1 => {
                // v1→v2 四步幂等迁移（单事务：任一步失败 = 整段回滚，
                // 下次启动可重试——各步 IF EXISTS/LIKE 幂等）。
                Self::with_tx(conn, |conn| {
                    // 1) DROP TABLE sync_peers（机制废除，§7）。
                    conn.execute_batch("DROP TABLE IF EXISTS sync_peers")?;
                    // 2) meta 'peer:<fp>:*' 键全清；'epoch' 保留续用（连续性）。
                    conn.execute("DELETE FROM meta WHERE key LIKE 'peer:%'", [])?;
                    // 3) v1 目录表改名保留取证（**不迁数据**——v1 行无
                    //    target_domain 语义，迁移 = 猜数据，fail-closed 不猜；
                    //    v2 行由客户端登录对账重建，§3.7）。条件执行 =
                    //    幂等（已迁移库无 v1 表）。
                    let has_v1: bool = conn
                        .query_row(
                            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'device_directory'",
                            [],
                            |r| {
                                let n: i64 = r.get(0)?;
                                Ok(n > 0)
                            },
                        )?;
                    if has_v1 {
                        conn.execute_batch(
                            "ALTER TABLE device_directory RENAME TO device_directory_v1_retired",
                        )?;
                    }
                    conn.execute_batch(SCHEMA_V2_DDL)?;
                    conn.execute_batch(SCHEMA_V3_DDL)?;
                    Ok(())
                })?;
                // 纯 DDL 形态升级；幂等守卫内含）。
                Self::migrate_ix_tokens_v3_to_v4(conn)?;
                conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '4')",
                    [],
                )?;
            }
            2 => {
                // ——v2 三表原样保留零触碰）。
                Self::with_tx(conn, |conn| {
                    conn.execute_batch(SCHEMA_V3_DDL)?;
                    Ok(())
                })?;
                Self::migrate_ix_tokens_v3_to_v4(conn)?;
                conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '4')",
                    [],
                )?;
            }
            3 => {
                // 明文→算哈希→回写」一次性，明文列置 NULL；device 行明文
                // 保留）。迁移失败 = 整段回滚、版本不推进 = 拒动下一轮
                // （fail-closed 无半程态）。
                Self::migrate_ix_tokens_v3_to_v4(conn)?;
                conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '4')",
                    [],
                )?;
            }
            _ => {} // 已 v4：幂等重放 DDL（IF NOT EXISTS 零副作用）。
        }
        conn.execute_batch(SCHEMA_V2_DDL)?;
        conn.execute_batch(SCHEMA_V3_DDL)?;
        conn.execute_batch(SCHEMA_V4_DDL)?;
        Ok(())
    }

    /// 建新表拷贝改名：v3 `token` 列带 UNIQUE 隐式索引，SQLite
    /// `ALTER TABLE DROP COLUMN` 对索引列不可用（rusqlite bundled 3.45
    /// 卡内核实）——12 步改名舞的标准收窄形态。步骤：v3 表改名留证 →
    /// 建 v4 新表（`token_hash` UNIQUE + cli 行零明文 CHECK）→ 逐行
    /// 「读明文 → 算哈希 → 回写」（cli 行明文置 NULL，device 行明文保留，
    /// 撤销水位/标签/前缀/id 原样）→ DROP v3 表。任一步失败 = 整段回滚
    /// （版本不推进，下次启动重试；无半程态）。幂等守卫 = `token_hash`
    /// 列存在性探测（已 v4 形态 = 零操作）。行数量级 = 管理员手加 cli 行
    /// + device 缓存行（个位数~十位数），逐行回写无性能面。
    fn migrate_ix_tokens_v3_to_v4(conn: &Connection) -> Result<(), DirStoreError> {
        let has_table: bool = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ix_tokens'",
            [],
            |r| {
                let n: i64 = r.get(0)?;
                Ok(n > 0)
            },
        )?;
        if !has_table {
            return Ok(()); // 守卫：v3 表不在位（理论上不可达）= 零操作。
        }
        let already_v4: bool = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('ix_tokens') WHERE name = 'token_hash'",
            [],
            |r| {
                let n: i64 = r.get(0)?;
                Ok(n > 0)
            },
        )?;
        if already_v4 {
            return Ok(()); // 已 v4 形态 = 幂等零操作。
        }
        Self::with_tx(conn, |conn| {
            // 1) v3 表改名留证（事务内，最终 DROP——失败整体回滚无残留）。
            //    其上的 idx_ix_source_target 随改名仍占用索引名，先 DROP
            //    让位（新表 DDL 内同名 IF NOT EXISTS 重建）。
            conn.execute_batch(
                "ALTER TABLE ix_tokens RENAME TO ix_tokens_v3_retired;
                 DROP INDEX IF EXISTS idx_ix_source_target;",
            )?;
            // 2) 建 v4 新表（含索引）。
            conn.execute_batch(SCHEMA_V4_DDL)?;
            // 3) 逐行「读明文 → 算哈希 → 回写」（一次性；cli 行明文置 NULL）。
            let mut stmt = conn.prepare(
                "SELECT id, token, token_prefix, label, source, target_domain, created_at, revoked_at
                 FROM ix_tokens_v3_retired",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, i64>(6)?,
                        r.get::<_, Option<i64>>(7)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            for (id, token, prefix, label, source, target_domain, created_at, revoked_at) in rows {
                let plaintext = if source == "device" {
                    Some(token.as_str())
                } else {
                    None
                };
                conn.execute(
                    "INSERT INTO ix_tokens(id, token, token_hash, token_prefix, label, source, target_domain, created_at, revoked_at)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        id,
                        plaintext,
                        ix_token_hash_hex(&token),
                        prefix,
                        label,
                        source,
                        target_domain,
                        created_at,
                        revoked_at
                    ],
                )?;
            }
            // 4) v3 表退役（取证列 = 迁移前数据已在 v4 表逐行承载；改名
            //    留证仅为事务内迁移载体，DROP 收口——与 v1 表永久留证
            //    「不迁数据」口径不同：本表数据已全量迁移）。
            conn.execute_batch("DROP TABLE ix_tokens_v3_retired")?;
            Ok(())
        })
    }

    /// autocommit 降为一次提交/fsync；闭包内任一错误 = 整段 ROLLBACK 无半写，
    /// 连接保持可用）。调用方须已持 `conn` 锁（所有入口经
    /// `Mutex<Connection>` 单写者串行化，`busy` 竞争窗口同步收缩）。
    fn with_tx<F, T>(conn: &Connection, f: F) -> Result<T, DirStoreError>
    where
        F: FnOnce(&Connection) -> Result<T, DirStoreError>,
    {
        // BEGIN IMMEDIATE = 写事务立获锁（单写者串行化下无升级死锁面）。
        conn.execute_batch("BEGIN IMMEDIATE")?;
        match f(conn) {
            Ok(v) => {
                conn.execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                // 整段回滚无半写（BEGIN 未生效时 ROLLBACK 自失败，忽略）。
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    // ── device_directory（v2 复合 PK） ─────────────────────────────────

    /// 直插 pushed 行（**仅单测**夹具；生产 pushed 行恒由
    /// `apply_push_batch` 声明式单事务写入，本直插仅供测试面）。
    #[cfg(test)]
    pub async fn insert_pushed_test(
        &self,
        device_id: &str,
        target_domain: &str,
        device_domain: &str,
        source_fp: &str,
        updated_at: u64,
        sig: Vec<u8>,
    ) -> Result<(), DirStoreError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, NULL, '', ?6, ?7, ?8)",
            params![
                device_id,
                target_domain,
                device_domain,
                SOURCE_PUSHED,
                source_fp,
                updated_at,
                sig,
                now_unix_secs()
            ],
        )?;
        Ok(())
    }

    /// 条目总数（**仅单测**）。
    #[cfg(test)]
    pub async fn count(&self) -> Result<usize, DirStoreError> {
        let conn = self.conn.lock().await;
        Ok(conn.query_row("SELECT COUNT(*) FROM device_directory", [], |r| {
            r.get::<_, i64>(0)
        })? as usize)
    }

    /// 素材（换键续灌检测用只读查询；不含本次键 = 空 = 无迁移）。
    /// 仅 `source='manual'` 行计入（pushed 行 owner_ip NULL 天然排除）。
    pub async fn distinct_other_owner_keys(
        &self,
        device_id: &str,
        this_key: &str,
    ) -> Result<Vec<String>, DirStoreError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT DISTINCT owner_ip FROM device_directory
             WHERE device_id = ?1 AND source = 'manual'
               AND owner_ip IS NOT NULL AND owner_ip != ?2
             ORDER BY owner_ip",
        )?;
        let rows = stmt.query_map(params![device_id, this_key], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 按 scope 列表（`DirScope` v2 语义见 relay protocol：All = 全表
    /// （本地+pushed）/ Local = 本中继自持行（source≠pushed）/ Peer(fp)
    /// = 来源 fp 的 pushed 行）+ 可选 `filter_device`（Some = 仅该设备行）。
    /// 排序冻结：`ORDER BY device_id, target_domain`。
    pub async fn list(
        &self,
        scope: DirListScope,
        filter_device: Option<&str>,
    ) -> Result<Vec<DirRow>, DirStoreError> {
        let conn = self.conn.lock().await;
        // 冻结读序：恒 `ORDER BY device_id, target_domain`（客户端列表稳定序；
        // 子句序钉死 SELECT…FROM…WHERE…ORDER BY，各分支只拼 WHERE 片段）。
        let (head, where_sql) = match (&scope, filter_device) {
            (DirListScope::All, None) => (
                format!("SELECT {} FROM device_directory", DIR_COLUMNS),
                String::new(),
            ),
            (DirListScope::All, Some(_)) => (
                format!("SELECT {} FROM device_directory", DIR_COLUMNS),
                " WHERE device_id = ?1".to_string(),
            ),
            (DirListScope::Local, None) => (
                format!("SELECT {} FROM device_directory", DIR_COLUMNS),
                " WHERE source != ?1".to_string(),
            ),
            (DirListScope::Local, Some(_)) => (
                format!("SELECT {} FROM device_directory", DIR_COLUMNS),
                " WHERE source != ?1 AND device_id = ?2".to_string(),
            ),
            (DirListScope::Peer(_), None) => (
                format!("SELECT {} FROM device_directory", DIR_COLUMNS),
                " WHERE source = ?1 AND source_fp = ?2".to_string(),
            ),
            (DirListScope::Peer(_), Some(_)) => (
                format!("SELECT {} FROM device_directory", DIR_COLUMNS),
                " WHERE source = ?1 AND source_fp = ?2 AND device_id = ?3".to_string(),
            ),
        };
        let sql = format!("{head}{where_sql} ORDER BY device_id, target_domain");
        // 惯用法钉死（同 quick_check_ok）：QueryMap 经 `let` 绑定再 collect
        // （链式临时量在此作用域下借用期不够——E0597）。
        let rows: Vec<DirRow> = match (&scope, filter_device) {
            (DirListScope::All, None) => {
                let mut s = conn.prepare(&sql)?;
                let it = s.query_map([], row_to_dir)?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            }
            (DirListScope::All, Some(dev)) => {
                let mut s = conn.prepare(&sql)?;
                let it = s.query_map(params![dev], row_to_dir)?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            }
            (DirListScope::Local, None) => {
                let mut s = conn.prepare(&sql)?;
                let it = s.query_map(params![SOURCE_PUSHED], row_to_dir)?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            }
            (DirListScope::Local, Some(dev)) => {
                let mut s = conn.prepare(&sql)?;
                let it = s.query_map(params![SOURCE_PUSHED, dev], row_to_dir)?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            }
            (DirListScope::Peer(fp), None) => {
                let mut s = conn.prepare(&sql)?;
                let it = s.query_map(params![SOURCE_PUSHED, fp], row_to_dir)?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            }
            (DirListScope::Peer(fp), Some(dev)) => {
                let mut s = conn.prepare(&sql)?;
                let it = s.query_map(params![SOURCE_PUSHED, fp, dev], row_to_dir)?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        Ok(rows)
    }

    /// 取单条（复合 PK (device_id, target_domain)）。
    #[allow(dead_code)] // 本 build 生产路径走 list()；单测/对账面引用
    pub async fn get(
        &self,
        device_id: &str,
        target_domain: &str,
    ) -> Result<Option<DirRow>, DirStoreError> {
        let conn = self.conn.lock().await;
        let row: Option<DirRow> = conn
            .query_row(
                &format!(
                    "SELECT {} FROM device_directory WHERE device_id = ?1 AND target_domain = ?2",
                    DIR_COLUMNS
                ),
                params![device_id, target_domain],
                row_to_dir,
            )
            .optional()?;
        Ok(row)
    }

    /// **本方法事务内**）：
    ///
    /// - `owner_ip` = 配额键形态（IPv4 原址 / IPv4-mapped 归一 IPv4 /
    ///   IPv6 /64 前缀；由 dir_backend `quota_key_for_ip` 纯函数归一后
    ///   传入）——**末次写入者口径**：每次 upsert 覆写（设备换 IP = 配额
    ///   归属迁移，旧键计数 −1、新键 +1）；
    /// - 配额判定（`ip_quota_limit` 0 = 不限）：`used` = 该键下
    ///   `COUNT(DISTINCT device_id)`；本次 device_id **已** ∈ 该集合
    ///   （同 IP 同设备再加 target / 改 domain）= 不增量放行；新设备且
    ///   `used >= 配额` → [`DirStoreError::QuotaExceeded`]（**只拒新增
    ///   不清存量**，v1 limit 口径继承）；pushed/registered 行
    ///   （owner_ip NULL）不计；
    ///   `dev_used` = 该 device_id 自持行（source ≠ pushed）计数；既有
    ///   (device_id, target_domain) 行 = 幂等重写不增量；新 target 且
    ///   `dev_used >= 上限` → [`DirStoreError::DeviceLimitExceeded`]
    ///   （**只拒新增不挤最旧**——不静默删存量，客户端先删再加）；
    /// - 复合 PK 冲突 (device_id, target_domain) = 就地 UPDATE
    ///   （source 恒回 manual、source_fp 清 NULL、note/ts/sig 覆写）；
    /// - 成功 = epoch +1；
    ///   面〕）：`Some(own) && target_domain != own` 时**同事务**写
    ///   `push_outbox` 触发记录（`NOT EXISTS` 幂等：已存在不重复、不刷
    ///   重试态——退避状态归调度器）+ 返回 `enqueued=true`（`push outbox
    ///   enqueued` 审计素材）；`devlast:<device_id>=now` 水位每次 upsert
    ///   更新（T8 liveness 清扫判据，§3.8）；
    /// - 返回 `(used_after, enqueued)`（`used_after` = 配额水位，审计行
    ///   素材）。
    pub async fn upsert_manual(
        &self,
        device_id: &str,
        target_domain: &str,
        device_domain: &str,
        note: &str,
        owner_ip: &str,
        updated_at: u64,
        sig: Vec<u8>,
        ip_quota_limit: usize,
        own_domain: Option<&str>,
    ) -> Result<(usize, bool), DirStoreError> {
        let conn = self.conn.lock().await;
        let now = now_unix_secs();
        Self::with_tx(&conn, |conn| {
            // 配额检查（事务内、与 owner_ip 计数同事务读；单写者串行下
            // 无竞态，§4.2 执法点）。
            let used: i64 = conn.query_row(
                "SELECT COUNT(DISTINCT device_id) FROM device_directory WHERE owner_ip = ?1",
                params![owner_ip],
                |r| r.get(0),
            )?;
            let used = used as usize;
            let same: i64 = conn.query_row(
                "SELECT COUNT(*) FROM device_directory WHERE device_id = ?1 AND owner_ip = ?2",
                params![device_id, owner_ip],
                |r| r.get(0),
            )?;
            if same == 0 && ip_quota_limit != 0 && used >= ip_quota_limit {
                return Err(DirStoreError::QuotaExceeded {
                    used,
                    limit: ip_quota_limit,
                });
            }
            // `dev_used` = 该 device_id 自持行（source ≠ pushed——pushed 行
            // = 他中继定向推送行，非设备自持发现条目，不计）；既有
            // (device_id, target_domain) 行 = 幂等重写不增量；超限只拒新增
            // （**不静默挤掉最旧条目**，存量保留）。
            let dev_used: i64 = conn.query_row(
                "SELECT COUNT(*) FROM device_directory WHERE device_id = ?1 AND source != ?2",
                params![device_id, SOURCE_PUSHED],
                |r| r.get(0),
            )?;
            let dev_used = dev_used as usize;
            let same_target: i64 = conn.query_row(
                "SELECT COUNT(*) FROM device_directory WHERE device_id = ?1 AND target_domain = ?2",
                params![device_id, target_domain],
                |r| r.get(0),
            )?;
            if same_target == 0 && dev_used >= MAX_DEVICE_DIR_ENTRIES {
                return Err(DirStoreError::DeviceLimitExceeded {
                    used: dev_used,
                    limit: MAX_DEVICE_DIR_ENTRIES,
                });
            }
            conn.execute(
                "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
                 VALUES(?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(device_id, target_domain) DO UPDATE SET
                   device_domain=excluded.device_domain,
                   source=excluded.source,
                   source_fp=NULL,
                   owner_ip=excluded.owner_ip,
                   note=excluded.note,
                   updated_at=excluded.updated_at,
                   sig=excluded.sig",
                params![
                    device_id,
                    target_domain,
                    device_domain,
                    SOURCE_MANUAL,
                    owner_ip,
                    note,
                    updated_at,
                    sig,
                    now
                ],
            )?;
            // 本域成功写入 → epoch +1（推送批次携带；B 侧 per-source 水位依据）。
            self.epoch_bump_locked(conn)?;
            // 单语句自增式幂等，无行/有行同覆盖）。
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![format!("devlast:{device_id}"), now.to_string()],
            )?;
            // target = 自域 = 无需推送，不入队）。
            let mut enqueued = false;
            if let Some(own) = own_domain {
                if target_domain != own {
                    let n = conn.execute(
                        "INSERT INTO push_outbox(target_domain, enqueued_at, attempts, next_retry_at)
                         SELECT ?1, ?2, 0, ?2
                         WHERE NOT EXISTS (SELECT 1 FROM push_outbox WHERE target_domain = ?1)",
                        params![target_domain, now],
                    )?;
                    enqueued = n > 0;
                }
            }
            // 水位回读（used_after，审计 `quota={used}/{limit}` 素材）。
            let used_after: i64 = conn.query_row(
                "SELECT COUNT(DISTINCT device_id) FROM device_directory WHERE owner_ip = ?1",
                params![owner_ip],
                |r| r.get(0),
            )?;
            Ok((used_after as usize, enqueued))
        })
    }

    /// 删除本中继自持行 (device_id, target_domain)（source ∈
    /// manual/registered）。**只删自持行**——目标仅以 pushed 形态存在
    /// （B 上的 (D,B) 行）= `Ok(false)` **不跨源删**（设计 §2.2：只能
    /// 由 A 的推送批次删除）。无此行同样 `Ok(false)`。
    ///
    /// target_domain != own` 时**同事务**写 outbox 触发记录（幂等同
    /// `upsert_manual` 口径）——撤销经声明式缺行批次传播（T2）。
    /// 返回 `(deleted, enqueued)`。
    pub async fn delete_manual(
        &self,
        device_id: &str,
        target_domain: &str,
        own_domain: Option<&str>,
    ) -> Result<(bool, bool), DirStoreError> {
        let conn = self.conn.lock().await;
        let now = now_unix_secs();
        Self::with_tx(&conn, |conn| {
            let n = conn.execute(
                "DELETE FROM device_directory
                 WHERE device_id = ?1 AND target_domain = ?2 AND source != ?3",
                params![device_id, target_domain, SOURCE_PUSHED],
            )?;
            let mut enqueued = false;
            if n > 0 {
                if let Some(own) = own_domain {
                    if target_domain != own {
                        let k = conn.execute(
                            "INSERT INTO push_outbox(target_domain, enqueued_at, attempts, next_retry_at)
                             SELECT ?1, ?2, 0, ?2
                             WHERE NOT EXISTS (SELECT 1 FROM push_outbox WHERE target_domain = ?1)",
                            params![target_domain, now],
                        )?;
                        enqueued = k > 0;
                    }
                }
            }
            Ok((n > 0, enqueued))
        })
    }


    /// 对接收方 `target_domain` 的**声明式全量子集**（推送热路径，§1/§2.3）：
    /// 本中继自持行（source ≠ pushed，`pushed` 行永不外推——防放大/无
    /// 传递信任）中 `target_domain` 命中者。排序冻结 `ORDER BY device_id`
    /// （= `batch_sig_v2` 冻结序，批次构造零重排）。
    pub async fn list_push_subset(&self, target_domain: &str) -> Result<Vec<DirRow>, DirStoreError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(&format!(
            "SELECT {} FROM device_directory
             WHERE target_domain = ?1 AND source != ?2
             ORDER BY device_id",
            DIR_COLUMNS
        ))?;
        let it = stmt.query_map(params![target_domain, SOURCE_PUSHED], row_to_dir)?;
        Ok(it.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 已知推送 target 集（`device_directory` 自持行 distinct target ∪
    /// `push_outbox` targets，去重升序——T2 撤销后 dir 行消失，outbox 行
    /// 保住 target 直至成功推送 superseded 剪除）。
    pub async fn push_targets(&self) -> Result<Vec<String>, DirStoreError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT target_domain FROM (
                 SELECT target_domain FROM device_directory WHERE source != ?1
                 UNION
                 SELECT target_domain FROM push_outbox
             ) ORDER BY target_domain",
        )?;
        let it = stmt.query_map(params![SOURCE_PUSHED], |r| r.get::<_, String>(0))?;
        Ok(it.collect::<rusqlite::Result<Vec<_>>>()?)
    }


    /// 到期待重试行（`next_retry_at <= now`，target 升序）。
    pub async fn outbox_due(&self, now: u64) -> Result<Vec<OutboxRow>, DirStoreError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT target_domain, enqueued_at, attempts, next_retry_at
             FROM push_outbox WHERE next_retry_at <= ?1 ORDER BY target_domain",
        )?;
        let it = stmt.query_map(params![now], |r| {
            Ok(OutboxRow {
                target_domain: r.get(0)?,
                enqueued_at: r.get::<_, i64>(1)? as u64,
                attempts: r.get::<_, i64>(2)? as u64,
                next_retry_at: r.get::<_, i64>(3)? as u64,
            })
        })?;
        Ok(it.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 剪除超龄行（`enqueued_at < now - ttl`，周期重推是真正恢复通道，
    /// 队列只服务短离线，T4）→ 逐 target `(target, n)`（升序）。
    pub async fn outbox_prune_expired(
        &self,
        now: u64,
        ttl: u64,
    ) -> Result<Vec<(String, usize)>, DirStoreError> {
        let conn = self.conn.lock().await;
        let threshold = now.saturating_sub(ttl);
        Self::with_tx(&conn, |conn| {
            let mut stmt = conn.prepare(
                "SELECT target_domain, COUNT(*) FROM push_outbox
                 WHERE enqueued_at < ?1 GROUP BY target_domain ORDER BY target_domain",
            )?;
            let groups = {
                let it = stmt.query_map(params![threshold], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
                })?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            };
            conn.execute("DELETE FROM push_outbox WHERE enqueued_at < ?1", params![threshold])?;
            Ok(groups)
        })
    }

    /// outbox 退避秒数（T4 冻结口径：首败 +30s / 二败 +2min / 三败起
    /// +10min cap；纯函数，单测钉死）。
    pub fn outbox_backoff_secs(attempts: u64) -> u64 {
        match attempts {
            1 => 30,
            2 => 120,
            _ => 600,
        }
    }

    /// 推送失败：该 target 退避登记（T4 **单入口**，写钩子行与失败行同一
    /// 口径）：
    /// - 行不存在 → 新入队（attempts=1，`next_retry_at=now+30s`）→ `(1, true)`
    ///   （`true` = 调用方发 `push outbox enqueued` 审计）；
    /// - 行已存在（写入时触发记录或历史失败行）→ `attempts+1` + 只刷
    ///   `next_retry_at`（幂等，不重复入队）→ `(a, false)`。
    /// 返回值 `(attempts, inserted)`。
    pub async fn outbox_register_failure(
        &self,
        target_domain: &str,
        now: u64,
    ) -> Result<(u64, bool), DirStoreError> {
        let conn = self.conn.lock().await;
        Self::with_tx(&conn, |conn| {
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM push_outbox WHERE target_domain = ?1",
                params![target_domain],
                |r| r.get(0),
            )?;
            if exists > 0 {
                let a: i64 = conn.query_row(
                    "SELECT attempts FROM push_outbox WHERE target_domain = ?1",
                    params![target_domain],
                    |r| r.get(0),
                )?;
                let next = (a.max(0) + 1) as u64;
                conn.execute(
                    "UPDATE push_outbox SET attempts = ?2, next_retry_at = ?3
                     WHERE target_domain = ?1",
                    params![
                        target_domain,
                        next as i64,
                        now.saturating_add(Self::outbox_backoff_secs(next)) as i64
                    ],
                )?;
                Ok((next, false))
            } else {
                conn.execute(
                    "INSERT INTO push_outbox(target_domain, enqueued_at, attempts, next_retry_at)
                     VALUES(?1, ?2, 1, ?3)",
                    params![
                        target_domain,
                        now as i64,
                        (now.saturating_add(Self::outbox_backoff_secs(1))) as i64
                    ],
                )?;
                Ok((1, true))
            }
        })
    }

    /// 成功推送 = 该 target 全部行剪除（superseded：声明式全量已送达，
    /// 队列内旧触发记录全部被覆盖，T4）→ 剪除数。
    pub async fn outbox_clear(&self, target_domain: &str) -> Result<usize, DirStoreError> {
        let conn = self.conn.lock().await;
        let n = conn.execute(
            "DELETE FROM push_outbox WHERE target_domain = ?1",
            params![target_domain],
        )?;
        Ok(n)
    }


    /// B 侧声明式批次应用（**单事务**，§2.3 应用步逐条）：
    /// 1. 逐条 upsert `(device_id, target_domain=本域, source=pushed,
    ///    source_fp=源 fp, sig 原样存储)`；
    /// 2. PK 碰撞本地自持行（manual/registered）= **跳过**（本地权威遮蔽，
    ///    幂等 no-op，无事件）；
    /// 3. 同源逐字节等价重放 = 幂等 no-op；跨源同设备 = P10 裁决
    ///    （[`adjudicate_push_entry`]：ts-LWW + fp 字典序）；
    /// 4. **revocation-by-absence**：本源既有 pushed 行中不在本批次者
    ///    = 删除（撤销/下线唯一传播通道，只触本源行，空批次 = 全撤销态）；
    /// 5. 水位续约 `push:<fp>:{last_epoch,last_push}`（TTL 基准）。
    ///
    /// 批次 device 集经 **temp 表** 承载（单参数逐行插入，规避 SQLite
    /// 999 参数上限——per-source cap 10000 量级）；temp DDL 事务化，
    /// 失败整段 ROLLBACK 无半写。`entries` = `(device_id, device_domain,
    /// updated_at, sig)`（调用方已过受理门 5 项，§2.3）。
    pub async fn apply_push_batch(
        &self,
        source_fp: &str,
        my_domain: &str,
        epoch: u64,
        entries: &[(String, String, u64, Vec<u8>)],
    ) -> Result<PushApplyResult, DirStoreError> {
        let conn = self.conn.lock().await;
        let now = now_unix_secs();
        Self::with_tx(&conn, |conn| {
            let mut res = PushApplyResult {
                entries_in: entries.len(),
                ..Default::default()
            };
            conn.execute(
                "CREATE TEMP TABLE _push_batch_ids(device_id TEXT PRIMARY KEY)",
                [],
            )?;
            let mut ins = conn.prepare("INSERT OR IGNORE INTO _push_batch_ids(device_id) VALUES(?1)")?;
            for (id, _, _, _) in entries {
                ins.execute(params![id])?;
            }
            for (device_id, domain, updated_at, sig) in entries {
                let existing: Option<DirRow> = conn
                    .query_row(
                        &format!(
                            "SELECT {} FROM device_directory WHERE device_id = ?1 AND target_domain = ?2",
                            DIR_COLUMNS
                        ),
                        params![device_id, my_domain],
                        row_to_dir,
                    )
                    .optional()?;
                if let Some(e) = &existing {
                    // 本地权威遮蔽（manual/registered 恒胜 pushed，与 ts 无关）。
                    if e.source != SOURCE_PUSHED {
                        res.skipped += 1;
                        continue;
                    }
                    let same_source = e.source_fp.as_deref() == Some(source_fp);
                    // 同源逐字节等价重放 = 幂等 no-op（不写不裁决）。
                    if same_source
                        && e.device_domain == *domain
                        && e.updated_at == *updated_at
                        && e.sig == Some(sig.clone())
                    {
                        continue;
                    }
                    if !same_source {
                        // 跨源同设备冲突 = P10 裁决（ts-LWW + fp 字典序）。
                        let outcome = adjudicate_push_entry(
                            Some((
                                e.source.as_str(),
                                e.updated_at,
                                e.source_fp.as_deref().unwrap_or(""),
                            )),
                            *updated_at,
                            source_fp,
                        );
                        if outcome == Adjudication::KeepExisting {
                            res.skipped += 1;
                            continue;
                        }
                    }
                    // 同源刷新 / 跨源 Replace：覆写（created_at 保持首入时刻）。
                    conn.execute(
                        "UPDATE device_directory SET device_domain = ?3, source = ?4,
                          source_fp = ?5, updated_at = ?6, sig = ?7
                         WHERE device_id = ?1 AND target_domain = ?2",
                        params![device_id, my_domain, domain, SOURCE_PUSHED, source_fp, updated_at, sig],
                    )?;
                    res.applied += 1;
                } else {
                    conn.execute(
                        "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
                         VALUES(?1, ?2, ?3, ?4, ?5, NULL, '', ?6, ?7, ?8)",
                        params![device_id, my_domain, domain, SOURCE_PUSHED, source_fp, updated_at, sig, now],
                    )?;
                    res.applied += 1;
                }
            }
            // revocation-by-absence（只触本源行；空批次 = 本源全删）。
            res.removed = conn.execute(
                "DELETE FROM device_directory
                 WHERE source = ?1 AND source_fp = ?2 AND target_domain = ?3
                   AND device_id NOT IN (SELECT device_id FROM _push_batch_ids)",
                params![SOURCE_PUSHED, source_fp, my_domain],
            )?;
            conn.execute("DROP TABLE _push_batch_ids", [])?;
            // 水位续约（TTL 基准；与行变更同事务，无半程态）。
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![format!("push:{source_fp}:last_epoch"), epoch.to_string()],
            )?;
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![format!("push:{source_fp}:last_push"), now.to_string()],
            )?;
            Ok(res)
        })
    }

    /// B 侧 pushed 行 TTL 超龄源（`push:<fp>:last_push < threshold` 且
    /// 仍有行）→ `(fp, 行数)`（fp 升序）。
    pub async fn expired_push_sources(&self, threshold: u64) -> Result<Vec<(String, usize)>, DirStoreError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT d.source_fp, COUNT(*) FROM device_directory d
             JOIN meta m ON m.key = 'push:' || d.source_fp || ':last_push'
             WHERE d.source = ?1 AND d.source_fp IS NOT NULL
               AND CAST(m.value AS INTEGER) < ?2
             GROUP BY d.source_fp ORDER BY d.source_fp",
        )?;
        let it = stmt.query_map(params![SOURCE_PUSHED, threshold], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as usize))
        })?;
        Ok(it.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 清单一源全部 pushed 行 + `push:<fp>:*` 水位键（单事务；
    /// `push source expired` 审计素材 = 返回行数）。
    pub async fn delete_pushed_by_source(&self, source_fp: &str) -> Result<usize, DirStoreError> {
        let conn = self.conn.lock().await;
        Self::with_tx(&conn, |conn| {
            let n = conn.execute(
                "DELETE FROM device_directory WHERE source = ?1 AND source_fp = ?2",
                params![SOURCE_PUSHED, source_fp],
            )?;
            conn.execute(
                "DELETE FROM meta WHERE key = ?1 OR key = ?2",
                params![
                    format!("push:{source_fp}:last_epoch"),
                    format!("push:{source_fp}:last_push")
                ],
            )?;
            Ok(n)
        })
    }


    /// liveness 候选设备（自持行存在 且 `devlast:<id>` 缺失或
    /// `< threshold`；device_id 升序）。活体判定（registry 在线）由
    /// 调用方探针过滤（§3.8「且 D 不在当前注册表」）。
    pub async fn liveness_stale_devices(&self, threshold: u64) -> Result<Vec<String>, DirStoreError> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT DISTINCT d.device_id FROM device_directory d
             LEFT JOIN meta m ON m.key = 'devlast:' || d.device_id
             WHERE d.source != ?1 AND (m.value IS NULL OR CAST(m.value AS INTEGER) < ?2)
             ORDER BY d.device_id",
        )?;
        let it = stmt.query_map(params![SOURCE_PUSHED, threshold], |r| r.get::<_, String>(0))?;
        Ok(it.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 删除设备**全部**自持行（source ≠ pushed；pushed 行不跨源删）→
    /// 被删行的 target 列表（升序，撤销推送 target + 审计素材）；
    /// n > 0 = epoch +1（同事务）。
    pub async fn delete_device_rows(&self, device_id: &str) -> Result<Vec<String>, DirStoreError> {
        let conn = self.conn.lock().await;
        Self::with_tx(&conn, |conn| {
            let mut stmt = conn.prepare(
                "SELECT target_domain FROM device_directory
                 WHERE device_id = ?1 AND source != ?2 ORDER BY target_domain",
            )?;
            let targets = {
                let it = stmt.query_map(params![device_id, SOURCE_PUSHED], |r| {
                    r.get::<_, String>(0)
                })?;
                it.collect::<rusqlite::Result<Vec<_>>>()?
            };
            let n = conn.execute(
                "DELETE FROM device_directory WHERE device_id = ?1 AND source != ?2",
                params![device_id, SOURCE_PUSHED],
            )?;
            if n > 0 {
            }
            Ok(targets)
        })
    }

    // ── push 水位（B 侧 per-source） ───────────────────────────────────

    /// `push:<fp>:last_epoch`（B 侧 epoch 水位；`None` = 该源从未受理）。
    pub async fn get_push_last_epoch(&self, fp: &str) -> Result<Option<u64>, DirStoreError> {
        Ok(self
            .get_meta(&format!("push:{fp}:last_epoch"))
            .await?
            .and_then(|v| v.parse::<u64>().ok()))
    }

    /// `push:<fp>:last_push`（TTL 续约基准；测试面）。
    #[cfg(test)]
    pub async fn get_push_last_push(&self, fp: &str) -> Result<Option<u64>, DirStoreError> {
        Ok(self
            .get_meta(&format!("push:{fp}:last_push"))
            .await?
            .and_then(|v| v.parse::<u64>().ok()))
    }

    // ── meta ────────────────────────────────────────────────────────────

    pub async fn get_meta(&self, key: &str) -> Result<Option<String>, DirStoreError> {
        let conn = self.conn.lock().await;
        Ok(conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub async fn set_meta(&self, key: &str, value: &str) -> Result<(), DirStoreError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// 本域 epoch（每次本地成功写入 +1；对外推送批次携带）。
    pub async fn get_epoch(&self) -> Result<u64, DirStoreError> {
        Ok(self
            .get_meta("epoch")
            .await?
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0))
    }

    /// 手动推进 epoch（**仅单测**；生产由本域写入内部推进）。
    #[cfg(test)]
    pub async fn bump_epoch(&self) -> Result<u64, DirStoreError> {
        let conn = self.conn.lock().await;
        self.epoch_bump_locked(&conn)
    }

    /// epoch +1（调用方须持 conn 锁）。
    ///
    /// 无行〔新库首写〕与有行两态，递增在 SQL 内 `CAST(value AS INTEGER)+1`
    /// 完成——无行/非数值 = 基数 0）。返回值不变（自增后 epoch）。
    fn bump_epoch_unlocked(conn: &Connection) -> Result<u64, DirStoreError> {
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('epoch', '1')
             ON CONFLICT(key) DO UPDATE SET value = (CAST(value AS INTEGER) + 1)",
            [],
        )?;
        let s: String =
            conn.query_row("SELECT value FROM meta WHERE key = 'epoch'", [], |r| r.get(0))?;
        Ok(s.parse::<i64>()
            .map_err(|_| DirStoreError::Sqlite(rusqlite::Error::InvalidQuery))?
            as u64)
    }

    /// 测试夹具：强制刷新 outbox 行 `next_retry_at`（退避重试时序单测用）。
    #[cfg(test)]
    pub async fn outbox_force_next_retry_test(
        &self,
        target_domain: &str,
        next_retry_at: u64,
    ) -> Result<(), DirStoreError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE push_outbox SET next_retry_at = ?2 WHERE target_domain = ?1",
            params![target_domain, next_retry_at],
        )?;
        Ok(())
    }

    /// 测试夹具：直接回拨 outbox 行 `enqueued_at`（TTL 剪除时序单测用）。
    #[cfg(test)]
    pub async fn outbox_set_enqueued_test(
        &self,
        target_domain: &str,
        enqueued_at: u64,
    ) -> Result<(), DirStoreError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE push_outbox SET enqueued_at = ?2 WHERE target_domain = ?1",
            params![target_domain, enqueued_at],
        )?;
        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────
// 自域豁免/失败退避登记/成功 superseded/TTL 剪除 + 撤销重触发 +
// push_targets 并集口径 + list_push_subset 排除 pushed）
// ────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod outbox_tests {
    use super::*;

    static OBOX_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn temp_db(name: &str) -> PathBuf {
        let i = OBOX_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "kirin_r1403_outbox_{}_{}_{}",
            std::process::id(),
            i,
            name
        ));
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        p
    }

    #[test]
    fn test_r140_3_outbox_backoff_pinned() {
        assert_eq!(DirStore::outbox_backoff_secs(1), 30, "首败 +30s");
        assert_eq!(DirStore::outbox_backoff_secs(2), 120, "二败 +2min");
        assert_eq!(DirStore::outbox_backoff_secs(3), 600, "三败 +10min cap");
        assert_eq!(DirStore::outbox_backoff_secs(99), 600, "cap 不再递增");
    }

    #[tokio::test]
    async fn test_r140_3_outbox_semantics() {
        let p = temp_db("sem");
        let s = DirStore::open(&p).unwrap();
        let now = now_unix_secs();
        // ① 写入时钩子：target ≠ 自域 = 同事务入队（enqueued=true）。
        let (used, enq) = s
            .upsert_manual("dev-1", "b.test.relay", "a.example.com", "", "10.0.0.1", 1, vec![0u8; 64], 0, Some("a.test.relay"))
            .await
            .unwrap();
        assert_eq!((used, enq), (1, true));
        let due = s.outbox_due(now + 1).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].target_domain, "b.test.relay");
        assert_eq!(due[0].attempts, 0, "写入时触发行 = attempts 0");
        // ② 幂等：已存在行不重复入队、不刷重试态（退避状态归调度器）。
        let (_, enq2) = s
            .upsert_manual("dev-1", "b.test.relay", "a.example.com", "", "10.0.0.1", 2, vec![0u8; 64], 0, Some("a.test.relay"))
            .await
            .unwrap();
        assert!(!enq2, "NOT EXISTS 幂等：不重复入队");
        // ③ target = 自域 = 不入队（不推给自己）。
        let (_, enq3) = s
            .upsert_manual("dev-2", "a.test.relay", "b.example.com", "", "10.0.0.1", 1, vec![0u8; 64], 0, Some("a.test.relay"))
            .await
            .unwrap();
        assert!(!enq3);
        assert_eq!(s.outbox_due(i64::MAX as u64).await.unwrap().len(), 1);
        // ④ 失败登记：行已存在 → attempts 0→1 + 退避 30s（inserted=false）。
        let (a, ins) = s.outbox_register_failure("b.test.relay", now).await.unwrap();
        assert_eq!((a, ins), (1, false));
        assert!(s.outbox_due(now).await.unwrap().is_empty(), "退避 30s：失败时点未到期");
        let due = s.outbox_due(now + 30).await.unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempts, 1);
        // ⑤ 行不存在 = 新入队（inserted=true；`push outbox enqueued` 素材）。
        let (a, ins) = s.outbox_register_failure("c.test.relay", now).await.unwrap();
        assert_eq!((a, ins), (1, true));
        // ⑥ 退避阶梯：1→2（+120s）→ 3（+600s cap）。
        let (a, _) = s.outbox_register_failure("c.test.relay", now + 40).await.unwrap();
        assert_eq!(a, 2);
        let due = s.outbox_due(now + 40 + 120).await.unwrap();
        assert!(due.iter().any(|r| r.target_domain == "c.test.relay" && r.attempts == 2));
        let (a, _) = s
            .outbox_register_failure("c.test.relay", now + 40 + 120 + 60)
            .await
            .unwrap();
        assert_eq!(a, 3);
        let due = s.outbox_due(i64::MAX as u64).await.unwrap();
        let c = due.iter().find(|r| r.target_domain == "c.test.relay").unwrap();
        assert_eq!(c.next_retry_at, now + 40 + 120 + 60 + 600, "三败 = +10min cap");
        // ⑦ 成功 = 该 target 全部行 superseded 剪除。
        assert_eq!(s.outbox_clear("c.test.relay").await.unwrap(), 1);
        assert_eq!(s.outbox_due(i64::MAX as u64).await.unwrap().len(), 1);
        // ⑧ TTL 剪除（age > 24h；素材 = (target, n) 升序）。
        assert!(
            s.outbox_prune_expired(now, 86_400).await.unwrap().is_empty(),
            "未超龄 = 不剪"
        );
        s.outbox_set_enqueued_test("b.test.relay", 1).await.unwrap();
        let groups = s.outbox_prune_expired(now, 86_400).await.unwrap();
        assert_eq!(groups, vec![("b.test.relay".to_string(), 1)], "超龄 = 剪除 + 返回计数");
        assert!(s.outbox_due(i64::MAX as u64).await.unwrap().is_empty());
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    #[tokio::test]
    async fn test_r140_3_outbox_delete_retrigger_and_push_targets() {
        let p = temp_db("del");
        let s = DirStore::open(&p).unwrap();
        let now = now_unix_secs();
        s.upsert_manual("dev-1", "b.test.relay", "a.example.com", "", "10.0.0.1", 1, vec![0u8; 64], 0, Some("a.test.relay"))
            .await
            .unwrap();
        // 模拟一次成功推送 superseded（行剪除）。
        s.outbox_clear("b.test.relay").await.unwrap();
        // 删除（target ≠ 自域）：outbox 行已剪 = 重新入队（撤销传播素材）。
        let (deleted, enq) = s.delete_manual("dev-1", "b.test.relay", Some("a.test.relay")).await.unwrap();
        assert_eq!((deleted, enq), (true, true), "撤销 = outbox 触发记录");
        // T2 口径：dir 行删后 target 仍经 outbox 行保活（至成功推送 superseded）。
        assert_eq!(s.push_targets().await.unwrap(), vec!["b.test.relay".to_string()]);
        // pushed 行不入 push_targets（永不外推；自持 ∪ outbox 口径）。
        s.insert_pushed_test("dev-p", "a.test.relay", "p.example.com", "aa:bb", now, vec![0u8; 64])
            .await
            .unwrap();
        assert_eq!(s.push_targets().await.unwrap(), vec!["b.test.relay".to_string()]);
        // list_push_subset：仅自持行（pushed 排除）+ device_id 升序。
        s.upsert_manual("dev-2", "b.test.relay", "b.example.com", "", "10.0.0.1", 1, vec![0u8; 64], 0, Some("a.test.relay"))
            .await
            .unwrap();
        let sub = s.list_push_subset("b.test.relay").await.unwrap();
        // dev-1 已于上方 delete 步删除；仅 dev-2 自持行在子集（升序）。
        assert_eq!(
            sub.iter().map(|r| r.device_id.clone()).collect::<Vec<_>>(),
            vec!["dev-2".to_string()]
        );
        assert!(sub.iter().all(|r| r.source != SOURCE_PUSHED));
        // delete_manual 不跨源：仅 pushed 行存在 = (false, false)。
        s.insert_pushed_test("dev-p", "b.test.relay", "p.example.com", "aa:bb", now, vec![0u8; 64])
            .await
            .unwrap();
        let (deleted, enq) = s.delete_manual("dev-p", "b.test.relay", Some("a.test.relay")).await.unwrap();
        assert_eq!((deleted, enq), (false, false));
        // delete_device_rows：设备全部自持行删 + pushed 不跨源 + 返回
        // targets + epoch+1（同事务）。
        s.upsert_manual("dev-3", "c.test.relay", "c.example.com", "", "10.0.0.1", 1, vec![0u8; 64], 0, Some("a.test.relay"))
            .await
            .unwrap();
        s.insert_pushed_test("dev-3", "a.test.relay", "q.example.com", "bb:cc", now, vec![0u8; 64])
            .await
            .unwrap();
        let e0 = s.get_epoch().await.unwrap();
        let targets = s.delete_device_rows("dev-3").await.unwrap();
        assert_eq!(targets, vec!["c.test.relay".to_string()]);
        assert_eq!(s.get_epoch().await.unwrap(), e0 + 1);
        assert!(s.get("dev-3", "c.test.relay").await.unwrap().is_none());
        assert!(s.get("dev-3", "a.test.relay").await.unwrap().is_some(), "pushed 行不跨源删");
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }
}

/// 列表 scope（与 relay protocol `DirScope` v2 同语义；本 crate 不依赖
/// relay 协议枚举，避免存储层耦合 wire 面——backend 负责双向映射）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirListScope {
    All,
    /// 本中继自持行（source != 'pushed'）。
    Local,
    /// 指定源指纹的 pushed 行（v2 语义；v1 = 该源同步来的 peer 行）。
    Peer(String),
}

// ────────────────────────────────────────────────────────────────────────
// 矩阵（499-501 边界/IPv6 /64/mapped/0=不限/末次写入者/pushed 不计）/
// schema v2 冻结 / v1→v2 四步迁移 / 损坏处置 / 零凭据核 / 事务化）
// ────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_db(name: &str) -> PathBuf {
        let i = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "kirin_r1402_{}_{}_{}",
            std::process::id(),
            i,
            name
        ));
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        p
    }

    // ── P10 冲突裁决纯函数全矩阵（v2：peer 值 → pushed 值对偶改写） ────

    #[test]
    fn test_r140_1_adjudication_matrix_pushed() {
        // 规则 0：无存量 → Insert。
        assert_eq!(
            adjudicate_push_entry(None, 100, "aa"),
            Adjudication::Insert
        );
        // 规则 1：manual > pushed（与 ts 无关——本地权威优先）。
        assert_eq!(
            adjudicate_push_entry(Some(("manual", 50, "")), 100, "aa"),
            Adjudication::KeepExisting
        );
        assert_eq!(
            adjudicate_push_entry(Some(("manual", 1000, "")), 100, "aa"),
            Adjudication::KeepExisting
        );
        // 规则 2：registered > pushed（与 ts 无关）。
        assert_eq!(
            adjudicate_push_entry(Some(("registered", 1000, "")), 100, "aa"),
            Adjudication::KeepExisting
        );
        // 规则 3a：pushed vs pushed，ts 新者胜（last-writer-wins）。
        assert_eq!(
            adjudicate_push_entry(Some(("pushed", 99, "bb")), 100, "aa"),
            Adjudication::Replace
        );
        // 规则 3b：pushed vs pushed，ts 旧者败。
        assert_eq!(
            adjudicate_push_entry(Some(("pushed", 101, "bb")), 100, "aa"),
            Adjudication::KeepExisting
        );
        // 规则 3c：ts 相等 = 源指纹字典序小者胜（确定性）。
        assert_eq!(
            adjudicate_push_entry(Some(("pushed", 100, "bb")), 100, "aa"),
            Adjudication::Replace
        );
        assert_eq!(
            adjudicate_push_entry(Some(("pushed", 100, "aa")), 100, "bb"),
            Adjudication::KeepExisting
        );
        // 同源自洽（fp 相同）= 幂等保留（不 Replace 自己）。
        assert_eq!(
            adjudicate_push_entry(Some(("pushed", 100, "aa")), 100, "aa"),
            Adjudication::KeepExisting
        );
        // source_rank 权重钉死（v2：pushed = 1；v1 'peer' 值废 = 未知档 0）。
        assert_eq!(source_rank(SOURCE_MANUAL), 3);
        assert_eq!(source_rank(SOURCE_REGISTERED), 2);
        assert_eq!(source_rank(SOURCE_PUSHED), 1);
        assert_eq!(source_rank("peer"), 0, "v1 'peer' 值 v2 不产生 = 未知档");
        assert_eq!(source_rank("garbage"), 0);
    }


    #[test]
    fn test_r140_1_schema_v2_ddl_frozen() {
        // 三表 + 四索引 + 复合 PK + 关键列全在（变更 = 冻结面变更）。
        for needle in [
            "CREATE TABLE IF NOT EXISTS device_directory",
            "device_id      TEXT NOT NULL",
            "target_domain  TEXT NOT NULL",
            "device_domain  TEXT NOT NULL",
            "source         TEXT NOT NULL",
            "source_fp      TEXT",
            "owner_ip       TEXT",
            "note           TEXT NOT NULL DEFAULT ''",
            "updated_at     INTEGER NOT NULL",
            "sig            BLOB",
            "created_at     INTEGER NOT NULL",
            "PRIMARY KEY (device_id, target_domain)",
            "CREATE INDEX IF NOT EXISTS idx_dd_target  ON device_directory(target_domain)",
            "CREATE INDEX IF NOT EXISTS idx_dd_updated ON device_directory(updated_at)",
            "CREATE INDEX IF NOT EXISTS idx_dd_source  ON device_directory(source, source_fp)",
            "CREATE TABLE IF NOT EXISTS push_outbox",
            "target_domain TEXT NOT NULL",
            "enqueued_at   INTEGER NOT NULL",
            "attempts      INTEGER NOT NULL DEFAULT 0",
            "next_retry_at INTEGER NOT NULL",
            "CREATE INDEX IF NOT EXISTS idx_po_target ON push_outbox(target_domain)",
            "CREATE TABLE IF NOT EXISTS meta",
            "key   TEXT PRIMARY KEY",
        ] {
            assert!(
                SCHEMA_V2_DDL.contains(needle),
                "schema v2 DDL 冻结面缺失: {needle:?}"
            );
        }
        assert_eq!(SCHEMA_VERSION, 4);
        // v2 三表无 sync_peers（机制废除，§7）。
        assert!(!SCHEMA_V2_DDL.contains("sync_peers"));
        for needle in [
            "ix_tokens",
            "id            INTEGER PRIMARY KEY",
            "token         TEXT NOT NULL UNIQUE",
            "token_prefix  TEXT NOT NULL",
            "label         TEXT NOT NULL",
            "source        TEXT NOT NULL CHECK(source IN ('cli','device'))",
            "target_domain TEXT",
            "created_at    INTEGER NOT NULL",
            "revoked_at    INTEGER",
            "CREATE INDEX IF NOT EXISTS idx_ix_source_target ON ix_tokens(source, target_domain)",
        ] {
            assert!(
                SCHEMA_V3_DDL.contains(needle),
                "schema v3 DDL 冻结面缺失: {needle:?}"
            );
        }
        assert!(!SCHEMA_V2_DDL.contains("ix_tokens"));
        // token 列可空——device 行明文 C-6 边界）。
        for needle in [
            "token         TEXT,",
            "token_hash    TEXT NOT NULL UNIQUE,",
            "CHECK(source = 'device' OR token IS NULL)",
            "source        TEXT NOT NULL CHECK(source IN ('cli','device'))",
            "CREATE INDEX IF NOT EXISTS idx_ix_source_target ON ix_tokens(source, target_domain)",
        ] {
            assert!(
                SCHEMA_V4_DDL.contains(needle),
                "schema v4 DDL 冻结面缺失: {needle:?}"
            );
        }
        // 不再 UNIQUE（UNIQUE 判重域已平移到 token_hash）。
        assert!(!SCHEMA_V3_DDL.contains("token_hash"));
        assert!(!SCHEMA_V4_DDL.contains("token         TEXT NOT NULL UNIQUE"));
    }

    // ── CRUD / scope（v2 复合 PK + filter_device + pushed 语义） ───────

    #[tokio::test]
    async fn test_r140_1_crud_and_scope_v2() {
        let p = temp_db("crud");
        let s = DirStore::open(&p).unwrap();
        let now = 1_700_000_000u64;
        let fp = "aa:bb:cc";

        // 本域写入（manual，自签占位 sig；配额 0 = 不限）。
        s.upsert_manual("dev-a", "b1.test.relay", "a.example.com", "", "10.0.0.1", now, vec![0xAA; 64], 0, None)
            .await
            .unwrap();
        s.upsert_manual("dev-b", "b2.test.relay", "b.example.com", "note-b", "10.0.0.1", now + 1, vec![0xBB; 64], 0, None)
            .await
            .unwrap();
        // 同设备多 target 行（复合 PK 语义：v1 单行 → v2 多行）。
        s.upsert_manual("dev-a", "b3.test.relay", "a.example.com", "", "10.0.0.1", now + 2, vec![0xAB; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 3);
        // 同 PK 再 upsert = 就地 UPDATE 不增行（note/ts 覆写）。
        s.upsert_manual("dev-a", "b1.test.relay", "a2.example.com", "n2", "10.0.0.1", now + 5, vec![0xAC; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 3);
        let a1 = s.get("dev-a", "b1.test.relay").await.unwrap().unwrap();
        assert_eq!(a1.device_domain, "a2.example.com");
        assert_eq!(a1.note, "n2");
        assert_eq!(a1.updated_at, now + 5);
        assert_eq!(a1.owner_ip.as_deref(), Some("10.0.0.1"));
        assert!(a1.source_fp.is_none());
        assert_eq!(a1.source, SOURCE_MANUAL);

        // list scope v2 语义。
        assert_eq!(s.list(DirListScope::All, None).await.unwrap().len(), 3);
        let local = s.list(DirListScope::Local, None).await.unwrap();
        assert_eq!(local.len(), 3);
        assert!(local.iter().all(|r| r.source == SOURCE_MANUAL));
        // filter_device（Some = 仅该设备行；两 target 行都在）。
        let fa = s.list(DirListScope::All, Some("dev-a")).await.unwrap();
        assert_eq!(fa.len(), 2);
        assert!(fa.iter().all(|r| r.device_id == "dev-a"));
        // 排序冻结：device_id, target_domain。
        let all = s.list(DirListScope::All, None).await.unwrap();
        let keys: Vec<(String, String)> = all
            .iter()
            .map(|r| (r.device_id.clone(), r.target_domain.clone()))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "ORDER BY device_id, target_domain 冻结");

        // 本域删除：自持行可删；不存在的 target 组合 = false。
        assert!(s.delete_manual("dev-a", "b1.test.relay", None).await.unwrap().0);
        assert!(!s.delete_manual("dev-a", "b9.test.relay", None).await.unwrap().0);
        assert!(!s.delete_manual("no-such", "b1.test.relay", None).await.unwrap().0);
        assert_eq!(s.count().await.unwrap(), 2);
        // 另一 target 行不受影响（复合 PK 精确删）。
        assert!(s.get("dev-a", "b3.test.relay").await.unwrap().is_some());

        // epoch 单调：本域成功写入 ×4 + 删除 ×1 = 5。
        assert_eq!(s.get_epoch().await.unwrap(), 5);

        // pushed 行语义（test-only 直插）：Peer(fp) scope = 来源 fp 的
        // pushed 行；delete_manual **不跨源删** pushed 行。
        let conn = s.conn.lock().await;
        conn.execute(
            "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
             VALUES('dev-pushed', 'self.test.relay', 'p.example.com', 'pushed', ?1, NULL, '', 1, x'00', 1)",
            params![fp],
        )
        .unwrap();
        drop(conn);
        let peer = s.list(DirListScope::Peer(fp.into()), None).await.unwrap();
        assert_eq!(peer.len(), 1);
        assert_eq!(peer[0].device_id, "dev-pushed");
        assert_eq!(peer[0].source_fp.as_deref(), Some(fp));
        assert_eq!(
            s.list(DirListScope::Peer("zz:zz".into()), None)
                .await
                .unwrap()
                .len(),
            0
        );
        // Local 不含 pushed 行。
        assert_eq!(
            s.list(DirListScope::Local, None)
                .await
                .unwrap()
                .iter()
                .filter(|r| r.device_id == "dev-pushed")
                .count(),
            0
        );
        // pushed 行不经 delete_manual 删除（只能由 A 的推送批次删除）。
        assert!(!s.delete_manual("dev-pushed", "self.test.relay", None).await.unwrap().0);
        assert!(s.get("dev-pushed", "self.test.relay").await.unwrap().is_some());

        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    // ── 单 IP 注册配额矩阵（§4：写侧执法，upsert_manual 事务内） ──────

    #[tokio::test]
    async fn test_r140_1_quota_enforcement_matrix() {
        let p = temp_db("quota");
        let s = DirStore::open(&p).unwrap();
        let now = 1_700_000_000u64;
        let limit = 3usize; // 小配额跑全语义矩阵（499-501 边界另测）

        // ① 配额内新增放行（used_after 水位返回）。
        let (used, _) = s
            .upsert_manual("d1", "t1.test.relay", "a.example.com", "", "203.0.113.7", now, vec![0u8; 64], limit, None)
            .await
            .unwrap();
        assert_eq!(used, 1);
        s.upsert_manual("d2", "t1.test.relay", "b.example.com", "", "203.0.113.7", now, vec![0u8; 64], limit, None)
            .await
            .unwrap();
        s.upsert_manual("d3", "t1.test.relay", "c.example.com", "", "203.0.113.7", now, vec![0u8; 64], limit, None)
            .await
            .unwrap();
        // ② 第 4 个 distinct device 同 IP = quota_exceeded（只拒新增不清存量）。
        let e = s
            .upsert_manual("d4", "t1.test.relay", "d.example.com", "", "203.0.113.7", now, vec![0u8; 64], limit, None)
            .await
            .unwrap_err();
        match &e {
            DirStoreError::QuotaExceeded { used, limit: l } => {
                assert_eq!(*used, 3);
                assert_eq!(*l, limit);
            }
            other => panic!("期望 QuotaExceeded，实得 {other:?}"),
        }
        assert_eq!(s.count().await.unwrap(), 3, "拒绝不落库（无半写）");
        // ③ 同 device 同 IP 再加 target / 改 domain = 不增量放行。
        s.upsert_manual("d1", "t2.test.relay", "a.example.com", "", "203.0.113.7", now + 1, vec![1u8; 64], limit, None)
            .await
            .unwrap();
        s.upsert_manual("d1", "t1.test.relay", "a2.example.com", "changed", "203.0.113.7", now + 2, vec![2u8; 64], limit, None)
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 4, "同设备新 target 放行");
        // ④ 异 IP 独立计数（新 IP 不受 203.0.113.7 配额影响）。
        s.upsert_manual("d5", "t1.test.relay", "e.example.com", "", "203.0.113.8", now, vec![0u8; 64], limit, None)
            .await
            .unwrap();
        // ⑤ IPv6 /64 聚合：/64 归一在 dir_backend::quota_key_for_ip（store 只
        // 按传入键精确计数）——此处以归一后的键驱动 store 面矩阵。
        let k_a = crate::dir_backend::quota_key_for_ip("2001:db8:abcd:1234::5".parse().unwrap());
        let k_b = crate::dir_backend::quota_key_for_ip("2001:db8:abcd:1234::ffff".parse().unwrap());
        let k_c = crate::dir_backend::quota_key_for_ip("2001:db8:abcd:1234:0:0:0:1".parse().unwrap());
        let k_d = crate::dir_backend::quota_key_for_ip("2001:db8:9999:1234::5".parse().unwrap());
        assert_eq!(k_a, k_b, "同 /64 必须同键");
        assert_eq!(k_b, k_c, "同 /64 不同 host 必须同键");
        assert_ne!(k_a, k_d, "异 /64 必须异键");
        s.upsert_manual("d6", "t1.test.relay", "f.example.com", "", &k_a, now, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        s.upsert_manual("d7", "t1.test.relay", "g.example.com", "", &k_b, now, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        // 该 /64 键下已 2 个 distinct；配额 2 时第 3 个拒。
        let e = s
            .upsert_manual("d8", "t1.test.relay", "h.example.com", "", &k_c, 2, vec![0u8; 64], 2, None)
            .await
            .unwrap_err();
        assert!(matches!(e, DirStoreError::QuotaExceeded { used: 2, limit: 2 }), "{e:?}");
        // 异 /64 = 独立键（放行）。
        s.upsert_manual("d9", "t1.test.relay", "i.example.com", "", &k_d, now, vec![0u8; 64], 2, None)
            .await
            .unwrap();
        // ⑥ 末次写入者：设备换 IP = 配额归属迁移（旧键 −1 腾出名额，新键 +1）。
        s.upsert_manual("d3", "t1.test.relay", "c.example.com", "", "203.0.113.8", now + 3, vec![3u8; 64], limit, None)
            .await
            .unwrap();
        // 203.0.113.7 键下现 d1/d2（d3 迁走）= 2 < 3 → 新设备 d10 放行。
        let (used, _) = s
            .upsert_manual("d10", "t1.test.relay", "j.example.com", "", "203.0.113.7", now + 4, vec![4u8; 64], limit, None)
            .await
            .unwrap();
        assert_eq!(used, 3, "迁移后旧键腾出名额（d1/d2/d10）");
        // 覆写确认：d3 行 owner_ip = 末次写入者。
        let d3 = s.get("d3", "t1.test.relay").await.unwrap().unwrap();
        assert_eq!(d3.owner_ip.as_deref(), Some("203.0.113.8"));
        // ⑦ pushed 行不计配额（owner_ip NULL）。
        let fp = "aa:bb:cc";
        {
            let conn = s.conn.lock().await;
            for i in 0..10u32 {
                conn.execute(
                    "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
                     VALUES(?1, 'self.test.relay', 'p.example.com', 'pushed', ?2, NULL, '', 1, x'00', 1)",
                    params![format!("pushed-{i}"), fp],
                )
                .unwrap();
            }
        }
        // 配额键不受 pushed 行影响（203.0.113.7 仍 3 个 distinct = 配额满，
        // 但同 device 更新放行、pushed 行计数为零贡献）。
        let e = s
            .upsert_manual("d11", "t1.test.relay", "k.example.com", "", "203.0.113.7", now + 5, vec![0u8; 64], limit, None)
            .await
            .unwrap_err();
        assert!(matches!(e, DirStoreError::QuotaExceeded { used: 3, .. }), "{e:?}");
        // ⑧ 0 = 不限（同键任意 distinct 放行）。
        for i in 0..20u32 {
            s.upsert_manual(
                &format!("unl-{i}"),
                "t1.test.relay",
                "u.example.com",
                "",
                "203.0.113.99",
                now + i as u64,
                vec![0u8; 64],
                0,
                None,
            )
            .await
            .unwrap();
        }
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }


    #[tokio::test]
    async fn test_r149_device_entry_limit_matrix() {
        let p = temp_db("r149_device_limit");
        let s = DirStore::open(&p).unwrap();
        let now = 1_700_000_000u64;
        // ip_quota = 0（IP 配额不限）——本矩阵只驱动每设备上限面。
        // ① 第 1~14 条放行。
        for i in 1..=14u32 {
            s.upsert_manual(
                "dev-a",
                &format!("t{i:02}.test.relay"),
                "a.example.com",
                "",
                "10.0.0.1",
                now + i as u64,
                vec![0u8; 64],
                0,
                None,
            )
            .await
            .unwrap();
        }
        // ② 第 15 条成功（上限内终态）。
        s.upsert_manual("dev-a", "t15.test.relay", "a.example.com", "", "10.0.0.1", now + 15, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 15);
        // ③ 第 16 条 = DeviceLimitExceeded（只拒新增，无半写）。
        let before = s.count().await.unwrap();
        let e = s
            .upsert_manual("dev-a", "t16.test.relay", "a.example.com", "", "10.0.0.1", now + 16, vec![0u8; 64], 0, None)
            .await
            .unwrap_err();
        match &e {
            DirStoreError::DeviceLimitExceeded { used, limit } => {
                assert_eq!(*used, 15);
                assert_eq!(*limit, MAX_DEVICE_DIR_ENTRIES);
            }
            other => panic!("期望 DeviceLimitExceeded，实得 {other:?}"),
        }
        assert_eq!(s.count().await.unwrap(), before, "拒绝不落库（无半写/不挤存量）");
        // ④ 既有 (device_id, target) 行幂等重写 = 不增量放行（改 domain）。
        s.upsert_manual("dev-a", "t01.test.relay", "a2.example.com", "changed", "10.0.0.1", now + 100, vec![1u8; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 15, "幂等重写不增行");
        // ⑤ 不同设备互不影响（dev-b 首条放行）。
        s.upsert_manual("dev-b", "tb1.test.relay", "b.example.com", "", "10.0.0.2", now, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 16);
        // ⑥ 删除后可再加（dev-a 删 t02 → 14，再加 t16 放行）。
        let (deleted, _) = s.delete_manual("dev-a", "t02.test.relay", None).await.unwrap();
        assert!(deleted);
        s.upsert_manual("dev-a", "t16.test.relay", "a.example.com", "", "10.0.0.1", now + 16, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(
            s.list(DirListScope::Local, Some("dev-a")).await.unwrap().len(),
            15,
            "删除腾位后新增放行"
        );
        // ⑦ pushed 行不计每设备上限（他中继定向推送行 ≠ 设备自持发现条目）：
        // dev-a 删 t03 → 14 自持行 + 直插 1 条 pushed 行 → 新 target 仍放行
        // （若误计 pushed 行 = 15 >= 15 会拒，此断言钉死不计口径）。
        let (deleted3, _) = s.delete_manual("dev-a", "t03.test.relay", None).await.unwrap();
        assert!(deleted3);
        {
            let conn = s.conn.lock().await;
            conn.execute(
                "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
                 VALUES('dev-a', 'self.test.relay', 'a.example.com', 'pushed', ?1, NULL, '', 1, x'00', 1)",
                params!["aa:bb:cc"],
            )
            .unwrap();
        }
        s.upsert_manual("dev-a", "t17.test.relay", "a.example.com", "", "10.0.0.1", now + 17, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        let self_rows = s.list(DirListScope::Local, Some("dev-a")).await.unwrap();
        assert_eq!(self_rows.len(), 15, "pushed 行不入 Local 自持计数");
        // ⑧ 上限常量双侧同值锚（客户端 NODES_MAX_ENTRIES 同口径）。
        assert_eq!(MAX_DEVICE_DIR_ENTRIES, 15);
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    #[tokio::test]
    async fn test_r140_1_quota_boundary_499_501() {
        // 边界 499-501（设计 §8-C）：批量 SQL 预填 499 同 IP distinct
        // （单事务，等价 499 次 upsert 的终态），第 500 放行 / 第 501 拒 /
        // 存量更新放行。
        let p = temp_db("quota499");
        let s = DirStore::open(&p).unwrap();
        let limit = 500usize;
        {
            let conn = s.conn.lock().await;
            conn.execute_batch("BEGIN").unwrap();
            let mut stmt = conn.prepare(
                "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
                 VALUES(?1, 't.test.relay', 'd.example.com', 'manual', NULL, '203.0.113.50', '', 1, x'00', 1)",
            )
            .unwrap();
            for i in 0..499u32 {
                stmt.execute(params![format!("dev-{i:06}")]).unwrap();
            }
            conn.execute_batch("COMMIT").unwrap();
        }
        // 第 500 个 distinct = 放行（used 499 → 500）。
        let (used, _) = s
            .upsert_manual("dev-0500", "t.test.relay", "x.example.com", "", "203.0.113.50", 1, vec![0u8; 64], limit, None)
            .await
            .unwrap();
        assert_eq!(used, 500);
        // 第 501 个 distinct = 拒（used 500 >= 500）。
        let e = s
            .upsert_manual("dev-0501", "t.test.relay", "y.example.com", "", "203.0.113.50", 1, vec![0u8; 64], limit, None)
            .await
            .unwrap_err();
        assert!(
            matches!(e, DirStoreError::QuotaExceeded { used: 500, limit: 500 }),
            "{e:?}"
        );
        // 存量更新（同 IP 同 device 改 target）= 放行（不增量）。
        // 预填 ID 为 6 位零填充形态（dev-000000）——4 位形态是**新**设备会撞配额。
        s.upsert_manual("dev-000000", "t2.test.relay", "d2.example.com", "", "203.0.113.50", 2, vec![1u8; 64], limit, None)
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 501, "500 存量 + 1 新 target 行");
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    // ── 损坏处置：改名保留取证 + 重建空库（v2 就绪，fail-closed） ─────

    #[tokio::test]
    async fn test_r140_1_corrupt_rebuild_keeps_forensic() {
        let p = temp_db("corrupt");
        // 垃圾文件 = 损坏库（quick_check 必败）。
        std::fs::write(&p, b"this is not a sqlite database at all, just garbage \0\0\x01").unwrap();
        let opened = DirStore::open_ex(&p).unwrap();
        assert!(opened.rebuilt, "损坏库必须置 rebuilt 标志（调用方审计）");
        // 原文件保留取证（<name>.corrupt-<ts>），按前缀精确定位。
        let base = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let forensics: Vec<String> = std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.strip_prefix(base.as_str())
                    .is_some_and(|rest| rest.starts_with(".corrupt-"))
            })
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(forensics.len(), 1, "损坏库必须改名保留: {forensics:?}");
        assert!(p.exists(), "原路径必须为重建后的新库");
        // 重建库 = 空库 + v2 就绪（三表可写）。
        assert_eq!(opened.store.count().await.unwrap(), 0);
        opened
            .store
            .upsert_manual("dev-x", "t.test.relay", "x.example.com", "", "10.1.1.1", 1, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(opened.store.count().await.unwrap(), 1);
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    #[tokio::test]
    async fn test_r140_1_corrupt_rename_failure_refuses() {
        // 改名失败场景：同目录已存在同名取证文件 → rename 在 Windows 上
        // 可能失败 = 拒绝启动（平台允许覆盖时 = rebuilt；两态都不得
        // 返回「正常打开」）。
        let p = temp_db("renamefail");
        std::fs::write(&p, b"garbage").unwrap();
        let ts = now_unix_secs();
        let forensic = p
            .file_name()
            .unwrap()
            .to_string_lossy()
            .trim()
            .to_string();
        let forensic_path = p.parent().unwrap().join(format!("{forensic}.corrupt-{ts}"));
        std::fs::write(&forensic_path, b"old forensic").unwrap();
        let r = DirStore::open_ex(&p);
        if let Ok(opened) = r {
            assert!(opened.rebuilt, "rename 成功时也必须置 rebuilt");
        } else {
            assert!(
                matches!(r.unwrap_err(), DirStoreError::CorruptRebuildFailed(_)),
                "rename 失败必须拒绝启动"
            );
        }
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    // ── 迁移门控：user_version > 2 拒启动 ─────────────────────────────

    #[tokio::test]
    async fn test_r140_1_future_schema_refused() {
        let p = temp_db("futurever");
        let s = DirStore::open(&p).unwrap();
        {
            let conn = s.conn.lock().await;
            conn.pragma_update(None, "user_version", 99).unwrap();
        }
        let e = DirStore::open_ex(&p).unwrap_err();
        assert!(
            matches!(e, DirStoreError::UnsupportedSchemaVersion(99)),
            "{e:?}"
        );
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    // ── v1→v2 四步幂等迁移（§2.4 逐条核验） ───────────────────────────

    /// 构造 v1 库夹具（SCHEMA_V1_DDL + v1 数据 + peer:* meta + epoch）。
    fn build_v1_db(p: &Path) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(p)?;
        conn.execute_batch(SCHEMA_V1_DDL)?;
        conn.pragma_update(None, "user_version", 1)?;
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', '1')",
            [],
        )?;
        // v1 目录行 ×2（无 target_domain 语义——迁移后保留在 renamed 表）。
        conn.execute(
            "INSERT INTO device_directory(device_id, domain, source, peer_fp, updated_at, sig, created_at)
             VALUES('v1-dev-1', 'v1a.example.com', 'manual', NULL, 1, x'00', 1),
                    ('v1-dev-2', 'v1b.example.com', 'peer', 'ff:ee', 2, x'00', 2)",
            [],
        )?;
        // v1 sync_peers 行（迁移必须 DROP）。
        conn.execute(
            "INSERT INTO sync_peers(domain, pubkey, fp, enabled, note, created_at)
             VALUES('sync.example.com', x'0101010101010101010101010101010101010101010101010101010101010101', 'ff:ee', 1, 'n', 1)",
            [],
        )?;
        // peer:* 水位键（迁移必须清）+ epoch（迁移必须保留续用）。
        conn.execute(
            "INSERT INTO meta(key, value) VALUES
             ('peer:ff:ee:last_sync', '123'),
             ('peer:ff:ee:last_epoch', '7'),
             ('epoch', '41')",
            [],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_r140_1_migration_v1_to_v2_four_steps() {
        let p = temp_db("migv1");
        {
            let _ = std::fs::remove_file(&p);
            build_v1_db(&p).unwrap();
        }
        let opened = DirStore::open_ex(&p).unwrap();
        assert!(!opened.rebuilt);
        let s = &opened.store;
        // 步骤 1：sync_peers 消失。
        {
            let conn = s.conn.lock().await;
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'sync_peers'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 0, "sync_peers 必须 DROP");
        }
        // 步骤 2：peer:* 键全清；epoch 保留续用（= 41 连续性）。
        assert!(s.get_meta("peer:ff:ee:last_sync").await.unwrap().is_none());
        assert!(s.get_meta("peer:ff:ee:last_epoch").await.unwrap().is_none());
        assert_eq!(s.get_meta("epoch").await.unwrap().as_deref(), Some("41"));
        assert_eq!(s.get_epoch().await.unwrap(), 41);
        // 步骤 3：v1 表改名保留（不迁数据）。
        {
            let conn = s.conn.lock().await;
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'device_directory_v1_retired'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "v1 表必须改名保留取证");
            let v1_rows: i64 = conn
                .query_row("SELECT COUNT(*) FROM device_directory_v1_retired", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v1_rows, 2, "v1 行保留在原表（不迁不删）");
        }
        assert_eq!(s.count().await.unwrap(), 0, "v2 目录表 = 空（登录对账重建）");
        {
            let conn = s.conn.lock().await;
            for t in ["device_directory", "push_outbox", "meta", "ix_tokens"] {
                let n: i64 = conn
                    .query_row(
                        &format!("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '{t}'"),
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(n, 1, "v2/v4 表缺失: {t}");
            }
            let ver: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        }
        // 注意：get_meta 须在本 conn 块外调用（tokio Mutex 非重入，
        assert_eq!(s.get_meta("schema_version").await.unwrap().as_deref(), Some("4"));
        // v2 面可写。
        s.upsert_manual("new-dev", "t.test.relay", "n.example.com", "", "10.2.2.2", 5, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 1);
        assert_eq!(s.get_epoch().await.unwrap(), 42, "epoch 连续性 +1");
        // 幂等：重开（已 v2）零副作用（先释放本连接）。
        drop(opened);
        let reopened = DirStore::open_ex(&p).unwrap();
        assert!(!reopened.rebuilt);
        assert_eq!(reopened.store.count().await.unwrap(), 1);
        assert_eq!(reopened.store.get_epoch().await.unwrap(), 42);
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    // ── 零凭据核（红线：v2 三表 dump 无 token/挑战码/私钥/会话密钥） ───

    #[tokio::test]
    async fn test_r140_1_zero_credentials_in_db_dump() {
        let p = temp_db("zerocred");
        let s = DirStore::open(&p).unwrap();
        let secret_token = "SUPER-SECRET-RELAY-TOKEN-0f997cb3";
        // 本模块 API 面不存在任何 token/challenge/私钥/会话密钥参数
        // （凭据零入库 = 构造上成立）；此测试钉死 dump 面：v2 三表
        // 全量导出后凭据串零出现。
        s.upsert_manual("dev-a", "t.test.relay", "a.example.com", "note", "203.0.113.7", 1, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        {
            let conn = s.conn.lock().await;
            conn.execute(
                "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
                 VALUES('dev-p', 'self.test.relay', 'p.example.com', 'pushed', 'ff:ff', NULL, '', 2, x'01', 2)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO push_outbox(target_domain, enqueued_at, attempts, next_retry_at)
                 VALUES('t.test.relay', 1, 0, 2)",
                [],
            )
            .unwrap();
        }
        s.set_meta("epoch", "7").await.unwrap();
        s.set_meta("push:ff:ff:last_epoch", "3").await.unwrap();
        s.set_meta("devlast:dev-a", "9").await.unwrap();

        let conn = s.conn.lock().await;
        let mut dump = String::new();
        for (table, sql) in [
            ("device_directory", "SELECT * FROM device_directory"),
            ("push_outbox", "SELECT * FROM push_outbox"),
            ("meta", "SELECT * FROM meta"),
        ] {
            dump.push_str(&format!("[{table}]"));
            let mut stmt = conn.prepare(sql).unwrap();
            let cols: Vec<String> = stmt.column_names().iter().map(|c| c.to_string()).collect();
            let mut rows = stmt
                .query_map([], |r| {
                    (0..cols.len())
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap();
            while let Some(row) = rows.next() {
                let v = row.unwrap();
                for cell in v {
                    match cell {
                        rusqlite::types::Value::Text(t) => dump.push_str(&format!(" {t}")),
                        rusqlite::types::Value::Blob(b) => {
                            if let Ok(str_) = std::str::from_utf8(&b) {
                                dump.push_str(str_);
                            }
                        }
                        rusqlite::types::Value::Integer(i) => dump.push_str(&format!(" {i}")),
                        rusqlite::types::Value::Real(f) => dump.push_str(&format!(" {f}")),
                        rusqlite::types::Value::Null => {}
                    }
                }
            }
        }
        assert!(!dump.contains(secret_token), "token 零入库: {dump}");
        // dump 面 sanity：业务数据确在（测试非空转）。
        assert!(dump.contains("a.example.com"));
        assert!(dump.contains("t.test.relay"));
        assert!(dump.contains("pushed"));
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }


    #[tokio::test]
    async fn test_r139_2_tx_atomic_no_half_write_v2() {
        // 事务内中途失败 = 整段回滚无半写（`with_tx` 机制 =
        // upsert_manual 共用路径）；回滚后连接仍可用。
        let p = temp_db("txatomic");
        let s = DirStore::open(&p).unwrap();
        assert_eq!(s.count().await.unwrap(), 0);
        {
            let conn = s.conn.lock().await;
            let r: Result<(), DirStoreError> = DirStore::with_tx(&conn, |c| {
                c.execute(
                    "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
                     VALUES('dev-half', 't.test.relay', 'half.example.com', 'manual', NULL, '192.168.77.9', '', 1, x'00', 1)",
                    [],
                )?;
                // 模拟事务内中途失败（任一 Err = 整段 ROLLBACK）。
                Err(DirStoreError::Sqlite(rusqlite::Error::InvalidQuery))
            });
            assert!(r.is_err(), "注入失败必须外抛");
        }
        assert_eq!(s.count().await.unwrap(), 0, "事务中途失败不得半写");
        // 回滚后连接可用（正常写入恢复）。
        s.upsert_manual("dev-ok", "t.test.relay", "ok.example.com", "", "192.168.77.9", 1, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(s.count().await.unwrap(), 1);
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    #[tokio::test]
    async fn test_r139_2_epoch_bump_single_stmt_pinned_v2() {
        // epoch 单语句自增语义：无行（新库）= 1；有值 = +1；非数值 =
        // 基数 0 → 1；upsert_manual 内部推进（单一事实源）。
        let p = temp_db("epochstmt");
        let s = DirStore::open(&p).unwrap();
        assert_eq!(s.bump_epoch().await.unwrap(), 1, "无 epoch 行 = 基数 0 → 1");
        assert_eq!(s.bump_epoch().await.unwrap(), 2);
        s.upsert_manual("dev-a", "t.test.relay", "a.example.com", "", "10.1.1.1", 1, vec![0u8; 64], 0, None)
            .await
            .unwrap();
        assert_eq!(s.get_epoch().await.unwrap(), 3);
        // 非数值 epoch 值 = 基数 0（parse 失败兜底同语义）。
        s.set_meta("epoch", "garbage").await.unwrap();
        assert_eq!(s.bump_epoch().await.unwrap(), 1);
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }


    /// 同构的 `<db>.epoch_hw`，不动 temp_db 命名）。
    fn r188_sidecar_of(p: &Path) -> PathBuf {
        let mut os = p.as_os_str().to_os_string();
        os.push(".epoch_hw");
        PathBuf::from(os)
    }

    #[tokio::test]
    async fn test_r188_epoch_restart_no_regress_same_db() {
        let p = temp_db("r188restart");
        let e0 = {
            let s = DirStore::open(&p).unwrap();
            assert_eq!(s.get_epoch().await.unwrap(), 0, "新库无 epoch 行 = 0");
            s.bump_epoch().await.unwrap();
            s.bump_epoch().await.unwrap()
        }; // drop = 关库（生产 = 进程退出）
        assert_eq!(e0, 2, "正常递增回归：1 → 2");
        let s = DirStore::open(&p).unwrap();
        assert_eq!(s.get_epoch().await.unwrap(), 2, "重启读回持久水位，不回退");
        assert_eq!(s.bump_epoch().await.unwrap(), 3, "续读后单调 +1");
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    #[tokio::test]
    async fn test_r188_epoch_sidecar_rebuild_selfheal() {
        // 行随库消失；sidecar（生产 = key 同卷）存活 → 启动对齐 floor
        // 抬升 = 自愈——对端门③ stale epoch 拒收即刻解除（下一批推送
        // epoch ≥ 旧水位），不再需要 5 轮变更自然追平。
        let p = temp_db("r188rebuild");
        let hw = r188_sidecar_of(&p);
        let _ = std::fs::remove_file(&hw);
        {
            let s = DirStore::open(&p).unwrap().with_epoch_sidecar(hw.clone());
            let (eff, raised) = s.epoch_highwater_sync().await.unwrap();
            assert_eq!((eff, raised), (0, false), "首启引导：sidecar 缺失 = 以 DB 为准");
            assert_eq!(
                std::fs::read_to_string(&hw).unwrap().trim(),
                "0",
                "sidecar 引导落盘"
            );
            for _ in 0..5 {
                s.bump_epoch().await.unwrap(); // epoch 1..=5，sidecar 写穿透同步
            }
        }
        // 换库：DB 文件删除（灾备重建/重装形态；WAL 伴生同清），sidecar 存活。
        std::fs::remove_file(&p).unwrap();
        for suf in ["-wal", "-shm"] {
            let mut os = p.as_os_str().to_os_string();
            os.push(suf);
            let _ = std::fs::remove_file(PathBuf::from(os));
        }
        let s = DirStore::open(&p).unwrap().with_epoch_sidecar(hw.clone());
        assert_eq!(
            s.get_epoch().await.unwrap(),
            0,
            "新库水位行消失（现状缺陷面）"
        );
        let (eff, raised) = s.epoch_highwater_sync().await.unwrap();
        assert_eq!((eff, raised), (5, true), "sidecar floor 抬升 = 自愈");
        assert_eq!(s.get_epoch().await.unwrap(), 5);
        assert_eq!(s.bump_epoch().await.unwrap(), 6, "自愈后继续单调");
        assert_eq!(
            std::fs::read_to_string(&hw).unwrap().trim(),
            "6",
            "sidecar 写穿透"
        );
        let _ = std::fs::remove_file(&hw);
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    #[tokio::test]
    async fn test_r188_epoch_sidecar_directions_and_garbage() {
        // 方向安全矩阵：① sidecar ≤ DB = 只升不降（sidecar 抬至 DB）；
        // ② sidecar > DB（事务回滚残留等）= floor 抬升（领先 = 安全方向，
        // 凭空跳号 = 对端 `==/>` 声明式幂等受理面）；③ sidecar 损坏 =
        // 忽略并按 DB 引导重写（fail-open 退回现状）；④ 未挂接 sidecar
        // （默认形态）= 行为零变化（既有库/既有单测兼容锚）。
        let p = temp_db("r188dir");
        let hw = r188_sidecar_of(&p);
        std::fs::write(&hw, b"3\n").unwrap();
        {
            let s = DirStore::open(&p).unwrap().with_epoch_sidecar(hw.clone());
            s.set_meta("epoch", "7").await.unwrap();
            let (eff, raised) = s.epoch_highwater_sync().await.unwrap();
            assert_eq!((eff, raised), (7, false), "① sidecar 落后 = 不降 DB");
            assert_eq!(std::fs::read_to_string(&hw).unwrap().trim(), "7", "① sidecar 抬至 DB");
        }
        std::fs::write(&hw, b"99\n").unwrap();
        {
            let s = DirStore::open(&p).unwrap().with_epoch_sidecar(hw.clone());
            let (eff, raised) = s.epoch_highwater_sync().await.unwrap();
            assert_eq!((eff, raised), (99, true), "② sidecar 领先 = floor 抬升");
            assert_eq!(s.get_epoch().await.unwrap(), 99);
            assert_eq!(s.bump_epoch().await.unwrap(), 100, "floor 后单调续增");
        }
        std::fs::write(&hw, b"garbage").unwrap();
        {
            let s = DirStore::open(&p).unwrap().with_epoch_sidecar(hw.clone());
            let (eff, raised) = s.epoch_highwater_sync().await.unwrap();
            assert_eq!((eff, raised), (100, false), "③ 损坏 sidecar 不抬不降");
            assert_eq!(
                std::fs::read_to_string(&hw).unwrap().trim(),
                "100",
                "③ 按 DB 引导重写"
            );
        }
        {
            let s = DirStore::open(&p).unwrap();
            assert_eq!(s.bump_epoch().await.unwrap(), 101, "④ 未挂接 = 零变化");
        }
        let _ = std::fs::remove_file(&hw);
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }


    /// 构造 v2 库夹具（SCHEMA_V2_DDL + 既有数据行 + user_version=2）。
    fn build_v2_db(p: &Path) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(p)?;
        conn.execute_batch(SCHEMA_V2_DDL)?;
        conn.pragma_update(None, "user_version", 2)?;
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', '2')",
            [],
        )?;
        conn.execute(
            "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
             VALUES('dev-v2', 't.test.relay', 'v2.example.com', 'manual', NULL, NULL, 'keep', 5, x'01', 5)",
            [],
        )?;
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('epoch', '9')",
            [],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_r168_v2_to_v3_migration_inplace_zero_data_loss() {
        let dir = std::env::temp_dir().join("k168_dirstore_v2mig");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("v2.db");
        build_v2_db(&p).unwrap();
        // v2 库原样打开 → 自动升 v3（原地建表，既有行零损）。
        let opened = DirStore::open_ex(&p).unwrap();
        assert!(!opened.rebuilt, "v2→v3 不得触发损坏重建");
        let s = &opened.store;
        assert_eq!(s.count().await.unwrap(), 1, "v2 数据行零损失");
        let row = s.get("dev-v2", "t.test.relay").await.unwrap().unwrap();
        assert_eq!(row.note, "keep");
        assert_eq!(s.get_epoch().await.unwrap(), 9, "epoch 连续性");
        assert_eq!(s.get_meta("schema_version").await.unwrap().as_deref(), Some("4"));
        {
            let conn = s.conn.lock().await;
            let ver: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
            assert_eq!(ver, 4);
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ix_tokens'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "v4 形态 ix_tokens 表就绪");
        }
        // v3 面可写（DAO 冒烟）。
        s.ix_add_cli_token("AAAAAAAA-token-1", "alpha", 100).await.unwrap();
        assert_eq!(s.ix_list_tokens().await.unwrap().len(), 1);
        // 幂等：重开（已 v3）零副作用。
        drop(opened);
        let reopened = DirStore::open_ex(&p).unwrap();
        assert!(!reopened.rebuilt);
        assert_eq!(reopened.store.ix_list_tokens().await.unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_r168_ix_tokens_dao_matrix() {
        let dir = std::env::temp_dir().join("k168_dirstore_dao");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("dao.db");
        let s = DirStore::open(&p).unwrap();

        // ① cli add：行字段/前缀/id 单调；同 label 各自独立 id。
        let t1 = s.ix_add_cli_token("tok-aaaa1111-xxxxxxxx", "alpha", 100).await.unwrap();
        let t2 = s.ix_add_cli_token("tok-bbbb2222-yyyyyyyy", "alpha", 200).await.unwrap();
        assert_eq!(t1.id, 1);
        assert_eq!(t2.id, 2);
        assert_eq!(t1.token_prefix, "tok-aaaa");
        assert_eq!(t1.source, "cli");
        assert_eq!(t1.target_domain, None);
        assert_eq!(t1.revoked_at, None);
        assert_eq!(s.ix_list_tokens().await.unwrap().len(), 2);
        // UNIQUE：同 token 串重复 add = 显式错误（不静默吞）。
        assert!(s.ix_add_cli_token("tok-aaaa1111-xxxxxxxx", "dup", 300).await.is_err());

        // ② revoke：软撤销置位行保留；重复 revoke = false；不存在 = false。
        assert!(s.ix_revoke_token(t1.id, 400).await.unwrap());
        let after = s.ix_get_token(t1.id).await.unwrap().unwrap();
        assert_eq!(after.revoked_at, Some(400), "软撤销 = 置位行保留");
        assert_eq!(s.ix_list_tokens().await.unwrap().len(), 2);
        assert!(!s.ix_revoke_token(t1.id, 500).await.unwrap(), "重复撤销 = false");
        assert!(!s.ix_revoke_token(999, 500).await.unwrap(), "不存在 id = false");
        assert!(s.ix_get_token(999).await.unwrap().is_none());

        // ③ 门⑥三态：活跃 cli 行 = Some(true)；撤销行 = Some(false)；
        //    未知串 / device 行 = None（device 缓存永不作门⑥凭据）。
        assert_eq!(s.ix_token_cli_state("tok-bbbb2222-yyyyyyyy").await.unwrap(), Some(true));
        assert_eq!(s.ix_token_cli_state("tok-aaaa1111-xxxxxxxx").await.unwrap(), Some(false));
        assert_eq!(s.ix_token_cli_state("no-such-token").await.unwrap(), None);
        assert_eq!(s.ix_token_cli_state("").await.unwrap(), None, "空串无命中");

        // ④ device upsert：同 target 全删后插（last-writer-wins）；lookup 最新一条。
        s.ix_upsert_device_token("b.example.com", "dev-tok-1", "dev-1", 110).await.unwrap();
        s.ix_upsert_device_token("b.example.com", "dev-tok-2", "dev-2", 120).await.unwrap();
        s.ix_upsert_device_token("c.example.com", "dev-tok-3", "dev-3", 130).await.unwrap();
        assert_eq!(
            s.ix_lookup_device_token("b.example.com").await.unwrap().as_deref(),
            Some("dev-tok-2"),
            "同 target 只留最新一条（home 对单 target 只携一个 token）"
        );
        // device 行不作门⑥凭据。
        assert_eq!(s.ix_token_cli_state("dev-tok-2").await.unwrap(), None);

        // ⑤ clear device token：显式撤回（重交空 token 口径）→ lookup = None。
        assert_eq!(s.ix_clear_device_token("b.example.com").await.unwrap(), 1);
        assert_eq!(s.ix_lookup_device_token("b.example.com").await.unwrap(), None);
        assert_eq!(s.ix_lookup_device_token("c.example.com").await.unwrap().as_deref(), Some("dev-tok-3"));

        // ⑥ UNIQUE 边界：device 缓存串恰为本机 cli 权威行 = 显式错误不覆盖权威行。
        assert!(s.ix_upsert_device_token("d.example.com", "tok-bbbb2222-yyyyyyyy", "dev-x", 140).await.is_err());
        let authority = s.ix_get_token(t2.id).await.unwrap().unwrap();
        assert_eq!(authority.label, "alpha", "权威行零触碰");

        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn test_r178_ix_token_ct_state_matrix() {
        let rows = vec![
            ("tok-active-aaaaaaaaaaaa".to_string(), true),
            ("tok-revoked-bbbbbbbbbbb".to_string(), false),
            ("short".to_string(), true),
        ];
        // 同长不同字节（未知串）→ None，等长行全遍历零长度跳过。
        let (s, n) = ix_token_ct_state(&rows, b"tok-unknown-ccccccccccc");
        assert_eq!(s, None, "同长不同字节无命中");
        assert_eq!(n, 1, "仅 short 行长度不等（等长行零跳过）");
        // 活跃行命中 → Some(true)。
        let (s, _) = ix_token_ct_state(&rows, b"tok-active-aaaaaaaaaaaa");
        assert_eq!(s, Some(true));
        // 撤销行命中 → Some(false)。
        let (s, _) = ix_token_ct_state(&rows, b"tok-revoked-bbbbbbbbbbb");
        assert_eq!(s, Some(false));
        // 不同长输入（空串）→ None 且 diff 计数逐行入账（不短路出口）。
        let (s, n) = ix_token_ct_state(&rows, b"");
        assert_eq!(s, None);
        assert_eq!(n, 3, "全部行长度不等 = 逐行置计数继续遍历");
        // 命中行与不同长行共存：diff 计数不影响命中语义。
        let (s, n) = ix_token_ct_state(&rows, b"tok-active-aaaaaaaaaaaa");
        assert_eq!(s, Some(true), "长度差行不污染命中");
        assert_eq!(n, 1, "仅 short 行长度不等");
        // 同长不同字节首字节差 / 尾字节差恒 None（常时折算不依赖差异位置）。
        assert_eq!(
            ix_token_ct_state(&rows, b"tok-active-aaaaaaaaaaab").0,
            None,
            "尾字节差"
        );
        assert_eq!(
            ix_token_ct_state(&rows, b"bok-active-aaaaaaaaaaaa").0,
            None,
            "首字节差"
        );
    }


    /// sha256 参考值来自标准实现离线核算）：
    /// - active cli: `r180-cli-token-activetoken-000000001`
    ///   → `ae061b6667749f694fef94099b50a71eb74148aa53e17b5fa844b581d3e949c5`
    /// - revoked cli: `r180-cli-token-revokedtok-00000001`
    ///   → `342bdff7a21dd83e3e10684c61ba8636afca76614d46a25b448ff217380271fc`
    /// - device cache: `r180-device-cachetoken-000000001`
    ///   → `3604708ca85869092b0b9ae8e7464e8da94723a61ca83a3744760212ab4ad7f7`
    fn build_v3_db(p: &Path) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(p)?;
        conn.execute_batch(SCHEMA_V2_DDL)?;
        conn.execute_batch(SCHEMA_V3_DDL)?;
        conn.pragma_update(None, "user_version", 3)?;
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', '3'),
             ('epoch', '7')",
            [],
        )?;
        conn.execute(
            "INSERT INTO device_directory(device_id, target_domain, device_domain, source, source_fp, owner_ip, note, updated_at, sig, created_at)
             VALUES('dev-v3', 't.test.relay', 'v3.example.com', 'manual', NULL, NULL, 'keep3', 5, x'01', 5)",
            [],
        )?;
        // cli 活跃行 + cli 撤销行 + device 缓存行（含 target_domain）。
        conn.execute(
            "INSERT INTO ix_tokens(token, token_prefix, label, source, target_domain, created_at, revoked_at)
             VALUES('r180-cli-token-activetoken-000000001', 'r180-cli', 'alpha', 'cli', NULL, 100, NULL)",
            [],
        )?;
        conn.execute(
            "INSERT INTO ix_tokens(token, token_prefix, label, source, target_domain, created_at, revoked_at)
             VALUES('r180-cli-token-revokedtok-00000001', 'r180-cli', 'beta', 'cli', NULL, 200, 300)",
            [],
        )?;
        conn.execute(
            "INSERT INTO ix_tokens(token, token_prefix, label, source, target_domain, created_at, revoked_at)
             VALUES('r180-device-cachetoken-000000001', 'r180-dev', 'cache-b', 'device', 'b.example.com', 110, NULL)",
            [],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn test_r180_v3_to_v4_migration_cli_hash_device_plaintext() {
        let dir = std::env::temp_dir().join("k180_dirstore_v3mig");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("v3.db");
        build_v3_db(&p).unwrap();
        let opened = DirStore::open_ex(&p).unwrap();
        assert!(!opened.rebuilt, "v3→v4 不得触发损坏重建");
        let s = &opened.store;
        // v2 三表零触碰（目录行/epoch 连续性）。
        let row = s.get("dev-v3", "t.test.relay").await.unwrap().unwrap();
        assert_eq!(row.note, "keep3", "v2 三表零损失");
        assert_eq!(s.get_epoch().await.unwrap(), 7, "epoch 连续性");
        assert_eq!(s.get_meta("schema_version").await.unwrap().as_deref(), Some("4"));
        {
            let conn = s.conn.lock().await;
            let ver: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
            assert_eq!(ver, 4, "user_version 必须推进 4");
            // v3 退役表零残留（事务内载体 DROP 收口）。
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ix_tokens_v3_retired'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 0, "v3 载体表必须 DROP");
            // cli 行：明文列 NULL + hash 列命中（独立预计算参考值）。
            let (tok, hash): (Option<String>, String) = conn
                .query_row(
                    "SELECT token, token_hash FROM ix_tokens WHERE source = 'cli' AND label = 'alpha'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(tok, None, "cli 行明文必须置 NULL");
            assert_eq!(
                hash,
                "ae061b6667749f694fef94099b50a71eb74148aa53e17b5fa844b581d3e949c5",
                "cli 行哈希 = 独立预计算 sha256"
            );
            // 撤销行：哈希化 + 撤销水位原样。
            let (hash2, revoked): (String, Option<i64>) = conn
                .query_row(
                    "SELECT token_hash, revoked_at FROM ix_tokens WHERE source = 'cli' AND label = 'beta'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(hash2, "342bdff7a21dd83e3e10684c61ba8636afca76614d46a25b448ff217380271fc");
            assert_eq!(revoked, Some(300), "撤销水位原样保留");
            // device 行：明文保留（C-6 边界）+ 哈希同步 + target 原样。
            let (tok3, hash3, td): (Option<String>, String, Option<String>) = conn
                .query_row(
                    "SELECT token, token_hash, target_domain FROM ix_tokens WHERE source = 'device'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(tok3.as_deref(), Some("r180-device-cachetoken-000000001"), "device 行明文保留");
            assert_eq!(hash3, "3604708ca85869092b0b9ae8e7464e8da94723a61ca83a3744760212ab4ad7f7");
            assert_eq!(td.as_deref(), Some("b.example.com"));
        }
        // 门⑥哈希域：活跃 cli 串 = Some(true)；撤销串 = Some(false)；
        // 未知串/空串 = None（三态语义零变化）。
        assert_eq!(s.ix_token_cli_state("r180-cli-token-activetoken-000000001").await.unwrap(), Some(true));
        assert_eq!(s.ix_token_cli_state("r180-cli-token-revokedtok-00000001").await.unwrap(), Some(false));
        assert_eq!(s.ix_token_cli_state("no-such-token").await.unwrap(), None);
        assert_eq!(s.ix_token_cli_state("").await.unwrap(), None, "空串无命中");
        // device 缓存行不作门⑥凭据。
        assert_eq!(s.ix_token_cli_state("r180-device-cachetoken-000000001").await.unwrap(), None);
        // A 侧取缓存 = 明文原样（C-6 边界）。
        assert_eq!(
            s.ix_lookup_device_token("b.example.com").await.unwrap().as_deref(),
            Some("r180-device-cachetoken-000000001")
        );
        // 幂等：重开（已 v4）零副作用。
        drop(opened);
        let reopened = DirStore::open_ex(&p).unwrap();
        assert!(!reopened.rebuilt);
        assert_eq!(reopened.store.ix_list_tokens().await.unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_r180_v0_fresh_lands_v4_shape() {
        // v0 全新库：ix_tokens 直落 v4 形态（token_hash 列在位 + cli 行
        // CHECK 零明文执法生效），不经过 v3 中间形态。
        let p = temp_db("r180v0");
        let s = DirStore::open(&p).unwrap();
        {
            let conn = s.conn.lock().await;
            let ver: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
            assert_eq!(ver, 4);
            let hash_col: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('ix_tokens') WHERE name = 'token_hash'",
                    [],
                    |r| { let n: i64 = r.get(0)?; Ok(n > 0) },
                )
                .unwrap();
            assert!(hash_col, "新库 ix_tokens 必须直落 v4 形态");
            // CHECK 约束执法：cli 行写明文 = 拒（代码面之外的第二道闸）。
            let r = conn.execute(
                "INSERT INTO ix_tokens(token, token_hash, token_prefix, label, source, target_domain, created_at, revoked_at)
                 VALUES('plain', 'deadbeef', 'plain', 'x', 'cli', NULL, 1, NULL)",
                [],
            );
            assert!(r.is_err(), "cli 行明文必须被 CHECK 拒绝");
        }
        // DAO 冒烟（v4 面可写）。
        let added = s.ix_add_cli_token("fresh-v4-token-aaaaaaaaaa", "fresh", 1).await.unwrap();
        assert_eq!(added.token.as_deref(), Some("fresh-v4-token-aaaaaaaaaa"), "add 回执 = 全量仅此一次");
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    #[tokio::test]
    async fn test_r180_user_version_5_refused() {
        // user_version = 5（> SCHEMA_VERSION=4）= 拒启（fail-closed 不猜未来版本）。
        let p = temp_db("r180future");
        let s = DirStore::open(&p).unwrap();
        {
            let conn = s.conn.lock().await;
            conn.pragma_update(None, "user_version", 5).unwrap();
        }
        drop(s);
        let e = DirStore::open_ex(&p).unwrap_err();
        assert!(matches!(e, DirStoreError::UnsupportedSchemaVersion(5)), "{e:?}");
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }

    #[tokio::test]
    async fn test_r180_db_dump_cli_rows_zero_plaintext() {
        // dump 面：ix_tokens 全表导出后 cli 行明文串零出现（哈希在位），
        // device 行明文 = C-6 裁定白名单边界（原样在库，A 侧推送取出用）。
        let p = temp_db("r180dump");
        let s = DirStore::open(&p).unwrap();
        s.ix_add_cli_token("r180-dump-cli-secret-token-000001", "cli-x", 1).await.unwrap();
        s.ix_upsert_device_token("d.example.com", "r180-dump-device-cache-0001", "dev-x", 2).await.unwrap();
        let conn = s.conn.lock().await;
        let mut stmt = conn.prepare("SELECT token, token_hash, source FROM ix_tokens").unwrap();
        let mut dump = String::new();
        let mut rows = stmt.query_map([], |r| {
            Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })
        .unwrap();
        while let Some(r) = rows.next() {
            let (tok, hash, src) = r.unwrap();
            dump.push_str(&format!("[{src}] token={tok:?} hash={hash} "));
        }
        assert!(!dump.contains("r180-dump-cli-secret-token-000001"), "cli 行零明文: {dump}");
        assert!(dump.contains("r180-dump-device-cache-0001"), "device 行明文 = C-6 白名单边界");
        // cli 行哈希在位（独立预计算参考）。
        let cli_hash: String = conn
            .query_row(
                "SELECT token_hash FROM ix_tokens WHERE source = 'cli'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(cli_hash, kirin_desk_core::connection::sha256_bytes(b"r180-dump-cli-secret-token-000001").iter().map(|b| format!("{b:02x}")).collect::<String>());
        let _ = std::fs::remove_dir_all(p.parent().unwrap().join(p.file_name().unwrap()));
    }


    /// Unix 语义：open_ex 后 db 文件 mode == 0600（新建路径 + 损坏重建
    /// `rebuilt` 分支复测）。Windows 跳过（无 mode 语义，改由 ACL/README 口径）。
    #[cfg(unix)]
    #[tokio::test]
    async fn test_r179_open_ex_db_file_mode_0600_incl_rebuilt() {
        use std::os::unix::fs::PermissionsExt;
        let p = temp_db("r179perm");
        let _ = std::fs::remove_file(&p);
        // 先落 umask 默认（常为 0644 世界可读）的库，再走 open_ex 收紧。
        {
            let conn = Connection::open(&p).unwrap();
            conn.execute_batch("CREATE TABLE t(x)").unwrap();
        }
        let opened = DirStore::open_ex(&p).unwrap();
        assert!(!opened.rebuilt);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "open_ex 后 db 必须 0600");
        // 损坏 → rebuilt 分支（改名保留 + 新建库）同样收紧 0600。
        std::fs::write(&p, b"corrupted-not-a-sqlite-db").unwrap();
        let reopened = DirStore::open_ex(&p).unwrap();
        assert!(reopened.rebuilt);
        let mode2 = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode2, 0o600, "rebuilt 重建库同样 0600");
        let _ = std::fs::remove_file(&p);
    }

    /// Unix 语义：父目录为本卡新建（create_dir_all 发生时）→ 收紧 0700。
    #[cfg(unix)]
    #[tokio::test]
    async fn test_r179_newly_created_parent_dir_mode_0700() {
        use std::os::unix::fs::PermissionsExt;
        let i = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("kirin_r179_dir_{}_{}", std::process::id(), i));
        let _ = std::fs::remove_dir_all(&root);
        let p = root.join("nested/deep/relay.db");
        let opened = DirStore::open_ex(&p).unwrap();
        assert!(!opened.rebuilt);
        // 直接父目录（本卡新建）0700；write_private 未参与（数据库不走该入口）。
        let dir_mode = std::fs::metadata(p.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "新建父目录必须 0700");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 权限收紧失败路径：WARN + **不拒启**（fail-open；注入失败跨平台断言）。
    #[tokio::test]
    async fn test_r179_tighten_fail_does_not_refuse_start() {
        let p = temp_db("r179failopen");
        let _ = std::fs::remove_file(&p);
        INJECT_TIGHTEN_FAIL.with(|f| f.set(true));
        let opened = DirStore::open_ex(&p);
        INJECT_TIGHTEN_FAIL.with(|f| f.set(false));
        // 收紧失败不拒启（可用性优先，失败仅 WARN 交由审计）。
        assert!(opened.is_ok(), "tighten 失败必须不拒启");
        let opened = opened.unwrap();
        assert!(!opened.rebuilt);
        let _ = std::fs::remove_file(&p);
    }
}
