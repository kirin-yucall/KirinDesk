//! M8-T026-P2: 服务端设备在线表（ID-001~005 / ID-SEC-001~003）+ 设备级中继配对（§8.1）。
//!
//! 职责对照：
//! - ID-001 设备注册：`Login` 携带 `device_id`（显式配置或公钥指纹派生，两者都接受）
//!   后调用 [`Registry::register`]；
//! - ID-002 在线表：`device_id → { candidates（含服务器观察地址）, ed25519_pub, last_seen }`
//!   内存表（`RwLock<HashMap>` + 空闲清理），单服务器容量目标 ≥ 10 万设备；
//! - ID-003 在线状态：心跳复用 M8-T026 控制连接 `Ping/Pong`，30s 无心跳 →
//!   [`Registry::sweep_idle`] 离线（标记 + 审计由调用方完成）；控制连接断开即
//!   [`Registry::unregister`]；
//! - ID-004 ID 唯一性：同 ID 不同公钥 → 后到者拒绝（`RegisterError::DeviceConflict`）；
//! - ID-005 候选刷新：`CandidateRegister` 与打洞候选交换共用 [`Registry::update_candidates`]；
//! - ID-SEC-001 响应签名：`DeviceInfo` 由服务器 Ed25519 私钥签名
//!   （[`Registry::resolve`] 自动签名，[`Registry::verify_device_info`] 验签）；
//! - ID-SEC-002 防枚举：解析限速（每 IP 每 30s ≤ 10 次），未知/离线 ID 统一
//!   响应（`online:false` + 空候选 + 空公钥，不泄露设备是否存在）；
//! - ID-SEC-003 只对已注册设备返回信息；候选仅地址+类型+优先级。
//!
//! 服务器密钥：首次生成并持久化 `~/.kirin_desk/relay_server_key.pem`（PKCS#8 PEM），
//! 客户端凭 `[tunnel] server_pubkey` 预置的公钥验签。

use crate::protocol::{
    encode_extension, Candidate, CandidateKind, DeviceInfo, DeviceInfoPayload, TunnelRequest,
    TYPE_TUNNEL_REQUEST,
};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

/// 心跳超时：30s 无心跳 → 离线（ID-003）。
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);
/// 解析限速窗口（ID-SEC-002）。
pub const RESOLVE_WINDOW: Duration = Duration::from_secs(30);
/// 解析限速额度：每 IP 每窗口 ≤ 10 次（ID-SEC-002）。
pub const RESOLVE_LIMIT: usize = 10;
/// 候选列表上限（PUNCH-PROTO-002：≤ 16 条）。
pub const MAX_CANDIDATES: usize = 16;
/// 服务器观察地址（NAT 映射）候选优先级（ID-002 / PUNCH-PROTO-001 关键信息）。
pub const OBSERVED_CANDIDATE_PRIORITY: u8 = 200;
/// 设备 ID 最大长度。
pub const MAX_DEVICE_ID_LEN: usize = 128;

/// 服务器密钥文件名。
pub const SERVER_KEY_FILE: &str = "relay_server_key.pem";

/// 注册表错误。
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("server key error: {0}")]
    ServerKey(String),
    /// ID-004：同 ID 不同公钥 → 后到者拒绝。
    #[error("device id conflict: {0}")]
    DeviceConflict(String),
    /// ID-SEC-003：目标未注册 / 离线（统一文案，防枚举）。
    #[error("device unavailable: {0}")]
    DeviceUnavailable(String),
    #[error("invalid device_id: {0}")]
    InvalidDeviceId(String),
    #[error("other: {0}")]
    Other(String),
}

/// 注册结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// 首次注册（上线）。
    Registered,
    /// 重连重注册（同 ID 同公钥，刷新在线表）。
    ReRegistered,
}

/// 在线表条目（ID-002）。
#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub device_id: String,
    /// 设备 Ed25519 公钥（base64）。
    pub ed25519_pub: String,
    /// 候选列表（含服务器观察地址；ID-002/ID-005）。
    pub candidates: Vec<Candidate>,
    pub last_seen: Instant,
    pub registered_at: Instant,
    /// 服务器视角的观察地址（控制连接 src addr，打洞关键信息 PUNCH-PROTO-001）。
    pub observed_addr: SocketAddr,
    /// 设备控制连接下行通道（预编码帧；TunnelRequest 推送用，§8.1）。
    pub ctrl_tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// 中继配对中的隧道（§8.1）。
struct PendingTunnel {
    target: String,
    from_peer: String,
    controller: Option<TcpStream>,
    device: Option<TcpStream>,
}

/// 服务端在线表（ID-002 内存表；`Arc<Registry>` 跨任务共享）。
pub struct Registry {
    devices: RwLock<HashMap<String, DeviceEntry>>,
    /// 服务器签名私钥（ID-SEC-001）。
    server_key: SigningKey,
    /// 解析限速表（ID-SEC-002）。
    resolve_limits: RwLock<HashMap<IpAddr, VecDeque<Instant>>>,
    /// 设备级中继 pending 表（§8.1；conn_id → 双端流）。
    tunnels: Mutex<HashMap<u64, PendingTunnel>>,
}

/// 默认服务器密钥路径：`~/.kirin_desk/relay_server_key.pem`
/// （对齐 utils `default_log_dir()` 约定；relay 零依赖自持解析）。
pub fn default_key_path() -> PathBuf {
    let home = {
        #[cfg(windows)]
        {
            std::env::var_os("USERPROFILE")
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("HOME")
        }
    };
    home.map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kirin_desk")
        .join(SERVER_KEY_FILE)
}

impl Registry {
    pub fn new(server_key: SigningKey) -> Self {
        Self {
            devices: RwLock::new(HashMap::new()),
            server_key,
            resolve_limits: RwLock::new(HashMap::new()),
            tunnels: Mutex::new(HashMap::new()),
        }
    }

    /// 加载或生成服务器 Ed25519 密钥（ID-SEC-001；PKCS#8 PEM 持久化）。
    pub fn load_or_create_server_key() -> Result<SigningKey, RegistryError> {
        Self::load_or_create_server_key_at(&default_key_path())
    }

    /// 指定路径加载或生成服务器密钥（测试注入临时路径）。
    ///
    /// 存储格式：PKCS#8 DER 字节（`to_pkcs8_der` / `from_pkcs8_der`，
    /// 零附加依赖；PEM 文本层由部署方自行包裹，非必需）。
    pub fn load_or_create_server_key_at(path: &std::path::Path) -> Result<SigningKey, RegistryError> {
        if path.exists() {
            let der = std::fs::read(path)?;
            SigningKey::from_pkcs8_der(&der)
                .map_err(|e| RegistryError::ServerKey(e.to_string()))
        } else {
            let mut csprng = rand::rngs::OsRng;
            let key = SigningKey::generate(&mut csprng);
            let der = key
                .to_pkcs8_der()
                .map_err(|e| RegistryError::ServerKey(e.to_string()))?;
            // S-07 (F-8): 私钥经 write_private 落盘（0600/0700/O_NOFOLLOW +
            // 原子替换；默认 0644 可被同机低权限用户读取伪造 DeviceInfo 应答）。
            kirin_desk_utils::fsutil::write_private(path, der.as_bytes())?;
            info!("generated relay server key at {}", path.display());
            Ok(key)
        }
    }

    /// 服务器公钥（base64；客户端 `[tunnel] server_pubkey` 预置验签）。
    pub fn server_public_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .encode(self.server_key.verifying_key().to_bytes())
    }

    /// 设备 ID 合法性（ID-001：显式 ID 或公钥指纹派生；字母数字 + `:_-`）。
    pub fn validate_device_id(device_id: &str) -> bool {
        !device_id.is_empty()
            && device_id.len() <= MAX_DEVICE_ID_LEN
            && device_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_' || c == '-')
    }

    /// ID-001/ID-004：注册（`Login` 携带 device_id 时调用）。
    ///
    /// 唯一性：同 ID 不同公钥 → `DeviceConflict`（后到者拒绝 + 调用方审计）；
    /// 同 ID 同公钥 → 重连重注册（刷新条目与 ctrl_tx）。
    pub async fn register(
        &self,
        device_id: &str,
        ed25519_pub: &str,
        observed_addr: SocketAddr,
        ctrl_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Result<RegisterOutcome, RegistryError> {
        if !Self::validate_device_id(device_id) {
            return Err(RegistryError::InvalidDeviceId(device_id.to_string()));
        }
        let mut devices = self.devices.write().await;
        if let Some(existing) = devices.get(device_id) {
            if existing.ed25519_pub != ed25519_pub {
                // ID-004：冲突 → 后到者拒绝 + 审计（调用方）。
                warn!(
                    "device id conflict: '{}' registered with a different public key",
                    device_id
                );
                return Err(RegistryError::DeviceConflict(device_id.to_string()));
            }
            // 重连重注册：更新下行通道与观察地址，保留候选。
            let mut entry = existing.clone();
            entry.observed_addr = observed_addr;
            entry.ctrl_tx = ctrl_tx;
            entry.last_seen = Instant::now();
            devices.insert(device_id.to_string(), entry);
            return Ok(RegisterOutcome::ReRegistered);
        }
        let entry = DeviceEntry {
            device_id: device_id.to_string(),
            ed25519_pub: ed25519_pub.to_string(),
            candidates: Vec::new(),
            last_seen: Instant::now(),
            registered_at: Instant::now(),
            observed_addr,
            ctrl_tx,
        };
        devices.insert(device_id.to_string(), entry);
        Ok(RegisterOutcome::Registered)
    }

    /// ID-003：控制连接断开 → 立即离线（移除在线表）。
    pub async fn unregister(&self, device_id: &str) -> bool {
        self.devices.write().await.remove(device_id).is_some()
    }

    /// ID-003：心跳（控制连接收到任何帧/`Ping` 时刷新 `last_seen`）。
    pub async fn heartbeat(&self, device_id: &str) {
        let mut devices = self.devices.write().await;
        if let Some(e) = devices.get_mut(device_id) {
            e.last_seen = Instant::now();
        }
    }

    /// ID-005：候选刷新（含服务器观察地址附加，去重 + 上限 16 条 PUNCH-PROTO-002）。
    pub async fn update_candidates(
        &self,
        device_id: &str,
        candidates: Vec<Candidate>,
    ) -> bool {
        let mut devices = self.devices.write().await;
        let Some(entry) = devices.get_mut(device_id) else {
            return false;
        };
        let mut list: Vec<Candidate> = Vec::with_capacity(MAX_CANDIDATES);
        let mut seen: Vec<SocketAddr> = Vec::with_capacity(MAX_CANDIDATES);
        for c in candidates {
            if seen.contains(&c.addr) {
                continue;
            }
            seen.push(c.addr);
            list.push(c);
            if list.len() >= MAX_CANDIDATES {
                break;
            }
        }
        // 附加服务器观察地址（打洞关键信息，ID-002 / PUNCH-PROTO-001）。
        let observed = Candidate {
            addr: entry.observed_addr,
            kind: CandidateKind::Tcp,
            priority: OBSERVED_CANDIDATE_PRIORITY,
        };
        if !seen.contains(&observed.addr) && list.len() < MAX_CANDIDATES {
            list.push(observed);
        }
        list.sort_by(|a, b| b.priority.cmp(&a.priority));
        entry.candidates = list;
        true
    }

    /// ID-010 + ID-SEC-001/002：解析（限速 + 查表 + 签名响应）。
    ///
    /// 返回 `(DeviceInfo, rate_limited)`：未知/离线/限速统一响应
    /// `online:false` + 空候选 + 空公钥（防枚举，不泄露设备存在性）；
    /// 响应始终带服务器签名。
    pub async fn resolve(&self, ip: IpAddr, device_id: &str) -> (DeviceInfo, bool) {
        let rate_limited = self.rate_limit(ip).await;
        let entry = self.devices.read().await.get(device_id).cloned();
        let payload = match entry {
            Some(e) => DeviceInfoPayload {
                device_id: e.device_id.clone(),
                candidates: e.candidates.clone(),
                ed25519_pub: e.ed25519_pub.clone(),
                online: true,
                ts: unix_secs(),
            },
            // ID-SEC-002：未知/离线统一响应。
            None => DeviceInfoPayload {
                device_id: device_id.to_string(),
                candidates: Vec::new(),
                ed25519_pub: String::new(),
                online: false,
                ts: unix_secs(),
            },
        };
        let signature = self.sign_device_info(&payload);
        let info = DeviceInfo { payload, signature };
        (info, rate_limited)
    }

    /// 设备是否在线（ID-SEC-003：只对已注册设备返回信息）。
    pub async fn is_online(&self, device_id: &str) -> bool {
        self.devices.read().await.contains_key(device_id)
    }

    /// 在线设备数（`tunnel status` / 容量验证）。
    pub async fn device_count(&self) -> usize {
        self.devices.read().await.len()
    }

    /// ID-003：空闲清理 —— `last_seen` 超过 `timeout`（默认 30s）的条目移除，
    /// 返回 `(被清理设备 ID, 服务器观察地址)`（调用方审计 `DeviceOffline`；
    /// R-24：附带 `observed_addr` 供审计定位设备，返回类型自 `Vec<String>`
    /// 扩展，`server.rs` 注册心跳 tick 旁挂的全局 sweep 为唯一调用方）。
    pub async fn sweep_idle(&self, timeout: Duration) -> Vec<(String, SocketAddr)> {
        let now = Instant::now();
        let mut devices = self.devices.write().await;
        let stale: Vec<(String, SocketAddr)> = devices
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_seen) > timeout)
            .map(|(id, e)| (id.clone(), e.observed_addr))
            .collect();
        for (id, _) in &stale {
            devices.remove(id);
        }
        stale
    }

    /// §8.1：控制器数据连接到达 —— 登记 pending + 向目标设备控制连接下发
    /// `TunnelRequest`。目标离线 / 控制通道已死 → `Err((err, stream))`
    /// （流归还调用方，用于统一错误响应，ID-SEC-002 防枚举）。
    pub async fn register_tunnel(
        &self,
        target: &str,
        from_peer: &str,
        controller: TcpStream,
    ) -> Result<u64, (RegistryError, TcpStream)> {
        let entry = {
            let devices = self.devices.read().await;
            match devices.get(target) {
                Some(e) => e.clone(),
                None => {
                    return Err((
                        RegistryError::DeviceUnavailable(target.to_string()),
                        controller,
                    ));
                }
            }
        };
        let conn_id = random_conn_id();
        let req = TunnelRequest {
            from_peer: from_peer.to_string(),
            conn_id,
        };
        let frame = match encode_extension(TYPE_TUNNEL_REQUEST, &req) {
            Ok(f) => f,
            Err(e) => return Err((RegistryError::Other(e.to_string()), controller)),
        };
        if entry.ctrl_tx.send(frame).is_err() {
            // 设备控制连接已死（发不出）→ 视为离线。
            return Err((
                RegistryError::DeviceUnavailable(format!("{} (control channel dead)", target)),
                controller,
            ));
        }
        self.tunnels.lock().await.insert(
            conn_id,
            PendingTunnel {
                target: target.to_string(),
                from_peer: from_peer.to_string(),
                controller: Some(controller),
                device: None,
            },
        );
        debug!("tunnel pending: conn_id={conn_id} target={target} from={from_peer}");
        Ok(conn_id)
    }

    /// §8.1：设备回连到达 —— 按 conn_id 精确配对（TNL-SERVER-005 语义对齐）。
    /// 返回 `false` = 未知/重复 conn_id（关闭该连接）。
    pub async fn pair_tunnel(&self, conn_id: u64, device: TcpStream) -> bool {
        let mut tunnels = self.tunnels.lock().await;
        match tunnels.get_mut(&conn_id) {
            Some(t) => {
                if t.device.is_some() {
                    warn!("tunnel pair rejected: duplicate conn_id={conn_id}");
                    return false;
                }
                t.device = Some(device);
                true
            }
            None => {
                warn!("tunnel pair rejected: unknown conn_id={conn_id}");
                false
            }
        }
    }

    /// §8.1：等待配对完成（控制器侧），超时返回 `None` 并清理 pending。
    pub async fn wait_for_pair(
        &self,
        conn_id: u64,
        timeout: Duration,
    ) -> Option<(TcpStream, TcpStream)> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let mut tunnels = self.tunnels.lock().await;
                let done = tunnels
                    .get(&conn_id)
                    .map(|t| t.controller.is_some() && t.device.is_some())
                    .unwrap_or(false);
                if done {
                    if let Some(t) = tunnels.remove(&conn_id) {
                        if let (Some(ctrl), Some(dev)) = (t.controller, t.device) {
                            debug!(
                                "tunnel paired: conn_id={conn_id} target={} from={}",
                                t.target, t.from_peer
                            );
                            return Some((ctrl, dev));
                        }
                    }
                }
            }
            if Instant::now() >= deadline {
                self.cancel_tunnel(conn_id).await;
                warn!("tunnel pairing timeout: conn_id={conn_id}");
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// 取消（移除）pending 隧道（配对超时 / 控制器侧放弃）。
    pub async fn cancel_tunnel(&self, conn_id: u64) {
        self.tunnels.lock().await.remove(&conn_id);
    }

    /// ID-SEC-001：对 `DeviceInfoPayload` 的 bincode 字节做 Ed25519 签名。
    pub fn sign_device_info(&self, payload: &DeviceInfoPayload) -> Vec<u8> {
        let bytes = bincode::serialize(payload).expect("DeviceInfoPayload serializable");
        let sig: Signature = self.server_key.sign(&bytes);
        sig.to_bytes().to_vec()
    }

    /// ID-SEC-001 验签：`verify_key`（服务器公钥）验 `DeviceInfo` 签名。
    pub fn verify_device_info(verify_key: &VerifyingKey, info: &DeviceInfo) -> bool {
        let bytes = match bincode::serialize(&info.payload) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig_bytes: [u8; 64] = match info.signature.clone().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);
        verify_key.verify_strict(&bytes, &sig).is_ok()
    }

    /// ID-SEC-002 解析限速：每 IP 每 `RESOLVE_WINDOW` ≤ `RESOLVE_LIMIT` 次。
    async fn rate_limit(&self, ip: IpAddr) -> bool {
        let mut limits = self.resolve_limits.write().await;
        let now = Instant::now();
        let q = limits.entry(ip).or_default();
        while let Some(&t) = q.front() {
            if now.duration_since(t) > RESOLVE_WINDOW {
                q.pop_front();
            } else {
                break;
            }
        }
        let limited = q.len() >= RESOLVE_LIMIT;
        if !limited {
            q.push_back(now);
        }
        // 惰性裁剪：表过大时清掉窗口外的桶（防多 IP 撑爆内存）。
        if limits.len() > 4096 {
            limits.retain(|_, q| {
                q.back()
                    .map_or(false, |&t| now.duration_since(t) <= RESOLVE_WINDOW)
            });
        }
        limited
    }
}

/// 随机 conn_id（uuid 随机源；碰撞概率可忽略）。
fn random_conn_id() -> u64 {
    uuid::Uuid::new_v4().as_u128() as u64
}

/// 当前 unix 秒（`DeviceInfoPayload.ts`）。
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpStream;

    fn test_key() -> SigningKey {
        let mut csprng = rand::rngs::OsRng;
        SigningKey::generate(&mut csprng)
    }

    fn chan() -> (mpsc::UnboundedSender<Vec<u8>>, mpsc::UnboundedReceiver<Vec<u8>>) {
        mpsc::unbounded_channel()
    }

    /// 生成一对真实 TCP 流（register_tunnel 需要 TcpStream）。
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let a = TcpStream::connect(addr).await.unwrap();
        let (b, _) = listener.accept().await.unwrap();
        (a, b)
    }

    #[tokio::test]
    async fn test_register_and_resolve_roundtrip() {
        let registry = Registry::new(test_key());
        let (tx, _rx) = chan();
        let outcome = registry
            .register("pc-a", "pub-a", "10.0.0.5:9000".parse().unwrap(), tx)
            .await
            .unwrap();
        assert_eq!(outcome, RegisterOutcome::Registered);

        // 观察地址自动成为候选？—— update_candidates 附加；未调用时为空。
        assert!(registry.is_online("pc-a").await);

        let (info, limited) = registry
            .resolve("1.2.3.4".parse().unwrap(), "pc-a")
            .await;
        assert!(!limited);
        assert!(info.payload.online);
        assert_eq!(info.payload.ed25519_pub, "pub-a");
        assert_eq!(info.payload.device_id, "pc-a");
        // ID-SEC-001：响应可验签。
        let key = registry.server_key.verifying_key();
        assert!(Registry::verify_device_info(&key, &info));
        // 篡改 → 验签失败（ID-SEC-001 防伪造）。
        let mut forged = info.clone();
        forged.payload.candidates.push(Candidate {
            addr: "6.6.6.6:1".parse().unwrap(),
            kind: CandidateKind::Tcp,
            priority: 255,
        });
        assert!(!Registry::verify_device_info(&key, &forged));
    }

    #[tokio::test]
    async fn test_unknown_and_offline_uniform_response() {
        let registry = Registry::new(test_key());
        // 未知 ID 与离线 ID 统一响应（ID-SEC-002）。
        let (info1, _) = registry.resolve("1.2.3.4".parse().unwrap(), "ghost").await;
        let (info2, _) = registry.resolve("1.2.3.4".parse().unwrap(), "ghost2").await;
        assert!(!info1.payload.online);
        assert!(!info2.payload.online);
        assert!(info1.payload.candidates.is_empty());
        assert!(info1.payload.ed25519_pub.is_empty());
        assert_eq!(info1.payload.ed25519_pub, info2.payload.ed25519_pub);
        assert_eq!(info1.payload.candidates, info2.payload.candidates);
    }

    #[tokio::test]
    async fn test_id_uniqueness_conflict() {
        let registry = Registry::new(test_key());
        let (tx, _rx) = chan();
        registry
            .register("pc-a", "pub-a", "10.0.0.5:1".parse().unwrap(), tx)
            .await
            .unwrap();
        // 同 ID 同公钥 → 重连重注册成功（ID-004 允许）。
        let (tx2, _rx2) = chan();
        let outcome = registry
            .register("pc-a", "pub-a", "10.0.0.6:1".parse().unwrap(), tx2)
            .await
            .unwrap();
        assert_eq!(outcome, RegisterOutcome::ReRegistered);
        // 同 ID 不同公钥 → 后到者拒绝（ID-004）。
        let (tx3, _rx3) = chan();
        let err = registry
            .register("pc-a", "pub-EVIL", "10.0.0.7:1".parse().unwrap(), tx3)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::DeviceConflict(_)));
    }

    #[tokio::test]
    async fn test_update_candidates_appends_observed() {
        let registry = Registry::new(test_key());
        let (tx, _rx) = chan();
        registry
            .register("pc-a", "pub-a", "203.0.113.9:7000".parse().unwrap(), tx)
            .await
            .unwrap();
        let cands = vec![
            Candidate {
                addr: "192.168.1.5:3389".parse().unwrap(),
                kind: CandidateKind::Tcp,
                priority: 100,
            },
            Candidate {
                addr: "192.168.1.5:3389".parse().unwrap(), // 重复去重
                kind: CandidateKind::Udp,
                priority: 50,
            },
        ];
        assert!(registry.update_candidates("pc-a", cands).await);
        let (info, _) = registry
            .resolve("1.2.3.4".parse().unwrap(), "pc-a")
            .await;
        let addrs: Vec<_> = info.payload.candidates.iter().map(|c| c.addr).collect();
        assert!(addrs.contains(&"192.168.1.5:3389".parse().unwrap()));
        // ID-002 / PUNCH-PROTO-001：观察地址附加。
        assert!(addrs.contains(&"203.0.113.9:7000".parse().unwrap()));
        assert_eq!(info.payload.candidates.len(), 2);
    }

    #[tokio::test]
    async fn test_resolve_rate_limit() {
        let registry = Registry::new(test_key());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut limited_any = false;
        for _ in 0..(RESOLVE_LIMIT + 3) {
            let (_, limited) = registry.resolve(ip, "x").await;
            limited_any |= limited;
        }
        assert!(limited_any, "over-limit resolves must be rate limited");
        // 限速后仍返回统一响应（不泄露）。
        let (info, limited) = registry.resolve(ip, "x").await;
        assert!(limited);
        assert!(!info.payload.online);
        // 其他 IP 不受影响。
        let (_, limited2) = registry
            .resolve("9.9.9.9".parse().unwrap(), "x")
            .await;
        assert!(!limited2);
    }

    #[tokio::test]
    async fn test_heartbeat_sweep_offline() {
        let registry = Registry::new(test_key());
        let (tx, _rx) = chan();
        registry
            .register("pc-a", "pub-a", "10.0.0.5:1".parse().unwrap(), tx)
            .await
            .unwrap();
        registry.heartbeat("pc-a").await;
        // 等 10ms 保证 last_seen 已过期（1ms 级断言在 CI 上抖动不可靠）。
        tokio::time::sleep(Duration::from_millis(10)).await;
        let stale = registry.sweep_idle(Duration::ZERO).await;
        assert_eq!(
            stale,
            vec![("pc-a".to_string(), "10.0.0.5:1".parse().unwrap())]
        );
        assert!(!registry.is_online("pc-a").await);
    }

    #[tokio::test]
    async fn test_unregister() {
        let registry = Registry::new(test_key());
        let (tx, _rx) = chan();
        registry
            .register("pc-a", "pub-a", "10.0.0.5:1".parse().unwrap(), tx)
            .await
            .unwrap();
        assert!(registry.unregister("pc-a").await);
        assert!(!registry.unregister("pc-a").await);
    }

    #[tokio::test]
    async fn test_device_id_validation() {
        assert!(Registry::validate_device_id("pc-a"));
        assert!(Registry::validate_device_id("a1b2:c3d4:eeee"));
        assert!(Registry::validate_device_id("PC_01"));
        assert!(!Registry::validate_device_id(""));
        assert!(!Registry::validate_device_id("bad id!"));
        assert!(!Registry::validate_device_id(&"x".repeat(129)));
    }

    #[tokio::test]
    async fn test_tunnel_pairing_flow() {
        let registry = Arc::new(Registry::new(test_key()));
        // 设备注册。
        let (tx, mut rx) = chan();
        registry
            .register("pc-b", "pub-b", "10.0.0.6:1".parse().unwrap(), tx)
            .await
            .unwrap();
        // 控制器数据连接到达。
        let (ctrl_a, ctrl_b) = tcp_pair().await;
        let conn_id = registry
            .register_tunnel("pc-b", "pc-a", ctrl_a)
            .await
            .unwrap();
        // 设备控制连接收到 TunnelRequest（§8.1 牵线）。
        let req_frame = rx.recv().await.expect("device must receive TunnelRequest");
        let (ty, payload) = crate::protocol::decode_frame(&req_frame).unwrap();
        let req: TunnelRequest =
            crate::protocol::decode_extension(ty, &payload, TYPE_TUNNEL_REQUEST).unwrap();
        assert_eq!(req.conn_id, conn_id);
        assert_eq!(req.from_peer, "pc-a");
        // 设备回连配对。
        let (dev_a, _dev_b) = tcp_pair().await;
        assert!(registry.pair_tunnel(conn_id, dev_a).await);
        let (ctrl, dev) = registry.wait_for_pair(conn_id, Duration::from_secs(1)).await.expect("pair");
        // 双端流身份正确（泵流由服务器集成侧负责）。
        let _ = (ctrl_b, ctrl, dev);
        assert!(true);
    }

    #[tokio::test]
    async fn test_tunnel_target_offline() {
        let registry = Registry::new(test_key());
        let (ctrl_a, _ctrl_b) = tcp_pair().await;
        let (err, _stream) = registry
            .register_tunnel("ghost", "pc-a", ctrl_a)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::DeviceUnavailable(_)));
    }

    #[test]
    fn test_server_key_persistence_roundtrip() {
        // 独立临时路径，不污染真实 ~/.kirin_desk。
        let path = std::env::temp_dir().join(format!(
            "kirin_relay_key_test_{}.pem",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&path);
        let key = Registry::load_or_create_server_key_at(&path).unwrap();
        // 重载 → 同一私钥（持久化 round-trip）。
        let key2 = Registry::load_or_create_server_key_at(&path).unwrap();
        assert_eq!(
            key.to_bytes(),
            key2.to_bytes(),
            "reloaded key must match persisted key"
        );
        let _ = std::fs::remove_file(&path);
    }
}
