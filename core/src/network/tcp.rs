use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, warn};

/// S-02 (F-5)：长度前缀消息默认上限（16 MiB，对齐
/// `multiplex.rs` 的 [`DEFAULT_MAX_FRAME_LEN`]，同 crate 复用避免重复常量）。
use crate::connection::multiplex::DEFAULT_MAX_FRAME_LEN;

/// Error types for TCP operations.
#[derive(Debug, thiserror::Error)]
pub enum TcpError {
    #[error("Failed to bind to {socket}: {source}")]
    Bind {
        socket: SocketAddr,
        source: std::io::Error,
    },
    #[error("Failed to connect to {remote}: {source}")]
    Connect {
        remote: SocketAddr,
        source: std::io::Error,
    },
    #[error("Connection timeout to {remote}")]
    Timeout { remote: SocketAddr },
    /// S-02 (F-5)：消息超过允许的最大长度（`read_length_prefixed` 超限）。
    /// 读取侧在**分配缓冲区之前**拒绝，杜绝巨长前缀（如 `0xFFFFFFFF`）引发的
    /// 4 GiB 分配 DoS；调用方收到本错误后应关闭连接。
    #[error("Message too large: {len} bytes exceeds max {max} bytes")]
    MessageTooLarge { len: usize, max: usize },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// TCP server wrapper.
///
/// M8-T033：双栈监听。`[::]` 监听在 Windows 上为 IPv6-only（v4 连接被拒），
/// 故按「v6 双栈 → v6-only + v4 双监听 → 仅 v4」逐级回退，保证 v4 客户端
/// 可连（详见 [`TcpServer::bind`]）。R-19b：`accept` 返回 `SocketAddr`，
/// v4-mapped v6（`::ffff:a.b.c.d`）在事件层呈现为真实 v4 地址（前缀剥离）。
pub struct TcpServer {
    /// 主监听：v6 双栈（v4-mapped 承接 v4）或 v6-only。
    v6: Option<TcpListener>,
    /// v4 兜底监听（仅 v6-only 路径存在；双栈路径无需）。
    v4: Option<TcpListener>,
    /// 统一端口（两监听同端口，取 v6 的实际端口）。
    port: u16,
}

impl TcpServer {
    /// 双栈绑定 `port`（0 = 系统分配），逐级回退，任一成功即组合生效：
    ///
    /// 1. **v6 双栈**：socket2 v6 socket + `set_only_v6(false)` + `[::]:port`
    ///    —— Linux/macOS 及支持 `IPV6_V6ONLY=0` 的 Windows 上一步到位
    ///    （v4-mapped 连接由 v6 监听承接）；
    /// 2. **v6-only + v4**：`set_only_v6(true)` 绑 `[::]:port` 成功 → 同端口
    ///    再绑 `0.0.0.0:port`（Windows 典型路径）；v4 绑失败不影响 v6（仅日志）；
    /// 3. **仅 v4**：v6 不可用（无 IPv6 栈）→ `0.0.0.0:port`。
    pub async fn bind(port: u16) -> Result<Self, TcpError> {
        debug!("TcpServer::bind(port={})", port);

        // 1) v6 双栈（IPV6_V6ONLY=0）：v4-mapped 连接经 v6 监听承接。
        if let Some(socket) = Self::new_v6_socket() {
            let dual_ok = socket.set_only_v6(false).is_ok()
                && socket
                    .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())
                    .is_ok();
            if dual_ok {
                match socket.listen(1024) {
                    Ok(_) => {
                        let listener = tokio::net::TcpListener::from_std(socket.into())
                            .map_err(TcpError::Io)?;
                        let addr = listener.local_addr().map_err(|source| TcpError::Bind {
                            socket: SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
                            source,
                        })?;
                        debug!("TcpServer::bind: dual-stack [::]:{}", addr.port());
                        return Ok(Self {
                            v6: Some(listener),
                            v4: None,
                            port: addr.port(),
                        });
                    }
                    Err(e) => warn!("dual-stack listen [::]:{port} failed: {e}; trying v6-only + v4"),
                }
            }
        }

        // 2) v6-only + v4 兜底：显式 v6-only 绑 `[::]:port`（保证 v4 端口可用），
        //    成功后再补绑同端口 `0.0.0.0`（v4 失败仅日志，v6 保持监听）。
        if let Some(socket) = Self::new_v6_socket() {
            let v6_only_ok = socket.set_only_v6(true).is_ok()
                && socket
                    .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())
                    .is_ok();
            if v6_only_ok {
                match socket.listen(1024) {
                    Ok(_) => {
                        let v6 = match tokio::net::TcpListener::from_std(socket.into()) {
                            Ok(l) => l,
                            Err(e) => return Err(TcpError::Io(e)),
                        };
                        let addr = v6.local_addr().map_err(|source| TcpError::Bind {
                            socket: SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
                            source,
                        })?;
                        // 同端口补绑 v4（port=0 时以 v6 实际端口为准）。
                        let v4 = match Self::bind_v4(addr.port()).await {
                            Ok(l) => {
                                debug!("TcpServer::bind: v4 fallback 0.0.0.0:{}", addr.port());
                                Some(l)
                            }
                            Err(e) => {
                                warn!(
                                    "v4 fallback bind 0.0.0.0:{} failed: {e}; \
                                     v6-only listener keeps serving",
                                    addr.port()
                                );
                                None
                            }
                        };
                        return Ok(Self {
                            v6: Some(v6),
                            v4,
                            port: addr.port(),
                        });
                    }
                    Err(e) => warn!("v6-only listen [::]:{port} failed: {e}; trying v4-only"),
                }
            }
        }

        // 3) 仅 v4：无 IPv6 栈（或 v6 绑定失败）→ `0.0.0.0:port`。
        let listener = Self::bind_v4(port).await?;
        let addr = listener.local_addr()?;
        debug!("TcpServer::bind: v4-only 0.0.0.0:{}", addr.port());
        Ok(Self {
            v6: None,
            v4: Some(listener),
            port: addr.port(),
        })
    }

    /// 创建 v6 TCP socket（失败 = 无 IPv6 栈）。
    fn new_v6_socket() -> Option<socket2::Socket> {
        socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .ok()
    }

    /// 绑 `0.0.0.0:port` 监听（v4 兜底路径共用）。
    async fn bind_v4(port: u16) -> Result<TcpListener, TcpError> {
        TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .await
            .map_err(|source| TcpError::Bind {
                socket: SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
                source,
            })
    }

    /// Accept 一条入站连接。R-19b：返回 `SocketAddr`（v4/v6 统一视角）——
    /// v4-mapped v6（`::ffff:a.b.c.d`）呈现为真实 v4（`map_addr` 前缀剥离），
    /// 原生 v6 保持不变；下游限速/审计无需再 `to_canonical()`（幂等，兼容旧路径）。
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), TcpError> {
        let (stream, addr) = match (&self.v6, &self.v4) {
            (Some(v6), Some(v4)) => {
                tokio::select! {
                    r = v6.accept() => r?,
                    r = v4.accept() => r?,
                }
            }
            (Some(v6), None) => v6.accept().await?,
            (None, Some(v4)) => v4.accept().await?,
            (None, None) => unreachable!("TcpServer always holds at least one listener"),
        };
        // R-31（审计 §4-3）：accept 侧同样关闭 Nagle —— 服务端→客户端的小包
        // （音频/键鼠）不被大帧滞留。失败不致命（连接仍可用，仅延迟优化失效）。
        if let Err(e) = set_nodelay(&stream) {
            debug!("set_nodelay failed: {e}");
        }
        Ok((stream, Self::map_addr(addr)))
    }

    /// 把 accept 得到的 [`SocketAddr`] 规范化为事件层统一视角（R-19b）：
    /// v4 保持 v4；v4-mapped v6（`::ffff:a.b.c.d`）还原为真实 v4 地址
    /// （前缀剥离）；原生 v6 保持不变。
    fn map_addr(addr: SocketAddr) -> SocketAddr {
        match addr {
            SocketAddr::V4(v4) => SocketAddr::V4(v4),
            SocketAddr::V6(v6) => match v6.ip().to_canonical() {
                IpAddr::V4(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
                IpAddr::V6(_) => SocketAddr::V6(v6),
            },
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// 主监听（v6 优先；纯 v4 环境返回 v4 监听）。
    pub fn listener(&self) -> &TcpListener {
        self.v6
            .as_ref()
            .or(self.v4.as_ref())
            .expect("TcpServer always holds at least one listener")
    }
}

/// TCP client for connecting to remote hosts.
pub struct TcpClient;

impl TcpClient {
    /// Connect to a remote host (IPv4 or IPv6).
    pub async fn connect(addr: SocketAddr) -> Result<TcpStream, TcpError> {
        debug!("TcpClient::connect -> {}", addr);
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| TcpError::Connect { remote: addr, source: e })?;
        debug!("TcpClient::connect <- OK from {}", addr);
        Ok(stream)
    }

    /// Connect to a remote host with a timeout (IPv4 or IPv6). Default 5s.
    pub async fn connect_with_timeout(
        addr: SocketAddr, timeout_secs: u64,
    ) -> Result<TcpStream, TcpError> {
        use std::time::Duration;
        tokio::time::timeout(Duration::from_secs(timeout_secs), TcpStream::connect(addr))
            .await
            .map_err(|_| TcpError::Timeout { remote: addr })?
            .map_err(|e| TcpError::Connect { remote: addr, source: e })
    }
}

// ── R-31：TCP_NODELAY（Nagle 关闭） ───────────────────────────

/// R-31（审计 §4-3）：关闭 Nagle 算法（`TCP_NODELAY`）。
///
/// Windows 默认开启 Nagle：大帧（视频）在途未 ACK 时，其后紧跟的小包
/// （音频/键鼠）不会立即发出，产生交互延迟。全仓 TCP 连接建立后统一调用
/// 本辅助（落点：`TcpServer::accept`、`client.rs::connect_peer`、
/// media TCP transport；relay 为叶子 crate 不依赖 core，直接调用
/// `TcpStream::set_nodelay`）。
///
/// 失败不致命：仅延迟优化失效，连接仍可用，调用方按告警处理。
pub fn set_nodelay(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)
}

// ── 泛型消息收发（用于 QUIC 流等） ──────────────────────────

/// Send a length-prefixed message over any async write stream.
pub async fn send_message<S: AsyncWrite + Unpin>(
    stream: &mut S, data: &[u8],
) -> Result<(), TcpError> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// 读一条长度前缀消息（4 字节大端长度 + payload），payload 长度上限 `max_len`。
///
/// S-02 (F-5)：长度前缀超限即返回 [`TcpError::MessageTooLarge`]，**不会**按
/// 前缀值分配缓冲区（拒绝 `0xFFFFFFFF` 等巨长前缀引发的 4 GiB 分配 DoS）。
/// 调用方收到错误后应关闭连接。tcp 层与已握手通道（`handshake.rs` 的
/// `SecureChannel::receive` / `SecureChannelReader::receive`）共用本函数，
/// 保证所有服务端读路径的长度上限行为一致。
pub async fn read_length_prefixed<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_len: usize,
) -> Result<Vec<u8>, TcpError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(TcpError::MessageTooLarge { len, max: max_len });
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Receive a length-prefixed message from any async read stream.
///
/// S-02 (F-5)：默认上限 [`DEFAULT_MAX_FRAME_LEN`]（16 MiB），超限返回
/// [`TcpError::MessageTooLarge`]（连接由调用方关闭）；需要自定义上限的调用方
/// 请使用 [`read_length_prefixed`]。
pub async fn receive_message<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, TcpError> {
    read_length_prefixed(stream, DEFAULT_MAX_FRAME_LEN as usize).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_message_format() {
        let data = b"hello";
        let len = data.len() as u32;
        assert_eq!(len.to_be_bytes(), [0, 0, 0, 5]);
    }

    #[tokio::test]
    async fn test_tcp_server_bind() {
        let server = TcpServer::bind(0).await.unwrap();
        assert!(server.port() > 0);
    }

    #[tokio::test]
    async fn test_connect_ipv4_loopback() {
        // M8-T033: TcpServer 双栈后 v4 回环直连可用（旧版 `[::]` 监听在
        // Windows 为 IPv6-only、v4 被拒，此处只能绑裸 127.0.0.1 绕开）。
        let server = TcpServer::bind(0).await.unwrap();
        let port = server.port();
        let handle = tokio::spawn(async move {
            server.accept().await.unwrap();
        });
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let stream = TcpClient::connect(remote).await.unwrap();
        assert!(stream.peer_addr().is_ok());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_dual_stack_accepts_ipv4() {
        // M8-T033 + R-19b: 双栈路径（v6 双栈或 v6-only+v4 双监听）下 v4 回环
        // 可连 TcpServer；R-19b 起 accept 把 v4 连接呈现为**真实 v4 地址**
        // （不再 v4-mapped v6 `::ffff:` 前缀），事件层视角 v4/v6 统一。
        let server = TcpServer::bind(0).await.unwrap();
        let port = server.port();
        let handle = tokio::spawn(async move {
            server.accept().await.unwrap()
        });
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let stream = TcpClient::connect(remote).await.unwrap();
        let (_stream, addr) = handle.await.unwrap();
        // v4 连接 → 真实 v4 地址（`127.0.0.1`，端口为客户端临时源端口），
        // 无 `::ffff:` 前缀。
        assert_eq!(addr.ip(), remote.ip(), "v4 连接应呈现为真实 v4 地址");
        assert!(matches!(addr, SocketAddr::V4(_)));
        assert!(
            !addr.ip().to_string().starts_with("::ffff:"),
            "不应残留 v4-mapped 前缀: {addr}"
        );
        assert!(stream.peer_addr().is_ok());
    }

    #[tokio::test]
    async fn test_connect_ipv6_loopback() {
        let server = TcpServer::bind(0).await.unwrap();
        let port = server.port();
        let handle = tokio::spawn(async move {
            server.accept().await.unwrap()
        });
        let remote = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
        let stream = TcpClient::connect(remote).await.unwrap();
        // R-19b：原生 v6 路径零回归——accept 呈现的仍是 v6 地址（[::1]，
        // 端口为客户端临时源端口）。
        let (_stream, addr) = handle.await.unwrap();
        assert_eq!(addr.ip(), remote.ip(), "原生 v6 连接应原样呈现");
        assert!(matches!(addr, SocketAddr::V6(_)));
        assert!(stream.peer_addr().is_ok());
    }

    // ── R-31：set_nodelay 辅助（审计 §4-3，Windows Nagle 小包滞留） ──

    /// R-31：helper 在已连接 socket 上生效（`nodelay()` 可读回 true）。
    #[tokio::test]
    async fn test_set_nodelay_roundtrip() {
        let server = TcpServer::bind(0).await.unwrap();
        let port = server.port();
        let handle = tokio::spawn(async move {
            server.accept().await.unwrap();
        });
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let stream = TcpClient::connect(remote).await.unwrap();
        set_nodelay(&stream).unwrap();
        assert!(stream.nodelay().unwrap(), "TCP_NODELAY 应已开启");
        handle.await.unwrap();
    }

    /// R-31：`TcpServer::accept` 返回的流已统一关闭 Nagle。
    #[tokio::test]
    async fn test_accept_side_nodelay_enabled() {
        let server = TcpServer::bind(0).await.unwrap();
        let port = server.port();
        let handle = tokio::spawn(async move {
            let (stream, _) = server.accept().await.unwrap();
            stream.nodelay().unwrap()
        });
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let _stream = TcpClient::connect(remote).await.unwrap();
        assert!(
            handle.await.unwrap(),
            "accept 侧连接应已设置 TCP_NODELAY"
        );
    }

    #[tokio::test]
    async fn test_connect_timeout() {
        // 黑洞地址多候选探测：正常网络下 link-local / RFC 5737 TEST-NET 地址
        // 无人应答，connect 挂起直至超时；但透明代理型网络（本机实测）会立即
        // 应答一切出站 SYN，用户态无法构造连接挂起 → 全部候选秒答则跳过并提示。
        const CANDIDATES: [[u8; 4]; 3] = [
            [169, 254, 0, 1],    // IPv4 link-local（ARP 黑洞）
            [192, 0, 2, 1],      // TEST-NET-1（RFC 5737）
            [198, 51, 100, 1],   // TEST-NET-2（RFC 5737）
        ];
        for octets in CANDIDATES {
            let remote = SocketAddr::from((Ipv4Addr::from(octets), 9999));
            match TcpClient::connect_with_timeout(remote, 1).await {
                Err(TcpError::Timeout { remote: r }) if r == remote => return, // 超时路径验证成功
                other => {
                    eprintln!("candidate {remote} answered instantly ({other:?}); trying next");
                }
            }
        }
        eprintln!(
            "skip: network answers every outbound SYN (transparent proxy); \
             connect-timeout path cannot be exercised from userspace here"
        );
    }

    #[tokio::test]
    async fn test_connect_refused() {
        // Reserve a port with a listener, then drop it so the connect is refused.
        let server = TcpServer::bind(0).await.unwrap();
        let port = server.port();
        drop(server);
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let err = TcpClient::connect(remote).await.unwrap_err();
        assert!(matches!(err, TcpError::Connect { remote: r, .. } if r == remote));
    }

    #[tokio::test]
    async fn test_send_receive_roundtrip() {
        use tokio::net::TcpListener as TokioListener;
        let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let msg = receive_message(&mut stream).await.unwrap();
            assert_eq!(msg, b"ping");
            send_message(&mut stream, b"pong").await.unwrap();
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        send_message(&mut client, b"ping").await.unwrap();
        let response = receive_message(&mut client).await.unwrap();
        assert_eq!(response, b"pong");
        handle.await.unwrap();
    }

    // ── S-02 (F-5)：长度前缀上限 / 超长拒绝 / 并发 accept 不阻塞 ─────────

    /// S-02a：`0xFFFFFFFF` 长度前缀 → `MessageTooLarge` 错误（且不分配 4 GiB），
    /// 服务端随后关闭连接（读侧返回错误后调用方 drop 流）。
    #[tokio::test]
    async fn test_receive_message_oversized_rejected() {
        use tokio::net::TcpListener as TokioListener;
        let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // 客户端只发 4 字节巨长前缀（0xFFFFFFFF），不发 payload。
            let err = receive_message(&mut stream).await.unwrap_err();
            match &err {
                TcpError::MessageTooLarge { len, max } => {
                    assert_eq!(*len, u32::MAX as usize);
                    assert_eq!(*max, DEFAULT_MAX_FRAME_LEN as usize);
                }
                other => panic!("expected MessageTooLarge, got {:?}", other),
            }
            err
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();
        server.await.unwrap();
    }

    /// S-02a：上限边界——自定义小上限拒绝；默认 16 MiB 超一字节拒绝（读侧
    /// 不按前缀分配缓冲）；恰好 16 MiB 正常收发。超限后帧流已不同步，协议上
    /// 连接即关闭，故各场景用独立连接验证。
    #[tokio::test]
    async fn test_read_length_prefixed_boundary() {
        use tokio::net::TcpListener as TokioListener;

        // 1) 自定义小上限（max=4）：8 字节 payload → MessageTooLarge。
        let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let err = read_length_prefixed(&mut stream, 4).await.unwrap_err();
            assert!(matches!(err, TcpError::MessageTooLarge { len: 8, max: 4 }));
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(&8u32.to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();
        server.await.unwrap();

        // 2) 默认上限 16 MiB：16 MiB + 1 → MessageTooLarge。
        let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let err = read_length_prefixed(&mut stream, DEFAULT_MAX_FRAME_LEN as usize)
                .await
                .unwrap_err();
            match &err {
                TcpError::MessageTooLarge { len, max } => {
                    assert_eq!(*len, DEFAULT_MAX_FRAME_LEN as usize + 1);
                    assert_eq!(*max, DEFAULT_MAX_FRAME_LEN as usize);
                }
                other => panic!("expected MessageTooLarge, got {:?}", other),
            }
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let oversized = DEFAULT_MAX_FRAME_LEN as usize + 1;
        client.write_all(&(oversized as u32).to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();
        server.await.unwrap();

        // 3) 恰好 16 MiB → 正常收发。
        let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let payload = vec![0xabu8; DEFAULT_MAX_FRAME_LEN as usize];
            let got = read_length_prefixed(&mut stream, DEFAULT_MAX_FRAME_LEN as usize)
                .await
                .unwrap();
            assert_eq!(got, payload);
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let payload = vec![0xabu8; DEFAULT_MAX_FRAME_LEN as usize];
        client.write_all(&(payload.len() as u32).to_be_bytes()).await.unwrap();
        client.write_all(&payload).await.unwrap();
        client.flush().await.unwrap();
        server.await.unwrap();
    }

    /// S-02c：accept 循环逐连接 spawn（每 handler 慢速处理）→ 并发连接不阻塞
    /// accept（N 个慢 handler 并存，总耗时 ≈ 单个 handler 耗时而非 N 倍）。
    #[tokio::test]
    async fn test_concurrent_accept_handlers_not_blocked() {
        use tokio::net::TcpListener as TokioListener;
        let listener = std::sync::Arc::new(TokioListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();
        const N: usize = 32;
        const HANDLER_SLEEP: std::time::Duration = std::time::Duration::from_millis(250);

        // 模拟「每连接 spawn 并发」的服务端：accept 后立即 spawn 慢 handler。
        let listener_clone = listener.clone();
        let accept_task = tokio::spawn(async move {
            let mut spawned = 0usize;
            while spawned < N {
                let (mut _stream, _) = listener_clone.accept().await.unwrap();
                spawned += 1;
                tokio::spawn(async move {
                    tokio::time::sleep(HANDLER_SLEEP).await;
                });
            }
        });

        let start = std::time::Instant::now();
        let mut clients = Vec::new();
        for _ in 0..N {
            clients.push(tokio::net::TcpStream::connect(addr).await.unwrap());
        }
        accept_task.await.unwrap();
        let elapsed = start.elapsed();
        // 顺序处理需 N × 250ms = 8s；并发下应远小于该值（留足 CI 余量）。
        let sequential = HANDLER_SLEEP * N as u32;
        assert!(
            elapsed < sequential / 4,
            "concurrent accept should not serialize handlers: elapsed={:?}, sequential={:?}",
            elapsed,
            sequential
        );
    }
}
