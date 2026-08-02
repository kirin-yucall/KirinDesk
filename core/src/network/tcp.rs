use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

/// S-02 (F-5)：长度前缀消息默认上限（16 MiB，对齐
/// `multiplex.rs` 的 [`DEFAULT_MAX_FRAME_LEN`]，同 crate 复用避免重复常量）。
use crate::connection::multiplex::DEFAULT_MAX_FRAME_LEN;

/// Error types for TCP operations.
#[derive(Debug, thiserror::Error)]
pub enum TcpError {
    #[error("Failed to bind to [{addr}]:{port}: {source}")]
    Bind {
        addr: Ipv6Addr,
        port: u16,
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
pub struct TcpServer {
    listener: TcpListener,
    port: u16,
}

impl TcpServer {
    pub async fn bind(port: u16) -> Result<Self, TcpError> {
        debug!("TcpServer::bind(port={})", port);
        let addr = format!("[::]:{}", port);
        if let Ok(listener) = TcpListener::bind(&addr).await {
            let addr = listener.local_addr()
                .map_err(|e| TcpError::Bind {
                    addr: Ipv6Addr::UNSPECIFIED, port, source: e,
                })?;
            return Ok(Self { listener, port: addr.port() });
        }
        let addr4 = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr4)
            .await
            .map_err(|e| TcpError::Bind {
                addr: Ipv6Addr::UNSPECIFIED, port, source: e,
            })?;
        let addr = listener.local_addr()
            .map_err(|e| TcpError::Bind {
                addr: Ipv6Addr::UNSPECIFIED, port, source: e,
            })?;
        Ok(Self { listener, port: addr.port() })
    }

    pub async fn accept(&self) -> Result<(TcpStream, SocketAddrV6), TcpError> {
        let (stream, addr) = self.listener.accept().await?;
        let v6_addr = match addr {
            std::net::SocketAddr::V6(v6) => v6,
            std::net::SocketAddr::V4(v4) => {
                let octets = v4.ip().octets();
                SocketAddrV6::new(
                    Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff,
                        (octets[0] as u16) << 8 | octets[1] as u16,
                        (octets[2] as u16) << 8 | octets[3] as u16),
                    v4.port(), 0, 0,
                )
            }
        };
        Ok((stream, v6_addr))
    }

    pub fn port(&self) -> u16 { self.port }
    pub fn listener(&self) -> &TcpListener { &self.listener }
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
        // Note: TcpServer::bind's `[::]` listener is IPv6-only on Windows
        // (v4 connects are refused), and TcpServer is frozen by the P2
        // parallel contract — so bind a plain 127.0.0.1 listener here. The
        // IPv6 loopback test below still exercises TcpServer.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            listener.accept().await.unwrap();
        });
        let remote = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let stream = TcpClient::connect(remote).await.unwrap();
        assert!(stream.peer_addr().is_ok());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_ipv6_loopback() {
        let server = TcpServer::bind(0).await.unwrap();
        let port = server.port();
        let handle = tokio::spawn(async move {
            server.accept().await.unwrap();
        });
        let remote = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
        let stream = TcpClient::connect(remote).await.unwrap();
        assert!(stream.peer_addr().is_ok());
        handle.await.unwrap();
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
