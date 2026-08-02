use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

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
        remote: SocketAddrV6,
        source: std::io::Error,
    },
    #[error("Connection timeout to {remote}")]
    Timeout { remote: SocketAddrV6 },
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
    pub async fn connect(addr: Ipv6Addr, port: u16) -> Result<TcpStream, TcpError> {
        let remote = SocketAddrV6::new(addr, port, 0, 0);
        debug!("TcpClient::connect -> [{}]:{}", addr, port);
        let stream = TcpStream::connect(remote)
            .await
            .map_err(|e| TcpError::Connect { remote, source: e })?;
        debug!("TcpClient::connect <- OK from [{}]:{}", addr, port);
        Ok(stream)
    }

    pub async fn connect_with_timeout(
        addr: Ipv6Addr, port: u16, timeout_secs: u64,
    ) -> Result<TcpStream, TcpError> {
        use std::time::Duration;
        let remote = SocketAddrV6::new(addr, port, 0, 0);
        tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            TcpStream::connect(remote),
        )
        .await
        .map_err(|_| TcpError::Timeout { remote })?
        .map_err(|e| TcpError::Connect { remote, source: e })
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

/// Receive a length-prefixed message from any async read stream.
pub async fn receive_message<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Vec<u8>, TcpError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
