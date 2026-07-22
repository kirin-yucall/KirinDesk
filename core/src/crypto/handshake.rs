use crate::crypto::ed25519::IdentityManager;
use crate::crypto::x25519::EphemeralSession;
use crate::crypto::aead::AeadCipher;
use crate::network::tcp::{send_message, receive_message, TcpError};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

/// Handshake protocol errors.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("TCP error: {0}")]
    Tcp(#[from] TcpError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("Peer signature verification failed")]
    SignatureVerificationFailed,

    #[error("Invalid handshake message: {0}")]
    InvalidMessage(String),

    #[error("Timeout during handshake")]
    Timeout,

    #[error("Serialization error: {0}")]
    Serialization(String),
}

// ---- Handshake Messages ----

#[derive(Debug, Serialize, Deserialize)]
struct HandshakeInit {
    pub client_id: String,
    pub client_x25519_pub: [u8; 32],
    pub nonce: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HandshakeResponse {
    pub server_x25519_pub: [u8; 32],
    pub signature: Vec<u8>,
}

/// Result of a successful handshake.
pub struct SecureChannel {
    pub stream: TcpStream,
    pub cipher: AeadCipher,
    pub peer_id: String,
}

// ---- Client side (initiator) ----

pub async fn client_handshake(
    mut stream: TcpStream,
    client_identity: &IdentityManager,
    client_id: &str,
    server_id: &str,
    server_public_key_base64: &str,
) -> Result<SecureChannel, HandshakeError> {
    let session = EphemeralSession::new();
    let x25519_pub = session.public_key_bytes();
    let nonce = generate_nonce();

    // Sign: (x25519_pub || nonce || client_id)
    let sig_payload = build_sig_payload(&x25519_pub, &nonce, client_id);
    let signature = client_identity.sign(&sig_payload);

    // Send HandshakeInit
    let init_msg = HandshakeInit {
        client_id: client_id.to_string(),
        client_x25519_pub: x25519_pub,
        nonce,
        signature: signature.to_bytes().to_vec(),
    };
    let init_data = bincode::serialize(&init_msg)
        .map_err(|e| HandshakeError::Serialization(e.to_string()))?;
    send_message(&mut stream, &init_data).await?;

    // Receive HandshakeResponse
    let resp_data = receive_message(&mut stream).await?;
    let response: HandshakeResponse = bincode::deserialize(&resp_data)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;

    // Verify server signature
    let server_pubkey = IdentityManager::parse_public_key(server_public_key_base64)
        .map_err(|e| HandshakeError::Dns(e.to_string()))?;

    let resp_sig_payload = build_response_sig_payload(
        &response.server_x25519_pub,
        &x25519_pub,
        &nonce,
        server_id,
    );
    let resp_signature = Signature::from_slice(&response.signature)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;

    if !IdentityManager::verify_with_key(&server_pubkey, &resp_sig_payload, &resp_signature) {
        return Err(HandshakeError::SignatureVerificationFailed);
    }

    // Derive session key
    let peer_x25519 = EphemeralSession::parse_public_key(&response.server_x25519_pub);
    let session_key = session.compute_session_key(&peer_x25519);
    let cipher = AeadCipher::new(&session_key);

    Ok(SecureChannel {
        stream,
        cipher,
        peer_id: server_id.to_string(),
    })
}

// ---- Server side (responder) ----

pub async fn server_handshake(
    mut stream: TcpStream,
    server_identity: &IdentityManager,
    server_id: &str,
    client_id: &str,
    client_public_key_base64: &str,
) -> Result<SecureChannel, HandshakeError> {
    // Receive HandshakeInit
    let init_data = receive_message(&mut stream).await?;
    let init: HandshakeInit = bincode::deserialize(&init_data)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;

    // Use the client_id from the message for verification
    let actual_client_id = &init.client_id;

    // Parse client public key & verify signature
    let client_pubkey = IdentityManager::parse_public_key(client_public_key_base64)
        .map_err(|e| HandshakeError::Dns(e.to_string()))?;

    let sig_payload = build_sig_payload(&init.client_x25519_pub, &init.nonce, actual_client_id);
    let client_sig = Signature::from_slice(&init.signature)
        .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;

    if !IdentityManager::verify_with_key(&client_pubkey, &sig_payload, &client_sig) {
        return Err(HandshakeError::SignatureVerificationFailed);
    }

    // Generate server X25519 session
    let session = EphemeralSession::new();
    let server_x25519_pub = session.public_key_bytes();

    // Sign and send response
    let resp_sig_payload = build_response_sig_payload(
        &server_x25519_pub,
        &init.client_x25519_pub,
        &init.nonce,
        server_id,
    );
    let signature = server_identity.sign(&resp_sig_payload);

    let response = HandshakeResponse {
        server_x25519_pub,
        signature: signature.to_bytes().to_vec(),
    };

    let resp_data = bincode::serialize(&response)
        .map_err(|e| HandshakeError::Serialization(e.to_string()))?;
    send_message(&mut stream, &resp_data).await?;

    // Derive session key
    let peer_x25519 = EphemeralSession::parse_public_key(&init.client_x25519_pub);
    let session_key = session.compute_session_key(&peer_x25519);
    let cipher = AeadCipher::new(&session_key);

    Ok(SecureChannel {
        stream,
        cipher,
        peer_id: server_id.to_string(),
    })
}

// ---- Helpers ----

fn generate_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

fn build_sig_payload(x25519_pub: &[u8; 32], nonce: &[u8; 32], peer_id: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64 + peer_id.len());
    payload.extend_from_slice(x25519_pub);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(peer_id.as_bytes());
    payload
}

fn build_response_sig_payload(
    server_x25519: &[u8; 32],
    client_x25519: &[u8; 32],
    nonce: &[u8; 32],
    peer_id: &str,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96 + peer_id.len());
    payload.extend_from_slice(server_x25519);
    payload.extend_from_slice(client_x25519);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(peer_id.as_bytes());
    payload
}

// ---- Encrypted Communication ----

impl SecureChannel {
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), HandshakeError> {
        use tokio::io::AsyncWriteExt;
        let (nonce, ciphertext) = self.cipher.encrypt_simple(plaintext)
            .map_err(|e| HandshakeError::InvalidMessage(e.to_string()))?;

        let mut packet = nonce;
        packet.extend_from_slice(&ciphertext);

        let len = packet.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;
        self.stream.write_all(&packet).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, HandshakeError> {
        use tokio::io::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut packet = vec![0u8; len];
        self.stream.read_exact(&mut packet).await?;

        if packet.len() < 12 {
            return Err(HandshakeError::InvalidMessage("packet too short".to_string()));
        }
        let (nonce, ciphertext) = packet.split_at(12);
        let mut ct = ciphertext.to_vec();
        self.cipher.decrypt_simple(nonce, &mut ct)
            .map_err(|_| HandshakeError::InvalidMessage("decryption failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::IdentityManager;
    use tokio::net::TcpListener;

    #[test]
    fn test_nonce_generation() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
        assert_eq!(n1.len(), 32);
    }

    #[tokio::test]
    async fn test_handshake_roundtrip() {
        let alice = IdentityManager::generate(std::env::temp_dir().join("h_rt_alice")).unwrap();
        let bob = IdentityManager::generate(std::env::temp_dir().join("h_rt_bob")).unwrap();
        let bob_pub = bob.public_key_base64();
        let alice_pub = alice.public_key_base64();

        // Use IPv4 loopback (more compatible on Windows)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ch = server_handshake(stream, &bob, "bob", "alice", &alice_pub).await.unwrap();
            let msg = ch.receive().await.unwrap();
            assert_eq!(msg, b"ping");
            ch.send(b"pong").await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut ch = client_handshake(stream, &alice, "alice", "bob", &bob_pub).await.unwrap();
        ch.send(b"ping").await.unwrap();
        let reply = ch.receive().await.unwrap();
        assert_eq!(reply, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_wrong_key_rejected() {
        let alice = IdentityManager::generate(std::env::temp_dir().join("h_wk_alice")).unwrap();
        let bob = IdentityManager::generate(std::env::temp_dir().join("h_wk_bob")).unwrap();
        let mallory = IdentityManager::generate(std::env::temp_dir().join("h_wk_mallory")).unwrap();
        let mallory_pub = mallory.public_key_base64();
        let bob_pub = bob.public_key_base64();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let result = server_handshake(stream, &bob, "bob", "alice", &mallory_pub).await;
            assert!(result.is_err());
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = client_handshake(stream, &alice, "alice", "bob", &bob_pub).await;
        assert!(result.is_err());
        server.await.unwrap();
    }
}
