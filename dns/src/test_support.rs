//! In-process mock of the GoDaddy Domains API for unit tests.
//!
//! Serves `GET/PUT/DELETE /v1/domains/{domain}/records/{type}/{name}` from an
//! in-memory record store, so managers / discovery / heartbeat can be tested
//! without network access. Record `data` strings are stored verbatim (same as
//! the real API); each manager does its own parse.
//!
//! Behavior mirrors the real API closely enough:
//! - `GET`  → 200 + JSON array of records; **404** when the (type, name) has no records
//! - `PUT`  → replaces records, 200
//! - `DELETE` → idempotent, 200 (real GoDaddy 404s on missing records, which
//!   callers ignore anyway)

use crate::godaddy::Record;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Default)]
struct MockState {
    /// (record_type, name) → records.
    records: HashMap<(String, String), Vec<Record>>,
    /// Logged DELETE calls: (record_type, name).
    deletes: Vec<(String, String)>,
}

/// Handle to a running mock GoDaddy server (one tokio task per connection).
#[derive(Debug, Clone)]
pub struct MockDns {
    state: Arc<Mutex<MockState>>,
    addr: SocketAddr,
}

impl MockDns {
    /// Bind a mock server on 127.0.0.1 (ephemeral port).
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind mock DNS server");
        let addr = listener.local_addr().expect("mock server address");
        let state = Arc::new(Mutex::new(MockState::default()));

        let server_state = state.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };
                let conn_state = server_state.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, &conn_state).await;
                });
            }
        });

        Self { state, addr }
    }

    /// Base URL to point `GoDaddyClient` at this mock.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Seed records (overwrites any existing for the key).
    pub fn set_records(&self, record_type: &str, name: &str, data: &[&str], ttl: u32) {
        let mut state = self.state.lock().unwrap();
        state.records.insert(
            (record_type.to_string(), name.to_string()),
            data.iter()
                .map(|d| Record {
                    data: d.to_string(),
                    ttl,
                })
                .collect(),
        );
    }

    /// Data of the currently stored records for (type, name) — for asserting registrations.
    pub fn records_of(&self, record_type: &str, name: &str) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state
            .records
            .get(&(record_type.to_string(), name.to_string()))
            .map(|r| r.iter().map(|rec| rec.data.clone()).collect())
            .unwrap_or_default()
    }

    /// Number of DELETE calls made for (type, name).
    pub fn delete_count(&self, record_type: &str, name: &str) -> usize {
        let state = self.state.lock().unwrap();
        state
            .deletes
            .iter()
            .filter(|(t, n)| t == record_type && n == name)
            .count()
    }
}

/// One HTTP request → response, routed to the in-memory store.
async fn handle_connection(
    mut stream: TcpStream,
    state: &Arc<Mutex<MockState>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut stream);

    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).await?;
    let body = String::from_utf8_lossy(&body).to_string();

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let response = route(&method, &path, &body, state);
    let raw = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.0,
        response.1.len(),
        response.1
    );
    stream.write_all(raw.as_bytes()).await?;
    stream.flush().await
}

/// `(status_line, body)`.
fn route(method: &str, path: &str, body: &str, state: &Arc<Mutex<MockState>>) -> (String, String) {
    // /v1/domains/{domain}/records/{type}/{name}
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() != 6 || segs[0] != "v1" || segs[1] != "domains" || segs[3] != "records" {
        return (String::from("404 Not Found"), String::new());
    }
    let record_type = segs[4].to_string();
    let name = segs[5].to_string();

    let mut state = state.lock().unwrap();
    match method {
        "GET" => {
            let key = (record_type, name);
            let records = state.records.get(&key);
            match records {
                Some(records) => {
                    let json = serde_json::to_string(records).unwrap_or_default();
                    (String::from("200 OK"), json)
                }
                None => (String::from("404 Not Found"), String::new()),
            }
        }
        "PUT" => {
            let records: Vec<Record> = serde_json::from_str(body).unwrap_or_default();
            state.records.insert((record_type, name), records);
            (String::from("200 OK"), String::new())
        }
        "DELETE" => {
            state.records.remove(&(record_type.clone(), name.clone()));
            state.deletes.push((record_type, name));
            (String::from("200 OK"), String::new())
        }
        _ => (String::from("405 Method Not Allowed"), String::new()),
    }
}
