//! A one-request-per-connection HTTP/1.1 server for driving the transport in tests.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub fn reply(status: u16, headers: &[(&str, &str)], body: &str) -> Reply {
    Reply {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
        body: body.to_owned(),
    }
}

pub type Handler = Arc<dyn Fn(&RecordedRequest) -> Reply + Send + Sync>;

/// Starts a server on an ephemeral port. Returns its base URL and the requests it saw.
pub async fn serve(handler: Handler) -> (String, mpsc::UnboundedReceiver<RecordedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let handler = Arc::clone(&handler);
            let sender = sender.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let count = socket.read(&mut chunk).await.unwrap_or(0);
                    if count == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..count]);
                    if let Some(index) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                        break index;
                    }
                };
                let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
                let mut lines = head.split("\r\n");
                let mut request_line = lines.next().unwrap_or("").split(' ');
                let method = request_line.next().unwrap_or("").to_owned();
                let path = request_line.next().unwrap_or("").to_owned();
                let headers: Vec<(String, String)> = lines
                    .filter_map(|line| line.split_once(':'))
                    .map(|(name, value)| (name.trim().to_lowercase(), value.trim().to_owned()))
                    .collect();
                let length: usize = headers
                    .iter()
                    .find(|(name, _)| name == "content-length")
                    .and_then(|(_, value)| value.parse().ok())
                    .unwrap_or(0);
                let mut body = buffer[header_end + 4..].to_vec();
                while body.len() < length {
                    let count = socket.read(&mut chunk).await.unwrap_or(0);
                    if count == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..count]);
                }
                let request = RecordedRequest {
                    method,
                    path,
                    headers,
                    body: String::from_utf8_lossy(&body).into_owned(),
                };
                let reply = handler(&request);
                let _ = sender.send(request);
                let mut response = format!("HTTP/1.1 {} X\r\nconnection: close\r\n", reply.status);
                let streaming = reply
                    .headers
                    .iter()
                    .any(|(_, value)| value == "text/event-stream");
                if !streaming {
                    response.push_str(&format!("content-length: {}\r\n", reply.body.len()));
                }
                for (name, value) in &reply.headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str("\r\n");
                response.push_str(&reply.body);
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (format!("http://{address}"), receiver)
}
