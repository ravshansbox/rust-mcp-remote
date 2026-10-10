//! A client connected over an in-memory pair to a stub server, the way the CLI connects them.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rust_mcp_remote::client::{Client, ClientTransport, McpError};
use rust_mcp_remote::stdio::TransportEvent;
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// Answers one request from the client; `None` leaves it unanswered.
pub type Handler = Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>;

pub struct Pair {
    pub client: Result<Client, McpError>,
    /// Everything the client sent, in order.
    pub sent: mpsc::UnboundedReceiver<Value>,
    /// Delivers a message, or a close, to the client as the server.
    pub server: mpsc::UnboundedSender<TransportEvent>,
    pub closes: Arc<AtomicUsize>,
}

pub fn tools_server() -> Handler {
    Arc::new(|message| match message["method"].as_str() {
        Some("initialize") => Some(json!({
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "stub", "version": "1.0.0"},
        })),
        Some("tools/list") => Some(json!({"tools": [
            {"name": "search", "description": "Search", "inputSchema": {"type": "object"}},
        ]})),
        _ => None,
    })
}

pub async fn connected_pair(handler: Handler) -> Pair {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let (sent_tx, sent_rx) = mpsc::unbounded_channel();
    let closes = Arc::new(AtomicUsize::new(0));
    let transport = {
        let events_tx = events_tx.clone();
        let closes = Arc::clone(&closes);
        let close_events = events_tx.clone();
        ClientTransport {
            send: Arc::new(move |message: Value| {
                let _ = sent_tx.send(message.clone());
                if message.get("method").is_some()
                    && let Some(id) = message.get("id")
                    && let Some(result) = handler(&message)
                {
                    let _ = events_tx.send(TransportEvent::Message(
                        json!({"jsonrpc": "2.0", "id": id, "result": result}),
                    ));
                }
                Box::pin(async { Ok(()) })
            }),
            close: Arc::new(move || {
                closes.fetch_add(1, Ordering::SeqCst);
                let _ = close_events.send(TransportEvent::Close);
            }),
            set_protocol_version: Arc::new(|_| {}),
        }
    };
    let client = Client::connect("mcp-remote", "0.0.0", transport, events_rx).await;
    Pair {
        client,
        sent: sent_rx,
        server: events_tx,
        closes,
    }
}
