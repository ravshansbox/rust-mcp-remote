//! The bidirectional proxy between the local client and the remote server
//! (`mcpProxy` in utils.ts), in its `legacy` protocol mode.
//!
//! Not yet ported: the `auto` protocol mode (era probe and bridging), the
//! keep-alive pings, re-authorization, session-expiry re-initialization and
//! stream-reconnect recovery.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;

use crate::logging::{debug_log, log};
use crate::stdio::{StdioServerTransport, TransportEvent};
use crate::streamable_http::StreamableHttpClientTransport;
use crate::utils::{MCP_REMOTE_VERSION, ignored_tool_call_error, transform_proxy_response};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How long the client's first requests wait on `notifications/initialized` before going anyway.
pub const LIFECYCLE_BARRIER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the remote server to answer the client's `initialize`.
pub const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(30);

/// The prefix every id this proxy mints carries.
pub const OWN_ID_PREFIX: &str = "mcp-remote-";

/// What the proxy needs from either side, in place of the SDK's `Transport`.
pub trait ProxyTransport: Clone + Send + Sync + 'static {
    fn send_message(&self, message: Value) -> BoxFuture<Result<(), String>>;
    fn close_transport(&self);
    fn set_protocol_version(&self, _version: String) {}
}

impl<W: AsyncWrite + Unpin + Send + 'static> ProxyTransport for StdioServerTransport<W> {
    fn send_message(&self, message: Value) -> BoxFuture<Result<(), String>> {
        let transport = self.clone();
        Box::pin(async move { transport.send(&message).await })
    }

    fn close_transport(&self) {
        self.close();
    }
}

impl ProxyTransport for StreamableHttpClientTransport {
    fn send_message(&self, message: Value) -> BoxFuture<Result<(), String>> {
        let transport = self.clone();
        Box::pin(async move {
            transport
                .send(&message)
                .await
                .map_err(|error| error.to_string())
        })
    }

    fn close_transport(&self) {
        self.close();
    }

    fn set_protocol_version(&self, version: String) {
        StreamableHttpClientTransport::set_protocol_version(self, Some(version));
    }
}

#[derive(Debug, Clone)]
pub struct ProxyOptions {
    pub ignored_tools: Vec<String>,
    pub initialize_timeout: Duration,
    pub lifecycle_barrier_timeout: Duration,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            ignored_tools: Vec::new(),
            initialize_timeout: INITIALIZE_TIMEOUT,
            lifecycle_barrier_timeout: LIFECYCLE_BARRIER_TIMEOUT,
        }
    }
}

fn is_own_id(id: &Value) -> bool {
    id.as_str().is_some_and(|id| id.starts_with(OWN_ID_PREFIX))
}

fn has_id(message: &Value) -> bool {
    message.get("id").is_some_and(|id| !id.is_null())
}

fn is_request(message: &Value) -> bool {
    has_id(message) && message.get("method").is_some()
}

fn is_response(message: &Value) -> bool {
    has_id(message) && message.get("method").is_none()
}

/// Map key for a JSON-RPC id; keeps `1` and `"1"` apart, as a JS Map does.
fn id_key(id: &Value) -> String {
    id.to_string()
}

/// `message.method || message.id`, as the `[Local→Remote]` log lines print it.
fn method_or_id(message: &Value) -> Value {
    match message.get("method") {
        Some(Value::String(method)) if !method.is_empty() => Value::String(method.clone()),
        _ => message.get("id").cloned().unwrap_or(Value::Null),
    }
}

fn reserved_id_error(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32600,
            "message": format!("mcp-remote reserves request ids beginning with \"{OWN_ID_PREFIX}\""),
        },
    })
}

fn on_client_error(error: &str) {
    log(
        "Error from local client:",
        &[Value::String(error.to_owned())],
    );
}

fn on_server_error(error: &str) {
    log(
        "Error from remote server:",
        &[Value::String(error.to_owned())],
    );
}

struct Shared<C, S> {
    client: C,
    server: S,
    options: ProxyOptions,
    /// The message transformer's held requests, by id.
    transformer: Mutex<HashMap<String, Value>>,
    /// Client requests that have gone to the server and still wait on an answer.
    pending_requests: Mutex<HashSet<String>>,
    initialize_request_id: Mutex<Option<Value>>,
}

impl<C: ProxyTransport, S: ProxyTransport> Shared<C, S> {
    /// `interceptRequest`: holds a request so its response can be paired with it.
    fn intercept_request(&self, message: &Value) {
        if is_request(message) {
            self.lock_transformer()
                .insert(id_key(&message["id"]), message.clone());
        }
    }

    /// `interceptResponse`: transforms a response against the request it answers.
    fn intercept_response(&self, message: Value) -> Value {
        if !is_response(&message) {
            return message;
        }
        let Some(request) = self.lock_transformer().remove(&id_key(&message["id"])) else {
            return message;
        };
        transform_proxy_response(&self.options.ignored_tools, false, &request, message)
    }

    /// Releases the held request for an answer that did not come from the server.
    fn release(&self, id: &Value, only: Option<&Value>) {
        let mut transformer = self.lock_transformer();
        let key = id_key(id);
        if only.is_some_and(|only| transformer.get(&key) != Some(only)) {
            return;
        }
        transformer.remove(&key);
    }

    fn lock_transformer(&self) -> std::sync::MutexGuard<'_, HashMap<String, Value>> {
        self.transformer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_pending(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.pending_requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn send_to_client(&self, message: Value) {
        if let Err(error) = self.client.send_message(message).await {
            on_client_error(&error);
        }
    }

    async fn reply_with_error(&self, message: &Value, error: &str) {
        if !is_request(message) {
            return;
        }
        self.release(&message["id"], Some(message));
        self.send_to_client(json!({
            "jsonrpc": "2.0",
            "id": message["id"],
            "error": {"code": -32001, "message": format!("mcp-remote: {error}")},
        }))
        .await;
    }

    async fn send_to_server(self: Arc<Self>, message: Value) {
        let awaits_answer = is_request(&message);
        if awaits_answer {
            self.lock_pending().insert(id_key(&message["id"]));
        }
        match self.server.send_message(message.clone()).await {
            Ok(()) => {
                if message["method"] == "initialize" {
                    self.schedule_initialize_timeout(message);
                }
            }
            Err(error) => {
                if awaits_answer {
                    self.lock_pending().remove(&id_key(&message["id"]));
                }
                on_server_error(&error);
                self.reply_with_error(&message, &error).await;
            }
        }
    }

    fn schedule_initialize_timeout(self: Arc<Self>, message: Value) {
        tokio::spawn(async move {
            tokio::time::sleep(self.options.initialize_timeout).await;
            if !self.lock_pending().remove(&id_key(&message["id"])) {
                return;
            }
            let seconds = self.options.initialize_timeout.as_secs_f64();
            log(
                &format!("Remote server did not answer 'initialize' within {seconds}s"),
                &[],
            );
            let error = format!(
                "timed out after {seconds}s waiting for the remote server to answer 'initialize'"
            );
            self.reply_with_error(&message, &error).await;
        });
    }

    async fn on_client_message(&self, mut message: Value, forward: &mpsc::UnboundedSender<Value>) {
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        if is_own_id(&id) {
            if message.get("method").is_some() {
                log(
                    &format!(
                        "Refusing a client request whose id is reserved by this proxy: {}",
                        id.as_str().unwrap_or_default()
                    ),
                    &[],
                );
                self.send_to_client(reserved_id_error(&id)).await;
            } else {
                debug_log(
                    "Discarding a late answer to a question this proxy had given up on",
                    &[json!({"id": id})],
                );
            }
            return;
        }

        self.intercept_request(&message);
        if let Some(error) = ignored_tool_call_error(&self.options.ignored_tools, &message) {
            self.send_to_client(error).await;
            if !id.is_null() {
                self.release(&id, None);
            }
            return;
        }

        log("[Local→Remote]", &[method_or_id(&message)]);
        debug_log(
            "Local → Remote message",
            &[json!({
                "method": message.get("method"),
                "id": message.get("id"),
                "params": message.get("params").map(|params| {
                    params.to_string().encode_utf16().take(500).collect::<Vec<u16>>()
                }).map(|units| String::from_utf16_lossy(&units)),
            })],
        );

        if message["method"] == "initialize" {
            *self
                .initialize_request_id
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(id.clone());
            if let Some(client_info) = message
                .get_mut("params")
                .and_then(|params| params.get_mut("clientInfo"))
                .filter(|client_info| client_info.is_object())
            {
                let name = match &client_info["name"] {
                    Value::String(name) => name.clone(),
                    Value::Null => "undefined".to_owned(),
                    other => other.to_string(),
                };
                client_info["name"] =
                    Value::String(format!("{name} (via mcp-remote {MCP_REMOTE_VERSION})"));
            }
            log(
                &serde_json::to_string_pretty(&message).unwrap_or_default(),
                &[],
            );
            debug_log(
                "Initialize message with modified client info",
                &[json!({"clientInfo": message["params"]["clientInfo"]})],
            );
        }

        let _ = forward.send(message);
    }

    async fn on_server_message(&self, message: Value) {
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        if is_own_id(&id) {
            if message.get("method").is_some() {
                log(
                    &format!(
                        "Refusing a server request whose id is reserved by this proxy: {}",
                        id.as_str().unwrap_or_default()
                    ),
                    &[],
                );
                if let Err(error) = self.server.send_message(reserved_id_error(&id)).await {
                    on_server_error(&error);
                }
            } else {
                debug_log(
                    "Discarding an answer to a request this proxy is no longer waiting on",
                    &[json!({"id": id})],
                );
            }
            return;
        }

        if !id.is_null() {
            self.lock_pending().remove(&id_key(&id));
        }

        let message = self.intercept_response(message);
        log("[Remote→Local]", &[method_or_id(&message)]);
        debug_log(
            "Remote → Local message",
            &[json!({
                "method": message.get("method"),
                "id": message.get("id"),
                "result": message.get("result").map(|_| "result-present"),
                "error": message.get("error"),
            })],
        );

        let answers_initialize = {
            let mut initialize_id = self
                .initialize_request_id
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let matches = initialize_id
                .as_ref()
                .is_some_and(|initialize_id| message.get("id") == Some(initialize_id));
            if matches {
                *initialize_id = None;
            }
            matches
        };
        if answers_initialize
            && let Some(Value::String(version)) = message
                .get("result")
                .and_then(|result| result.get("protocolVersion"))
        {
            debug_log(
                "Setting negotiated protocol version on remote transport",
                &[Value::String(version.clone())],
            );
            self.server.set_protocol_version(version.clone());
        }

        self.send_to_client(message).await;
    }
}

/// `forwardInOrder`: sends the client's messages to the server in the order
/// they arrived, holding everything after `notifications/initialized` until
/// that notification has been delivered (or the barrier times out).
async fn forward_in_order<C: ProxyTransport, S: ProxyTransport>(
    shared: Arc<Shared<C, S>>,
    mut messages: mpsc::UnboundedReceiver<Value>,
) {
    let mut initialized_delivered: Option<tokio::task::JoinHandle<()>> = None;
    while let Some(message) = messages.recv().await {
        if let Some(barrier) = initialized_delivered.as_mut()
            && !barrier.is_finished()
        {
            let _ = tokio::time::timeout(shared.options.lifecycle_barrier_timeout, barrier).await;
        }
        let task = tokio::spawn(Arc::clone(&shared).send_to_server(message.clone()));
        if message["method"] == "notifications/initialized" && message.get("id").is_none() {
            initialized_delivered = Some(task);
        }
    }
}

/// Proxies messages between `client` and `server` until both have closed.
pub async fn mcp_proxy<C: ProxyTransport, S: ProxyTransport>(
    client: C,
    mut client_events: mpsc::UnboundedReceiver<TransportEvent>,
    server: S,
    mut server_events: mpsc::UnboundedReceiver<TransportEvent>,
    options: ProxyOptions,
) {
    let shared = Arc::new(Shared {
        client,
        server,
        options,
        transformer: Mutex::new(HashMap::new()),
        pending_requests: Mutex::new(HashSet::new()),
        initialize_request_id: Mutex::new(None),
    });
    let (forward, forward_receiver) = mpsc::unbounded_channel();
    let forwarder = tokio::spawn(forward_in_order(Arc::clone(&shared), forward_receiver));

    let mut client_closed = false;
    let mut server_closed = false;
    while !(client_closed && server_closed) {
        tokio::select! {
            event = client_events.recv(), if !client_closed => match event {
                Some(TransportEvent::Message(message)) => {
                    shared.on_client_message(message, &forward).await;
                }
                Some(TransportEvent::Error(error)) => on_client_error(&error),
                Some(TransportEvent::Close) | None => {
                    client_closed = true;
                    if !server_closed {
                        debug_log("Local transport closed, closing remote transport", &[]);
                        shared.server.close_transport();
                    }
                }
            },
            event = server_events.recv(), if !server_closed => match event {
                Some(TransportEvent::Message(message)) => shared.on_server_message(message).await,
                Some(TransportEvent::Error(error)) => on_server_error(&error),
                Some(TransportEvent::Close) | None => {
                    server_closed = true;
                    if !client_closed {
                        debug_log("Remote transport closed, closing local transport", &[]);
                        shared.client.close_transport();
                    }
                }
            },
        }
    }
    forwarder.abort();
}
