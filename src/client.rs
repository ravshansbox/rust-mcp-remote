//! The parts of the SDK `Client` that client.ts uses (`connect`, `request`, `close` and the
//! `onerror`/`onclose` hooks), and `attachClientDiagnostics` from client-diagnostics.ts.
//!
//! The client owns the transport's events: a dispatcher task settles each pending `request` from
//! the response carrying its id, answers the server's `ping`, and refuses any other request the
//! server sends, as a client that declared no capabilities.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::{mpsc::UnboundedReceiver, oneshot};

use crate::connect::RemoteTransport;
use crate::logging::log;
use crate::protocol_era::{LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};
use crate::stdio::TransportEvent;
use crate::streamable_http::BoxFuture;

/// `DEFAULT_REQUEST_TIMEOUT_MSEC`: how long a request waits for its answer.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// `ErrorCode.ConnectionClosed`.
pub const CONNECTION_CLOSED: i64 = -32000;
/// `ErrorCode.RequestTimeout`.
pub const REQUEST_TIMEOUT: i64 = -32001;
const METHOD_NOT_FOUND: i64 = -32601;

/// An `McpError`: a JSON-RPC error the server answered with, or one the client raised itself.
#[derive(Debug, Clone, PartialEq)]
pub struct McpError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MCP error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for McpError {}

impl McpError {
    fn new(code: i64, message: &str) -> Self {
        McpError {
            code,
            message: message.to_owned(),
            data: None,
        }
    }

    fn from_response(error: &Value) -> Self {
        McpError {
            code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            data: error.get("data").cloned(),
        }
    }
}

/// Sends one message over the transport the client was connected with.
pub type SendFn = Arc<dyn Fn(Value) -> BoxFuture<Result<(), String>> + Send + Sync>;

/// The transport surface the client drives: a remote transport, or an in-memory pair in tests.
#[derive(Clone)]
pub struct ClientTransport {
    pub send: SendFn,
    pub close: Arc<dyn Fn() + Send + Sync>,
    /// Told the negotiated protocol version, so it can send the `mcp-protocol-version` header.
    pub set_protocol_version: Arc<dyn Fn(Option<String>) + Send + Sync>,
}

impl From<RemoteTransport> for ClientTransport {
    fn from(transport: RemoteTransport) -> Self {
        let sender = transport.clone();
        let closer = transport.clone();
        ClientTransport {
            send: Arc::new(move |message| {
                let sender = sender.clone();
                Box::pin(async move { sender.send(&message).await.map_err(|e| e.to_string()) })
            }),
            close: Arc::new(move || closer.close()),
            set_protocol_version: Arc::new(move |version| transport.set_protocol_version(version)),
        }
    }
}

type MessageHook = Arc<dyn Fn(&Value) + Send + Sync>;
type ErrorHook = Arc<dyn Fn(&str) + Send + Sync>;
type CloseHook = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct Hooks {
    on_message: Option<MessageHook>,
    on_error: Option<ErrorHook>,
    on_close: Option<CloseHook>,
}

struct Inner {
    transport: ClientTransport,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Value, McpError>>>>,
    next_id: AtomicU64,
    closed: AtomicBool,
    hooks: Mutex<Hooks>,
    server_info: Mutex<Option<Value>>,
}

impl Inner {
    fn hooks(&self) -> std::sync::MutexGuard<'_, Hooks> {
        self.hooks.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn take_pending(&self, id: u64) -> Option<oneshot::Sender<Result<Value, McpError>>> {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id)
    }

    /// `_onclose`: fails every pending request and calls `onclose` once.
    fn on_close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let pending: Vec<_> = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain()
            .collect();
        for (_, waiter) in pending {
            let _ = waiter.send(Err(McpError::new(CONNECTION_CLOSED, "Connection closed")));
        }
        let hook = self.hooks().on_close.clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    async fn on_message(self: &Arc<Self>, message: Value) {
        let hook = self.hooks().on_message.clone();
        if let Some(hook) = hook {
            hook(&message);
        }
        let id = message.get("id").cloned();
        if let Some(method) = message.get("method").and_then(Value::as_str) {
            // A request from the server; a notification needs nothing from a bare client.
            let Some(id) = id else { return };
            let answer = if method == "ping" {
                json!({"jsonrpc": "2.0", "id": id, "result": {}})
            } else {
                json!({"jsonrpc": "2.0", "id": id, "error": {
                    "code": METHOD_NOT_FOUND, "message": "Method not found",
                }})
            };
            if let Err(error) = (self.transport.send)(answer).await {
                self.report_error(&format!("Failed to send response: {error}"));
            }
            return;
        }
        let waiter = id
            .as_ref()
            .and_then(Value::as_u64)
            .and_then(|id| self.take_pending(id));
        let Some(waiter) = waiter else {
            self.report_error(&format!(
                "Received a response for an unknown message ID: {}",
                serde_json::to_string(&message).unwrap_or_default()
            ));
            return;
        };
        let outcome = match message.get("error") {
            Some(error) => Err(McpError::from_response(error)),
            None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
        };
        let _ = waiter.send(outcome);
    }

    fn report_error(&self, error: &str) {
        let hook = self.hooks().on_error.clone();
        if let Some(hook) = hook {
            hook(error);
        }
    }
}

/// A connected MCP client.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    /// `new Client({name, version}, {capabilities: {}})` followed by `client.connect(transport)`:
    /// the `initialize` handshake, then `notifications/initialized`.
    pub async fn connect(
        name: &str,
        version: &str,
        transport: impl Into<ClientTransport>,
        mut events: UnboundedReceiver<TransportEvent>,
    ) -> Result<Client, McpError> {
        let inner = Arc::new(Inner {
            transport: transport.into(),
            pending: Mutex::default(),
            next_id: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            hooks: Mutex::default(),
            server_info: Mutex::new(None),
        });
        let dispatcher = Arc::clone(&inner);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                match event {
                    TransportEvent::Message(message) => dispatcher.on_message(message).await,
                    TransportEvent::Error(error) => dispatcher.report_error(&error),
                    TransportEvent::Close => break,
                }
            }
            dispatcher.on_close();
        });

        let client = Client { inner };
        let handshake = async {
            let result = client
                .request(
                    "initialize",
                    Some(json!({
                        "protocolVersion": LATEST_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": name, "version": version},
                    })),
                )
                .await?;
            let negotiated = result
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !SUPPORTED_PROTOCOL_VERSIONS.contains(&negotiated) {
                return Err(McpError::new(
                    0,
                    &format!("Server's protocol version is not supported: {negotiated}"),
                ));
            }
            (client.inner.transport.set_protocol_version)(Some(negotiated.to_owned()));
            *client
                .inner
                .server_info
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = result.get("serverInfo").cloned();
            client
                .notify("notifications/initialized", None)
                .await
                .map_err(|error| McpError::new(CONNECTION_CLOSED, &error))
        };
        if let Err(error) = handshake.await {
            client.close();
            return Err(error);
        }
        Ok(client)
    }

    /// `getServerVersion()`: the `serverInfo` the server answered `initialize` with.
    pub fn server_version(&self) -> Option<Value> {
        self.inner
            .server_info
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// `client.request({method, params})` with the default timeout.
    pub async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, McpError> {
        self.request_with_timeout(method, params, DEFAULT_REQUEST_TIMEOUT)
            .await
    }

    pub async fn request_with_timeout(
        &self,
        method: &str,
        params: Option<Value>,
        timeout: Duration,
    ) -> Result<Value, McpError> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(McpError::new(CONNECTION_CLOSED, "Not connected"));
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let mut message = json!({"jsonrpc": "2.0", "id": id, "method": method});
        if let Some(params) = params {
            message["params"] = params;
        }
        let (waiter, answer) = oneshot::channel();
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, waiter);
        if let Err(error) = (self.inner.transport.send)(message).await {
            self.inner.take_pending(id);
            return Err(McpError::new(CONNECTION_CLOSED, &error));
        }
        match tokio::time::timeout(timeout, answer).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(McpError::new(CONNECTION_CLOSED, "Connection closed")),
            Err(_) => {
                self.inner.take_pending(id);
                let cancelled = json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                    "params": {"requestId": id, "reason": "Request timed out"}});
                let _ = (self.inner.transport.send)(cancelled).await;
                Err(McpError {
                    code: REQUEST_TIMEOUT,
                    message: "Request timed out".to_owned(),
                    data: Some(json!({"timeout": timeout.as_millis() as u64})),
                })
            }
        }
    }

    /// `client.notification({method, params})`.
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), String> {
        let mut message = json!({"jsonrpc": "2.0", "method": method});
        if let Some(params) = params {
            message["params"] = params;
        }
        (self.inner.transport.send)(message).await
    }

    /// `client.close()`: closes the transport and settles everything still pending.
    pub fn close(&self) {
        (self.inner.transport.close)();
        self.inner.on_close();
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Observes every message the transport delivers, before it is dispatched.
    pub fn set_on_message(&self, hook: impl Fn(&Value) + Send + Sync + 'static) {
        self.inner.hooks().on_message = Some(Arc::new(hook));
    }

    /// `client.onerror`.
    pub fn set_on_error(&self, hook: impl Fn(&str) + Send + Sync + 'static) {
        self.inner.hooks().on_error = Some(Arc::new(hook));
    }

    /// `client.onclose`: called once, after every pending request has been failed.
    pub fn set_on_close(&self, hook: impl Fn() + Send + Sync + 'static) {
        self.inner.hooks().on_close = Some(Arc::new(hook));
    }
}

/// `attachClientDiagnostics`: makes a connected client narrate what it receives. The message
/// hook only observes, so the dispatcher that settles `request` keeps running
/// (geelen/mcp-remote#324 was a logger that displaced it).
pub fn attach_client_diagnostics(client: &Client, on_close: impl Fn() + Send + Sync + 'static) {
    client.set_on_message(|message| {
        log(
            "Received message:",
            &[Value::String(
                serde_json::to_string_pretty(message).unwrap_or_default(),
            )],
        );
    });
    client.set_on_error(|error| log("Transport error:", &[Value::String(error.to_owned())]));
    client.set_on_close(move || {
        log("Connection closed.", &[]);
        on_close();
    });
}
