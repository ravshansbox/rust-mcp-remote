//! The bidirectional proxy between the local client and the remote server
//! (`mcpProxy` in utils.ts), in its `legacy` protocol mode.
//!
//! Not yet ported: the `auto` protocol mode (era probe and bridging) and
//! stream-reconnect recovery.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::AsyncWrite;
use tokio::sync::{mpsc, oneshot};

use crate::connect::RemoteTransport;
use crate::logging::{debug_log, log};
use crate::stdio::{StdioServerTransport, TransportEvent};
use crate::streamable_http::{StreamableHttpClientTransport, TransportError};
use crate::utils::{MCP_REMOTE_VERSION, ignored_tool_call_error, transform_proxy_response};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How long the client's first requests wait on `notifications/initialized` before going anyway.
pub const LIFECYCLE_BARRIER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the remote server to answer the client's `initialize`.
pub const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the remote server to answer a re-initialize after its session expired.
pub const REINITIALIZE_TIMEOUT: Duration = Duration::from_secs(30);

/// The prefix every id this proxy mints carries.
pub const OWN_ID_PREFIX: &str = "mcp-remote-";

/// Why a send failed, kept as far as the proxy needs to tell the cases apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The SDK's UnauthorizedError.
    Unauthorized(String),
    /// The SDK's SdkHttpError.
    Http {
        status: u16,
        message: String,
    },
    Other(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Unauthorized(message)
            | SendError::Http { message, .. }
            | SendError::Other(message) => formatter.write_str(message),
        }
    }
}

impl From<String> for SendError {
    fn from(message: String) -> Self {
        SendError::Other(message)
    }
}

impl From<TransportError> for SendError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::Unauthorized(message) => SendError::Unauthorized(message),
            TransportError::Http { status, message } => SendError::Http { status, message },
            other => SendError::Other(other.to_string()),
        }
    }
}

impl SendError {
    /// `isUnauthorized`: the server refused this because nobody is signed in.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, SendError::Unauthorized(_)) || self.to_string().contains("Unauthorized")
    }

    /// `isRejectedAfterAuthorizing`: the SDK's 401 after it had just authorized.
    pub fn is_rejected_after_authorizing(&self) -> bool {
        matches!(self, SendError::Http { status: 401, .. })
    }
}

/// What the proxy needs from either side, in place of the SDK's `Transport`.
pub trait ProxyTransport: Clone + Send + Sync + 'static {
    fn send_message(&self, message: Value) -> BoxFuture<Result<(), SendError>>;
    fn close_transport(&self);
    fn set_protocol_version(&self, _version: String) {}
    /// The SDK's `transport.sessionId`; only the streamable HTTP transport has one.
    fn session_id(&self) -> Option<String> {
        None
    }
    /// Clears the session id, so a re-initialize is not sent against the dead session.
    fn clear_session_id(&self) {}
}

/// Completes a sign-in, or discards a refused token, on the proxy's behalf.
pub type AuthHook = Arc<dyn Fn() -> BoxFuture<Result<(), String>> + Send + Sync>;

impl<W: AsyncWrite + Unpin + Send + 'static> ProxyTransport for StdioServerTransport<W> {
    fn send_message(&self, message: Value) -> BoxFuture<Result<(), SendError>> {
        let transport = self.clone();
        Box::pin(async move { transport.send(&message).await.map_err(SendError::from) })
    }

    fn close_transport(&self) {
        self.close();
    }
}

impl ProxyTransport for RemoteTransport {
    fn send_message(&self, message: Value) -> BoxFuture<Result<(), SendError>> {
        let transport = self.clone();
        Box::pin(async move { transport.send(&message).await.map_err(SendError::from) })
    }

    fn close_transport(&self) {
        self.close();
    }

    fn set_protocol_version(&self, version: String) {
        RemoteTransport::set_protocol_version(self, Some(version));
    }

    fn session_id(&self) -> Option<String> {
        match self {
            RemoteTransport::Http(transport) => transport.session_id(),
            RemoteTransport::Sse(_) => None,
        }
    }

    fn clear_session_id(&self) {
        if let RemoteTransport::Http(transport) = self {
            transport.clear_session_id();
        }
    }
}

impl ProxyTransport for StreamableHttpClientTransport {
    fn send_message(&self, message: Value) -> BoxFuture<Result<(), SendError>> {
        let transport = self.clone();
        Box::pin(async move { transport.send(&message).await.map_err(SendError::from) })
    }

    fn close_transport(&self) {
        self.close();
    }

    fn set_protocol_version(&self, version: String) {
        StreamableHttpClientTransport::set_protocol_version(self, Some(version));
    }

    fn session_id(&self) -> Option<String> {
        StreamableHttpClientTransport::session_id(self)
    }

    fn clear_session_id(&self) {
        StreamableHttpClientTransport::clear_session_id(self);
    }
}

#[derive(Clone)]
pub struct ProxyOptions {
    pub ignored_tools: Vec<String>,
    /// Pings the server on this interval, so a connection carrying no traffic is not reaped.
    pub keep_alive: Option<Duration>,
    /// Completes a sign-in for a request the server refused, or None to answer with the error.
    pub reauthorize: Option<AuthHook>,
    /// Discards a token the server refused after the SDK had just obtained it.
    pub forget_rejected_authorization: Option<AuthHook>,
    pub initialize_timeout: Duration,
    pub reinitialize_timeout: Duration,
    pub lifecycle_barrier_timeout: Duration,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            ignored_tools: Vec::new(),
            keep_alive: None,
            reauthorize: None,
            forget_rejected_authorization: None,
            initialize_timeout: INITIALIZE_TIMEOUT,
            reinitialize_timeout: REINITIALIZE_TIMEOUT,
            lifecycle_barrier_timeout: LIFECYCLE_BARRIER_TIMEOUT,
        }
    }
}

/// Coalesces concurrent callers, so several failed requests produce one recovery, not one each.
///
/// A caller that arrives while a run is in flight shares its result; one that arrives after it
/// finished starts a new run, as the TS `inFlight ??= run().finally(() => inFlight = null)` does.
#[derive(Default)]
struct SingleFlight {
    lock: tokio::sync::Mutex<()>,
    generation: AtomicU64,
    last: Mutex<Option<Result<(), String>>>,
}

impl SingleFlight {
    async fn run<F: Future<Output = Result<(), String>>>(
        &self,
        start: impl FnOnce() -> F,
    ) -> Result<(), String> {
        let seen = self.generation.load(Ordering::SeqCst);
        let _guard = self.lock.lock().await;
        if self.generation.load(Ordering::SeqCst) != seen
            && let Some(result) = lock(&self.last).clone()
        {
            return result;
        }
        let result = start().await;
        *lock(&self.last) = Some(result.clone());
        self.generation.fetch_add(1, Ordering::SeqCst);
        result
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    /// The client's last `initialize`, replayed when the server drops the session.
    last_initialize: Mutex<Option<Value>>,
    reinit_seq: AtomicU64,
    pending_reinit: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    ping_seq: AtomicU64,
    pending_pings: Mutex<HashSet<String>>,
    reauthorize_flight: SingleFlight,
    reinitialize_flight: SingleFlight,
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
            on_client_error(&error.to_string());
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
        let mut already_reauthorized = false;
        let mut already_discarded_token = false;
        loop {
            if awaits_answer {
                self.lock_pending().insert(id_key(&message["id"]));
            }
            let error = match self.server.send_message(message.clone()).await {
                Ok(()) => {
                    if message["method"] == "initialize" {
                        self.schedule_initialize_timeout(message);
                    }
                    return;
                }
                Err(error) => error,
            };
            if awaits_answer {
                self.lock_pending().remove(&id_key(&message["id"]));
            }

            // A token the server refused straight after issuing it is a dead credential the SDK
            // keeps presenting. Discarding it turns the next attempt into an ordinary 401, which
            // the branch below answers with a real sign-in. Once only.
            if let Some(forget) = &self.options.forget_rejected_authorization
                && !already_discarded_token
                && error.is_rejected_after_authorizing()
            {
                log(
                    "The server rejected a token it had just issued - discarding it and asking for another",
                    &[],
                );
                debug_log(
                    "Rejected token mid-session",
                    &[json!({"id": message.get("id"), "method": message.get("method")})],
                );
                if let Err(discard_error) = forget().await {
                    on_server_error(&discard_error);
                    self.reply_with_error(&message, &discard_error).await;
                    return;
                }
                already_discarded_token = true;
                continue;
            }

            // The sign-in the SDK started can still be completed, but only by someone holding the
            // callback port. Retried once: a second refusal will not be fixed by another flow.
            if let Some(reauthorize) = &self.options.reauthorize
                && !already_reauthorized
                && error.is_unauthorized()
            {
                log(
                    "Remote server requires authorization, completing sign-in",
                    &[],
                );
                debug_log(
                    "Unauthorized send, re-authorizing",
                    &[json!({"id": message.get("id"), "method": message.get("method")})],
                );
                if let Err(auth_error) = self.reauthorize_flight.run(|| reauthorize()).await {
                    on_server_error(&auth_error);
                    self.reply_with_error(&message, &auth_error).await;
                    return;
                }
                already_reauthorized = true;
                continue;
            }

            // Re-initializing in response to a failed initialize would loop
            if !self.is_session_expired(&error) || message["method"] == "initialize" {
                let error = error.to_string();
                on_server_error(&error);
                self.reply_with_error(&message, &error).await;
                return;
            }

            log("Remote session expired, re-initializing", &[]);
            debug_log(
                "Remote session expired",
                &[json!({"id": message.get("id"), "method": message.get("method")})],
            );
            let retried = match Arc::clone(&self).reinitialize_session().await {
                Ok(()) => self
                    .server
                    .send_message(message.clone())
                    .await
                    .map_err(|error| error.to_string()),
                Err(error) => Err(error),
            };
            if let Err(retry_error) = retried {
                on_server_error(&retry_error);
                self.reply_with_error(&message, &retry_error).await;
            }
            return;
        }
    }

    /// A 404 to a request that carried a session id: the server dropped the session. Without a
    /// session id it is an ordinary "no such endpoint", and re-initializing would not help.
    fn is_session_expired(&self, error: &SendError) -> bool {
        matches!(error, SendError::Http { status: 404, .. }) && self.server.session_id().is_some()
    }

    /// Coalesces concurrent callers so several in-flight 404s produce one new session.
    async fn reinitialize_session(self: Arc<Self>) -> Result<(), String> {
        let shared = Arc::clone(&self);
        self.reinitialize_flight
            .run(|| shared.do_reinitialize_session())
            .await
    }

    async fn do_reinitialize_session(self: Arc<Self>) -> Result<(), String> {
        let Some(mut initialize) = lock(&self.last_initialize).clone() else {
            return Err(
                "no initialize request was seen, cannot re-establish the session".to_owned(),
            );
        };

        // Cleared before sending, or the transport re-attaches the dead id
        self.server.clear_session_id();

        let id = format!(
            "{OWN_ID_PREFIX}reinit-{}",
            self.reinit_seq.fetch_add(1, Ordering::SeqCst) + 1
        );
        initialize["id"] = Value::String(id.clone());
        let (settle, answer) = oneshot::channel();
        lock(&self.pending_reinit).insert(id.clone(), settle);
        if let Err(error) = self.server.send_message(initialize).await {
            lock(&self.pending_reinit).remove(&id);
            return Err(error.to_string());
        }
        let response = match tokio::time::timeout(self.options.reinitialize_timeout, answer).await {
            Ok(Ok(response)) => response,
            _ => {
                lock(&self.pending_reinit).remove(&id);
                return Err("timed out waiting for the re-initialize response".to_owned());
            }
        };

        if let Some(error) = response.get("error") {
            return Err(format!("server rejected re-initialize: {error}"));
        }

        // The new session negotiates its own version, and the header has to follow it
        self.apply_negotiated_protocol_version(&response);

        // The SDK only (re)opens the GET SSE stream when it sees this notification
        self.server
            .send_message(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await
            .map_err(|error| error.to_string())?;

        log(
            &format!(
                "Re-established session {} after server expiry",
                self.server
                    .session_id()
                    .unwrap_or_else(|| "(none)".to_owned())
            ),
            &[],
        );
        Ok(())
    }

    fn apply_negotiated_protocol_version(&self, response: &Value) {
        if let Some(Value::String(version)) = response
            .get("result")
            .and_then(|result| result.get("protocolVersion"))
        {
            debug_log(
                "Setting negotiated protocol version on remote transport",
                &[Value::String(version.clone())],
            );
            self.server.set_protocol_version(version.clone());
        }
    }

    /// Pings the server on an interval so a connection carrying no traffic is not reaped. Every
    /// id here is ours, and so is every answer: they are dropped rather than forwarded.
    fn start_keep_alive(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        log(
            &format!(
                "Keep-alive enabled, pinging every {} seconds",
                interval.as_secs_f64()
            ),
            &[],
        );
        tokio::spawn(async move {
            let mut timer =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            loop {
                timer.tick().await;
                let id = format!(
                    "{OWN_ID_PREFIX}keepalive-{}",
                    self.ping_seq.fetch_add(1, Ordering::SeqCst) + 1
                );
                lock(&self.pending_pings).insert(id.clone());
                let shared = Arc::clone(&self);
                tokio::spawn(async move {
                    let ping = json!({"jsonrpc": "2.0", "id": id, "method": "ping"});
                    if let Err(error) = shared.server.send_message(ping).await {
                        // Not fatal on its own: the next request decides whether the connection
                        // is really gone
                        lock(&shared.pending_pings).remove(&id);
                        log(&format!("Keep-alive ping failed: {error}"), &[]);
                    }
                });
            }
        })
    }

    /// Settles every request this proxy made on its own account with an error.
    fn fail_own_pending_requests(&self, reason: &str) {
        for (id, settle) in lock(&self.pending_reinit).drain() {
            let _ = settle.send(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32001, "message": format!("mcp-remote: {reason}")},
            }));
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
            *lock(&self.last_initialize) = Some(message.clone());
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
                    on_server_error(&error.to_string());
                }
                return;
            }
            let key = id.as_str().unwrap_or_default();
            if lock(&self.pending_pings).remove(key) {
                return;
            }
            if let Some(settle) = lock(&self.pending_reinit).remove(key) {
                let _ = settle.send(message);
                return;
            }
            debug_log(
                "Discarding an answer to a request this proxy is no longer waiting on",
                &[json!({"id": id})],
            );
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
        if answers_initialize {
            self.apply_negotiated_protocol_version(&message);
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
        last_initialize: Mutex::new(None),
        reinit_seq: AtomicU64::new(0),
        pending_reinit: Mutex::new(HashMap::new()),
        ping_seq: AtomicU64::new(0),
        pending_pings: Mutex::new(HashSet::new()),
        reauthorize_flight: SingleFlight::default(),
        reinitialize_flight: SingleFlight::default(),
    });
    let (forward, forward_receiver) = mpsc::unbounded_channel();
    let forwarder = tokio::spawn(forward_in_order(Arc::clone(&shared), forward_receiver));
    let mut keep_alive = shared
        .options
        .keep_alive
        .map(|interval| Arc::clone(&shared).start_keep_alive(interval));
    let stop_keep_alive = |keep_alive: &mut Option<tokio::task::JoinHandle<()>>| {
        if let Some(timer) = keep_alive.take() {
            timer.abort();
        }
        lock(&shared.pending_pings).clear();
    };
    const CLOSED: &str = "the connection closed before this could be answered";

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
                    stop_keep_alive(&mut keep_alive);
                    client_closed = true;
                    shared.fail_own_pending_requests(CLOSED);
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
                    stop_keep_alive(&mut keep_alive);
                    server_closed = true;
                    shared.fail_own_pending_requests(CLOSED);
                    if !client_closed {
                        debug_log("Remote transport closed, closing local transport", &[]);
                        shared.client.close_transport();
                    }
                }
            },
        }
    }
    stop_keep_alive(&mut keep_alive);
    forwarder.abort();
}
