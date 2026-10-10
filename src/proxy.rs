//! The bidirectional proxy between the local client and the remote server
//! (`mcpProxy` in utils.ts).
//!
//! In the `auto` protocol mode the first handshake is preceded by one `server/discover`, and a
//! 2026-07-28 server is bridged: the handshake is answered here and every request is stamped with
//! the metadata that era requires. A server answering `input_required` has its questions put to
//! the client and the request retried with the answers, and a `subscriptions/listen` stream is
//! opened on the client's behalf so it keeps hearing about changes.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::AsyncWrite;
use tokio::sync::{mpsc, oneshot, watch};

use crate::connect::{RemoteTransport, StreamReconnectHook};
use crate::logging::{debug_log, log};
use crate::protocol_era::{
    EraVerdict, LegacyClientIdentity, MAX_INPUT_REQUESTS_PER_ROUND, MAX_INPUT_REQUIRED_ROUNDS,
    ProtocolMode, RETIRED_SET_LOG_LEVEL, RETIRED_SUBSCRIBE_RESOURCE, RETIRED_UNSUBSCRIBE_RESOURCE,
    TranslatedResult, can_fulfil_input_request, client_declared_capability_for, discover_request,
    input_required_retry_params, is_dropped_in_modern_era, is_input_required_result,
    is_modern_only_notification, local_answer_for, read_era_from_discover_response,
    stamp_log_level, stamp_modern_meta, strip_subscription_meta, subscription_filter_for,
    subscriptions_listen_request, synthesize_initialize_result, translate_modern_result,
    unacknowledged_subscriptions,
};
use crate::stdio::{StdioServerTransport, TransportEvent};
use crate::streamable_http::{StreamableHttpClientTransport, TransportError};
use crate::utils::{MCP_REMOTE_VERSION, ignored_tool_call_error, transform_proxy_response};

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// How long the client's first requests wait on `notifications/initialized` before going anyway.
pub const LIFECYCLE_BARRIER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the remote server to answer the client's `initialize`.
pub const INITIALIZE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a reconnected SSE stream gets to advertise its new POST endpoint.
pub const RECONNECT_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the POST endpoint is checked while waiting for it to move.
const RECONNECT_ENDPOINT_POLL: Duration = Duration::from_millis(25);

/// How long to wait for the remote server to answer a re-initialize after its session expired.
pub const REINITIALIZE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the `server/discover` probe waits for an answer before treating the server as legacy.
pub const DISCOVER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long each leg of a multi-round-trip exchange may take: a question to the client is a model
/// call or a person reading something, not a request that was never expected to run long.
pub const MULTI_ROUND_TRIP_LEG_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long a `subscriptions/listen` stream may stay open. Not a request timeout: the request
/// is the stream, so this bounds a session's worth of change notifications.
pub const SUBSCRIPTION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// How long to wait before reopening a change-notification stream that ended.
pub const SUBSCRIPTION_REOPEN_DELAY: Duration = Duration::from_secs(2);

/// How many times a change-notification stream may end without ever staying open before this
/// stops reopening it.
pub const SUBSCRIPTION_REOPEN_LIMIT: u32 = 5;

/// How long a stream has to stay open to count as having worked. Below this it did not really
/// open, and reopening it on a timer would be a request every couple of seconds forever.
pub const SUBSCRIPTION_HELD_OPEN: Duration = Duration::from_secs(30);

/// What `ask_remote` fails with when its `cancelled` future completes.
const ASK_CANCELLED: &str = "the request was cancelled";

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
    /// Where an SSE transport is currently POSTing, which is where its session lives. It moves
    /// when the stream comes back on a new session.
    fn post_endpoint(&self) -> Option<String> {
        None
    }
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

    fn post_endpoint(&self) -> Option<String> {
        match self {
            RemoteTransport::Http(_) => None,
            RemoteTransport::Sse(transport) => transport.endpoint().map(|url| url.to_string()),
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
    /// The transport's `onStreamReconnect` slot, which the proxy fills for as long as it runs.
    pub stream_reconnect: Option<StreamReconnectHook>,
    /// Whether to look for a 2026-07-28 server before handing it a handshake it no longer answers.
    pub protocol_mode: ProtocolMode,
    pub discover_timeout: Duration,
    pub subscription_reopen_delay: Duration,
    pub subscription_held_open: Duration,
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
            stream_reconnect: None,
            protocol_mode: ProtocolMode::Legacy,
            discover_timeout: DISCOVER_TIMEOUT,
            subscription_reopen_delay: SUBSCRIPTION_REOPEN_DELAY,
            subscription_held_open: SUBSCRIPTION_HELD_OPEN,
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
    /// The message transformer's held requests, by id, each with the token it was held under so
    /// a stale exchange can release its own hold without freeing a request that reused the id.
    transformer: Mutex<HashMap<String, (u64, Value)>>,
    hold_seq: AtomicU64,
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
    /// `sessionResumption`: true while the session is re-handshaked after the stream came back.
    resuming: watch::Sender<bool>,
    /// Set once the probe has run. Until then nothing is known about the server's era.
    era: Mutex<Option<EraVerdict>>,
    /// Set when the probe is queued, so a client re-sending `initialize` does not start a second.
    negotiation_started: std::sync::atomic::AtomicBool,
    /// What the client said in its `initialize`, replayed into the `_meta` of every modern request.
    client_identity: Mutex<LegacyClientIdentity>,
    discover_seq: AtomicU64,
    pending_discover: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    /// Resources the client subscribed to, in the order it asked, which the modern era carries on
    /// the listen stream instead.
    subscribed_resources: Mutex<Vec<String>>,
    /// The minimum log level the client asked for, which the modern era carries per request.
    requested_log_level: Mutex<Option<String>>,
    own_request_seq: AtomicU64,
    /// Requests this proxy issued to the remote on its own account, such as each retry leg.
    pending_own: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    /// Requests this proxy put to the local client on the remote's behalf.
    pending_client_requests: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    /// Client requests in flight against a modern server, with their transformer hold token, kept
    /// so an `input_required` answer can be retried with what the client sent.
    modern_originals: Mutex<HashMap<String, (Value, Option<u64>)>>,
    /// The id of the retry leg the server is running for a client request, so a cancellation
    /// naming the client's id can be re-addressed.
    modern_retry_ids: Mutex<HashMap<String, String>>,
    /// The exchange that currently speaks for a client request id. A token rather than a flag,
    /// because the client may reuse an id while a stranded exchange still runs under it.
    live_exchanges: Mutex<HashMap<String, u64>>,
    exchange_seq: AtomicU64,
    /// Set once either transport has closed.
    closed: watch::Sender<bool>,
    /// `refreshSubscription`: bumped whenever the client changes what it wants listened to, which
    /// both wakes an idle wait and cancels the stream listening for the old filter.
    subscription_generation: watch::Sender<u64>,
    /// Whether to leave resource subscriptions out of the filter: set when a server refuses a
    /// filter naming them, cleared the next time the client changes what it wants.
    drop_resource_subscriptions: std::sync::atomic::AtomicBool,
}

/// What the forwarder works through, in the order the client sent it.
enum Forward {
    /// The client's first handshake, held until the probe says which era to answer it in.
    Negotiate(Value),
    Message(Value),
}

impl<C: ProxyTransport, S: ProxyTransport> Shared<C, S> {
    /// `interceptRequest`: holds a request so its response can be paired with it.
    fn intercept_request(&self, message: &Value) {
        if is_request(message) {
            let token = self.hold_seq.fetch_add(1, Ordering::SeqCst);
            self.lock_transformer()
                .insert(id_key(&message["id"]), (token, message.clone()));
        }
    }

    /// `interceptResponse`: transforms a response against the request it answers.
    fn intercept_response(&self, message: Value) -> Value {
        if !is_response(&message) {
            return message;
        }
        let Some((_, request)) = self.lock_transformer().remove(&id_key(&message["id"])) else {
            return message;
        };
        let modern = self.modern_era().is_some();
        transform_proxy_response(&self.options.ignored_tools, modern, &request, message)
    }

    /// The revision and `server/discover` result of a server being bridged, if it is modern.
    fn modern_era(&self) -> Option<(String, Value)> {
        match &*lock(&self.era) {
            Some(EraVerdict::Modern { version, discover }) => {
                Some((version.clone(), discover.clone()))
            }
            _ => None,
        }
    }

    /// Stamps a request with what the modern era carries per request, when bridging to one.
    fn written_for_era(&self, message: &Value) -> Value {
        match self.modern_era() {
            Some((version, _)) if is_request(message) => {
                let identity = lock(&self.client_identity).clone();
                let level = lock(&self.requested_log_level).clone();
                stamp_log_level(
                    stamp_modern_meta(message, &identity, &version),
                    level.as_deref(),
                )
            }
            _ => message.clone(),
        }
    }

    /// `negotiateEra`: finds out which era the remote server belongs to with one
    /// `server/discover`, and answers the client's handshake either way. Only a `DiscoverResult`
    /// changes what happens next; anything else ends with the `initialize` going out as before.
    async fn negotiate_era(self: Arc<Self>, initialize: Value) {
        let id = format!(
            "{OWN_ID_PREFIX}discover-{}",
            self.discover_seq.fetch_add(1, Ordering::SeqCst) + 1
        );
        let identity = lock(&self.client_identity).clone();
        let (settle, answer) = oneshot::channel();
        lock(&self.pending_discover).insert(id.clone(), settle);
        let probe = async {
            self.server
                .send_message(discover_request(&id, &identity))
                .await
                .map_err(|error| error.to_string())?;
            answer
                .await
                .map_err(|_| "the connection closed before this could be answered".to_owned())
        };
        let response = match tokio::time::timeout(self.options.discover_timeout, probe).await {
            Ok(response) => response,
            Err(_) => Err("timed out waiting for the server/discover response".to_owned()),
        };
        let era = match response {
            Ok(response) => read_era_from_discover_response(&response),
            Err(reason) => {
                lock(&self.pending_discover).remove(&id);
                debug_log(
                    "server/discover produced no evidence of a modern server",
                    &[Value::String(reason.clone())],
                );
                EraVerdict::Legacy { reason }
            }
        };
        *lock(&self.era) = Some(era.clone());

        match era {
            EraVerdict::Modern { version, discover } => {
                log(
                    &format!(
                        "Remote server speaks MCP {version}; answering the local client's handshake here and bridging every request"
                    ),
                    &[],
                );
                debug_log(
                    "Bridging to a modern server",
                    &[json!({"version": version, "capabilities": discover.get("capabilities")})],
                );
                // Nothing will answer an `initialize` we never send, and the header has to name
                // the revision the `_meta` of every request will, or the server answers -32020
                *lock(&self.initialize_request_id) = None;
                self.server.set_protocol_version(version.clone());
                self.send_to_client(json!({
                    "jsonrpc": "2.0",
                    "id": initialize["id"],
                    "result": synthesize_initialize_result(&discover, &identity),
                }))
                .await;
                let capabilities = discover
                    .get("capabilities")
                    .and_then(Value::as_object)
                    .cloned();
                tokio::spawn(Arc::clone(&self).open_change_subscription(version, capabilities));
            }
            EraVerdict::Incompatible { reason } => {
                // Falling back to `initialize` here would fail too, and hide why it failed
                log(&format!("Cannot bridge to this server: {reason}"), &[]);
                self.send_to_client(json!({
                    "jsonrpc": "2.0",
                    "id": initialize["id"],
                    "error": {
                        "code": -32603,
                        "message": format!("mcp-remote cannot bridge to this server: {reason}"),
                    },
                }))
                .await;
            }
            EraVerdict::Legacy { reason } => {
                debug_log(
                    "Treating the remote server as legacy",
                    &[json!({"reason": reason})],
                );
                tokio::spawn(self.send_to_server(initialize));
            }
        }
    }

    /// The part of `forwardInOrder` that answers or drops what a modern server has no method
    /// for. Returns whether the message was dealt with here.
    async fn bridge_locally(self: &Arc<Self>, message: &Value) -> bool {
        let Some((_, discover)) = self.modern_era() else {
            return false;
        };
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return false;
        };

        // A cancellation names the id the client knows; mid-exchange the server is working under
        // the id this proxy minted for the retry leg, so it has to be re-addressed
        let cancelled = message
            .get("params")
            .and_then(|params| params.get("requestId"))
            .map(id_key);
        if method == "notifications/cancelled"
            && let Some(cancelled) = cancelled
            && lock(&self.live_exchanges).remove(&cancelled).is_some()
        {
            // Retired whether or not a leg is running yet: the exchange will still finish and
            // must not answer a request the client has abandoned
            self.lock_pending().remove(&cancelled);
            let retry_id = lock(&self.modern_retry_ids).remove(&cancelled);
            if let Some(retry_id) = retry_id {
                debug_log(
                    "Re-addressing a cancellation to the leg the server is actually running",
                    &[json!({"retryId": retry_id})],
                );
                let mut readdressed = message.clone();
                readdressed["params"]["requestId"] = Value::String(retry_id);
                tokio::spawn(Arc::clone(self).send_to_server(readdressed));
            } else {
                debug_log(
                    "Cancelling an exchange that has nothing in flight with the server yet",
                    &[json!({"id": message["params"]["requestId"]})],
                );
            }
            return true;
        }

        if let Some(answer) = local_answer_for(method) {
            // Retired methods whose effect this proxy still owes the client
            let params = message.get("params");
            let uri = params
                .and_then(|params| params.get("uri"))
                .and_then(Value::as_str);
            match (method, uri) {
                (RETIRED_SUBSCRIBE_RESOURCE, Some(uri)) => {
                    let mut resources = lock(&self.subscribed_resources);
                    if !resources.iter().any(|resource| resource == uri) {
                        resources.push(uri.to_owned());
                    }
                    drop(resources);
                    self.refresh_subscription();
                }
                (RETIRED_UNSUBSCRIBE_RESOURCE, Some(uri)) => {
                    lock(&self.subscribed_resources).retain(|resource| resource != uri);
                    self.refresh_subscription();
                }
                (RETIRED_SET_LOG_LEVEL, _) => {
                    if let Some(level) = params
                        .and_then(|params| params.get("level"))
                        .and_then(Value::as_str)
                    {
                        *lock(&self.requested_log_level) = Some(level.to_owned());
                        debug_log(
                            "Recording the log level to carry on every later request",
                            &[json!({"level": level})],
                        );
                    }
                }
                _ => {}
            }

            // A request is answered; the same method sent as a notification is simply dropped
            if has_id(message) {
                debug_log(
                    "Answering locally a method the modern era does not define",
                    &[json!({"method": method})],
                );
                self.release(&message["id"], None);
                self.send_to_client(
                    json!({"jsonrpc": "2.0", "id": message["id"], "result": answer}),
                )
                .await;
            } else {
                debug_log(
                    "Dropping a notification for a method the modern era does not define",
                    &[json!({"method": method})],
                );
            }
            return true;
        }

        if is_dropped_in_modern_era(method) {
            debug_log(
                "Dropping a notification the modern era has no place for",
                &[json!({"method": method})],
            );
            return true;
        }

        // The handshake was answered here, so a repeat is this proxy's to answer too
        if method == "initialize" && has_id(message) {
            debug_log(
                "Answering a repeated handshake from the bridge rather than forwarding it",
                &[],
            );
            let identity = lock(&self.client_identity).clone();
            self.send_to_client(json!({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": synthesize_initialize_result(&discover, &identity),
            }))
            .await;
            return true;
        }

        false
    }

    /// `askRemote`: issues a request to the remote server on this proxy's own account and waits
    /// for its answer. `build` is handed the minted id.
    ///
    /// `cancelled`, when it completes, gives up on the answer and tells the server, because a
    /// `subscriptions/listen` that is abandoned rather than cancelled stays open and goes on
    /// delivering.
    async fn ask_remote(
        &self,
        build: impl FnOnce(&str) -> Value,
        timeout: Duration,
        cancelled: impl Future<Output = ()>,
    ) -> Result<Value, String> {
        let id = format!(
            "{OWN_ID_PREFIX}own-{}",
            self.own_request_seq.fetch_add(1, Ordering::SeqCst) + 1
        );
        tokio::pin!(cancelled);
        // The same barrier `send_to_server` waits on; without it a retry leg is POSTed onto the
        // session that just went away. Cancelled before it was ever sent, there is nothing to
        // tell the server about.
        tokio::select! {
            _ = self.await_session_resumption() => {}
            _ = &mut cancelled => return Err(ASK_CANCELLED.to_owned()),
        }

        let (settle, answer) = oneshot::channel();
        lock(&self.pending_own).insert(id.clone(), settle);
        if let Err(error) = self.server.send_message(build(&id)).await {
            lock(&self.pending_own).remove(&id);
            return Err(error.to_string());
        }
        tokio::select! {
            answer = tokio::time::timeout(timeout, answer) => match answer {
                Ok(Ok(message)) => Ok(message),
                Ok(Err(_)) => {
                    Err("the connection closed before this could be answered".to_owned())
                }
                Err(_) => {
                    lock(&self.pending_own).remove(&id);
                    Err("timed out waiting for the remote server to answer".to_owned())
                }
            },
            _ = &mut cancelled => {
                lock(&self.pending_own).remove(&id);
                let cancellation = json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": id},
                });
                let _ = self.server.send_message(cancellation).await;
                Err(ASK_CANCELLED.to_owned())
            }
        }
    }

    /// `refreshSubscription`: the client changed what it wants listened to.
    fn refresh_subscription(&self) {
        self.drop_resource_subscriptions
            .store(false, Ordering::SeqCst);
        self.subscription_generation
            .send_modify(|generation| *generation += 1);
    }

    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    async fn wait_closed(&self) {
        let mut closed = self.closed.subscribe();
        let _ = closed.wait_for(|closed| *closed).await;
    }

    /// Sleeps for `duration`, returning whether there is still a connection worth working on.
    async fn pause(&self, duration: Duration) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(duration) => !self.is_closed(),
            _ = self.wait_closed() => false,
        }
    }

    /// `openChangeSubscription`: opens the change-notification stream a 2025-era client would
    /// never open for itself. That era had `notifications/tools/list_changed` and friends simply
    /// arrive; the modern era sends them only down a `subscriptions/listen` stream, so this asks
    /// on the client's behalf for exactly what the server said it can send.
    ///
    /// Nothing awaits this: failing to open the stream costs the client change notifications, not
    /// its session.
    async fn open_change_subscription(
        self: Arc<Self>,
        version: String,
        capabilities: Option<serde_json::Map<String, Value>>,
    ) {
        let delay = self.options.subscription_reopen_delay;
        let mut generation = self.subscription_generation.subscribe();
        // Counts only streams the server ended as soon as they opened. A reopen the client asked
        // for spends none of this budget.
        let mut short_lived_streams = 0;

        while short_lived_streams < SUBSCRIPTION_REOPEN_LIMIT {
            // Marked seen before the filter is read, so a change made after this point always
            // reopens or wakes what follows
            generation.borrow_and_update();
            let resources = if self.drop_resource_subscriptions.load(Ordering::SeqCst) {
                Vec::new()
            } else {
                lock(&self.subscribed_resources).clone()
            };
            let Some(Value::Object(notifications)) =
                subscription_filter_for(capabilities.as_ref(), &resources)
            else {
                // A later `resources/subscribe` is what gives this a reason to exist
                debug_log(
                    "Nothing to subscribe to yet; waiting for the client to ask for something",
                    &[],
                );
                short_lived_streams = 0;
                tokio::select! {
                    _ = generation.changed() => continue,
                    _ = self.wait_closed() => return,
                }
            };

            let opened_at = std::time::Instant::now();
            debug_log(
                "Subscribing to change notifications on the client behalf",
                &[json!({"notifications": notifications})],
            );
            let identity = lock(&self.client_identity).clone();
            let mut reopen = generation.clone();
            // Cancelled rather than abandoned when the filter changes: a stream left open goes on
            // delivering, so the client would see every change once per filter it ever asked for
            let reopened = async move {
                let _ = reopen.changed().await;
            };
            let response = self
                .ask_remote(
                    |id| subscriptions_listen_request(id, &identity, &version, &notifications),
                    SUBSCRIPTION_LIFETIME,
                    reopened,
                )
                .await;

            match response {
                Ok(response) if response.get("error").is_some() => {
                    // A transport that has gone answers everything outstanding with an error,
                    // and that is not the server refusing anything
                    if self.is_closed() {
                        return;
                    }
                    let error = response["error"].to_string();
                    if !self.drop_resource_subscriptions.load(Ordering::SeqCst)
                        && !lock(&self.subscribed_resources).is_empty()
                    {
                        // The filter named resources; the rest of it may still be acceptable
                        log(
                            &format!(
                                "The remote server refused a subscription naming resources; listening for the rest: {error}"
                            ),
                            &[],
                        );
                        self.drop_resource_subscriptions
                            .store(true, Ordering::SeqCst);
                        continue;
                    }
                    // A refusal is a decision, not a flake; reopening would only ask again
                    log(
                        &format!(
                            "The remote server refused the change-notification subscription: {error}"
                        ),
                        &[],
                    );
                    return;
                }
                Ok(_) => debug_log(
                    "The change-notification stream ended",
                    &[json!({"heldForMs": opened_at.elapsed().as_millis() as u64})],
                ),
                Err(error) if error == ASK_CANCELLED => {
                    debug_log(
                        "Reopening the change-notification stream against a filter the client changed",
                        &[],
                    );
                    // Debounced, so a client subscribing in a tight loop cannot turn each call
                    // into an immediate round trip
                    if self.is_closed() || !self.pause(delay).await {
                        return;
                    }
                    continue;
                }
                Err(error) => debug_log(
                    "The change-notification stream failed",
                    &[json!({
                        "heldForMs": opened_at.elapsed().as_millis() as u64,
                        "error": error,
                    })],
                ),
            }

            // A stream that stayed open did its job, so the budget starts again. One that ended
            // immediately is a server that does not really hold it open.
            if opened_at.elapsed() >= self.options.subscription_held_open {
                short_lived_streams = 0;
            } else {
                short_lived_streams += 1;
            }
            if self.is_closed() || !self.pause(delay).await {
                return;
            }
        }

        log(
            "Giving up on change notifications: the subscription stream kept ending as soon as it opened",
            &[],
        );
    }

    /// `askClient`: puts a request to the local client on the remote server's behalf. A 2025-era
    /// client already answers sampling, elicitation and roots; that era had the server ask directly.
    async fn ask_client(
        &self,
        method: &str,
        params: Option<&Value>,
        timeout: Duration,
    ) -> Result<Value, String> {
        let id = format!(
            "{OWN_ID_PREFIX}input-{}",
            self.own_request_seq.fetch_add(1, Ordering::SeqCst) + 1
        );
        let (settle, answer) = oneshot::channel();
        lock(&self.pending_client_requests).insert(id.clone(), settle);
        let mut request = json!({"jsonrpc": "2.0", "id": id, "method": method});
        if let Some(params) = params {
            request["params"] = params.clone();
        }
        if let Err(error) = self.client.send_message(request).await {
            lock(&self.pending_client_requests).remove(&id);
            return Err(error.to_string());
        }
        match tokio::time::timeout(timeout, answer).await {
            Ok(Ok(message)) => Ok(message),
            Ok(Err(_)) => Err("the connection closed before this could be answered".to_owned()),
            Err(_) => {
                lock(&self.pending_client_requests).remove(&id);
                Err(format!("the local client did not answer {method}"))
            }
        }
    }

    /// `answerClient`: answers the client's own request through the response transformer, so the
    /// `--ignore-tool` filter applies to an answer that arrived across a round trip. Only the
    /// exchange still holding the id may answer it.
    async fn answer_client(&self, message: Value, exchange: Option<u64>, token: Option<u64>) {
        if has_id(&message) {
            let key = id_key(&message["id"]);
            if let Some(exchange) = exchange
                && lock(&self.live_exchanges).get(&key) != Some(&exchange)
            {
                debug_log(
                    "Dropping an answer from an exchange that no longer speaks for this request",
                    &[json!({"id": message["id"], "exchange": exchange})],
                );
                // Releases this exchange's own hold, not that of a request that reused the id
                self.release_hold(&message["id"], token);
                return;
            }
            self.lock_pending().remove(&key);
            lock(&self.modern_retry_ids).remove(&key);
            lock(&self.live_exchanges).remove(&key);
        }
        let message = self.intercept_response(message);
        self.send_to_client(message).await;
    }

    /// `driveInputRequired`: puts each question a modern server embedded in an `input_required`
    /// result to the client, retries the original request with the answers, and answers the
    /// client once the server completes.
    async fn drive_input_required(
        self: Arc<Self>,
        original: &Value,
        first_result: Value,
        version: &str,
        exchange: u64,
        token: Option<u64>,
    ) -> Result<(), String> {
        let mut pending = first_result;
        for _ in 0..MAX_INPUT_REQUIRED_ROUNDS {
            let requests = pending
                .get("inputRequests")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let request_state = pending.get("requestState").filter(|state| !state.is_null());

            // A retry byte-identical to the request that produced this would just run the tool
            // again, with every side effect that implies
            if requests.is_empty() && request_state.is_none() {
                return Err("the remote server asked for more input but named none, and carried no state to continue from".to_owned());
            }
            if requests.len() > MAX_INPUT_REQUESTS_PER_ROUND {
                return Err(format!(
                    "the remote server embedded {} questions in one answer, which is more than this proxy will put to a client at once",
                    requests.len()
                ));
            }

            let mut responses = serde_json::Map::new();
            for (key, request) in &requests {
                let method = request
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("undefined");
                let params = request.get("params");
                if !can_fulfil_input_request(method, params) {
                    return Err(format!(
                        "the remote server asked for {method}, which this proxy cannot put to a 2025-era client"
                    ));
                }
                // The client said in its handshake what it can do; asking anyway earns a -32601
                let capabilities = lock(&self.client_identity).capabilities.clone();
                if !client_declared_capability_for(method, capabilities.as_ref()) {
                    return Err(format!(
                        "the remote server asked for {method}, which this client did not declare it supports"
                    ));
                }
                let answer = self
                    .ask_client(method, params, MULTI_ROUND_TRIP_LEG_TIMEOUT)
                    .await?;
                if let Some(error) = answer.get("error") {
                    return Err(format!("the local client refused {method}: {error}"));
                }
                responses.insert(
                    key.clone(),
                    answer.get("result").cloned().unwrap_or(Value::Null),
                );
            }

            let retry_params = input_required_retry_params(
                original.get("params"),
                &responses,
                request_state.and_then(Value::as_str),
            );
            let identity = lock(&self.client_identity).clone();
            let level = lock(&self.requested_log_level).clone();
            let reply = self
                .ask_remote(
                    |id| {
                        // Recorded so a cancellation naming the client's id can be re-addressed
                        // to the leg the server is actually running
                        lock(&self.modern_retry_ids).insert(id_key(&original["id"]), id.to_owned());
                        let mut retry = original.clone();
                        retry["id"] = Value::String(id.to_owned());
                        retry["params"] = retry_params;
                        stamp_log_level(
                            stamp_modern_meta(&retry, &identity, version),
                            level.as_deref(),
                        )
                    },
                    MULTI_ROUND_TRIP_LEG_TIMEOUT,
                    std::future::pending(),
                )
                .await?;

            if let Some(error) = reply.get("error") {
                self.answer_client(
                    json!({"jsonrpc": "2.0", "id": original["id"], "error": error}),
                    Some(exchange),
                    token,
                )
                .await;
                return Ok(());
            }
            let result = reply.get("result").cloned().unwrap_or(Value::Null);
            if !is_input_required_result(&result) {
                let answer = match translate_modern_result(result) {
                    TranslatedResult::Result(result) => {
                        json!({"jsonrpc": "2.0", "id": original["id"], "result": result})
                    }
                    TranslatedResult::Error { code, message } => json!({
                        "jsonrpc": "2.0",
                        "id": original["id"],
                        "error": {"code": code, "message": message},
                    }),
                };
                self.answer_client(answer, Some(exchange), token).await;
                return Ok(());
            }
            pending = result;
        }
        Err(format!(
            "the remote server asked for more input {MAX_INPUT_REQUIRED_ROUNDS} times without answering"
        ))
    }

    /// Releases the held request for an answer that did not come from the server.
    fn release(&self, id: &Value, only: Option<&Value>) {
        let mut transformer = self.lock_transformer();
        let key = id_key(id);
        if only.is_some_and(|only| transformer.get(&key).map(|(_, held)| held) != Some(only)) {
            return;
        }
        transformer.remove(&key);
    }

    /// Releases the hold taken under `token`, and nobody else's.
    fn release_hold(&self, id: &Value, token: Option<u64>) {
        let mut transformer = self.lock_transformer();
        let key = id_key(id);
        if token.is_some() && transformer.get(&key).map(|(held, _)| *held) == token {
            transformer.remove(&key);
        }
    }

    fn lock_transformer(&self) -> std::sync::MutexGuard<'_, HashMap<String, (u64, Value)>> {
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
        // The stream came back on a session that has not been handshaked yet; sending now would
        // race the recovery onto the session the server dropped. The recovery's own messages go
        // straight to the transport, so it never waits on itself.
        self.await_session_resumption().await;

        let awaits_answer = is_request(&message);
        let mut already_reauthorized = false;
        let mut already_discarded_token = false;
        loop {
            if awaits_answer {
                self.lock_pending().insert(id_key(&message["id"]));
            }
            // Stamped here rather than on arrival, which can be before the probe has said which
            // era to speak
            let outgoing = self.written_for_era(&message);
            // Kept so that a server answering `input_required` can be retried with what the client
            // sent. The id is the client's to reuse, and doing so ends whatever ran under it.
            if awaits_answer && self.modern_era().is_some() {
                let key = id_key(&message["id"]);
                lock(&self.live_exchanges).remove(&key);
                lock(&self.modern_retry_ids).remove(&key);
                let token = self.lock_transformer().get(&key).map(|(token, _)| *token);
                lock(&self.modern_originals).insert(key, (message.clone(), token));
            }
            let error = match self.server.send_message(outgoing).await {
                Ok(()) => {
                    if message["method"] == "initialize" {
                        self.schedule_initialize_timeout(message);
                    }
                    return;
                }
                Err(error) => error,
            };
            if awaits_answer {
                let key = id_key(&message["id"]);
                self.lock_pending().remove(&key);
                // Left behind, a later stray frame for this id would start a whole exchange for a
                // request the client has already been told failed
                lock(&self.modern_originals).remove(&key);
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
                    .send_message(self.written_for_era(&message))
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

    async fn await_session_resumption(&self) {
        let mut resuming = self.resuming.subscribe();
        let _ = resuming.wait_for(|resuming| !*resuming).await;
    }

    /// `onStreamReconnect`: the stream coming back is not the session coming back. The endpoint
    /// moves to a session the server has just created, and requests would keep going out against
    /// a lifecycle that never started.
    fn on_stream_reconnect(self: Arc<Self>) {
        let dropped_endpoint = self.server.post_endpoint();
        // Set before anything is awaited: a client request arriving in the gap must not go out
        // to the session that has gone away
        self.resuming.send_replace(true);
        let failed: Vec<String> = self.lock_pending().drain().collect();
        tokio::spawn(async move {
            // Whatever was in flight went to a session that no longer exists, and its answer was
            // going to arrive on a stream that no longer exists either
            self.fail_pending_requests(
                failed,
                "the connection to the remote server dropped before this could be answered",
            )
            .await;
            let deadline = tokio::time::Instant::now() + RECONNECT_ENDPOINT_TIMEOUT;
            // Giving up on the wait does not give up on the handshake: a server that reuses the
            // endpoint still discarded the lifecycle
            while self.server.post_endpoint() == dropped_endpoint
                && tokio::time::Instant::now() < deadline
            {
                tokio::time::sleep(RECONNECT_ENDPOINT_POLL).await;
            }
            if let Err(error) = Arc::clone(&self).reinitialize_session().await {
                on_server_error(&error);
            }
            self.resuming.send_replace(false);
        });
    }

    /// `failPendingRequests`: answers every request the dropped session can no longer answer.
    async fn fail_pending_requests(&self, ids: Vec<String>, reason: &str) {
        if ids.is_empty() {
            return;
        }
        debug_log(
            "Failing requests the dropped session can no longer answer",
            &[
                json!({"ids": ids.iter().map(|id| serde_json::from_str::<Value>(id).unwrap_or(Value::Null)).collect::<Vec<_>>()}),
            ],
        );
        for key in ids {
            let id: Value = serde_json::from_str(&key).unwrap_or(Value::Null);
            self.release(&id, None);
            // Answered now, so there is nothing left to retry an exchange for, and an exchange
            // still running loses its claim on the id
            lock(&self.modern_originals).remove(&key);
            lock(&self.modern_retry_ids).remove(&key);
            lock(&self.live_exchanges).remove(&key);
            self.send_to_client(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32001, "message": format!("mcp-remote: {reason}")},
            }))
            .await;
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
                // `ping` is not a method the 2026-07-28 era defines, and a stateless server has
                // no session whose liveness could lapse
                if self.modern_era().is_some() {
                    continue;
                }
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
        let mut pending: Vec<(String, oneshot::Sender<Value>)> =
            lock(&self.pending_own).drain().collect();
        pending.extend(lock(&self.pending_client_requests).drain());
        pending.extend(lock(&self.pending_discover).drain());
        pending.extend(lock(&self.pending_reinit).drain());
        for (id, settle) in pending {
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

    async fn on_client_message(
        &self,
        mut message: Value,
        forward: &mpsc::UnboundedSender<Forward>,
    ) {
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
            } else if let Some(settle) =
                lock(&self.pending_client_requests).remove(id.as_str().unwrap_or_default())
            {
                let _ = settle.send(message);
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
            let params = message.get("params");
            *lock(&self.client_identity) = LegacyClientIdentity {
                protocol_version: params
                    .and_then(|params| params.get("protocolVersion"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                capabilities: Some(
                    params
                        .and_then(|params| params.get("capabilities"))
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default(),
                ),
                client_info: params
                    .and_then(|params| params.get("clientInfo"))
                    .filter(|client_info| !client_info.is_null())
                    .cloned(),
            };

            // The handshake is the only moment the era can be settled, and only once: a client
            // re-sending `initialize` during the probe must not start a second one
            if self.options.protocol_mode == ProtocolMode::Auto
                && lock(&self.era).is_none()
                && !self.negotiation_started.swap(true, Ordering::SeqCst)
            {
                let _ = forward.send(Forward::Negotiate(message));
                return;
            }
        }

        let _ = forward.send(Forward::Message(message));
    }

    async fn on_server_message(self: &Arc<Self>, message: Value) {
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
            let settle = lock(&self.pending_own)
                .remove(key)
                .or_else(|| lock(&self.pending_discover).remove(key))
                .or_else(|| lock(&self.pending_reinit).remove(key));
            if let Some(settle) = settle {
                let _ = settle.send(message);
                return;
            }
            debug_log(
                "Discarding an answer to a request this proxy is no longer waiting on",
                &[json!({"id": id})],
            );
            return;
        }

        let modern = self.modern_era();

        // Confirmation of a stream this proxy opened for the client, which it never asked for
        if let Some((_, discover)) = &modern
            && let Some(method) = message.get("method").and_then(Value::as_str)
            && is_modern_only_notification(method)
        {
            let resources = lock(&self.subscribed_resources).clone();
            let capabilities = discover.get("capabilities").and_then(Value::as_object);
            if let Some(Value::Object(requested)) =
                subscription_filter_for(capabilities, &resources)
            {
                let granted = message
                    .get("params")
                    .and_then(|params| params.get("notifications"));
                let missing = unacknowledged_subscriptions(&requested, granted);
                if !missing.is_empty() {
                    // Otherwise a type the server quietly dropped is one the client waits for
                    log(
                        &format!(
                            "The remote server did not subscribe this client to: {}",
                            missing.join(", ")
                        ),
                        &[],
                    );
                }
            }
            debug_log(
                "Consuming a notification that belongs to this proxy, not the client",
                &[json!({"method": method})],
            );
            return;
        }

        // A modern server asking for input rather than answering. The client is left waiting on
        // the request it sent while the questions are put to it, and is answered once.
        if let Some((version, _)) = &modern
            && !id.is_null()
            && message.get("result").is_some_and(is_input_required_result)
        {
            let key = id_key(&id);
            let Some((original, token)) = lock(&self.modern_originals).remove(&key) else {
                // Already answered, by a dropped session or a cancellation; translating it would
                // send the client a second response for the same id
                debug_log(
                    "Discarding a request for more input on an exchange that is already over",
                    &[json!({"id": id})],
                );
                return;
            };
            // Left in `pending_requests`: the exchange is still owed an answer, and a dropped
            // session has to be able to fail it
            log(
                "[Remote→Local]",
                &[Value::String(format!(
                    "{} (asking for more input)",
                    id.as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| id.to_string())
                ))],
            );
            let exchange = self.exchange_seq.fetch_add(1, Ordering::SeqCst) + 1;
            lock(&self.live_exchanges).insert(key, exchange);
            let shared = Arc::clone(self);
            let first_result = message["result"].clone();
            let version = version.clone();
            tokio::spawn(async move {
                let outcome = Arc::clone(&shared)
                    .drive_input_required(&original, first_result, &version, exchange, token)
                    .await;
                if let Err(error) = outcome {
                    on_server_error(&error);
                    shared
                        .answer_client(
                            json!({
                                "jsonrpc": "2.0",
                                "id": original["id"],
                                "error": {"code": -32001, "message": format!("mcp-remote: {error}")},
                            }),
                            Some(exchange),
                            token,
                        )
                        .await;
                }
            });
            return;
        }

        if !id.is_null() {
            let key = id_key(&id);
            self.lock_pending().remove(&key);
            lock(&self.modern_originals).remove(&key);
            lock(&self.modern_retry_ids).remove(&key);
        }

        let message = self.intercept_response(message);
        let message = if modern.is_some() {
            strip_subscription_meta(message)
        } else {
            message
        };
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
    mut messages: mpsc::UnboundedReceiver<Forward>,
) {
    let mut initialized_delivered: Option<(tokio::task::JoinHandle<()>, tokio::time::Instant)> =
        None;
    while let Some(item) = messages.recv().await {
        let message = match item {
            // Nothing after the handshake can be written correctly until the probe has said
            // which era to write it in, so everything queues behind it
            Forward::Negotiate(initialize) => {
                Arc::clone(&shared).negotiate_era(initialize).await;
                continue;
            }
            Forward::Message(message) => message,
        };
        if shared.bridge_locally(&message).await {
            continue;
        }
        if let Some((barrier, deadline)) = initialized_delivered.as_mut()
            && !barrier.is_finished()
        {
            let _ = tokio::time::timeout_at(*deadline, barrier).await;
        }
        let task = tokio::spawn(Arc::clone(&shared).send_to_server(message.clone()));
        if message["method"] == "notifications/initialized" && message.get("id").is_none() {
            let deadline = tokio::time::Instant::now() + shared.options.lifecycle_barrier_timeout;
            initialized_delivered = Some((task, deadline));
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
        hold_seq: AtomicU64::new(0),
        pending_requests: Mutex::new(HashSet::new()),
        initialize_request_id: Mutex::new(None),
        last_initialize: Mutex::new(None),
        reinit_seq: AtomicU64::new(0),
        pending_reinit: Mutex::new(HashMap::new()),
        ping_seq: AtomicU64::new(0),
        pending_pings: Mutex::new(HashSet::new()),
        reauthorize_flight: SingleFlight::default(),
        reinitialize_flight: SingleFlight::default(),
        resuming: watch::Sender::new(false),
        era: Mutex::new(None),
        negotiation_started: std::sync::atomic::AtomicBool::new(false),
        client_identity: Mutex::new(LegacyClientIdentity::default()),
        discover_seq: AtomicU64::new(0),
        pending_discover: Mutex::new(HashMap::new()),
        subscribed_resources: Mutex::new(Vec::new()),
        requested_log_level: Mutex::new(None),
        own_request_seq: AtomicU64::new(0),
        pending_own: Mutex::new(HashMap::new()),
        pending_client_requests: Mutex::new(HashMap::new()),
        modern_originals: Mutex::new(HashMap::new()),
        modern_retry_ids: Mutex::new(HashMap::new()),
        live_exchanges: Mutex::new(HashMap::new()),
        exchange_seq: AtomicU64::new(0),
        closed: watch::Sender::new(false),
        subscription_generation: watch::Sender::new(0),
        drop_resource_subscriptions: std::sync::atomic::AtomicBool::new(false),
    });
    let reconnect_slot = shared.options.stream_reconnect.clone();
    if let Some(slot) = &reconnect_slot {
        let weak = Arc::downgrade(&shared);
        *lock(slot) = Some(Arc::new(move || {
            if let Some(shared) = weak.upgrade() {
                shared.on_stream_reconnect();
            }
        }));
    }
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
                    shared.closed.send_replace(true);
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
                    shared.closed.send_replace(true);
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
    if let Some(slot) = &reconnect_slot {
        *lock(slot) = None;
    }
}
