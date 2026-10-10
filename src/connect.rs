//! `connectToRemoteServer` from utils.ts: opens the remote transport, probes it with a throwaway
//! client, and answers what the probe runs into - a sign-in, a token refused straight after it
//! was issued, or a server that speaks the other transport.
//!
//! Not yet ported: the with-client mode client.ts uses.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use reqwest::header::{COOKIE, HeaderValue};
use reqwest::{Request, Url};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::auth::OAuthClientProvider;
use crate::callback_server::AuthCodeResult;
use crate::logging::{debug_log, log};
use crate::node_oauth_client_provider::CredentialScope;
use crate::oauth_provider::OAuthProvider;
use crate::protocol_era::{
    LATEST_PROTOCOL_VERSION, LegacyClientIdentity, ProbeVerdict, ProtocolMode,
    SUPPORTED_MODERN_VERSIONS, SUPPORTED_PROTOCOL_VERSIONS, classify_probe_error,
    classify_probe_response, stamp_modern_meta,
};
use crate::sse_client::{SseClientOptions, SseClientTransport};
use crate::stdio::TransportEvent;
use crate::streamable_http::{
    BoxFuture, FetchFn, StreamableHttpClientTransport, StreamableHttpOptions, TransportError,
    TransportOAuth, default_fetch,
};
use crate::utils::{TransportStrategy, capture_cookies, cookie_header_for, fetch_with_mcp_headers};

const REASON_AUTH_NEEDED: &str = "authentication-needed";
const REASON_TRANSPORT_FALLBACK: &str = "falling-back-to-alternate-transport";
const REASON_REJECTED_TOKEN: &str = "server-rejected-a-freshly-issued-token";
const REASON_SIBLING_TOKENS: &str = "signed-in-by-another-instance";

/// The SDK's DEFAULT_REQUEST_TIMEOUT_MSEC, which bounds the probe's `initialize`.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// Starts waiting for the authorization code; called only once a code is actually expected.
pub type WaitForAuthCode = Box<dyn FnOnce() -> BoxFuture<Result<AuthCodeResult, String>> + Send>;

/// What the auth initializer hands back: how to wait for a code, and whether another instance
/// is running the sign-in instead.
pub struct AuthInitialization {
    pub wait_for_auth_code: WaitForAuthCode,
    pub skip_browser_auth: bool,
}

/// proxy.ts's `authInitializer`; the flag is `forceRefresh`.
pub type AuthInitializer =
    Arc<dyn Fn(bool) -> BoxFuture<Result<AuthInitialization, String>> + Send + Sync>;

/// What connecting needs from the OAuth client provider.
pub trait RemoteAuth: Send + Sync {
    /// The provider as the transport drives it.
    fn transport_oauth(&self) -> Arc<dyn TransportOAuth>;
    /// `invalidateCredentials('tokens')`.
    fn forget_tokens(&self) -> BoxFuture<Result<(), String>>;
    /// `useAuthorizationState(state)`.
    fn use_authorization_state(&self, state: &str);
}

impl RemoteAuth for Arc<OAuthProvider> {
    fn transport_oauth(&self) -> Arc<dyn TransportOAuth> {
        Arc::new(Arc::clone(self))
    }

    fn forget_tokens(&self) -> BoxFuture<Result<(), String>> {
        let provider = Arc::clone(self);
        Box::pin(async move {
            provider
                .invalidate_credentials(CredentialScope::Tokens)
                .await
                .map_err(|error| error.to_string())
        })
    }

    fn use_authorization_state(&self, state: &str) {
        OAuthProvider::use_authorization_state(self, state);
    }
}

/// `forgetRejectedAuthorization`: discards the refused token, so the next attempt finds none
/// and runs a full sign-in.
pub async fn forget_rejected_authorization(auth: &dyn RemoteAuth) {
    if let Err(error) = auth.forget_tokens().await {
        debug_log(
            "Could not discard the refused token",
            &[Value::String(error)],
        );
    }
}

/// `isRejectedAfterAuthorizing`: the SDK's 401 after it had just authorized.
pub fn is_rejected_after_authorizing(error: &TransportError) -> bool {
    matches!(error, TransportError::Http { status: 401, .. })
}

fn should_fall_back_on(error: &TransportError) -> bool {
    let message = error.to_string();
    matches!(
        error,
        TransportError::Http {
            status: 404 | 405,
            ..
        }
    ) || ["405", "Method Not Allowed", "404", "Not Found"]
        .iter()
        .any(|needle| message.contains(needle))
}

fn is_unauthorized(error: &TransportError) -> bool {
    matches!(error, TransportError::Unauthorized(_)) || error.to_string().contains("Unauthorized")
}

/// Either transport connectToRemoteServer can hand back.
#[derive(Clone)]
pub enum RemoteTransport {
    Http(StreamableHttpClientTransport),
    Sse(SseClientTransport),
}

impl RemoteTransport {
    /// The SDK class name, as `transport.constructor.name` logs it.
    pub fn name(&self) -> &'static str {
        match self {
            RemoteTransport::Http(_) => "StreamableHTTPClientTransport",
            RemoteTransport::Sse(_) => "SSEClientTransport",
        }
    }

    pub async fn send(&self, message: &Value) -> Result<(), TransportError> {
        match self {
            RemoteTransport::Http(transport) => transport.send(message).await,
            RemoteTransport::Sse(transport) => transport.send(message).await,
        }
    }

    pub fn close(&self) {
        match self {
            RemoteTransport::Http(transport) => transport.close(),
            RemoteTransport::Sse(transport) => transport.close(),
        }
    }

    pub fn set_protocol_version(&self, version: Option<String>) {
        match self {
            RemoteTransport::Http(transport) => transport.set_protocol_version(version),
            RemoteTransport::Sse(transport) => transport.set_protocol_version(version),
        }
    }

    /// `finishAuth(code, iss)`; the SSE transport takes no `iss`.
    pub async fn finish_auth(&self, code: &str, iss: Option<&str>) -> Result<(), TransportError> {
        match self {
            RemoteTransport::Http(transport) => transport.finish_auth(code, iss).await,
            RemoteTransport::Sse(transport) => transport.finish_auth(code).await,
        }
    }
}

/// `onStreamReconnect`: set by the proxy, called when the SSE stream comes back on a new
/// session after it dropped. The SDK raises no event for that, so the stream fetch infers it
/// from the stream opening again.
pub type StreamReconnectHook = Arc<std::sync::Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>;

/// The connected remote transport and the events it delivers.
pub struct RemoteConnection {
    pub transport: RemoteTransport,
    pub events: UnboundedReceiver<TransportEvent>,
    /// Only ever called for an SSE transport.
    pub on_stream_reconnect: StreamReconnectHook,
}

/// `eventSourceInit.fetch`: opens the SSE stream with the jar's cookies (the stream is usually
/// where a balancer plants its cookie) and keeps the ones it sets. Every stream that opens after
/// the first is a reconnect, and is reported through `on_stream_reconnect`; a failed attempt is
/// not, since another follows it.
fn event_source_fetch(on_stream_reconnect: StreamReconnectHook) -> FetchFn {
    let fetch = default_fetch();
    let opened = Arc::new(AtomicUsize::new(0));
    Arc::new(move |mut request: Request| {
        let url = request.url().to_string();
        if let Some(cookie) = cookie_header_for(&url)
            && let Ok(value) = HeaderValue::from_str(&cookie)
            && !request.headers().contains_key(COOKIE)
        {
            request.headers_mut().insert(COOKIE, value);
        }
        let response = fetch(request);
        let opened = Arc::clone(&opened);
        let on_stream_reconnect = Arc::clone(&on_stream_reconnect);
        Box::pin(async move {
            let response = response.await?;
            capture_cookies(&url, &response);
            if response.status().is_success() && opened.fetch_add(1, Ordering::SeqCst) >= 1 {
                log("Remote SSE stream reconnected", &[]);
                let hook = on_stream_reconnect
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                if let Some(hook) = hook {
                    hook();
                }
            }
            Ok(response)
        })
    })
}

/// What connectToRemoteServer takes besides the auth provider and the initializer.
#[derive(Clone)]
pub struct ConnectOptions {
    pub server_url: String,
    pub headers: Vec<(String, String)>,
    pub transport_strategy: TransportStrategy,
    pub protocol_mode: ProtocolMode,
    /// NON_INTERACTIVE_FLOW: the sign-in needs no browser (device code, client credentials).
    pub non_interactive_flow: bool,
}

/// Why waiting for the answer to one request ended without it.
enum Unanswered {
    Closed,
    TimedOut,
}

/// Waits for the message answering `id` on `events`.
async fn answer_to(
    events: &mut UnboundedReceiver<TransportEvent>,
    id: &Value,
) -> Result<Value, Unanswered> {
    tokio::time::timeout(PROBE_TIMEOUT, async {
        loop {
            match events.recv().await {
                Some(TransportEvent::Message(message)) if message.get("id") == Some(id) => {
                    return Ok(message);
                }
                Some(TransportEvent::Close) | None => return Err(Unanswered::Closed),
                Some(_) => {}
            }
        }
    })
    .await
    .unwrap_or(Err(Unanswered::TimedOut))
}

/// `classifyHttpError` and its siblings: what a failed send of the probe says.
fn classify_probe_send_error(error: TransportError, requested: &str) -> Result<(), TransportError> {
    let negotiation_failed = |reason: String| {
        Err(TransportError::Other(format!(
            "Version negotiation probe failed: {reason}"
        )))
    };
    match error {
        TransportError::Unauthorized(_) | TransportError::Auth(_) => Err(error),
        TransportError::Http { status, .. } if status == 401 || status == 403 => {
            let reason = if status == 403 {
                "the server denied access (HTTP 403)"
            } else {
                "the server requires authorization (HTTP 401)"
            };
            Err(TransportError::Http {
                status,
                message: format!("Version negotiation failed: {reason}"),
            })
        }
        TransportError::Http { status, .. } if status >= 500 => Err(TransportError::Http {
            status,
            message: format!(
                "Version negotiation failed: the server answered the probe with HTTP {status}"
            ),
        }),
        TransportError::Http { message, .. } => {
            let rpc_error = message
                .strip_prefix("Error POSTing to endpoint: ")
                .and_then(|body| serde_json::from_str::<Value>(body).ok())
                .and_then(|body| body.get("error").cloned())
                .filter(|error| error.get("code").is_some_and(Value::is_i64));
            match rpc_error.map(|error| classify_probe_error(&error, requested)) {
                Some(ProbeVerdict::Error(message)) => Err(TransportError::Other(message)),
                _ => Ok(()),
            }
        }
        TransportError::Other(message) if message.starts_with("Unexpected content type") => {
            negotiation_failed(format!(
                "the server answered with an unusable reply ({message})"
            ))
        }
        other => negotiation_failed(other.to_string()),
    }
}

/// The SDK's `negotiateEra` for an `auto` client: one `server/discover`, retried once on a
/// corrective answer. Returns the modern version the server speaks, or None to fall back to
/// `initialize`.
async fn negotiate_probe_era(
    transport: &StreamableHttpClientTransport,
    events: &mut UnboundedReceiver<TransportEvent>,
) -> Result<Option<String>, TransportError> {
    let identity = LegacyClientIdentity {
        protocol_version: None,
        capabilities: Some(serde_json::Map::new()),
        client_info: Some(PROBE_CLIENT_INFO.clone()),
    };
    let mut requested = SUPPORTED_MODERN_VERSIONS[0].to_owned();
    let mut corrective_used = false;
    for attempt in 1.. {
        let id = json!(format!("server-discover-probe-{attempt}"));
        let request = stamp_modern_meta(
            &json!({"jsonrpc": "2.0", "id": id, "method": "server/discover", "params": {}}),
            &identity,
            &requested,
        );
        if let Err(error) = transport.send(&request).await {
            classify_probe_send_error(error, &requested)?;
            return Ok(None);
        }
        let answer = match answer_to(events, &id).await {
            Ok(answer) => answer,
            Err(Unanswered::Closed) => {
                return Err(TransportError::Other(
                    "Version negotiation probe failed: Connection closed during the version negotiation probe"
                        .to_owned(),
                ));
            }
            Err(Unanswered::TimedOut) => {
                return Err(TransportError::Other(format!(
                    "Version negotiation probe timed out after {}ms",
                    PROBE_TIMEOUT.as_millis()
                )));
            }
        };
        match classify_probe_response(&answer, &requested) {
            ProbeVerdict::Modern { version, .. } => return Ok(Some(version)),
            ProbeVerdict::Legacy => return Ok(None),
            ProbeVerdict::Error(message) => return Err(TransportError::Other(message)),
            ProbeVerdict::Corrective { version } => {
                if corrective_used {
                    return Err(TransportError::Other(format!(
                        "MCP error -32022: Unsupported protocol version: {requested}"
                    )));
                }
                corrective_used = true;
                requested = version;
            }
        }
    }
    unreachable!()
}

static PROBE_CLIENT_INFO: std::sync::LazyLock<Value> =
    std::sync::LazyLock::new(|| json!({"name": "mcp-remote-fallback-test", "version": "0.0.0"}));

/// The SDK `Client.connect` the throwaway probe does: in protocol mode `auto`, `server/discover`
/// first, which settles a modern server; otherwise `initialize`, then
/// `notifications/initialized`.
async fn probe_initialize(
    transport: &StreamableHttpClientTransport,
    events: &mut UnboundedReceiver<TransportEvent>,
    protocol_mode: ProtocolMode,
) -> Result<(), TransportError> {
    if protocol_mode == ProtocolMode::Auto
        && let Some(version) = negotiate_probe_era(transport, events).await?
    {
        transport.set_protocol_version(Some(version));
        return Ok(());
    }
    let request = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": PROBE_CLIENT_INFO.clone(),
        },
    });
    transport.send(&request).await?;
    let answer = answer_to(events, &json!(0))
        .await
        .map_err(|unanswered| match unanswered {
            Unanswered::Closed => TransportError::Other("Connection closed".to_owned()),
            Unanswered::TimedOut => TransportError::Other("Request timed out".to_owned()),
        })?;

    if let Some(error) = answer.get("error") {
        return Err(TransportError::Other(format!(
            "MCP error {}: {}",
            error.get("code").unwrap_or(&Value::Null),
            error.get("message").and_then(Value::as_str).unwrap_or("")
        )));
    }
    let version = answer
        .pointer("/result/protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&version) {
        return Err(TransportError::Other(format!(
            "Server's protocol version is not supported: {version}"
        )));
    }
    transport.set_protocol_version(Some(version.to_owned()));
    transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
}

fn http_transport(
    url: &Url,
    auth: &dyn RemoteAuth,
    headers: &[(String, String)],
) -> (
    StreamableHttpClientTransport,
    UnboundedReceiver<TransportEvent>,
) {
    StreamableHttpClientTransport::new(
        url.clone(),
        StreamableHttpOptions {
            headers: headers.to_vec(),
            oauth: Some(auth.transport_oauth()),
            fetch: Some(fetch_with_mcp_headers(None)),
            ..StreamableHttpOptions::default()
        },
    )
}

/// One connection attempt. A failure carries the transport that received the challenge, so the
/// code can be redeemed on the transport that stored its resource_metadata URL.
async fn attempt(
    url: &Url,
    auth: &dyn RemoteAuth,
    headers: &[(String, String)],
    strategy: TransportStrategy,
    protocol_mode: ProtocolMode,
) -> Result<RemoteConnection, (TransportError, Option<RemoteTransport>)> {
    let sse_transport = matches!(
        strategy,
        TransportStrategy::SseOnly | TransportStrategy::SseFirst
    );
    debug_log(
        "Attempting to connect to remote server",
        &[json!({"sseTransport": sse_transport})],
    );
    let on_stream_reconnect: StreamReconnectHook = Arc::default();
    if sse_transport {
        let (transport, events) = SseClientTransport::new(
            url.clone(),
            SseClientOptions {
                headers: headers.to_vec(),
                oauth: Some(auth.transport_oauth()),
                fetch: Some(fetch_with_mcp_headers(None)),
                event_source_fetch: Some(event_source_fetch(Arc::clone(&on_stream_reconnect))),
                ..SseClientOptions::default()
            },
        );
        debug_log("Starting transport directly", &[]);
        // The SSE transport signs in from start(), so it is the one a 401 lands on. Closing it
        // stops the EventSource reconnecting; finish_auth needs no stream.
        if let Err(error) = transport.start().await {
            transport.close();
            return Err((error, Some(RemoteTransport::Sse(transport))));
        }
        log("Connected to remote server using SSEClientTransport", &[]);
        return Ok(RemoteConnection {
            transport: RemoteTransport::Sse(transport),
            events,
            on_stream_reconnect,
        });
    }

    let (transport, events) = http_transport(url, auth, headers);
    debug_log("Starting transport directly", &[]);
    transport.start().map_err(|error| (error, None))?;

    // transport.start() sends nothing, so a one-off client makes the first request and finds
    // out whether an HTTP server is there at all. Its transport is the one a 401 lands on.
    debug_log("Creating test transport for HTTP-only connection test", &[]);
    let (probe, mut probe_events) = http_transport(url, auth, headers);
    let probed = match probe.start() {
        Ok(()) => probe_initialize(&probe, &mut probe_events, protocol_mode).await,
        Err(error) => Err(error),
    };
    if let Err(error) = probed {
        transport.close();
        return Err((error, Some(RemoteTransport::Http(probe))));
    }
    probe.close();

    log(
        "Connected to remote server using StreamableHTTPClientTransport",
        &[],
    );
    Ok(RemoteConnection {
        transport: RemoteTransport::Http(transport),
        events,
        on_stream_reconnect,
    })
}

/// Creates and connects the remote transport, signing in when the server asks for it.
pub async fn connect_to_remote_server(
    auth: &dyn RemoteAuth,
    auth_initializer: &AuthInitializer,
    options: &ConnectOptions,
) -> Result<RemoteConnection, TransportError> {
    let mut reasons: HashSet<&'static str> = HashSet::new();
    let mut strategy = options.transport_strategy;
    loop {
        log(
            &format!(
                "[{}] Connecting to remote server: {}",
                std::process::id(),
                options.server_url
            ),
            &[],
        );
        let url = Url::parse(&options.server_url)
            .map_err(|error| TransportError::Other(format!("Invalid URL: {error}")))?;
        log(
            &format!("Using transport strategy: {}", strategy.as_str()),
            &[],
        );
        let should_attempt_fallback = matches!(
            strategy,
            TransportStrategy::HttpFirst | TransportStrategy::SseFirst
        );

        let (error, challenge_transport) = match attempt(
            &url,
            auth,
            &options.headers,
            strategy,
            options.protocol_mode,
        )
        .await
        {
            Ok(connection) => return Ok(connection),
            Err(failure) => failure,
        };

        if should_attempt_fallback && should_fall_back_on(&error) {
            let status = match &error {
                TransportError::Http { status, .. } => status.to_string(),
                _ => "unknown".to_owned(),
            };
            log(&format!("Received error (status {status}): {error}"), &[]);
            if reasons.contains(REASON_TRANSPORT_FALLBACK) {
                let message = "Already attempted transport fallback. Giving up.";
                log(message, &[]);
                return Err(TransportError::Other(message.to_owned()));
            }
            log(
                &format!("Recursively reconnecting for reason: {REASON_TRANSPORT_FALLBACK}"),
                &[],
            );
            reasons.insert(REASON_TRANSPORT_FALLBACK);
            strategy = match strategy {
                TransportStrategy::SseOnly | TransportStrategy::SseFirst => {
                    TransportStrategy::HttpOnly
                }
                _ => TransportStrategy::SseOnly,
            };
            continue;
        }

        if is_rejected_after_authorizing(&error) {
            if reasons.contains(REASON_REJECTED_TOKEN) {
                log(
                    "The server rejected a freshly issued token as well. Giving up.",
                    &[],
                );
                return Err(error);
            }
            log(
                "The server rejected a token it had just issued - discarding it and signing in again",
                &[],
            );
            debug_log(
                "Rejected token after a successful authorization",
                &[json!({"message": error.to_string()})],
            );
            forget_rejected_authorization(auth).await;
            reasons.insert(REASON_REJECTED_TOKEN);
            continue;
        }

        if !is_unauthorized(&error) {
            log("Connection error:", &[Value::String(error.to_string())]);
            debug_log(
                "Connection error",
                &[json!({
                    "errorMessage": error.to_string(),
                    "transportType": if matches!(
                        strategy,
                        TransportStrategy::SseOnly | TransportStrategy::SseFirst
                    ) {
                        "SSEClientTransport"
                    } else {
                        "StreamableHTTPClientTransport"
                    },
                })],
            );
            return Err(error);
        }

        log("Authentication required. Initializing auth...", &[]);
        debug_log(
            "Authentication error detected",
            &[json!({"errorMessage": error.to_string()})],
        );
        let give_up_if_already_retried = |reasons: &HashSet<&str>| {
            if !reasons.contains(REASON_AUTH_NEEDED) {
                return Ok(());
            }
            let message = format!(
                "Already attempted reconnection for reason: {REASON_AUTH_NEEDED}. Giving up."
            );
            log(&message, &[]);
            debug_log(
                "Already attempted auth reconnection, giving up",
                &[json!({"recursionReasons": reasons.iter().collect::<Vec<_>>()})],
            );
            Err(TransportError::Other(message))
        };

        // The SDK's redirect step already ran a non-interactive grant to completion.
        if options.non_interactive_flow {
            log(
                "Signed in without a browser - reconnecting with the tokens it produced",
                &[],
            );
            give_up_if_already_retried(&reasons)?;
            reasons.insert(REASON_AUTH_NEEDED);
            continue;
        }

        debug_log("Calling authInitializer to start auth flow", &[]);
        let handover_already_tried = reasons.contains(REASON_SIBLING_TOKENS);
        let initialization = auth_initializer(handover_already_tried)
            .await
            .map_err(TransportError::Other)?;

        if initialization.skip_browser_auth {
            if handover_already_tried {
                log(
                    "Another instance owns the sign-in, and the tokens it wrote were refused; giving up",
                    &[],
                );
                return Err(TransportError::Other(
                    "Another instance completed the sign-in, but the remote server refused the tokens it wrote"
                        .to_owned(),
                ));
            }
            log(
                "Authentication was completed by another instance - reconnecting with the tokens it wrote",
                &[],
            );
            reasons.insert(REASON_SIBLING_TOKENS);
            debug_log(
                "Recursively reconnecting using a sibling instance tokens",
                &[json!({"recursionReasons": reasons.iter().collect::<Vec<_>>()})],
            );
            continue;
        }

        log("Authentication required. Waiting for authorization...", &[]);
        debug_log("Waiting for auth code from callback server", &[]);
        let code = (initialization.wait_for_auth_code)()
            .await
            .map_err(TransportError::Other)?;
        debug_log("Received auth code from callback server", &[]);

        // The code may belong to a flow another instance started, whose verifier is not this one's
        if let Some(state) = &code.state {
            auth.use_authorization_state(state);
        }

        // Before the exchange: a code is single-use, and the callback server hands the same one
        // back on a second call.
        give_up_if_already_retried(&reasons)?;

        log("Completing authorization...", &[]);
        let Some(challenge_transport) = challenge_transport else {
            return Err(error);
        };
        if let Err(auth_error) = challenge_transport
            .finish_auth(&code.code, code.iss.as_deref())
            .await
        {
            log(
                "Authorization error:",
                &[Value::String(auth_error.to_string())],
            );
            debug_log(
                "Authorization error during finishAuth",
                &[json!({"errorMessage": auth_error.to_string()})],
            );
            return Err(auth_error);
        }
        debug_log("Authorization completed successfully", &[]);
        reasons.insert(REASON_AUTH_NEEDED);
        log(
            &format!("Recursively reconnecting for reason: {REASON_AUTH_NEEDED}"),
            &[],
        );
        debug_log(
            "Recursively reconnecting after auth",
            &[json!({"recursionReasons": reasons.iter().collect::<Vec<_>>()})],
        );
    }
}
