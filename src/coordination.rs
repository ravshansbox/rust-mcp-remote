use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::sync::{Mutex, OnceCell};

use crate::callback_server::{
    AuthCodeResult, AuthEvents, CallbackServerError, MCP_REMOTE_ID_PATH, OAuthCallbackServer,
    OAuthCallbackServerOptions, setup_oauth_callback_server_with_long_poll,
};
use crate::logging::{debug_log, log};
use crate::mcp_auth_config::read_json_file;

pub const FOLLOWER_PATIENCE_MS: u64 = 3 * 60_000;
pub const REFRESH_FOLLOWER_PATIENCE_MS: u64 = 10_000;
pub const FOLLOWER_POLL_INTERVAL_MS: u64 = 250;
pub const TOKEN_EXPIRY_MARGIN_MS: u64 = 60_000;

pub const PORT_CANDIDATES: u16 = 8;

pub fn callback_port_candidates(callback_port: u16, strict_port: bool) -> Vec<u16> {
    if strict_port {
        return vec![callback_port];
    }
    (0..PORT_CANDIDATES)
        .filter_map(|offset| callback_port.checked_add(offset))
        .collect()
}

pub fn no_free_callback_port_message(candidates: &[u16]) -> String {
    let first = candidates.first().copied().unwrap_or_default();
    let last = candidates.last().copied().unwrap_or_default();
    format!(
        "Could not find a free callback port for this server (tried {first}-{last}). Close whatever is holding those ports, or pass a port as the second argument to choose one."
    )
}

fn coerce_number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

pub fn has_usable_tokens_at(server_url_hash: &str, now_ms: u64) -> bool {
    let Some(tokens) = read_json_file::<Value>(server_url_hash, "tokens.json") else {
        return false;
    };
    if !tokens.get("access_token").is_some_and(Value::is_string)
        || !tokens.get("token_type").is_some_and(Value::is_string)
    {
        return false;
    }
    let expires_at = tokens.get("expires_at").and_then(coerce_number);
    if let Some(expires_at) = expires_at.filter(|expires_at| *expires_at != 0.0)
        && now_ms as f64 >= expires_at - TOKEN_EXPIRY_MARGIN_MS as f64
    {
        return tokens
            .get("refresh_token")
            .and_then(Value::as_str)
            .is_some_and(|refresh_token| !refresh_token.is_empty());
    }
    true
}

pub fn has_usable_tokens(server_url_hash: &str) -> bool {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default();
    has_usable_tokens_at(server_url_hash, now_ms)
}

/// Why coordinating the sign-in failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinationError {
    /// Binding the callback server failed in a way that is not ours to step over (code
    /// EADDRINUSE or EACCES with a pinned port, or anything else).
    CallbackServer(CallbackServerError),
    /// Every candidate port was held by strangers (no_free_callback_port_message).
    NoFreePort(String),
}

impl std::fmt::Display for CoordinationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CallbackServer(error) => error.fmt(f),
            Self::NoFreePort(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CoordinationError {}

/// The outcome of coordinateAuth: either this instance owns the callback server and runs the
/// browser flow, or it follows another instance and owns no server (TS `unownedFlow`).
pub struct CoordinatedAuth {
    /// None for a follower; TS hands it a throwaway server on a random port instead.
    pub server: Option<OAuthCallbackServer>,
    pub actual_port: u16,
    pub skip_browser_auth: bool,
}

impl CoordinatedAuth {
    fn unowned(port: u16) -> Self {
        Self {
            server: None,
            actual_port: port,
            skip_browser_auth: true,
        }
    }

    /// Waits for a code on the owned callback server. A follower fails immediately rather than
    /// waiting for a code it is never going to receive.
    pub fn wait_for_auth_code(
        &self,
    ) -> impl Future<Output = Result<AuthCodeResult, String>> + Send + 'static {
        let pending = self
            .server
            .as_ref()
            .map(|server| server.wait_for_auth_code());
        async move {
            match pending {
                Some(pending) => pending.await,
                None => Err("This instance does not own the sign-in; it cannot receive an authorization code".to_owned()),
            }
        }
    }

    pub fn close(&self) {
        if let Some(server) = &self.server {
            server.close();
        }
    }

    /// Closes the callback server and waits until its port is free again.
    pub async fn shutdown(&self) {
        if let Some(server) = &self.server {
            server.shutdown().await;
        }
    }
}

/// Talks to loopback directly: a proxy configured for the process must not see the identity
/// probe, or every sibling is mistaken for a stranger.
fn loopback_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap_or_default()
    })
}

/// Asks whoever holds a port whether they are an mcp-remote serving this same server.
pub async fn port_held_by_sibling_for(port: u16, server_url_hash: &str) -> bool {
    let client = loopback_client();
    let probe = async {
        let response = client
            .get(format!("http://127.0.0.1:{port}{MCP_REMOTE_ID_PATH}"))
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        response.json::<Value>().await.ok()
    };
    // No answer, or not something that speaks our identity route
    let Ok(Some(body)) = tokio::time::timeout(Duration::from_millis(1000), probe).await else {
        return false;
    };
    body.get("mcpRemote") == Some(&Value::Bool(true))
        && body.get("serverUrlHash").and_then(Value::as_str) == Some(server_url_hash)
}

/// Whether the server answers an unauthenticated GET with a 401 challenge. Unreachable or too
/// slow to say counts as no, leaving it to the 401 handler.
pub async fn server_issues_auth_challenge(server_url: &str, headers: &[(String, String)]) -> bool {
    let mut request = crate::streamable_http::redirect_following_client().get(server_url);
    for (name, value) in headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let request = request
        .header("accept", "application/json, text/event-stream")
        .timeout(Duration::from_millis(5000));
    match crate::streamable_http::within_headers_timeout(request.send()).await {
        Ok(response) => {
            let status = response.status().as_u16();
            debug_log(
                "Probed the server for an auth challenge",
                &[json!({ "status": status })],
            );
            status == 401
        }
        Err(error) => {
            debug_log(
                "Could not probe the server for an auth challenge",
                &[json!(error.to_string())],
            );
            false
        }
    }
}

async fn bind_callback_server(
    port: u16,
    callback_path: &str,
    events: &AuthEvents,
    auth_timeout_ms: u64,
    server_url_hash: &str,
) -> Result<OAuthCallbackServer, CallbackServerError> {
    setup_oauth_callback_server_with_long_poll(OAuthCallbackServerOptions {
        port,
        path: callback_path.to_owned(),
        events: events.clone(),
        auth_timeout_ms: Some(auth_timeout_ms),
        server_url_hash: server_url_hash.to_owned(),
    })
    .await
}

/// Takes ownership of a server's OAuth flow by binding its callback port, or waits for whoever
/// has it. The lowest bound candidate wins.
pub async fn coordinate_auth(
    server_url_hash: &str,
    callback_path: &str,
    callback_port: u16,
    events: &AuthEvents,
    auth_timeout_ms: u64,
    strict_port: bool,
    follower_patience_ms: u64,
) -> Result<CoordinatedAuth, CoordinationError> {
    debug_log(
        "Coordinating authentication",
        &[
            json!({ "serverUrlHash": server_url_hash, "callbackPath": callback_path, "callbackPort": callback_port }),
        ],
    );
    let candidates = callback_port_candidates(callback_port, strict_port);

    for &port in &candidates {
        match bind_callback_server(
            port,
            callback_path,
            events,
            auth_timeout_ms,
            server_url_hash,
        )
        .await
        {
            Ok(server) => {
                // Instances pushed past a stranger can race onto different candidates and each
                // conclude it won, so a later candidate yields to a sibling on an earlier one.
                if let Some(established) =
                    first_sibling_before(&candidates, port, server_url_hash).await
                {
                    debug_log(
                        "Yielding to a sibling established on an earlier candidate",
                        &[json!({ "ours": server.actual_port, "theirs": established })],
                    );
                    server.shutdown().await;
                    return follow_until_tokens_or_port(
                        server_url_hash,
                        callback_path,
                        established,
                        events,
                        auth_timeout_ms,
                        follower_patience_ms,
                    )
                    .await;
                }
                log(
                    &format!(
                        "This instance is running the sign-in for this server (callback port {})",
                        server.actual_port
                    ),
                    &[],
                );
                return Ok(CoordinatedAuth {
                    actual_port: server.actual_port,
                    server: Some(server),
                    skip_browser_auth: false,
                });
            }
            Err(error @ CallbackServerError::PermissionDenied { .. }) => {
                // Reserved by the OS rather than held by anyone we can talk to
                debug_log(
                    &format!("Not permitted to bind port {port}"),
                    &[json!({ "serverUrlHash": server_url_hash })],
                );
                if strict_port {
                    return Err(CoordinationError::CallbackServer(error));
                }
            }
            Err(error @ CallbackServerError::AddrInUse { .. }) => {
                if port_held_by_sibling_for(port, server_url_hash).await {
                    log(
                        &format!(
                            "Another instance is running the sign-in for this server on port {port}"
                        ),
                        &[],
                    );
                    return follow_until_tokens_or_port(
                        server_url_hash,
                        callback_path,
                        port,
                        events,
                        auth_timeout_ms,
                        follower_patience_ms,
                    )
                    .await;
                }
                // Somebody else's process. Ours is not there to be waited for, so keep looking.
                debug_log(
                    &format!("Port {port} is held by an unrelated process"),
                    &[json!({ "serverUrlHash": server_url_hash })],
                );
                if strict_port {
                    return Err(CoordinationError::CallbackServer(error));
                }
            }
            Err(error) => return Err(CoordinationError::CallbackServer(error)),
        }
    }

    Err(CoordinationError::NoFreePort(
        no_free_callback_port_message(&candidates),
    ))
}

/// The earliest candidate before `port` that a sibling has taken, if any. One-directional, so
/// two instances never both stand down for each other.
async fn first_sibling_before(candidates: &[u16], port: u16, server_url_hash: &str) -> Option<u16> {
    for &candidate in candidates {
        if candidate == port {
            return None;
        }
        if port_held_by_sibling_for(candidate, server_url_hash).await {
            return Some(candidate);
        }
    }
    None
}

/// Waits for the instance that owns the flow: tokens appearing mean it finished, the port
/// becoming bindable means it died and this instance takes over.
async fn follow_until_tokens_or_port(
    server_url_hash: &str,
    callback_path: &str,
    port: u16,
    events: &AuthEvents,
    auth_timeout_ms: u64,
    follower_patience_ms: u64,
) -> Result<CoordinatedAuth, CoordinationError> {
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(auth_timeout_ms.max(follower_patience_ms));

    while tokio::time::Instant::now() < deadline {
        if has_usable_tokens(server_url_hash) {
            log(
                "The sign-in was completed by another instance; using the tokens it wrote",
                &[],
            );
            // The port it would have used, not a throwaway one: a changed port makes callers
            // re-register the client
            return Ok(CoordinatedAuth::unowned(port));
        }

        match bind_callback_server(
            port,
            callback_path,
            events,
            auth_timeout_ms,
            server_url_hash,
        )
        .await
        {
            Ok(server) => {
                log(
                    &format!(
                        "The instance running the sign-in exited; taking it over on port {}",
                        server.actual_port
                    ),
                    &[],
                );
                return Ok(CoordinatedAuth {
                    actual_port: server.actual_port,
                    server: Some(server),
                    skip_browser_auth: false,
                });
            }
            Err(CallbackServerError::AddrInUse { .. }) => {}
            Err(error) => return Err(CoordinationError::CallbackServer(error)),
        }

        tokio::time::sleep(Duration::from_millis(FOLLOWER_POLL_INTERVAL_MS)).await;
    }

    // Connecting unaided may still work, and is always better than exiting
    log(
        &format!(
            "Gave up waiting for another instance on port {port}; continuing without owning the sign-in"
        ),
        &[],
    );
    Ok(CoordinatedAuth::unowned(port))
}

type AuthState = Arc<OnceCell<Result<Arc<CoordinatedAuth>, CoordinationError>>>;

/// Starts coordinating only when a sign-in is first needed. Concurrent callers share the one
/// in-flight attempt; a failed attempt is not cached.
pub struct LazyAuthCoordinator {
    server_url_hash: String,
    callback_path: String,
    callback_port: u16,
    events: AuthEvents,
    auth_timeout_ms: u64,
    strict_port: bool,
    state: Mutex<Option<AuthState>>,
}

pub fn create_lazy_auth_coordinator(
    server_url_hash: &str,
    callback_path: &str,
    callback_port: u16,
    events: AuthEvents,
    auth_timeout_ms: u64,
    strict_port: bool,
) -> LazyAuthCoordinator {
    LazyAuthCoordinator {
        server_url_hash: server_url_hash.to_owned(),
        callback_path: callback_path.to_owned(),
        callback_port,
        events,
        auth_timeout_ms,
        strict_port,
        state: Mutex::new(None),
    }
}

impl LazyAuthCoordinator {
    /// `force_refresh` discards a cached verdict this instance has already acted on.
    pub async fn initialize_auth(
        &self,
        force_refresh: bool,
    ) -> Result<Arc<CoordinatedAuth>, CoordinationError> {
        let mut refreshed = false;
        let mut state = self.state.lock().await;

        if force_refresh && let Some(stale) = state.take() {
            debug_log(
                "Discarding the cached auth coordination verdict and looking again",
                &[],
            );
            refreshed = true;
            // Its callback server would otherwise answer the port probe of the coordinateAuth
            // about to run, so this instance would find itself as "a sibling". Awaited so the
            // port is free before the fresh attempt binds it.
            let settled = stale
                .get_or_init(|| async {
                    Err(CoordinationError::NoFreePort("superseded".to_owned()))
                })
                .await;
            if let Ok(auth) = settled {
                auth.shutdown().await;
            }
        }

        let cell = match state.as_ref() {
            Some(cell) => {
                debug_log("Auth already initializing or initialized, reusing it", &[]);
                Arc::clone(cell)
            }
            None => {
                log("Initializing auth coordination on-demand", &[]);
                debug_log(
                    "Initializing auth coordination on-demand",
                    &[
                        json!({ "serverUrlHash": self.server_url_hash, "callbackPort": self.callback_port }),
                    ],
                );
                let cell: AuthState = Arc::new(OnceCell::new());
                *state = Some(Arc::clone(&cell));
                cell
            }
        };
        drop(state);

        let patience = if refreshed {
            REFRESH_FOLLOWER_PATIENCE_MS
        } else {
            FOLLOWER_PATIENCE_MS
        };
        let result = cell
            .get_or_init(|| async {
                coordinate_auth(
                    &self.server_url_hash,
                    &self.callback_path,
                    self.callback_port,
                    &self.events,
                    self.auth_timeout_ms,
                    self.strict_port,
                    patience,
                )
                .await
                .map(Arc::new)
            })
            .await
            .clone();

        match &result {
            Ok(auth) => debug_log(
                "Auth coordination completed",
                &[
                    json!({ "skipBrowserAuth": auth.skip_browser_auth, "actualPort": auth.actual_port }),
                ],
            ),
            Err(_) => {
                // A failed attempt must not be cached, or every later retry replays it
                let mut state = self.state.lock().await;
                if state
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &cell))
                {
                    *state = None;
                }
            }
        }
        result
    }
}
