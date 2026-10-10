//! The OAuth callback server (utils.ts setupOAuthCallbackServerWithLongPoll): receives the
//! authorization code from the browser, answers siblings long-polling for the sign-in to finish,
//! and answers the identity probe a losing instance uses to tell a sibling from a stranger.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot, watch};

use crate::logging::log;

/// Endpoint secondary instances long-poll to await the auth flow the primary instance is running.
pub const LONG_POLL_PATH: &str = "/wait-for-auth";
/// Lets an instance that lost the bind identify who holds the port.
pub const MCP_REMOTE_ID_PATH: &str = "/.mcp-remote/id";
const DEFAULT_LONG_POLL_TIMEOUT_MS: u64 = 30_000;

/// An authorization code, with the state identifying the flow it belongs to and the RFC 9207
/// `iss` parameter, which must reach finishAuth unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCodeResult {
    pub code: String,
    pub state: Option<String>,
    pub iss: Option<String>,
}

/// What the TS code emits on its EventEmitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthEvent {
    /// 'auth-code-received' (code, state)
    CodeReceived { code: String, state: Option<String> },
    /// 'auth-code-failed' (error message)
    CodeFailed(String),
}

/// The process-wide event emitter shared by every callback server a coordinator starts.
#[derive(Clone)]
pub struct AuthEvents {
    sender: broadcast::Sender<AuthEvent>,
}

impl Default for AuthEvents {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthEvents {
    pub fn new() -> Self {
        Self {
            sender: broadcast::channel(64).0,
        }
    }

    pub fn emit(&self, event: AuthEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuthEvent> {
        self.sender.subscribe()
    }
}

pub struct OAuthCallbackServerOptions {
    pub port: u16,
    pub path: String,
    pub events: AuthEvents,
    /// Timeout of the long poll; None or 0 means 30 seconds.
    pub auth_timeout_ms: Option<u64>,
    pub server_url_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackServerError {
    /// 'Callback port N is already in use' (code EADDRINUSE, requestedPort N)
    AddrInUse {
        requested_port: u16,
    },
    Io(String),
}

impl std::fmt::Display for CallbackServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddrInUse { requested_port } => {
                write!(f, "Callback port {requested_port} is already in use")
            }
            Self::Io(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CallbackServerError {}

#[derive(Default)]
struct CodeQueue {
    /// Codes that arrived and nobody has redeemed yet, oldest first. A queue rather than one
    /// retained code: an authorization code is single-use, so a later sign-in needs its own.
    unclaimed: VecDeque<AuthCodeResult>,
    /// Callers waiting for a code that has not arrived yet, in the order they asked.
    waiting: VecDeque<(u64, oneshot::Sender<AuthCodeResult>)>,
    next_waiter: u64,
}

struct Shared {
    options_path: String,
    server_url_hash: String,
    long_poll_timeout: Duration,
    events: AuthEvents,
    codes: Mutex<CodeQueue>,
    /// Some once any sign-in has completed here; stays set when the queue drains.
    completed: watch::Sender<Option<AuthCodeResult>>,
}

/// The running server. Dropping it (or calling close) stops accepting connections.
pub struct OAuthCallbackServer {
    pub actual_port: u16,
    shared: Arc<Shared>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl Drop for OAuthCallbackServer {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl OAuthCallbackServer {
    pub fn close(&self) {
        self.accept_task.abort();
    }

    /// The TS `authCode` field, which is always null.
    pub fn auth_code(&self) -> Option<String> {
        None
    }

    /// Takes the next unredeemed code, waiting for one if none has arrived. The waiter is
    /// registered before this returns, so a code or a denial arriving later reaches it.
    pub fn wait_for_auth_code(
        &self,
    ) -> impl std::future::Future<Output = Result<AuthCodeResult, String>> + Send + 'static {
        wait_for_auth_code(&self.shared)
    }

    /// A cloneable handle to `wait_for_auth_code`, for callers that outlive a borrow.
    pub fn code_waiter(&self) -> AuthCodeWaiter {
        AuthCodeWaiter {
            shared: Arc::clone(&self.shared),
        }
    }

    /// The TS `authCompletedPromise`: resolves with the first code this server received.
    pub async fn auth_completed(&self) -> AuthCodeResult {
        auth_completed(&self.shared).await
    }
}

#[derive(Clone)]
pub struct AuthCodeWaiter {
    shared: Arc<Shared>,
}

impl AuthCodeWaiter {
    pub fn wait_for_auth_code(
        &self,
    ) -> impl std::future::Future<Output = Result<AuthCodeResult, String>> + Send + 'static {
        wait_for_auth_code(&self.shared)
    }
}

fn wait_for_auth_code(
    shared: &Arc<Shared>,
) -> impl std::future::Future<Output = Result<AuthCodeResult, String>> + Send + 'static {
    let mut codes = shared.codes.lock().unwrap_or_else(|p| p.into_inner());
    let registered = match codes.unclaimed.pop_front() {
        Some(code) => Err(code),
        None => {
            let (sender, receiver) = oneshot::channel();
            let id = codes.next_waiter;
            codes.next_waiter += 1;
            codes.waiting.push_back((id, sender));
            // Subscribed now, as TS attaches `once('auth-code-failed')` synchronously
            Ok((id, receiver, shared.events.subscribe()))
        }
    };
    drop(codes);
    let shared = Arc::clone(shared);
    async move {
        let (id, mut receiver, mut failures) = match registered {
            Err(code) => return Ok(code),
            Ok(parts) => parts,
        };
        loop {
            tokio::select! {
                result = &mut receiver => {
                    return result.map_err(|_| "OAuth callback server closed".to_owned());
                }
                event = failures.recv() => match event {
                    Ok(AuthEvent::CodeFailed(message)) => {
                        // An authorization the user denied never produces a code
                        let mut codes = shared.codes.lock().unwrap_or_else(|p| p.into_inner());
                        codes.waiting.retain(|(waiter, _)| *waiter != id);
                        drop(codes);
                        // The code may have been handed over just before the failure arrived
                        if let Ok(code) = receiver.try_recv() {
                            return Ok(code);
                        }
                        return Err(message);
                    }
                    Ok(AuthEvent::CodeReceived { .. }) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => {
                        return receiver.await.map_err(|_| "OAuth callback server closed".to_owned());
                    }
                },
            }
        }
    }
}

async fn auth_completed(shared: &Shared) -> AuthCodeResult {
    let mut receiver = shared.completed.subscribe();
    loop {
        if let Some(code) = receiver.borrow_and_update().clone() {
            return code;
        }
        if receiver.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// Binds 127.0.0.1:port and serves the callback, long-poll and identity endpoints. There is
/// deliberately no random-port fallback: EADDRINUSE means somebody else owns this flow.
pub async fn setup_oauth_callback_server_with_long_poll(
    options: OAuthCallbackServerOptions,
) -> Result<OAuthCallbackServer, CallbackServerError> {
    let listener = TcpListener::bind(("127.0.0.1", options.port))
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AddrInUse {
                CallbackServerError::AddrInUse {
                    requested_port: options.port,
                }
            } else {
                CallbackServerError::Io(error.to_string())
            }
        })?;
    let actual_port = listener
        .local_addr()
        .map_err(|error| CallbackServerError::Io(error.to_string()))?
        .port();
    log(
        &format!("OAuth callback server running at http://127.0.0.1:{actual_port}"),
        &[],
    );
    let timeout_ms = options
        .auth_timeout_ms
        .filter(|ms| *ms != 0)
        .unwrap_or(DEFAULT_LONG_POLL_TIMEOUT_MS);
    let shared = Arc::new(Shared {
        options_path: options.path,
        server_url_hash: options.server_url_hash,
        long_poll_timeout: Duration::from_millis(timeout_ms),
        events: options.events,
        codes: Mutex::new(CodeQueue::default()),
        completed: watch::channel(None).0,
    });
    let accept_shared = Arc::clone(&shared);
    let accept_task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                // e.g. out of file descriptors; do not spin
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };
            let shared = Arc::clone(&accept_shared);
            tokio::spawn(async move { serve_connection(socket, shared).await });
        }
    });
    Ok(OAuthCallbackServer {
        actual_port,
        shared,
        accept_task,
    })
}

struct Response {
    status: u16,
    content_type: &'static str,
    body: String,
}

fn text(status: u16, body: &str) -> Response {
    Response {
        status,
        content_type: "text/html; charset=utf-8",
        body: body.to_owned(),
    }
}

async fn serve_connection(mut socket: TcpStream, shared: Arc<Shared>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let Ok(count) = socket.read(&mut chunk).await else {
            return;
        };
        if count == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..count]);
        if let Some(index) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break index;
        }
        if buffer.len() > 64 * 1024 {
            return;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut request_line = head.split("\r\n").next().unwrap_or("").split(' ');
    let method = request_line.next().unwrap_or("").to_owned();
    let target = request_line.next().unwrap_or("/").to_owned();
    let response = handle_request(&method, &target, &shared).await;
    let reason = match response.status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let mut bytes = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    if method != "HEAD" {
        bytes.push_str(&response.body);
    }
    let _ = socket.write_all(bytes.as_bytes()).await;
    let _ = socket.shutdown().await;
}

/// Express routing: case-insensitive, and a trailing slash is allowed.
fn route_matches(route: &str, path: &str) -> bool {
    let path = if path.len() > 1 {
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };
    route.eq_ignore_ascii_case(path)
}

async fn handle_request(method: &str, target: &str, shared: &Arc<Shared>) -> Response {
    let Ok(url) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
        return text(400, "Bad Request");
    };
    let path = url.path().to_owned();
    if method != "GET" && method != "HEAD" {
        return text(404, &format!("Cannot {method} {path}"));
    }
    // Express keeps the first route registered, so the long poll and probe win over the callback
    let query = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    };
    if route_matches(LONG_POLL_PATH, &path) {
        return long_poll(query("poll").as_deref() == Some("false"), shared).await;
    }
    if route_matches(MCP_REMOTE_ID_PATH, &path) {
        return Response {
            status: 200,
            content_type: "application/json; charset=utf-8",
            body: json!({"mcpRemote": true, "serverUrlHash": shared.server_url_hash}).to_string(),
        };
    }
    if route_matches(&shared.options_path, &path) {
        return callback(
            query("code"),
            query("state"),
            query("iss"),
            query("error"),
            query("error_description"),
            shared,
        );
    }
    text(404, &format!("Cannot GET {path}"))
}

async fn long_poll(no_poll: bool, shared: &Arc<Shared>) -> Response {
    if shared.completed.borrow().is_some() {
        // Secondary instances read the tokens from disk, so the code itself is not returned
        log("Auth already completed, returning 200", &[]);
        return text(200, "Authentication completed");
    }
    if no_poll {
        log("Client requested no long poll, responding with 202", &[]);
        return text(202, "Authentication in progress");
    }
    match tokio::time::timeout(shared.long_poll_timeout, auth_completed(shared)).await {
        Ok(_) => {
            log("Auth completed during long poll, responding with 200", &[]);
            text(200, "Authentication completed")
        }
        Err(_) => {
            log("Long poll timeout reached, responding with 202", &[]);
            text(202, "Authentication in progress")
        }
    }
}

fn callback(
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    shared: &Arc<Shared>,
) -> Response {
    if let Some(error) = error.filter(|error| !error.is_empty()) {
        let description = error_description.unwrap_or_else(|| error.clone());
        log(
            &format!("Authorization failed: {error} - {description}"),
            &[],
        );
        shared.events.emit(AuthEvent::CodeFailed(format!(
            "Authorization failed: {error} - {description}"
        )));
        return text(
            400,
            &format!(
                "Authorization failed: {description}\n\nYou may close this window and return to the CLI."
            ),
        );
    }
    let Some(code) = code.filter(|code| !code.is_empty()) else {
        return text(400, "Error: No authorization code received");
    };
    let received = AuthCodeResult {
        code: code.clone(),
        state: state.clone(),
        iss,
    };
    log("Auth code received, resolving promise", &[]);
    shared.completed.send_if_modified(|completed| {
        if completed.is_none() {
            *completed = Some(received.clone());
            true
        } else {
            false
        }
    });
    // Hand it straight to whoever is waiting; hold it only if nobody is yet
    let mut codes = shared.codes.lock().unwrap_or_else(|p| p.into_inner());
    let mut pending = Some(received);
    while let Some((_, waiter)) = codes.waiting.pop_front() {
        match waiter.send(pending.take().expect("code still pending")) {
            Ok(()) => break,
            // That caller gave up waiting; offer the code to the next one
            Err(code) => pending = Some(code),
        }
    }
    if let Some(code) = pending {
        codes.unclaimed.push_back(code);
    }
    drop(codes);
    shared.events.emit(AuthEvent::CodeReceived { code, state });
    Response {
        status: 200,
        content_type: "text/html; charset=utf-8",
        body: r#"
      Authorization successful!
      You may close this window and return to the CLI.
      <script>
        // If this is a non-interactive session (no manual approval step was required) then
        // this should automatically close the window. If not, this will have no effect and
        // the user will see the message above.
        window.close();
      </script>
    "#
        .to_owned(),
    }
}
