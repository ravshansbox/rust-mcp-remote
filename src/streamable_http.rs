use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Request, Response, Url};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::auth::{
    AuthError, AuthOptions, AuthResult, OAuthClientProvider, WwwAuthenticateChallenge, auth,
    compute_scope_union, extract_www_authenticate_params, is_strict_scope_superset,
};
use crate::protocol_era::{FIRST_MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION_META_KEY};
use crate::sse::{EventSourceParser, SseItem};
use crate::stdio::TransportEvent;
use crate::utils::encode_mcp_header_value;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Sends one request, standing in for the `fetch` option the SDK transports take.
pub type FetchFn = Arc<dyn Fn(Request) -> BoxFuture<Result<Response, String>> + Send + Sync>;

/// Returns the bearer token to send, standing in for the SDK's `authProvider.token()`.
pub type TokenFn = Arc<dyn Fn() -> BoxFuture<Result<Option<String>, String>> + Send + Sync>;

const MAX_REDIRECTS: usize = 5;

/// The SDK's DEFAULT_MAX_STEP_UP_RETRIES.
const DEFAULT_MAX_STEP_UP_RETRIES: u32 = 1;

/// What the transport needs from an OAuthClientProvider: the SDK's `adaptOAuthProvider`
/// (the bearer token and the `onUnauthorized` run of `auth()`), plus the provider itself
/// for `finishAuth` and the 403 step-up.
pub trait TransportOAuth: Send + Sync {
    fn tokens(&self) -> BoxFuture<Option<Value>>;
    fn auth(&self, options: AuthOptions) -> BoxFuture<Result<AuthResult, AuthError>>;
}

impl<P: OAuthClientProvider + 'static> TransportOAuth for Arc<P> {
    fn tokens(&self) -> BoxFuture<Option<Value>> {
        let provider = Arc::clone(self);
        Box::pin(async move { OAuthClientProvider::tokens(&*provider, None).await })
    }

    fn auth(&self, options: AuthOptions) -> BoxFuture<Result<AuthResult, AuthError>> {
        let provider = Arc::clone(self);
        Box::pin(async move { auth(&*provider, &options).await })
    }
}

/// The SDK's `createFetchWithInit`: `headers` go on every request that does not set them itself.
pub fn fetch_with_headers(fetch: Option<FetchFn>, headers: &[(String, String)]) -> Option<FetchFn> {
    if headers.is_empty() {
        return fetch;
    }
    let headers = headers.to_vec();
    let fetch = fetch.unwrap_or_else(|| {
        let client = redirect_following_client();
        Arc::new(move |request| {
            let client = client.clone();
            Box::pin(async move { client.execute(request).await.map_err(fetch_error) })
        })
    });
    Some(Arc::new(move |mut request: Request| {
        for (name, value) in &headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) && !request.headers().contains_key(&name)
            {
                request.headers_mut().insert(name, value);
            }
        }
        fetch(request)
    }))
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReconnectionOptions {
    pub initial_reconnection_delay_ms: u64,
    pub max_reconnection_delay_ms: u64,
    pub reconnection_delay_grow_factor: f64,
    pub max_retries: u32,
}

impl Default for ReconnectionOptions {
    fn default() -> Self {
        Self {
            initial_reconnection_delay_ms: 1_000,
            max_reconnection_delay_ms: 30_000,
            reconnection_delay_grow_factor: 1.5,
            max_retries: 2,
        }
    }
}

#[derive(Clone, Default)]
pub struct StreamableHttpOptions {
    /// `requestInit.headers`: sent on every request, under the transport's own headers.
    pub headers: Vec<(String, String)>,
    pub fetch: Option<FetchFn>,
    /// A minimal auth provider (just `token()`): a 401 then fails with
    /// `TransportError::Unauthorized`.
    pub token: Option<TokenFn>,
    /// An OAuthClientProvider: a 401 runs `auth()` and retries once, a 403
    /// `insufficient_scope` steps the scope up, and `finish_auth` redeems a code.
    /// Takes the place of `token`.
    pub oauth: Option<Arc<dyn TransportOAuth>>,
    pub skip_issuer_metadata_validation: bool,
    pub session_id: Option<String>,
    pub protocol_version: Option<String>,
    pub reconnection: ReconnectionOptions,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportError {
    /// The SDK's UnauthorizedError.
    Unauthorized(String),
    /// The SDK's SdkHttpError.
    Http {
        status: u16,
        message: String,
    },
    /// The SDK's InsufficientScopeError: a 403 step-up with no OAuth provider to run it.
    InsufficientScope {
        required_scope: Option<String>,
        resource_metadata_url: Option<String>,
        error_description: Option<String>,
    },
    /// An error `auth()` threw while the transport ran it.
    Auth(Box<AuthError>),
    Other(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Unauthorized(message)
            | TransportError::Http { message, .. }
            | TransportError::Other(message) => formatter.write_str(message),
            TransportError::InsufficientScope { required_scope, .. } => match required_scope {
                Some(scope) => write!(formatter, "Insufficient scope: required \"{scope}\""),
                None => formatter.write_str("Insufficient scope"),
            },
            TransportError::Auth(error) => error.fmt(formatter),
        }
    }
}

impl From<AuthError> for TransportError {
    fn from(error: AuthError) -> Self {
        TransportError::Auth(Box::new(error))
    }
}

impl std::error::Error for TransportError {}

/// A client that leaves every redirect to the transport, which follows only
/// those that stay within the origin (the SDK's default 'same-origin' policy).
pub fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

/// A client that follows redirects, like Node's global fetch. Shared, because building a
/// client loads the platform's root certificates.
pub fn redirect_following_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new).clone()
}

pub fn default_fetch() -> FetchFn {
    let client = default_client();
    Arc::new(move |request| {
        let client = client.clone();
        Box::pin(async move { client.execute(request).await.map_err(fetch_error) })
    })
}

pub fn fetch_error(error: reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message = format!("{message}: {cause}");
        source = cause.source();
    }
    message
}

pub fn status_text(response: &Response) -> String {
    response
        .status()
        .canonical_reason()
        .unwrap_or_default()
        .to_owned()
}

/// The media type of a Content-Type header, without its parameters.
pub fn media_type_essence(header: Option<&str>) -> Option<String> {
    let header = header?;
    let essence = header.split(';').next().unwrap_or("").trim().to_lowercase();
    if essence.is_empty() || header.get(essence.len()..).unwrap_or("").contains(',') {
        return None;
    }
    Some(essence)
}

fn is_request(message: &Value) -> bool {
    message.get("method").is_some_and(Value::is_string)
        && message
            .get("id")
            .is_some_and(|id| id.is_string() || id.is_number())
}

fn is_response(message: &Value) -> bool {
    message.get("id").is_some()
        && (message.get("result").is_some() || message.get("error").is_some())
}

fn is_message_with_method(message: &Value, method: &str) -> bool {
    message.get("method").and_then(Value::as_str) == Some(method)
}

fn messages_of(message: &Value) -> Vec<&Value> {
    match message {
        Value::Array(messages) => messages.iter().collect(),
        message => vec![message],
    }
}

pub fn parse_jsonrpc_message(value: Value) -> Result<Value, String> {
    let is_message = value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && (value.get("method").is_some_and(Value::is_string) || is_response(&value));
    if is_message {
        Ok(value)
    } else {
        Err(format!("Invalid JSON-RPC message: {value}"))
    }
}

fn envelope_version(message: &Value) -> Option<&str> {
    if !is_request(message) {
        return None;
    }
    message
        .get("params")?
        .get("_meta")?
        .get(PROTOCOL_VERSION_META_KEY)?
        .as_str()
}

fn mcp_name_field(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        "tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId"),
        _ => None,
    }
}

pub fn set_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(name, value);
    }
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

fn merge_accept(headers: &mut HeaderMap, extra: &[&str]) {
    let mut types: Vec<String> = header_string(headers, "accept")
        .map(|accept| {
            accept
                .split(',')
                .map(|part| part.trim().to_lowercase())
                .collect()
        })
        .unwrap_or_default();
    types.extend(extra.iter().map(|value| value.to_string()));
    let mut unique: Vec<String> = Vec::new();
    for value in types {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    set_header(headers, "accept", &unique.join(", "));
}

pub fn redirect_target(url: &Url, response: &Response) -> Option<Url> {
    if ![301, 302, 303, 307, 308].contains(&response.status().as_u16()) {
        return None;
    }
    let location = response.headers().get("location")?.to_str().ok()?;
    if location.is_empty() {
        return None;
    }
    url.join(location).ok()
}

pub fn is_within_origin(from: &Url, to: &Url) -> bool {
    if from.scheme() == to.scheme() && from.host_str() == to.host_str() && from.port() == to.port()
    {
        return true;
    }
    from.scheme() == "http"
        && to.scheme() == "https"
        && from.host_str() == to.host_str()
        && from.port().is_none()
        && to.port().is_none()
}

/// The SDK's `fetchWithinOrigin`: sends a request, following only redirects that keep the
/// method and stay within the origin. `closed` aborts it, as the transport's signal does.
pub async fn fetch_within_origin(
    fetch: &FetchFn,
    url: &Url,
    method: Method,
    headers: HeaderMap,
    body: Option<String>,
    closed: &AtomicBool,
) -> Result<Response, TransportError> {
    let mut current = url.clone();
    let mut followed = 0;
    loop {
        let mut request = Request::new(method.clone(), current.clone());
        *request.headers_mut() = headers.clone();
        if let Some(body) = &body {
            *request.body_mut() = Some(body.clone().into());
        }
        if closed.load(Ordering::SeqCst) {
            return Err(TransportError::Other(
                "This operation was aborted".to_owned(),
            ));
        }
        let response = fetch(request).await.map_err(TransportError::Other)?;
        let Some(target) = redirect_target(&current, &response) else {
            return Ok(response);
        };
        if followed == MAX_REDIRECTS {
            return Ok(response);
        }
        let keeps_method = method == Method::GET || matches!(response.status().as_u16(), 307 | 308);
        let keeps_userinfo = (target.username().is_empty() && target.password().is_none())
            || (target.username() == current.username() && target.password() == current.password());
        if !keeps_method || !keeps_userinfo || !is_within_origin(&current, &target) {
            return Ok(response);
        }
        let _ = response.bytes().await;
        current = target;
        followed += 1;
    }
}

/// Error text for a redirect that was not followed, or None for any other response.
pub fn unfollowed_redirect(url: &Url, response: &Response) -> Option<String> {
    let mut target = redirect_target(url, response)?;
    let _ = target.set_username("");
    let _ = target.set_password(None);
    target.set_query(None);
    target.set_fragment(None);
    let text = if target.scheme() == "http" && url.scheme() == "https" {
        let _ = target.set_scheme("https");
        format!("Redirect from https to plain http not followed; try {target} as the endpoint")
    } else {
        format!(
            "Redirect to {target} not followed; use that URL as the endpoint if it is the intended server"
        )
    };
    Some(format!("{text} (redirectPolicy: 'same-origin')"))
}

struct StreamOptions {
    resumption_token: Option<String>,
    replay_message_id: Option<Value>,
}

struct Inner {
    url: Url,
    headers: Vec<(String, String)>,
    fetch: FetchFn,
    token: Option<TokenFn>,
    oauth: Option<Arc<dyn TransportOAuth>>,
    /// `_fetchWithInit`: the fetch `auth()` runs with.
    auth_fetch: Option<FetchFn>,
    skip_issuer_metadata_validation: bool,
    resource_metadata_url: Mutex<Option<Url>>,
    scope: Mutex<Option<String>>,
    max_step_up_retries: u32,
    session_id: Mutex<Option<String>>,
    protocol_version: Mutex<Option<String>>,
    server_retry_ms: Mutex<Option<u64>>,
    reconnection: ReconnectionOptions,
    events: mpsc::UnboundedSender<TransportEvent>,
    started: AtomicBool,
    closed: AtomicBool,
    tasks: Mutex<Vec<AbortHandle>>,
}

/// Client transport for Streamable HTTP, ported from the SDK v2
/// StreamableHTTPClientTransport: messages go out as POSTs, and responses come
/// back as JSON or as an SSE stream; a standalone GET stream opens after the
/// `notifications/initialized` POST.
///
/// Not yet ported: the `(URLSearchParams)` form of `finishAuth`, DPoP, per-request send options (resumption tokens, request signals, extra
/// headers) and a custom reconnection scheduler.
#[derive(Clone)]
pub struct StreamableHttpClientTransport {
    inner: Arc<Inner>,
}

impl StreamableHttpClientTransport {
    pub fn new(
        url: Url,
        options: StreamableHttpOptions,
    ) -> (Self, mpsc::UnboundedReceiver<TransportEvent>) {
        let (events, receiver) = mpsc::unbounded_channel();
        let auth_fetch = fetch_with_headers(options.fetch.clone(), &options.headers);
        let inner = Inner {
            url,
            headers: options.headers,
            fetch: options.fetch.unwrap_or_else(default_fetch),
            token: options.token,
            oauth: options.oauth,
            auth_fetch,
            skip_issuer_metadata_validation: options.skip_issuer_metadata_validation,
            resource_metadata_url: Mutex::new(None),
            scope: Mutex::new(None),
            max_step_up_retries: DEFAULT_MAX_STEP_UP_RETRIES,
            session_id: Mutex::new(options.session_id),
            protocol_version: Mutex::new(options.protocol_version),
            server_retry_ms: Mutex::new(None),
            reconnection: options.reconnection,
            events,
            started: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
        };
        (
            Self {
                inner: Arc::new(inner),
            },
            receiver,
        )
    }

    pub fn start(&self) -> Result<(), TransportError> {
        if self.inner.started.swap(true, Ordering::SeqCst) {
            return Err(TransportError::Other(
                "StreamableHTTPClientTransport already started! If using Client class, note that connect() calls start() automatically."
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Ok(mut tasks) = self.inner.tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
        let _ = self.inner.events.send(TransportEvent::Close);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub fn session_id(&self) -> Option<String> {
        self.inner.session_id.lock().ok()?.clone()
    }

    pub fn set_protocol_version(&self, version: Option<String>) {
        if let Ok(mut slot) = self.inner.protocol_version.lock() {
            *slot = version;
        }
    }

    pub fn protocol_version(&self) -> Option<String> {
        self.inner.protocol_version.lock().ok()?.clone()
    }

    /// Redeems the authorization code a sign-in brought back, the SDK's `finishAuth(code, iss)`.
    pub async fn finish_auth(&self, code: &str, iss: Option<&str>) -> Result<(), TransportError> {
        let Some(oauth) = &self.inner.oauth else {
            return Err(TransportError::Unauthorized(
                "finishAuth requires an OAuthClientProvider".to_owned(),
            ));
        };
        let mut options = self.inner.auth_options();
        options.authorization_code = Some(code.to_owned());
        options.iss = iss.map(str::to_owned);
        options.scope = self.inner.scope.lock().ok().and_then(|slot| slot.clone());
        if oauth.auth(options).await? != AuthResult::Authorized {
            return Err(TransportError::Unauthorized(
                "Failed to authorize".to_owned(),
            ));
        }
        Ok(())
    }

    pub async fn send(&self, message: &Value) -> Result<(), TransportError> {
        let result = Arc::clone(&self.inner)
            .send(message.clone(), false, 0)
            .await;
        if let Err(error) = &result {
            self.inner.emit_error(error.to_string());
        }
        result
    }

    /// Opens a GET stream that replays the events after `last_event_id`.
    pub async fn resume_stream(&self, last_event_id: &str) -> Result<(), TransportError> {
        Arc::clone(&self.inner)
            .start_or_auth_sse(
                StreamOptions {
                    resumption_token: Some(last_event_id.to_owned()),
                    replay_message_id: None,
                },
                false,
                0,
            )
            .await
    }

    /// Ends the session with a DELETE, as the spec asks of a client that is done with it.
    pub async fn terminate_session(&self) -> Result<(), TransportError> {
        if self.session_id().is_none() {
            return Ok(());
        }
        let result = async {
            let headers = self.inner.common_headers().await?;
            let response = self
                .inner
                .fetch_within_origin(Method::DELETE, headers, None)
                .await?;
            let status = response.status();
            let reason = unfollowed_redirect(&self.inner.url, &response)
                .unwrap_or_else(|| status_text(&response));
            let _ = response.bytes().await;
            if !status.is_success() && status.as_u16() != 405 {
                return Err(TransportError::Http {
                    status: status.as_u16(),
                    message: format!("Failed to terminate session: {reason}"),
                });
            }
            if let Ok(mut session_id) = self.inner.session_id.lock() {
                *session_id = None;
            }
            Ok(())
        }
        .await;
        if let Err(error) = &result {
            self.inner.emit_error(error.to_string());
        }
        result
    }
}

impl Inner {
    fn emit(&self, event: TransportEvent) {
        let _ = self.events.send(event);
    }

    fn emit_error(&self, message: String) {
        if !self.closed.load(Ordering::SeqCst) {
            self.emit(TransportEvent::Error(message));
        }
    }

    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let handle = tokio::spawn(task);
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.retain(|task| !task.is_finished());
            tasks.push(handle.abort_handle());
        }
        if self.closed.load(Ordering::SeqCst) {
            handle.abort();
        }
    }

    async fn common_headers(&self) -> Result<HeaderMap, TransportError> {
        let mut headers = HeaderMap::new();
        for (name, value) in &self.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.append(name, value);
            }
        }
        let token = if let Some(oauth) = &self.oauth {
            oauth.tokens().await.and_then(|tokens| {
                tokens
                    .get("access_token")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
        } else if let Some(token_fn) = &self.token {
            token_fn().await.map_err(TransportError::Other)?
        } else {
            None
        };
        {
            if let Some(token) = token.filter(|token| !token.is_empty()) {
                set_header(&mut headers, "authorization", &format!("Bearer {token}"));
            }
        }
        if let Some(session_id) = self.session_id.lock().ok().and_then(|slot| slot.clone()) {
            set_header(&mut headers, "mcp-session-id", &session_id);
        }
        if let Some(version) = self
            .protocol_version
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
        {
            set_header(&mut headers, "mcp-protocol-version", &version);
        }
        Ok(headers)
    }

    /// Sends a request, following only redirects that keep the method and stay within the origin.
    async fn fetch_within_origin(
        &self,
        method: Method,
        headers: HeaderMap,
        body: Option<String>,
    ) -> Result<Response, TransportError> {
        fetch_within_origin(&self.fetch, &self.url, method, headers, body, &self.closed).await
    }

    fn unauthorized(&self, is_auth_retry: bool) -> TransportError {
        if is_auth_retry {
            TransportError::Http {
                status: 401,
                message: "Server returned 401 after re-authentication".to_owned(),
            }
        } else {
            TransportError::Unauthorized("Unauthorized".to_owned())
        }
    }

    fn has_auth_provider(&self) -> bool {
        self.oauth.is_some() || self.token.is_some()
    }

    fn auth_options(&self) -> AuthOptions {
        let mut options = AuthOptions::new(self.url.clone());
        options.resource_metadata_url = self
            .resource_metadata_url
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        options.fetch = self.auth_fetch.clone();
        options.skip_issuer_metadata_validation = self.skip_issuer_metadata_validation;
        options
    }

    /// Records what a 401's challenge says; `union` adds its scope to the earlier ones
    /// instead of replacing them.
    fn record_challenge(&self, response: &Response, union: bool) {
        let Some(header) = response.headers().get("www-authenticate") else {
            return;
        };
        let challenge = extract_www_authenticate_params(header.to_str().ok());
        if let Ok(mut slot) = self.resource_metadata_url.lock() {
            *slot = challenge.resource_metadata_url;
        }
        if let Ok(mut slot) = self.scope.lock() {
            *slot = if union {
                compute_scope_union(&[slot.as_deref(), challenge.scope.as_deref()])
            } else {
                challenge.scope
            };
        }
    }

    /// The SDK's `handleOAuthUnauthorized`: runs `auth()` with the 401's challenge.
    async fn on_unauthorized(
        &self,
        oauth: &Arc<dyn TransportOAuth>,
        response: &Response,
    ) -> Result<(), TransportError> {
        let challenge = extract_www_authenticate_params(
            response
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok()),
        );
        let mut options = AuthOptions::new(self.url.clone());
        options.resource_metadata_url = challenge.resource_metadata_url;
        options.scope = challenge.scope;
        options.fetch = self.auth_fetch.clone();
        options.skip_issuer_metadata_validation = self.skip_issuer_metadata_validation;
        if oauth.auth(options).await? != AuthResult::Authorized {
            return Err(TransportError::Unauthorized("Unauthorized".to_owned()));
        }
        Ok(())
    }

    /// The SDK's `_stepUpAuthorize`: widens the scope to what a 403 asks for and signs in again.
    async fn step_up_authorize(
        &self,
        challenge: WwwAuthenticateChallenge,
        step_up_retries: u32,
    ) -> Result<(), TransportError> {
        let Some(oauth) = &self.oauth else {
            return Err(TransportError::InsufficientScope {
                required_scope: challenge.scope,
                resource_metadata_url: challenge.resource_metadata_url.map(String::from),
                error_description: challenge.error_description,
            });
        };
        if step_up_retries >= self.max_step_up_retries {
            return Err(TransportError::Http {
                status: 403,
                message: format!(
                    "Server returned 403 insufficient_scope after step-up re-authorization (retry limit {} reached)",
                    self.max_step_up_retries
                ),
            });
        }
        if let Some(url) = challenge.resource_metadata_url
            && let Ok(mut slot) = self.resource_metadata_url.lock()
        {
            *slot = Some(url);
        }
        let granted = oauth.tokens().await.and_then(|tokens| {
            tokens
                .get("scope")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        let union = {
            let mut slot = self
                .scope
                .lock()
                .map_err(|error| TransportError::Other(error.to_string()))?;
            *slot = compute_scope_union(&[
                slot.as_deref(),
                granted.as_deref(),
                challenge.scope.as_deref(),
            ]);
            slot.clone()
        };
        let mut options = self.auth_options();
        options.force_reauthorization =
            is_strict_scope_superset(union.as_deref(), granted.as_deref());
        options.scope = union;
        if oauth.auth(options).await? != AuthResult::Authorized {
            return Err(TransportError::Unauthorized("Unauthorized".to_owned()));
        }
        Ok(())
    }

    fn send(
        self: Arc<Self>,
        message: Value,
        is_auth_retry: bool,
        step_up_retries: u32,
    ) -> BoxFuture<Result<(), TransportError>> {
        Box::pin(async move {
            self.send_once(message, is_auth_retry, step_up_retries)
                .await
        })
    }

    async fn send_once(
        self: Arc<Self>,
        message: Value,
        is_auth_retry: bool,
        step_up_retries: u32,
    ) -> Result<(), TransportError> {
        let message = &message;
        let mut headers = self.common_headers().await?;
        if let Some(version) = envelope_version(message) {
            let method = message["method"].as_str().unwrap_or_default();
            set_header(&mut headers, "mcp-protocol-version", version);
            set_header(&mut headers, "mcp-method", method);
            if let Some(name) =
                mcp_name_field(method).and_then(|field| message.get("params")?.get(field)?.as_str())
            {
                set_header(&mut headers, "mcp-name", &encode_mcp_header_value(name));
            }
        }
        let messages = messages_of(message);
        let is_handshake = messages
            .iter()
            .any(|message| is_request(message) && is_message_with_method(message, "initialize"));
        if is_handshake {
            headers.remove("mcp-session-id");
        }
        set_header(&mut headers, "content-type", "application/json");
        merge_accept(&mut headers, &["application/json", "text/event-stream"]);

        let response = self
            .fetch_within_origin(Method::POST, headers, Some(message.to_string()))
            .await?;
        let status = response.status();
        if is_handshake && status.is_success() {
            let session_id = response
                .headers()
                .get("mcp-session-id")
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            if let Ok(mut slot) = self.session_id.lock() {
                *slot = session_id;
            }
        }

        if !status.is_success() {
            if status.as_u16() == 401 && self.has_auth_provider() {
                self.record_challenge(&response, true);
                if let Some(oauth) = self.oauth.clone()
                    && !is_auth_retry
                {
                    self.on_unauthorized(&oauth, &response).await?;
                    let _ = response.bytes().await;
                    return self.send(message.clone(), true, step_up_retries).await;
                }
                let _ = response.bytes().await;
                return Err(self.unauthorized(is_auth_retry));
            }
            let redirect = unfollowed_redirect(&self.url, &response);
            let challenge = (status.as_u16() == 403).then(|| {
                extract_www_authenticate_params(
                    response
                        .headers()
                        .get("www-authenticate")
                        .and_then(|value| value.to_str().ok()),
                )
            });
            let text = response.text().await.ok();
            if let Some(challenge) = challenge
                && challenge.error.as_deref() == Some("insufficient_scope")
            {
                self.step_up_authorize(challenge, step_up_retries).await?;
                return self
                    .send(message.clone(), is_auth_retry, step_up_retries + 1)
                    .await;
            }
            if status.as_u16() == 400
                && envelope_version(message).is_some_and(|v| v >= FIRST_MODERN_PROTOCOL_VERSION)
                && let Some(parsed) = text
                    .as_deref()
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
                    .and_then(|value| parse_jsonrpc_message(value).ok())
                && parsed.get("error").is_some()
                && messages
                    .iter()
                    .any(|request| is_request(request) && request.get("id") == parsed.get("id"))
            {
                self.emit(TransportEvent::Message(parsed));
                return Ok(());
            }
            let reason = redirect.or(text).unwrap_or_else(|| "null".to_owned());
            return Err(TransportError::Http {
                status: status.as_u16(),
                message: format!("Error POSTing to endpoint: {reason}"),
            });
        }

        if status.as_u16() == 202 {
            let _ = response.bytes().await;
            if is_message_with_method(message, "notifications/initialized") {
                let inner = Arc::clone(&self);
                self.spawn(async move {
                    let _ = inner
                        .start_or_auth_sse(
                            StreamOptions {
                                resumption_token: None,
                                replay_message_id: None,
                            },
                            false,
                            0,
                        )
                        .await;
                });
            }
            return Ok(());
        }

        let has_requests = messages.iter().any(|message| is_request(message));
        if !has_requests {
            let _ = response.bytes().await;
            return Ok(());
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        match media_type_essence(content_type.as_deref()).as_deref() {
            Some("text/event-stream") => {
                Arc::clone(&self).handle_sse_stream(
                    response,
                    StreamOptions {
                        resumption_token: None,
                        replay_message_id: None,
                    },
                    false,
                );
                Ok(())
            }
            Some("application/json") => {
                let data: Value = response
                    .json()
                    .await
                    .map_err(|error| TransportError::Other(error.to_string()))?;
                let incoming = match data {
                    Value::Array(messages) => messages,
                    message => vec![message],
                };
                let parsed = incoming
                    .into_iter()
                    .map(parse_jsonrpc_message)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(TransportError::Other)?;
                for message in parsed {
                    self.emit(TransportEvent::Message(message));
                }
                Ok(())
            }
            _ => {
                let _ = response.bytes().await;
                Err(TransportError::Other(format!(
                    "Unexpected content type: {}",
                    content_type.as_deref().unwrap_or("null")
                )))
            }
        }
    }

    fn start_or_auth_sse(
        self: Arc<Self>,
        options: StreamOptions,
        is_auth_retry: bool,
        step_up_retries: u32,
    ) -> BoxFuture<Result<(), TransportError>> {
        Box::pin(async move {
            let result = async {
                let mut headers = self.common_headers().await?;
                merge_accept(&mut headers, &["text/event-stream"]);
                if let Some(token) = &options.resumption_token {
                    set_header(&mut headers, "last-event-id", token);
                }
                let response = self.fetch_within_origin(Method::GET, headers, None).await?;
                let status = response.status();
                if !status.is_success() {
                    if status.as_u16() == 401 && self.has_auth_provider() {
                        self.record_challenge(&response, true);
                        if let Some(oauth) = self.oauth.clone()
                            && !is_auth_retry
                        {
                            self.on_unauthorized(&oauth, &response).await?;
                            let _ = response.bytes().await;
                            return Arc::clone(&self)
                                .start_or_auth_sse(options, true, step_up_retries)
                                .await;
                        }
                        let _ = response.bytes().await;
                        return Err(self.unauthorized(is_auth_retry));
                    }
                    if status.as_u16() == 403 {
                        let challenge = extract_www_authenticate_params(
                            response
                                .headers()
                                .get("www-authenticate")
                                .and_then(|value| value.to_str().ok()),
                        );
                        if challenge.error.as_deref() == Some("insufficient_scope") {
                            let _ = response.bytes().await;
                            self.step_up_authorize(challenge, step_up_retries).await?;
                            return Arc::clone(&self)
                                .start_or_auth_sse(options, is_auth_retry, step_up_retries + 1)
                                .await;
                        }
                    }
                    let reason = unfollowed_redirect(&self.url, &response)
                        .unwrap_or_else(|| status_text(&response));
                    let _ = response.bytes().await;
                    if status.as_u16() == 405 {
                        return Ok(());
                    }
                    return Err(TransportError::Http {
                        status: status.as_u16(),
                        message: format!("Failed to open SSE stream: {reason}"),
                    });
                }
                Arc::clone(&self).handle_sse_stream(response, options, true);
                Ok(())
            }
            .await;
            if let Err(error) = &result {
                self.emit_error(error.to_string());
            }
            result
        })
    }

    fn reconnection_delay(&self, attempt: u32) -> u64 {
        if let Some(retry) = self.server_retry_ms.lock().ok().and_then(|slot| *slot) {
            return retry;
        }
        let options = &self.reconnection;
        let delay = options.initial_reconnection_delay_ms as f64
            * options.reconnection_delay_grow_factor.powi(attempt as i32);
        delay.min(options.max_reconnection_delay_ms as f64) as u64
    }

    fn schedule_reconnection(self: Arc<Self>, options: StreamOptions, attempt: u32) {
        let max_retries = self.reconnection.max_retries;
        if attempt >= max_retries {
            self.emit_error(format!(
                "Maximum reconnection attempts ({max_retries}) exceeded."
            ));
            return;
        }
        let delay = self.reconnection_delay(attempt);
        let inner = Arc::clone(&self);
        self.spawn(async move {
            tokio::time::sleep(Duration::from_millis(delay)).await;
            if inner.closed.load(Ordering::SeqCst) {
                return;
            }
            let retry = StreamOptions {
                resumption_token: options.resumption_token.clone(),
                replay_message_id: options.replay_message_id.clone(),
            };
            if let Err(error) = Arc::clone(&inner).start_or_auth_sse(retry, false, 0).await {
                if inner.closed.load(Ordering::SeqCst) {
                    return;
                }
                inner.emit_error(format!("Failed to reconnect SSE stream: {error}"));
                inner.schedule_reconnection(options, attempt + 1);
            }
        });
    }

    fn handle_sse_stream(
        self: Arc<Self>,
        mut response: Response,
        options: StreamOptions,
        is_reconnectable: bool,
    ) {
        let inner = Arc::clone(&self);
        self.spawn(async move {
            let mut parser = EventSourceParser::new();
            let mut last_event_id: Option<String> = None;
            let mut has_priming_event = false;
            let mut received_response = false;
            let outcome = loop {
                let chunk = match response.chunk().await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break Ok(()),
                    Err(error) => break Err(fetch_error(error)),
                };
                for item in parser.feed(&chunk) {
                    let event = match item {
                        SseItem::Event(event) => event,
                        SseItem::Retry(retry) => {
                            if let Ok(mut slot) = inner.server_retry_ms.lock() {
                                *slot = Some(retry);
                            }
                            continue;
                        }
                        SseItem::Error(_) => continue,
                    };
                    if let Some(id) = event.id.filter(|id| !id.is_empty()) {
                        last_event_id = Some(id);
                        has_priming_event = true;
                    }
                    if event.data.is_empty() {
                        continue;
                    }
                    if event.event.as_deref().is_some_and(|name| name != "message") {
                        continue;
                    }
                    let parsed = serde_json::from_str::<Value>(&event.data)
                        .map_err(|error| error.to_string())
                        .and_then(parse_jsonrpc_message);
                    match parsed {
                        Ok(mut message) => {
                            if is_response(&message) {
                                received_response = true;
                                if let Some(id) = &options.replay_message_id {
                                    message["id"] = id.clone();
                                }
                            }
                            inner.emit(TransportEvent::Message(message));
                        }
                        Err(error) => inner.emit_error(error),
                    }
                }
            };
            if inner.closed.load(Ordering::SeqCst) {
                return;
            }
            if let Err(error) = outcome {
                inner.emit_error(format!("SSE stream disconnected: {error}"));
            }
            if (is_reconnectable || has_priming_event) && !received_response {
                Arc::clone(&inner).schedule_reconnection(
                    StreamOptions {
                        resumption_token: last_event_id,
                        replay_message_id: options.replay_message_id,
                    },
                    0,
                );
            }
        });
    }
}
