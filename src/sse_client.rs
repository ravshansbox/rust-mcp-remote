//! The SDK's (deprecated) SSEClientTransport: messages come in over a Server-Sent Events stream
//! opened with a GET, and go out as POSTs to the endpoint the stream's first `endpoint` event
//! names. The stream behaves like the `eventsource` package's EventSource the SDK opens it with:
//! a 3 s reconnect delay a `retry:` field can change, a reconnect after the stream ends or the
//! request fails, and no reconnect after a non-200 status, a 204 or a body that is not an event
//! stream.
//!
//! Not yet ported: the `redirectPolicy: 'follow'` option (redirects are followed only within the
//! origin, the SDK's default).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Url};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::auth::{AuthOptions, AuthResult, extract_www_authenticate_params};
use crate::sse::{EventSourceParser, SseItem};
use crate::stdio::TransportEvent;
use crate::streamable_http::{
    FetchFn, TransportError, TransportOAuth, default_fetch, fetch_with_headers,
    fetch_within_origin, parse_jsonrpc_message, set_header, unfollowed_redirect,
};

/// The EventSource's reconnect delay until the stream sets another with `retry:`.
const DEFAULT_RECONNECT_INTERVAL_MS: u64 = 3_000;

#[derive(Clone, Default)]
pub struct SseClientOptions {
    /// `requestInit.headers`: sent on every request, over the transport's own headers.
    pub headers: Vec<(String, String)>,
    /// `fetch`: sends the POSTs, and (with `headers`) the requests `auth()` makes.
    pub fetch: Option<FetchFn>,
    /// `eventSourceInit.fetch`: opens the stream; `fetch` does when it is unset.
    pub event_source_fetch: Option<FetchFn>,
    /// An OAuthClientProvider: a 401 runs `auth()` and tries again, and `finish_auth`
    /// redeems a code.
    pub oauth: Option<Arc<dyn TransportOAuth>>,
    pub skip_issuer_metadata_validation: bool,
}

type Ready = Option<oneshot::Sender<Result<(), TransportError>>>;

struct Inner {
    url: Url,
    headers: Vec<(String, String)>,
    fetch: FetchFn,
    stream_fetch: FetchFn,
    oauth: Option<Arc<dyn TransportOAuth>>,
    /// `_fetchWithInit`: the fetch `auth()` runs with.
    auth_fetch: Option<FetchFn>,
    skip_issuer_metadata_validation: bool,
    resource_metadata_url: Mutex<Option<Url>>,
    scope: Mutex<Option<String>>,
    endpoint: Mutex<Option<Url>>,
    protocol_version: Mutex<Option<String>>,
    events: mpsc::UnboundedSender<TransportEvent>,
    started: AtomicBool,
    closed: AtomicBool,
    tasks: Mutex<Vec<AbortHandle>>,
}

/// Client transport for SSE, ported from the SDK's SSEClientTransport.
#[derive(Clone)]
pub struct SseClientTransport {
    inner: Arc<Inner>,
}

impl SseClientTransport {
    pub fn new(
        url: Url,
        options: SseClientOptions,
    ) -> (Self, mpsc::UnboundedReceiver<TransportEvent>) {
        let (events, receiver) = mpsc::unbounded_channel();
        let auth_fetch = fetch_with_headers(options.fetch.clone(), &options.headers);
        let fetch = options.fetch.unwrap_or_else(default_fetch);
        let inner = Inner {
            url,
            headers: options.headers,
            stream_fetch: options.event_source_fetch.unwrap_or_else(|| fetch.clone()),
            fetch,
            oauth: options.oauth,
            auth_fetch,
            skip_issuer_metadata_validation: options.skip_issuer_metadata_validation,
            resource_metadata_url: Mutex::new(None),
            scope: Mutex::new(None),
            endpoint: Mutex::new(None),
            protocol_version: Mutex::new(None),
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

    /// Opens the stream and resolves once its `endpoint` event arrives, signing in first when
    /// the stream answers 401.
    pub async fn start(&self) -> Result<(), TransportError> {
        if self.inner.started.swap(true, Ordering::SeqCst) {
            return Err(TransportError::Other(
                "SSEClientTransport already started! If using Client class, note that connect() calls start() automatically."
                    .to_owned(),
            ));
        }
        let (ready, opened) = oneshot::channel();
        let inner = Arc::clone(&self.inner);
        self.inner
            .spawn(async move { inner.run_event_source(Some(ready)).await });
        opened.await.unwrap_or_else(|_| {
            Err(TransportError::Other(
                "This operation was aborted".to_owned(),
            ))
        })
    }

    /// Redeems the authorization code a sign-in brought back, the SDK's `finishAuth(code)`.
    /// The SSE transport has no `iss` parameter, so the issuer is not checked against it.
    pub async fn finish_auth(&self, code: &str) -> Result<(), TransportError> {
        let Some(oauth) = &self.inner.oauth else {
            return Err(TransportError::Unauthorized("No auth provider".to_owned()));
        };
        let mut options = self.inner.auth_options();
        options.authorization_code = Some(code.to_owned());
        if oauth.auth(options).await? != AuthResult::Authorized {
            return Err(TransportError::Unauthorized(
                "Failed to authorize".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.inner.close_tasks();
        let _ = self.inner.events.send(TransportEvent::Close);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// The URL the stream's `endpoint` event named, where messages are POSTed.
    pub fn endpoint(&self) -> Option<Url> {
        self.inner.endpoint.lock().ok()?.clone()
    }

    pub fn set_protocol_version(&self, version: Option<String>) {
        if let Ok(mut slot) = self.inner.protocol_version.lock() {
            *slot = version;
        }
    }

    pub async fn send(&self, message: &Value) -> Result<(), TransportError> {
        let Some(endpoint) = self.endpoint() else {
            return Err(TransportError::Other("Not connected".to_owned()));
        };
        let result = self.inner.post(&endpoint, message).await;
        if let Err(error) = &result {
            self.inner.emit_error(error.to_string());
        }
        result
    }
}

fn sse_error(message: &str) -> TransportError {
    TransportError::Other(format!("SSE error: {message}"))
}

impl Inner {
    fn emit_error(&self, message: String) {
        if !self.closed.load(Ordering::SeqCst) {
            let _ = self.events.send(TransportEvent::Error(message));
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

    fn close_tasks(&self) {
        if let Ok(mut tasks) = self.tasks.lock() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }

    /// `void this.close()` from inside the stream's own task, which must not abort itself.
    fn close_from_stream(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.events.send(TransportEvent::Close);
    }

    async fn common_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(oauth) = &self.oauth
            && let Some(tokens) = oauth.tokens().await
        {
            let token = tokens
                .get("access_token")
                .and_then(Value::as_str)
                .unwrap_or("undefined");
            set_header(&mut headers, "authorization", &format!("Bearer {token}"));
        }
        if let Some(version) = self
            .protocol_version
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
        {
            set_header(&mut headers, "mcp-protocol-version", &version);
        }
        for (name, value) in &self.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }
        headers
    }

    fn auth_options(&self) -> AuthOptions {
        let mut options = AuthOptions::new(self.url.clone());
        options.resource_metadata_url = self
            .resource_metadata_url
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        options.scope = self.scope.lock().ok().and_then(|slot| slot.clone());
        options.fetch = self.auth_fetch.clone();
        options.skip_issuer_metadata_validation = self.skip_issuer_metadata_validation;
        options
    }

    /// Takes the resource_metadata URL and scope from a 401's challenge (both are cleared when
    /// it has none).
    fn record_challenge(&self, header: Option<&str>) {
        let challenge = extract_www_authenticate_params(header);
        if let Ok(mut slot) = self.resource_metadata_url.lock() {
            *slot = challenge.resource_metadata_url;
        }
        if let Ok(mut slot) = self.scope.lock() {
            *slot = challenge.scope;
        }
    }

    /// Runs `auth()` with what the last challenge said.
    async fn authorize(&self, oauth: &Arc<dyn TransportOAuth>) -> Result<(), TransportError> {
        if oauth.auth(self.auth_options()).await? != AuthResult::Authorized {
            return Err(TransportError::Unauthorized("Unauthorized".to_owned()));
        }
        Ok(())
    }

    /// The EventSource, reopened after a 401 the way `_authThenStart` opens a new one.
    /// `ready` settles `start()`: it resolves on the `endpoint` event and rejects on the first
    /// error, and later errors only reach the event channel.
    async fn run_event_source(self: Arc<Self>, mut ready: Ready) {
        let settle = |ready: &mut Ready, result: Result<(), TransportError>| {
            if let Some(ready) = ready.take() {
                let _ = ready.send(result);
            }
        };
        let mut reconnect_interval = DEFAULT_RECONNECT_INTERVAL_MS;
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            let mut headers = self.common_headers().await;
            set_header(&mut headers, "accept", "text/event-stream");
            let response = match fetch_within_origin(
                &self.stream_fetch,
                &self.url,
                Method::GET,
                headers,
                None,
                &self.closed,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    if self.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    let error = sse_error(&error.to_string());
                    self.emit_error(error.to_string());
                    settle(&mut ready, Err(error));
                    tokio::time::sleep(Duration::from_millis(reconnect_interval)).await;
                    continue;
                }
            };

            let redirect = unfollowed_redirect(&self.url, &response);
            let status = response.status().as_u16();
            if status == 401
                && let Some(header) = response.headers().get("www-authenticate")
            {
                self.record_challenge(header.to_str().ok());
            }
            let failure = if status == 204 {
                Some("Server sent HTTP 204, not reconnecting")
            } else if status != 200 {
                Some("Non-200 status code")
            } else if !response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .starts_with("text/event-stream")
            {
                Some("Invalid content type, expected \"text/event-stream\"")
            } else {
                None
            };
            if let Some(failure) = failure {
                let _ = response.bytes().await;
                if status == 401
                    && let Some(oauth) = &self.oauth
                {
                    match self.authorize(oauth).await {
                        Ok(()) => {
                            reconnect_interval = DEFAULT_RECONNECT_INTERVAL_MS;
                            continue;
                        }
                        Err(error) => {
                            if matches!(error, TransportError::Auth(_)) {
                                self.emit_error(error.to_string());
                            }
                            settle(&mut ready, Err(error));
                            return;
                        }
                    }
                }
                let message = if failure == "Non-200 status code" {
                    format!("{failure} ({status})")
                } else {
                    failure.to_owned()
                };
                let error = sse_error(&redirect.unwrap_or(message));
                self.emit_error(error.to_string());
                settle(&mut ready, Err(error));
                return;
            }

            let mut response = response;
            let mut parser = EventSourceParser::new();
            let ended = loop {
                let chunk = match response.chunk().await {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break redirect.clone().unwrap_or("undefined".to_owned()),
                    Err(error) => break error.to_string(),
                };
                for item in parser.feed(&chunk) {
                    match item {
                        SseItem::Retry(interval) => reconnect_interval = interval,
                        SseItem::Error(_) => {}
                        SseItem::Event(event) => {
                            match event.event.as_deref().unwrap_or("message") {
                                "endpoint" => match self.accept_endpoint(&event.data) {
                                    Ok(()) => settle(&mut ready, Ok(())),
                                    Err(error) => {
                                        self.emit_error(error.to_string());
                                        settle(&mut ready, Err(error));
                                        self.close_from_stream();
                                        return;
                                    }
                                },
                                "message" => match serde_json::from_str(&event.data)
                                    .map_err(|error| error.to_string())
                                    .and_then(parse_jsonrpc_message)
                                {
                                    Ok(message) => {
                                        let _ = self.events.send(TransportEvent::Message(message));
                                    }
                                    Err(error) => self.emit_error(error),
                                },
                                _ => {}
                            }
                        }
                    }
                }
            };
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            let error = sse_error(&ended);
            self.emit_error(error.to_string());
            settle(&mut ready, Err(error));
            tokio::time::sleep(Duration::from_millis(reconnect_interval)).await;
        }
    }

    fn accept_endpoint(&self, data: &str) -> Result<(), TransportError> {
        let endpoint = self
            .url
            .join(data)
            .map_err(|_| TransportError::Other("Invalid URL".to_owned()))?;
        if endpoint.origin() != self.url.origin() {
            return Err(TransportError::Other(format!(
                "Endpoint origin does not match connection origin: {}",
                endpoint.origin().ascii_serialization()
            )));
        }
        if let Ok(mut slot) = self.endpoint.lock() {
            *slot = Some(endpoint);
        }
        Ok(())
    }

    /// POSTs one message, signing in again and resending it after a 401.
    async fn post(&self, endpoint: &Url, message: &Value) -> Result<(), TransportError> {
        loop {
            let mut headers = self.common_headers().await;
            set_header(&mut headers, "content-type", "application/json");
            let response = fetch_within_origin(
                &self.fetch,
                endpoint,
                Method::POST,
                headers,
                Some(message.to_string()),
                &self.closed,
            )
            .await?;
            let status = response.status();
            if status.is_success() {
                let _ = response.bytes().await;
                return Ok(());
            }
            let redirect = unfollowed_redirect(endpoint, &response);
            let challenge = response
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let text = response.text().await.unwrap_or_else(|_| "null".to_owned());
            if status.as_u16() == 401
                && let Some(oauth) = &self.oauth
            {
                self.record_challenge(challenge.as_deref());
                self.authorize(oauth).await?;
                continue;
            }
            return Err(TransportError::Other(format!(
                "Error POSTing to endpoint (HTTP {}): {}",
                status.as_u16(),
                redirect.unwrap_or(text)
            )));
        }
    }
}
