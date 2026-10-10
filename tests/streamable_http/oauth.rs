use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;
use rust_mcp_remote::auth::{AuthError, AuthOptions, AuthResult};
use rust_mcp_remote::streamable_http::{
    BoxFuture, StreamableHttpClientTransport, StreamableHttpOptions, TokenFn, TransportError,
    TransportOAuth,
};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::test_server::{RecordedRequest, Reply, reply, serve};

const JSON: (&str, &str) = ("content-type", "application/json");

fn initialize(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"}}})
}

fn ok_reply() -> Reply {
    reply(
        200,
        &[JSON],
        r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
    )
}

/// What one `auth()` call was asked to do.
#[derive(Debug, Clone, PartialEq)]
struct AuthCall {
    scope: Option<String>,
    resource_metadata_url: Option<String>,
    authorization_code: Option<String>,
    iss: Option<String>,
    force_reauthorization: bool,
}

/// A provider that records each `auth()` call; every Authorized result issues token at-N.
struct FakeOAuth {
    issued: AtomicUsize,
    granted_scope: Option<String>,
    result: AuthResult,
    calls: Mutex<Vec<AuthCall>>,
}

impl FakeOAuth {
    fn new(result: AuthResult, granted_scope: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            issued: AtomicUsize::new(0),
            granted_scope: granted_scope.map(str::to_owned),
            result,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<AuthCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl TransportOAuth for FakeOAuth {
    fn tokens(&self) -> BoxFuture<Option<Value>> {
        let issued = self.issued.load(Ordering::SeqCst);
        let scope = self.granted_scope.clone();
        Box::pin(async move {
            (issued > 0).then(|| json!({"access_token": format!("at-{issued}"), "scope": scope}))
        })
    }

    fn auth(&self, options: AuthOptions) -> BoxFuture<Result<AuthResult, AuthError>> {
        self.calls.lock().unwrap().push(AuthCall {
            scope: options.scope.clone(),
            resource_metadata_url: options.resource_metadata_url.map(|url| url.to_string()),
            authorization_code: options.authorization_code.clone(),
            iss: options.iss.clone(),
            force_reauthorization: options.force_reauthorization,
        });
        if self.result == AuthResult::Authorized {
            self.issued.fetch_add(1, Ordering::SeqCst);
        }
        let result = self.result;
        Box::pin(async move { Ok(result) })
    }
}

/// Wraps a fake provider the way the transport stores one.
struct Shared(Arc<FakeOAuth>);

impl TransportOAuth for Shared {
    fn tokens(&self) -> BoxFuture<Option<Value>> {
        self.0.tokens()
    }

    fn auth(&self, options: AuthOptions) -> BoxFuture<Result<AuthResult, AuthError>> {
        self.0.auth(options)
    }
}

fn transport_with(base: &str, oauth: &Arc<FakeOAuth>) -> StreamableHttpClientTransport {
    let url = Url::parse(&format!("{base}/mcp")).unwrap();
    let (transport, events) = StreamableHttpClientTransport::new(
        url,
        StreamableHttpOptions {
            oauth: Some(Arc::new(Shared(Arc::clone(oauth)))),
            ..Default::default()
        },
    );
    std::mem::forget(events);
    transport.start().unwrap();
    transport
}

fn drain(requests: &mut UnboundedReceiver<RecordedRequest>) -> Vec<RecordedRequest> {
    let mut seen = Vec::new();
    while let Ok(request) = requests.try_recv() {
        seen.push(request);
    }
    seen
}

fn challenge(base: &str, scope: &str) -> String {
    format!(
        r#"Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/mcp", scope="{scope}""#
    )
}

/// An MCP server that accepts only `Bearer at-1`, and challenges anything else.
async fn protected_server() -> (String, UnboundedReceiver<RecordedRequest>) {
    let base = Arc::new(std::sync::OnceLock::<String>::new());
    let handler_base = Arc::clone(&base);
    let (url, requests) = serve(Arc::new(move |request: &RecordedRequest| {
        if request.header("authorization") == Some("Bearer at-1") {
            return ok_reply();
        }
        let header = challenge(handler_base.get().unwrap(), "mcp:read");
        reply(401, &[("www-authenticate", header.as_str())], "no")
    }))
    .await;
    base.set(url.clone()).unwrap();
    (url, requests)
}

#[tokio::test]
async fn a_401_runs_auth_with_the_challenge_and_retries_with_the_new_token() {
    let (base, mut requests) = protected_server().await;
    let oauth = FakeOAuth::new(AuthResult::Authorized, None);
    let transport = transport_with(&base, &oauth);

    transport.send(&initialize(1)).await.unwrap();

    assert_eq!(
        oauth.calls(),
        vec![AuthCall {
            scope: Some("mcp:read".to_owned()),
            resource_metadata_url: Some(format!("{base}/.well-known/oauth-protected-resource/mcp")),
            authorization_code: None,
            iss: None,
            force_reauthorization: false,
        }]
    );
    let seen = drain(&mut requests);
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].header("authorization"), None);
    assert_eq!(seen[1].header("authorization"), Some("Bearer at-1"));
}

#[tokio::test]
async fn a_401_after_re_authentication_is_an_http_error() {
    let (base, mut requests) = serve(Arc::new(|_: &RecordedRequest| reply(401, &[], "no"))).await;
    let oauth = FakeOAuth::new(AuthResult::Authorized, None);
    let transport = transport_with(&base, &oauth);

    let error = transport.send(&initialize(1)).await.unwrap_err();

    assert_eq!(
        error,
        TransportError::Http {
            status: 401,
            message: "Server returned 401 after re-authentication".to_owned()
        }
    );
    assert_eq!(oauth.calls().len(), 1);
    assert_eq!(drain(&mut requests).len(), 2);
}

#[tokio::test]
async fn a_sign_in_that_redirects_is_unauthorized_and_finish_auth_redeems_the_code() {
    let (base, mut requests) = protected_server().await;
    let oauth = FakeOAuth::new(AuthResult::Redirect, None);
    let transport = transport_with(&base, &oauth);

    let error = transport.send(&initialize(1)).await.unwrap_err();
    assert_eq!(
        error,
        TransportError::Unauthorized("Unauthorized".to_owned())
    );
    assert_eq!(drain(&mut requests).len(), 1);

    // finishAuth reuses the resource metadata URL and scope the 401 recorded.
    let _ = transport
        .finish_auth("the-code", Some("https://issuer"))
        .await;
    assert_eq!(
        oauth.calls()[1],
        AuthCall {
            scope: Some("mcp:read".to_owned()),
            resource_metadata_url: Some(format!("{base}/.well-known/oauth-protected-resource/mcp")),
            authorization_code: Some("the-code".to_owned()),
            iss: Some("https://issuer".to_owned()),
            force_reauthorization: false,
        }
    );
}

#[tokio::test]
async fn finish_auth_reports_a_result_that_is_not_authorized() {
    let (base, _requests) = protected_server().await;
    let oauth = FakeOAuth::new(AuthResult::Redirect, None);
    let transport = transport_with(&base, &oauth);

    assert_eq!(
        transport.finish_auth("code", None).await,
        Err(TransportError::Unauthorized(
            "Failed to authorize".to_owned()
        ))
    );
}

#[tokio::test]
async fn finish_auth_needs_an_oauth_provider() {
    let url = Url::parse("http://localhost:1/mcp").unwrap();
    let (transport, _events) = StreamableHttpClientTransport::new(url, Default::default());

    assert_eq!(
        transport.finish_auth("code", None).await,
        Err(TransportError::Unauthorized(
            "finishAuth requires an OAuthClientProvider".to_owned()
        ))
    );
}

fn insufficient_scope(scope: &str) -> Reply {
    let header = format!(r#"Bearer error="insufficient_scope", scope="{scope}""#);
    reply(403, &[("www-authenticate", header.as_str())], "forbidden")
}

#[tokio::test]
async fn a_403_insufficient_scope_steps_up_to_the_scope_union_and_retries() {
    let posts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&posts);
    let (base, mut requests) = serve(Arc::new(move |_: &RecordedRequest| {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            insufficient_scope("mcp:write")
        } else {
            ok_reply()
        }
    }))
    .await;
    let oauth = FakeOAuth::new(AuthResult::Authorized, Some("mcp:read"));
    oauth.issued.store(1, Ordering::SeqCst);
    let transport = transport_with(&base, &oauth);

    transport.send(&initialize(1)).await.unwrap();

    assert_eq!(
        oauth.calls(),
        vec![AuthCall {
            scope: Some("mcp:read mcp:write".to_owned()),
            resource_metadata_url: None,
            authorization_code: None,
            iss: None,
            force_reauthorization: true,
        }]
    );
    let seen = drain(&mut requests);
    assert_eq!(seen[0].header("authorization"), Some("Bearer at-1"));
    assert_eq!(seen[1].header("authorization"), Some("Bearer at-2"));
}

#[tokio::test]
async fn a_second_403_insufficient_scope_hits_the_step_up_limit() {
    let (base, _requests) = serve(Arc::new(|_: &RecordedRequest| {
        insufficient_scope("mcp:write")
    }))
    .await;
    let oauth = FakeOAuth::new(AuthResult::Authorized, Some("mcp:read"));
    let transport = transport_with(&base, &oauth);

    let error = transport.send(&initialize(1)).await.unwrap_err();

    assert_eq!(
        error,
        TransportError::Http {
            status: 403,
            message: "Server returned 403 insufficient_scope after step-up re-authorization (retry limit 1 reached)".to_owned()
        }
    );
    assert_eq!(oauth.calls().len(), 1);
}

#[tokio::test]
async fn a_403_insufficient_scope_without_an_oauth_provider_is_insufficient_scope() {
    let (base, _requests) = serve(Arc::new(|_: &RecordedRequest| {
        insufficient_scope("mcp:write")
    }))
    .await;
    let token: TokenFn = Arc::new(|| Box::pin(async { Ok(Some("abc".to_owned())) }));
    let url = Url::parse(&format!("{base}/mcp")).unwrap();
    let (transport, _events) = StreamableHttpClientTransport::new(
        url,
        StreamableHttpOptions {
            token: Some(token),
            ..Default::default()
        },
    );

    let error = transport.send(&initialize(1)).await.unwrap_err();

    assert_eq!(
        error.to_string(),
        r#"Insufficient scope: required "mcp:write""#
    );
    assert!(matches!(error, TransportError::InsufficientScope { .. }));
}

#[tokio::test]
async fn a_401_on_the_standalone_stream_signs_in_and_reopens_it() {
    let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.method == "GET" {
            if request.header("authorization") == Some("Bearer at-1") {
                return reply(405, &[], "");
            }
            return reply(
                401,
                &[("www-authenticate", r#"Bearer scope="mcp:read""#)],
                "no",
            );
        }
        reply(202, &[], "")
    }))
    .await;
    let oauth = FakeOAuth::new(AuthResult::Authorized, None);
    let transport = transport_with(&base, &oauth);

    transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut gets = Vec::new();
    while gets.len() < 2 && tokio::time::Instant::now() < deadline {
        if let Ok(Some(request)) =
            tokio::time::timeout(Duration::from_millis(100), requests.recv()).await
            && request.method == "GET"
        {
            gets.push(request);
        }
    }
    assert_eq!(gets.len(), 2);
    assert_eq!(gets[1].header("authorization"), Some("Bearer at-1"));
    assert_eq!(oauth.calls()[0].scope.as_deref(), Some("mcp:read"));
}
