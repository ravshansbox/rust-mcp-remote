//! The connect-to-remote-server.test.ts scenarios, against a real HTTP server rather than mocked
//! SDK classes. The with-client mode test is left out: that mode is not ported yet.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rust_mcp_remote::auth::{AuthError, AuthOptions, AuthResult};
use rust_mcp_remote::callback_server::AuthCodeResult;
use rust_mcp_remote::connect::{
    AuthInitialization, AuthInitializer, ConnectOptions, RemoteAuth, connect_to_remote_server,
};
use rust_mcp_remote::protocol_era::ProtocolMode;
use rust_mcp_remote::streamable_http::{BoxFuture, TransportOAuth};
use rust_mcp_remote::utils::TransportStrategy;
use serde_json::{Value, json};

use crate::test_server::{RecordedRequest, reply, serve};

/// What one `auth()` call carried.
#[derive(Debug, Clone, PartialEq)]
struct AuthCall {
    authorization_code: Option<String>,
    iss: Option<String>,
    resource_metadata_url: Option<String>,
}

/// A provider whose `auth()` without a code either redirects (a browser sign-in) or issues a
/// token straight away (as a refresh would), and whose `auth()` with a code issues a token.
struct FakeAuth {
    token: Mutex<Option<String>>,
    issued: AtomicUsize,
    issue_without_code: bool,
    calls: Mutex<Vec<AuthCall>>,
    forgotten: AtomicUsize,
}

impl FakeAuth {
    fn new(issue_without_code: bool) -> Arc<Self> {
        Arc::new(Self {
            token: Mutex::new(None),
            issued: AtomicUsize::new(0),
            issue_without_code,
            calls: Mutex::new(Vec::new()),
            forgotten: AtomicUsize::new(0),
        })
    }

    fn issue(&self) {
        let issued = self.issued.fetch_add(1, Ordering::SeqCst) + 1;
        *self.token.lock().unwrap() = Some(format!("at-{issued}"));
    }

    fn codes(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter_map(|call| call.authorization_code.clone())
            .collect()
    }

    fn code_calls(&self) -> Vec<AuthCall> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.authorization_code.is_some())
            .cloned()
            .collect()
    }
}

struct Oauth(Arc<FakeAuth>);

impl TransportOAuth for Oauth {
    fn tokens(&self) -> BoxFuture<Option<Value>> {
        let token = self.0.token.lock().unwrap().clone();
        Box::pin(async move { token.map(|token| json!({"access_token": token})) })
    }

    fn auth(&self, options: AuthOptions) -> BoxFuture<Result<AuthResult, AuthError>> {
        let has_code = options.authorization_code.is_some();
        self.0.calls.lock().unwrap().push(AuthCall {
            authorization_code: options.authorization_code,
            iss: options.iss,
            resource_metadata_url: options.resource_metadata_url.map(|url| url.to_string()),
        });
        let result = if has_code || self.0.issue_without_code {
            self.0.issue();
            AuthResult::Authorized
        } else {
            AuthResult::Redirect
        };
        Box::pin(async move { Ok(result) })
    }
}

/// The provider as connecting sees it.
struct Remote(Arc<FakeAuth>);

impl RemoteAuth for Remote {
    fn transport_oauth(&self) -> Arc<dyn TransportOAuth> {
        Arc::new(Oauth(Arc::clone(&self.0)))
    }

    fn forget_tokens(&self) -> BoxFuture<Result<(), String>> {
        self.0.forgotten.fetch_add(1, Ordering::SeqCst);
        *self.0.token.lock().unwrap() = None;
        Box::pin(async { Ok(()) })
    }

    fn use_authorization_state(&self, _state: &str) {}
}

/// An MCP server that takes the bearer tokens `accepts` lets through and challenges the rest.
async fn mcp_server(accepts: impl Fn(&str) -> bool + Send + Sync + 'static) -> String {
    let base = Arc::new(OnceLock::<String>::new());
    let handler_base = Arc::clone(&base);
    let (url, _requests) = serve(Arc::new(move |request: &RecordedRequest| {
        let token = request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "));
        if !token.is_some_and(&accepts) {
            let header = format!(
                r#"Bearer resource_metadata="{}/.well-known/oauth-protected-resource/mcp""#,
                handler_base.get().unwrap()
            );
            return reply(401, &[("www-authenticate", header.as_str())], "no");
        }
        let body: Value = serde_json::from_str(&request.body).unwrap_or(Value::Null);
        if body["method"] == "initialize" {
            let answer = json!({"jsonrpc": "2.0", "id": body["id"], "result": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "serverInfo": {"name": "fake", "version": "1"}}});
            return reply(
                200,
                &[
                    ("content-type", "application/json"),
                    ("mcp-session-id", "s1"),
                ],
                &answer.to_string(),
            );
        }
        reply(202, &[], "")
    }))
    .await;
    base.set(url.clone()).unwrap();
    url
}

fn options(base: &str) -> ConnectOptions {
    ConnectOptions {
        server_url: format!("{base}/mcp"),
        headers: Vec::new(),
        transport_strategy: TransportStrategy::HttpFirst,
        protocol_mode: ProtocolMode::Legacy,
        non_interactive_flow: false,
    }
}

/// An initializer that hands back `code` (with `iss`) for this instance to redeem.
fn owner_of(code: &'static str, iss: Option<&'static str>) -> AuthInitializer {
    Arc::new(move |_force_refresh| {
        Box::pin(async move {
            Ok(AuthInitialization {
                wait_for_auth_code: Box::new(move || {
                    Box::pin(async move {
                        Ok(AuthCodeResult {
                            code: code.to_owned(),
                            state: None,
                            iss: iss.map(str::to_owned),
                        })
                    })
                }),
                skip_browser_auth: false,
            })
        })
    })
}

/// What coordinateAuth hands an instance whose sibling ran the sign-in: no code is coming.
fn follower(waited: Arc<AtomicBool>) -> AuthInitialization {
    AuthInitialization {
        wait_for_auth_code: Box::new(move || {
            waited.store(true, Ordering::SeqCst);
            Box::pin(std::future::pending())
        }),
        skip_browser_auth: true,
    }
}

#[tokio::test]
async fn completes_auth_on_the_transport_that_received_the_401_challenge() {
    let base = mcp_server(|token| token == "at-1").await;
    let auth = FakeAuth::new(false);

    let connection = connect_to_remote_server(
        &Remote(Arc::clone(&auth)),
        &owner_of("auth-code-123", None),
        &options(&base),
    )
    .await
    .unwrap();
    connection.transport.close();

    // Redeemed with the resource_metadata URL only the challenged probe transport had stored
    assert_eq!(
        auth.code_calls(),
        vec![AuthCall {
            authorization_code: Some("auth-code-123".to_owned()),
            iss: None,
            resource_metadata_url: Some(format!("{base}/.well-known/oauth-protected-resource/mcp")),
        }]
    );
}

#[tokio::test]
async fn discards_a_token_the_server_refused_after_issuing_it_then_signs_in_again() {
    // The first token issued is refused even though it was just authorized; later ones work
    let base = mcp_server(|token| token != "at-1").await;
    let auth = FakeAuth::new(true);

    let connection = connect_to_remote_server(
        &Remote(Arc::clone(&auth)),
        &owner_of("unused", None),
        &options(&base),
    )
    .await
    .unwrap();
    connection.transport.close();

    assert_eq!(auth.forgotten.load(Ordering::SeqCst), 1);
    assert!(auth.codes().is_empty());
}

#[tokio::test]
async fn gives_up_when_the_token_it_signed_in_for_is_refused_as_well() {
    let base = mcp_server(|_| false).await;
    let auth = FakeAuth::new(true);

    let error = connect_to_remote_server(
        &Remote(Arc::clone(&auth)),
        &owner_of("unused", None),
        &options(&base),
    )
    .await
    .err()
    .unwrap();

    assert!(error.to_string().contains("401 after re-authentication"));
    assert_eq!(auth.forgotten.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn forwards_the_callback_iss_to_finish_auth() {
    let base = mcp_server(|token| token == "at-1").await;
    let auth = FakeAuth::new(false);

    let initializer = owner_of("auth-code-iss", Some("https://mcp.example.com"));
    let connection =
        connect_to_remote_server(&Remote(Arc::clone(&auth)), &initializer, &options(&base))
            .await
            .unwrap();
    connection.transport.close();

    let calls = auth.code_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].iss.as_deref(), Some("https://mcp.example.com"));
}

#[tokio::test]
async fn reconnects_instead_of_awaiting_a_code_when_a_sibling_completed_the_sign_in() {
    let base = mcp_server(|token| token == "sibling-token").await;
    let auth = FakeAuth::new(false);
    let waited = Arc::new(AtomicBool::new(false));
    let initializer: AuthInitializer = {
        let auth = Arc::clone(&auth);
        let waited = Arc::clone(&waited);
        Arc::new(move |_| {
            // The sibling has written its tokens by the time the verdict comes back
            *auth.token.lock().unwrap() = Some("sibling-token".to_owned());
            let waited = Arc::clone(&waited);
            Box::pin(async move { Ok(follower(waited)) })
        })
    };

    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        connect_to_remote_server(&Remote(Arc::clone(&auth)), &initializer, &options(&base)),
    )
    .await
    .expect("hung waiting for a code")
    .unwrap();
    connection.transport.close();

    assert!(!waited.load(Ordering::SeqCst));
    assert!(auth.codes().is_empty());
}

#[tokio::test]
async fn gives_up_rather_than_looping_when_a_sibling_instance_tokens_still_do_not_work() {
    let base = mcp_server(|_| false).await;
    let auth = FakeAuth::new(false);
    let initializer: AuthInitializer =
        Arc::new(|_| Box::pin(async { Ok(follower(Arc::new(AtomicBool::new(false)))) }));

    let error = connect_to_remote_server(&Remote(Arc::clone(&auth)), &initializer, &options(&base))
        .await
        .err()
        .unwrap();

    assert!(
        error
            .to_string()
            .contains("the remote server refused the tokens it wrote")
    );
}

#[tokio::test]
async fn looks_again_rather_than_trusting_a_handover_verdict_its_tokens_were_refused_for() {
    let base = mcp_server(|_| false).await;
    let auth = FakeAuth::new(false);
    let refreshes = Arc::new(Mutex::new(Vec::new()));
    let owner = owner_of("auth-code-352", None);
    let initializer: AuthInitializer = {
        let refreshes = Arc::clone(&refreshes);
        Arc::new(move |force_refresh| {
            refreshes.lock().unwrap().push(force_refresh);
            // On the second look the sibling has released the port, so this instance signs in
            if force_refresh {
                owner(true)
            } else {
                Box::pin(async { Ok(follower(Arc::new(AtomicBool::new(false)))) })
            }
        })
    };

    let error = connect_to_remote_server(&Remote(Arc::clone(&auth)), &initializer, &options(&base))
        .await
        .err()
        .unwrap();

    assert!(error.to_string().contains("Already attempted reconnection"));
    assert!(refreshes.lock().unwrap().contains(&true));
    assert_eq!(auth.codes(), vec!["auth-code-352"]);
}

#[tokio::test]
async fn does_not_re_exchange_a_spent_authorization_code_when_the_retry_also_fails() {
    let base = mcp_server(|_| false).await;
    let auth = FakeAuth::new(false);

    let error = connect_to_remote_server(
        &Remote(Arc::clone(&auth)),
        &owner_of("auth-code-789", None),
        &options(&base),
    )
    .await
    .err()
    .unwrap();

    assert!(error.to_string().contains("Already attempted reconnection"));
    assert_eq!(auth.codes(), vec!["auth-code-789"]);
}

#[tokio::test]
async fn a_non_interactive_sign_in_reconnects_once_without_a_callback() {
    let base = mcp_server(|_| false).await;
    let auth = FakeAuth::new(false);
    let initialized = Arc::new(AtomicUsize::new(0));
    let initializer: AuthInitializer = {
        let initialized = Arc::clone(&initialized);
        Arc::new(move |_| {
            initialized.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err("no callback port for this grant".to_owned()) })
        })
    };
    let mut options = options(&base);
    options.non_interactive_flow = true;

    let error = connect_to_remote_server(&Remote(Arc::clone(&auth)), &initializer, &options)
        .await
        .err()
        .unwrap();

    assert!(error.to_string().contains("Already attempted reconnection"));
    assert_eq!(initialized.load(Ordering::SeqCst), 0);
}

async fn connect_to_a_404(strategy: TransportStrategy) -> String {
    let (base, _requests) = serve(Arc::new(|_: &RecordedRequest| reply(404, &[], "gone"))).await;
    let auth = FakeAuth::new(false);
    let mut options = options(&base);
    options.transport_strategy = strategy;
    connect_to_remote_server(
        &Remote(Arc::clone(&auth)),
        &owner_of("unused", None),
        &options,
    )
    .await
    .err()
    .unwrap()
    .to_string()
}

#[tokio::test]
async fn an_http_only_strategy_does_not_fall_back_on_a_404() {
    assert_eq!(
        connect_to_a_404(TransportStrategy::HttpOnly).await,
        "Error POSTing to endpoint: gone"
    );
}

#[tokio::test]
async fn an_http_first_strategy_falls_back_to_sse_on_a_404() {
    // The SSE attempt meets the same 404, and an sse-only strategy does not fall back again
    assert_eq!(
        connect_to_a_404(TransportStrategy::HttpFirst).await,
        "SSE error: Non-200 status code (404)"
    );
}

#[tokio::test]
async fn an_sse_first_strategy_falls_back_to_http_on_a_404() {
    assert_eq!(
        connect_to_a_404(TransportStrategy::SseFirst).await,
        "Error POSTing to endpoint: gone"
    );
}

#[tokio::test]
async fn an_sse_only_strategy_signs_in_from_the_stream_and_redeems_the_code_on_it() {
    let (base, _requests) = serve(Arc::new(|request: &RecordedRequest| {
        let authorized = request.header("authorization") == Some("Bearer at-1");
        match (request.method.as_str(), authorized) {
            (_, false) => reply(
                401,
                &[(
                    "www-authenticate",
                    "Bearer resource_metadata=\"http://127.0.0.1:9/prm\"",
                )],
                "",
            ),
            ("GET", true) => reply(
                200,
                &[("content-type", "text/event-stream")],
                "retry: 60000\nevent: endpoint\ndata: /messages?sessionId=1\n\n",
            ),
            _ => reply(202, &[], ""),
        }
    }))
    .await;
    let auth = FakeAuth::new(false);
    let mut options = options(&base);
    options.transport_strategy = TransportStrategy::SseOnly;
    let connection = connect_to_remote_server(
        &Remote(Arc::clone(&auth)),
        &owner_of("sse-code", Some("https://mcp.example.com")),
        &options,
    )
    .await
    .unwrap();

    let calls = auth.code_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].authorization_code.as_deref(), Some("sse-code"));
    // The SSE transport's finishAuth takes no iss
    assert_eq!(calls[0].iss, None);
    assert_eq!(
        calls[0].resource_metadata_url.as_deref(),
        Some("http://127.0.0.1:9/prm")
    );
    assert_eq!(connection.transport.name(), "SSEClientTransport");
    connection.transport.close();
}
