//! SseClientTransport against a real HTTP server that holds the event stream open.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;
use rust_mcp_remote::auth::{AuthError, AuthOptions, AuthResult};
use rust_mcp_remote::sse_client::{SseClientOptions, SseClientTransport};
use rust_mcp_remote::stdio::TransportEvent;
use rust_mcp_remote::streamable_http::{BoxFuture, FetchFn, TransportOAuth, default_fetch};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::stream_server::{Recorded, Streams, fixed, serve};

const ENDPOINT_EVENT: &str = "retry: 60000\nevent: endpoint\ndata: /messages?sessionId=abc\n\n";

/// What one `auth()` call carried.
#[derive(Debug, Clone)]
struct AuthCall {
    authorization_code: Option<String>,
    resource_metadata_url: Option<String>,
    scope: Option<String>,
}

/// A provider whose `auth()` answers `result` and, when that is Authorized, issues `at-1`.
struct FakeOauth {
    token: Mutex<Option<String>>,
    result: AuthResult,
    calls: Mutex<Vec<AuthCall>>,
    /// The fetch the latest `auth()` call was given for its own requests.
    fetch: Mutex<Option<FetchFn>>,
}

impl FakeOauth {
    fn new(token: Option<&str>, result: AuthResult) -> Arc<Self> {
        Arc::new(Self {
            token: Mutex::new(token.map(str::to_owned)),
            result,
            calls: Mutex::new(Vec::new()),
            fetch: Mutex::new(None),
        })
    }
}

struct Oauth(Arc<FakeOauth>);

impl TransportOAuth for Oauth {
    fn tokens(&self) -> BoxFuture<Option<Value>> {
        let token = self.0.token.lock().unwrap().clone();
        Box::pin(async move { token.map(|token| json!({"access_token": token})) })
    }

    fn auth(&self, mut options: AuthOptions) -> BoxFuture<Result<AuthResult, AuthError>> {
        *self.0.fetch.lock().unwrap() = options.fetch.take();
        self.0.calls.lock().unwrap().push(AuthCall {
            authorization_code: options.authorization_code,
            resource_metadata_url: options.resource_metadata_url.map(|url| url.to_string()),
            scope: options.scope,
        });
        if self.0.result == AuthResult::Authorized {
            *self.0.token.lock().unwrap() = Some("at-1".to_owned());
        }
        let result = self.0.result;
        Box::pin(async move { Ok(result) })
    }
}

fn transport(
    base: &str,
    options: SseClientOptions,
) -> (SseClientTransport, UnboundedReceiver<TransportEvent>) {
    SseClientTransport::new(Url::parse(&format!("{base}/sse")).unwrap(), options)
}

async fn next_event(events: &mut UnboundedReceiver<TransportEvent>) -> TransportEvent {
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("an event")
        .expect("an open channel")
}

#[tokio::test]
async fn resolves_on_the_endpoint_event_and_delivers_messages_both_ways() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, mut requests) = serve(Arc::new(move |request: &Recorded| {
        if request.method == "GET" {
            handler_streams.open(ENDPOINT_EVENT)
        } else {
            fixed(202, &[], "Accepted")
        }
    }))
    .await;
    let (transport, mut events) = transport(
        &base,
        SseClientOptions {
            headers: vec![("x-api-key".to_owned(), "secret".to_owned())],
            ..SseClientOptions::default()
        },
    );

    transport.start().await.unwrap();
    assert_eq!(
        transport.endpoint().unwrap().as_str(),
        format!("{base}/messages?sessionId=abc")
    );
    let get = requests.recv().await.unwrap();
    assert_eq!(get.path, "/sse");
    assert_eq!(get.header("accept"), Some("text/event-stream"));
    assert_eq!(get.header("x-api-key"), Some("secret"));

    transport.set_protocol_version(Some("2025-06-18".to_owned()));
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    transport.send(&request).await.unwrap();
    let post = requests.recv().await.unwrap();
    assert_eq!(post.method, "POST");
    assert_eq!(post.path, "/messages?sessionId=abc");
    assert_eq!(post.header("content-type"), Some("application/json"));
    assert_eq!(post.header("mcp-protocol-version"), Some("2025-06-18"));
    assert_eq!(post.header("x-api-key"), Some("secret"));
    assert_eq!(serde_json::from_str::<Value>(&post.body).unwrap(), request);

    let answer = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}});
    streams.push(&format!("event: message\ndata: {answer}\n\n"));
    match next_event(&mut events).await {
        TransportEvent::Message(message) => assert_eq!(message, answer),
        other => panic!("expected a message, got {other:?}"),
    }
    transport.close();
    assert!(matches!(
        next_event(&mut events).await,
        TransportEvent::Close
    ));
}

#[tokio::test]
async fn reports_a_message_that_is_not_json_rpc_and_keeps_reading() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, _requests) = serve(Arc::new(move |_: &Recorded| {
        handler_streams.open(ENDPOINT_EVENT)
    }))
    .await;
    let (transport, mut events) = transport(&base, SseClientOptions::default());
    transport.start().await.unwrap();

    streams.push("data: not json\n\n");
    assert!(matches!(
        next_event(&mut events).await,
        TransportEvent::Error(_)
    ));
    let notification = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
    streams.push(&format!("data: {notification}\n\n"));
    match next_event(&mut events).await {
        TransportEvent::Message(message) => assert_eq!(message, notification),
        other => panic!("expected a message, got {other:?}"),
    }
    transport.close();
}

#[tokio::test]
async fn rejects_an_endpoint_on_another_origin_and_closes() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, _requests) = serve(Arc::new(move |_: &Recorded| {
        handler_streams.open("event: endpoint\ndata: https://evil.example.com/messages\n\n")
    }))
    .await;
    let (transport, mut events) = transport(&base, SseClientOptions::default());

    let error = transport.start().await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "Endpoint origin does not match connection origin: https://evil.example.com"
    );
    assert!(matches!(
        next_event(&mut events).await,
        TransportEvent::Error(_)
    ));
    assert!(matches!(
        next_event(&mut events).await,
        TransportEvent::Close
    ));
    assert!(transport.is_closed());
}

#[tokio::test]
async fn fails_without_reconnecting_on_a_non_200_status() {
    let (base, mut requests) = serve(Arc::new(|_: &Recorded| fixed(404, &[], "Not Found"))).await;
    let (transport, _events) = transport(&base, SseClientOptions::default());

    let error = transport.start().await.unwrap_err();
    assert_eq!(error.to_string(), "SSE error: Non-200 status code (404)");
    requests.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn fails_without_reconnecting_when_the_server_sends_204() {
    let (base, mut requests) = serve(Arc::new(|_: &Recorded| fixed(204, &[], ""))).await;
    let (transport, mut events) = transport(&base, SseClientOptions::default());

    let error = transport.start().await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "SSE error: Server sent HTTP 204, not reconnecting"
    );
    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Error("SSE error: Server sent HTTP 204, not reconnecting".to_owned())
    );
    requests.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn fails_on_a_body_that_is_not_an_event_stream() {
    let (base, _requests) = serve(Arc::new(|_: &Recorded| {
        fixed(200, &[("content-type", "application/json")], "{}")
    }))
    .await;
    let (transport, _events) = transport(&base, SseClientOptions::default());

    let error = transport.start().await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "SSE error: Invalid content type, expected \"text/event-stream\""
    );
}

#[tokio::test]
async fn reconnects_after_the_stream_ends_with_the_interval_the_server_set() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, mut requests) = serve(Arc::new(move |_: &Recorded| {
        handler_streams.open("retry: 50\nevent: endpoint\ndata: /messages\n\n")
    }))
    .await;
    let (transport, mut events) = transport(&base, SseClientOptions::default());
    transport.start().await.unwrap();
    assert_eq!(
        requests
            .recv()
            .await
            .unwrap()
            .header("mcp-protocol-version"),
        None
    );

    transport.set_protocol_version(Some("2025-06-18".to_owned()));
    streams.end_all();
    match next_event(&mut events).await {
        TransportEvent::Error(message) => assert_eq!(message, "SSE error: undefined"),
        other => panic!("expected an error, got {other:?}"),
    }
    let again = tokio::time::timeout(Duration::from_secs(2), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.method, "GET");
    assert_eq!(again.header("mcp-protocol-version"), Some("2025-06-18"));
    transport.close();
}

#[tokio::test]
async fn reports_a_failed_post_with_its_status_and_body() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, _requests) = serve(Arc::new(move |request: &Recorded| {
        if request.method == "GET" {
            handler_streams.open(ENDPOINT_EVENT)
        } else {
            fixed(500, &[], "boom")
        }
    }))
    .await;
    let (transport, mut events) = transport(&base, SseClientOptions::default());
    transport.start().await.unwrap();

    let error = transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Error POSTing to endpoint (HTTP 500): boom"
    );
    assert!(matches!(
        next_event(&mut events).await,
        TransportEvent::Error(_)
    ));
    transport.close();
}

#[tokio::test]
async fn a_post_redirected_to_another_origin_is_not_followed() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, mut requests) = serve(Arc::new(move |request: &Recorded| {
        if request.method == "GET" {
            handler_streams.open(ENDPOINT_EVENT)
        } else {
            fixed(
                307,
                &[("location", "http://other.example/messages?sessionId=abc")],
                "",
            )
        }
    }))
    .await;
    let (transport, _events) = transport(&base, SseClientOptions::default());
    transport.start().await.unwrap();

    let error = transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Error POSTing to endpoint (HTTP 307): Redirect to http://other.example/messages not followed; \
         use that URL as the endpoint if it is the intended server (redirectPolicy: 'same-origin')"
    );
    let mut posts = 0;
    while let Ok(request) = requests.try_recv() {
        posts += usize::from(request.method == "POST");
    }
    assert_eq!(posts, 1);
    transport.close();
}

#[tokio::test]
async fn a_401_post_whose_sign_in_needs_a_browser_is_unauthorized() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, _requests) = serve(Arc::new(move |request: &Recorded| {
        if request.method == "GET" {
            handler_streams.open(ENDPOINT_EVENT)
        } else {
            fixed(401, &[], "")
        }
    }))
    .await;
    let oauth = FakeOauth::new(Some("stale"), AuthResult::Redirect);
    let (transport, mut events) = transport(
        &base,
        SseClientOptions {
            oauth: Some(Arc::new(Oauth(Arc::clone(&oauth)))),
            ..SseClientOptions::default()
        },
    );
    transport.start().await.unwrap();

    let error = transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "Unauthorized");
    assert_eq!(oauth.calls.lock().unwrap().len(), 1);
    match next_event(&mut events).await {
        TransportEvent::Error(message) => assert_eq!(message, "Unauthorized"),
        other => panic!("expected an error event, got {other:?}"),
    }
    transport.close();
}

#[tokio::test]
async fn send_before_start_is_not_connected() {
    let (transport, _events) = transport("http://127.0.0.1:9", SseClientOptions::default());
    let error = transport
        .send(&json!({"jsonrpc": "2.0", "method": "ping", "id": 1}))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "Not connected");
}

/// A server whose stream and POSTs want `Bearer at-1` and challenge everything else.
async fn protected_server(streams: Streams) -> (String, UnboundedReceiver<Recorded>) {
    serve(Arc::new(move |request: &Recorded| {
        if request.header("authorization") != Some("Bearer at-1") {
            return fixed(
                401,
                &[(
                    "www-authenticate",
                    "Bearer resource_metadata=\"http://127.0.0.1:9/prm\", scope=\"read\"",
                )],
                "no",
            );
        }
        if request.method == "GET" {
            streams.open(ENDPOINT_EVENT)
        } else {
            fixed(202, &[], "")
        }
    }))
    .await
}

#[tokio::test]
async fn signs_in_on_a_401_stream_and_opens_it_again() {
    let (base, _requests) = protected_server(Streams::default()).await;
    let oauth = FakeOauth::new(None, AuthResult::Authorized);
    let (transport, _events) = transport(
        &base,
        SseClientOptions {
            oauth: Some(Arc::new(Oauth(Arc::clone(&oauth)))),
            ..SseClientOptions::default()
        },
    );

    transport.start().await.unwrap();
    let calls = oauth.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].resource_metadata_url.as_deref(),
        Some("http://127.0.0.1:9/prm")
    );
    assert_eq!(calls[0].scope.as_deref(), Some("read"));
    transport.close();
}

#[tokio::test]
async fn sign_in_requests_carry_the_configured_headers() {
    let (base, mut requests) = protected_server(Streams::default()).await;
    let oauth = FakeOauth::new(None, AuthResult::Authorized);
    let (transport, _events) = transport(
        &base,
        SseClientOptions {
            headers: vec![("x-api-key".to_owned(), "secret".to_owned())],
            oauth: Some(Arc::new(Oauth(Arc::clone(&oauth)))),
            ..SseClientOptions::default()
        },
    );
    transport.start().await.unwrap();
    requests.recv().await.unwrap();
    requests.recv().await.unwrap();

    let fetch = oauth
        .fetch
        .lock()
        .unwrap()
        .clone()
        .expect("a fetch for auth()");
    let url = Url::parse(&format!("{base}/.well-known/oauth-protected-resource")).unwrap();
    fetch(reqwest::Request::new(reqwest::Method::GET, url))
        .await
        .unwrap();
    let metadata = requests.recv().await.unwrap();
    assert_eq!(metadata.path, "/.well-known/oauth-protected-resource");
    assert_eq!(metadata.header("x-api-key"), Some("secret"));
    transport.close();
}

#[tokio::test]
async fn a_401_stream_that_needs_a_browser_is_unauthorized_and_the_code_redeems_on_it() {
    let (base, _requests) = protected_server(Streams::default()).await;
    let oauth = FakeOauth::new(None, AuthResult::Redirect);
    let (transport, _events) = transport(
        &base,
        SseClientOptions {
            oauth: Some(Arc::new(Oauth(Arc::clone(&oauth)))),
            ..SseClientOptions::default()
        },
    );

    let error = transport.start().await.unwrap_err();
    assert_eq!(error.to_string(), "Unauthorized");

    // finishAuth reuses the challenge's resource_metadata URL and scope
    let _ = transport.finish_auth("code-1").await;
    let calls = oauth.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].authorization_code.as_deref(), Some("code-1"));
    assert_eq!(
        calls[1].resource_metadata_url.as_deref(),
        Some("http://127.0.0.1:9/prm")
    );
    assert_eq!(calls[1].scope.as_deref(), Some("read"));
}

#[tokio::test]
async fn signs_in_on_a_401_post_and_sends_it_again() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let posts = Arc::new(Mutex::new(0));
    let handler_posts = Arc::clone(&posts);
    let (base, _requests) = serve(Arc::new(move |request: &Recorded| {
        if request.method == "GET" {
            return handler_streams.open(ENDPOINT_EVENT);
        }
        *handler_posts.lock().unwrap() += 1;
        if request.header("authorization") == Some("Bearer at-1") {
            fixed(202, &[], "")
        } else {
            fixed(401, &[("www-authenticate", "Bearer scope=\"write\"")], "")
        }
    }))
    .await;
    let oauth = FakeOauth::new(Some("stale"), AuthResult::Authorized);
    let (transport, _events) = transport(
        &base,
        SseClientOptions {
            oauth: Some(Arc::new(Oauth(Arc::clone(&oauth)))),
            ..SseClientOptions::default()
        },
    );
    transport.start().await.unwrap();

    transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .unwrap();
    assert_eq!(*posts.lock().unwrap(), 2);
    let calls = oauth.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].scope.as_deref(), Some("write"));
    transport.close();
}

#[tokio::test]
async fn a_second_start_is_refused() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, _requests) = serve(Arc::new(move |_: &Recorded| {
        handler_streams.open(ENDPOINT_EVENT)
    }))
    .await;
    let (transport, _events) = transport(&base, SseClientOptions::default());
    transport.start().await.unwrap();
    assert!(
        transport
            .start()
            .await
            .unwrap_err()
            .to_string()
            .contains("already started")
    );
    transport.close();
}

#[tokio::test]
async fn finish_auth_fails_without_a_provider_and_when_the_sign_in_is_not_authorized() {
    let (without_provider, _events) = transport("http://127.0.0.1:9", SseClientOptions::default());
    let error = without_provider.finish_auth("code-1").await.unwrap_err();
    assert_eq!(error.to_string(), "No auth provider");

    let oauth = FakeOauth::new(None, AuthResult::Redirect);
    let (transport, _events) = transport(
        "http://127.0.0.1:9",
        SseClientOptions {
            oauth: Some(Arc::new(Oauth(Arc::clone(&oauth)))),
            ..SseClientOptions::default()
        },
    );
    let error = transport.finish_auth("code-1").await.unwrap_err();
    assert_eq!(error.to_string(), "Failed to authorize");
    let calls = oauth.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].authorization_code.as_deref(), Some("code-1"));
}

#[tokio::test]
async fn a_configured_authorization_header_replaces_the_bearer_token() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, mut requests) = serve(Arc::new(move |_: &Recorded| {
        handler_streams.open(ENDPOINT_EVENT)
    }))
    .await;
    let oauth = FakeOauth::new(Some("at-0"), AuthResult::Authorized);
    let (transport, _events) = transport(
        &base,
        SseClientOptions {
            headers: vec![("authorization".to_owned(), "Bearer custom".to_owned())],
            oauth: Some(Arc::new(Oauth(oauth))),
            ..SseClientOptions::default()
        },
    );

    transport.start().await.unwrap();
    let get = requests.recv().await.unwrap();
    assert_eq!(get.header("authorization"), Some("Bearer custom"));
    transport.close();
}

#[tokio::test]
async fn closing_twice_reports_close_once() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, _requests) = serve(Arc::new(move |_: &Recorded| {
        handler_streams.open(ENDPOINT_EVENT)
    }))
    .await;
    let (transport, mut events) = transport(&base, SseClientOptions::default());
    transport.start().await.unwrap();

    transport.close();
    transport.close();
    assert!(transport.is_closed());
    assert!(matches!(
        next_event(&mut events).await,
        TransportEvent::Close
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn a_stream_that_cannot_connect_rejects_start_with_an_sse_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let (transport, mut events) = transport(&base, SseClientOptions::default());

    let error = transport.start().await.unwrap_err();
    assert!(error.to_string().starts_with("SSE error: "), "{error}");
    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Error(error.to_string())
    );
    transport.close();
}

#[tokio::test]
async fn ignores_events_of_other_types() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, _requests) = serve(Arc::new(move |_: &Recorded| {
        handler_streams.open(ENDPOINT_EVENT)
    }))
    .await;
    let (transport, mut events) = transport(&base, SseClientOptions::default());
    transport.start().await.unwrap();

    streams.push("event: ping\ndata: not json\n\n");
    let notification = json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"});
    streams.push(&format!("event: message\ndata: {notification}\n\n"));
    match next_event(&mut events).await {
        TransportEvent::Message(message) => assert_eq!(message, notification),
        other => panic!("expected a message, got {other:?}"),
    }
    transport.close();
}

#[tokio::test]
async fn a_401_stream_without_a_provider_fails_as_a_non_200_status() {
    let (base, mut requests) = protected_server(Streams::default()).await;
    let (transport, _events) = transport(&base, SseClientOptions::default());

    let error = transport.start().await.unwrap_err();
    assert_eq!(error.to_string(), "SSE error: Non-200 status code (401)");
    requests.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn resolves_a_relative_endpoint_against_the_stream_url_and_follows_a_later_one() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, mut requests) = serve(Arc::new(move |request: &Recorded| {
        if request.method == "GET" {
            handler_streams.open("event: endpoint\ndata: messages?sessionId=1\n\n")
        } else {
            fixed(202, &[], "Accepted")
        }
    }))
    .await;
    let (transport, mut events) = SseClientTransport::new(
        Url::parse(&format!("{base}/api/sse")).unwrap(),
        SseClientOptions::default(),
    );

    transport.start().await.unwrap();
    assert_eq!(
        transport.endpoint().unwrap().as_str(),
        format!("{base}/api/messages?sessionId=1")
    );
    assert_eq!(requests.recv().await.unwrap().path, "/api/sse");

    let ping = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    streams.push(&format!(
        "event: endpoint\ndata: /other?sessionId=2\n\nevent: message\ndata: {ping}\n\n"
    ));
    match next_event(&mut events).await {
        TransportEvent::Message(message) => assert_eq!(message, ping),
        other => panic!("expected a message, got {other:?}"),
    }
    assert_eq!(
        transport.endpoint().unwrap().as_str(),
        format!("{base}/other?sessionId=2")
    );
    transport.send(&ping).await.unwrap();
    assert_eq!(requests.recv().await.unwrap().path, "/other?sessionId=2");
    transport.close();
}

/// A fetch that records the method of every request it carries before sending it.
fn recording_fetch() -> (FetchFn, Arc<Mutex<Vec<String>>>) {
    let methods = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&methods);
    let inner = default_fetch();
    let fetch: FetchFn = Arc::new(move |request| {
        recorded
            .lock()
            .unwrap()
            .push(request.method().as_str().to_owned());
        inner(request)
    });
    (fetch, methods)
}

#[tokio::test]
async fn opens_the_stream_with_the_event_source_fetch_and_posts_with_fetch() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, _requests) = serve(Arc::new(move |request: &Recorded| {
        if request.method == "GET" {
            handler_streams.open(ENDPOINT_EVENT)
        } else {
            fixed(202, &[], "Accepted")
        }
    }))
    .await;
    let (fetch, posted) = recording_fetch();
    let (event_source_fetch, streamed) = recording_fetch();
    let (transport, _events) = transport(
        &base,
        SseClientOptions {
            fetch: Some(fetch),
            event_source_fetch: Some(event_source_fetch),
            ..SseClientOptions::default()
        },
    );

    transport.start().await.unwrap();
    transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .unwrap();
    assert_eq!(*streamed.lock().unwrap(), ["GET"]);
    assert_eq!(*posted.lock().unwrap(), ["POST"]);
    transport.close();
}

#[tokio::test]
async fn opens_the_stream_with_fetch_when_no_event_source_fetch_is_set() {
    let streams = Streams::default();
    let handler_streams = streams.clone();
    let (base, _requests) = serve(Arc::new(move |request: &Recorded| {
        if request.method == "GET" {
            handler_streams.open(ENDPOINT_EVENT)
        } else {
            fixed(202, &[], "Accepted")
        }
    }))
    .await;
    let (fetch, methods) = recording_fetch();
    let (transport, _events) = transport(
        &base,
        SseClientOptions {
            fetch: Some(fetch),
            ..SseClientOptions::default()
        },
    );

    transport.start().await.unwrap();
    transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .unwrap();
    assert_eq!(*methods.lock().unwrap(), ["GET", "POST"]);
    transport.close();
}
