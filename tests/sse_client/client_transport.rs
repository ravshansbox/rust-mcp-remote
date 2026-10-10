//! SseClientTransport against a real HTTP server that holds the event stream open.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::Url;
use rust_mcp_remote::auth::{AuthError, AuthOptions, AuthResult};
use rust_mcp_remote::sse_client::{SseClientOptions, SseClientTransport};
use rust_mcp_remote::stdio::TransportEvent;
use rust_mcp_remote::streamable_http::{BoxFuture, TransportOAuth};
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
}

impl FakeOauth {
    fn new(token: Option<&str>, result: AuthResult) -> Arc<Self> {
        Arc::new(Self {
            token: Mutex::new(token.map(str::to_owned)),
            result,
            calls: Mutex::new(Vec::new()),
        })
    }
}

struct Oauth(Arc<FakeOauth>);

impl TransportOAuth for Oauth {
    fn tokens(&self) -> BoxFuture<Option<Value>> {
        let token = self.0.token.lock().unwrap().clone();
        Box::pin(async move { token.map(|token| json!({"access_token": token})) })
    }

    fn auth(&self, options: AuthOptions) -> BoxFuture<Result<AuthResult, AuthError>> {
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
    requests.recv().await.unwrap();

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
