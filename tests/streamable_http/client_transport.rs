use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use reqwest::Url;
use rust_mcp_remote::stdio::TransportEvent;
use rust_mcp_remote::streamable_http::{
    ReconnectionOptions, StreamableHttpClientTransport, StreamableHttpOptions, TokenFn,
    TransportError, media_type_essence,
};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::test_server::{RecordedRequest, Reply, reply, serve};

const SSE: (&str, &str) = ("content-type", "text/event-stream");
const JSON: (&str, &str) = ("content-type", "application/json");

fn initialize(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"}}})
}

fn transport(
    base: &str,
    options: StreamableHttpOptions,
) -> (
    StreamableHttpClientTransport,
    UnboundedReceiver<TransportEvent>,
) {
    let url = Url::parse(&format!("{base}/mcp")).unwrap();
    let (transport, events) = StreamableHttpClientTransport::new(url, options);
    transport.start().unwrap();
    (transport, events)
}

async fn next_event(events: &mut UnboundedReceiver<TransportEvent>) -> TransportEvent {
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("timed out waiting for a transport event")
        .expect("event channel closed")
}

async fn next_request(requests: &mut UnboundedReceiver<RecordedRequest>) -> RecordedRequest {
    tokio::time::timeout(Duration::from_secs(5), requests.recv())
        .await
        .expect("timed out waiting for a request")
        .expect("request channel closed")
}

fn handler(
    f: impl Fn(&RecordedRequest) -> Reply + Send + Sync + 'static,
) -> crate::test_server::Handler {
    Arc::new(f)
}

#[tokio::test]
async fn initialize_stores_the_session_and_delivers_a_json_response() {
    let (base, mut requests) = serve(handler(|_| {
        reply(
            200,
            &[JSON, ("mcp-session-id", "session-1")],
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
        )
    }))
    .await;
    let options = StreamableHttpOptions {
        headers: vec![("X-Custom".to_owned(), "yes".to_owned())],
        session_id: Some("stale".to_owned()),
        ..Default::default()
    };
    let (transport, mut events) = transport(&base, options);

    transport.send(&initialize(1)).await.unwrap();

    let request = next_request(&mut requests).await;
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/mcp");
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(
        request.header("accept"),
        Some("application/json, text/event-stream")
    );
    assert_eq!(request.header("x-custom"), Some("yes"));
    assert_eq!(request.header("mcp-session-id"), None);
    assert_eq!(
        serde_json::from_str::<Value>(&request.body).unwrap(),
        initialize(1)
    );
    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Message(json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}}))
    );
    assert_eq!(transport.session_id().as_deref(), Some("session-1"));
}

#[tokio::test]
async fn later_requests_carry_the_session_and_protocol_version() {
    let (base, mut requests) = serve(handler(|_| {
        reply(200, &[JSON], r#"{"jsonrpc":"2.0","id":2,"result":{}}"#)
    }))
    .await;
    let options = StreamableHttpOptions {
        session_id: Some("session-9".to_owned()),
        headers: vec![("Accept".to_owned(), "Text/Plain".to_owned())],
        ..Default::default()
    };
    let (transport, _events) = transport(&base, options);
    transport.set_protocol_version(Some("2025-06-18".to_owned()));

    transport
        .send(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
        .await
        .unwrap();

    let request = next_request(&mut requests).await;
    assert_eq!(request.header("mcp-session-id"), Some("session-9"));
    assert_eq!(request.header("mcp-protocol-version"), Some("2025-06-18"));
    assert_eq!(
        request.header("accept"),
        Some("text/plain, application/json, text/event-stream")
    );
    assert_eq!(request.header("mcp-method"), None);
}

#[tokio::test]
async fn an_enveloped_request_derives_its_headers_from_the_body() {
    let (base, mut requests) = serve(handler(|_| {
        reply(200, &[JSON], r#"{"jsonrpc":"2.0","id":3,"result":{}}"#)
    }))
    .await;
    let (transport, _events) = transport(&base, StreamableHttpOptions::default());
    transport.set_protocol_version(Some("2025-06-18".to_owned()));

    transport
        .send(
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"echo","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}),
        )
        .await
        .unwrap();

    let request = next_request(&mut requests).await;
    assert_eq!(request.header("mcp-protocol-version"), Some("2026-07-28"));
    assert_eq!(request.header("mcp-method"), Some("tools/call"));
    assert_eq!(request.header("mcp-name"), Some("echo"));
}

#[tokio::test]
async fn an_sse_response_delivers_its_messages_and_does_not_reconnect() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let (base, _requests) = serve(handler(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        reply(
            200,
            &[SSE],
            "event: message\nid: e1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n\
             data: {\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{}}\n\n",
        )
    }))
    .await;
    let options = StreamableHttpOptions {
        reconnection: ReconnectionOptions {
            initial_reconnection_delay_ms: 10,
            ..Default::default()
        },
        ..Default::default()
    };
    let (transport, mut events) = transport(&base, options);

    transport
        .send(&json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}))
        .await
        .unwrap();

    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Message(json!({"jsonrpc":"2.0","method":"notifications/progress"}))
    );
    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Message(json!({"jsonrpc":"2.0","id":4,"result":{}}))
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn initialized_opens_the_standalone_stream_and_a_405_is_quiet() {
    let (base, mut requests) = serve(handler(|request| {
        if request.method == "GET" {
            reply(405, &[], "")
        } else {
            reply(202, &[], "")
        }
    }))
    .await;
    let (transport, mut events) = transport(&base, StreamableHttpOptions::default());

    transport
        .send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .await
        .unwrap();

    assert_eq!(next_request(&mut requests).await.method, "POST");
    let get = next_request(&mut requests).await;
    assert_eq!(get.method, "GET");
    assert_eq!(get.header("accept"), Some("text/event-stream"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn a_dropped_standalone_stream_resumes_from_the_last_event_id_then_gives_up() {
    let gets = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&gets);
    let (base, mut requests) = serve(handler(move |request| {
        if request.method == "POST" {
            return reply(202, &[], "");
        }
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            reply(
                200,
                &[SSE],
                "retry: 20\nid: e1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n",
            )
        } else {
            reply(500, &[], "")
        }
    }))
    .await;
    let options = StreamableHttpOptions {
        reconnection: ReconnectionOptions {
            max_retries: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let (transport, mut events) = transport(&base, options);

    transport
        .send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .await
        .unwrap();

    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Message(
            json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"})
        )
    );
    next_request(&mut requests).await;
    next_request(&mut requests).await;
    let resumed = next_request(&mut requests).await;
    assert_eq!(resumed.method, "GET");
    assert_eq!(resumed.header("last-event-id"), Some("e1"));
    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Error("Failed to open SSE stream: Internal Server Error".to_owned())
    );
    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Error(
            "Failed to reconnect SSE stream: Failed to open SSE stream: Internal Server Error"
                .to_owned()
        )
    );
    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Error("Maximum reconnection attempts (1) exceeded.".to_owned())
    );
}

#[tokio::test]
async fn a_401_with_a_token_provider_is_unauthorized_and_the_token_was_sent() {
    let (base, mut requests) = serve(handler(|_| reply(401, &[], "no"))).await;
    let token: TokenFn = Arc::new(|| Box::pin(async { Ok(Some("abc".to_owned())) }));
    let options = StreamableHttpOptions {
        token: Some(token),
        ..Default::default()
    };
    let (transport, mut events) = transport(&base, options);

    let error = transport.send(&initialize(1)).await.unwrap_err();

    assert_eq!(
        error,
        TransportError::Unauthorized("Unauthorized".to_owned())
    );
    assert_eq!(
        next_request(&mut requests).await.header("authorization"),
        Some("Bearer abc")
    );
    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Error("Unauthorized".to_owned())
    );
}

#[tokio::test]
async fn a_failed_post_reports_the_body() {
    let (base, _requests) = serve(handler(|_| reply(500, &[], "boom"))).await;
    let (transport, mut events) = transport(&base, StreamableHttpOptions::default());

    let error = transport.send(&initialize(1)).await.unwrap_err();

    assert_eq!(
        error,
        TransportError::Http {
            status: 500,
            message: "Error POSTing to endpoint: boom".to_owned()
        }
    );
    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Error("Error POSTing to endpoint: boom".to_owned())
    );
}

#[tokio::test]
async fn a_modern_400_error_body_is_delivered_as_the_response() {
    let (base, _requests) = serve(handler(|_| {
        reply(
            400,
            &[JSON],
            r#"{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"bad"}}"#,
        )
    }))
    .await;
    let (transport, mut events) = transport(&base, StreamableHttpOptions::default());

    transport
        .send(
            &json!({"jsonrpc":"2.0","id":5,"method":"tools/list","params":{
            "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}),
        )
        .await
        .unwrap();

    assert_eq!(
        next_event(&mut events).await,
        TransportEvent::Message(
            json!({"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"bad"}})
        )
    );
}

#[tokio::test]
async fn an_unexpected_content_type_is_an_error() {
    let (base, _requests) = serve(handler(|_| {
        reply(200, &[("content-type", "text/html")], "<p>")
    }))
    .await;
    let (transport, _events) = transport(&base, StreamableHttpOptions::default());

    let error = transport.send(&initialize(1)).await.unwrap_err();

    assert_eq!(
        error,
        TransportError::Other("Unexpected content type: text/html".to_owned())
    );
}

#[tokio::test]
async fn follows_a_same_origin_redirect_but_not_a_cross_origin_one() {
    let (base, mut requests) = serve(handler(|request| match request.path.as_str() {
        "/mcp" => reply(307, &[("location", "/moved")], ""),
        "/moved" => reply(307, &[("location", "http://elsewhere.invalid/mcp?x=1")], ""),
        _ => reply(404, &[], ""),
    }))
    .await;
    let (transport, _events) = transport(&base, StreamableHttpOptions::default());

    let error = transport.send(&initialize(1)).await.unwrap_err();

    assert_eq!(next_request(&mut requests).await.path, "/mcp");
    assert_eq!(next_request(&mut requests).await.path, "/moved");
    assert_eq!(
        error.to_string(),
        "Error POSTing to endpoint: Redirect to http://elsewhere.invalid/mcp not followed; \
         use that URL as the endpoint if it is the intended server (redirectPolicy: 'same-origin')"
    );
}

#[tokio::test]
async fn terminate_session_sends_a_delete_and_forgets_the_session() {
    let (base, mut requests) = serve(handler(|_| reply(405, &[], ""))).await;
    let options = StreamableHttpOptions {
        session_id: Some("session-2".to_owned()),
        ..Default::default()
    };
    let (transport, _events) = transport(&base, options);

    transport.terminate_session().await.unwrap();

    let request = next_request(&mut requests).await;
    assert_eq!(request.method, "DELETE");
    assert_eq!(request.header("mcp-session-id"), Some("session-2"));
    assert_eq!(transport.session_id(), None);
    transport.terminate_session().await.unwrap();
}

#[tokio::test]
async fn start_twice_fails_and_close_reports_once() {
    let url = Url::parse("http://127.0.0.1:9/mcp").unwrap();
    let (transport, mut events) =
        StreamableHttpClientTransport::new(url, StreamableHttpOptions::default());
    transport.start().unwrap();
    assert!(
        transport
            .start()
            .unwrap_err()
            .to_string()
            .contains("already started")
    );

    transport.close();
    transport.close();

    assert!(transport.is_closed());
    assert_eq!(next_event(&mut events).await, TransportEvent::Close);
    assert!(events.try_recv().is_err());
}

#[test]
fn media_type_essence_drops_parameters() {
    assert_eq!(
        media_type_essence(Some("Text/Event-Stream; charset=utf-8")).as_deref(),
        Some("text/event-stream")
    );
    assert_eq!(media_type_essence(Some("")), None);
    assert_eq!(media_type_essence(None), None);
}
