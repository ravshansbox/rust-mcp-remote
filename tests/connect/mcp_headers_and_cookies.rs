//! utils.test.ts's "Method-aware MCP HTTP gateways", "Load balancer session stickiness" and
//! "Noticing an SSE stream come back" scenarios: what fetchWithMcpHeaders and the SSE stream's
//! fetch add to the requests connectToRemoteServer's transports send.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rust_mcp_remote::auth::{AuthError, AuthOptions, AuthResult};
use rust_mcp_remote::client::Client;
use rust_mcp_remote::connect::{
    AuthInitializer, ConnectOptions, RemoteAuth, RemoteConnection, RemoteTransport,
    connect_client_to_remote_server, connect_to_remote_server,
};
use rust_mcp_remote::protocol_era::ProtocolMode;
use rust_mcp_remote::streamable_http::{BoxFuture, TransportOAuth};
use rust_mcp_remote::utils::{TransportStrategy, encode_mcp_header_value};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::test_server::{RecordedRequest, Reply, reply, serve};

struct NoAuth;

impl TransportOAuth for NoAuth {
    fn tokens(&self) -> BoxFuture<Option<Value>> {
        Box::pin(async { None })
    }

    fn auth(&self, _options: AuthOptions) -> BoxFuture<Result<AuthResult, AuthError>> {
        panic!("the test server should not request OAuth")
    }
}

impl RemoteAuth for NoAuth {
    fn transport_oauth(&self) -> Arc<dyn TransportOAuth> {
        Arc::new(NoAuth)
    }

    fn forget_tokens(&self) -> BoxFuture<Result<(), String>> {
        Box::pin(async { Ok(()) })
    }

    fn use_authorization_state(&self, _state: &str) {}
}

fn no_auth() -> AuthInitializer {
    Arc::new(|_| Box::pin(async { Err("the test server should not request OAuth".to_owned()) }))
}

fn connect_options(
    url: String,
    headers: &[(&str, &str)],
    transport_strategy: TransportStrategy,
) -> ConnectOptions {
    ConnectOptions {
        server_url: url,
        headers: headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
        transport_strategy,
        protocol_mode: ProtocolMode::Legacy,
        non_interactive_flow: false,
    }
}

async fn connect(
    url: String,
    headers: &[(&str, &str)],
    transport_strategy: TransportStrategy,
) -> RemoteConnection {
    let options = connect_options(url, headers, transport_strategy);
    connect_to_remote_server(&NoAuth, &no_auth(), &options)
        .await
        .unwrap()
}

/// Connects a `Client` over an http-only transport, as the TS scenarios do.
async fn connect_client(url: String, headers: &[(&str, &str)]) -> (Client, RemoteTransport) {
    let options = connect_options(url, headers, TransportStrategy::HttpOnly);
    connect_client_to_remote_server(&NoAuth, &no_auth(), &options, "test-client", "1.0.0")
        .await
        .unwrap()
}

/// Answers a Streamable HTTP POST the way createHeaderRecordingServer does.
fn answer(request: &RecordedRequest, extra_headers: &[(&str, &str)]) -> Reply {
    let message: Value = serde_json::from_str(&request.body).unwrap_or(Value::Null);
    if message.get("id").is_none() {
        return reply(202, extra_headers, "");
    }
    let result = if message["method"] == "initialize" {
        json!({"protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
            "serverInfo": {"name": "test-server", "version": "1.0.0"}})
    } else {
        json!({"content": [{"type": "text", "text": "ok"}]})
    };
    let mut headers = vec![("content-type", "application/json")];
    headers.extend_from_slice(extra_headers);
    reply(
        200,
        &headers,
        &json!({"jsonrpc": "2.0", "id": message["id"], "result": result}).to_string(),
    )
}

/// The JSON-RPC method of each POST, with the Mcp-Method and Mcp-Name headers it carried.
type Seen = (String, Option<String>, Option<String>);

fn seen(requests: &mut UnboundedReceiver<RecordedRequest>) -> Vec<Seen> {
    let mut seen = Vec::new();
    while let Ok(request) = requests.try_recv() {
        if request.method != "POST" {
            continue;
        }
        let message: Value = serde_json::from_str(&request.body).unwrap();
        seen.push((
            message["method"].as_str().unwrap().to_owned(),
            request.header("mcp-method").map(str::to_owned),
            request.header("mcp-name").map(str::to_owned),
        ));
    }
    seen
}

fn entry(method: &str, mcp_method: &str, mcp_name: Option<&str>) -> Seen {
    (
        method.to_owned(),
        Some(mcp_method.to_owned()),
        mcp_name.map(str::to_owned),
    )
}

async fn header_recording_server() -> (String, UnboundedReceiver<RecordedRequest>) {
    let (base, requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.method != "POST" {
            return reply(405, &[], "");
        }
        answer(request, &[])
    }))
    .await;
    (format!("{base}/mcp"), requests)
}

#[tokio::test]
async fn the_json_rpc_method_is_mirrored_into_mcp_method() {
    let (url, mut requests) = header_recording_server().await;
    let (_client, transport) = connect_client(url, &[]).await;

    transport
        .send(&json!({"jsonrpc": "2.0", "method": "server/discover", "params": {}}))
        .await
        .unwrap();

    // Then every POST carries the method it is actually sending
    let seen = seen(&mut requests);
    assert_eq!(seen[0], entry("initialize", "initialize", None));
    assert!(seen.contains(&entry("server/discover", "server/discover", None)));
    transport.close();
}

#[tokio::test]
async fn tools_call_also_carries_the_tool_name_in_mcp_name() {
    let (url, mut requests) = header_recording_server().await;
    let (client, transport) = connect_client(url, &[]).await;

    client
        .request(
            "tools/call",
            Some(json!({"name": "get_weather", "arguments": {"location": "Seattle, WA"}})),
        )
        .await
        .unwrap();

    let seen = seen(&mut requests);
    assert!(seen.contains(&entry("tools/call", "tools/call", Some("get_weather"))));
    // And a method that has no Mcp-Name source does not invent one
    assert_eq!(seen[0], entry("initialize", "initialize", None));
    transport.close();
}

#[tokio::test]
async fn the_http_first_probe_carries_the_headers_too() {
    let (url, mut requests) = header_recording_server().await;
    let connection = connect(url, &[], TransportStrategy::HttpFirst).await;

    // The probe sends the very request a method-aware gateway routes on
    assert_eq!(
        seen(&mut requests)[0],
        entry("initialize", "initialize", None)
    );
    connection.transport.close();
}

#[tokio::test]
async fn resources_read_sources_mcp_name_from_params_uri() {
    let (url, mut requests) = header_recording_server().await;
    let (_client, transport) = connect_client(url, &[]).await;

    for message in [
        json!({"jsonrpc": "2.0", "method": "resources/read", "params": {"uri": "file:///app/config.json"}}),
        json!({"jsonrpc": "2.0", "method": "prompts/get", "params": {"name": "summarize"}}),
        // A URI RFC 9110 cannot carry verbatim has to survive the trip encoded
        json!({"jsonrpc": "2.0", "method": "resources/read", "params": {"uri": "file:///projects/世界.json"}}),
    ] {
        transport.send(&message).await.unwrap();
    }

    let seen = seen(&mut requests);
    assert!(seen.contains(&entry(
        "resources/read",
        "resources/read",
        Some("file:///app/config.json")
    )));
    assert!(seen.contains(&entry("prompts/get", "prompts/get", Some("summarize"))));
    assert!(seen.contains(&entry(
        "resources/read",
        "resources/read",
        Some(&encode_mcp_header_value("file:///projects/世界.json"))
    )));
    transport.close();
}

#[tokio::test]
async fn an_explicitly_passed_header_is_not_overwritten() {
    let (url, mut requests) = header_recording_server().await;
    let (_client, transport) = connect_client(url, &[("Mcp-Method", "pinned-by-user")]).await;

    assert_eq!(
        seen(&mut requests)[0],
        entry("initialize", "pinned-by-user", None)
    );
    transport.close();
}

/// createStickyServer: plants a routing cookie on the first response and records the Cookie
/// header of every request.
async fn sticky_server() -> (String, UnboundedReceiver<RecordedRequest>) {
    let responses = Arc::new(AtomicUsize::new(0));
    let (base, requests) = serve(Arc::new(move |request: &RecordedRequest| {
        if responses.fetch_add(1, Ordering::SeqCst) == 0 {
            answer(
                request,
                &[
                    ("set-cookie", "AWSALB=node-1; Path=/"),
                    ("set-cookie", "AWSALBCORS=node-1; Path=/; SameSite=None"),
                ],
            )
        } else {
            answer(request, &[])
        }
    }))
    .await;
    (format!("{base}/mcp"), requests)
}

fn cookies_seen(requests: &mut UnboundedReceiver<RecordedRequest>) -> Vec<Option<String>> {
    let mut cookies = Vec::new();
    while let Ok(request) = requests.try_recv() {
        cookies.push(request.header("cookie").map(str::to_owned));
    }
    cookies
}

#[tokio::test]
async fn a_cookie_the_server_sets_is_sent_back_on_every_later_request() {
    let (url, mut requests) = sticky_server().await;
    let (_client, transport) = connect_client(url, &[]).await;
    transport
        .send(&json!({"jsonrpc": "2.0", "method": "server/discover", "id": 2, "params": {}}))
        .await
        .unwrap();

    // Then the first request could not have carried one, and everything after it does
    let cookies = cookies_seen(&mut requests);
    assert_eq!(cookies[0], None);
    assert!(cookies.len() > 1);
    for cookie in &cookies[1..] {
        assert_eq!(cookie.as_deref(), Some("AWSALB=node-1; AWSALBCORS=node-1"));
    }
    transport.close();
}

#[tokio::test]
async fn a_header_the_user_pinned_is_not_overwritten_by_the_jar() {
    let (url, mut requests) = sticky_server().await;
    let (_client, transport) = connect_client(url, &[("Cookie", "pinned=by-the-user")]).await;
    transport
        .send(&json!({"jsonrpc": "2.0", "method": "server/discover", "id": 2, "params": {}}))
        .await
        .unwrap();

    for cookie in cookies_seen(&mut requests) {
        assert_eq!(cookie.as_deref(), Some("pinned=by-the-user"));
    }
    transport.close();
}

/// createSseServer: every stream it serves plants its own cookie and hands out a POST endpoint
/// with a session of its own. The test server ends each stream once it is written, so a
/// `retry` of 10 ms makes the EventSource come straight back for another.
async fn sse_server(
    retry_ms: u64,
) -> (String, UnboundedReceiver<RecordedRequest>, Arc<AtomicUsize>) {
    let streams_served = Arc::new(AtomicUsize::new(0));
    let served = Arc::clone(&streams_served);
    let (base, requests) = serve(Arc::new(move |request: &RecordedRequest| {
        if !request.path.starts_with("/sse") {
            return reply(202, &[], "");
        }
        let served = served.fetch_add(1, Ordering::SeqCst) + 1;
        let cookie = format!("AWSALB=node-{served}; Path=/");
        reply(
            200,
            &[
                ("content-type", "text/event-stream"),
                ("set-cookie", &cookie),
            ],
            &format!(
                "retry: {retry_ms}\n\nevent: endpoint\ndata: /messages/?session_id={served}\n\n"
            ),
        )
    }))
    .await;
    (format!("{base}/sse"), requests, streams_served)
}

fn count_reconnects(connection: &RemoteConnection) -> Arc<AtomicUsize> {
    let reconnected = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reconnected);
    *connection.on_stream_reconnect.lock().unwrap() = Some(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    reconnected
}

#[tokio::test]
async fn a_stream_that_drops_and_reconnects_is_reported_to_the_proxy() {
    let (url, _requests, streams_served) = sse_server(10).await;
    let connection = connect(url, &[], TransportStrategy::SseOnly).await;
    let reconnected = count_reconnects(&connection);

    tokio::time::timeout(Duration::from_secs(5), async {
        while reconnected.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the reconnected stream was not reported");
    assert!(streams_served.load(Ordering::SeqCst) > 1);
    connection.transport.close();
}

#[tokio::test]
async fn a_cookie_set_on_the_stream_rides_the_posts_that_follow_it() {
    let (url, mut requests, _) = sse_server(60_000).await;
    let connection = connect(url, &[], TransportStrategy::SseOnly).await;
    connection
        .transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .unwrap();

    let mut post_cookies = Vec::new();
    while let Ok(request) = requests.try_recv() {
        if request.method == "POST" {
            post_cookies.push(request.header("cookie").map(str::to_owned));
        }
    }
    assert_eq!(post_cookies, vec![Some("AWSALB=node-1".to_owned())]);
    connection.transport.close();
}

#[tokio::test]
async fn the_first_connection_is_not_a_reconnection() {
    let (url, _requests, streams_served) = sse_server(60_000).await;
    let connection = connect(url, &[], TransportStrategy::SseOnly).await;
    let reconnected = count_reconnects(&connection);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(reconnected.load(Ordering::SeqCst), 0);
    assert_eq!(streams_served.load(Ordering::SeqCst), 1);
    connection.transport.close();
}
