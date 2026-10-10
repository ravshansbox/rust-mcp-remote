//! A reconnected SSE stream: the proxy re-handshakes the new session (`onStreamReconnect`).

use super::*;
use rust_mcp_remote::connect::StreamReconnectHook;

const OLD_ENDPOINT: &str = "http://server.example/messages/?session_id=old";
const NEW_ENDPOINT: &str = "http://server.example/messages/?session_id=new";

/// A proxy over an SSE-like server transport, POSTing to the old endpoint.
fn start_sse() -> (Harness, StreamReconnectHook) {
    let slot: StreamReconnectHook = Arc::default();
    let harness = start(ProxyOptions {
        stream_reconnect: Some(Arc::clone(&slot)),
        ..ProxyOptions::default()
    });
    *harness.server.transport.endpoint.lock().unwrap() = Some(OLD_ENDPOINT.to_owned());
    (harness, slot)
}

/// The stream comes back, and the endpoint moves to the new session shortly after.
fn reconnect(harness: &Harness, slot: &StreamReconnectHook) {
    let hook = slot.lock().unwrap().clone().expect("the proxy set no hook");
    hook();
    let endpoint = Arc::clone(&harness.server.transport.endpoint);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        *endpoint.lock().unwrap() = Some(NEW_ENDPOINT.to_owned());
    });
}

/// Completes the lifecycle against the old session.
async fn initialized(harness: &mut Harness) {
    from_client(harness, initialize(json!("1")));
    next(&mut harness.server.sent).await;
    from_server(
        harness,
        json!({"jsonrpc": "2.0", "id": "1", "result": {"protocolVersion": "2025-06-18", "capabilities": {}}}),
    );
    next(&mut harness.client.sent).await;
}

/// Expects the replayed handshake on the new session and answers it.
async fn expect_handshake(harness: &mut Harness) -> Value {
    let handshake = next(&mut harness.server.sent).await;
    assert_eq!(handshake["method"], "initialize");
    assert_eq!(handshake["id"], "mcp-remote-reinit-1");
    assert_eq!(handshake["sentTo"], NEW_ENDPOINT);
    from_server(
        harness,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-reinit-1", "result": {"protocolVersion": "2025-11-25"}}),
    );
    let initialized = next(&mut harness.server.sent).await;
    assert_eq!(initialized["method"], "notifications/initialized");
    assert_eq!(initialized["sentTo"], NEW_ENDPOINT);
    handshake
}

#[tokio::test]
async fn hands_the_new_session_the_handshake_the_old_one_had() {
    let (mut harness, slot) = start_sse();
    initialized(&mut harness).await;

    reconnect(&harness, &slot);

    let handshake = expect_handshake(&mut harness).await;
    assert!(
        handshake["params"]["clientInfo"]["name"]
            .as_str()
            .unwrap()
            .starts_with("client (via mcp-remote")
    );
    assert_eq!(
        harness
            .server
            .transport
            .protocol_version
            .lock()
            .unwrap()
            .as_deref(),
        Some("2025-11-25")
    );
    // The client never sees any of it
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn holds_a_request_that_arrives_mid_handshake_and_leaves_it_alone() {
    let (mut harness, slot) = start_sse();
    initialized(&mut harness).await;

    reconnect(&harness, &slot);
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": "2", "method": "tools/call", "params": {"name": "ping"}}),
    );

    expect_handshake(&mut harness).await;
    let call = next(&mut harness.server.sent).await;
    assert_eq!(call["method"], "tools/call");
    assert_eq!(call["sentTo"], NEW_ENDPOINT);
    // Queued, not in flight, so not failed
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn re_handshakes_once_however_many_requests_are_waiting() {
    let (mut harness, slot) = start_sse();
    initialized(&mut harness).await;

    reconnect(&harness, &slot);
    for (id, name) in [("2", "a"), ("3", "b")] {
        from_client(
            &harness,
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name}}),
        );
    }

    expect_handshake(&mut harness).await;
    let mut calls = [
        next(&mut harness.server.sent).await,
        next(&mut harness.server.sent).await,
    ];
    calls.sort_by_key(|call| call["id"].as_str().unwrap().to_owned());
    assert_eq!(calls[0]["id"], "2");
    assert_eq!(calls[1]["id"], "3");
    assert!(calls.iter().all(|call| call["method"] == "tools/call"));
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn answers_requests_the_vanished_session_can_no_longer_answer() {
    let (mut harness, slot) = start_sse();
    initialized(&mut harness).await;
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": "2", "method": "tools/call", "params": {"name": "ping"}}),
    );
    assert_eq!(next(&mut harness.server.sent).await["sentTo"], OLD_ENDPOINT);

    reconnect(&harness, &slot);

    let failed = next(&mut harness.client.sent).await;
    assert_eq!(failed["id"], "2");
    assert_eq!(failed["error"]["code"], -32001);
    assert_eq!(
        failed["error"]["message"],
        "mcp-remote: the connection to the remote server dropped before this could be answered"
    );
    expect_handshake(&mut harness).await;
}

#[tokio::test]
async fn leaves_a_stream_that_has_never_dropped_alone() {
    let (mut harness, _slot) = start_sse();
    initialized(&mut harness).await;
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": "2", "method": "tools/call", "params": {"name": "ping"}}),
    );
    let call = next(&mut harness.server.sent).await;
    assert_eq!(call["method"], "tools/call");
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn clears_the_hook_when_the_proxy_ends() {
    let (harness, slot) = start_sse();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(slot.lock().unwrap().is_some());
    harness.client.transport.close_transport();
    tokio::time::timeout(Duration::from_secs(5), harness.proxy)
        .await
        .unwrap()
        .unwrap();
    assert!(slot.lock().unwrap().is_none());
}
