//! Ports the utils.test.ts scenarios under 'Feature: Bridging the modern surfaces a 2025-era
//! client has never heard of' that need the change-notification stream (`openChangeSubscription`).

use super::*;
use rust_mcp_remote::connect::StreamReconnectHook;
use rust_mcp_remote::protocol_era::ProtocolMode;

fn auto() -> ProxyOptions {
    ProxyOptions {
        protocol_mode: ProtocolMode::Auto,
        subscription_reopen_delay: Duration::from_millis(20),
        ..ProxyOptions::default()
    }
}

/// Completes the bridged handshake against a modern server announcing `capabilities`.
async fn bridged(options: ProxyOptions, capabilities: Value) -> Harness {
    let mut harness = start(options);
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "initialize", "id": "init-1", "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"sampling": {}},
            "clientInfo": {"name": "host", "version": "1.0.0"}}}),
    );
    let probe = next(&mut harness.server.sent).await;
    assert_eq!(probe["method"], "server/discover");
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": probe["id"], "result": {
            "supportedVersions": ["2026-07-28"], "capabilities": capabilities}}),
    );
    assert_eq!(next(&mut harness.client.sent).await["id"], "init-1");
    harness
}

async fn next_listen(harness: &mut Harness) -> Value {
    let listen = next(&mut harness.server.sent).await;
    assert_eq!(listen["method"], "subscriptions/listen", "{listen}");
    listen
}

fn subscribe(harness: &Harness, id: &str, uri: &str) {
    from_client(
        harness,
        json!({"jsonrpc": "2.0", "method": "resources/subscribe", "id": id, "params": {"uri": uri}}),
    );
}

/// Expects the local answer to a `resources/subscribe`.
async fn subscribed(harness: &mut Harness, id: &str) {
    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], id);
    assert_eq!(answer["result"], json!({}));
}

async fn expect_cancelled(harness: &mut Harness, listen: &Value) {
    let cancelled = next(&mut harness.server.sent).await;
    assert_eq!(cancelled["method"], "notifications/cancelled");
    assert_eq!(cancelled["params"]["requestId"], listen["id"]);
}

#[tokio::test]
async fn subscribes_to_change_notifications_the_client_will_never_ask_for_itself() {
    let mut harness = bridged(
        auto(),
        json!({"tools": {"listChanged": true}, "resources": {"listChanged": true}}),
    )
    .await;

    let listen = next_listen(&mut harness).await;
    assert_eq!(
        listen["params"]["notifications"],
        json!({"toolsListChanged": true, "resourcesListChanged": true})
    );
    assert_eq!(
        listen["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert!(
        listen["id"]
            .as_str()
            .unwrap()
            .starts_with("mcp-remote-own-")
    );
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn opens_no_stream_for_a_server_that_announces_no_changes() {
    let mut harness = bridged(auto(), json!({"tools": {}})).await;
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn reopens_a_stream_the_server_closed_but_stops_when_it_never_stays_open() {
    let mut harness = bridged(auto(), json!({"tools": {"listChanged": true}})).await;

    // The stream ends cleanly the moment it is opened, every time
    for _ in 0..5 {
        let listen = next_listen(&mut harness).await;
        from_server(
            &harness,
            json!({"jsonrpc": "2.0", "id": listen["id"], "result": {"_meta": {}}}),
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_stream_that_stayed_open_does_not_spend_the_reopen_budget() {
    let mut harness = bridged(
        ProxyOptions {
            subscription_held_open: Duration::ZERO,
            ..auto()
        },
        json!({"tools": {"listChanged": true}}),
    )
    .await;

    for _ in 0..7 {
        let listen = next_listen(&mut harness).await;
        from_server(
            &harness,
            json!({"jsonrpc": "2.0", "id": listen["id"], "result": {"_meta": {}}}),
        );
    }
    next_listen(&mut harness).await;
}

#[tokio::test]
async fn stops_reopening_a_stream_the_server_refused() {
    let mut harness = bridged(auto(), json!({"tools": {"listChanged": true}})).await;
    let listen = next_listen(&mut harness).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": listen["id"], "error": {"code": -32601, "message": "Method not found"}}),
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_resource_subscription_is_honoured_through_the_stream_that_replaced_it() {
    let mut harness = bridged(auto(), json!({"resources": {"subscribe": true}})).await;
    nothing_more(&mut harness.server.sent).await;

    subscribe(&harness, "sub-1", "file:///a");
    subscribed(&mut harness, "sub-1").await;
    let listen = next_listen(&mut harness).await;
    assert_eq!(
        listen["params"]["notifications"],
        json!({"resourceSubscriptions": ["file:///a"]})
    );
}

#[tokio::test]
async fn every_later_resource_subscription_is_honoured_and_the_old_stream_cancelled() {
    let mut harness = bridged(auto(), json!({"resources": {}})).await;

    subscribe(&harness, "s1", "file:///a");
    subscribed(&mut harness, "s1").await;
    let first = next_listen(&mut harness).await;

    subscribe(&harness, "s2", "file:///b");
    subscribed(&mut harness, "s2").await;
    expect_cancelled(&mut harness, &first).await;
    let second = next_listen(&mut harness).await;
    assert_eq!(
        second["params"]["notifications"]["resourceSubscriptions"],
        json!(["file:///a", "file:///b"])
    );

    // The server answers the cancelled stream anyway; that id was never the client's
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": first["id"], "result": {"_meta": {}}}),
    );
    nothing_more(&mut harness.client.sent).await;
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn unsubscribing_the_last_resource_closes_the_stream_and_waits() {
    let mut harness = bridged(auto(), json!({"resources": {}})).await;

    subscribe(&harness, "s1", "file:///a");
    subscribed(&mut harness, "s1").await;
    let listen = next_listen(&mut harness).await;

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "resources/unsubscribe", "id": "u1", "params": {"uri": "file:///a"}}),
    );
    subscribed(&mut harness, "u1").await;
    expect_cancelled(&mut harness, &listen).await;
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_refused_resource_subscription_keeps_the_rest_and_a_later_one_is_tried_again() {
    let mut harness = bridged(
        auto(),
        json!({"tools": {"listChanged": true}, "resources": {}}),
    )
    .await;
    let first = next_listen(&mut harness).await;
    assert_eq!(
        first["params"]["notifications"],
        json!({"toolsListChanged": true})
    );

    subscribe(&harness, "s1", "file:///a");
    subscribed(&mut harness, "s1").await;
    expect_cancelled(&mut harness, &first).await;
    let naming = next_listen(&mut harness).await;
    assert_eq!(
        naming["params"]["notifications"]["resourceSubscriptions"],
        json!(["file:///a"])
    );
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": naming["id"], "error": {"code": -32602, "message": "not that one"}}),
    );

    // It drops the resources and keeps listening for what the server will serve
    let rest = next_listen(&mut harness).await;
    assert_eq!(
        rest["params"]["notifications"],
        json!({"toolsListChanged": true})
    );

    // The refusal was about the resources named then, not every resource ever named
    subscribe(&harness, "s2", "file:///b");
    subscribed(&mut harness, "s2").await;
    expect_cancelled(&mut harness, &rest).await;
    let retried = next_listen(&mut harness).await;
    assert_eq!(
        retried["params"]["notifications"]["resourceSubscriptions"],
        json!(["file:///a", "file:///b"])
    );
}

#[tokio::test]
async fn a_stream_held_at_the_session_barrier_is_cancelled_without_telling_the_server() {
    let slot: StreamReconnectHook = Arc::default();
    let mut harness = bridged(
        ProxyOptions {
            stream_reconnect: Some(Arc::clone(&slot)),
            ..auto()
        },
        json!({"tools": {"listChanged": true}, "resources": {}}),
    )
    .await;
    let first = next_listen(&mut harness).await;

    // The stream comes back, so every later send waits on the handshake repairing the session
    let hook = slot.lock().unwrap().clone().expect("the proxy set no hook");
    hook();

    subscribe(&harness, "s1", "file:///a");
    subscribed(&mut harness, "s1").await;
    expect_cancelled(&mut harness, &first).await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    subscribe(&harness, "s2", "file:///b");
    subscribed(&mut harness, "s2").await;

    // The parked stream was never sent, so there is nothing to cancel on the wire
    nothing_more(&mut harness.server.sent).await;
    assert!(!harness.proxy.is_finished());
}

#[tokio::test]
async fn the_stream_is_not_reopened_once_a_transport_has_closed() {
    let mut harness = bridged(auto(), json!({"tools": {"listChanged": true}})).await;
    next_listen(&mut harness).await;

    harness.client.transport.close_transport();
    tokio::time::timeout(Duration::from_secs(5), &mut harness.proxy)
        .await
        .expect("the proxy did not end")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    nothing_more(&mut harness.server.sent).await;
}
