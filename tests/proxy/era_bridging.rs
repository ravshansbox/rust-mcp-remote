//! Ports the utils.test.ts scenarios under 'Feature: Bridging a legacy client to a 2026-07-28
//! server', plus the parts of the modern-surface bridging that need no subscription stream.

use super::*;
use rust_mcp_remote::protocol_era::ProtocolMode;

fn legacy_initialize() -> Value {
    json!({"jsonrpc": "2.0", "method": "initialize", "id": "init-1", "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {"roots": {}},
        "clientInfo": {"name": "desktop-host", "version": "0.1.0"}}})
}

fn discover_result() -> Value {
    json!({"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}})
}

fn auto() -> ProxyOptions {
    ProxyOptions {
        protocol_mode: ProtocolMode::Auto,
        ..ProxyOptions::default()
    }
}

/// Sends the handshake, answers the probe with `result`, and returns what the client was told.
async fn handshake(harness: &mut Harness, result: Value) -> Value {
    from_client(harness, legacy_initialize());
    let probe = next(&mut harness.server.sent).await;
    assert_eq!(probe["method"], "server/discover");
    from_server(
        harness,
        json!({"jsonrpc": "2.0", "id": probe["id"], "result": result}),
    );
    next(&mut harness.client.sent).await
}

#[tokio::test]
async fn the_handshake_is_answered_here_from_what_server_discover_advertised() {
    let mut harness = start(auto());
    let answer = handshake(&mut harness, discover_result()).await;

    assert_eq!(answer["id"], "init-1");
    assert_eq!(answer["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(answer["result"]["capabilities"], json!({"tools": {}}));
    nothing_more(&mut harness.server.sent).await;
    assert_eq!(
        harness
            .server
            .transport
            .protocol_version
            .lock()
            .unwrap()
            .as_deref(),
        Some("2026-07-28")
    );
}

#[tokio::test]
async fn every_request_after_the_handshake_carries_the_metadata_the_server_requires() {
    let mut harness = start(auto());
    handshake(&mut harness, discover_result()).await;

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "tools/call", "id": "call-1", "params": {"name": "search"}}),
    );
    let call = next(&mut harness.server.sent).await;
    assert_eq!(call["method"], "tools/call");
    let meta = &call["params"]["_meta"];
    assert_eq!(
        meta["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert_eq!(
        meta["io.modelcontextprotocol/clientCapabilities"],
        json!({"roots": {}})
    );
    assert!(
        meta["io.modelcontextprotocol/clientInfo"]["name"]
            .as_str()
            .unwrap()
            .contains("desktop-host")
    );
}

#[tokio::test]
async fn requests_sent_before_the_probe_answers_still_go_out_written_correctly() {
    let mut harness = start(auto());
    from_client(&harness, legacy_initialize());
    let probe = next(&mut harness.server.sent).await;
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "tools/list", "id": "list-1", "params": {}}),
    );

    // Nothing goes out while the era is still unknown
    nothing_more(&mut harness.server.sent).await;

    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": probe["id"], "result": discover_result()}),
    );
    let list = next(&mut harness.server.sent).await;
    assert_eq!(list["method"], "tools/list");
    assert_eq!(
        list["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
}

#[tokio::test]
async fn a_server_that_never_heard_of_server_discover_gets_the_handshake_it_was_always_sent() {
    let mut harness = start(auto());
    from_client(&harness, legacy_initialize());
    let probe = next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": probe["id"], "error": {"code": -32601, "message": "Method not found"}}),
    );

    let forwarded = next(&mut harness.server.sent).await;
    assert_eq!(forwarded["method"], "initialize");
    assert!(forwarded["params"].get("_meta").is_none());
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn a_probe_that_is_never_answered_falls_back_to_the_handshake() {
    let mut harness = start(ProxyOptions {
        discover_timeout: Duration::from_millis(50),
        ..auto()
    });
    from_client(&harness, legacy_initialize());
    assert_eq!(
        next(&mut harness.server.sent).await["method"],
        "server/discover"
    );
    assert_eq!(next(&mut harness.server.sent).await["method"], "initialize");
}

#[tokio::test]
async fn left_alone_entirely_unless_asked_for() {
    let mut harness = start(ProxyOptions::default());
    from_client(&harness, legacy_initialize());
    assert_eq!(next(&mut harness.server.sent).await["method"], "initialize");
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_handshake_repeated_during_the_probe_starts_no_second_probe() {
    let mut harness = start(auto());
    from_client(&harness, legacy_initialize());
    let probe = next(&mut harness.server.sent).await;
    from_client(&harness, legacy_initialize());
    nothing_more(&mut harness.server.sent).await;

    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": probe["id"], "result": discover_result()}),
    );
    // Both are answered from the bridge, and neither reaches the server
    assert_eq!(next(&mut harness.client.sent).await["id"], "init-1");
    assert_eq!(next(&mut harness.client.sent).await["id"], "init-1");
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn the_notification_that_closed_the_old_handshake_is_not_put_on_the_wire() {
    let mut harness = start(auto());
    handshake(&mut harness, discover_result()).await;

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "tools/list", "id": "list-1", "params": {}}),
    );
    assert_eq!(next(&mut harness.server.sent).await["method"], "tools/list");
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_liveness_check_is_answered_here() {
    let mut harness = start(auto());
    handshake(&mut harness, discover_result()).await;

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "ping", "id": "ping-1"}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": "ping-1", "result": {}})
    );
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_modern_result_is_handed_over_in_terms_the_client_understands() {
    let mut harness = start(auto());
    handshake(&mut harness, discover_result()).await;

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "tools/list", "id": "list-1", "params": {}}),
    );
    next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": "list-1", "result": {"resultType": "complete", "tools": [{"name": "search"}]}}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await["result"],
        json!({"tools": [{"name": "search"}]})
    );
}

#[tokio::test]
async fn a_server_that_speaks_only_revisions_this_proxy_does_not_is_reported() {
    let mut harness = start(auto());
    let answer = handshake(
        &mut harness,
        json!({"supportedVersions": ["2099-01-01"], "capabilities": {}}),
    )
    .await;
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap()
            .contains("2099-01-01")
    );
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_requested_log_level_is_carried_on_every_later_request() {
    let mut harness = start(auto());
    handshake(&mut harness, discover_result()).await;

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "logging/setLevel", "id": "lvl-1", "params": {"level": "debug"}}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": "lvl-1", "result": {}})
    );
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "tools/list", "id": "list-1", "params": {}}),
    );
    let list = next(&mut harness.server.sent).await;
    assert_eq!(list["method"], "tools/list");
    assert_eq!(
        list["params"]["_meta"]["io.modelcontextprotocol/logLevel"],
        "debug"
    );
}

#[tokio::test]
async fn subscription_confirmations_are_consumed_and_subscription_ids_stripped() {
    let mut harness = start(auto());
    handshake(&mut harness, discover_result()).await;

    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged", "params": {"notifications": {}}}),
    );
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {
            "_meta": {"io.modelcontextprotocol/subscriptionId": "sub-1"}}}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {}})
    );
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn keep_alive_sends_no_pings_to_a_modern_server() {
    let mut harness = start(ProxyOptions {
        keep_alive: Some(Duration::from_millis(100)),
        ..auto()
    });
    handshake(&mut harness, discover_result()).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    nothing_more(&mut harness.server.sent).await;
}
