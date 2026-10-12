//! The SDK `Client` surface client.ts uses.

use std::sync::Arc;
use std::time::Duration;

use rust_mcp_remote::client::{CONNECTION_CLOSED, REQUEST_TIMEOUT};
use rust_mcp_remote::stdio::TransportEvent;
use serde_json::json;

use crate::pair::{connected_pair, tools_server};

#[tokio::test]
async fn connecting_initializes_and_then_announces_it() {
    let mut pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();

    let initialize = pair.sent.recv().await.unwrap();
    assert_eq!(initialize["method"], "initialize");
    assert_eq!(initialize["params"]["protocolVersion"], "2025-11-25");
    assert_eq!(initialize["params"]["capabilities"], json!({}));
    assert_eq!(
        initialize["params"]["clientInfo"],
        json!({"name": "mcp-remote", "version": "0.0.0"})
    );
    let initialized = pair.sent.recv().await.unwrap();
    assert_eq!(
        initialized,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
    );
    assert_eq!(client.server_version().unwrap()["name"], "stub");
}

#[tokio::test]
async fn an_unsupported_protocol_version_fails_the_connection() {
    let pair = connected_pair(Arc::new(|message| {
        (message["method"] == "initialize").then(|| {
            json!({"protocolVersion": "1999-01-01", "capabilities": {},
                "serverInfo": {"name": "old", "version": "1"}})
        })
    }))
    .await;

    let error = pair.client.err().unwrap();
    assert_eq!(
        error.message,
        "Server's protocol version is not supported: 1999-01-01"
    );
    assert_eq!(
        pair.closes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the transport is closed"
    );
}

#[tokio::test]
async fn an_error_response_fails_the_request_with_its_code_and_message() {
    let mut pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    pair.sent.recv().await.unwrap();
    pair.sent.recv().await.unwrap();

    let request = tokio::spawn({
        let client = client.clone();
        async move { client.request("resources/list", None).await }
    });
    let sent = pair.sent.recv().await.unwrap();
    pair.server
        .send(TransportEvent::Message(
            json!({"jsonrpc": "2.0", "id": sent["id"],
            "error": {"code": -32601, "message": "Method not found"}}),
        ))
        .unwrap();

    let error = request.await.unwrap().unwrap_err();
    assert_eq!(error.code, -32601);
    assert_eq!(error.to_string(), "MCP error -32601: Method not found");
}

#[tokio::test]
async fn the_server_s_ping_is_answered_and_other_requests_are_refused() {
    let mut pair = connected_pair(tools_server()).await;
    let _client = pair.client.unwrap();
    pair.sent.recv().await.unwrap();
    pair.sent.recv().await.unwrap();

    pair.server
        .send(TransportEvent::Message(
            json!({"jsonrpc": "2.0", "id": "p", "method": "ping"}),
        ))
        .unwrap();
    assert_eq!(
        pair.sent.recv().await.unwrap(),
        json!({"jsonrpc": "2.0", "id": "p", "result": {}})
    );

    pair.server
        .send(TransportEvent::Message(
            json!({"jsonrpc": "2.0", "id": 7, "method": "sampling/createMessage"}),
        ))
        .unwrap();
    let refusal = pair.sent.recv().await.unwrap();
    assert_eq!(refusal["id"], 7);
    assert_eq!(refusal["error"]["code"], -32601);
}

#[tokio::test]
async fn a_closed_connection_fails_the_requests_in_flight() {
    let mut pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    pair.sent.recv().await.unwrap();
    pair.sent.recv().await.unwrap();

    let request = tokio::spawn({
        let client = client.clone();
        async move { client.request("resources/list", None).await }
    });
    pair.sent.recv().await.unwrap();
    pair.server.send(TransportEvent::Close).unwrap();

    let error = request.await.unwrap().unwrap_err();
    assert_eq!(error.code, CONNECTION_CLOSED);
    assert!(client.is_closed());
    assert_eq!(
        client.request("tools/list", None).await.unwrap_err().code,
        CONNECTION_CLOSED
    );
}

#[tokio::test]
async fn a_request_that_times_out_is_cancelled() {
    let mut pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    pair.sent.recv().await.unwrap();
    pair.sent.recv().await.unwrap();

    let error = client
        .request_with_timeout("resources/list", None, Duration::from_millis(20))
        .await
        .unwrap_err();

    assert_eq!(error.code, REQUEST_TIMEOUT);
    let request = pair.sent.recv().await.unwrap();
    let cancelled = pair.sent.recv().await.unwrap();
    assert_eq!(cancelled["method"], "notifications/cancelled");
    assert_eq!(cancelled["params"]["requestId"], request["id"]);
}

#[tokio::test]
async fn a_notification_carries_no_id_and_only_the_params_it_was_given() {
    let mut pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    pair.sent.recv().await.unwrap();
    pair.sent.recv().await.unwrap();

    client.notify("notifications/progress", None).await.unwrap();
    client
        .notify("notifications/message", Some(json!({"level": "info"})))
        .await
        .unwrap();

    assert_eq!(
        pair.sent.recv().await.unwrap(),
        json!({"jsonrpc": "2.0", "method": "notifications/progress"})
    );
    assert_eq!(
        pair.sent.recv().await.unwrap(),
        json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}})
    );
}

#[tokio::test]
async fn a_transport_error_reaches_the_error_hook_without_closing_the_client() {
    let pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    let (errors_tx, mut errors) = tokio::sync::mpsc::unbounded_channel();
    client.set_on_error(move |error| {
        let _ = errors_tx.send(error.to_owned());
    });

    pair.server
        .send(TransportEvent::Error("stream reset".to_owned()))
        .unwrap();

    assert_eq!(errors.recv().await.unwrap(), "stream reset");
    assert!(!client.is_closed());
    assert!(client.request("tools/list", None).await.is_ok());
}

#[tokio::test]
async fn closing_the_client_fails_requests_in_flight_and_calls_the_close_hook_once() {
    let mut pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    pair.sent.recv().await.unwrap();
    pair.sent.recv().await.unwrap();
    let (hook_tx, mut hook_calls) = tokio::sync::mpsc::unbounded_channel();
    client.set_on_close(move || {
        let _ = hook_tx.send(());
    });

    let request = tokio::spawn({
        let client = client.clone();
        async move { client.request("resources/list", None).await }
    });
    pair.sent.recv().await.unwrap();
    client.close();
    client.close();

    assert_eq!(request.await.unwrap().unwrap_err().code, CONNECTION_CLOSED);
    hook_calls.recv().await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(hook_calls.try_recv().is_err());
    assert_eq!(
        pair.closes.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "each close() closes the transport"
    );
}
