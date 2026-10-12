//! The SDK `Client` surface client.ts uses.

use std::sync::Arc;
use std::time::Duration;

use rust_mcp_remote::client::{CONNECTION_CLOSED, Client, ClientTransport, REQUEST_TIMEOUT};
use rust_mcp_remote::stdio::TransportEvent;
use serde_json::{Value, json};

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
    assert_eq!(
        *pair.protocol_versions.lock().unwrap(),
        [Some("2025-06-18".to_owned())],
        "the transport is told the negotiated version"
    );
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
    assert!(
        pair.protocol_versions.lock().unwrap().is_empty(),
        "the transport is never told an unsupported version"
    );
}

#[tokio::test]
async fn an_error_response_fails_the_request_with_its_code_message_and_data() {
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
            "error": {"code": -32601, "message": "Method not found",
                "data": {"method": "resources/list"}}}),
        ))
        .unwrap();

    let error = request.await.unwrap().unwrap_err();
    assert_eq!(error.code, -32601);
    assert_eq!(error.to_string(), "MCP error -32601: Method not found");
    assert_eq!(error.data, Some(json!({"method": "resources/list"})));
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
    assert_eq!(error.message, "Request timed out");
    assert_eq!(error.data, Some(json!({"timeout": 20})));
    let request = pair.sent.recv().await.unwrap();
    let cancelled = pair.sent.recv().await.unwrap();
    assert_eq!(cancelled["method"], "notifications/cancelled");
    assert_eq!(cancelled["params"]["requestId"], request["id"]);
    assert_eq!(cancelled["params"]["reason"], "Request timed out");
}

#[tokio::test]
async fn a_response_with_an_unknown_id_is_reported_and_ignored() {
    let pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    let (errors_tx, mut errors) = tokio::sync::mpsc::unbounded_channel();
    client.set_on_error(move |error| {
        let _ = errors_tx.send(error.to_owned());
    });

    pair.server
        .send(TransportEvent::Message(
            json!({"jsonrpc": "2.0", "id": 999, "result": {}}),
        ))
        .unwrap();

    assert_eq!(
        errors.recv().await.unwrap(),
        r#"Received a response for an unknown message ID: {"jsonrpc":"2.0","id":999,"result":{}}"#
    );
    assert!(!client.is_closed());
    assert_eq!(
        client.request("tools/list", None).await.unwrap(),
        json!({"tools": [
            {"name": "search", "description": "Search", "inputSchema": {"type": "object"}},
        ]})
    );
}

#[tokio::test]
async fn a_failed_answer_to_a_server_request_is_reported() {
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
    let transport = {
        let events_tx = events_tx.clone();
        ClientTransport {
            send: Arc::new(move |message: Value| {
                let Some(method) = message["method"].as_str() else {
                    return Box::pin(async { Err("pipe closed".to_owned()) });
                };
                let result = match method {
                    "initialize" => Some(json!({
                        "protocolVersion": "2025-06-18", "capabilities": {},
                        "serverInfo": {"name": "stub", "version": "1.0.0"},
                    })),
                    _ => None,
                };
                if let Some(result) = result {
                    let _ = events_tx.send(TransportEvent::Message(
                        json!({"jsonrpc": "2.0", "id": message["id"], "result": result}),
                    ));
                }
                Box::pin(async { Ok(()) })
            }),
            close: Arc::new(|| {}),
            set_protocol_version: Arc::new(|_| {}),
        }
    };
    let client = Client::connect("mcp-remote", "0.0.0", transport, events_rx)
        .await
        .unwrap();
    let (errors_tx, mut errors) = tokio::sync::mpsc::unbounded_channel();
    client.set_on_error(move |error| {
        let _ = errors_tx.send(error.to_owned());
    });

    events_tx
        .send(TransportEvent::Message(
            json!({"jsonrpc": "2.0", "id": "p", "method": "ping"}),
        ))
        .unwrap();

    assert_eq!(
        errors.recv().await.unwrap(),
        "Failed to send response: pipe closed"
    );
    assert!(!client.is_closed());
}

#[tokio::test]
async fn a_request_the_transport_fails_to_send_is_refused_and_forgotten() {
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
    let (failed_tx, mut failed_ids) = tokio::sync::mpsc::unbounded_channel();
    let transport = {
        let events_tx = events_tx.clone();
        ClientTransport {
            send: Arc::new(move |message: Value| {
                if message["method"] == "tools/list" {
                    let _ = failed_tx.send(message["id"].clone());
                    return Box::pin(async { Err("pipe closed".to_owned()) });
                }
                if message["method"] == "initialize" {
                    let _ = events_tx.send(TransportEvent::Message(json!({
                        "jsonrpc": "2.0", "id": message["id"], "result": {
                            "protocolVersion": "2025-06-18", "capabilities": {},
                            "serverInfo": {"name": "stub", "version": "1.0.0"},
                        },
                    })));
                }
                Box::pin(async { Ok(()) })
            }),
            close: Arc::new(|| {}),
            set_protocol_version: Arc::new(|_| {}),
        }
    };
    let client = Client::connect("mcp-remote", "0.0.0", transport, events_rx)
        .await
        .unwrap();
    let (errors_tx, mut errors) = tokio::sync::mpsc::unbounded_channel();
    client.set_on_error(move |error| {
        let _ = errors_tx.send(error.to_owned());
    });

    let error = client.request("tools/list", None).await.unwrap_err();
    assert_eq!(error.code, CONNECTION_CLOSED);
    assert_eq!(error.message, "pipe closed");

    // A late answer finds no pending request left to settle.
    let id = failed_ids.recv().await.unwrap();
    events_tx
        .send(TransportEvent::Message(
            json!({"jsonrpc": "2.0", "id": id, "result": {}}),
        ))
        .unwrap();
    assert!(
        errors
            .recv()
            .await
            .unwrap()
            .starts_with("Received a response for an unknown message ID:")
    );
    assert!(!client.is_closed());
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
    assert_eq!(
        client.request("tools/list", None).await.unwrap(),
        json!({"tools": [
            {"name": "search", "description": "Search", "inputSchema": {"type": "object"}},
        ]})
    );
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

#[tokio::test]
async fn a_request_after_closing_is_refused_without_being_sent() {
    let mut pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    pair.sent.recv().await.unwrap();
    pair.sent.recv().await.unwrap();

    client.close();
    let error = client.request("tools/list", None).await.unwrap_err();

    assert_eq!(error.code, CONNECTION_CLOSED);
    assert_eq!(error.message, "Not connected");
    assert!(
        pair.sent.try_recv().is_err(),
        "nothing reaches the transport"
    );
}
