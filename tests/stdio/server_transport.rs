use rust_mcp_remote::stdio::{StdioServerTransport, TransportEvent};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn messages_on_stdin_become_events_and_eof_closes() {
    let (mut client_in, server_in) = tokio::io::duplex(1024);
    let (server_out, _client_out) = tokio::io::duplex(1024);
    let (transport, mut events) = StdioServerTransport::start(server_in, server_out, 1024);

    client_in
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\nnoise\n{\"x\":1}\n")
        .await
        .unwrap();
    drop(client_in);

    assert_eq!(
        events.recv().await,
        Some(TransportEvent::Message(
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        ))
    );
    assert!(matches!(
        events.recv().await,
        Some(TransportEvent::Error(_))
    ));
    assert_eq!(events.recv().await, Some(TransportEvent::Close));
    assert!(transport.is_closed());
}

#[tokio::test]
async fn send_writes_one_line_per_message() {
    let (_client_in, server_in) = tokio::io::duplex(1024);
    let (server_out, mut client_out) = tokio::io::duplex(1024);
    let (transport, _events) = StdioServerTransport::start(server_in, server_out, 1024);

    transport
        .send(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
        .await
        .unwrap();
    transport
        .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await
        .unwrap();

    let expected = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
    let mut received = vec![0u8; expected.len()];
    client_out.read_exact(&mut received).await.unwrap();
    assert_eq!(String::from_utf8(received).unwrap(), expected);
}

#[tokio::test]
async fn close_fires_close_once_and_send_then_fails() {
    let (_client_in, server_in) = tokio::io::duplex(1024);
    let (server_out, _client_out) = tokio::io::duplex(1024);
    let (transport, mut events) = StdioServerTransport::start(server_in, server_out, 1024);

    transport.close();
    transport.close();

    assert_eq!(events.recv().await, Some(TransportEvent::Close));
    assert_eq!(
        transport
            .send(&json!({"jsonrpc": "2.0", "method": "x"}))
            .await,
        Err("StdioServerTransport is closed".to_owned())
    );
    drop(transport);
    assert_eq!(events.recv().await, None);
}

#[tokio::test]
async fn an_oversized_message_reports_an_error_and_closes() {
    let (mut client_in, server_in) = tokio::io::duplex(1024);
    let (server_out, _client_out) = tokio::io::duplex(1024);
    let (_transport, mut events) = StdioServerTransport::start(server_in, server_out, 8);

    client_in.write_all(b"0123456789").await.unwrap();

    assert_eq!(
        events.recv().await,
        Some(TransportEvent::Error(
            "ReadBuffer exceeded maximum size of 8 bytes".to_owned()
        ))
    );
    assert_eq!(events.recv().await, Some(TransportEvent::Close));
}
