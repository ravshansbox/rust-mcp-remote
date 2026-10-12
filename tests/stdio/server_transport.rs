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

#[tokio::test]
async fn a_failed_write_reports_an_error_and_closes() {
    let (_client_in, server_in) = tokio::io::duplex(1024);
    let (server_out, client_out) = tokio::io::duplex(1024);
    let (transport, mut events) = StdioServerTransport::start(server_in, server_out, 1024);
    drop(client_out);

    let error = transport
        .send(&json!({"jsonrpc": "2.0", "method": "x"}))
        .await
        .unwrap_err();

    assert_eq!(events.recv().await, Some(TransportEvent::Error(error)));
    assert_eq!(events.recv().await, Some(TransportEvent::Close));
    assert!(transport.is_closed());
}

#[tokio::test]
async fn an_invalid_json_rpc_message_is_reported_without_closing() {
    let (mut client_in, server_in) = tokio::io::duplex(1024);
    let (server_out, _client_out) = tokio::io::duplex(1024);
    let (transport, mut events) = StdioServerTransport::start(server_in, server_out, 1024);

    client_in
        .write_all(b"{\"jsonrpc\":\"1.0\"}\n")
        .await
        .unwrap();
    assert_eq!(
        events.recv().await,
        Some(TransportEvent::Error(
            "Invalid JSON-RPC message: {\"jsonrpc\":\"1.0\"}".to_owned()
        ))
    );

    client_in
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n")
        .await
        .unwrap();
    assert_eq!(
        events.recv().await,
        Some(TransportEvent::Message(
            json!({"jsonrpc": "2.0", "method": "ping"})
        ))
    );
    assert!(!transport.is_closed());
}

struct FailingReader;

impl tokio::io::AsyncRead for FailingReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
        _buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("stdin broke")))
    }
}

#[tokio::test]
async fn a_failed_read_reports_the_error_and_closes() {
    let (server_out, _client_out) = tokio::io::duplex(1024);
    let (transport, mut events) = StdioServerTransport::start(FailingReader, server_out, 1024);

    assert_eq!(
        events.recv().await,
        Some(TransportEvent::Error("stdin broke".to_owned()))
    );
    assert_eq!(events.recv().await, Some(TransportEvent::Close));
    assert!(transport.is_closed());
}
