use std::process::Command;

fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rust-mcp-remote"))
        .args(arguments)
        .env(
            "MCP_REMOTE_CONFIG_DIR",
            std::env::temp_dir().join("rust-mcp-remote-main-cli"),
        )
        .output()
        .unwrap()
}

const USAGE: &str = "Usage: mcp-remote <https://server-url> [callback-port] [--debug]";

#[test]
fn prints_the_usage_and_exits_with_zero_for_help() {
    let output = run(&["--help"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{USAGE}\n")
    );
}

#[test]
fn prints_the_version_and_exits_with_zero_for_version() {
    let output = run(&["--version"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "0.1.38\n");
}

#[test]
fn logs_the_usage_and_exits_with_one_without_a_server_url() {
    let output = run(&[]);

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).ends_with(&format!("] {USAGE}\n")));
    assert!(output.stdout.is_empty());
}

#[test]
fn logs_a_fatal_error_and_exits_with_one_for_an_invalid_url() {
    let output = run(&["not a url"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("] Fatal error: Invalid URL"));
}

#[path = "../streamable_http/test_server.rs"]
#[allow(dead_code)]
mod test_server;

#[tokio::test]
async fn proxies_stdio_to_a_streamable_http_server_end_to_end() {
    use std::process::Stdio;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (base, _requests) = test_server::serve(Arc::new(|request| {
        let json = [("content-type", "application/json")];
        if request.method != "POST" {
            return test_server::reply(405, &[], "");
        }
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        match body["method"].as_str() {
            Some("initialize") => test_server::reply(
                200,
                &[json[0], ("mcp-session-id", "session-1")],
                &serde_json::json!({"jsonrpc": "2.0", "id": body["id"], "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "1"}}})
                .to_string(),
            ),
            Some("tools/call") => {
                assert_eq!(request.header("mcp-session-id"), Some("session-1"));
                assert_eq!(request.header("mcp-protocol-version"), Some("2025-06-18"));
                test_server::reply(
                    200,
                    &json,
                    &serde_json::json!({"jsonrpc": "2.0", "id": body["id"], "result": {
                        "content": [{"type": "text", "text": body["params"]["arguments"]["text"]}]}})
                    .to_string(),
                )
            }
            _ => test_server::reply(202, &[], ""),
        }
    }))
    .await;

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rust-mcp-remote"))
        .args([&format!("{base}/mcp"), "--allow-http", "--silent"])
        .env(
            "MCP_REMOTE_CONFIG_DIR",
            std::env::temp_dir().join("rust-mcp-remote-main-cli"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut read_line = async || {
        let line = tokio::time::timeout(std::time::Duration::from_secs(10), stdout.next_line())
            .await
            .expect("timed out waiting for the proxy")
            .unwrap()
            .expect("proxy closed stdout");
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    };

    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}\n")
        .await
        .unwrap();
    assert_eq!(read_line().await["result"]["serverInfo"]["name"], "fake");

    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"hi\"}}}\n")
        .await
        .unwrap();
    let answer = read_line().await;
    assert_eq!(answer["id"], 2);
    assert_eq!(answer["result"]["content"][0]["text"], "hi");

    drop(stdin);
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
        .await
        .expect("proxy did not exit after stdin closed")
        .unwrap();
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
#[ignore = "needs network access to mcp.deepwiki.com"]
async fn connects_to_a_server_that_stalls_get_over_http2_within_eight_seconds() {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rust-mcp-remote"))
        .args(["https://mcp.deepwiki.com/mcp", "--silent"])
        .env(
            "MCP_REMOTE_CONFIG_DIR",
            std::env::temp_dir().join("rust-mcp-remote-main-cli-deepwiki"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();

    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}\n")
        .await
        .unwrap();
    let line = tokio::time::timeout(std::time::Duration::from_secs(8), stdout.next_line())
        .await
        .expect("timed out waiting for DeepWiki")
        .unwrap()
        .expect("proxy closed stdout");
    let answer: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(answer["result"]["serverInfo"]["name"], "DeepWiki");
}

/// Runs the proxy against `url` with stdin held open, and waits up to `limit` for it to exit.
async fn exit_within(
    url: &str,
    extra_arguments: &[&str],
    limit: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    use std::process::Stdio;

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rust-mcp-remote"))
        .arg(url)
        .args(["--allow-http", "--transport", "http-only", "--silent"])
        .args(extra_arguments)
        .env(
            "MCP_REMOTE_CONFIG_DIR",
            std::env::temp_dir().join("rust-mcp-remote-main-cli-network"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(limit, child.wait())
        .await
        .ok()
        .map(Result::unwrap)
}

/// A server that answers every GET with a 404 and hands every POST to `stall`.
async fn stalling_server(
    stall: fn(tokio::net::TcpStream) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>,
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let count = socket.read(&mut buffer).await.unwrap_or(0);
                if buffer[..count].starts_with(b"POST") {
                    stall(socket).await;
                } else {
                    let _ = socket
                        .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                        .await;
                }
            });
        }
    });
    format!("http://{address}/mcp")
}

#[tokio::test]
async fn gives_up_on_a_server_that_never_sends_headers_after_the_headers_timeout() {
    let url = stalling_server(|socket| {
        Box::pin(async move {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            drop(socket);
        })
    })
    .await;

    let status = exit_within(
        &url,
        &["--headers-timeout", "1"],
        std::time::Duration::from_secs(15),
    )
    .await
    .expect("the proxy was still waiting for headers");
    assert_eq!(status.code(), Some(1));
}

#[tokio::test]
async fn gives_up_on_a_body_that_stops_arriving_after_the_body_timeout() {
    let url = stalling_server(|mut socket| {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1000\r\n\r\n{\"jsonrpc\"")
                .await;
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        })
    })
    .await;

    let status = exit_within(
        &url,
        &["--body-timeout", "1"],
        std::time::Duration::from_secs(15),
    )
    .await
    .expect("the proxy was still waiting for the body");
    assert_eq!(status.code(), Some(1));
}

#[tokio::test]
async fn gives_up_on_an_unreachable_host_after_the_connect_timeout() {
    let status = exit_within(
        "http://10.255.255.1/mcp",
        &["--connect-timeout", "1"],
        std::time::Duration::from_secs(20),
    )
    .await
    .expect("the proxy was still connecting");
    assert_eq!(status.code(), Some(1));
}

#[tokio::test]
async fn connects_over_ipv4_only_with_the_ipv4_flag() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    let url = format!("http://localhost:{port}/mcp");
    let limit = std::time::Duration::from_secs(20);

    exit_within(&url, &[], limit).await.expect("the proxy hung");
    assert!(
        connections.load(Ordering::SeqCst) > 0,
        "without --ipv4 the proxy should reach the IPv6 loopback"
    );

    connections.store(0, Ordering::SeqCst);
    exit_within(&url, &["--ipv4"], limit)
        .await
        .expect("the proxy hung");
    assert_eq!(connections.load(Ordering::SeqCst), 0);
}
