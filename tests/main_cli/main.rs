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
