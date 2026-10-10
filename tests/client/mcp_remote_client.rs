//! client.ts, run as the mcp-remote-client binary.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use crate::test_server;

const USAGE: &str = "Usage: mcp-remote-client <https://server-url> [callback-port] [--debug]";

fn command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-remote-client"));
    command.env(
        "MCP_REMOTE_CONFIG_DIR",
        std::env::temp_dir().join("rust-mcp-remote-client-cli"),
    );
    command
}

#[tokio::test]
async fn prints_its_own_usage_for_help() {
    let output = command().arg("--help").output().await.unwrap();

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{USAGE}\n")
    );
}

#[tokio::test]
async fn lists_the_tools_and_resources_of_a_streamable_http_server_and_exits() {
    let (base, mut requests) = test_server::serve(Arc::new(|request| {
        let json = [("content-type", "application/json")];
        if request.method != "POST" {
            return test_server::reply(405, &[], "");
        }
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        let result = match body["method"].as_str() {
            Some("initialize") => json!({
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "fake", "version": "1"}}),
            Some("tools/list") => json!({"tools": [
                {"name": "search", "inputSchema": {"type": "object"}}]}),
            Some("resources/list") => json!({"resources": [
                {"uri": "file:///notes.txt", "name": "notes"}]}),
            _ => return test_server::reply(202, &[], ""),
        };
        test_server::reply(
            200,
            &json,
            &json!({"jsonrpc": "2.0", "id": body["id"], "result": result}).to_string(),
        )
    }))
    .await;

    let mut child = command()
        .args([&format!("{base}/mcp"), "--allow-http"])
        // Kept open: the end of stdin shuts the client down, as in client.ts.
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // wait_with_output would close it.
    let stdin = child.stdin.take();
    let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .expect("the client did not exit")
        .unwrap();
    drop(stdin);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    for line in [
        "Connected successfully!",
        "Requesting tools list...",
        "Received message:",
        "\"search\"",
        "Requesting resource list...",
        "file:///notes.txt",
        "Exiting OK...",
    ] {
        assert!(stderr.contains(line), "missing {line:?} in {stderr}");
    }
    let mut methods = Vec::new();
    while let Ok(request) = requests.try_recv() {
        if let Ok(body) = serde_json::from_str::<serde_json::Value>(&request.body) {
            methods.push(body["method"].as_str().unwrap_or("").to_owned());
        }
    }
    assert!(methods.contains(&"tools/list".to_owned()), "{methods:?}");
    assert!(
        methods.contains(&"resources/list".to_owned()),
        "{methods:?}"
    );
}

#[tokio::test]
async fn exits_with_one_when_the_server_cannot_be_reached() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let output = tokio::time::timeout(
        Duration::from_secs(20),
        command()
            .args([&format!("http://127.0.0.1:{port}/mcp"), "--allow-http"])
            .stdin(Stdio::piped())
            .output(),
    )
    .await
    .expect("the client did not exit")
    .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Fatal error:"));
}

#[tokio::test]
async fn the_end_of_stdin_shuts_the_client_down() {
    // A server that never answers tools/list, so only the shutdown can end the run.
    let (base, _requests) = test_server::serve(Arc::new(|request| {
        if request.method != "POST" {
            return test_server::reply(405, &[], "");
        }
        let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        if body["method"] != "initialize" {
            // Accepted, with the answer promised on a stream that never opens.
            return test_server::reply(202, &[], "");
        }
        test_server::reply(
            200,
            &[("content-type", "application/json")],
            &json!({"jsonrpc": "2.0", "id": body["id"], "result": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "serverInfo": {"name": "slow", "version": "1"}}})
            .to_string(),
        )
    }))
    .await;

    let output = tokio::time::timeout(
        Duration::from_secs(20),
        command()
            .args([&format!("{base}/mcp"), "--allow-http"])
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .expect("the client did not shut down")
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("Shutting down..."), "{stderr}");
    assert!(stderr.contains("Closing connection..."), "{stderr}");
    assert!(!stderr.contains("Exiting OK..."), "{stderr}");
}

#[tokio::test]
async fn settles_who_owns_the_sign_in_before_connecting_with_client_credentials() {
    let (base, _requests) =
        test_server::serve(Arc::new(|_request| test_server::reply(401, &[], ""))).await;
    let config_dir = std::env::temp_dir().join(format!(
        "rust-mcp-remote-client-cli-credentials-{}",
        std::process::id()
    ));

    let mut child = command()
        .env("MCP_REMOTE_CONFIG_DIR", &config_dir)
        .args([
            &format!("{base}/mcp"),
            "--allow-http",
            "--client-credentials",
            "--static-oauth-client-info",
            r#"{"client_id":"client","client_secret":"secret"}"#,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stdin = child.stdin.take();
    let output = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
        .await
        .expect("the client did not exit")
        .unwrap();
    drop(stdin);
    let _ = std::fs::remove_dir_all(config_dir);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("Initializing auth coordination on-demand"),
        "{stderr}"
    );
}
