use std::sync::Arc;

use rust_mcp_remote::utils::{fetch_with_mcp_headers, set_cookies_enabled};

use crate::GLOBAL_STATE;
use crate::test_server::{RecordedRequest, reply, serve};

/// Runs `action` on a fresh runtime with the cookie flag set to `cookies_enabled`, restoring it
/// afterwards. The lock is held outside the runtime so no guard lives across an await.
fn with_cookies_enabled<T>(
    cookies_enabled: bool,
    action: impl std::future::Future<Output = T>,
) -> T {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    set_cookies_enabled(cookies_enabled);
    let result = tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(action);
    set_cookies_enabled(true);
    result
}

/// Serves replies that set a session cookie, sends two requests through the wrapper, and
/// returns what the server saw.
async fn send_twice(first_body: &str, caller_method: Option<&str>) -> Vec<RecordedRequest> {
    let (url, mut requests) = serve(Arc::new(|_| {
        reply(200, &[("set-cookie", "session=abc; Path=/")], "{}")
    }))
    .await;
    let fetch = fetch_with_mcp_headers(None);
    let client = reqwest::Client::new();
    let mut first = client.post(&url).body(first_body.to_owned());
    if let Some(method) = caller_method {
        first = first.header("mcp-method", method);
    }
    fetch(first.build().unwrap()).await.unwrap();
    fetch(client.get(&url).build().unwrap()).await.unwrap();
    vec![
        requests.recv().await.unwrap(),
        requests.recv().await.unwrap(),
    ]
}

#[test]
fn mirrors_the_method_and_name_and_replays_captured_cookies() {
    let seen = with_cookies_enabled(
        true,
        send_twice(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}"#,
            None,
        ),
    );
    assert_eq!(seen[0].header("mcp-method"), Some("tools/call"));
    assert_eq!(seen[0].header("mcp-name"), Some("echo"));
    assert_eq!(seen[0].header("cookie"), None);
    assert_eq!(seen[1].header("mcp-method"), None);
    assert_eq!(seen[1].header("cookie"), Some("session=abc"));
}

#[test]
fn keeps_a_header_the_caller_already_set() {
    let seen = with_cookies_enabled(
        true,
        send_twice(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            Some("custom/method"),
        ),
    );
    assert_eq!(seen[0].header("mcp-method"), Some("custom/method"));
    assert_eq!(seen[0].header("mcp-name"), None);
}

#[test]
fn neither_captures_nor_sends_cookies_when_disabled() {
    let seen = with_cookies_enabled(false, send_twice("not json", None));
    assert_eq!(seen[0].header("mcp-method"), None);
    assert_eq!(seen[1].header("cookie"), None);
}

#[test]
fn a_cookie_header_the_caller_set_wins_over_the_jar() {
    let seen = with_cookies_enabled(true, async {
        let (url, mut requests) = serve(Arc::new(|_| {
            reply(200, &[("set-cookie", "session=abc; Path=/")], "{}")
        }))
        .await;
        let fetch = fetch_with_mcp_headers(None);
        let client = reqwest::Client::new();
        fetch(client.get(&url).build().unwrap()).await.unwrap();
        let own = client.get(&url).header("cookie", "session=mine");
        fetch(own.build().unwrap()).await.unwrap();
        requests.recv().await.unwrap();
        requests.recv().await.unwrap()
    });
    assert_eq!(seen.header("cookie"), Some("session=mine"));
}
