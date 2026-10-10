//! Ports of the setupOAuthCallbackServerWithLongPoll tests in utils.test.ts.

use std::time::Duration;

use rust_mcp_remote::callback_server::{
    AuthCodeResult, AuthEvent, AuthEvents, CallbackServerError, OAuthCallbackServer,
    OAuthCallbackServerOptions, setup_oauth_callback_server_with_long_poll,
};

async fn start(path: &str, events: &AuthEvents, timeout: Option<u64>) -> OAuthCallbackServer {
    setup_oauth_callback_server_with_long_poll(OAuthCallbackServerOptions {
        port: 0,
        path: path.to_owned(),
        events: events.clone(),
        auth_timeout_ms: timeout,
        server_url_hash: "test-hash".to_owned(),
    })
    .await
    .unwrap()
}

async fn get(url: String) -> (u16, String) {
    let response = reqwest::get(url).await.unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

fn code(code: &str, state: Option<&str>) -> AuthCodeResult {
    AuthCodeResult {
        code: code.to_owned(),
        state: state.map(str::to_owned),
        iss: None,
    }
}

#[tokio::test]
async fn binds_an_ephemeral_port_and_reports_it() {
    let server = start("/oauth/callback", &AuthEvents::new(), Some(5000)).await;
    assert!(server.actual_port > 0);
    assert_eq!(server.auth_code(), None);
    // Something is listening on the reported port
    tokio::net::TcpStream::connect(("127.0.0.1", server.actual_port))
        .await
        .unwrap();
}

#[tokio::test]
async fn surfaces_eaddrinuse_instead_of_moving_to_a_random_port() {
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let blocked_port = blocker.local_addr().unwrap().port();
    let error = setup_oauth_callback_server_with_long_poll(OAuthCallbackServerOptions {
        port: blocked_port,
        path: "/oauth/callback".to_owned(),
        events: AuthEvents::new(),
        auth_timeout_ms: None,
        server_url_hash: "test-hash".to_owned(),
    })
    .await
    .err()
    .unwrap();
    assert_eq!(
        error,
        CallbackServerError::AddrInUse {
            requested_port: blocked_port
        }
    );
    assert_eq!(
        error.to_string(),
        format!("Callback port {blocked_port} is already in use")
    );
}

#[tokio::test]
async fn reports_a_denied_authorization_instead_of_waiting_for_a_code() {
    let events = AuthEvents::new();
    let mut emitted = events.subscribe();
    let server = start("/oauth/callback", &events, None).await;
    let settled = tokio::spawn(server.wait_for_auth_code());

    let (status, body) = get(format!(
        "http://127.0.0.1:{}/oauth/callback?error=access_denied&error_description=User%20denied",
        server.actual_port
    ))
    .await;

    assert_eq!(status, 400);
    assert!(body.contains("User denied"));
    let error = settled.await.unwrap().unwrap_err();
    assert!(error.contains("access_denied"), "{error}");
    assert_eq!(
        emitted.recv().await.unwrap(),
        AuthEvent::CodeFailed("Authorization failed: access_denied - User denied".to_owned())
    );
}

#[tokio::test]
async fn answers_an_identity_probe() {
    let server = setup_oauth_callback_server_with_long_poll(OAuthCallbackServerOptions {
        port: 0,
        path: "/oauth/callback".to_owned(),
        events: AuthEvents::new(),
        auth_timeout_ms: None,
        server_url_hash: "a-particular-server".to_owned(),
    })
    .await
    .unwrap();
    let (status, body) = get(format!(
        "http://127.0.0.1:{}/.mcp-remote/id",
        server.actual_port
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"mcpRemote": true, "serverUrlHash": "a-particular-server"})
    );
}

#[tokio::test]
async fn serves_the_callback_on_the_configured_path_only() {
    let events = AuthEvents::new();
    let mut emitted = events.subscribe();
    let server = start("/custom/callback", &events, None).await;
    let (status, _) = get(format!(
        "http://127.0.0.1:{}/custom/callback?code=test-code",
        server.actual_port
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        server.wait_for_auth_code().await,
        Ok(code("test-code", None))
    );
    assert_eq!(
        emitted.recv().await.unwrap(),
        AuthEvent::CodeReceived {
            code: "test-code".to_owned(),
            state: None
        }
    );

    let (status, _) = get(format!(
        "http://127.0.0.1:{}/oauth/callback?code=test-code",
        server.actual_port
    ))
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn hands_each_sign_in_its_own_code() {
    let server = start("/oauth/callback", &AuthEvents::new(), None).await;
    let base = format!("http://127.0.0.1:{}/oauth/callback", server.actual_port);

    get(format!("{base}?code=first&state=s1")).await;
    assert_eq!(
        server.wait_for_auth_code().await,
        Ok(code("first", Some("s1")))
    );

    get(format!("{base}?code=second&state=s2")).await;
    assert_eq!(
        server.wait_for_auth_code().await,
        Ok(code("second", Some("s2")))
    );
}

#[tokio::test]
async fn holds_a_code_that_arrives_before_anyone_is_waiting() {
    let server = start("/oauth/callback", &AuthEvents::new(), None).await;
    get(format!(
        "http://127.0.0.1:{}/oauth/callback?code=early",
        server.actual_port
    ))
    .await;
    assert_eq!(server.wait_for_auth_code().await, Ok(code("early", None)));
}

#[tokio::test]
async fn hands_a_code_to_a_caller_already_waiting_with_its_iss() {
    let server = start("/oauth/callback", &AuthEvents::new(), None).await;
    let waiting = tokio::spawn(server.code_waiter().wait_for_auth_code());
    tokio::time::sleep(Duration::from_millis(20)).await;
    get(format!(
        "http://127.0.0.1:{}/oauth/callback?code=c&state=s&iss=https%3A%2F%2Fas.example",
        server.actual_port
    ))
    .await;
    assert_eq!(
        waiting.await.unwrap(),
        Ok(AuthCodeResult {
            code: "c".to_owned(),
            state: Some("s".to_owned()),
            iss: Some("https://as.example".to_owned()),
        })
    );
    assert_eq!(server.auth_completed().await.code, "c");
}

#[tokio::test]
async fn still_tells_a_sibling_the_sign_in_finished_after_the_code_was_taken() {
    let server = start("/oauth/callback", &AuthEvents::new(), None).await;
    get(format!(
        "http://127.0.0.1:{}/oauth/callback?code=taken",
        server.actual_port
    ))
    .await;
    server.wait_for_auth_code().await.unwrap();
    let (status, _) = get(format!(
        "http://127.0.0.1:{}/wait-for-auth?poll=false",
        server.actual_port
    ))
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn long_poll_answers_202_on_timeout_and_200_when_the_code_arrives() {
    let server = start("/oauth/callback", &AuthEvents::new(), Some(100)).await;
    let port = server.actual_port;
    assert_eq!(
        get(format!("http://127.0.0.1:{port}/wait-for-auth?poll=false"))
            .await
            .0,
        202
    );
    assert_eq!(
        get(format!("http://127.0.0.1:{port}/wait-for-auth"))
            .await
            .0,
        202
    );

    let slow = start("/oauth/callback", &AuthEvents::new(), Some(5000)).await;
    let slow_port = slow.actual_port;
    let poll = tokio::spawn(get(format!("http://127.0.0.1:{slow_port}/wait-for-auth")));
    tokio::time::sleep(Duration::from_millis(100)).await;
    get(format!(
        "http://127.0.0.1:{slow_port}/oauth/callback?code=x"
    ))
    .await;
    assert_eq!(
        poll.await.unwrap(),
        (200, "Authentication completed".to_owned())
    );
}

#[tokio::test]
async fn a_callback_without_a_code_is_a_bad_request() {
    let server = start("/oauth/callback", &AuthEvents::new(), None).await;
    let (status, body) = get(format!(
        "http://127.0.0.1:{}/oauth/callback",
        server.actual_port
    ))
    .await;
    assert_eq!(status, 400);
    assert_eq!(body, "Error: No authorization code received");
}
