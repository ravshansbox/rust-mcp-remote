//! Ports of coordinate-auth.test.ts: deciding who runs the sign-in.

use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::callback_server::{
    AuthEvents, OAuthCallbackServer, OAuthCallbackServerOptions,
    setup_oauth_callback_server_with_long_poll,
};
use rust_mcp_remote::coordination::{
    CoordinatedAuth, coordinate_auth, port_held_by_sibling_for, server_issues_auth_challenge,
};
use rust_mcp_remote::mcp_auth_config::write_json_file;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::run_in_config_dir;

const HASH: &str = "coordinate-test";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Something that is not us, answering every request on a port with the given status.
async fn responder(port: u16, status: u16) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}"
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (port, task)
}

/// Something claiming to be one of us for this server, holding a port.
async fn sibling(port: u16, server_url_hash: &str) -> OAuthCallbackServer {
    setup_oauth_callback_server_with_long_poll(OAuthCallbackServerOptions {
        port,
        path: "/oauth/callback".to_owned(),
        events: AuthEvents::new(),
        auth_timeout_ms: Some(1000),
        server_url_hash: server_url_hash.to_owned(),
    })
    .await
    .unwrap()
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap().port()
}

async fn coordinate(port: u16, patience_ms: u64) -> CoordinatedAuth {
    coordinate_auth(
        HASH,
        "/oauth/callback",
        port,
        &AuthEvents::new(),
        1000,
        false,
        patience_ms,
    )
    .await
    .unwrap()
}

fn live_tokens() -> serde_json::Value {
    json!({ "access_token": "a", "token_type": "Bearer", "expires_at": now_ms() + 3_600_000 })
}

#[test]
fn a_free_port_makes_this_instance_the_owner() {
    run_in_config_dir("mcp-remote-coord", || async {
        let port = free_port();
        let result = coordinate(port, 500).await;
        assert!(!result.skip_browser_auth);
        assert_eq!(result.actual_port, port);
        assert!(result.server.is_some());
    });
}

#[test]
fn a_sibling_on_the_port_makes_this_instance_a_follower() {
    run_in_config_dir("mcp-remote-coord", || async {
        let port = free_port();
        let _sibling = sibling(port, HASH).await;
        write_json_file(HASH, "tokens.json", &live_tokens()).unwrap();

        let result = coordinate(port, 500).await;

        assert!(result.skip_browser_auth);
        assert_eq!(result.actual_port, port);
        assert!(result.server.is_none());
    });
}

#[test]
fn a_stranger_on_the_port_is_stepped_over_not_waited_for() {
    run_in_config_dir("mcp-remote-coord", || async {
        let (port, _stranger) = responder(free_port(), 404).await;

        let result = coordinate(port, 500).await;

        assert!(!result.skip_browser_auth);
        assert!(result.actual_port > port);
    });
}

#[test]
fn a_sibling_holding_an_unusable_token_is_not_mistaken_for_a_finished_sign_in() {
    run_in_config_dir("mcp-remote-coord", || async {
        let port = free_port();
        let _sibling = sibling(port, HASH).await;
        write_json_file(
            HASH,
            "tokens.json",
            &json!({ "access_token": "stale", "token_type": "Bearer", "expires_at": now_ms() - 60_000 }),
        )
        .unwrap();

        let result = coordinate(port, 400).await;

        // It waited instead, then gave up without claiming a sign-in had happened
        assert_eq!(result.actual_port, port);
        let error = result.wait_for_auth_code().await.unwrap_err();
        assert!(error.contains("does not own the sign-in"), "{error}");
    });
}

#[test]
fn giving_up_on_another_instance_does_not_kill_this_one() {
    run_in_config_dir("mcp-remote-coord", || async {
        let port = free_port();
        let _sibling = sibling(port, HASH).await;

        let result = coordinate(port, 400).await;

        assert_eq!(result.actual_port, port);
        assert!(result.skip_browser_auth);
    });
}

#[test]
fn a_sibling_for_a_different_server_is_a_stranger() {
    run_in_config_dir("mcp-remote-coord", || async {
        let port = free_port();
        let _sibling = sibling(port, "some-other-server").await;

        let result = coordinate(port, 500).await;

        assert!(!result.skip_browser_auth);
        assert!(result.actual_port > port);
    });
}

#[test]
fn a_follower_takes_over_when_the_owner_exits() {
    run_in_config_dir("mcp-remote-coord", || async {
        let port = free_port();
        let owner = sibling(port, HASH).await;
        let release = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            owner.shutdown().await;
        });

        let result = coordinate(port, 5000).await;

        release.await.unwrap();
        assert!(!result.skip_browser_auth);
        assert_eq!(result.actual_port, port);
        assert!(result.server.is_some());
    });
}

/// Holds a port and answers 404 to the first identity probe, then claims to be a sibling: the
/// race in which two instances pushed past a stranger each think they won.
async fn late_sibling() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut answered = 0;
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = [0u8; 4096];
            let _ = socket.read(&mut buffer).await;
            let body = if answered == 0 {
                String::new()
            } else {
                json!({ "mcpRemote": true, "serverUrlHash": HASH }).to_string()
            };
            let status = if answered == 0 {
                "404 Not Found"
            } else {
                "200 OK"
            };
            answered += 1;
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    (port, task)
}

#[test]
fn a_later_candidate_yields_to_a_sibling_on_an_earlier_one() {
    run_in_config_dir("mcp-remote-coord", || async {
        let (first, _holder) = late_sibling().await;
        if std::net::TcpListener::bind(("127.0.0.1", first + 1)).is_err() {
            return;
        }
        write_json_file(HASH, "tokens.json", &live_tokens()).unwrap();

        let result = coordinate(first, 500).await;

        // It bound the second candidate, then stood down for the sibling on the first
        assert!(result.skip_browser_auth);
        assert_eq!(result.actual_port, first);
        assert!(result.server.is_none());
        // and released the second candidate it had bound
        std::net::TcpListener::bind(("127.0.0.1", first + 1)).unwrap();
    });
}

#[test]
fn the_identity_probe_tells_siblings_from_strangers() {
    run_in_config_dir("mcp-remote-coord", || async {
        let port = free_port();
        let _sibling = sibling(port, HASH).await;
        assert!(port_held_by_sibling_for(port, HASH).await);
        assert!(!port_held_by_sibling_for(port, "other").await);
        let (stranger_port, _stranger) = responder(0, 404).await;
        assert!(!port_held_by_sibling_for(stranger_port, HASH).await);
        assert!(!port_held_by_sibling_for(free_port(), HASH).await);
    });
}

#[tokio::test]
async fn a_challenge_means_coordinate() {
    let (port, _server) = responder(0, 401).await;
    assert!(server_issues_auth_challenge(&format!("http://127.0.0.1:{port}/mcp"), &[]).await);
}

#[tokio::test]
async fn a_server_that_serves_us_needs_no_coordination() {
    let (port, _server) = responder(0, 200).await;
    assert!(!server_issues_auth_challenge(&format!("http://127.0.0.1:{port}/mcp"), &[]).await);
}

#[tokio::test]
async fn a_server_we_cannot_reach_is_left_to_the_401_handler() {
    assert!(!server_issues_auth_challenge("http://127.0.0.1:9/mcp", &[]).await);
}
