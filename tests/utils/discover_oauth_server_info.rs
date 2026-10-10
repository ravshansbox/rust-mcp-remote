use std::sync::Arc;

use rust_mcp_remote::utils::{OAuthServerDiscoveryResult, discover_oauth_server_info};
use serde_json::json;

use crate::test_server::{RecordedRequest, reply, serve};

#[tokio::test]
async fn skips_oauth_discovery_when_a_client_credentials_token_endpoint_is_explicit() {
    let (base, mut requests) = serve(Arc::new(|_: &RecordedRequest| reply(500, &[], ""))).await;

    let result = discover_oauth_server_info(
        &format!("{base}/mcp"),
        &[],
        Some("https://auth.example.com/oauth/token"),
    )
    .await
    .unwrap();

    assert!(requests.try_recv().is_err());
    assert_eq!(
        result,
        OAuthServerDiscoveryResult {
            authorization_server_url: "https://auth.example.com".to_string(),
            authorization_server_metadata: Some(json!({
                "issuer": "https://auth.example.com",
                "token_endpoint": "https://auth.example.com/oauth/token",
            })),
            ..OAuthServerDiscoveryResult::default()
        }
    );
    assert!(
        discover_oauth_server_info("https://example.com/mcp", &[], Some("not a url"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn follows_the_challenge_to_the_authorization_server_it_names() {
    let (auth_base, _auth_requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.path == "/.well-known/oauth-authorization-server" {
            reply(200, &[], r#"{"issuer":"as","token_endpoint":"as/token"}"#)
        } else {
            reply(404, &[], "")
        }
    }))
    .await;
    let prm = json!({"resource": "mcp", "authorization_servers": [auth_base.clone()]}).to_string();
    let (base, mut requests) = serve(Arc::new(move |request: &RecordedRequest| {
        match request.path.as_str() {
            "/mcp" => reply(
                401,
                &[(
                    "www-authenticate",
                    r#"Bearer resource_metadata="/prm-is-relative", scope="read write""#,
                )],
                "",
            ),
            "/.well-known/oauth-protected-resource/mcp" => reply(200, &[], &prm),
            _ => reply(404, &[], ""),
        }
    }))
    .await;

    let headers = [
        ("X-Custom".to_string(), "1".to_string()),
        ("accept".to_string(), "text/plain".to_string()),
    ];
    let result = discover_oauth_server_info(&format!("{base}/mcp"), &headers, None)
        .await
        .unwrap();

    assert_eq!(result.authorization_server_url, auth_base);
    assert_eq!(
        result.authorization_server_metadata,
        Some(json!({"issuer": "as", "token_endpoint": "as/token"}))
    );
    assert_eq!(
        result.protected_resource_metadata.as_ref().unwrap()["resource"],
        "mcp"
    );
    assert_eq!(result.www_authenticate_scope.as_deref(), Some("read write"));

    let probe = requests.try_recv().unwrap();
    assert_eq!(probe.path, "/mcp");
    assert_eq!(probe.method, "GET");
    assert_eq!(probe.header("x-custom"), Some("1"));
    assert_eq!(
        probe.header("accept"),
        Some("application/json, text/event-stream")
    );
}

#[tokio::test]
async fn uses_the_server_url_as_the_authorization_server_when_the_server_answers_without_auth() {
    let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
        match request.path.as_str() {
            "/mcp" => reply(200, &[], "{}"),
            "/.well-known/oauth-authorization-server/mcp" => {
                reply(200, &[], r#"{"issuer":"self"}"#)
            }
            _ => reply(404, &[], ""),
        }
    }))
    .await;

    let server_url = format!("{base}/mcp");
    let result = discover_oauth_server_info(&server_url, &[], None)
        .await
        .unwrap();

    assert_eq!(
        result,
        OAuthServerDiscoveryResult {
            authorization_server_url: server_url,
            authorization_server_metadata: Some(json!({"issuer": "self"})),
            ..OAuthServerDiscoveryResult::default()
        }
    );
    let mut paths = Vec::new();
    while let Ok(request) = requests.try_recv() {
        paths.push(request.path);
    }
    // No protected resource metadata lookup after an unauthenticated success
    assert_eq!(
        paths,
        ["/mcp", "/.well-known/oauth-authorization-server/mcp"]
    );
}

#[tokio::test]
async fn falls_back_to_the_server_url_when_no_metadata_names_an_authorization_server() {
    let (base, _requests) = serve(Arc::new(|request: &RecordedRequest| {
        match request.path.as_str() {
            "/mcp" => reply(401, &[], ""),
            "/.well-known/oauth-protected-resource" => reply(200, &[], r#"{"resource":"r"}"#),
            _ => reply(404, &[], ""),
        }
    }))
    .await;

    let server_url = format!("{base}/mcp");
    let result = discover_oauth_server_info(&server_url, &[], None)
        .await
        .unwrap();

    assert_eq!(result.authorization_server_url, server_url);
    assert_eq!(result.authorization_server_metadata, None);
    assert_eq!(
        result.protected_resource_metadata,
        Some(json!({"resource": "r"}))
    );
    assert_eq!(result.www_authenticate_scope, None);
}

#[tokio::test]
async fn carries_on_with_discovery_when_the_probe_fails() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let server_url = format!("http://127.0.0.1:{port}/mcp");
    let result = discover_oauth_server_info(&server_url, &[], None)
        .await
        .unwrap();
    assert_eq!(
        result,
        OAuthServerDiscoveryResult {
            authorization_server_url: server_url,
            ..OAuthServerDiscoveryResult::default()
        }
    );
}
