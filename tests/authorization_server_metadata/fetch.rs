use std::sync::Arc;

use rust_mcp_remote::authorization_server_metadata::fetch_authorization_server_metadata;
use serde_json::json;

use crate::test_server::{RecordedRequest, reply, serve};

#[tokio::test]
async fn falls_back_through_the_candidates_to_the_first_document_found() {
    let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.path == "/.well-known/openid-configuration/realms/a" {
            reply(
                200,
                &[("content-type", "application/json")],
                r#"{"issuer":"https://idp.example.com/realms/a","scopes_supported":["openid"]}"#,
            )
        } else {
            reply(404, &[], "not found")
        }
    }))
    .await;

    let metadata = fetch_authorization_server_metadata(&format!("{base}/realms/a/")).await;
    assert_eq!(
        metadata,
        Some(json!({"issuer": "https://idp.example.com/realms/a", "scopes_supported": ["openid"]}))
    );

    let mut paths = Vec::new();
    while let Ok(request) = requests.try_recv() {
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("accept-encoding"), Some("identity"));
        paths.push(request.path);
    }
    assert_eq!(
        paths,
        [
            "/.well-known/oauth-authorization-server/realms/a",
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration/realms/a",
        ]
    );
}

#[tokio::test]
async fn gives_up_quietly_when_nothing_answers() {
    let (base, _requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.path.ends_with("oauth-authorization-server") {
            reply(500, &[], "boom")
        } else {
            reply(200, &[], "not json")
        }
    }))
    .await;
    assert_eq!(fetch_authorization_server_metadata(&base).await, None);
    assert_eq!(fetch_authorization_server_metadata("not a url").await, None);
}
