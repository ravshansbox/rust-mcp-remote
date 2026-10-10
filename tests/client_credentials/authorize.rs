use std::sync::Arc;

use rust_mcp_remote::client_credentials::authorize_with_client_credentials;
use serde_json::{Value, json};
use url::Url;

use crate::test_server::{RecordedRequest, Reply, reply, serve};

async fn token_server(
    respond: fn(&RecordedRequest) -> Reply,
) -> (Value, tokio::sync::mpsc::UnboundedReceiver<RecordedRequest>) {
    let (base, requests) = serve(Arc::new(respond)).await;
    (
        json!({
            "issuer": base,
            "token_endpoint": format!("{base}/token"),
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
        }),
        requests,
    )
}

#[tokio::test]
async fn posts_the_grant_and_returns_the_tokens() {
    let (metadata, mut requests) = token_server(|_| {
        reply(
            200,
            &[("content-type", "application/json")],
            r#"{"access_token":"cc-1","token_type":"Bearer","expires_in":60,"extra":1}"#,
        )
    })
    .await;

    let tokens = authorize_with_client_credentials(
        &metadata,
        &json!({"client_id": "machine", "client_secret": "s3cret"}),
        Some("read write"),
        Some(&Url::parse("https://mcp.example.com/mcp").unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(
        tokens,
        json!({"access_token": "cc-1", "token_type": "Bearer", "expires_in": 60})
    );

    let request = requests.try_recv().unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/token");
    assert_eq!(
        request.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        request.body,
        "grant_type=client_credentials&client_id=machine&client_secret=s3cret&scope=read+write&resource=https%3A%2F%2Fmcp.example.com%2Fmcp"
    );
}

#[tokio::test]
async fn reports_the_server_error_description() {
    let (metadata, _requests) = token_server(|_| {
        reply(
            401,
            &[("content-type", "application/json")],
            r#"{"error":"invalid_client","error_description":"bad secret"}"#,
        )
    })
    .await;

    let error = authorize_with_client_credentials(
        &metadata,
        &json!({"client_id": "machine", "client_secret": "wrong"}),
        None,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error,
        "The client_credentials token request failed (HTTP 401): bad secret"
    );
}

#[tokio::test]
async fn refuses_a_plain_http_endpoint_before_sending_the_secret() {
    let error = authorize_with_client_credentials(
        &json!({"token_endpoint": "http://idp.example.com/token"}),
        &json!({"client_id": "machine", "client_secret": "s3cret"}),
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .starts_with("Refusing to send the client secret to http://idp.example.com over http.")
    );
}
