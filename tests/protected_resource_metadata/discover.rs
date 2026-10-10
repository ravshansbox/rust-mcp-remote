use std::sync::Arc;

use rust_mcp_remote::protected_resource_metadata::{
    authorization_server_url_of, discover_protected_resource_metadata,
};
use serde_json::json;

use crate::test_server::{RecordedRequest, reply, serve};

fn paths(requests: &mut tokio::sync::mpsc::UnboundedReceiver<RecordedRequest>) -> Vec<String> {
    let mut paths = Vec::new();
    while let Ok(request) = requests.try_recv() {
        paths.push(request.path);
    }
    paths
}

#[tokio::test]
async fn uses_the_resource_metadata_url_from_the_www_authenticate_header() {
    let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
        assert_eq!(request.header("accept"), Some("application/json"));
        assert_eq!(request.header("accept-encoding"), Some("identity"));
        reply(
            200,
            &[("content-type", "application/json")],
            r#"{"resource":"https://mcp.example.com/mcp","authorization_servers":["https://auth.example.com"],"scopes_supported":["read","write"]}"#,
        )
    }))
    .await;

    let header = format!(r#"Bearer resource_metadata="{base}/custom/prm""#);
    let metadata =
        discover_protected_resource_metadata(&format!("{base}/mcp"), Some(&header)).await;

    assert_eq!(
        metadata,
        Some(json!({
            "resource": "https://mcp.example.com/mcp",
            "authorization_servers": ["https://auth.example.com"],
            "scopes_supported": ["read", "write"],
        }))
    );
    assert_eq!(paths(&mut requests), ["/custom/prm"]);
}

#[tokio::test]
async fn falls_back_to_well_known_urls_if_the_header_url_fails() {
    let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.path == "/.well-known/oauth-protected-resource/mcp" {
            reply(
                200,
                &[],
                r#"{"resource":"r","authorization_servers":["https://a"]}"#,
            )
        } else {
            reply(404, &[], "Not Found")
        }
    }))
    .await;

    let header = format!(r#"Bearer resource_metadata="{base}/invalid-url""#);
    let metadata =
        discover_protected_resource_metadata(&format!("{base}/mcp"), Some(&header)).await;

    assert_eq!(
        metadata.as_ref().and_then(authorization_server_url_of),
        Some("https://a")
    );
    assert_eq!(
        paths(&mut requests),
        ["/invalid-url", "/.well-known/oauth-protected-resource/mcp"]
    );
}

#[tokio::test]
async fn tries_the_path_specific_url_first_when_no_header_is_given() {
    let (base, mut requests) = serve(Arc::new(|_: &RecordedRequest| {
        reply(
            200,
            &[],
            r#"{"resource":"r","authorization_servers":["https://a"]}"#,
        )
    }))
    .await;

    let metadata = discover_protected_resource_metadata(&format!("{base}/mcp"), None).await;

    assert!(metadata.is_some());
    assert_eq!(
        paths(&mut requests),
        ["/.well-known/oauth-protected-resource/mcp"]
    );
}

#[tokio::test]
async fn falls_back_to_the_root_well_known_url_if_the_path_specific_one_fails() {
    let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.path == "/.well-known/oauth-protected-resource" {
            reply(
                200,
                &[],
                r#"{"resource":"r","authorization_servers":["https://a"]}"#,
            )
        } else {
            reply(404, &[], "Not Found")
        }
    }))
    .await;

    let metadata = discover_protected_resource_metadata(&format!("{base}/mcp"), None).await;

    assert_eq!(
        metadata,
        Some(json!({"resource": "r", "authorization_servers": ["https://a"]}))
    );
    assert_eq!(
        paths(&mut requests),
        [
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource"
        ]
    );
}

#[tokio::test]
async fn returns_none_if_all_discovery_methods_fail() {
    let (base, _requests) =
        serve(Arc::new(|_: &RecordedRequest| reply(404, &[], "Not Found"))).await;
    assert_eq!(
        discover_protected_resource_metadata(&format!("{base}/mcp"), None).await,
        None
    );
}

#[tokio::test]
async fn handles_network_errors_gracefully() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let metadata =
        discover_protected_resource_metadata(&format!("http://127.0.0.1:{port}/mcp"), None).await;
    assert_eq!(metadata, None);
}

#[tokio::test]
async fn treats_a_falsy_or_unparseable_document_as_not_found() {
    let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.path.ends_with("/mcp") {
            reply(200, &[], "null")
        } else {
            reply(200, &[], "not json")
        }
    }))
    .await;
    assert_eq!(
        discover_protected_resource_metadata(&format!("{base}/mcp"), None).await,
        None
    );
    assert_eq!(paths(&mut requests).len(), 2);
}

#[tokio::test]
async fn parses_supabase_protected_resource_metadata() {
    let document = json!({
        "resource": "https://mcp.supabase.com/mcp",
        "bearer_methods_supported": ["Bearer"],
        "authorization_servers": ["https://api.supabase.com"],
        "resource_documentation": "https://api.supabase.com/api/mcp",
        "resource_name": "Supabase MCP (Beta)",
        "scopes_supported": ["organizations:read", "projects:read", "database:write"],
    });
    let body = document.to_string();
    let (base, mut requests) =
        serve(Arc::new(move |_: &RecordedRequest| reply(200, &[], &body))).await;

    let header = format!(
        r#"Bearer error="invalid_request", error_description="No access token was provided in this request", resource_metadata="{base}/.well-known/oauth-protected-resource/mcp""#
    );
    let metadata = discover_protected_resource_metadata(&format!("{base}/mcp"), Some(&header))
        .await
        .unwrap();

    assert_eq!(metadata, document);
    assert_eq!(
        authorization_server_url_of(&metadata),
        Some("https://api.supabase.com")
    );
    assert_eq!(
        paths(&mut requests),
        ["/.well-known/oauth-protected-resource/mcp"]
    );
}
