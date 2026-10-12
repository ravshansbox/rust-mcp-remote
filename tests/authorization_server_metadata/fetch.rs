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

fn json_reply(body: &serde_json::Value) -> crate::test_server::Reply {
    reply(
        200,
        &[("content-type", "application/json")],
        &body.to_string(),
    )
}

#[tokio::test]
async fn fetches_and_parses_the_metadata() {
    let metadata = json!({
        "issuer": "https://example.com",
        "authorization_endpoint": "https://example.com/oauth/authorize",
        "token_endpoint": "https://example.com/oauth/token",
        "scopes_supported": ["openid", "email", "profile", "custom:read"],
        "response_types_supported": ["code"],
    });
    let served = metadata.clone();
    let (base, mut requests) =
        serve(Arc::new(move |_: &RecordedRequest| json_reply(&served))).await;

    assert_eq!(
        fetch_authorization_server_metadata(&format!("{base}/mcp")).await,
        Some(metadata)
    );
    let request = requests.try_recv().unwrap();
    assert_eq!(request.path, "/.well-known/oauth-authorization-server/mcp");
    assert_eq!(request.header("accept"), Some("application/json"));
    assert_eq!(request.header("accept-encoding"), Some("identity"));
}

#[tokio::test]
async fn falls_back_to_the_root_when_path_insertion_404s() {
    let metadata = json!({"issuer": "https://example.com", "token_endpoint": "https://example.com/oauth/token"});
    let served = metadata.clone();
    let (base, mut requests) = serve(Arc::new(move |request: &RecordedRequest| {
        if request.path == "/.well-known/oauth-authorization-server" {
            json_reply(&served)
        } else {
            reply(404, &[], "Not Found")
        }
    }))
    .await;

    assert_eq!(
        fetch_authorization_server_metadata(&format!("{base}/mcp")).await,
        Some(metadata)
    );
    let mut count = 0;
    while requests.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn reaches_an_oidc_issuer_that_appends_the_well_known_segment() {
    let (base, _requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.path == "/auth/realms/myRealm/.well-known/openid-configuration" {
            json_reply(&json!({"issuer": "realm"}))
        } else {
            reply(404, &[], "Not Found")
        }
    }))
    .await;

    assert_eq!(
        fetch_authorization_server_metadata(&format!("{base}/auth/realms/myRealm")).await,
        Some(json!({"issuer": "realm"}))
    );
}

#[tokio::test]
async fn stops_at_the_first_candidate_that_answers() {
    let (base, mut requests) = serve(Arc::new(|_: &RecordedRequest| {
        json_reply(&json!({"issuer": "https://example.com/mcp"}))
    }))
    .await;

    assert_eq!(
        fetch_authorization_server_metadata(&format!("{base}/mcp")).await,
        Some(json!({"issuer": "https://example.com/mcp"}))
    );
    assert_eq!(
        requests.try_recv().unwrap().path,
        "/.well-known/oauth-authorization-server/mcp"
    );
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn follows_a_redirect_to_the_metadata_document() {
    let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.path == "/.well-known/oauth-authorization-server" {
            reply(302, &[("location", "/moved/metadata.json")], "")
        } else if request.path == "/moved/metadata.json" {
            json_reply(&json!({"issuer": "moved"}))
        } else {
            reply(404, &[], "Not Found")
        }
    }))
    .await;

    assert_eq!(
        fetch_authorization_server_metadata(&base).await,
        Some(json!({"issuer": "moved"}))
    );
    let mut paths = Vec::new();
    while let Ok(request) = requests.try_recv() {
        paths.push(request.path);
    }
    assert_eq!(
        paths,
        [
            "/.well-known/oauth-authorization-server",
            "/moved/metadata.json"
        ]
    );
}

#[tokio::test]
async fn returns_nothing_on_404() {
    let (base, _requests) =
        serve(Arc::new(|_: &RecordedRequest| reply(404, &[], "Not Found"))).await;
    assert_eq!(
        fetch_authorization_server_metadata(&format!("{base}/mcp")).await,
        None
    );
}

#[tokio::test]
async fn returns_nothing_on_other_http_errors() {
    let (base, _requests) = serve(Arc::new(|_: &RecordedRequest| {
        reply(500, &[], "Internal Server Error")
    }))
    .await;
    assert_eq!(
        fetch_authorization_server_metadata(&format!("{base}/mcp")).await,
        None
    );
}

#[tokio::test]
async fn returns_nothing_on_network_errors() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    assert_eq!(
        fetch_authorization_server_metadata(&format!("http://{address}/mcp")).await,
        None
    );
}

#[tokio::test]
async fn returns_nothing_when_every_candidate_times_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    let started = std::time::Instant::now();
    assert_eq!(
        fetch_authorization_server_metadata(&format!("http://{address}")).await,
        None
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(15));
}

#[tokio::test]
async fn keeps_metadata_without_scopes_supported() {
    let metadata = json!({
        "issuer": "https://example.com",
        "authorization_endpoint": "https://example.com/oauth/authorize",
        "token_endpoint": "https://example.com/oauth/token",
    });
    let served = metadata.clone();
    let (base, _requests) = serve(Arc::new(move |_: &RecordedRequest| json_reply(&served))).await;

    let fetched = fetch_authorization_server_metadata(&format!("{base}/mcp"))
        .await
        .unwrap();
    assert_eq!(fetched, metadata);
    assert!(fetched.get("scopes_supported").is_none());
}

#[tokio::test]
async fn keeps_empty_scopes_supported() {
    let metadata = json!({"issuer": "https://example.com", "scopes_supported": []});
    let served = metadata.clone();
    let (base, _requests) = serve(Arc::new(move |_: &RecordedRequest| json_reply(&served))).await;

    let fetched = fetch_authorization_server_metadata(&format!("{base}/mcp"))
        .await
        .unwrap();
    assert_eq!(fetched["scopes_supported"], json!([]));
}

#[tokio::test]
async fn skips_a_candidate_whose_success_body_is_not_json() {
    let (base, mut requests) = serve(Arc::new(|request: &RecordedRequest| {
        if request.path == "/.well-known/oauth-authorization-server/mcp" {
            reply(200, &[("content-type", "application/json")], "not json")
        } else {
            json_reply(&json!({"issuer": "https://example.com"}))
        }
    }))
    .await;

    assert_eq!(
        fetch_authorization_server_metadata(&format!("{base}/mcp")).await,
        Some(json!({"issuer": "https://example.com"}))
    );
    let mut paths = Vec::new();
    while let Ok(request) = requests.try_recv() {
        paths.push(request.path);
    }
    assert_eq!(
        paths,
        [
            "/.well-known/oauth-authorization-server/mcp",
            "/.well-known/oauth-authorization-server",
        ]
    );
}
