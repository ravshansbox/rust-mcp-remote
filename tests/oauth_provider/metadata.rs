//! `OAuthProvider::get_authorization_server_metadata`: it fetches the metadata once and then
//! answers from the cache, but keeps asking while nothing has been found.

use std::sync::Arc;

use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use rust_mcp_remote::oauth_provider::OAuthProvider;
use serde_json::json;

use crate::test_server::{reply, serve};
use crate::use_temporary_config_dir;

fn provider(base: &str, hash: &str) -> OAuthProvider {
    use_temporary_config_dir();
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: format!("{base}/"),
        callback_port: 3334,
        host: "localhost".to_owned(),
        server_url_hash: hash.to_owned(),
        ..Default::default()
    })
    .unwrap();
    OAuthProvider::new(provider, None)
}

#[tokio::test]
async fn fetches_the_metadata_once_and_then_answers_from_the_cache() {
    let (base, mut requests) = serve(Arc::new(|request| {
        if request.path == "/.well-known/oauth-authorization-server" {
            reply(
                200,
                &[("content-type", "application/json")],
                r#"{"issuer":"https://issuer.example","scopes_supported":["mcp"]}"#,
            )
        } else {
            reply(404, &[], "")
        }
    }))
    .await;
    let provider = provider(&base, "metadata-cached");
    let expected = json!({"issuer": "https://issuer.example", "scopes_supported": ["mcp"]});

    assert_eq!(
        provider.get_authorization_server_metadata().await,
        Some(expected.clone())
    );
    assert_eq!(
        provider.get_authorization_server_metadata().await,
        Some(expected.clone())
    );

    let request = requests.try_recv().unwrap();
    assert_eq!(request.path, "/.well-known/oauth-authorization-server");
    assert!(
        requests.try_recv().is_err(),
        "the second call fetched again"
    );
    assert_eq!(
        provider.lock().authorization_server_metadata,
        Some(expected)
    );
}

#[tokio::test]
async fn asks_again_while_no_metadata_has_been_found() {
    let (base, mut requests) = serve(Arc::new(|_| reply(404, &[], ""))).await;
    let provider = provider(&base, "metadata-missing");

    assert_eq!(provider.get_authorization_server_metadata().await, None);
    assert_eq!(provider.get_authorization_server_metadata().await, None);

    let paths: Vec<String> = std::iter::from_fn(|| requests.try_recv().ok())
        .map(|request| request.path)
        .collect();
    let candidates = [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ];
    assert_eq!(paths, [candidates, candidates].concat());
}
