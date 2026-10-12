use rust_mcp_remote::mcp_auth_config::write_json_file;
use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use serde_json::json;

use crate::with_temporary_config_dir;

const HASH: &str = "scope-to-repeat-on-refresh-test";

fn provider() -> NodeOAuthClientProvider {
    NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: HASH.to_string(),
        static_oauth_client_metadata: Some(json!({ "scope": "read write" })),
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn repeats_the_granted_scope_from_the_stored_tokens() {
    with_temporary_config_dir(|| {
        write_json_file(
            HASH,
            "tokens.json",
            &json!({ "access_token": "access", "token_type": "Bearer", "scope": "read" }),
        )
        .unwrap();
        assert_eq!(provider().scope_to_repeat_on_refresh(), "read");
    });
}

#[test]
fn falls_back_to_the_effective_scope_without_stored_tokens() {
    with_temporary_config_dir(|| {
        assert_eq!(provider().scope_to_repeat_on_refresh(), "read write");
    });
}

#[test]
fn falls_back_to_the_effective_scope_when_the_stored_tokens_have_no_scope() {
    with_temporary_config_dir(|| {
        write_json_file(
            HASH,
            "tokens.json",
            &json!({ "access_token": "access", "token_type": "Bearer" }),
        )
        .unwrap();
        assert_eq!(provider().scope_to_repeat_on_refresh(), "read write");
    });
}

#[test]
fn falls_back_to_the_effective_scope_when_the_stored_tokens_are_invalid() {
    with_temporary_config_dir(|| {
        write_json_file(HASH, "tokens.json", &json!({ "scope": "read" })).unwrap();
        assert_eq!(provider().scope_to_repeat_on_refresh(), "read write");
    });
}
