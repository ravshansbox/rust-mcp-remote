use rust_mcp_remote::mcp_auth_config::read_json_file;
use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use serde_json::{Value, json};

use crate::with_temporary_config_dir;

const HASH: &str = "save-tokens-test";

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

fn stored_tokens() -> Option<Value> {
    read_json_file::<Value>(HASH, "tokens.json")
}

#[test]
fn stores_an_absolute_expiry_and_the_requested_scope() {
    with_temporary_config_dir(|| {
        let mut provider = provider();
        provider
            .save_tokens(
                &json!({ "access_token": "access", "token_type": "Bearer", "expires_in": 3600 }),
                1_000.0,
            )
            .unwrap();
        assert_eq!(
            stored_tokens(),
            Some(json!({
                "access_token": "access",
                "token_type": "Bearer",
                "expires_in": 3600,
                "expires_at": 3_601_000.0,
                "requested_scope": "read write",
            }))
        );
    });
}

#[test]
fn keeps_the_expiry_of_a_token_read_back_from_disk() {
    with_temporary_config_dir(|| {
        let mut provider = provider();
        provider
            .save_tokens(
                &json!({
                    "access_token": "access",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "expires_at": 5_000.0,
                }),
                1_000.0,
            )
            .unwrap();
        assert_eq!(stored_tokens().unwrap()["expires_at"], json!(5_000.0));
    });
}

#[test]
fn ends_the_flow_and_deletes_its_code_verifier() {
    with_temporary_config_dir(|| {
        let mut provider = provider();
        provider.next_state(0.0);
        provider.save_code_verifier("verifier").unwrap();
        provider
            .save_tokens(
                &json!({ "access_token": "access", "token_type": "Bearer" }),
                1_000.0,
            )
            .unwrap();
        assert!(provider.pending_flow.is_none());
        let error = provider.code_verifier().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), "No code verifier saved for session");
    });
}

#[test]
fn refuses_to_save_during_a_token_storm() {
    with_temporary_config_dir(|| {
        let mut provider = provider();
        let tokens = json!({ "access_token": "access", "token_type": "Bearer" });
        for _ in 0..20 {
            provider.save_tokens(&tokens, 1_000.0).unwrap();
        }
        let error = provider
            .save_tokens(
                &json!({ "access_token": "next", "token_type": "Bearer" }),
                1_000.0,
            )
            .unwrap_err();
        assert!(error.starts_with("Stopped after 20 token exchanges"));
        assert_eq!(stored_tokens().unwrap()["access_token"], json!("access"));
    });
}
