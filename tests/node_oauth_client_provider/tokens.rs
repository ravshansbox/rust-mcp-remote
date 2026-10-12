use std::cell::RefCell;

use rust_mcp_remote::mcp_auth_config::write_json_file;
use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use serde_json::{Value, json};

use crate::with_temporary_config_dir;

const HASH: &str = "tokens-test";
const NOW_MS: f64 = 1_000_000_000.0;

fn provider() -> NodeOAuthClientProvider {
    crate::provider_with_hash(HASH)
}

fn client_credentials_provider() -> NodeOAuthClientProvider {
    NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: HASH.to_string(),
        use_client_credentials: Some(true),
        token_endpoint: Some("https://auth.example.com/token".to_string()),
        ..Default::default()
    })
    .unwrap()
}

fn stored(access_token: &str, expires_at: f64) -> Value {
    json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "refresh_token": "stored-refresh",
        "expires_in": 3600,
        "expires_at": expires_at,
    })
}

fn no_renewal(_: Option<&str>) -> Result<(), String> {
    panic!("renewal was not expected")
}

fn no_refresh(_: &str) -> Option<Value> {
    panic!("refresh was not expected")
}

#[test]
fn returns_nothing_without_stored_tokens() {
    with_temporary_config_dir(|| {
        assert_eq!(provider().tokens(NOW_MS, no_renewal, no_refresh), None);
    });
}

#[test]
fn returns_fresh_tokens_without_renewing() {
    with_temporary_config_dir(|| {
        let tokens = stored("fresh", NOW_MS + 3_600_000.0);
        write_json_file(HASH, "tokens.json", &tokens).unwrap();
        assert_eq!(
            provider().tokens(NOW_MS, no_renewal, no_refresh),
            Some(tokens)
        );
    });
}

#[test]
fn refreshes_expired_tokens_with_the_stored_refresh_token() {
    with_temporary_config_dir(|| {
        write_json_file(HASH, "tokens.json", &stored("expired", NOW_MS)).unwrap();
        let used_refresh_token = RefCell::new(None);
        let refreshed = json!({ "access_token": "refreshed", "token_type": "Bearer" });

        let result = provider().tokens(NOW_MS, no_renewal, |refresh_token| {
            *used_refresh_token.borrow_mut() = Some(refresh_token.to_string());
            Some(refreshed.clone())
        });

        assert_eq!(result, Some(refreshed));
        assert_eq!(
            used_refresh_token.into_inner().as_deref(),
            Some("stored-refresh")
        );
    });
}

#[test]
fn falls_back_to_the_stored_tokens_when_refresh_fails() {
    with_temporary_config_dir(|| {
        let tokens = stored("expired", NOW_MS);
        write_json_file(HASH, "tokens.json", &tokens).unwrap();
        assert_eq!(
            provider().tokens(NOW_MS, no_renewal, |_| None),
            Some(tokens)
        );
    });
}

#[test]
fn returns_expired_tokens_without_a_refresh_token() {
    with_temporary_config_dir(|| {
        let tokens =
            json!({ "access_token": "expired", "token_type": "Bearer", "expires_at": NOW_MS });
        write_json_file(HASH, "tokens.json", &tokens).unwrap();
        assert_eq!(
            provider().tokens(NOW_MS, no_renewal, no_refresh),
            Some(tokens)
        );
    });
}

#[test]
fn renews_client_credentials_and_reads_the_new_tokens() {
    with_temporary_config_dir(|| {
        let mut tokens = stored("expired", NOW_MS);
        tokens["requested_scope"] = json!("read");
        tokens["scope"] = json!("granted");
        write_json_file(HASH, "tokens.json", &tokens).unwrap();
        let renewed = json!({ "access_token": "renewed", "token_type": "Bearer", "requested_scope": "read", "expires_at": NOW_MS });
        let renewed_scope = RefCell::new(None);

        let result = client_credentials_provider().tokens(
            NOW_MS,
            |scope| {
                *renewed_scope.borrow_mut() = scope.map(str::to_string);
                write_json_file(HASH, "tokens.json", &renewed).map_err(|error| error.to_string())
            },
            no_refresh,
        );

        assert_eq!(result, Some(renewed.clone()));
        assert_eq!(renewed_scope.into_inner().as_deref(), Some("read"));
    });
}

#[test]
fn renews_client_credentials_with_the_granted_scope_when_none_was_requested() {
    with_temporary_config_dir(|| {
        let mut tokens = stored("expired", NOW_MS);
        tokens["scope"] = json!("granted");
        write_json_file(HASH, "tokens.json", &tokens).unwrap();
        let renewed_scope = RefCell::new(None);

        client_credentials_provider().tokens(
            NOW_MS,
            |scope| {
                *renewed_scope.borrow_mut() = scope.map(str::to_string);
                Ok(())
            },
            no_refresh,
        );

        assert_eq!(renewed_scope.into_inner().as_deref(), Some("granted"));
    });
}

#[test]
fn falls_back_to_the_stored_tokens_when_client_credentials_renewal_fails() {
    with_temporary_config_dir(|| {
        let tokens = stored("expired", NOW_MS);
        write_json_file(HASH, "tokens.json", &tokens).unwrap();
        let result = client_credentials_provider().tokens(
            NOW_MS,
            |_| Err("token endpoint unreachable".to_string()),
            no_refresh,
        );
        assert_eq!(result, Some(tokens));
    });
}
