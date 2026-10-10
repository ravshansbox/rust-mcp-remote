use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rust_mcp_remote::mcp_auth_config::{read_json_file, write_json_file};
use rust_mcp_remote::node_oauth_client_provider::{
    NodeOAuthClientProvider, OAuthProviderOptions, StoredTokens,
};
use serde_json::{Value, json};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const HASH: &str = "read-stored-tokens-test";
const NOW_MS: f64 = 1_000_000_000.0;

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-read-stored-tokens-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

fn provider(use_id_token: bool) -> NodeOAuthClientProvider {
    NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: HASH.to_string(),
        static_oauth_client_metadata: Some(json!({ "scope": "read write" })),
        use_id_token: Some(use_id_token),
        ..Default::default()
    })
    .unwrap()
}

fn id_token_expiring_at(expires_at_seconds: f64) -> String {
    let payload = URL_SAFE_NO_PAD.encode(json!({ "exp": expires_at_seconds }).to_string());
    format!("header.{payload}.signature")
}

#[test]
fn returns_nothing_without_stored_tokens() {
    with_temporary_config_dir(|| {
        assert_eq!(provider(false).read_stored_tokens(NOW_MS), None);
    });
}

#[test]
fn ignores_stored_tokens_that_are_not_valid() {
    with_temporary_config_dir(|| {
        write_json_file(HASH, "tokens.json", &json!({ "scope": "read" })).unwrap();
        assert_eq!(provider(false).read_stored_tokens(NOW_MS), None);
    });
}

#[test]
fn discards_tokens_obtained_for_a_different_scope_request() {
    with_temporary_config_dir(|| {
        write_json_file(
            HASH,
            "tokens.json",
            &json!({ "access_token": "access", "token_type": "Bearer", "requested_scope": "read" }),
        )
        .unwrap();
        assert_eq!(provider(false).read_stored_tokens(NOW_MS), None);
        assert_eq!(read_json_file::<Value>(HASH, "tokens.json"), None);
    });
}

#[test]
fn reports_tokens_well_before_their_expiry_as_current() {
    with_temporary_config_dir(|| {
        let tokens = json!({
            "access_token": "access",
            "token_type": "Bearer",
            "requested_scope": "read write",
            "expires_at": NOW_MS + 120_000.0,
        });
        write_json_file(HASH, "tokens.json", &tokens).unwrap();
        assert_eq!(
            provider(false).read_stored_tokens(NOW_MS),
            Some(StoredTokens {
                tokens,
                is_expired: false
            })
        );
    });
}

#[test]
fn reports_tokens_within_a_minute_of_their_expiry_as_expired() {
    with_temporary_config_dir(|| {
        let tokens = json!({
            "access_token": "access",
            "token_type": "Bearer",
            "expires_at": NOW_MS + 30_000.0,
        });
        write_json_file(HASH, "tokens.json", &tokens).unwrap();
        assert_eq!(
            provider(false).read_stored_tokens(NOW_MS),
            Some(StoredTokens {
                tokens,
                is_expired: true
            })
        );
    });
}

#[test]
fn judges_expiry_by_the_id_token_when_it_is_the_bearer_credential() {
    with_temporary_config_dir(|| {
        let tokens = json!({
            "access_token": "access",
            "token_type": "Bearer",
            "id_token": id_token_expiring_at((NOW_MS + 30_000.0) / 1000.0),
            "expires_at": NOW_MS + 3_600_000.0,
        });
        write_json_file(HASH, "tokens.json", &tokens).unwrap();
        assert_eq!(
            provider(true).read_stored_tokens(NOW_MS),
            Some(StoredTokens {
                tokens: tokens.clone(),
                is_expired: true
            })
        );
        assert_eq!(
            provider(false).read_stored_tokens(NOW_MS),
            Some(StoredTokens {
                tokens,
                is_expired: false
            })
        );
    });
}

#[test]
fn presents_the_id_token_as_the_bearer_credential() {
    with_temporary_config_dir(|| {
        let tokens =
            json!({ "access_token": "access", "token_type": "Bearer", "id_token": "identity" });
        let bearer = provider(true).as_bearer_tokens(Some(tokens)).unwrap();
        assert_eq!(bearer["access_token"], "identity");
    });
}

#[test]
fn keeps_the_access_token_when_no_id_token_was_issued() {
    with_temporary_config_dir(|| {
        let tokens = json!({ "access_token": "access", "token_type": "Bearer" });
        let mut provider = provider(true);
        assert_eq!(
            provider.as_bearer_tokens(Some(tokens.clone())),
            Some(tokens)
        );
        assert!(provider.warned_about_missing_id_token);
    });
}
