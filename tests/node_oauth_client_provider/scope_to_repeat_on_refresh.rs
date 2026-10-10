use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::write_json_file;
use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use serde_json::json;

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "scope-to-repeat-on-refresh-test";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-scope-to-repeat-on-refresh-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

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
