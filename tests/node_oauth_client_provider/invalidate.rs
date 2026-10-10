use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{config_file_path, write_text_file};
use rust_mcp_remote::node_oauth_client_provider::{
    ClientRegistrationSource, CredentialScope, NodeOAuthClientProvider, OAuthProviderOptions,
};
use serde_json::json;

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "invalidate-test";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-invalidate-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

fn provider_with_credentials() -> (NodeOAuthClientProvider, String) {
    let mut provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: HASH.to_string(),
        ..Default::default()
    })
    .unwrap();
    let state = provider.next_state(0.0);
    provider.save_code_verifier("verifier").unwrap();
    write_text_file(HASH, "client_info.json", "{}").unwrap();
    write_text_file(HASH, "tokens.json", "{}").unwrap();
    provider.client_info = Some(json!({ "client_id": "client" }));
    provider.client_registration_source = Some(ClientRegistrationSource::CachedDynamic);
    (provider, format!("code_verifier_{state}.txt"))
}

fn exists(filename: &str) -> bool {
    config_file_path(HASH, filename).exists()
}

#[test]
fn a_new_provider_has_no_client_registration_source() {
    with_temporary_config_dir(|| {
        let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
            server_url: "https://auth.example.com".to_string(),
            server_url_hash: HASH.to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(provider.client_registration_source, None);
    });
}

#[test]
fn invalidating_all_removes_every_file_and_forgets_the_client() {
    with_temporary_config_dir(|| {
        let (mut provider, verifier) = provider_with_credentials();
        provider.invalidate_credentials(CredentialScope::All);
        assert!(!exists("client_info.json"));
        assert!(!exists("tokens.json"));
        assert!(!exists(&verifier));
        assert_eq!(provider.client_info, None);
        assert_eq!(provider.client_registration_source, None);
        assert!(provider.pending_flow.is_none());
    });
}

#[test]
fn invalidating_the_client_keeps_tokens_and_verifier() {
    with_temporary_config_dir(|| {
        let (mut provider, verifier) = provider_with_credentials();
        provider.invalidate_credentials(CredentialScope::Client);
        assert!(!exists("client_info.json"));
        assert!(exists("tokens.json"));
        assert!(exists(&verifier));
        assert_eq!(provider.client_info, None);
        assert_eq!(provider.client_registration_source, None);
        assert!(provider.pending_flow.is_some());
    });
}

#[test]
fn invalidating_tokens_only_removes_the_tokens_file() {
    with_temporary_config_dir(|| {
        let (mut provider, verifier) = provider_with_credentials();
        provider.invalidate_credentials(CredentialScope::Tokens);
        assert!(exists("client_info.json"));
        assert!(!exists("tokens.json"));
        assert!(exists(&verifier));
        assert!(provider.client_info.is_some());
        assert!(provider.pending_flow.is_some());
    });
}

#[test]
fn invalidating_the_verifier_removes_it_and_ends_the_pending_flow() {
    with_temporary_config_dir(|| {
        let (mut provider, verifier) = provider_with_credentials();
        provider.invalidate_credentials(CredentialScope::Verifier);
        assert!(exists("client_info.json"));
        assert!(exists("tokens.json"));
        assert!(!exists(&verifier));
        assert!(provider.client_info.is_some());
        assert!(provider.pending_flow.is_none());
    });
}
