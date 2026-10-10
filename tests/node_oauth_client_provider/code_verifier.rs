use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{config_file_path, read_text_file};
use rust_mcp_remote::node_oauth_client_provider::{
    NodeOAuthClientProvider, OAuthProviderOptions, code_challenge_for,
};

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "verifier-test";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-verifier-{}-{nanos}",
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
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn the_verifier_is_saved_under_the_own_state_without_a_pending_flow() {
    with_temporary_config_dir(|| {
        let mut provider = provider();
        provider.save_code_verifier("verifier-one").unwrap();
        let filename = format!("code_verifier_{}.txt", provider.state);
        assert_eq!(
            read_text_file(HASH, &filename, None).unwrap(),
            "verifier-one"
        );
        assert_eq!(provider.code_verifier().unwrap(), "verifier-one");
    });
}

#[test]
fn the_first_verifier_of_a_pending_flow_wins() {
    with_temporary_config_dir(|| {
        let mut provider = provider();
        let state = provider.next_state(0.0);
        provider.save_code_verifier("first").unwrap();
        provider.save_code_verifier("second").unwrap();
        let filename = format!("code_verifier_{state}.txt");
        assert_eq!(read_text_file(HASH, &filename, None).unwrap(), "first");
        assert_eq!(
            provider.pending_flow.unwrap().challenge.as_deref(),
            Some(code_challenge_for("first").as_str())
        );
    });
}

#[test]
fn the_verifier_is_read_for_the_incoming_state() {
    with_temporary_config_dir(|| {
        let mut other = provider();
        other.save_code_verifier("other-verifier").unwrap();
        let mut provider = provider();
        provider.use_authorization_state(&other.state);
        assert_eq!(provider.code_verifier().unwrap(), "other-verifier");
    });
}

#[test]
fn a_missing_verifier_reports_no_saved_verifier() {
    with_temporary_config_dir(|| {
        let provider = provider();
        let filename = format!("code_verifier_{}.txt", provider.state);
        assert!(!config_file_path(HASH, &filename).exists());
        let error = provider.code_verifier().unwrap_err();
        assert_eq!(error.to_string(), "No code verifier saved for session");
    });
}
