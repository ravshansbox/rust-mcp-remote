use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::coordination::{
    FOLLOWER_PATIENCE_MS, FOLLOWER_POLL_INTERVAL_MS, REFRESH_FOLLOWER_PATIENCE_MS,
    TOKEN_EXPIRY_MARGIN_MS, has_usable_tokens, has_usable_tokens_at,
};
use rust_mcp_remote::mcp_auth_config::write_json_file;
use serde_json::{Value, json};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const HASH: &str = "usable-test";
const NOW: u64 = 1_700_000_000_000;

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf =
        std::env::temp_dir().join(format!("mcp-remote-usable-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

fn usable_with(tokens: Option<Value>) -> bool {
    with_temporary_config_dir(|| {
        if let Some(tokens) = tokens {
            write_json_file(HASH, "tokens.json", &tokens).expect("write tokens");
        }
        has_usable_tokens_at(HASH, NOW)
    })
}

#[test]
fn timing_constants_match_typescript() {
    assert_eq!(FOLLOWER_PATIENCE_MS, 180_000);
    assert_eq!(REFRESH_FOLLOWER_PATIENCE_MS, 10_000);
    assert_eq!(FOLLOWER_POLL_INTERVAL_MS, 250);
    assert_eq!(TOKEN_EXPIRY_MARGIN_MS, 60_000);
}

#[test]
fn missing_tokens_are_not_usable() {
    assert!(!usable_with(None));
}

#[test]
fn tokens_failing_the_schema_are_not_usable() {
    assert!(!usable_with(Some(json!({ "refresh_token": "rt" }))));
}

#[test]
fn tokens_without_expiry_are_usable() {
    assert!(usable_with(Some(
        json!({ "access_token": "at", "token_type": "Bearer" })
    )));
}

#[test]
fn tokens_expiring_after_the_margin_are_usable() {
    assert!(usable_with(Some(json!({
        "access_token": "at",
        "token_type": "Bearer",
        "expires_at": NOW + TOKEN_EXPIRY_MARGIN_MS + 1,
    }))));
}

#[test]
fn tokens_inside_the_margin_without_refresh_token_are_not_usable() {
    assert!(!usable_with(Some(json!({
        "access_token": "at",
        "token_type": "Bearer",
        "expires_at": NOW + TOKEN_EXPIRY_MARGIN_MS,
    }))));
}

#[test]
fn expired_tokens_with_refresh_token_are_usable() {
    assert!(usable_with(Some(json!({
        "access_token": "at",
        "token_type": "Bearer",
        "expires_at": NOW - 1,
        "refresh_token": "rt",
    }))));
}

#[test]
fn expires_at_given_as_a_string_is_coerced() {
    assert!(!usable_with(Some(json!({
        "access_token": "at",
        "token_type": "Bearer",
        "expires_at": (NOW - 1).to_string(),
    }))));
}

#[test]
fn has_usable_tokens_uses_the_current_time() {
    let expired = with_temporary_config_dir(|| {
        write_json_file(
            HASH,
            "tokens.json",
            &json!({ "access_token": "at", "token_type": "Bearer", "expires_at": 1 }),
        )
        .expect("write tokens");
        has_usable_tokens(HASH)
    });
    assert!(!expired);
}
