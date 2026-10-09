use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{config_file_path, write_text_file};
use rust_mcp_remote::utils::invalidate_mismatched_client_registration;

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const HASH: &str = "invalidate-test";
const FILENAME: &str = "client_info.json";
const REDIRECT_URL: &str = "http://localhost:5599/oauth/callback";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf =
        std::env::temp_dir().join(format!("mcp-remote-config-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

fn registration_survives(contents: &str, redirect_url: &str) -> bool {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, contents).expect("write registration");
        invalidate_mismatched_client_registration(HASH, redirect_url);
        config_file_path(HASH, FILENAME).exists()
    })
}

#[test]
fn keeps_a_registration_whose_redirect_uri_matches() {
    let contents = format!(r#"{{"client_id":"registered-id","redirect_uris":["{REDIRECT_URL}"]}}"#);
    assert!(registration_survives(&contents, REDIRECT_URL));
}

#[test]
fn keeps_a_registration_that_lists_the_redirect_uri_among_others() {
    let contents = format!(
        r#"{{"client_id":"registered-id","redirect_uris":["https://proxy.example.com/oauth/callback","{REDIRECT_URL}"]}}"#
    );
    assert!(registration_survives(&contents, REDIRECT_URL));
}

#[test]
fn deletes_a_registration_for_another_port() {
    let contents =
        r#"{"client_id":"registered-id","redirect_uris":["http://localhost:7788/oauth/callback"]}"#;
    assert!(!registration_survives(contents, REDIRECT_URL));
}

#[test]
fn deletes_a_registration_for_another_host() {
    let contents =
        r#"{"client_id":"registered-id","redirect_uris":["http://localhost:5599/oauth/callback"]}"#;
    assert!(!registration_survives(
        contents,
        "http://127.0.0.1:5599/oauth/callback"
    ));
}

#[test]
fn deletes_a_registration_pointing_at_a_reverse_proxy() {
    let contents = r#"{"client_id":"registered-id","redirect_uris":["https://proxy.example.com/oauth/callback"]}"#;
    assert!(!registration_survives(contents, REDIRECT_URL));
}

#[test]
fn keeps_a_file_that_is_not_a_valid_registration() {
    assert!(registration_survives("not json", REDIRECT_URL));
    assert!(registration_survives(
        r#"{"client_id":"registered-id"}"#,
        REDIRECT_URL
    ));
}

#[test]
fn does_nothing_when_there_is_no_registration() {
    with_temporary_config_dir(|| {
        invalidate_mismatched_client_registration(HASH, REDIRECT_URL);
        assert!(!config_file_path(HASH, FILENAME).exists());
    });
}
