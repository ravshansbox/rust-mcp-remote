use std::path::PathBuf;
use std::sync::Mutex;

use rust_mcp_remote::mcp_auth_config::{config_dir, config_file_path};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

fn with_config_dir_env<T>(value: Option<&str>, action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    unsafe {
        match value {
            Some(value) => std::env::set_var("MCP_REMOTE_CONFIG_DIR", value),
            None => std::env::remove_var("MCP_REMOTE_CONFIG_DIR"),
        }
    }
    action()
}

fn home() -> PathBuf {
    std::env::home_dir().expect("home directory")
}

#[test]
fn the_path_does_not_move_when_the_package_version_does() {
    let directory = with_config_dir_env(None, config_dir);

    assert_eq!(directory, home().join(".mcp-auth").join("mcp-remote-v1"));
    assert!(
        !directory
            .to_string_lossy()
            .contains(env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn mcp_remote_config_dir_relocates_the_store_and_keeps_it_stable() {
    let directory = with_config_dir_env(Some("/tmp/somewhere-else"), config_dir);

    assert_eq!(
        directory,
        PathBuf::from("/tmp/somewhere-else").join("mcp-remote-v1")
    );
}

#[test]
fn an_empty_mcp_remote_config_dir_falls_back_to_the_home_directory() {
    let directory = with_config_dir_env(Some(""), config_dir);

    assert_eq!(directory, home().join(".mcp-auth").join("mcp-remote-v1"));
}

#[test]
fn a_config_file_is_prefixed_with_the_server_url_hash() {
    let file_path = with_config_dir_env(Some("/tmp/somewhere-else"), || {
        config_file_path("abc123", "tokens.json")
    });

    assert_eq!(
        file_path,
        PathBuf::from("/tmp/somewhere-else/mcp-remote-v1/abc123_tokens.json")
    );
}
