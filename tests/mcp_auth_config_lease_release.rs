use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{config_file_path, release_config_lease, write_text_file};
use serde_json::json;

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const HASH: &str = "lease-release-test";
const FILENAME: &str = "refresh_in_progress.json";

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

fn write_lease(lease: serde_json::Value) {
    write_text_file(HASH, FILENAME, &lease.to_string()).expect("write lease");
}

#[test]
fn releasing_a_lease_this_instance_holds_removes_it() {
    with_temporary_config_dir(|| {
        write_lease(json!({ "pid": std::process::id(), "nonce": "mine", "at": 1 }));

        release_config_lease(HASH, FILENAME, "mine");

        assert!(!config_file_path(HASH, FILENAME).exists());
    });
}

#[test]
fn releasing_a_lease_another_instance_took_leaves_it() {
    with_temporary_config_dir(|| {
        write_lease(json!({ "pid": std::process::id(), "nonce": "theirs", "at": 1 }));

        release_config_lease(HASH, FILENAME, "mine");

        let content = std::fs::read_to_string(config_file_path(HASH, FILENAME)).expect("lease");
        assert!(content.contains("theirs"));
    });
}

#[test]
fn releasing_when_no_lease_exists_is_a_no_op() {
    with_temporary_config_dir(|| {
        release_config_lease(HASH, FILENAME, "mine");

        assert!(!config_file_path(HASH, FILENAME).exists());
    });
}

#[test]
fn releasing_leaves_an_unreadable_lease_alone() {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "not json").expect("write lease");

        release_config_lease(HASH, FILENAME, "mine");

        assert!(config_file_path(HASH, FILENAME).exists());
    });
}
