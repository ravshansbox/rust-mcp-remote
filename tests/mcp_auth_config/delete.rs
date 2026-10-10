use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{config_file_path, delete_config_file, write_text_file};

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "delete-test";
const FILENAME: &str = "tokens.json";

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

#[test]
fn deleting_an_existing_file_removes_it() {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "{}").expect("write file");
        delete_config_file(HASH, FILENAME);
        assert!(!config_file_path(HASH, FILENAME).exists());
    });
}

#[test]
fn deleting_a_missing_file_does_nothing() {
    with_temporary_config_dir(|| {
        delete_config_file(HASH, FILENAME);
        assert!(!config_file_path(HASH, FILENAME).exists());
    });
}

#[test]
fn deleting_leaves_other_files_alone() {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "{}").expect("write file");
        write_text_file(HASH, "client_info.json", "{}").expect("write other file");
        write_text_file("other-hash", FILENAME, "{}").expect("write other hash file");
        delete_config_file(HASH, FILENAME);
        assert!(config_file_path(HASH, "client_info.json").exists());
        assert!(config_file_path("other-hash", FILENAME).exists());
    });
}
