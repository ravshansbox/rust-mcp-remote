use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::logging::{append_debug_log, format_debug_log_entry};
use rust_mcp_remote::mcp_auth_config::{config_dir, config_file_path};
use serde_json::json;

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "debug-log-test";

fn with_temporary_config_dir<T>(action: impl FnOnce(&PathBuf) -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-debug-log-{}-{nanos}",
        std::process::id()
    ));
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action(&directory);
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    let _ = std::fs::remove_dir_all(&directory);
    result
}

#[test]
fn an_entry_without_arguments_keeps_the_trailing_space() {
    assert_eq!(
        format_debug_log_entry("[2026-01-01T00:00:00.000Z][42] Starting", &[]),
        "[2026-01-01T00:00:00.000Z][42] Starting \n"
    );
}

#[test]
fn strings_are_written_as_they_are_and_other_values_as_json() {
    let entry = format_debug_log_entry(
        "[t][1] Got",
        &[
            json!("plain text"),
            json!(3),
            json!(true),
            json!(null),
            json!({"access_token": "abc", "nested": {"b": 1, "a": [1, "x"]}}),
            json!(["one", 2]),
        ],
    );
    assert_eq!(
        entry,
        "[t][1] Got plain text 3 true null {\"access_token\":\"abc\",\"nested\":{\"b\":1,\"a\":[1,\"x\"]}} [\"one\",2]\n"
    );
}

#[test]
fn entries_are_appended_to_the_debug_log_of_the_server() {
    with_temporary_config_dir(|_| {
        append_debug_log(HASH, "first \n").expect("append first");
        append_debug_log(HASH, "second \n").expect("append second");
        let content =
            std::fs::read_to_string(config_file_path(HASH, "debug.log")).expect("read debug log");
        assert_eq!(content, "first \nsecond \n");
    });
}

#[cfg(unix)]
#[test]
fn the_debug_log_and_its_directory_are_private() {
    use std::os::unix::fs::PermissionsExt;
    with_temporary_config_dir(|_| {
        append_debug_log(HASH, "secret \n").expect("append");
        let file_mode = std::fs::metadata(config_file_path(HASH, "debug.log"))
            .expect("file metadata")
            .permissions()
            .mode();
        let directory_mode = std::fs::metadata(config_dir())
            .expect("directory metadata")
            .permissions()
            .mode();
        assert_eq!(file_mode & 0o777, 0o600);
        assert_eq!(directory_mode & 0o777, 0o700);
    });
}

#[test]
fn a_directory_that_cannot_be_made_is_reported() {
    with_temporary_config_dir(|directory| {
        std::fs::write(directory, "not a directory").expect("write blocking file");
        assert!(append_debug_log(HASH, "lost \n").is_err());
        std::fs::remove_file(directory).expect("remove blocking file");
    });
}
