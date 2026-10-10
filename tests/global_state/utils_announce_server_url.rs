use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::logging::{set_current_server_url_hash, set_debug};
use rust_mcp_remote::mcp_auth_config::config_file_path;
use rust_mcp_remote::utils::announce_server_url_to;

use crate::GLOBAL_STATE;

const HASH: &str = "announce-server-url-test";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-announce-server-url-{}-{nanos}",
        std::process::id()
    ));
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    let _ = std::fs::remove_dir_all(&directory);
    set_debug(false);
    set_current_server_url_hash(None);
    result
}

fn console_text(console: Vec<u8>) -> String {
    String::from_utf8(console).expect("utf8")
}

#[test]
fn writes_the_starting_line_to_the_debug_log_of_the_server() {
    with_temporary_config_dir(|| {
        set_debug(true);
        let mut console = Vec::new();

        announce_server_url_to(&mut console, "https://example.com/mcp", HASH);

        let pid = std::process::id();
        let suffix =
            format!("][{pid}] Starting mcp-remote with server URL: https://example.com/mcp");
        let console_output = console_text(console);
        assert!(console_output.starts_with('['));
        assert!(console_output.ends_with(&format!("{suffix}\n")));
        let content =
            std::fs::read_to_string(config_file_path(HASH, "debug.log")).expect("read debug log");
        assert!(content.ends_with(&format!("{suffix} \n")));
    });
}

#[test]
fn sets_the_server_hash_silently_when_debug_is_off() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();

        announce_server_url_to(&mut console, "https://example.com/mcp", HASH);

        assert_eq!(console_text(console), "");
        assert!(!config_file_path(HASH, "debug.log").exists());
        set_debug(true);
        let mut later = Vec::new();
        rust_mcp_remote::logging::debug_log_to(&mut later, "Later", &[]);
        assert!(config_file_path(HASH, "debug.log").exists());
    });
}
