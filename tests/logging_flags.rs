use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::logging::{
    debug_log_to, log_to, set_current_server_url_hash, set_debug, set_silent,
};
use rust_mcp_remote::mcp_auth_config::config_file_path;
use serde_json::json;

static GLOBAL_STATE: Mutex<()> = Mutex::new(());

const HASH: &str = "logging-flags-test";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-logging-flags-{}-{nanos}",
        std::process::id()
    ));
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    let _ = std::fs::remove_dir_all(&directory);
    set_debug(false);
    set_silent(false);
    set_current_server_url_hash(None);
    result
}

fn console_text(console: Vec<u8>) -> String {
    String::from_utf8(console).expect("utf8")
}

#[test]
fn debug_log_does_nothing_when_debug_is_off() {
    with_temporary_config_dir(|| {
        set_current_server_url_hash(Some(HASH.to_string()));
        let mut console = Vec::new();
        debug_log_to(&mut console, "Hidden", &[]);
        assert_eq!(console_text(console), "");
        assert!(!config_file_path(HASH, "debug.log").exists());
    });
}

#[test]
fn debug_log_writes_a_timestamped_line_when_debug_is_on() {
    with_temporary_config_dir(|| {
        set_debug(true);
        set_current_server_url_hash(Some(HASH.to_string()));
        let mut console = Vec::new();
        debug_log_to(&mut console, "Token", &[json!({"expires_in": 3600})]);

        let line = console_text(console);
        let prefix_end = line.find("] Token").expect("message after prefix");
        let prefix = &line[..prefix_end + 1];
        let pid_marker = format!("][{}]", std::process::id());
        assert!(prefix.starts_with('['), "{prefix}");
        assert!(prefix.ends_with(&pid_marker), "{prefix}");
        assert_eq!(
            prefix.len(),
            "[2026-01-01T00:00:00.000Z]".len() + pid_marker.len() - 1
        );
        assert_eq!(&line[prefix_end + 1..], " Token {\"expires_in\":3600}\n");

        let content =
            std::fs::read_to_string(config_file_path(HASH, "debug.log")).expect("read debug log");
        assert_eq!(content, line);
    });
}

#[test]
fn debug_log_reports_a_missing_server_url_hash() {
    with_temporary_config_dir(|| {
        set_debug(true);
        let mut console = Vec::new();
        debug_log_to(&mut console, "Lost", &[]);
        assert_eq!(
            console_text(console),
            "[DEBUG LOG ERROR] global.currentServerUrlHash is not set. Cannot write debug log.\n"
        );
    });
}

#[test]
fn log_writes_a_pid_prefixed_line() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();
        log_to(&mut console, "Connected", &[json!("to"), json!(42)]);
        assert_eq!(
            console_text(console),
            format!("[{}] Connected to 42\n", std::process::id())
        );
    });
}

#[test]
fn log_without_extra_values_has_no_trailing_space() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();
        log_to(&mut console, "Ready", &[]);
        assert_eq!(
            console_text(console),
            format!("[{}] Ready\n", std::process::id())
        );
    });
}

#[test]
fn log_does_nothing_when_silent() {
    with_temporary_config_dir(|| {
        set_silent(true);
        let mut console = Vec::new();
        log_to(&mut console, "Quiet", &[]);
        assert_eq!(console_text(console), "");
    });
}
