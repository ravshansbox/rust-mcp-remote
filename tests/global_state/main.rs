//! Tests that change process-wide state (the logging flags, the cookie flag and
//! jar, environment variables). They run in their own test binary so that state
//! cannot leak into tests of other modules.

/// Serializes tests that change process-wide state (environment variables, logging and cookie flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Decodes captured console output as UTF-8.
pub fn console_text(console: Vec<u8>) -> String {
    String::from_utf8(console).expect("utf8")
}

/// Runs `action` with `GLOBAL_STATE` held and `MCP_REMOTE_CONFIG_DIR` pointing at a
/// fresh temporary directory, then removes the directory and resets the logging flags.
pub fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mcp-remote-global-state-{}-{nanos}",
        std::process::id()
    ));
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    let _ = std::fs::remove_dir_all(&directory);
    rust_mcp_remote::logging::set_debug(false);
    rust_mcp_remote::logging::set_silent(false);
    rust_mcp_remote::logging::set_current_server_url_hash(None);
    result
}

mod logging_flags;
mod mcp_auth_config_lease_acquire;
#[path = "../streamable_http/test_server.rs"]
#[allow(dead_code)]
mod test_server;
mod utils_announce_server_url;
mod utils_capture_cookies;
mod utils_fetch_with_mcp_headers;
mod utils_parse_command_line_args;
mod utils_parse_debug_and_silent_flags;
