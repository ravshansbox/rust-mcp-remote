//! Tests that change process-wide state (the logging flags, the cookie flag and
//! jar, environment variables). They run in their own test binary so that state
//! cannot leak into tests of other modules.

/// Serializes tests that change process-wide state (environment variables, logging and cookie flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
