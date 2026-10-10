//! Tests that change the process-wide logging flags (debug, silent, server
//! hash). They run in their own test binary so the flags cannot leak into
//! tests of other modules that capture log output.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod logging_flags;
mod mcp_auth_config_lease_acquire;
mod utils_announce_server_url;
mod utils_parse_command_line_args;
mod utils_parse_debug_and_silent_flags;
