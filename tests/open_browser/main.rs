//! Tests for the `open_browser` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod launch_environment_details;
mod launch_helper;
mod linux_fallbacks;
mod open_browser_with;
mod sanitize_url;
