//! Tests for the `auth` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod flow;
mod helpers;
#[allow(dead_code)]
#[path = "../streamable_http/test_server.rs"]
mod test_server;
