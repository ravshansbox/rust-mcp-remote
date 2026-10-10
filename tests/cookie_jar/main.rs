//! Tests for the `cookie_jar` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod cookie_jar;
