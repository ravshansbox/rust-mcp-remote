//! Tests for the `mcp_auth_config` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod delete;
mod lease_read;
mod lease_release;
mod paths;
mod reads;
mod stale;
mod text_files;
mod writes;
