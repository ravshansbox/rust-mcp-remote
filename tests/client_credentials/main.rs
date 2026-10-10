//! Tests for the `client_credentials` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod build_request;
mod check_token_endpoint;
mod request_debug_details;
mod token_request_failure_message;
