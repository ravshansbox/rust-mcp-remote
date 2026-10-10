//! Tests for the `device_authorization` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod apply_client_authentication;
mod authorize_with_device_code;
mod build_device_authorization_request;
mod build_device_token_request;
mod error_detail;
mod next_poll_interval;
mod parse_device_authorization_response;
mod poll_for_tokens;
mod polling_schedule;
mod select_client_auth_method;
mod supports_device_authorization;
mod verification_prompt_lines;
