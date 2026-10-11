//! Tests for the `device_authorization` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Turns string literal pairs into the owned name/value list the form builders take.
pub fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

mod apply_client_authentication;
mod authorize_with_device_code;
mod build_device_authorization_request;
mod build_device_token_request;
mod error_detail;
mod next_poll_interval;
mod parse_device_authorization_response;
mod poll_for_tokens;
mod polling_schedule;
mod post_form;
mod select_client_auth_method;
mod supports_device_authorization;
#[allow(dead_code)]
#[path = "../streamable_http/test_server.rs"]
mod test_server;
mod verification_prompt_lines;
