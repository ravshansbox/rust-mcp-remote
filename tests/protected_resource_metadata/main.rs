//! Tests for the `protected_resource_metadata` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod build_urls;
mod discover;
mod get_authorization_server_url;
mod parse_www_authenticate_header;
#[allow(dead_code)]
#[path = "../streamable_http/test_server.rs"]
mod test_server;
