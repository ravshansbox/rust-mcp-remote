//! Tests for the `utils` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

mod build_redirect_url;
mod calculate_default_port;
mod discover_oauth_server_info;
mod early_exit_output;
mod encode_mcp_header_value;
mod env_vars;
mod env_vars_logging;
mod extract_header_args;
mod finalise_headers;
mod get_server_url_hash;
mod ignored_tool_call_error;
mod invalidate_mismatched_client_registration;
mod is_client_metadata_url;
mod log_authorize_param_keys;
mod mcp_headers_from_body;
mod merge_headers;
mod message_transformer;
mod parse_authorize_params;
mod parse_authorize_params_logging;
mod parse_callback_host;
mod parse_callback_path;
mod parse_client_metadata_url;
mod parse_enable_proxy;
mod parse_grant_and_cookie_flags;
mod parse_header_line;
mod parse_id_token_and_resource;
mod parse_ignore_tool_and_auth_timeout;
mod parse_keep_alive;
mod parse_network_options;
mod parse_protocol_mode;
mod parse_seconds_option;
mod parse_seconds_option_logging;
mod parse_static_oauth_client_info;
mod parse_static_oauth_client_metadata;
mod parse_token_endpoint;
mod parse_transport_strategy;
mod read_header_file;
mod select_callback_port;
mod should_include_tool;
#[allow(dead_code)]
#[path = "../streamable_http/test_server.rs"]
mod test_server;
mod transform_proxy_response;
mod validate_server_url;
