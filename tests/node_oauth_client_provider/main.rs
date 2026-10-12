//! Tests for the `node_oauth_client_provider` module, gathered into one test binary.

/// Serializes tests that change process-wide state (environment variables, logging flags).
pub static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs `action` with `MCP_REMOTE_CONFIG_DIR` pointing at a fresh temporary directory,
/// holding `GLOBAL_STATE` throughout and removing the directory afterwards.
pub fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mcp-remote-node-oauth-client-provider-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

/// Milliseconds since the Unix epoch, as stored in a refresh lease's `at` field.
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time after epoch")
        .as_millis() as u64
}

/// Writes a refresh lease for `hash` held by another process `pid`, taken just now.
pub fn write_sibling_lease(hash: &str, pid: u32) {
    let lease = serde_json::json!({ "pid": pid, "nonce": "theirs", "at": now_millis() });
    rust_mcp_remote::mcp_auth_config::write_text_file(
        hash,
        rust_mcp_remote::node_oauth_client_provider::REFRESH_LEASE_FILE,
        &lease.to_string(),
    )
    .expect("write lease");
}

mod apply_authorize_params;
mod apply_scope;
mod as_bearer_tokens;
mod authorization_state;
mod authorization_storm_brake;
mod authorize_with_client_credentials;
mod authorize_with_device_code;
mod await_refresh_by_sibling;
mod bearer_expires_at;
mod client_information;
mod client_metadata;
mod code_challenge_for;
mod code_verifier;
mod device_authorization_resource;
mod discovery_state;
mod effective_scope;
mod flow;
mod getters;
mod grant_types;
mod invalidate;
mod is_issued_state;
mod is_sibling_token_fresh;
mod is_token_expired;
mod jwt_expires_at;
mod new;
mod pending_flow;
mod preflight_cached_dynamic_client_registration;
mod prepare_token_request;
mod prepare_token_request_method;
mod read_stored_tokens;
mod refresh_once_per_host;
mod refresh_tokens;
mod renew_client_credentials;
mod requested_scope;
mod resource_selection;
mod save_client_information;
mod save_tokens;
mod scope_request_changed;
mod scope_to_repeat_on_refresh;
mod stale_client_registration_error;
mod state;
mod take_refresh_lease;
mod token_endpoint_auth_method;
mod token_storm_brake;
mod tokens;
mod tokens_to_save;
