//! Tests for the `oauth_provider` module, gathered into one test binary.

mod flow;
#[allow(dead_code)]
#[path = "../streamable_http/test_server.rs"]
mod test_server;

/// One config directory for the whole binary; each test signs in under its own server hash.
pub fn use_temporary_config_dir() {
    static DIRECTORY: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory = std::env::temp_dir().join(format!(
            "rust-mcp-remote-oauth-provider-{}",
            std::process::id()
        ));
        // SAFETY: set once, before any test reads it, and never changed afterwards.
        unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
        directory
    });
}
