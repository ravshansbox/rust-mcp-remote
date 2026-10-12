//! Tests for the `oauth_provider` module, gathered into one test binary.

mod explicit_client_credentials;
mod flow;
mod metadata;
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

/// A server hash no other test in this binary uses.
pub fn unique_hash(name: &str) -> String {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    format!(
        "{name}-{}",
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    )
}

/// The current time in milliseconds since the Unix epoch.
pub fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as f64
}

static OPENED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// A browser opener that records each URL instead of opening it.
pub fn record_opened(url: &str) -> bool {
    OPENED.lock().unwrap().push(url.to_owned());
    true
}

/// The first recorded browser URL that contains `base`, if any.
pub fn opened_url(base: &str) -> Option<String> {
    OPENED
        .lock()
        .unwrap()
        .iter()
        .find(|url| url.contains(base))
        .cloned()
}
