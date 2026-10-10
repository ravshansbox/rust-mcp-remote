use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::read_json_file;
use rust_mcp_remote::node_oauth_client_provider::{
    NodeOAuthClientProvider, OAuthProviderOptions, REFRESH_LEASE_FILE,
};
use serde_json::{Value, json};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const HASH: &str = "refresh-tokens-test";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-refresh-tokens-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

fn provider() -> NodeOAuthClientProvider {
    NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: HASH.to_string(),
        ..Default::default()
    })
    .unwrap()
}

fn refreshed(access_token: &str) -> Value {
    json!({ "access_token": access_token, "token_type": "Bearer" })
}

#[test]
fn concurrent_callers_share_one_refresh() {
    with_temporary_config_dir(|| {
        let provider = provider();
        let attempts = AtomicUsize::new(0);

        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                provider.refresh_tokens("callers", |_| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(300));
                    Some(refreshed("first"))
                })
            });
            std::thread::sleep(Duration::from_millis(100));
            let second = scope.spawn(|| {
                provider.refresh_tokens("callers", |_| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Some(refreshed("second"))
                })
            });
            (first.join().unwrap(), second.join().unwrap())
        });

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(first, Some(refreshed("first")));
        assert_eq!(second, Some(refreshed("first")));
        assert!(read_json_file::<Value>(HASH, REFRESH_LEASE_FILE).is_none());
    });
}

#[test]
fn a_later_caller_refreshes_again_once_the_attempt_is_over() {
    with_temporary_config_dir(|| {
        let provider = provider();

        let first = provider.refresh_tokens("callers", |_| None);
        let second = provider.refresh_tokens("callers", |_| Some(refreshed("second")));

        assert_eq!(first, None);
        assert_eq!(second, Some(refreshed("second")));
    });
}
