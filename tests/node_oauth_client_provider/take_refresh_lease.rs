use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::read_json_file;
use rust_mcp_remote::node_oauth_client_provider::{
    NodeOAuthClientProvider, OAuthProviderOptions, REFRESH_LEASE_FILE, UNCOORDINATED,
};
use serde_json::Value;

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "take-refresh-lease-test";

fn with_config_dir<T>(prepare: impl FnOnce(&PathBuf) -> PathBuf, action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-take-refresh-lease-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    let config_dir = prepare(&directory);
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &config_dir) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    with_config_dir(|directory| directory.clone(), action)
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

#[test]
fn takes_the_lease_when_nobody_holds_it() {
    with_temporary_config_dir(|| {
        let lease = provider().take_refresh_lease().expect("lease");

        assert_ne!(lease, UNCOORDINATED);
        let on_disk = read_json_file::<Value>(HASH, REFRESH_LEASE_FILE).expect("lease file");
        assert_eq!(on_disk["nonce"], Value::String(lease));
    });
}

#[test]
fn leaves_the_lease_to_a_live_sibling() {
    with_temporary_config_dir(|| {
        let held = provider().take_refresh_lease().expect("lease");

        assert_eq!(provider().take_refresh_lease(), None);
        let on_disk = read_json_file::<Value>(HASH, REFRESH_LEASE_FILE).expect("lease file");
        assert_eq!(on_disk["nonce"], Value::String(held));
    });
}

#[test]
fn refreshes_uncoordinated_when_no_lease_can_be_taken() {
    with_config_dir(
        |directory| {
            let blocker = directory.join("not-a-directory");
            std::fs::write(&blocker, "").expect("write blocker file");
            blocker
        },
        || {
            assert_eq!(
                provider().take_refresh_lease(),
                Some(UNCOORDINATED.to_string())
            );
        },
    );
}
