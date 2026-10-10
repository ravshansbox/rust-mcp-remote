use std::cell::RefCell;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{
    delete_config_file, read_json_file, write_json_file, write_text_file,
};
use rust_mcp_remote::node_oauth_client_provider::{
    NodeOAuthClientProvider, OAuthProviderOptions, REFRESH_LEASE_FILE,
};
use serde_json::{Value, json};

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "refresh-once-per-host-test";
const DEAD_PID: u32 = 0x7fffffff;

fn with_config_dir<T>(prepare: impl FnOnce(&PathBuf) -> PathBuf, action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-refresh-once-per-host-{}-{nanos}",
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

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_millis() as u64
}

fn write_lease(pid: u32) {
    let lease = json!({ "pid": pid, "nonce": "theirs", "at": now_millis() });
    write_text_file(HASH, REFRESH_LEASE_FILE, &lease.to_string()).expect("write lease");
}

fn refreshed() -> Value {
    json!({ "access_token": "refreshed", "token_type": "Bearer" })
}

#[test]
fn redeems_the_stored_refresh_token_and_releases_the_lease() {
    with_temporary_config_dir(|| {
        let stored =
            json!({ "access_token": "old", "token_type": "Bearer", "refresh_token": "stored" });
        write_json_file(HASH, "tokens.json", &stored).expect("write tokens");
        let redeemed = RefCell::new(None);

        let result = provider().refresh_once_per_host("callers", |refresh_token| {
            assert!(read_json_file::<Value>(HASH, REFRESH_LEASE_FILE).is_some());
            *redeemed.borrow_mut() = Some(refresh_token.to_string());
            Some(refreshed())
        });

        assert_eq!(result, Some(refreshed()));
        assert_eq!(redeemed.into_inner().as_deref(), Some("stored"));
        assert!(read_json_file::<Value>(HASH, REFRESH_LEASE_FILE).is_none());
    });
}

#[test]
fn redeems_the_callers_refresh_token_when_none_is_stored() {
    with_temporary_config_dir(|| {
        let redeemed = RefCell::new(None);

        let result = provider().refresh_once_per_host("callers", |refresh_token| {
            *redeemed.borrow_mut() = Some(refresh_token.to_string());
            None
        });

        assert_eq!(result, None);
        assert_eq!(redeemed.into_inner().as_deref(), Some("callers"));
        assert!(read_json_file::<Value>(HASH, REFRESH_LEASE_FILE).is_none());
    });
}

#[test]
fn returns_the_token_a_live_sibling_wrote_without_refreshing() {
    with_temporary_config_dir(|| {
        let tokens = json!({ "access_token": "sibling", "token_type": "Bearer", "expires_at": now_millis() + 3_600_000 });
        write_json_file(HASH, "tokens.json", &tokens).expect("write tokens");
        write_lease(std::process::id());

        let result = provider().refresh_once_per_host("callers", |_| panic!("must not refresh"));

        assert_eq!(result, Some(tokens));
        let on_disk = read_json_file::<Value>(HASH, REFRESH_LEASE_FILE).expect("lease file");
        assert_eq!(on_disk["nonce"], "theirs");
    });
}

#[test]
fn gives_up_when_the_sibling_released_without_a_fresh_token() {
    with_temporary_config_dir(|| {
        write_lease(std::process::id());
        let releaser = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(300));
            delete_config_file(HASH, REFRESH_LEASE_FILE);
        });

        let result = provider().refresh_once_per_host("callers", |_| panic!("must not refresh"));
        releaser.join().expect("releaser thread");

        assert_eq!(result, None);
    });
}

#[test]
fn picks_up_the_refresh_an_abandoned_sibling_left() {
    with_temporary_config_dir(|| {
        write_lease(DEAD_PID);
        let redeemed = RefCell::new(None);

        let result = provider().refresh_once_per_host("callers", |refresh_token| {
            let on_disk = read_json_file::<Value>(HASH, REFRESH_LEASE_FILE).expect("lease file");
            assert_ne!(on_disk["nonce"], "theirs");
            *redeemed.borrow_mut() = Some(refresh_token.to_string());
            Some(refreshed())
        });

        assert_eq!(result, Some(refreshed()));
        assert_eq!(redeemed.into_inner().as_deref(), Some("callers"));
        assert!(read_json_file::<Value>(HASH, REFRESH_LEASE_FILE).is_none());
    });
}

#[test]
fn refreshes_without_coordinating_when_no_lease_can_be_taken() {
    with_config_dir(
        |directory| {
            let blocker = directory.join("not-a-directory");
            std::fs::write(&blocker, "").expect("write blocker file");
            blocker
        },
        || {
            let redeemed = RefCell::new(None);

            let result = provider().refresh_once_per_host("callers", |refresh_token| {
                *redeemed.borrow_mut() = Some(refresh_token.to_string());
                Some(refreshed())
            });

            assert_eq!(result, Some(refreshed()));
            assert_eq!(redeemed.into_inner().as_deref(), Some("callers"));
        },
    );
}
