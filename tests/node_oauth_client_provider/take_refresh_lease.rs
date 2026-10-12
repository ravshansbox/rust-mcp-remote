use rust_mcp_remote::mcp_auth_config::read_json_file;
use rust_mcp_remote::node_oauth_client_provider::{
    NodeOAuthClientProvider, REFRESH_LEASE_FILE, UNCOORDINATED,
};
use serde_json::Value;

use crate::{with_config_dir, with_temporary_config_dir};

const HASH: &str = "take-refresh-lease-test";

fn provider() -> NodeOAuthClientProvider {
    crate::provider_with_hash(HASH)
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
