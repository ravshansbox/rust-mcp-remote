use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{write_json_file, write_text_file};
use rust_mcp_remote::node_oauth_client_provider::{
    REFRESH_LEASE_FILE, SiblingRefresh, await_refresh_by_sibling,
};
use serde_json::json;

use crate::with_temporary_config_dir;

const HASH: &str = "sibling-test";
const DEAD_PID: u32 = 0x7fffffff;

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

#[test]
fn a_fresh_token_written_by_the_sibling_is_returned() {
    with_temporary_config_dir(|| {
        let tokens = json!({ "access_token": "new", "token_type": "Bearer", "expires_at": now_millis() + 3_600_000 });
        write_json_file(HASH, "tokens.json", &tokens).expect("write tokens");
        write_lease(std::process::id());

        assert_eq!(
            await_refresh_by_sibling(HASH),
            SiblingRefresh::Tokens(tokens)
        );
    });
}

#[test]
fn a_released_lease_without_a_fresh_token_ends_the_wait() {
    with_temporary_config_dir(|| {
        let tokens =
            json!({ "access_token": "old", "token_type": "Bearer", "expires_at": now_millis() });
        write_json_file(HASH, "tokens.json", &tokens).expect("write tokens");

        assert_eq!(await_refresh_by_sibling(HASH), SiblingRefresh::Released);
    });
}

#[test]
fn a_lease_held_by_a_dead_owner_is_abandoned() {
    with_temporary_config_dir(|| {
        write_lease(DEAD_PID);

        assert_eq!(await_refresh_by_sibling(HASH), SiblingRefresh::Abandoned);
    });
}

#[test]
fn waits_while_a_live_sibling_holds_the_lease_until_it_writes_a_token() {
    with_temporary_config_dir(|| {
        write_lease(std::process::id());
        let tokens = json!({ "access_token": "later", "token_type": "Bearer", "expires_at": now_millis() + 3_600_000 });
        let written = tokens.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            write_json_file(HASH, "tokens.json", &written).expect("write tokens");
        });

        let result = await_refresh_by_sibling(HASH);
        writer.join().expect("writer thread");

        assert_eq!(result, SiblingRefresh::Tokens(tokens));
    });
}
