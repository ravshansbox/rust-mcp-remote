use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{read_config_lease, write_text_file};
use serde_json::json;

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "lease-test";
const FILENAME: &str = "refresh_in_progress.json";
const TTL: Duration = Duration::from_secs(30);
const DEAD_PID: u32 = 0x7fffffff;

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = ENVIRONMENT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf =
        std::env::temp_dir().join(format!("mcp-remote-config-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create temporary directory");
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    std::fs::remove_dir_all(&directory).expect("remove temporary directory");
    result
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_millis() as u64
}

fn write_lease(lease: serde_json::Value) {
    write_text_file(HASH, FILENAME, &lease.to_string()).expect("write lease");
}

#[test]
fn no_lease_on_disk_reads_as_none() {
    with_temporary_config_dir(|| {
        assert_eq!(read_config_lease(HASH, FILENAME, TTL), None);
    });
}

#[test]
fn a_lease_held_by_a_running_owner_within_its_deadline_is_live() {
    with_temporary_config_dir(|| {
        let at = now_millis();
        write_lease(json!({ "pid": std::process::id(), "nonce": "theirs", "at": at }));

        let lease = read_config_lease(HASH, FILENAME, TTL).expect("lease");

        assert_eq!(lease.pid, std::process::id());
        assert_eq!(lease.nonce, "theirs");
        assert_eq!(lease.at, at as f64);
        assert!(lease.live);
    });
}

#[test]
fn a_lease_whose_owner_died_is_not_live() {
    with_temporary_config_dir(|| {
        write_lease(json!({ "pid": DEAD_PID, "nonce": "theirs", "at": now_millis() }));

        let lease = read_config_lease(HASH, FILENAME, TTL).expect("lease");

        assert!(!lease.live);
    });
}

#[test]
fn a_lease_held_past_its_deadline_is_not_live() {
    with_temporary_config_dir(|| {
        let at = now_millis() - TTL.as_millis() as u64 - 1;
        write_lease(json!({ "pid": std::process::id(), "nonce": "theirs", "at": at }));

        let lease = read_config_lease(HASH, FILENAME, TTL).expect("lease");

        assert!(!lease.live);
    });
}

#[test]
fn a_lease_that_is_not_json_reads_as_none() {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "not json at all").expect("write lease");

        assert_eq!(read_config_lease(HASH, FILENAME, TTL), None);
    });
}

#[test]
fn a_lease_that_breaks_the_schema_reads_as_none() {
    with_temporary_config_dir(|| {
        let at = now_millis();
        for lease in [
            json!({ "pid": 0, "nonce": "theirs", "at": at }),
            json!({ "pid": -1, "nonce": "theirs", "at": at }),
            json!({ "pid": 1.5, "nonce": "theirs", "at": at }),
            json!({ "pid": std::process::id(), "nonce": "", "at": at }),
            json!({ "pid": std::process::id(), "at": at }),
            json!({ "pid": std::process::id(), "nonce": "theirs" }),
        ] {
            write_lease(lease.clone());

            assert_eq!(read_config_lease(HASH, FILENAME, TTL), None, "{lease}");
        }
    });
}
