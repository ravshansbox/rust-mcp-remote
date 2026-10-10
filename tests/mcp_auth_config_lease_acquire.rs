use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{
    acquire_config_lease, config_file_path, read_config_lease, release_config_lease,
    write_text_file,
};
use serde_json::{Value, json};

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const HASH: &str = "lease-acquire-test";
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

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_millis()
}

fn lease_on_disk() -> Value {
    let content = std::fs::read_to_string(config_file_path(HASH, FILENAME)).expect("lease");
    serde_json::from_str(&content).expect("lease is JSON")
}

fn write_lease(lease: Value) {
    write_text_file(HASH, FILENAME, &lease.to_string()).expect("write lease");
}

#[test]
fn several_instances_race_and_exactly_one_gets_the_lease() {
    with_temporary_config_dir(|| {
        let claims: Vec<Option<String>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| acquire_config_lease(HASH, FILENAME, TTL).expect("config dir"))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("thread"))
                .collect()
        });

        let winners: Vec<&String> = claims.iter().flatten().collect();
        assert_eq!(winners.len(), 1);
        assert_eq!(lease_on_disk()["nonce"], json!(winners[0]));
    });
}

#[test]
fn an_instance_that_is_still_working_keeps_its_lease() {
    with_temporary_config_dir(|| {
        assert!(
            acquire_config_lease(HASH, FILENAME, TTL)
                .expect("config dir")
                .is_some()
        );

        assert_eq!(
            acquire_config_lease(HASH, FILENAME, TTL).expect("config dir"),
            None
        );
        assert!(read_config_lease(HASH, FILENAME, TTL).expect("lease").live);
    });
}

#[test]
fn a_lease_its_owner_died_holding_is_taken_over_at_once() {
    with_temporary_config_dir(|| {
        write_lease(json!({ "pid": DEAD_PID, "nonce": "theirs", "at": now_millis() as u64 }));

        assert!(!read_config_lease(HASH, FILENAME, TTL).expect("lease").live);
        assert!(
            acquire_config_lease(HASH, FILENAME, TTL)
                .expect("config dir")
                .is_some()
        );
        assert_eq!(lease_on_disk()["pid"], json!(std::process::id()));
    });
}

#[test]
fn a_live_owner_past_its_deadline_stops_holding_everyone_up() {
    with_temporary_config_dir(|| {
        let at = now_millis() - TTL.as_millis() - 1;
        write_lease(json!({ "pid": std::process::id(), "nonce": "theirs", "at": at as u64 }));

        assert!(!read_config_lease(HASH, FILENAME, TTL).expect("lease").live);
        assert!(
            acquire_config_lease(HASH, FILENAME, TTL)
                .expect("config dir")
                .is_some()
        );
    });
}

#[test]
fn a_lease_nothing_can_make_sense_of_is_not_left_blocking() {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "not json at all").expect("write lease");

        assert_eq!(read_config_lease(HASH, FILENAME, TTL), None);
        assert!(
            acquire_config_lease(HASH, FILENAME, TTL)
                .expect("config dir")
                .is_some()
        );
    });
}

#[test]
fn the_lease_records_this_process_and_an_integer_timestamp() {
    with_temporary_config_dir(|| {
        let nonce = acquire_config_lease(HASH, FILENAME, TTL)
            .expect("config dir")
            .expect("lease");

        let lease = lease_on_disk();
        assert_eq!(lease["nonce"], json!(nonce));
        assert_eq!(lease["pid"], json!(std::process::id()));
        assert!(lease["at"].is_u64());
    });
}

#[test]
fn releasing_frees_the_filename_for_the_next_instance() {
    with_temporary_config_dir(|| {
        let nonce = acquire_config_lease(HASH, FILENAME, TTL)
            .expect("config dir")
            .expect("lease");

        release_config_lease(HASH, FILENAME, &nonce);

        assert_eq!(read_config_lease(HASH, FILENAME, TTL), None);
        assert!(
            acquire_config_lease(HASH, FILENAME, TTL)
                .expect("config dir")
                .is_some()
        );
    });
}

#[test]
fn a_filename_nothing_can_hold_does_not_spin() {
    with_temporary_config_dir(|| {
        std::fs::create_dir_all(config_file_path(HASH, FILENAME)).expect("create directory");

        assert_eq!(
            acquire_config_lease(HASH, FILENAME, TTL).expect("config dir"),
            None
        );
    });
}

#[cfg(unix)]
#[test]
fn the_lease_is_readable_only_by_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    with_temporary_config_dir(|| {
        acquire_config_lease(HASH, FILENAME, TTL)
            .expect("config dir")
            .expect("lease");

        let metadata = std::fs::metadata(config_file_path(HASH, FILENAME)).expect("metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    });
}
