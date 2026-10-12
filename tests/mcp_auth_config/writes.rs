use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};

use rust_mcp_remote::mcp_auth_config::{config_dir, config_file_path, write_json_file};
use serde_json::{Value, json};

use crate::with_temporary_config_dir;

const HASH: &str = "write-test";
const FILENAME: &str = "tokens.json";

#[test]
fn a_reader_never_observes_a_half_written_file() {
    with_temporary_config_dir(|| {
        let big = json!({ "access_token": "a".repeat(5_000_000), "refresh_token": "r" });
        let target = config_file_path(HASH, FILENAME);
        let done = AtomicBool::new(false);
        let torn = AtomicBool::new(false);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::SeqCst) {
                    match std::fs::read_to_string(&target) {
                        Ok(content) => {
                            if serde_json::from_str::<Value>(&content).is_err() {
                                torn.store(true, Ordering::SeqCst);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(_) => torn.store(true, Ordering::SeqCst),
                    }
                }
            });
            write_json_file(HASH, FILENAME, &big).expect("write succeeds");
            done.store(true, Ordering::SeqCst);
        });

        assert!(!torn.load(Ordering::SeqCst));
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&target).expect("read")).expect("json");
        assert_eq!(
            written["access_token"].as_str().map(str::len),
            Some(5_000_000)
        );
    });
}

#[test]
fn no_temp_files_are_left_behind() {
    with_temporary_config_dir(|| {
        write_json_file(HASH, FILENAME, &json!({ "access_token": "a" })).expect("write succeeds");

        let leftovers: Vec<String> = std::fs::read_dir(config_dir())
            .expect("read directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert_eq!(leftovers, Vec::<String>::new());
    });
}

#[test]
fn the_file_stays_owner_only() {
    with_temporary_config_dir(|| {
        write_json_file(HASH, FILENAME, &json!({ "access_token": "a" })).expect("write succeeds");

        let mode = std::fs::metadata(config_file_path(HASH, FILENAME))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    });
}

#[test]
fn the_file_is_pretty_printed_with_two_space_indentation() {
    with_temporary_config_dir(|| {
        write_json_file(
            HASH,
            FILENAME,
            &json!({ "access_token": "a", "scopes": ["x"] }),
        )
        .expect("write succeeds");

        let content = std::fs::read_to_string(config_file_path(HASH, FILENAME)).expect("read");
        assert_eq!(
            content,
            "{\n  \"access_token\": \"a\",\n  \"scopes\": [\n    \"x\"\n  ]\n}"
        );
    });
}

#[test]
fn the_config_directory_is_created_when_missing() {
    with_temporary_config_dir(|| {
        assert!(!config_dir().exists());

        write_json_file(HASH, FILENAME, &json!({})).expect("write succeeds");

        assert!(config_file_path(HASH, FILENAME).exists());
    });
}
