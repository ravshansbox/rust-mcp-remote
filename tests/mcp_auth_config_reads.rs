use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{config_file_path, read_json_file, write_json_file};
use serde::Deserialize;
use serde_json::json;

static ENVIRONMENT: Mutex<()> = Mutex::new(());

const HASH: &str = "read-test";
const FILENAME: &str = "tokens.json";

#[derive(Debug, Deserialize, PartialEq)]
struct Tokens {
    access_token: String,
    token_type: String,
}

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

fn write_raw(content: &str) {
    let path = config_file_path(HASH, FILENAME);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create config directory");
    std::fs::write(path, content).expect("write raw file");
}

#[test]
fn a_missing_file_reads_as_none() {
    with_temporary_config_dir(|| {
        assert_eq!(read_json_file::<Tokens>(HASH, FILENAME), None);
    });
}

#[test]
fn a_written_file_reads_back_as_the_typed_value() {
    with_temporary_config_dir(|| {
        write_json_file(
            HASH,
            FILENAME,
            &json!({ "access_token": "abc", "token_type": "Bearer" }),
        )
        .expect("write succeeds");
        assert_eq!(
            read_json_file::<Tokens>(HASH, FILENAME),
            Some(Tokens {
                access_token: "abc".to_string(),
                token_type: "Bearer".to_string(),
            })
        );
    });
}

#[test]
fn malformed_json_reads_as_none() {
    with_temporary_config_dir(|| {
        write_raw("{\"access_token\": \"ab");
        assert_eq!(read_json_file::<Tokens>(HASH, FILENAME), None);
    });
}

#[test]
fn content_that_does_not_match_the_type_reads_as_none() {
    with_temporary_config_dir(|| {
        write_raw("{\"access_token\": 42}");
        assert_eq!(read_json_file::<Tokens>(HASH, FILENAME), None);
    });
}

#[test]
fn reading_creates_the_config_directory() {
    with_temporary_config_dir(|| {
        assert_eq!(read_json_file::<Tokens>(HASH, FILENAME), None);
        assert!(
            config_file_path(HASH, FILENAME)
                .parent()
                .expect("parent")
                .is_dir()
        );
    });
}
