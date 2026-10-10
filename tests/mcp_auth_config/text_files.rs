use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::mcp_auth_config::{
    config_dir, config_file_path, read_text_file, write_text_file,
};

use crate::GLOBAL_STATE as ENVIRONMENT;

const HASH: &str = "text-test";
const FILENAME: &str = "code_verifier.txt";

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

#[test]
fn written_text_is_read_back_unchanged() {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "test-verifier\n").expect("write text");
        let text = read_text_file(HASH, FILENAME, None).expect("read text");
        assert_eq!(text, "test-verifier\n");
    });
}

#[test]
fn writing_creates_a_missing_config_directory() {
    with_temporary_config_dir(|| {
        assert!(!config_dir().exists());
        write_text_file(HASH, FILENAME, "value").expect("write text");
        assert!(config_file_path(HASH, FILENAME).is_file());
    });
}

#[test]
fn writing_replaces_existing_content() {
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "a much longer first value").expect("first write");
        write_text_file(HASH, FILENAME, "short").expect("second write");
        assert_eq!(read_text_file(HASH, FILENAME, None).expect("read"), "short");
    });
}

#[cfg(unix)]
#[test]
fn written_text_is_readable_only_by_the_owner() {
    use std::os::unix::fs::PermissionsExt;
    with_temporary_config_dir(|| {
        write_text_file(HASH, FILENAME, "secret").expect("write text");
        let mode = std::fs::metadata(config_file_path(HASH, FILENAME))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    });
}

#[test]
fn reading_a_missing_file_fails_with_the_default_message() {
    with_temporary_config_dir(|| {
        let error = read_text_file(HASH, FILENAME, None).expect_err("missing file");
        assert_eq!(error.to_string(), "Error reading code_verifier.txt");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    });
}

#[test]
fn reading_a_missing_file_fails_with_the_given_message() {
    with_temporary_config_dir(|| {
        let error = read_text_file(HASH, FILENAME, Some("No code verifier saved for session"))
            .expect_err("missing file");
        assert_eq!(error.to_string(), "No code verifier saved for session");
    });
}

#[test]
fn reading_with_an_empty_message_uses_the_default_message() {
    with_temporary_config_dir(|| {
        let error = read_text_file(HASH, FILENAME, Some("")).expect_err("missing file");
        assert_eq!(error.to_string(), "Error reading code_verifier.txt");
    });
}
