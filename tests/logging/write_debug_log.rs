use rust_mcp_remote::logging::write_debug_log;
use rust_mcp_remote::mcp_auth_config::config_file_path;
use serde_json::json;

use crate::with_temporary_config_dir;

const HASH: &str = "write-debug-log-test";

#[test]
fn the_message_goes_to_the_console_and_to_the_debug_log() {
    with_temporary_config_dir(|_| {
        let mut console = Vec::new();
        write_debug_log(
            &mut console,
            Some(HASH),
            "[t][7] Token",
            &[json!("refreshed"), json!({"expires_in": 3600})],
        );
        assert_eq!(
            String::from_utf8(console).expect("utf8"),
            "[t][7] Token refreshed {\"expires_in\":3600}\n"
        );
        let content =
            std::fs::read_to_string(config_file_path(HASH, "debug.log")).expect("read debug log");
        assert_eq!(content, "[t][7] Token refreshed {\"expires_in\":3600}\n");
    });
}

#[test]
fn a_message_without_arguments_has_no_trailing_space_on_the_console() {
    with_temporary_config_dir(|_| {
        let mut console = Vec::new();
        write_debug_log(&mut console, Some(HASH), "[t][7] Starting", &[]);
        assert_eq!(
            String::from_utf8(console).expect("utf8"),
            "[t][7] Starting\n"
        );
        let content =
            std::fs::read_to_string(config_file_path(HASH, "debug.log")).expect("read debug log");
        assert_eq!(content, "[t][7] Starting \n");
    });
}

#[test]
fn without_a_server_url_hash_only_an_error_is_shown() {
    with_temporary_config_dir(|directory| {
        let mut console = Vec::new();
        write_debug_log(&mut console, None, "[t][7] Starting", &[]);
        assert_eq!(
            String::from_utf8(console).expect("utf8"),
            "[DEBUG LOG ERROR] global.currentServerUrlHash is not set. Cannot write debug log.\n"
        );
        assert!(!directory.exists());
    });
}

#[test]
fn a_failed_file_write_is_reported_on_the_console() {
    with_temporary_config_dir(|directory| {
        std::fs::write(directory, "not a directory").expect("write blocking file");
        let mut console = Vec::new();
        write_debug_log(&mut console, Some(HASH), "[t][7] Starting", &[]);
        std::fs::remove_file(directory).expect("remove blocking file");
        let output = String::from_utf8(console).expect("utf8");
        let mut lines = output.lines();
        assert_eq!(lines.next(), Some("[t][7] Starting"));
        assert!(
            lines
                .next()
                .is_some_and(|line| line.starts_with("[DEBUG LOG ERROR] ")),
            "{output}"
        );
        assert_eq!(lines.next(), None);
    });
}
