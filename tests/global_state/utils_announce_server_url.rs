use rust_mcp_remote::logging::set_debug;
use rust_mcp_remote::mcp_auth_config::config_file_path;
use rust_mcp_remote::utils::announce_server_url_to;

use crate::{console_text, with_temporary_config_dir};

const HASH: &str = "announce-server-url-test";

#[test]
fn writes_the_starting_line_to_the_debug_log_of_the_server() {
    with_temporary_config_dir(|| {
        set_debug(true);
        let mut console = Vec::new();

        announce_server_url_to(&mut console, "https://example.com/mcp", HASH);

        let pid = std::process::id();
        let suffix =
            format!("][{pid}] Starting mcp-remote with server URL: https://example.com/mcp");
        let console_output = console_text(console);
        assert!(console_output.starts_with('['));
        assert!(console_output.ends_with(&format!("{suffix}\n")));
        let content =
            std::fs::read_to_string(config_file_path(HASH, "debug.log")).expect("read debug log");
        assert!(content.ends_with(&format!("{suffix} \n")));
    });
}

#[test]
fn sets_the_server_hash_silently_when_debug_is_off() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();

        announce_server_url_to(&mut console, "https://example.com/mcp", HASH);

        assert_eq!(console_text(console), "");
        assert!(!config_file_path(HASH, "debug.log").exists());
        set_debug(true);
        let mut later = Vec::new();
        rust_mcp_remote::logging::debug_log_to(&mut later, "Later", &[]);
        assert!(config_file_path(HASH, "debug.log").exists());
    });
}
