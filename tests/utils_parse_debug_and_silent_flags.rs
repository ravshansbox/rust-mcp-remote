use std::sync::Mutex;

use rust_mcp_remote::logging::{log_to, set_current_server_url_hash, set_debug, set_silent};
use rust_mcp_remote::utils::parse_debug_and_silent_flags_to;

static GLOBAL_STATE: Mutex<()> = Mutex::new(());

fn with_reset_flags<T>(action: impl FnOnce() -> T) -> T {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let result = action();
    set_debug(false);
    set_silent(false);
    set_current_server_url_hash(None);
    result
}

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn console_text(console: Vec<u8>) -> String {
    String::from_utf8(console).expect("utf8")
}

const MISSING_HASH: &str =
    "[DEBUG LOG ERROR] global.currentServerUrlHash is not set. Cannot write debug log.\n";

#[test]
fn leaves_both_modes_off_without_the_flags() {
    with_reset_flags(|| {
        let mut console = Vec::new();

        let debug = parse_debug_and_silent_flags_to(&mut console, &arguments(&["https://x"]));

        assert!(!debug);
        assert_eq!(console_text(console), "");
        let mut later = Vec::new();
        log_to(&mut later, "Visible", &[]);
        assert_eq!(
            console_text(later),
            format!("[{}] Visible\n", std::process::id())
        );
    });
}

#[test]
fn enables_debug_and_announces_it() {
    with_reset_flags(|| {
        let mut console = Vec::new();

        let debug =
            parse_debug_and_silent_flags_to(&mut console, &arguments(&["https://x", "--debug"]));

        assert!(debug);
        assert_eq!(
            console_text(console),
            format!(
                "[{}] Debug mode enabled - detailed logs will be written to ~/.mcp-auth/\n{MISSING_HASH}",
                std::process::id()
            )
        );
    });
}

#[test]
fn enables_silent_mode_after_which_its_own_message_is_hidden() {
    with_reset_flags(|| {
        let mut console = Vec::new();

        let debug =
            parse_debug_and_silent_flags_to(&mut console, &arguments(&["https://x", "--silent"]));

        assert!(!debug);
        assert_eq!(console_text(console), "");
        let mut later = Vec::new();
        log_to(&mut later, "Hidden", &[]);
        assert_eq!(console_text(later), "");
    });
}

#[test]
fn with_both_flags_the_silent_message_only_reaches_the_debug_log() {
    with_reset_flags(|| {
        let mut console = Vec::new();

        let debug = parse_debug_and_silent_flags_to(
            &mut console,
            &arguments(&["https://x", "--silent", "--debug"]),
        );

        assert!(debug);
        assert_eq!(
            console_text(console),
            format!(
                "[{}] Debug mode enabled - detailed logs will be written to ~/.mcp-auth/\n{MISSING_HASH}{MISSING_HASH}",
                std::process::id()
            )
        );
    });
}
