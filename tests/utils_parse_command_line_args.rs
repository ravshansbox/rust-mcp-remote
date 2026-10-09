use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rust_mcp_remote::logging::{set_current_server_url_hash, set_debug, set_silent};
use rust_mcp_remote::protocol_era::ProtocolMode;
use rust_mcp_remote::utils::{
    KeepAliveConfig, TransportStrategy, calculate_default_port, get_server_url_hash,
    parse_command_line_args_to,
};

static GLOBAL_STATE: Mutex<()> = Mutex::new(());

const USAGE: &str = "Usage: mcp-remote <https://server-url> [callback-port]";

fn with_temporary_config_dir<T>(action: impl FnOnce() -> T) -> T {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_nanos();
    let directory: PathBuf = std::env::temp_dir().join(format!(
        "mcp-remote-parse-command-line-args-{}-{nanos}",
        std::process::id()
    ));
    unsafe { std::env::set_var("MCP_REMOTE_CONFIG_DIR", &directory) };
    let result = action();
    unsafe { std::env::remove_var("MCP_REMOTE_CONFIG_DIR") };
    let _ = std::fs::remove_dir_all(&directory);
    set_debug(false);
    set_silent(false);
    set_current_server_url_hash(None);
    result
}

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn console_lines(console: Vec<u8>) -> Vec<String> {
    String::from_utf8(console)
        .expect("utf8")
        .lines()
        .map(|line| {
            line.split_once("] ")
                .map_or(line, |(_, rest)| rest)
                .to_string()
        })
        .collect()
}

#[test]
fn missing_server_url_logs_usage_and_returns_none() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();

        let parsed = parse_command_line_args_to(&mut console, arguments(&[]), USAGE);

        assert_eq!(parsed, Ok(None));
        assert_eq!(console_lines(console), vec![USAGE.to_string()]);
    });
}

#[test]
fn plain_http_server_url_is_rejected_without_allow_http() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();

        let parsed =
            parse_command_line_args_to(&mut console, arguments(&["http://example.com/mcp"]), USAGE);

        assert_eq!(parsed, Ok(None));
    });
}

#[test]
fn defaults_derive_the_callback_port_from_the_server_url_hash() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();

        let parsed = parse_command_line_args_to(
            &mut console,
            arguments(&["https://example.com/mcp"]),
            USAGE,
        )
        .expect("parsed")
        .expect("not exiting");

        let expected_hash = get_server_url_hash(
            "https://example.com/mcp",
            None,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            None,
        );
        let expected_port = calculate_default_port(&expected_hash).expect("port");
        assert_eq!(parsed.server_url, "https://example.com/mcp");
        assert_eq!(parsed.server_url_hash, expected_hash);
        assert_eq!(parsed.specified_port, None);
        assert_eq!(parsed.callback_port, expected_port);
        assert_eq!(parsed.callback_path, "/oauth/callback");
        assert_eq!(parsed.transport_strategy, TransportStrategy::HttpFirst);
        assert_eq!(parsed.protocol_mode, ProtocolMode::Legacy);
        assert_eq!(
            parsed.keep_alive,
            KeepAliveConfig {
                enabled: false,
                interval_ms: 30_000,
            }
        );
        assert_eq!(parsed.auth_timeout_ms, 30_000);
        assert!(parsed.headers.is_empty());
        assert!(parsed.ignored_tools.is_empty());
        assert!(!parsed.debug);
        assert!(parsed.cookies_enabled);
        assert!(!parsed.non_interactive_flow);
        assert_eq!(
            console_lines(console),
            vec![format!(
                "Using callback port derived from the server URL: {expected_port}"
            )]
        );
    });
}

#[test]
fn flags_are_parsed_and_logged_in_typescript_order() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();

        let parsed = parse_command_line_args_to(
            &mut console,
            arguments(&[
                "https://example.com/mcp",
                "4321",
                "--header",
                "X-Team:alpha",
                "--keep-alive",
                "--transport",
                "sse-only",
                "--ignore-tool",
                "delete*",
                "--device-code",
                "--auth-timeout",
                "60",
            ]),
            USAGE,
        )
        .expect("parsed")
        .expect("not exiting");

        let expected_hash = get_server_url_hash(
            "https://example.com/mcp",
            None,
            &BTreeMap::from([("X-Team".to_string(), "alpha".to_string())]),
            &BTreeMap::new(),
            None,
            None,
        );
        assert_eq!(parsed.server_url_hash, expected_hash);
        assert_eq!(parsed.specified_port, Some(4321));
        assert_eq!(parsed.callback_port, 4321);
        assert_eq!(
            parsed.headers,
            vec![("X-Team".to_string(), "alpha".to_string())]
        );
        assert!(parsed.keep_alive.enabled);
        assert_eq!(parsed.transport_strategy, TransportStrategy::SseOnly);
        assert_eq!(parsed.ignored_tools, vec!["delete*".to_string()]);
        assert!(parsed.use_device_code);
        assert!(parsed.non_interactive_flow);
        assert_eq!(parsed.auth_timeout_ms, 60_000);
        assert_eq!(
            console_lines(console),
            vec![
                "Using transport strategy: sse-only".to_string(),
                "Using the OAuth device grant; no browser will be opened on this machine"
                    .to_string(),
                "Ignoring tool: delete*".to_string(),
                "Using auth callback timeout: 60 seconds".to_string(),
                "Using specified callback port: 4321".to_string(),
                "Using custom headers: X-Team".to_string(),
            ]
        );
    });
}

#[test]
fn non_numeric_second_argument_is_not_a_port() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();

        let parsed = parse_command_line_args_to(
            &mut console,
            arguments(&["https://example.com/mcp", "--keep-alive"]),
            USAGE,
        )
        .expect("parsed")
        .expect("not exiting");

        assert_eq!(parsed.specified_port, None);
    });
}

#[test]
fn token_endpoint_without_client_credentials_is_an_error() {
    with_temporary_config_dir(|| {
        let mut console = Vec::new();

        let parsed = parse_command_line_args_to(
            &mut console,
            arguments(&[
                "https://example.com/mcp",
                "--token-endpoint",
                "https://auth.example.com/token",
            ]),
            USAGE,
        );

        assert!(parsed.is_err());
    });
}
