use rust_mcp_remote::utils::{NetworkOptions, parse_network_options_to};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn parses_timeouts_and_ipv4_and_logs_them() {
    let mut console = Vec::new();

    let options = parse_network_options_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--connect-timeout",
            "1.5",
            "--body-timeout",
            "0",
            "--headers-timeout",
            "30",
            "--ipv4",
        ]),
    );

    assert_eq!(
        options,
        NetworkOptions {
            connect_timeout_ms: Some(1500),
            body_timeout_ms: Some(0),
            headers_timeout_ms: Some(30000),
            force_ipv4: true,
        }
    );
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Restricting connections to IPv4\n\
             [{pid}] Using connect timeout: 1.5 seconds\n\
             [{pid}] Using body timeout: disabled\n\
             [{pid}] Using headers timeout: 30 seconds\n"
        )
    );
}

#[test]
fn logs_disabled_headers_timeout_and_seconds_body_timeout() {
    let mut console = Vec::new();

    let options = parse_network_options_to(
        &mut console,
        &arguments(&["--body-timeout", "0.001", "--headers-timeout", "0"]),
    );

    assert_eq!(options.body_timeout_ms, Some(1));
    assert_eq!(options.headers_timeout_ms, Some(0));
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Using body timeout: 0.001 seconds\n\
             [{pid}] Using headers timeout: disabled\n"
        )
    );
}

#[test]
fn writes_warnings_before_logs_and_nothing_without_flags() {
    let mut console = Vec::new();

    let options = parse_network_options_to(
        &mut console,
        &arguments(&["--connect-timeout", "0", "--ipv4"]),
    );

    assert_eq!(options.connect_timeout_ms, None);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Warning: Ignoring invalid --connect-timeout value: 0. Must be a positive number of seconds.\n\
             [{pid}] Restricting connections to IPv4\n"
        )
    );

    let mut quiet_console = Vec::new();
    let defaults =
        parse_network_options_to(&mut quiet_console, &arguments(&["https://example.com"]));
    assert_eq!(defaults, NetworkOptions::default());
    assert!(quiet_console.is_empty());
}
