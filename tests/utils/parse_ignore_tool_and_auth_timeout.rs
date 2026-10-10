use rust_mcp_remote::utils::{parse_auth_timeout_to, parse_ignored_tools_to};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn collects_ignored_tools_and_removes_them_from_arguments() {
    let mut console = Vec::new();
    let mut args = arguments(&[
        "https://example.com",
        "--ignore-tool",
        "delete*",
        "--allow-http",
        "--ignore-tool",
        "write",
        "--ignore-tool",
    ]);

    let ignored_tools = parse_ignored_tools_to(&mut console, &mut args);

    assert_eq!(ignored_tools, vec!["delete*", "write"]);
    assert_eq!(
        args,
        arguments(&["https://example.com", "--allow-http", "--ignore-tool"])
    );
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Ignoring tool: delete*\n[{pid}] Ignoring tool: write\n")
    );
}

#[test]
fn uses_a_positive_auth_timeout_in_milliseconds() {
    let mut console = Vec::new();

    let auth_timeout_ms = parse_auth_timeout_to(
        &mut console,
        &arguments(&["https://example.com", "--auth-timeout", " 45s"]),
    );

    assert_eq!(auth_timeout_ms, 45_000);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Using auth callback timeout: 45 seconds\n")
    );
}

#[test]
fn ignores_an_invalid_auth_timeout() {
    for raw in ["0", "-5", "abc"] {
        let mut console = Vec::new();

        let auth_timeout_ms = parse_auth_timeout_to(
            &mut console,
            &arguments(&["https://example.com", "--auth-timeout", raw]),
        );

        assert_eq!(auth_timeout_ms, 30_000);
        let pid = std::process::id();
        assert_eq!(
            String::from_utf8(console).expect("utf8"),
            format!(
                "[{pid}] Warning: Ignoring invalid auth timeout value: {raw}. Must be a positive number.\n"
            )
        );
    }
}

#[test]
fn defaults_the_auth_timeout_silently() {
    let mut console = Vec::new();

    let auth_timeout_ms = parse_auth_timeout_to(
        &mut console,
        &arguments(&["https://example.com", "--auth-timeout"]),
    );

    assert_eq!(auth_timeout_ms, 30_000);
    assert!(console.is_empty());
}
