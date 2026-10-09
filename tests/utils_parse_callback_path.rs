use rust_mcp_remote::utils::{DEFAULT_CALLBACK_PATH, parse_callback_path_to};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn uses_and_logs_a_valid_callback_path() {
    let mut console = Vec::new();

    let callback_path = parse_callback_path_to(
        &mut console,
        &arguments(&["https://example.com", "--callback-path", "/custom/callback"]),
    );

    assert_eq!(callback_path, "/custom/callback");
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Using callback path: /custom/callback\n")
    );
}

#[test]
fn warns_about_a_path_without_a_leading_slash() {
    let mut console = Vec::new();

    let callback_path = parse_callback_path_to(
        &mut console,
        &arguments(&["https://example.com", "--callback-path", "callback"]),
    );

    assert_eq!(callback_path, DEFAULT_CALLBACK_PATH);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Warning: Ignoring invalid callback path: callback. It must start with '/'.\n"
        )
    );
}

#[test]
fn warns_about_reserved_coordination_paths() {
    for reserved in ["/wait-for-auth", "/.mcp-remote/id"] {
        let mut console = Vec::new();

        let callback_path = parse_callback_path_to(
            &mut console,
            &arguments(&["https://example.com", "--callback-path", reserved]),
        );

        assert_eq!(callback_path, DEFAULT_CALLBACK_PATH);
        let pid = std::process::id();
        assert_eq!(
            String::from_utf8(console).expect("utf8"),
            format!(
                "[{pid}] Warning: Ignoring reserved callback path: {reserved}. It is used to coordinate concurrent instances.\n"
            )
        );
    }
}

#[test]
fn falls_back_to_the_default_silently() {
    for args in [
        arguments(&["https://example.com"]),
        arguments(&["https://example.com", "--callback-path"]),
    ] {
        let mut console = Vec::new();

        let callback_path = parse_callback_path_to(&mut console, &args);

        assert_eq!(callback_path, "/oauth/callback");
        assert!(console.is_empty());
    }
}
