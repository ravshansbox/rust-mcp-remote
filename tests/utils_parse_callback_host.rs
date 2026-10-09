use rust_mcp_remote::utils::parse_callback_host_to;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn uses_and_logs_an_explicit_host() {
    let mut console = Vec::new();

    let host = parse_callback_host_to(
        &mut console,
        &arguments(&["https://example.com", "--host", "127.0.0.1"]),
    );

    assert_eq!(host, "127.0.0.1");
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Using callback hostname: 127.0.0.1\n")
    );
}

#[test]
fn falls_back_to_the_platform_default_silently() {
    let expected = if cfg!(windows) {
        "127.0.0.1"
    } else {
        "localhost"
    };
    for args in [
        arguments(&["https://example.com"]),
        arguments(&["https://example.com", "--host"]),
    ] {
        let mut console = Vec::new();

        let host = parse_callback_host_to(&mut console, &args);

        assert_eq!(host, expected);
        assert!(console.is_empty());
    }
}
