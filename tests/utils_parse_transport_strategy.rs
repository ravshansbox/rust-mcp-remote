use rust_mcp_remote::utils::{TransportStrategy, parse_transport_strategy_to};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn uses_and_logs_a_valid_transport_strategy() {
    let mut console = Vec::new();

    let strategy = parse_transport_strategy_to(
        &mut console,
        &arguments(&["https://example.com", "--transport", "sse-only"]),
    );

    assert_eq!(strategy, TransportStrategy::SseOnly);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Using transport strategy: sse-only\n")
    );
}

#[test]
fn warns_about_an_invalid_strategy_and_keeps_the_default() {
    let mut console = Vec::new();

    let strategy = parse_transport_strategy_to(
        &mut console,
        &arguments(&["https://example.com", "--transport", "websocket"]),
    );

    assert_eq!(strategy, TransportStrategy::HttpFirst);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Warning: Ignoring invalid transport strategy: websocket. Valid values are: sse-only, http-only, sse-first, http-first\n"
        )
    );
}

#[test]
fn defaults_to_http_first_silently_without_a_value() {
    for values in [
        &["https://example.com"][..],
        &["https://example.com", "--transport"][..],
    ] {
        let mut console = Vec::new();

        let strategy = parse_transport_strategy_to(&mut console, &arguments(values));

        assert_eq!(strategy, TransportStrategy::HttpFirst);
        assert!(console.is_empty());
    }
}

#[test]
fn reads_every_valid_strategy_name() {
    for (name, expected) in [
        ("sse-only", TransportStrategy::SseOnly),
        ("http-only", TransportStrategy::HttpOnly),
        ("sse-first", TransportStrategy::SseFirst),
        ("http-first", TransportStrategy::HttpFirst),
    ] {
        let mut console = Vec::new();

        let strategy =
            parse_transport_strategy_to(&mut console, &arguments(&["--transport", name]));

        assert_eq!(strategy, expected);
        assert_eq!(expected.as_str(), name);
    }
}
