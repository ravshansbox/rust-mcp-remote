use rust_mcp_remote::protocol_era::ProtocolMode;
use rust_mcp_remote::utils::parse_protocol_mode_to;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn uses_and_logs_a_valid_protocol_mode() {
    let mut console = Vec::new();

    let mode = parse_protocol_mode_to(
        &mut console,
        &arguments(&["https://example.com", "--protocol", "auto"]),
    );

    assert_eq!(mode, ProtocolMode::Auto);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Using protocol mode: auto\n")
    );
}

#[test]
fn warns_about_an_invalid_mode_and_keeps_legacy() {
    let mut console = Vec::new();

    let mode = parse_protocol_mode_to(
        &mut console,
        &arguments(&["https://example.com", "--protocol", "modern"]),
    );

    assert_eq!(mode, ProtocolMode::Legacy);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Warning: Ignoring invalid protocol mode: modern. Valid values are: legacy, auto\n"
        )
    );
}

#[test]
fn defaults_to_legacy_silently_without_a_value() {
    for values in [
        &["https://example.com"][..],
        &["https://example.com", "--protocol"][..],
    ] {
        let mut console = Vec::new();

        let mode = parse_protocol_mode_to(&mut console, &arguments(values));

        assert_eq!(mode, ProtocolMode::Legacy);
        assert!(console.is_empty());
    }
}

#[test]
fn logs_an_explicit_legacy_mode() {
    let mut console = Vec::new();

    let mode = parse_protocol_mode_to(&mut console, &arguments(&["--protocol", "legacy"]));

    assert_eq!(mode, ProtocolMode::Legacy);
    assert_eq!(ProtocolMode::Legacy.as_str(), "legacy");
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Using protocol mode: legacy\n")
    );
}
