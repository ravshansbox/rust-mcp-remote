use rust_mcp_remote::utils::{parse_resource_to, parse_use_id_token_to};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn output(console: Vec<u8>) -> String {
    String::from_utf8(console).expect("utf8")
}

#[test]
fn uses_the_id_token_and_logs() {
    let mut console = Vec::new();

    let use_id_token = parse_use_id_token_to(
        &mut console,
        &arguments(&["https://example.com", "--use-id-token"]),
    );

    assert!(use_id_token);
    let pid = std::process::id();
    assert_eq!(
        output(console),
        format!("[{pid}] Using the ID token as the bearer credential\n")
    );
}

#[test]
fn does_not_use_the_id_token_by_default() {
    let mut console = Vec::new();

    let use_id_token = parse_use_id_token_to(&mut console, &arguments(&["https://example.com"]));

    assert!(!use_id_token);
    assert_eq!(output(console), "");
}

#[test]
fn uses_a_trimmed_resource_and_logs() {
    let mut console = Vec::new();

    let parsed = parse_resource_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--resource",
            " https://example.com/mcp ",
        ]),
    );

    assert_eq!(
        parsed,
        Ok((Some("https://example.com/mcp".to_string()), false))
    );
    let pid = std::process::id();
    assert_eq!(
        output(console),
        format!("[{pid}] Using authorize resource: https://example.com/mcp\n")
    );
}

#[test]
fn rejects_a_relative_resource() {
    let mut console = Vec::new();

    let parsed = parse_resource_to(
        &mut console,
        &arguments(&["https://example.com", "--resource", "/mcp"]),
    );

    assert_eq!(
        parsed,
        Err("Invalid --resource value: \"/mcp\". RFC 8707 requires an absolute URI, e.g. https://example.com/mcp".to_string())
    );
    assert_eq!(output(console), "");
}

#[test]
fn an_empty_resource_disables_the_parameter() {
    let mut console = Vec::new();

    let parsed = parse_resource_to(
        &mut console,
        &arguments(&["https://example.com", "--resource", " "]),
    );

    assert_eq!(parsed, Ok((None, true)));
    let pid = std::process::id();
    assert_eq!(
        output(console),
        format!(
            "[{pid}] Resource parameter disabled - it will be omitted from authorization and token requests\n"
        )
    );
}

#[test]
fn disabling_overrides_a_set_resource() {
    let mut console = Vec::new();

    let parsed = parse_resource_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--resource",
            "https://example.com/mcp",
            "--disable-resource-parameter",
        ]),
    );

    assert_eq!(parsed, Ok((None, true)));
    let pid = std::process::id();
    assert_eq!(
        output(console),
        format!(
            "[{pid}] Warning: --disable-resource-parameter overrides --resource https://example.com/mcp; the resource parameter will be omitted.\n[{pid}] Resource parameter disabled - it will be omitted from authorization and token requests\n"
        )
    );
}

#[test]
fn has_no_resource_by_default() {
    let mut console = Vec::new();

    let parsed = parse_resource_to(
        &mut console,
        &arguments(&["https://example.com", "--resource"]),
    );

    assert_eq!(parsed, Ok((None, false)));
    assert_eq!(output(console), "");
}
