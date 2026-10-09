use rust_mcp_remote::utils::parse_static_oauth_client_info_to;
use serde_json::json;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn parses_and_logs_inline_information() {
    let mut console = Vec::new();

    let information = parse_static_oauth_client_info_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--static-oauth-client-info",
            r#"{"client_id":"abc"}"#,
        ]),
    )
    .expect("parsed");

    assert_eq!(information, Some(json!({"client_id": "abc"})));
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Using static OAuth client information from string\n")
    );
}

#[test]
fn reads_and_logs_information_from_a_file() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let file_path = std::env::temp_dir().join(format!(
        "mcp-remote-client-info-{}-{nanos}.json",
        std::process::id()
    ));
    std::fs::write(&file_path, r#"{"client_id":"from-file"}"#).expect("write");
    let mut console = Vec::new();

    let information = parse_static_oauth_client_info_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--static-oauth-client-info",
            &format!("@{}", file_path.display()),
        ]),
    )
    .expect("parsed");

    std::fs::remove_file(&file_path).expect("remove");
    assert_eq!(information, Some(json!({"client_id": "from-file"})));
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Using static OAuth client information from file: {}\n",
            file_path.display()
        )
    );
}

#[test]
fn expands_environment_variable_placeholders() {
    let mut console = Vec::new();

    let information = parse_static_oauth_client_info_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--static-oauth-client-info",
            r#"{"client_secret":"${CARGO_PKG_NAME}"}"#,
        ]),
    )
    .expect("parsed");

    assert_eq!(
        information,
        Some(json!({"client_secret": env!("CARGO_PKG_NAME")}))
    );
}

#[test]
fn fails_on_invalid_json_without_logging() {
    let mut console = Vec::new();

    let result = parse_static_oauth_client_info_to(
        &mut console,
        &arguments(&["https://example.com", "--static-oauth-client-info", "{"]),
    );

    assert_eq!(
        result,
        Err("Could not parse the static OAuth client information as JSON".to_string())
    );
    assert!(console.is_empty());
}

#[test]
fn returns_none_silently_without_a_value() {
    for args in [
        arguments(&["https://example.com"]),
        arguments(&["https://example.com", "--static-oauth-client-info"]),
    ] {
        let mut console = Vec::new();

        let information = parse_static_oauth_client_info_to(&mut console, &args).expect("parsed");

        assert_eq!(information, None);
        assert!(console.is_empty());
    }
}
