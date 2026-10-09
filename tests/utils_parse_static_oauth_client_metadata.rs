use rust_mcp_remote::utils::parse_static_oauth_client_metadata_to;
use serde_json::json;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn parses_and_logs_inline_metadata() {
    let mut console = Vec::new();

    let metadata = parse_static_oauth_client_metadata_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--static-oauth-client-metadata",
            r#"{"scope":"read"}"#,
        ]),
    )
    .expect("parsed");

    assert_eq!(metadata, Some(json!({"scope": "read"})));
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Using static OAuth client metadata from string\n")
    );
}

#[test]
fn reads_and_logs_metadata_from_a_file() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let file_path = std::env::temp_dir().join(format!(
        "mcp-remote-metadata-{}-{nanos}.json",
        std::process::id()
    ));
    std::fs::write(&file_path, r#"{"client_name":"Test"}"#).expect("write");
    let mut console = Vec::new();

    let metadata = parse_static_oauth_client_metadata_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--static-oauth-client-metadata",
            &format!("@{}", file_path.display()),
        ]),
    )
    .expect("parsed");

    std::fs::remove_file(&file_path).expect("remove");
    assert_eq!(metadata, Some(json!({"client_name": "Test"})));
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Using static OAuth client metadata from file: {}\n",
            file_path.display()
        )
    );
}

#[test]
fn fails_on_invalid_json_without_logging() {
    let mut console = Vec::new();

    let result = parse_static_oauth_client_metadata_to(
        &mut console,
        &arguments(&["https://example.com", "--static-oauth-client-metadata", "{"]),
    );

    assert!(result.is_err());
    assert!(console.is_empty());
}

#[test]
fn returns_none_silently_without_a_value() {
    for args in [
        arguments(&["https://example.com"]),
        arguments(&["https://example.com", "--static-oauth-client-metadata"]),
    ] {
        let mut console = Vec::new();

        let metadata = parse_static_oauth_client_metadata_to(&mut console, &args).expect("parsed");

        assert_eq!(metadata, None);
        assert!(console.is_empty());
    }
}
