use rust_mcp_remote::utils::parse_client_metadata_url_to;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn uses_and_logs_a_trimmed_valid_url() {
    let mut console = Vec::new();

    let client_metadata_url = parse_client_metadata_url_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--client-metadata-url",
            "  https://client.example.com/metadata.json  ",
        ]),
    );

    assert_eq!(
        client_metadata_url.as_deref(),
        Some("https://client.example.com/metadata.json")
    );
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Using client metadata document: https://client.example.com/metadata.json\n"
        )
    );
}

#[test]
fn warns_about_an_invalid_url() {
    let mut console = Vec::new();

    let client_metadata_url = parse_client_metadata_url_to(
        &mut console,
        &arguments(&[
            "https://example.com",
            "--client-metadata-url",
            "http://client.example.com/metadata.json",
        ]),
    );

    assert_eq!(client_metadata_url, None);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Warning: Ignoring invalid client metadata URL: http://client.example.com/metadata.json. It must be an HTTPS URL with a path.\n"
        )
    );
}

#[test]
fn returns_none_silently_without_a_value() {
    for values in [
        vec!["https://example.com"],
        vec!["https://example.com", "--client-metadata-url"],
    ] {
        let mut console = Vec::new();

        let client_metadata_url = parse_client_metadata_url_to(&mut console, &arguments(&values));

        assert_eq!(client_metadata_url, None);
        assert!(console.is_empty());
    }
}
