use rust_mcp_remote::utils::parse_token_endpoint_to;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn parse(
    values: &[&str],
    use_client_credentials: bool,
) -> (Result<Option<String>, String>, String) {
    let mut console = Vec::new();
    let result = parse_token_endpoint_to(&mut console, &arguments(values), use_client_credentials);
    (result, String::from_utf8(console).expect("utf8"))
}

#[test]
fn accepts_an_https_endpoint_and_logs_its_origin() {
    let (result, output) = parse(
        &[
            "https://example.com",
            "--token-endpoint",
            " https://auth.example.com/oauth/token ",
        ],
        true,
    );

    assert_eq!(
        result,
        Ok(Some("https://auth.example.com/oauth/token".to_string()))
    );
    let pid = std::process::id();
    assert_eq!(
        output,
        format!("[{pid}] Using an explicit OAuth token endpoint at https://auth.example.com\n")
    );
}

#[test]
fn accepts_http_loopback_endpoints() {
    for value in [
        "http://localhost:8080/token",
        "http://127.0.0.1/token",
        "http://[::1]:9000/token",
    ] {
        let (result, _) = parse(&["--token-endpoint", value], true);
        assert_eq!(result, Ok(Some(value.to_string())));
    }
}

#[test]
fn returns_none_without_the_flag() {
    let (result, output) = parse(&["https://example.com"], false);

    assert_eq!(result, Ok(None));
    assert_eq!(output, "");
}

#[test]
fn rejects_a_missing_value() {
    for values in [
        &["--token-endpoint"][..],
        &["--token-endpoint", "--client-credentials"][..],
    ] {
        let (result, _) = parse(values, true);
        assert_eq!(
            result,
            Err("--token-endpoint requires an HTTPS URL".to_string())
        );
    }
}

#[test]
fn rejects_use_without_client_credentials() {
    let (result, _) = parse(
        &["--token-endpoint", "https://auth.example.com/token"],
        false,
    );

    assert_eq!(
        result,
        Err("--token-endpoint can only be used with --client-credentials".to_string())
    );
}

#[test]
fn rejects_an_unparseable_value() {
    let (result, _) = parse(&["--token-endpoint", "not a url"], true);

    assert_eq!(
        result,
        Err("Invalid --token-endpoint value. Expected an HTTPS URL.".to_string())
    );
}

#[test]
fn rejects_plain_http_to_a_remote_host() {
    let (result, _) = parse(&["--token-endpoint", "http://auth.example.com/token"], true);

    assert_eq!(
        result,
        Err("--token-endpoint must use HTTPS, except for an HTTP loopback endpoint".to_string())
    );
}

#[test]
fn rejects_credentials_and_fragments() {
    for value in [
        "https://user@auth.example.com/token",
        "https://user:secret@auth.example.com/token",
        "https://auth.example.com/token#part",
    ] {
        let (result, output) = parse(&["--token-endpoint", value], true);
        assert_eq!(
            result,
            Err("--token-endpoint must not contain credentials or a URL fragment".to_string())
        );
        assert_eq!(output, "");
    }
}
