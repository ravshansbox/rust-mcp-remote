use rust_mcp_remote::utils::validate_server_url_to;

const USAGE: &str = "Usage: mcp-remote <https://server-url>";

fn console_text(console: Vec<u8>) -> String {
    String::from_utf8(console).expect("utf8")
}

#[test]
fn logs_usage_when_the_server_url_is_missing() {
    let mut console = Vec::new();

    let result = validate_server_url_to(&mut console, None, false, USAGE);

    assert_eq!(result, Ok(false));
    let pid = std::process::id();
    assert_eq!(console_text(console), format!("[{pid}] {USAGE}\n"));
}

#[test]
fn accepts_https_and_loopback_http_urls_silently() {
    for server_url in [
        "https://example.com/mcp",
        "http://localhost:3000/mcp",
        "http://127.0.0.1/mcp",
    ] {
        let mut console = Vec::new();

        let result = validate_server_url_to(&mut console, Some(server_url), false, USAGE);

        assert_eq!(result, Ok(true), "{server_url}");
        assert_eq!(console_text(console), "");
    }
}

#[test]
fn rejects_remote_and_ipv6_loopback_http_urls_without_allow_http() {
    for server_url in ["http://example.com/mcp", "http://[::1]/mcp"] {
        let mut console = Vec::new();

        let result = validate_server_url_to(&mut console, Some(server_url), false, USAGE);

        assert_eq!(result, Ok(false), "{server_url}");
        let pid = std::process::id();
        assert_eq!(
            console_text(console),
            format!(
                "[{pid}] Error: Non-HTTPS URLs are only allowed for localhost or when --allow-http flag is provided\n[{pid}] {USAGE}\n"
            )
        );
    }
}

#[test]
fn accepts_remote_http_urls_with_allow_http() {
    let mut console = Vec::new();

    let result = validate_server_url_to(&mut console, Some("http://example.com/mcp"), true, USAGE);

    assert_eq!(result, Ok(true));
    assert_eq!(console_text(console), "");
}

#[test]
fn reports_an_unparseable_server_url() {
    let mut console = Vec::new();

    let result = validate_server_url_to(&mut console, Some("not a url"), true, USAGE);

    assert_eq!(result, Err("Invalid URL".to_string()));
    assert_eq!(console_text(console), "");
}
