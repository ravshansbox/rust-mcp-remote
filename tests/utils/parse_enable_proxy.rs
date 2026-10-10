use rust_mcp_remote::utils::parse_enable_proxy_to;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn proxy_is_disabled_by_default_and_logs_nothing() {
    let mut console = Vec::new();

    let enable_proxy = parse_enable_proxy_to(&mut console, &arguments(&["https://example.com"]));

    assert!(!enable_proxy);
    assert!(console.is_empty());
}

#[test]
fn enable_proxy_flag_enables_proxy_and_logs_it() {
    let mut console = Vec::new();

    let enable_proxy = parse_enable_proxy_to(
        &mut console,
        &arguments(&["https://example.com", "--enable-proxy"]),
    );

    assert!(enable_proxy);
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{}] HTTP proxy support enabled - using system HTTP_PROXY/HTTPS_PROXY environment variables\n",
            std::process::id()
        )
    );
}
