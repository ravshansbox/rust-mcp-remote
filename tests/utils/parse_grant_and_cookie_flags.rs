use rust_mcp_remote::utils::{
    parse_client_credentials_to, parse_cookies_enabled_to, parse_device_code_to,
};

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn disables_cookies_and_logs() {
    let mut console = Vec::new();

    let cookies_enabled = parse_cookies_enabled_to(
        &mut console,
        &arguments(&["https://example.com", "--disable-cookies"]),
    );

    assert!(!cookies_enabled);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!("[{pid}] Cookies disabled; requests will not carry session stickiness\n")
    );
}

#[test]
fn uses_the_device_grant_and_logs() {
    let mut console = Vec::new();

    let use_device_code = parse_device_code_to(
        &mut console,
        &arguments(&["https://example.com", "--device-code"]),
    );

    assert!(use_device_code);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Using the OAuth device grant; no browser will be opened on this machine\n"
        )
    );
}

#[test]
fn uses_the_client_credentials_grant_and_logs() {
    let mut console = Vec::new();

    let use_client_credentials = parse_client_credentials_to(
        &mut console,
        &arguments(&["https://example.com", "--client-credentials"]),
    );

    assert!(use_client_credentials);
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Using the OAuth client_credentials grant; no browser will be opened and no user will be asked\n"
        )
    );
}

#[test]
fn keeps_the_defaults_silently_without_the_flags() {
    let mut console = Vec::new();
    let values = arguments(&["https://example.com"]);

    assert!(parse_cookies_enabled_to(&mut console, &values));
    assert!(!parse_device_code_to(&mut console, &values));
    assert!(!parse_client_credentials_to(&mut console, &values));
    assert!(console.is_empty());
}
