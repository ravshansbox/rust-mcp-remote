use rust_mcp_remote::utils::finalise_headers_to;

fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[test]
fn logs_header_names_and_substitutes_environment_variables() {
    unsafe { std::env::set_var("FINALISE_HEADERS_TOKEN", "secret") };
    let mut console = Vec::new();

    let headers = finalise_headers_to(
        &mut console,
        pairs(&[
            ("Authorization", "Bearer ${FINALISE_HEADERS_TOKEN}"),
            ("X-Tenant", "acme"),
        ]),
    );

    assert_eq!(
        headers,
        pairs(&[("Authorization", "Bearer secret"), ("X-Tenant", "acme")])
    );
    let pid = std::process::id();
    assert_eq!(
        String::from_utf8(console).expect("utf8"),
        format!(
            "[{pid}] Using custom headers: Authorization, X-Tenant\n\
             [{pid}] Replacing ${{FINALISE_HEADERS_TOKEN}} with environment value in header 'Authorization'\n"
        )
    );
}

#[test]
fn writes_nothing_when_there_are_no_headers() {
    let mut console = Vec::new();

    let headers = finalise_headers_to(&mut console, Vec::new());

    assert!(headers.is_empty());
    assert!(console.is_empty());
}
