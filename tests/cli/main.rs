use rust_mcp_remote::cli::vpn_hint;

#[test]
fn an_untrusted_certificate_gets_the_vpn_hint() {
    let hint = vpn_hint("error sending request: invalid peer certificate: UnknownIssuer").unwrap();
    assert!(hint.starts_with("You may be behind a VPN!"));
    assert!(hint.contains("\"NODE_EXTRA_CA_CERTS\": \"${your CA certificate file path}.pem\""));
    assert!(vpn_hint("self-signed certificate in certificate chain").is_some());
}

#[test]
fn any_other_error_gets_no_hint() {
    assert_eq!(vpn_hint("Connection refused"), None);
}
