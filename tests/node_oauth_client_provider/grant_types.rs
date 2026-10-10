use rust_mcp_remote::device_authorization::DEVICE_CODE_GRANT_TYPE;
use rust_mcp_remote::node_oauth_client_provider::grant_types;

#[test]
fn client_credentials_is_registered_alone() {
    assert_eq!(grant_types(true, false), vec!["client_credentials"]);
}

#[test]
fn client_credentials_wins_over_device_code() {
    assert_eq!(grant_types(true, true), vec!["client_credentials"]);
}

#[test]
fn device_code_is_registered_with_refresh_token() {
    assert_eq!(
        grant_types(false, true),
        vec![DEVICE_CODE_GRANT_TYPE, "refresh_token"]
    );
}

#[test]
fn authorization_code_is_registered_with_refresh_token_by_default() {
    assert_eq!(
        grant_types(false, false),
        vec!["authorization_code", "refresh_token"]
    );
}
