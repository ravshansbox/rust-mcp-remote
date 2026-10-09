use rust_mcp_remote::authorization_server_metadata::{get_metadata_url, get_metadata_urls};

#[test]
fn constructs_the_well_known_url() {
    assert_eq!(
        get_metadata_url("https://example.com").unwrap(),
        "https://example.com/.well-known/oauth-authorization-server"
    );
}

#[test]
fn handles_a_trailing_slash() {
    assert_eq!(
        get_metadata_url("https://example.com/").unwrap(),
        "https://example.com/.well-known/oauth-authorization-server"
    );
}

#[test]
fn handles_trailing_slashes() {
    assert_eq!(
        get_metadata_url("https://example.com///").unwrap(),
        "https://example.com/.well-known/oauth-authorization-server"
    );
}

#[test]
fn inserts_the_well_known_segment_before_the_path() {
    assert_eq!(
        get_metadata_url("https://example.com/mcp").unwrap(),
        "https://example.com/.well-known/oauth-authorization-server/mcp"
    );
}

#[test]
fn handles_different_paths() {
    assert_eq!(
        get_metadata_url("https://api.example.com/v1/mcp/server").unwrap(),
        "https://api.example.com/.well-known/oauth-authorization-server/v1/mcp/server"
    );
}

#[test]
fn handles_ports() {
    assert_eq!(
        get_metadata_url("https://localhost:8080/mcp").unwrap(),
        "https://localhost:8080/.well-known/oauth-authorization-server/mcp"
    );
}

#[test]
fn tries_rfc_8414_insertion_then_the_root_then_the_oidc_shapes() {
    assert_eq!(
        get_metadata_urls("https://example.com/auth/realms/myRealm").unwrap(),
        vec![
            "https://example.com/.well-known/oauth-authorization-server/auth/realms/myRealm",
            "https://example.com/.well-known/oauth-authorization-server",
            "https://example.com/.well-known/openid-configuration/auth/realms/myRealm",
            "https://example.com/auth/realms/myRealm/.well-known/openid-configuration",
        ]
    );
}

#[test]
fn only_tries_the_root_shapes_when_the_issuer_has_no_path() {
    assert_eq!(
        get_metadata_urls("https://example.com").unwrap(),
        vec![
            "https://example.com/.well-known/oauth-authorization-server",
            "https://example.com/.well-known/openid-configuration",
        ]
    );
}

#[test]
fn does_not_double_up_separators_on_a_trailing_slash() {
    assert_eq!(
        get_metadata_urls("https://example.com/mcp///").unwrap()[0],
        "https://example.com/.well-known/oauth-authorization-server/mcp"
    );
}

#[test]
fn rejects_an_invalid_url() {
    assert!(get_metadata_urls("not a url").is_err());
}
