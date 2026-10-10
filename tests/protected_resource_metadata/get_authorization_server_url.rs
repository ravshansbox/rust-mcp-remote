use rust_mcp_remote::protected_resource_metadata::{
    ProtectedResourceMetadata, get_authorization_server_url,
};

fn metadata_from(json: &str) -> ProtectedResourceMetadata {
    serde_json::from_str(json).unwrap()
}

#[test]
fn returns_the_first_authorization_server_from_metadata() {
    let metadata = metadata_from(
        r#"{"resource":"https://mcp.example.com","authorization_servers":["https://auth1.example.com","https://auth2.example.com"]}"#,
    );

    assert_eq!(
        get_authorization_server_url(&metadata),
        Some("https://auth1.example.com")
    );
}

#[test]
fn returns_none_if_authorization_servers_is_empty() {
    let metadata =
        metadata_from(r#"{"resource":"https://mcp.example.com","authorization_servers":[]}"#);

    assert_eq!(get_authorization_server_url(&metadata), None);
}

#[test]
fn returns_none_if_authorization_servers_is_missing() {
    let metadata = metadata_from(r#"{"resource":"https://mcp.example.com"}"#);

    assert_eq!(get_authorization_server_url(&metadata), None);
}

#[test]
fn reads_known_fields_and_ignores_additional_ones() {
    let metadata = metadata_from(
        r#"{"resource":"https://mcp.example.com","scopes_supported":["read"],"bearer_methods_supported":["header"],"resource_signing_alg_values_supported":["RS256"],"resource_documentation":"https://docs.example.com","resource_name":"Example","custom":42}"#,
    );

    assert_eq!(metadata.resource, "https://mcp.example.com");
    assert_eq!(metadata.scopes_supported, Some(vec!["read".to_string()]));
    assert_eq!(
        metadata.bearer_methods_supported,
        Some(vec!["header".to_string()])
    );
    assert_eq!(
        metadata.resource_signing_alg_values_supported,
        Some(vec!["RS256".to_string()])
    );
    assert_eq!(
        metadata.resource_documentation.as_deref(),
        Some("https://docs.example.com")
    );
    assert_eq!(metadata.resource_name.as_deref(), Some("Example"));
}
