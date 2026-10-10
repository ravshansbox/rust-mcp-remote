use std::collections::BTreeMap;

use rust_mcp_remote::node_oauth_client_provider::{
    NodeOAuthClientProvider, OAuthProviderOptions, ResourceSelection, is_issued_state,
};
use rust_mcp_remote::utils::MCP_REMOTE_VERSION;
use url::Url;

fn options() -> OAuthProviderOptions {
    OAuthProviderOptions {
        server_url: "https://example.com/mcp".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: "abc123".to_string(),
        ..Default::default()
    }
}

#[test]
fn missing_options_fall_back_to_the_defaults() {
    let provider = NodeOAuthClientProvider::new(options()).unwrap();
    assert_eq!(provider.server_url_hash, "abc123");
    assert_eq!(provider.callback_path, "/oauth/callback");
    assert_eq!(provider.client_name, "MCP CLI Client");
    assert_eq!(
        provider.client_uri,
        "https://github.com/modelcontextprotocol/mcp-cli"
    );
    assert_eq!(provider.software_id, "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d");
    assert_eq!(provider.software_version, MCP_REMOTE_VERSION);
    assert!(!provider.use_id_token);
    assert!(!provider.use_device_code);
    assert!(!provider.use_client_credentials);
    assert!(!provider.skip_resource_parameter);
    assert!(provider.authorize_params.is_empty());
    assert_eq!(provider.authorize_resource, None);
    assert_eq!(provider.resource_selection, ResourceSelection::SdkDefault);
    assert_eq!(provider.incoming_state, None);
}

#[test]
fn empty_strings_fall_back_to_the_defaults() {
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        callback_path: Some(String::new()),
        client_name: Some(String::new()),
        ..options()
    })
    .unwrap();
    assert_eq!(provider.callback_path, "/oauth/callback");
    assert_eq!(provider.client_name, "MCP CLI Client");
}

#[test]
fn given_options_are_kept() {
    let authorize_params = BTreeMap::from([("prompt".to_string(), "consent".to_string())]);
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        callback_path: Some("/cb".to_string()),
        client_name: Some("My Client".to_string()),
        client_uri: Some("https://client.example.com".to_string()),
        software_id: Some("software".to_string()),
        software_version: Some("9.9.9".to_string()),
        use_id_token: Some(true),
        use_device_code: Some(true),
        use_client_credentials: Some(true),
        authorize_params: Some(authorize_params.clone()),
        www_authenticate_scope: Some("read".to_string()),
        ..options()
    })
    .unwrap();
    assert_eq!(provider.callback_path, "/cb");
    assert_eq!(provider.client_name, "My Client");
    assert_eq!(provider.client_uri, "https://client.example.com");
    assert_eq!(provider.software_id, "software");
    assert_eq!(provider.software_version, "9.9.9");
    assert!(provider.use_id_token);
    assert!(provider.use_device_code);
    assert!(provider.use_client_credentials);
    assert_eq!(provider.authorize_params, authorize_params);
    assert_eq!(provider.www_authenticate_scope, Some("read".to_string()));
}

#[test]
fn the_state_is_a_fresh_issued_uuid() {
    let first = NodeOAuthClientProvider::new(options()).unwrap();
    let second = NodeOAuthClientProvider::new(options()).unwrap();
    assert!(is_issued_state(&first.state));
    assert_ne!(first.state, second.state);
}

#[test]
fn the_authorize_resource_is_trimmed_and_fixes_the_resource() {
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        authorize_resource: Some("  https://api.example.com/mcp ".to_string()),
        ..options()
    })
    .unwrap();
    assert_eq!(
        provider.authorize_resource,
        Some("https://api.example.com/mcp".to_string())
    );
    assert_eq!(
        provider.resource_selection,
        ResourceSelection::Fixed(Url::parse("https://api.example.com/mcp").unwrap())
    );
}

#[test]
fn an_explicit_token_endpoint_sends_no_resource() {
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        use_client_credentials: Some(true),
        token_endpoint: Some("https://auth.example.com/token".to_string()),
        ..options()
    })
    .unwrap();
    assert_eq!(provider.resource_selection, ResourceSelection::NoResource);
}

#[test]
fn an_invalid_authorize_resource_is_an_error() {
    assert!(
        NodeOAuthClientProvider::new(OAuthProviderOptions {
            authorize_resource: Some("not a url".to_string()),
            ..options()
        })
        .is_err()
    );
}

#[test]
fn set_callback_port_changes_the_port() {
    let mut provider = NodeOAuthClientProvider::new(options()).unwrap();
    provider.set_callback_port(4444);
    assert_eq!(provider.options.callback_port, 4444);
}
