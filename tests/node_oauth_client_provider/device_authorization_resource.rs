use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};
use serde_json::{Value, json};
use url::Url;

fn provider(
    server_url: &str,
    protected_resource_metadata: Option<Value>,
    configure: impl FnOnce(&mut OAuthProviderOptions),
) -> NodeOAuthClientProvider {
    let mut options = OAuthProviderOptions {
        server_url: server_url.to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: "device-resource-test".to_string(),
        protected_resource_metadata,
        ..Default::default()
    };
    configure(&mut options);
    NodeOAuthClientProvider::new(options).unwrap()
}

#[test]
fn without_protected_resource_metadata_no_resource_is_sent() {
    let provider = provider("https://mcp.example.com/mcp", None, |_| {});
    assert_eq!(provider.device_authorization_resource(), Ok(None));
}

#[test]
fn the_metadata_resource_is_preferred_when_it_covers_the_server() {
    let provider = provider(
        "https://mcp.example.com/mcp/v1#fragment",
        Some(json!({ "resource": "https://mcp.example.com/mcp" })),
        |_| {},
    );
    assert_eq!(
        provider.device_authorization_resource(),
        Ok(Some(Url::parse("https://mcp.example.com/mcp").unwrap()))
    );
}

#[test]
fn a_metadata_resource_for_another_path_is_an_error() {
    let provider = provider(
        "https://mcp.example.com/mcp",
        Some(json!({ "resource": "https://mcp.example.com/other" })),
        |_| {},
    );
    assert_eq!(
        provider.device_authorization_resource(),
        Err(
            "Protected resource https://mcp.example.com/other does not match expected https://mcp.example.com/mcp (or origin)"
                .to_string()
        )
    );
}

#[test]
fn a_metadata_resource_on_another_origin_is_an_error() {
    let provider = provider(
        "https://mcp.example.com/mcp",
        Some(json!({ "resource": "https://evil.example.com/mcp" })),
        |_| {},
    );
    assert!(provider.device_authorization_resource().is_err());
}

#[test]
fn a_path_prefix_without_a_segment_boundary_is_an_error() {
    let provider = provider(
        "https://mcp.example.com/api123",
        Some(json!({ "resource": "https://mcp.example.com/api" })),
        |_| {},
    );
    assert!(provider.device_authorization_resource().is_err());
}

#[test]
fn the_resource_server_url_is_used_instead_of_the_server_url() {
    let provider = provider(
        "https://auth.example.com",
        Some(json!({ "resource": "https://mcp.example.com/" })),
        |options| options.resource_server_url = Some("https://mcp.example.com/mcp".to_string()),
    );
    assert_eq!(
        provider.device_authorization_resource(),
        Ok(Some(Url::parse("https://mcp.example.com/").unwrap()))
    );
}

#[test]
fn an_authorize_resource_overrides_the_metadata() {
    let provider = provider(
        "https://mcp.example.com/mcp",
        Some(json!({ "resource": "https://evil.example.com/mcp" })),
        |options| options.authorize_resource = Some("https://api.example.com/mcp".to_string()),
    );
    assert_eq!(
        provider.device_authorization_resource(),
        Ok(Some(Url::parse("https://api.example.com/mcp").unwrap()))
    );
}

#[test]
fn skipping_the_resource_parameter_sends_no_resource() {
    let provider = provider(
        "https://mcp.example.com/mcp",
        Some(json!({ "resource": "https://mcp.example.com/mcp" })),
        |options| options.skip_resource_parameter = Some(true),
    );
    assert_eq!(provider.device_authorization_resource(), Ok(None));
}
