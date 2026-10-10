use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};

fn options() -> OAuthProviderOptions {
    OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: "abc123".to_string(),
        ..Default::default()
    }
}

fn client_credentials_options() -> OAuthProviderOptions {
    OAuthProviderOptions {
        use_client_credentials: Some(true),
        token_endpoint: Some("https://tokens.example.com/oauth/token".to_string()),
        ..options()
    }
}

#[test]
fn has_explicit_token_endpoint_needs_client_credentials_and_an_endpoint() {
    let provider = NodeOAuthClientProvider::new(options()).unwrap();
    assert!(!provider.has_explicit_token_endpoint());
    let provider = NodeOAuthClientProvider::new(client_credentials_options()).unwrap();
    assert!(provider.has_explicit_token_endpoint());
}

#[test]
fn redirect_url_follows_the_callback_port() {
    let mut provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        callback_path: Some("/cb".to_string()),
        ..options()
    })
    .unwrap();
    provider.set_callback_port(4444);
    assert_eq!(
        provider.redirect_url().as_deref(),
        Some("http://localhost:4444/cb")
    );
}

#[test]
fn redirect_url_is_none_with_an_explicit_token_endpoint() {
    let provider = NodeOAuthClientProvider::new(client_credentials_options()).unwrap();
    assert_eq!(provider.redirect_url(), None);
}

#[test]
fn resource_server_url_falls_back_to_the_server_url() {
    let provider = NodeOAuthClientProvider::new(options()).unwrap();
    assert_eq!(provider.resource_server_url(), "https://auth.example.com");
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        resource_server_url: Some("https://mcp.example.com/mcp".to_string()),
        ..options()
    })
    .unwrap();
    assert_eq!(
        provider.resource_server_url(),
        "https://mcp.example.com/mcp"
    );
}

#[test]
fn discovery_state_uses_the_token_endpoint_and_resource_server_url() {
    let provider = NodeOAuthClientProvider::new(options()).unwrap();
    assert_eq!(provider.discovery_state(), None);
    let provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        resource_server_url: Some("https://mcp.example.com/mcp".to_string()),
        ..client_credentials_options()
    })
    .unwrap();
    let state = provider.discovery_state().unwrap();
    assert_eq!(
        state["authorizationServerUrl"],
        "https://tokens.example.com"
    );
    assert_eq!(
        state["resourceMetadata"]["resource"],
        "https://mcp.example.com/mcp"
    );
}
