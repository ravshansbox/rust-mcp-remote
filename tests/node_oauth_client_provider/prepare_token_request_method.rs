use rust_mcp_remote::mcp_auth_config::write_json_file;
use rust_mcp_remote::node_oauth_client_provider::{
    ClientRegistrationSource, NodeOAuthClientProvider, OAuthProviderOptions,
};
use serde_json::json;

use crate::{pairs, with_temporary_config_dir};

const HASH: &str = "prepare-token-request-method-test";

fn provider(options: OAuthProviderOptions) -> NodeOAuthClientProvider {
    NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: HASH.to_string(),
        use_client_credentials: Some(true),
        token_endpoint: Some("https://auth.example.com/oauth/token".to_string()),
        ..options
    })
    .unwrap()
}

#[test]
fn no_request_and_no_client_read_without_an_explicit_token_endpoint() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(json!({ "client_id": "id", "client_secret": "secret" })),
            ..Default::default()
        });
        provider.use_client_credentials = false;
        assert_eq!(provider.prepare_token_request(Some("read"), 0.0), Ok(None));
        assert_eq!(provider.client_registration_source, None);
        assert_eq!(provider.www_authenticate_scope, None);
    });
}

#[test]
fn uses_the_static_client_secret_and_records_the_scope() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(json!({ "client_id": "id", "client_secret": "secret" })),
            ..Default::default()
        });
        let params = provider
            .prepare_token_request(Some("read"), 0.0)
            .unwrap()
            .unwrap();
        assert_eq!(
            pairs(&params),
            vec![
                ("grant_type".to_string(), "client_credentials".to_string()),
                ("scope".to_string(), "read".to_string()),
            ]
        );
        assert_eq!(provider.www_authenticate_scope.as_deref(), Some("read"));
        assert_eq!(
            provider.client_registration_source,
            Some(ClientRegistrationSource::Static)
        );
    });
}

#[test]
fn a_pinned_static_scope_wins_over_the_challenge_scope() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(json!({ "client_id": "id", "client_secret": "secret" })),
            static_oauth_client_metadata: Some(json!({ "scope": "  pinned  " })),
            ..Default::default()
        });
        let params = provider
            .prepare_token_request(Some("read"), 0.0)
            .unwrap()
            .unwrap();
        assert_eq!(
            pairs(&params)[1],
            ("scope".to_string(), "pinned".to_string())
        );
        assert_eq!(provider.www_authenticate_scope.as_deref(), Some("pinned"));
    });
}

#[test]
fn uses_the_cached_client_secret() {
    with_temporary_config_dir(|| {
        write_json_file(
            HASH,
            "client_info.json",
            &json!({ "client_id": "cached", "client_secret": "cached-secret" }),
        )
        .unwrap();
        let mut provider = provider(OAuthProviderOptions::default());
        let params = provider.prepare_token_request(None, 0.0).unwrap().unwrap();
        assert_eq!(
            pairs(&params),
            vec![("grant_type".to_string(), "client_credentials".to_string())]
        );
        assert_eq!(provider.www_authenticate_scope, None);
    });
}

#[test]
fn fails_without_a_client_secret() {
    with_temporary_config_dir(|| {
        let mut provider = provider(OAuthProviderOptions {
            static_oauth_client_info: Some(json!({ "client_id": "id" })),
            ..Default::default()
        });
        assert_eq!(
            provider.prepare_token_request(Some("read"), 0.0),
            Err(
                "The client_credentials grant needs a client secret; supply it with --static-oauth-client-info"
                    .to_string()
            )
        );
    });
}
