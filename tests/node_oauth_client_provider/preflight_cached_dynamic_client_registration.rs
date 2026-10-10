use rust_mcp_remote::node_oauth_client_provider::{
    ClientRegistrationSource, NodeOAuthClientProvider, OAuthError, OAuthProviderOptions,
};
use url::Url;

fn provider(source: Option<ClientRegistrationSource>) -> NodeOAuthClientProvider {
    let mut provider = NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: "preflight-test".to_string(),
        ..Default::default()
    })
    .unwrap();
    provider.client_registration_source = source;
    provider
}

fn authorization_url() -> Url {
    Url::parse("https://auth.example.com/authorize?client_id=abc").unwrap()
}

#[test]
fn skips_the_request_unless_the_client_is_cached_dynamic() {
    for source in [
        None,
        Some(ClientRegistrationSource::Static),
        Some(ClientRegistrationSource::FreshDynamic),
    ] {
        let result = provider(source)
            .preflight_cached_dynamic_client_registration(&authorization_url(), |_| {
                panic!("fetch should not run")
            });
        assert_eq!(result, Ok(()));
    }
}

#[test]
fn requests_the_authorization_url() {
    let mut requested = None;
    let result = provider(Some(ClientRegistrationSource::CachedDynamic))
        .preflight_cached_dynamic_client_registration(&authorization_url(), |url| {
            requested = Some(url.to_string());
            Ok((302, String::new()))
        });
    assert_eq!(result, Ok(()));
    assert_eq!(requested, Some(authorization_url().to_string()));
}

#[test]
fn continues_when_the_request_fails() {
    let result = provider(Some(ClientRegistrationSource::CachedDynamic))
        .preflight_cached_dynamic_client_registration(&authorization_url(), |_| {
            Err("connection refused".to_string())
        });
    assert_eq!(result, Ok(()));
}

#[test]
fn ignores_error_bodies_on_other_statuses() {
    let result = provider(Some(ClientRegistrationSource::CachedDynamic))
        .preflight_cached_dynamic_client_registration(&authorization_url(), |_| {
            Ok((500, r#"{"error":"invalid_client"}"#.to_string()))
        });
    assert_eq!(result, Ok(()));
}

#[test]
fn continues_when_the_body_is_not_json() {
    let result = provider(Some(ClientRegistrationSource::CachedDynamic))
        .preflight_cached_dynamic_client_registration(&authorization_url(), |_| {
            Ok((400, "<html>bad request</html>".to_string()))
        });
    assert_eq!(result, Ok(()));
}

#[test]
fn continues_when_the_error_is_not_about_the_registration() {
    let result = provider(Some(ClientRegistrationSource::CachedDynamic))
        .preflight_cached_dynamic_client_registration(&authorization_url(), |_| {
            Ok((400, r#"{"error":"invalid_scope"}"#.to_string()))
        });
    assert_eq!(result, Ok(()));
}

#[test]
fn fails_when_the_cached_registration_is_rejected() {
    for status in [400, 401] {
        let result = provider(Some(ClientRegistrationSource::CachedDynamic))
            .preflight_cached_dynamic_client_registration(&authorization_url(), |_| {
                Ok((
                    status,
                    r#"{"error":"invalid_client","error_description":"unknown client"}"#
                        .to_string(),
                ))
            });
        assert_eq!(
            result,
            Err(OAuthError {
                code: "invalid_client".to_string(),
                message: "unknown client".to_string(),
            })
        );
    }
}
