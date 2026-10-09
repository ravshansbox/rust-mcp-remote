use rust_mcp_remote::node_oauth_client_provider::{
    TokenRequestSources, TokenStormBrake, prepare_token_request,
};

fn sources<'a>() -> TokenRequestSources<'a> {
    TokenRequestSources {
        has_explicit_token_endpoint: true,
        token_endpoint: Some("https://auth.example.com/oauth/token"),
        client_secret: Some("secret"),
        static_scope: None,
        scope: None,
    }
}

fn pairs(params: &[(&str, String)]) -> Vec<(String, String)> {
    params
        .iter()
        .map(|(key, value)| (key.to_string(), value.clone()))
        .collect()
}

#[test]
fn no_token_request_without_an_explicit_token_endpoint() {
    let mut brake = TokenStormBrake::default();
    let mut www_authenticate_scope = None;
    let request_sources = TokenRequestSources {
        has_explicit_token_endpoint: false,
        ..sources()
    };
    let result = prepare_token_request(
        &request_sources,
        &mut brake,
        0.0,
        &mut www_authenticate_scope,
    );
    assert_eq!(result, Ok(None));
    assert_eq!(www_authenticate_scope, None);
}

#[test]
fn client_credentials_grant_needs_a_client_secret() {
    let mut brake = TokenStormBrake::default();
    let mut www_authenticate_scope = None;
    for client_secret in [None, Some("")] {
        let request_sources = TokenRequestSources {
            client_secret,
            ..sources()
        };
        let result = prepare_token_request(
            &request_sources,
            &mut brake,
            0.0,
            &mut www_authenticate_scope,
        );
        assert_eq!(
            result,
            Err("The client_credentials grant needs a client secret; supply it with --static-oauth-client-info".to_string())
        );
    }
}

#[test]
fn grant_type_only_without_any_scope() {
    let mut brake = TokenStormBrake::default();
    let mut www_authenticate_scope = Some("old".to_string());
    let params = prepare_token_request(&sources(), &mut brake, 0.0, &mut www_authenticate_scope)
        .unwrap()
        .unwrap();
    assert_eq!(
        pairs(&params),
        vec![("grant_type".to_string(), "client_credentials".to_string())]
    );
    assert_eq!(www_authenticate_scope, None);
}

#[test]
fn challenged_scope_is_requested_and_recorded() {
    let mut brake = TokenStormBrake::default();
    let mut www_authenticate_scope = None;
    let request_sources = TokenRequestSources {
        scope: Some("read write"),
        ..sources()
    };
    let params = prepare_token_request(
        &request_sources,
        &mut brake,
        0.0,
        &mut www_authenticate_scope,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        pairs(&params),
        vec![
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("scope".to_string(), "read write".to_string()),
        ]
    );
    assert_eq!(www_authenticate_scope, Some("read write".to_string()));
}

#[test]
fn pinned_static_scope_wins_over_the_challenged_scope() {
    let mut brake = TokenStormBrake::default();
    let mut www_authenticate_scope = None;
    let request_sources = TokenRequestSources {
        static_scope: Some("  pinned  "),
        scope: Some("read write"),
        ..sources()
    };
    let params = prepare_token_request(
        &request_sources,
        &mut brake,
        0.0,
        &mut www_authenticate_scope,
    )
    .unwrap()
    .unwrap();
    assert_eq!(params[1], ("scope", "pinned".to_string()));
    assert_eq!(www_authenticate_scope, Some("pinned".to_string()));
}

#[test]
fn blank_static_scope_falls_back_to_the_challenged_scope() {
    let mut brake = TokenStormBrake::default();
    let mut www_authenticate_scope = None;
    let request_sources = TokenRequestSources {
        static_scope: Some("   "),
        scope: Some("read"),
        ..sources()
    };
    let params = prepare_token_request(
        &request_sources,
        &mut brake,
        0.0,
        &mut www_authenticate_scope,
    )
    .unwrap()
    .unwrap();
    assert_eq!(params[1], ("scope", "read".to_string()));
}

#[test]
fn token_storm_stops_the_request() {
    let mut brake = TokenStormBrake::default();
    for _ in 0..20 {
        brake.guard_against_token_storm(0.0).unwrap();
    }
    let mut www_authenticate_scope = None;
    let result = prepare_token_request(&sources(), &mut brake, 1.0, &mut www_authenticate_scope);
    assert!(
        result
            .unwrap_err()
            .starts_with("Stopped after 20 token exchanges in 30s.")
    );
}
