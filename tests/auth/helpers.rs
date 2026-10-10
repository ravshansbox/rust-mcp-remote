use rust_mcp_remote::auth::{
    AuthError, DiscoveryType, IssuerMismatchKind, StartAuthorizationOptions, build_discovery_urls,
    check_resource_allowed, compute_scope_union, derive_application_type, determine_scope,
    discard_if_issuer_mismatch, extract_field_from_www_auth, extract_www_authenticate_params,
    is_https_url, is_strict_scope_superset, issuers_match, parse_error_response,
    parse_oauth_metadata, parse_tokens, pkce_challenge, resource_url_from_server_url,
    start_authorization, validate_authorization_response_issuer,
};
use rust_mcp_remote::node_oauth_client_provider::code_challenge_for;
use serde_json::json;
use url::Url;

fn url(text: &str) -> Url {
    Url::parse(text).unwrap()
}

#[test]
fn www_authenticate_params_come_from_bearer_and_dpop_challenges() {
    let header = r#"Bearer error="insufficient_scope", scope="read write", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource", error_description="needs more""#;
    let params = extract_www_authenticate_params(Some(header));
    assert_eq!(
        params.resource_metadata_url,
        Some(url(
            "https://api.example.com/.well-known/oauth-protected-resource"
        ))
    );
    assert_eq!(params.scope.as_deref(), Some("read write"));
    assert_eq!(params.error.as_deref(), Some("insufficient_scope"));
    assert_eq!(params.error_description.as_deref(), Some("needs more"));

    let dpop = extract_www_authenticate_params(Some("DPoP scope=files:read, algs=\"ES256\""));
    assert_eq!(dpop.scope.as_deref(), Some("files:read"));

    assert_eq!(
        extract_www_authenticate_params(Some("Basic realm=\"x\"")),
        Default::default()
    );
    assert_eq!(
        extract_www_authenticate_params(Some("Bearer")),
        Default::default()
    );
    let bad_url = extract_www_authenticate_params(Some("Bearer resource_metadata=\"not a url\""));
    assert_eq!(bad_url.resource_metadata_url, None);
}

#[test]
fn a_field_needs_a_value_and_the_first_match_wins() {
    // Like the SDK's regex, an empty quoted value falls through to the unquoted branch.
    assert_eq!(
        extract_field_from_www_auth(r#"Bearer realm="", realm=api"#, "realm").as_deref(),
        Some("\"\"")
    );
    assert_eq!(
        extract_field_from_www_auth("Bearer realm=, realm=api", "realm").as_deref(),
        Some("api")
    );
    assert_eq!(
        extract_field_from_www_auth("Bearer scope=a,scope=b", "scope").as_deref(),
        Some("a")
    );
    assert_eq!(extract_field_from_www_auth("Bearer x=1", "scope"), None);
}

#[test]
fn scope_union_and_superset_follow_the_sdk() {
    assert_eq!(
        compute_scope_union(&[Some("a b"), None, Some("b  c"), Some("")]).as_deref(),
        Some("a b c")
    );
    assert_eq!(compute_scope_union(&[None, Some(" ")]), None);
    assert!(is_strict_scope_superset(Some("a b"), Some("a")));
    assert!(is_strict_scope_superset(Some("a"), None));
    assert!(!is_strict_scope_superset(Some("a"), Some("b a")));
    assert!(!is_strict_scope_superset(None, Some("a")));
}

#[test]
fn determine_scope_prefers_request_then_resource_then_client_and_adds_offline_access() {
    let client = json!({"scope": "client", "grant_types": ["authorization_code", "refresh_token"]});
    let resource = json!({"scopes_supported": ["r1", "r2"]});
    let server = json!({"scopes_supported": ["offline_access"]});
    assert_eq!(
        determine_scope(Some("asked"), Some(&resource), None, &client).as_deref(),
        Some("asked")
    );
    assert_eq!(
        determine_scope(None, Some(&resource), None, &client).as_deref(),
        Some("r1 r2")
    );
    assert_eq!(
        determine_scope(None, Some(&json!({"scopes_supported": []})), None, &client).as_deref(),
        Some("client")
    );
    assert_eq!(
        determine_scope(None, None, Some(&server), &client).as_deref(),
        Some("client offline_access")
    );
    assert_eq!(
        determine_scope(Some("offline_access x"), None, Some(&server), &client).as_deref(),
        Some("offline_access x")
    );
    assert_eq!(
        determine_scope(None, None, Some(&server), &json!({"scope": "c"})).as_deref(),
        Some("c")
    );
    assert_eq!(determine_scope(None, None, Some(&server), &json!({})), None);
}

#[test]
fn resource_checks_compare_origin_and_path_prefix() {
    assert!(check_resource_allowed(
        &url("https://a.example/mcp/x"),
        &url("https://a.example/mcp")
    ));
    assert!(check_resource_allowed(
        &url("https://a.example/mcp"),
        &url("https://a.example/")
    ));
    assert!(!check_resource_allowed(
        &url("https://a.example/mcpx"),
        &url("https://a.example/mcp")
    ));
    assert!(!check_resource_allowed(
        &url("https://b.example/mcp"),
        &url("https://a.example/mcp")
    ));
    assert_eq!(
        resource_url_from_server_url(&url("https://a.example/mcp?x=1#frag")).as_str(),
        "https://a.example/mcp?x=1"
    );
}

#[test]
fn discovery_urls_cover_oauth_and_oidc_paths() {
    let root = build_discovery_urls(&url("https://auth.example"));
    assert_eq!(
        root.iter()
            .map(|(url, kind)| (url.as_str(), *kind))
            .collect::<Vec<_>>(),
        vec![
            (
                "https://auth.example/.well-known/oauth-authorization-server",
                DiscoveryType::OAuth
            ),
            (
                "https://auth.example/.well-known/openid-configuration",
                DiscoveryType::Oidc
            ),
        ]
    );
    let tenant = build_discovery_urls(&url("https://auth.example/tenant/"));
    assert_eq!(
        tenant
            .iter()
            .map(|(url, _)| url.as_str())
            .collect::<Vec<_>>(),
        vec![
            "https://auth.example/.well-known/oauth-authorization-server/tenant",
            "https://auth.example/.well-known/openid-configuration/tenant",
            "https://auth.example/tenant/.well-known/openid-configuration",
        ]
    );
}

#[test]
fn error_responses_become_oauth_errors_or_server_errors() {
    assert_eq!(
        parse_error_response(
            Some(400),
            r#"{"error":"invalid_grant","error_description":"expired","error_uri":"https://e"}"#
        ),
        AuthError::OAuth {
            code: "invalid_grant".into(),
            message: "expired".into(),
            error_uri: Some("https://e".into())
        }
    );
    assert_eq!(
        parse_error_response(None, r#"{"error":"invalid_client"}"#).to_string(),
        "invalid_client"
    );
    let fallback = parse_error_response(Some(502), "<html>");
    assert_eq!(fallback.oauth_code(), Some("server_error"));
    let message = fallback.to_string();
    assert!(
        message.starts_with("HTTP 502: Invalid OAuth error response: SyntaxError"),
        "{message}"
    );
    assert!(message.ends_with(". Raw body: <html>"), "{message}");
}

#[test]
fn authorization_response_issuer_follows_the_rfc_9207_table() {
    let expected = Some("https://as.example");
    assert!(validate_authorization_response_issuer(None, None, true).is_ok());
    assert!(validate_authorization_response_issuer(None, expected, false).is_ok());
    assert!(
        validate_authorization_response_issuer(Some("https://as.example"), expected, true).is_ok()
    );
    let missing = validate_authorization_response_issuer(None, expected, true).unwrap_err();
    assert_eq!(
        missing.to_string(),
        "Issuer mismatch in authorization response (RFC 9207): expected \"https://as.example\", received undefined"
    );
    let wrong =
        validate_authorization_response_issuer(Some("https://as.example/"), expected, false)
            .unwrap_err();
    assert!(matches!(
        wrong,
        AuthError::IssuerMismatch {
            kind: IssuerMismatchKind::AuthorizationResponse,
            ..
        }
    ));
}

#[test]
fn issuer_stamps_isolate_credentials() {
    assert!(issuers_match("https://a/", "https://a"));
    assert!(issuers_match("https://a", "https://a/"));
    assert!(!issuers_match("https://a", "https://b"));
    let stamped = json!({"client_id": "x", "issuer": "https://a"});
    assert_eq!(
        discard_if_issuer_mismatch(Some(stamped.clone()), "https://a/", true),
        Some(stamped.clone())
    );
    assert_eq!(
        discard_if_issuer_mismatch(Some(stamped), "https://b", true),
        None
    );
    assert_eq!(
        discard_if_issuer_mismatch(
            Some(json!({"client_id": "x", "issuer": 5})),
            "https://b",
            false
        ),
        Some(json!({"client_id": "x"}))
    );
}

#[test]
fn token_responses_are_stripped_and_coerced() {
    let tokens = parse_tokens(&json!({
        "access_token": "a", "token_type": "Bearer", "expires_in": "3600",
        "issuer": "https://evil", "extra": true, "refresh_token": "r"
    }))
    .unwrap();
    assert_eq!(
        tokens,
        json!({"access_token": "a", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "r"})
    );
    assert!(parse_tokens(&json!({"access_token": "a"})).is_err());
    assert!(
        parse_tokens(&json!({"access_token": "a", "token_type": "x", "expires_in": "soon"}))
            .is_err()
    );
}

#[test]
fn oauth_metadata_keeps_unknown_fields_and_drops_a_non_boolean_iss_flag() {
    let metadata = parse_oauth_metadata(&json!({
        "issuer": "https://as", "authorization_endpoint": "https://as/authorize",
        "token_endpoint": "https://as/token", "response_types_supported": ["code"],
        "authorization_response_iss_parameter_supported": "yes", "custom": 1
    }))
    .unwrap();
    assert_eq!(metadata["custom"], 1);
    assert!(
        metadata
            .get("authorization_response_iss_parameter_supported")
            .is_none()
    );
    assert!(
        parse_oauth_metadata(&json!({
            "issuer": "https://as", "authorization_endpoint": "javascript:alert(1)",
            "token_endpoint": "https://as/token", "response_types_supported": ["code"]
        }))
        .is_err()
    );
}

#[test]
fn application_type_and_client_metadata_urls() {
    assert_eq!(
        derive_application_type(Some(&json!(["http://localhost:3334/cb"]))),
        "native"
    );
    assert_eq!(
        derive_application_type(Some(&json!(["com.example.app:/cb"]))),
        "native"
    );
    assert_eq!(
        derive_application_type(Some(&json!(["https://app.example/cb"]))),
        "web"
    );
    assert_eq!(derive_application_type(None), "web");
    assert!(is_https_url("https://app.example/client.json"));
    assert!(!is_https_url("https://app.example/"));
    assert!(!is_https_url("http://app.example/client.json"));
}

#[test]
fn pkce_verifiers_are_43_unreserved_characters_with_an_s256_challenge() {
    let (verifier, challenge) = pkce_challenge().unwrap();
    assert_eq!(verifier.len(), 43);
    assert!(
        verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
    );
    assert_eq!(challenge, code_challenge_for(&verifier));
    assert_ne!(pkce_challenge().unwrap().0, verifier);
}

#[test]
fn start_authorization_builds_the_pkce_url() {
    let metadata = json!({
        "issuer": "https://as", "authorization_endpoint": "https://as/authorize?tenant=t&state=old",
        "token_endpoint": "https://as/token", "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"]
    });
    let (authorization_url, verifier) = start_authorization(
        "https://as",
        StartAuthorizationOptions {
            metadata: Some(&metadata),
            client_information: &json!({"client_id": "cid"}),
            redirect_url: "http://localhost:3334/oauth/callback",
            scope: Some("openid offline_access"),
            state: Some("st"),
            resource: Some("https://mcp.example/mcp"),
        },
    )
    .unwrap();
    let pairs: Vec<(String, String)> = authorization_url.query_pairs().into_owned().collect();
    let get = |name: &str| {
        pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(get("tenant"), ["t"]);
    assert_eq!(get("state"), ["st"]);
    assert_eq!(get("response_type"), ["code"]);
    assert_eq!(get("client_id"), ["cid"]);
    assert_eq!(
        get("code_challenge"),
        [code_challenge_for(&verifier).as_str()]
    );
    assert_eq!(get("code_challenge_method"), ["S256"]);
    assert_eq!(
        get("redirect_uri"),
        ["http://localhost:3334/oauth/callback"]
    );
    assert_eq!(get("scope"), ["openid offline_access"]);
    assert_eq!(get("prompt"), ["consent"]);
    assert_eq!(get("resource"), ["https://mcp.example/mcp"]);

    let (fallback, _) = start_authorization(
        "https://as/base/",
        StartAuthorizationOptions {
            metadata: None,
            client_information: &json!({"client_id": "cid"}),
            redirect_url: "http://localhost/cb",
            scope: None,
            state: None,
            resource: None,
        },
    )
    .unwrap();
    assert_eq!(fallback.path(), "/authorize");
    assert!(
        fallback
            .query_pairs()
            .all(|(key, _)| key != "scope" && key != "state")
    );

    let no_code =
        json!({"authorization_endpoint": "https://as/a", "response_types_supported": ["token"]});
    let error = start_authorization(
        "https://as",
        StartAuthorizationOptions {
            metadata: Some(&no_code),
            client_information: &json!({"client_id": "cid"}),
            redirect_url: "http://localhost/cb",
            scope: None,
            state: None,
            resource: None,
        },
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Incompatible auth server: does not support response type code"
    );
}
