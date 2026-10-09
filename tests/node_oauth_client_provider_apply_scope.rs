use rust_mcp_remote::node_oauth_client_provider::{ScopeSources, apply_scope};
use serde_json::json;
use url::Url;

fn authorization_url(query: &str) -> Url {
    Url::parse(&format!("https://auth.example.com/authorize?{query}")).unwrap()
}

#[test]
fn the_effective_scope_is_added_when_the_url_has_none() {
    let mut url = authorization_url("client_id=abc");
    let protected_resource_metadata = json!({ "scopes_supported": ["read", "write"] });
    let sources = ScopeSources {
        protected_resource_metadata: Some(&protected_resource_metadata),
        ..Default::default()
    };

    apply_scope(&mut url, &sources, false);

    assert_eq!(url.query(), Some("client_id=abc&scope=read+write"));
}

#[test]
fn a_scope_the_server_asked_for_is_kept() {
    let mut url = authorization_url("client_id=abc&scope=admin&state=s");
    let protected_resource_metadata = json!({ "scopes_supported": ["read"] });
    let sources = ScopeSources {
        protected_resource_metadata: Some(&protected_resource_metadata),
        ..Default::default()
    };

    apply_scope(&mut url, &sources, false);

    assert_eq!(url.query(), Some("client_id=abc&scope=admin&state=s"));
}

#[test]
fn a_scope_pinned_by_the_user_replaces_the_one_in_the_url() {
    let mut url = authorization_url("client_id=abc&scope=admin&state=s");
    let static_oauth_client_metadata = json!({ "scope": "mine" });
    let sources = ScopeSources {
        static_oauth_client_metadata: Some(&static_oauth_client_metadata),
        ..Default::default()
    };

    apply_scope(&mut url, &sources, false);

    assert_eq!(url.query(), Some("client_id=abc&scope=mine&state=s"));
}

#[test]
fn a_scope_matching_the_resource_scopes_is_replaced_by_the_effective_scope() {
    let mut url = authorization_url("scope=read+write");
    let protected_resource_metadata = json!({ "scopes_supported": ["read", "write"] });
    let www_authenticate_scope = "read";
    let sources = ScopeSources {
        www_authenticate_scope: Some(www_authenticate_scope),
        protected_resource_metadata: Some(&protected_resource_metadata),
        ..Default::default()
    };

    apply_scope(&mut url, &sources, false);

    assert_eq!(url.query(), Some("scope=read"));
}

#[test]
fn the_fallback_scope_is_used_when_no_source_describes_one() {
    let mut url = authorization_url("client_id=abc");

    apply_scope(&mut url, &ScopeSources::default(), false);

    assert_eq!(
        url.query(),
        Some("client_id=abc&scope=openid+email+profile")
    );
}

#[test]
fn no_scope_is_added_when_the_effective_scope_is_empty() {
    let mut url = authorization_url("client_id=abc");

    apply_scope(&mut url, &ScopeSources::default(), true);

    assert_eq!(url.query(), Some("client_id=abc"));
}
