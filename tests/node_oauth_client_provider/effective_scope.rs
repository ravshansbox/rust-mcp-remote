use rust_mcp_remote::node_oauth_client_provider::{ScopeSources, effective_scope};
use serde_json::json;

#[test]
fn requested_scope_wins_over_fallback() {
    let static_metadata = json!({ "scope": "read write" });
    let sources = ScopeSources {
        static_oauth_client_metadata: Some(&static_metadata),
        ..ScopeSources::default()
    };
    assert_eq!(effective_scope(&sources, false), "read write");
    assert_eq!(effective_scope(&sources, true), "read write");
}

#[test]
fn no_source_falls_back_to_openid_email_profile() {
    assert_eq!(
        effective_scope(&ScopeSources::default(), false),
        "openid email profile"
    );
}

#[test]
fn no_source_with_explicit_token_endpoint_requests_no_scope() {
    assert_eq!(effective_scope(&ScopeSources::default(), true), "");
}

#[test]
fn empty_advertised_scopes_are_not_replaced_by_fallback() {
    let resource_metadata = json!({ "scopes_supported": [] });
    let sources = ScopeSources {
        protected_resource_metadata: Some(&resource_metadata),
        ..ScopeSources::default()
    };
    assert_eq!(effective_scope(&sources, false), "");
}
