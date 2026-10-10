use rust_mcp_remote::node_oauth_client_provider::{ScopeSources, scope_request_changed};
use serde_json::json;

#[test]
fn token_without_a_recorded_request_is_left_alone() {
    let static_metadata = json!({ "scope": "read write" });
    let sources = ScopeSources {
        static_oauth_client_metadata: Some(&static_metadata),
        ..ScopeSources::default()
    };
    let tokens = json!({ "access_token": "a", "scope": "read" });
    assert!(!scope_request_changed(&tokens, &sources));
}

#[test]
fn nothing_requested_now_is_not_a_change() {
    let tokens = json!({ "access_token": "a", "requested_scope": "read" });
    assert!(!scope_request_changed(&tokens, &ScopeSources::default()));
}

#[test]
fn same_request_is_not_a_change_even_when_less_was_granted() {
    let static_metadata = json!({ "scope": "read write" });
    let sources = ScopeSources {
        static_oauth_client_metadata: Some(&static_metadata),
        ..ScopeSources::default()
    };
    let tokens = json!({ "access_token": "a", "scope": "read", "requested_scope": "read write" });
    assert!(!scope_request_changed(&tokens, &sources));
}

#[test]
fn different_request_is_a_change() {
    let static_metadata = json!({ "scope": "read write admin" });
    let sources = ScopeSources {
        static_oauth_client_metadata: Some(&static_metadata),
        ..ScopeSources::default()
    };
    let tokens = json!({ "access_token": "a", "requested_scope": "read write" });
    assert!(scope_request_changed(&tokens, &sources));
}

#[test]
fn empty_recorded_request_differs_from_a_new_scope() {
    let resource = json!({ "scopes_supported": ["mcp"] });
    let sources = ScopeSources {
        protected_resource_metadata: Some(&resource),
        ..ScopeSources::default()
    };
    let tokens = json!({ "access_token": "a", "requested_scope": "" });
    assert!(scope_request_changed(&tokens, &sources));
}
