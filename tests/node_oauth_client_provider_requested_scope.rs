use rust_mcp_remote::node_oauth_client_provider::{ScopeSources, requested_scope};
use serde_json::json;

#[test]
fn static_client_metadata_scope_comes_first() {
    let static_metadata = json!({ "scope": "static" });
    let resource = json!({ "scopes_supported": ["resource"] });
    let sources = ScopeSources {
        static_oauth_client_metadata: Some(&static_metadata),
        www_authenticate_scope: Some("header"),
        protected_resource_metadata: Some(&resource),
        ..ScopeSources::default()
    };
    assert_eq!(requested_scope(&sources).as_deref(), Some("static"));
}

#[test]
fn blank_static_scope_falls_through_to_the_www_authenticate_scope() {
    let static_metadata = json!({ "scope": "   " });
    let sources = ScopeSources {
        static_oauth_client_metadata: Some(&static_metadata),
        www_authenticate_scope: Some("header"),
        ..ScopeSources::default()
    };
    assert_eq!(requested_scope(&sources).as_deref(), Some("header"));
}

#[test]
fn protected_resource_scopes_are_joined_with_spaces() {
    let resource = json!({ "scopes_supported": ["read", "write"] });
    let sources = ScopeSources {
        www_authenticate_scope: Some(" "),
        protected_resource_metadata: Some(&resource),
        ..ScopeSources::default()
    };
    assert_eq!(requested_scope(&sources).as_deref(), Some("read write"));
}

#[test]
fn an_empty_protected_resource_scope_list_omits_the_scope() {
    let resource = json!({ "scopes_supported": [] });
    let client = json!({ "scope": "client" });
    let sources = ScopeSources {
        protected_resource_metadata: Some(&resource),
        client_information: Some(&client),
        ..ScopeSources::default()
    };
    assert_eq!(requested_scope(&sources).as_deref(), Some(""));
}

#[test]
fn client_registration_scope_comes_before_authorization_server_scopes() {
    let client = json!({ "scope": "client" });
    let server = json!({ "scopes_supported": ["server"] });
    let sources = ScopeSources {
        client_information: Some(&client),
        authorization_server_metadata: Some(&server),
        ..ScopeSources::default()
    };
    assert_eq!(requested_scope(&sources).as_deref(), Some("client"));
}

#[test]
fn authorization_server_scopes_are_the_last_source() {
    let server = json!({ "scopes_supported": ["openid", "profile"] });
    let sources = ScopeSources {
        authorization_server_metadata: Some(&server),
        ..ScopeSources::default()
    };
    assert_eq!(requested_scope(&sources).as_deref(), Some("openid profile"));

    let empty = json!({ "scopes_supported": [] });
    let sources = ScopeSources {
        authorization_server_metadata: Some(&empty),
        ..ScopeSources::default()
    };
    assert_eq!(requested_scope(&sources).as_deref(), Some(""));
}

#[test]
fn no_source_gives_no_scope() {
    let resource = json!({});
    let sources = ScopeSources {
        protected_resource_metadata: Some(&resource),
        ..ScopeSources::default()
    };
    assert_eq!(requested_scope(&sources), None);
}
