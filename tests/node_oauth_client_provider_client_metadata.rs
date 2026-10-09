use rust_mcp_remote::node_oauth_client_provider::{ClientMetadataSources, client_metadata};
use serde_json::{Value, json};

fn sources<'a>(
    static_metadata: Option<&'a Value>,
    effective_scope: &'a str,
) -> ClientMetadataSources<'a> {
    ClientMetadataSources {
        redirect_url: Some("http://localhost:3334/oauth/callback"),
        token_endpoint_auth_method: "none",
        grant_types: vec!["authorization_code", "refresh_token"],
        client_name: "MCP CLI Client",
        client_uri: "https://github.com/modelcontextprotocol/mcp-cli",
        software_id: "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d",
        software_version: "0.1.38",
        static_oauth_client_metadata: static_metadata,
        effective_scope,
    }
}

#[test]
fn builds_metadata_with_scope() {
    assert_eq!(
        client_metadata(&sources(None, "openid email")),
        json!({
            "redirect_uris": ["http://localhost:3334/oauth/callback"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": "MCP CLI Client",
            "client_uri": "https://github.com/modelcontextprotocol/mcp-cli",
            "software_id": "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d",
            "software_version": "0.1.38",
            "scope": "openid email",
        })
    );
}

#[test]
fn missing_redirect_url_gives_empty_redirect_uris() {
    let mut without_redirect = sources(None, "openid");
    without_redirect.redirect_url = None;
    assert_eq!(
        client_metadata(&without_redirect)["redirect_uris"],
        json!([])
    );
}

#[test]
fn empty_scope_is_left_out() {
    let metadata = client_metadata(&sources(None, ""));
    assert!(metadata.get("scope").is_none());
}

#[test]
fn static_metadata_overrides_defaults() {
    let static_metadata =
        json!({ "client_name": "Custom", "logo_uri": "https://example.com/logo.png" });
    let metadata = client_metadata(&sources(Some(&static_metadata), "openid"));
    assert_eq!(metadata["client_name"], "Custom");
    assert_eq!(metadata["logo_uri"], "https://example.com/logo.png");
    assert_eq!(
        metadata["software_id"],
        "2e6dc280-f3c3-4e01-99a7-8181dbd1d23d"
    );
}

#[test]
fn effective_scope_overrides_static_scope() {
    let static_metadata = json!({ "scope": "static" });
    let metadata = client_metadata(&sources(Some(&static_metadata), "effective"));
    assert_eq!(metadata["scope"], "effective");
}

#[test]
fn static_scope_stays_when_effective_scope_is_empty() {
    let static_metadata = json!({ "scope": "static" });
    let metadata = client_metadata(&sources(Some(&static_metadata), ""));
    assert_eq!(metadata["scope"], "static");
}
