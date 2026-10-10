use rust_mcp_remote::node_oauth_client_provider::{
    ResourceSelection, resource_selection, resource_server_url, trimmed_authorize_resource,
};
use url::Url;

#[test]
fn authorize_resource_is_trimmed_and_blank_is_dropped() {
    assert_eq!(
        trimmed_authorize_resource(Some("  https://api.example.com/mcp  ")),
        Some("https://api.example.com/mcp".to_string())
    );
    assert_eq!(trimmed_authorize_resource(Some("   ")), None);
    assert_eq!(trimmed_authorize_resource(None), None);
}

#[test]
fn skipping_the_resource_parameter_omits_it_even_with_an_authorize_resource() {
    assert_eq!(
        resource_selection(true, Some("https://api.example.com/mcp"), true),
        Ok(ResourceSelection::Omit)
    );
}

#[test]
fn an_authorize_resource_is_used_as_the_fixed_resource() {
    assert_eq!(
        resource_selection(false, Some("https://api.example.com/mcp"), true),
        Ok(ResourceSelection::Fixed(
            Url::parse("https://api.example.com/mcp").unwrap()
        ))
    );
}

#[test]
fn an_invalid_authorize_resource_is_an_error() {
    assert!(resource_selection(false, Some("not a url"), false).is_err());
}

#[test]
fn an_explicit_token_endpoint_sends_no_resource() {
    assert_eq!(
        resource_selection(false, None, true),
        Ok(ResourceSelection::NoResource)
    );
}

#[test]
fn otherwise_the_sdk_default_applies() {
    assert_eq!(
        resource_selection(false, None, false),
        Ok(ResourceSelection::SdkDefault)
    );
}

#[test]
fn resource_server_url_falls_back_to_the_server_url() {
    assert_eq!(
        resource_server_url(
            Some("https://mcp.example.com/mcp"),
            "https://auth.example.com"
        ),
        "https://mcp.example.com/mcp"
    );
    assert_eq!(
        resource_server_url(None, "https://auth.example.com"),
        "https://auth.example.com"
    );
}
