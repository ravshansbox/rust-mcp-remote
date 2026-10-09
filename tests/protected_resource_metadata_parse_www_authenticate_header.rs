use rust_mcp_remote::protected_resource_metadata::{
    WwwAuthenticateParams, parse_www_authenticate_header,
};

#[test]
fn parses_the_resource_metadata_url() {
    let result = parse_www_authenticate_header(
        "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\"",
    );
    assert_eq!(
        result.resource_metadata_url.as_deref(),
        Some("https://mcp.example.com/.well-known/oauth-protected-resource")
    );
}

#[test]
fn parses_the_scope() {
    let result = parse_www_authenticate_header("Bearer scope=\"files:read files:write\"");
    assert_eq!(result.scope.as_deref(), Some("files:read files:write"));
}

#[test]
fn parses_both_resource_metadata_and_scope() {
    let result = parse_www_authenticate_header(
        "Bearer resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", scope=\"read write\"",
    );
    assert_eq!(
        result.resource_metadata_url.as_deref(),
        Some("https://mcp.example.com/.well-known/oauth-protected-resource")
    );
    assert_eq!(result.scope.as_deref(), Some("read write"));
}

#[test]
fn parses_error_and_error_description() {
    let result = parse_www_authenticate_header(
        "Bearer error=\"invalid_request\", error_description=\"No access token was provided\"",
    );
    assert_eq!(result.error.as_deref(), Some("invalid_request"));
    assert_eq!(
        result.error_description.as_deref(),
        Some("No access token was provided")
    );
}

#[test]
fn parses_a_supabase_style_header() {
    let result = parse_www_authenticate_header(
        "Bearer error=\"invalid_request\", error_description=\"No access token was provided in this request\", resource_metadata=\"https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp\"",
    );
    assert_eq!(
        result,
        WwwAuthenticateParams {
            resource_metadata_url: Some(
                "https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp".to_string()
            ),
            scope: None,
            error: Some("invalid_request".to_string()),
            error_description: Some("No access token was provided in this request".to_string()),
        }
    );
}

#[test]
fn returns_nothing_for_an_empty_header() {
    assert_eq!(
        parse_www_authenticate_header(""),
        WwwAuthenticateParams::default()
    );
}

#[test]
fn parses_a_header_without_the_bearer_prefix() {
    let result = parse_www_authenticate_header("resource_metadata=\"https://example.com/prm\"");
    assert_eq!(
        result.resource_metadata_url.as_deref(),
        Some("https://example.com/prm")
    );
}

#[test]
fn parses_unquoted_values() {
    let result = parse_www_authenticate_header("Bearer error=invalid_token");
    assert_eq!(result.error.as_deref(), Some("invalid_token"));
}

#[test]
fn ignores_the_bearer_prefix_case() {
    let result = parse_www_authenticate_header("bEaReR\tscope=read");
    assert_eq!(result.scope.as_deref(), Some("read"));
}

#[test]
fn keeps_the_last_value_when_a_key_repeats() {
    let result = parse_www_authenticate_header("Bearer scope=read, scope=\"write\"");
    assert_eq!(result.scope.as_deref(), Some("write"));
}

#[test]
fn skips_a_quoted_value_without_a_closing_quote() {
    let result = parse_www_authenticate_header("Bearer error=\"broken, scope=read");
    assert_eq!(result.error, None);
    assert_eq!(result.scope.as_deref(), Some("read"));
}
