use rust_mcp_remote::protected_resource_metadata::build_protected_resource_metadata_urls;

#[test]
fn builds_path_specific_and_root_urls_for_a_url_with_a_path() {
    assert_eq!(
        build_protected_resource_metadata_urls("https://mcp.example.com/mcp").unwrap(),
        vec![
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
            "https://mcp.example.com/.well-known/oauth-protected-resource",
        ]
    );
}

#[test]
fn builds_only_the_root_url_for_a_url_without_a_path() {
    assert_eq!(
        build_protected_resource_metadata_urls("https://mcp.example.com").unwrap(),
        vec!["https://mcp.example.com/.well-known/oauth-protected-resource"]
    );
}

#[test]
fn builds_only_the_root_url_for_a_url_with_just_a_slash() {
    assert_eq!(
        build_protected_resource_metadata_urls("https://mcp.example.com/").unwrap(),
        vec!["https://mcp.example.com/.well-known/oauth-protected-resource"]
    );
}

#[test]
fn handles_deep_paths() {
    assert_eq!(
        build_protected_resource_metadata_urls("https://api.example.com/v1/mcp/server").unwrap(),
        vec![
            "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp/server",
            "https://api.example.com/.well-known/oauth-protected-resource",
        ]
    );
}

#[test]
fn handles_urls_with_ports() {
    assert_eq!(
        build_protected_resource_metadata_urls("https://localhost:8080/mcp").unwrap(),
        vec![
            "https://localhost:8080/.well-known/oauth-protected-resource/mcp",
            "https://localhost:8080/.well-known/oauth-protected-resource",
        ]
    );
}

#[test]
fn strips_one_trailing_slash_from_the_path() {
    assert_eq!(
        build_protected_resource_metadata_urls("https://example.com/mcp/").unwrap(),
        vec![
            "https://example.com/.well-known/oauth-protected-resource/mcp",
            "https://example.com/.well-known/oauth-protected-resource",
        ]
    );
    assert_eq!(
        build_protected_resource_metadata_urls("https://example.com/mcp//").unwrap(),
        vec![
            "https://example.com/.well-known/oauth-protected-resource/mcp/",
            "https://example.com/.well-known/oauth-protected-resource",
        ]
    );
}

#[test]
fn rejects_an_invalid_url() {
    assert!(build_protected_resource_metadata_urls("not a url").is_err());
}
