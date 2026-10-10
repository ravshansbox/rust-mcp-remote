use rust_mcp_remote::utils::is_client_metadata_url;

#[test]
fn https_url_with_a_path_is_accepted() {
    assert!(is_client_metadata_url(
        "https://example.com/.well-known/oauth-client-metadata"
    ));
}

#[test]
fn urls_an_authorization_server_would_reject_are_refused() {
    for url in [
        "http://example.com/client-metadata",
        "https://example.com/",
        "https://example.com",
        "not-a-url",
    ] {
        assert!(!is_client_metadata_url(url), "{url}");
    }
}

#[test]
fn query_or_fragment_alone_does_not_count_as_a_path() {
    assert!(!is_client_metadata_url("https://example.com?client=a"));
    assert!(!is_client_metadata_url("https://example.com/#client"));
}

#[test]
fn scheme_case_and_surrounding_spaces_are_normalised() {
    assert!(is_client_metadata_url("HTTPS://Example.com/client"));
    assert!(is_client_metadata_url("  https://example.com/client  "));
}

#[test]
fn empty_string_is_refused() {
    assert!(!is_client_metadata_url(""));
}
