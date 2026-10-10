use std::collections::BTreeMap;

use rust_mcp_remote::utils::get_server_url_hash;

fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn hash_with(resource: Option<&str>, headers: &[(&str, &str)]) -> String {
    get_server_url_hash(
        "https://example.com",
        resource,
        &map(headers),
        &BTreeMap::new(),
        None,
        None,
    )
}

#[test]
fn bare_server_url_hashes_like_node_md5() {
    assert_eq!(hash_with(None, &[]), "c984d06aafbecf6bc55569f964148ea3");
}

#[test]
fn resource_and_headers_hash_like_node() {
    assert_eq!(
        hash_with(Some("resource1"), &[("Auth", "token")]),
        "7514eba3047341d84736f2307209438a"
    );
}

#[test]
fn different_resources_give_different_hashes() {
    assert_ne!(
        hash_with(Some("resource1"), &[]),
        hash_with(Some("resource2"), &[])
    );
}

#[test]
fn different_headers_give_different_hashes() {
    assert_ne!(
        hash_with(Some(""), &[("Auth", "token1")]),
        hash_with(Some(""), &[("Auth", "token2")])
    );
}

#[test]
fn empty_resource_and_headers_match_missing_ones() {
    assert_eq!(hash_with(Some(""), &[]), hash_with(None, &[]));
}

#[test]
fn every_part_is_joined_in_order_like_node() {
    let hash = get_server_url_hash(
        "https://example.com/mcp",
        Some("r"),
        &map(&[("B", "2"), ("A", "1")]),
        &map(&[("audience", "api")]),
        Some("https://c.example/m"),
        Some("https://auth/token"),
    );
    assert_eq!(hash, "d46fe76b473280f61cf90e1996fcfe89");
}

#[test]
fn different_token_endpoints_give_different_hashes() {
    let hash_for = |token_endpoint| {
        get_server_url_hash(
            "https://example.com/mcp",
            None,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
            Some(token_endpoint),
        )
    };
    assert_ne!(
        hash_for("https://auth-a.example.com/token"),
        hash_for("https://auth-b.example.com/token")
    );
}

#[test]
fn header_keys_are_sorted_by_utf16_code_units_like_node() {
    let expected = format!(
        "{:x}",
        md5::compute("https://example.com|{\"😀\":\"x\",\"\u{FFFF}\":\"y\"}")
    );
    assert_eq!(hash_with(None, &[("\u{FFFF}", "y"), ("😀", "x")]), expected);
}
