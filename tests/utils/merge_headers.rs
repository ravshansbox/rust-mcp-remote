use rust_mcp_remote::utils::merge_headers;

fn owned(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[test]
fn keeps_headers_from_every_source() {
    let merged = merge_headers(&[
        &[("mcp-protocol-version", "2025-06-18")],
        &[("Accept", "text/event-stream")],
    ]);

    assert_eq!(
        merged,
        owned(&[
            ("mcp-protocol-version", "2025-06-18"),
            ("Accept", "text/event-stream"),
        ])
    );
}

#[test]
fn one_header_per_name_however_its_writers_spelled_it() {
    let merged = merge_headers(&[
        &[("authorization", "Bearer stale")],
        &[("Authorization", "Bearer fresh")],
    ]);

    assert_eq!(merged, owned(&[("Authorization", "Bearer fresh")]));
}

#[test]
fn custom_header_keeps_the_case_it_was_written_in() {
    let merged = merge_headers(&[
        &[("accept", "text/event-stream")],
        &[("Company", "ACME"), ("TenantId", "abc")],
    ]);

    assert_eq!(
        merged,
        owned(&[
            ("accept", "text/event-stream"),
            ("Company", "ACME"),
            ("TenantId", "abc"),
        ])
    );
}

#[test]
fn empty_sources_give_empty_headers() {
    assert_eq!(merge_headers(&[]), owned(&[]));
    assert_eq!(merge_headers(&[&[]]), owned(&[]));
    assert_eq!(
        merge_headers(&[&[("a", "1")], &[], &[("b", "2")]]),
        owned(&[("a", "1"), ("b", "2")])
    );
}

#[test]
fn replaced_header_keeps_its_first_position() {
    let merged = merge_headers(&[&[("X-A", "1"), ("X-B", "2")], &[("x-a", "3")]]);

    assert_eq!(merged, owned(&[("x-a", "3"), ("X-B", "2")]));
}

#[test]
fn later_pair_in_the_same_source_wins() {
    let merged = merge_headers(&[&[("X-A", "1"), ("x-a", "2")]]);

    assert_eq!(merged, owned(&[("x-a", "2")]));
}
