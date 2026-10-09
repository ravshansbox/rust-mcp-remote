use rust_mcp_remote::utils::parse_header_line;

fn parsed(name: &str, value: &str) -> Option<(String, String)> {
    Some((name.to_string(), value.to_string()))
}

#[test]
fn name_and_value_are_split_at_the_colon() {
    assert_eq!(
        parse_header_line("Authorization: Bearer secret-token"),
        parsed("Authorization", "Bearer secret-token")
    );
}

#[test]
fn space_after_the_colon_is_optional() {
    assert_eq!(
        parse_header_line("X-Tenant:acme"),
        parsed("X-Tenant", "acme")
    );
}

#[test]
fn line_without_a_colon_is_rejected() {
    assert_eq!(parse_header_line("Authorization Bearer super-secret"), None);
}

#[test]
fn name_allows_only_letters_digits_underscores_and_hyphens() {
    assert_eq!(
        parse_header_line("X_Custom-9: a"),
        parsed("X_Custom-9", "a")
    );
    assert_eq!(parse_header_line("X Custom: a"), None);
    assert_eq!(parse_header_line("X.Custom: a"), None);
    assert_eq!(parse_header_line(": a"), None);
    assert_eq!(parse_header_line(" X: a"), None);
}

#[test]
fn value_keeps_later_colons_and_trailing_spaces() {
    assert_eq!(
        parse_header_line("X-Url: https://example.com:8080  "),
        parsed("X-Url", "https://example.com:8080  ")
    );
}

#[test]
fn value_may_be_empty() {
    assert_eq!(parse_header_line("X-Empty:"), parsed("X-Empty", ""));
    assert_eq!(parse_header_line("X-Empty:   "), parsed("X-Empty", ""));
}

#[test]
fn leading_javascript_whitespace_is_dropped_from_the_value() {
    assert_eq!(
        parse_header_line("X-A:\t\u{a0}\u{feff}\u{3000}v"),
        parsed("X-A", "v")
    );
    assert_eq!(parse_header_line("X-A:\nv"), parsed("X-A", "v"));
    assert_eq!(parse_header_line("X-A:\u{85}v"), parsed("X-A", "\u{85}v"));
}

#[test]
fn value_with_a_line_terminator_is_rejected() {
    assert_eq!(parse_header_line("X-A: a\nb"), None);
    assert_eq!(parse_header_line("X-A: a\r"), None);
    assert_eq!(parse_header_line("X-A: a\u{2028}b"), None);
    assert_eq!(parse_header_line("X-A: a\u{2029}b"), None);
}
