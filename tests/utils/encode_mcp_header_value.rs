use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rust_mcp_remote::utils::encode_mcp_header_value;

#[test]
fn plain_ascii_values_are_sent_as_is() {
    assert_eq!(encode_mcp_header_value("get_weather"), "get_weather");
    assert_eq!(
        encode_mcp_header_value("file:///projects/myapp/config.json"),
        "file:///projects/myapp/config.json"
    );
}

#[test]
fn values_rfc_9110_cannot_carry_are_base64_encoded() {
    assert_eq!(
        encode_mcp_header_value("Hello, 世界"),
        "=?base64?SGVsbG8sIOS4lueVjA==?="
    );
    assert_eq!(
        encode_mcp_header_value(" padded "),
        "=?base64?IHBhZGRlZCA=?="
    );
    assert_eq!(
        encode_mcp_header_value("line1\nline2"),
        "=?base64?bGluZTEKbGluZTI=?="
    );
}

#[test]
fn a_literal_that_looks_like_the_sentinel_is_itself_encoded() {
    assert_eq!(
        encode_mcp_header_value("=?base64?literal?="),
        "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="
    );
}

#[test]
fn encoded_values_round_trip_back_to_the_body_value() {
    for original in [
        "Hello, 世界",
        " padded ",
        "line1\nline2",
        "=?base64?literal?=",
    ] {
        let encoded = encode_mcp_header_value(original);
        let payload = &encoded["=?base64?".len()..encoded.len() - "?=".len()];
        let decoded = String::from_utf8(STANDARD.decode(payload).unwrap()).unwrap();
        assert_eq!(decoded, original);
    }
}

#[test]
fn inner_spaces_and_tabs_are_kept_but_empty_and_edge_whitespace_are_encoded() {
    assert_eq!(encode_mcp_header_value("a b\tc"), "a b\tc");
    assert_eq!(encode_mcp_header_value("x"), "x");
    assert_eq!(encode_mcp_header_value(""), "=?base64??=");
    assert_eq!(encode_mcp_header_value("\tx"), "=?base64?CXg=?=");
    assert_eq!(encode_mcp_header_value("x\u{7f}"), "=?base64?eH8=?=");
}
