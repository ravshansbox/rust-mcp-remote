use rust_mcp_remote::device_authorization::error_detail;

#[test]
fn returns_short_body_unchanged() {
    assert_eq!(
        error_detail(Some("invalid_client"), "Bad Request"),
        "invalid_client"
    );
}

#[test]
fn keeps_only_first_500_characters_of_body() {
    let body = "é".repeat(600);
    assert_eq!(error_detail(Some(&body), "Bad Request"), "é".repeat(500));
}

#[test]
fn falls_back_to_status_text_when_body_is_empty() {
    assert_eq!(error_detail(Some(""), "Bad Request"), "Bad Request");
}

#[test]
fn falls_back_to_status_text_when_body_cannot_be_read() {
    assert_eq!(
        error_detail(None, "Internal Server Error"),
        "Internal Server Error"
    );
}
