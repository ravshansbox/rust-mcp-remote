use rust_mcp_remote::device_authorization::{
    DeviceAuthorizationResponse, verification_prompt_lines,
};

fn authorization(verification_uri_complete: Option<&str>) -> DeviceAuthorizationResponse {
    DeviceAuthorizationResponse {
        device_code: "dc".to_string(),
        user_code: "ABCD-EFGH".to_string(),
        verification_uri: "https://example.com/device".to_string(),
        verification_uri_complete: verification_uri_complete.map(str::to_string),
        expires_in: None,
        interval: None,
    }
}

#[test]
fn without_complete_uri_shows_uri_and_code() {
    assert_eq!(
        verification_prompt_lines(&authorization(None)),
        vec![
            "",
            "To authorize this client, visit:",
            "  https://example.com/device",
            "",
            "And enter the code: ABCD-EFGH",
            "",
            "Waiting for approval...",
        ]
    );
}

#[test]
fn with_complete_uri_shows_only_that_link() {
    assert_eq!(
        verification_prompt_lines(&authorization(Some(
            "https://example.com/device?user_code=ABCD-EFGH"
        ))),
        vec![
            "",
            "To authorize this client, visit:",
            "  https://example.com/device?user_code=ABCD-EFGH",
            "",
            "Waiting for approval...",
        ]
    );
}
