use rust_mcp_remote::device_authorization::{
    DeviceAuthorizationResponse, parse_device_authorization_response,
};
use serde_json::{Value, json};

const INCOMPLETE: &str =
    "The authorization server returned an incomplete device authorization response";

#[test]
fn complete_response_keeps_every_field() {
    let body = json!({
        "device_code": "dc",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://example.com/device",
        "verification_uri_complete": "https://example.com/device?user_code=ABCD-EFGH",
        "expires_in": 600,
        "interval": 2.5
    });

    assert_eq!(
        parse_device_authorization_response(&body),
        Ok(DeviceAuthorizationResponse {
            device_code: "dc".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            verification_uri: "https://example.com/device".to_string(),
            verification_uri_complete: Some(
                "https://example.com/device?user_code=ABCD-EFGH".to_string()
            ),
            expires_in: Some(600.0),
            interval: Some(2.5),
        })
    );
}

#[test]
fn optional_fields_may_be_missing() {
    let body = json!({
        "device_code": "dc",
        "user_code": "uc",
        "verification_uri": "https://example.com/device"
    });

    let response = parse_device_authorization_response(&body).unwrap();

    assert_eq!(response.verification_uri_complete, None);
    assert_eq!(response.expires_in, None);
    assert_eq!(response.interval, None);
}

#[test]
fn missing_or_empty_required_fields_are_incomplete() {
    for body in [
        json!({ "user_code": "uc", "verification_uri": "https://example.com" }),
        json!({ "device_code": "dc", "user_code": "", "verification_uri": "https://example.com" }),
        json!({ "device_code": "dc", "user_code": "uc" }),
        json!({}),
        Value::Null,
        json!("text"),
    ] {
        assert_eq!(
            parse_device_authorization_response(&body),
            Err(INCOMPLETE.to_string())
        );
    }
}
