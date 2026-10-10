use rust_mcp_remote::device_authorization::{
    DEVICE_CODE_GRANT_TYPE, supports_device_authorization,
};
use serde_json::json;

#[test]
fn uses_the_rfc_8628_grant_type() {
    assert_eq!(
        DEVICE_CODE_GRANT_TYPE,
        "urn:ietf:params:oauth:grant-type:device_code"
    );
}

#[test]
fn rejects_missing_metadata() {
    assert!(!supports_device_authorization(None));
}

#[test]
fn rejects_metadata_without_an_endpoint() {
    let metadata = json!({ "issuer": "https://auth.example.com" });
    assert!(!supports_device_authorization(Some(&metadata)));
}

#[test]
fn rejects_an_empty_endpoint() {
    let metadata =
        json!({ "issuer": "https://auth.example.com", "device_authorization_endpoint": "" });
    assert!(!supports_device_authorization(Some(&metadata)));
}

#[test]
fn accepts_an_endpoint_without_advertised_grants() {
    let metadata = json!({
        "issuer": "https://auth.example.com",
        "device_authorization_endpoint": "https://auth.example.com/device"
    });
    assert!(supports_device_authorization(Some(&metadata)));
}

#[test]
fn accepts_an_endpoint_when_grants_is_not_an_array() {
    let metadata = json!({
        "issuer": "https://auth.example.com",
        "device_authorization_endpoint": "https://auth.example.com/device",
        "grant_types_supported": "authorization_code"
    });
    assert!(supports_device_authorization(Some(&metadata)));
}

#[test]
fn accepts_an_endpoint_when_the_grant_is_advertised() {
    let metadata = json!({
        "issuer": "https://auth.example.com",
        "device_authorization_endpoint": "https://auth.example.com/device",
        "grant_types_supported": ["authorization_code", DEVICE_CODE_GRANT_TYPE]
    });
    assert!(supports_device_authorization(Some(&metadata)));
}

#[test]
fn rejects_an_endpoint_when_the_grant_is_not_advertised() {
    let metadata = json!({
        "issuer": "https://auth.example.com",
        "device_authorization_endpoint": "https://auth.example.com/device",
        "grant_types_supported": ["authorization_code"]
    });
    assert!(!supports_device_authorization(Some(&metadata)));
}
