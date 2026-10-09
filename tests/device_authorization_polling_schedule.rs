use rust_mcp_remote::device_authorization::{DeviceAuthorizationResponse, polling_schedule};

fn authorization(expires_in: Option<f64>, interval: Option<f64>) -> DeviceAuthorizationResponse {
    DeviceAuthorizationResponse {
        device_code: "dc".to_string(),
        user_code: "ABCD-EFGH".to_string(),
        verification_uri: "https://example.com/device".to_string(),
        verification_uri_complete: None,
        expires_in,
        interval,
    }
}

#[test]
fn defaults_to_five_second_interval_and_thirty_minute_expiry() {
    assert_eq!(polling_schedule(&authorization(None, None)), (5.0, 1800.0));
}

#[test]
fn uses_server_interval_and_expiry() {
    assert_eq!(
        polling_schedule(&authorization(Some(600.0), Some(2.0))),
        (2.0, 600.0)
    );
}

#[test]
fn keeps_zero_values_from_server() {
    assert_eq!(
        polling_schedule(&authorization(Some(0.0), Some(0.0))),
        (0.0, 0.0)
    );
}
