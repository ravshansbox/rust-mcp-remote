use rust_mcp_remote::device_authorization::next_poll_interval;
use serde_json::json;

#[test]
fn keeps_the_interval_while_authorization_is_pending() {
    let body = json!({ "error": "authorization_pending" });
    assert_eq!(next_poll_interval(400, Some(&body), 5.0), Ok(5.0));
}

#[test]
fn adds_five_seconds_on_every_slow_down() {
    let body = json!({ "error": "slow_down" });
    assert_eq!(next_poll_interval(400, Some(&body), 5.0), Ok(10.0));
    assert_eq!(next_poll_interval(400, Some(&body), 10.0), Ok(15.0));
}

#[test]
fn stops_when_access_is_denied() {
    let body = json!({ "error": "access_denied" });
    assert_eq!(
        next_poll_interval(400, Some(&body), 5.0),
        Err("Authorization was denied".to_string())
    );
}

#[test]
fn stops_when_the_device_code_expired() {
    let body = json!({ "error": "expired_token" });
    assert_eq!(
        next_poll_interval(400, Some(&body), 5.0),
        Err("The device code expired before it was approved".to_string())
    );
}

#[test]
fn prefers_the_error_description_for_other_errors() {
    let body = json!({ "error": "invalid_client", "error_description": "Bad client" });
    assert_eq!(
        next_poll_interval(401, Some(&body), 5.0),
        Err("Device token request failed (HTTP 401): Bad client".to_string())
    );
}

#[test]
fn falls_back_to_the_error_code_for_other_errors() {
    let body = json!({ "error": "invalid_grant" });
    assert_eq!(
        next_poll_interval(400, Some(&body), 5.0),
        Err("Device token request failed (HTTP 400): invalid_grant".to_string())
    );
}

#[test]
fn reports_an_unknown_error_without_a_json_body() {
    assert_eq!(
        next_poll_interval(500, None, 5.0),
        Err("Device token request failed (HTTP 500): unknown error".to_string())
    );
}
