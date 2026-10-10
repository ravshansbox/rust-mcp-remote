use std::cell::RefCell;

use rust_mcp_remote::device_authorization::{
    DeviceAuthorizationResponse, FormRequest, FormResponse, build_device_token_request,
    poll_for_tokens,
};
use serde_json::json;

fn authorization(interval: Option<f64>, expires_in: Option<f64>) -> DeviceAuthorizationResponse {
    DeviceAuthorizationResponse {
        device_code: "device-123".to_string(),
        user_code: "ABCD-EFGH".to_string(),
        verification_uri: "https://auth.example.com/device".to_string(),
        verification_uri_complete: None,
        expires_in,
        interval,
    }
}

fn request() -> FormRequest {
    build_device_token_request("none", "client-1", None, "device-123", None).unwrap()
}

fn response(status: u16, body: serde_json::Value) -> FormResponse {
    FormResponse {
        status,
        body: body.to_string(),
    }
}

#[test]
fn returns_the_tokens_after_pending_responses() {
    let clock = RefCell::new(0.0);
    let sleeps = RefCell::new(Vec::new());
    let mut responses = vec![
        response(400, json!({ "error": "authorization_pending" })),
        response(200, json!({ "access_token": "at", "token_type": "Bearer" })),
    ]
    .into_iter();
    let mut sent = Vec::new();

    let tokens = poll_for_tokens(
        "https://auth.example.com/token",
        &authorization(Some(2.0), None),
        &request(),
        || *clock.borrow(),
        |seconds| {
            sleeps.borrow_mut().push(seconds);
            *clock.borrow_mut() += seconds * 1000.0;
        },
        |endpoint, form| {
            sent.push((endpoint.to_string(), form.clone()));
            Ok(responses.next().unwrap())
        },
    );

    assert_eq!(
        tokens,
        Ok(json!({ "access_token": "at", "token_type": "Bearer" }))
    );
    assert_eq!(*sleeps.borrow(), vec![2.0, 2.0]);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].0, "https://auth.example.com/token");
    assert_eq!(sent[0].1, request());
}

#[test]
fn backs_off_permanently_after_slow_down() {
    let clock = RefCell::new(0.0);
    let sleeps = RefCell::new(Vec::new());
    let mut responses = vec![
        response(400, json!({ "error": "slow_down" })),
        response(400, json!({ "error": "authorization_pending" })),
        response(200, json!({ "access_token": "at", "token_type": "Bearer" })),
    ]
    .into_iter();

    let tokens = poll_for_tokens(
        "https://auth.example.com/token",
        &authorization(None, None),
        &request(),
        || *clock.borrow(),
        |seconds| {
            sleeps.borrow_mut().push(seconds);
            *clock.borrow_mut() += seconds * 1000.0;
        },
        |_, _| Ok(responses.next().unwrap()),
    );

    assert!(tokens.is_ok());
    assert_eq!(*sleeps.borrow(), vec![5.0, 10.0, 10.0]);
}

#[test]
fn stops_when_access_is_denied() {
    let clock = RefCell::new(0.0);
    let tokens = poll_for_tokens(
        "https://auth.example.com/token",
        &authorization(Some(1.0), None),
        &request(),
        || *clock.borrow(),
        |seconds| *clock.borrow_mut() += seconds * 1000.0,
        |_, _| Ok(response(400, json!({ "error": "access_denied" }))),
    );

    assert_eq!(tokens, Err("Authorization was denied".to_string()));
}

#[test]
fn reports_an_unparseable_error_body_as_unknown() {
    let clock = RefCell::new(0.0);
    let tokens = poll_for_tokens(
        "https://auth.example.com/token",
        &authorization(Some(1.0), None),
        &request(),
        || *clock.borrow(),
        |seconds| *clock.borrow_mut() += seconds * 1000.0,
        |_, _| {
            Ok(FormResponse {
                status: 502,
                body: "<html>Bad Gateway</html>".to_string(),
            })
        },
    );

    assert_eq!(
        tokens,
        Err("Device token request failed (HTTP 502): unknown error".to_string())
    );
}

#[test]
fn gives_up_once_the_device_code_lapses() {
    let clock = RefCell::new(0.0);
    let mut attempts = 0;
    let tokens = poll_for_tokens(
        "https://auth.example.com/token",
        &authorization(Some(5.0), Some(12.0)),
        &request(),
        || *clock.borrow(),
        |seconds| *clock.borrow_mut() += seconds * 1000.0,
        |_, _| {
            attempts += 1;
            Ok(response(400, json!({ "error": "authorization_pending" })))
        },
    );

    assert_eq!(
        tokens,
        Err("The device code expired before it was approved".to_string())
    );
    assert_eq!(attempts, 3);
}

#[test]
fn passes_a_transport_error_through() {
    let clock = RefCell::new(0.0);
    let tokens = poll_for_tokens(
        "https://auth.example.com/token",
        &authorization(Some(1.0), None),
        &request(),
        || *clock.borrow(),
        |seconds| *clock.borrow_mut() += seconds * 1000.0,
        |_, _| Err("fetch failed".to_string()),
    );

    assert_eq!(tokens, Err("fetch failed".to_string()));
}

#[test]
fn rejects_a_success_body_that_is_not_tokens() {
    let clock = RefCell::new(0.0);
    let tokens = poll_for_tokens(
        "https://auth.example.com/token",
        &authorization(Some(1.0), None),
        &request(),
        || *clock.borrow(),
        |seconds| *clock.borrow_mut() += seconds * 1000.0,
        |_, _| Ok(response(200, json!({ "token_type": "Bearer" }))),
    );

    assert!(tokens.is_err());
}
