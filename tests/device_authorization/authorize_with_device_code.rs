use std::cell::RefCell;

use rust_mcp_remote::device_authorization::{
    FormRequest, FormResponse, authorize_with_device_code, build_device_authorization_request,
    build_device_token_request,
};
use serde_json::{Value, json};
use url::Url;

fn metadata() -> Value {
    json!({
        "issuer": "https://auth.example.com",
        "device_authorization_endpoint": "https://auth.example.com/device",
        "token_endpoint": "https://auth.example.com/token",
    })
}

fn response(status: u16, body: Value) -> FormResponse {
    FormResponse {
        status,
        body: body.to_string(),
    }
}

fn run(
    metadata: &Value,
    client_information: &Value,
    scope: Option<&str>,
    resource: Option<&Url>,
    responses: Vec<FormResponse>,
) -> (Result<Value, String>, Vec<(String, FormRequest)>) {
    let clock = RefCell::new(0.0);
    let mut responses = responses.into_iter();
    let mut sent = Vec::new();
    let result = authorize_with_device_code(
        metadata,
        client_information,
        scope,
        resource,
        || *clock.borrow(),
        |seconds| *clock.borrow_mut() += seconds * 1000.0,
        |endpoint, form| {
            sent.push((endpoint.to_string(), form.clone()));
            Ok(responses.next().unwrap())
        },
    );
    (result, sent)
}

#[test]
fn requests_a_device_code_then_polls_for_tokens() {
    let resource = Url::parse("https://mcp.example.com/mcp").unwrap();
    let (result, sent) = run(
        &metadata(),
        &json!({ "client_id": "client-1" }),
        Some("read write"),
        Some(&resource),
        vec![
            response(
                200,
                json!({
                    "device_code": "device-123",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://auth.example.com/activate",
                    "interval": 1,
                }),
            ),
            response(400, json!({ "error": "authorization_pending" })),
            response(200, json!({ "access_token": "at", "token_type": "Bearer" })),
        ],
    );

    assert_eq!(
        result,
        Ok(json!({ "access_token": "at", "token_type": "Bearer" }))
    );
    assert_eq!(sent.len(), 3);
    assert_eq!(
        sent[0],
        (
            "https://auth.example.com/device".to_string(),
            build_device_authorization_request(
                "none",
                "client-1",
                None,
                Some("read write"),
                Some("https://mcp.example.com/mcp"),
            )
            .unwrap()
        )
    );
    let token_request = build_device_token_request(
        "none",
        "client-1",
        None,
        "device-123",
        Some("https://mcp.example.com/mcp"),
    )
    .unwrap();
    assert_eq!(
        sent[1],
        (
            "https://auth.example.com/token".to_string(),
            token_request.clone()
        )
    );
    assert_eq!(sent[2].1, token_request);
}

#[test]
fn authenticates_with_the_selected_client_method() {
    let mut metadata = metadata();
    metadata["token_endpoint_auth_methods_supported"] = json!(["client_secret_post"]);
    let (_, sent) = run(
        &metadata,
        &json!({ "client_id": "client-1", "client_secret": "s3cret" }),
        None,
        None,
        vec![response(400, json!({ "error": "invalid_client" }))],
    );

    assert_eq!(
        sent[0].1,
        build_device_authorization_request(
            "client_secret_post",
            "client-1",
            Some("s3cret"),
            None,
            None
        )
        .unwrap()
    );
}

#[test]
fn rejects_metadata_without_a_device_authorization_endpoint() {
    let mut metadata = metadata();
    metadata
        .as_object_mut()
        .unwrap()
        .remove("device_authorization_endpoint");
    let (result, sent) = run(&metadata, &json!({ "client_id": "c" }), None, None, vec![]);

    assert_eq!(
        result,
        Err("The authorization server does not offer a device authorization endpoint".to_string())
    );
    assert!(sent.is_empty());
}

#[test]
fn rejects_metadata_without_a_token_endpoint() {
    let mut metadata = metadata();
    metadata["token_endpoint"] = json!("");
    let (result, sent) = run(&metadata, &json!({ "client_id": "c" }), None, None, vec![]);

    assert_eq!(
        result,
        Err("The authorization server metadata has no token endpoint".to_string())
    );
    assert!(sent.is_empty());
}

#[test]
fn reports_a_failed_device_authorization_request() {
    let (result, sent) = run(
        &metadata(),
        &json!({ "client_id": "c" }),
        None,
        None,
        vec![FormResponse {
            status: 400,
            body: "{\"error\":\"invalid_client\"}".to_string(),
        }],
    );

    assert_eq!(
        result,
        Err(
            "Device authorization request failed (HTTP 400): {\"error\":\"invalid_client\"}"
                .to_string()
        )
    );
    assert_eq!(sent.len(), 1);
}

#[test]
fn rejects_an_incomplete_device_authorization_response() {
    let (result, sent) = run(
        &metadata(),
        &json!({ "client_id": "c" }),
        None,
        None,
        vec![response(200, json!({ "device_code": "d" }))],
    );

    assert_eq!(
        result,
        Err(
            "The authorization server returned an incomplete device authorization response"
                .to_string()
        )
    );
    assert_eq!(sent.len(), 1);
}
