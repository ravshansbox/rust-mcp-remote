use rust_mcp_remote::device_authorization::{FormRequest, build_device_authorization_request};

fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[test]
fn none_sends_only_the_client_id() {
    let request = build_device_authorization_request("none", "c1", None, None, None).unwrap();

    assert_eq!(
        request,
        FormRequest {
            headers: pairs(&[
                ("content-type", "application/x-www-form-urlencoded"),
                ("accept", "application/json"),
            ]),
            params: pairs(&[("client_id", "c1")]),
        }
    );
}

#[test]
fn scope_and_resource_follow_client_authentication() {
    let request = build_device_authorization_request(
        "client_secret_post",
        "c1",
        Some("s1"),
        Some("read write"),
        Some("https://example.com/mcp"),
    )
    .unwrap();

    assert_eq!(
        request.params,
        pairs(&[
            ("client_id", "c1"),
            ("client_secret", "s1"),
            ("scope", "read write"),
            ("resource", "https://example.com/mcp"),
        ])
    );
}

#[test]
fn an_empty_scope_is_left_out() {
    let request = build_device_authorization_request("none", "c1", None, Some(""), None).unwrap();

    assert_eq!(request.params, pairs(&[("client_id", "c1")]));
}

#[test]
fn client_secret_basic_adds_an_authorization_header_and_no_params() {
    let request =
        build_device_authorization_request("client_secret_basic", "c1", Some("s1"), None, None)
            .unwrap();

    assert_eq!(
        request.headers,
        pairs(&[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "application/json"),
            ("Authorization", "Basic YzE6czE="),
        ])
    );
    assert!(request.params.is_empty());
}

#[test]
fn an_unsupported_method_is_an_error() {
    let result = build_device_authorization_request("private_key_jwt", "c1", None, None, None);

    assert_eq!(
        result,
        Err("Unsupported client authentication method: private_key_jwt".to_string())
    );
}
