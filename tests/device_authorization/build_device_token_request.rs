use rust_mcp_remote::device_authorization::{FormRequest, build_device_token_request};

fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[test]
fn none_adds_the_client_id_after_the_device_code() {
    let request = build_device_token_request("none", "c1", None, "dc1", None).unwrap();

    assert_eq!(
        request,
        FormRequest {
            headers: pairs(&[
                ("content-type", "application/x-www-form-urlencoded"),
                ("accept", "application/json"),
            ]),
            params: pairs(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", "dc1"),
                ("client_id", "c1"),
            ]),
        }
    );
}

#[test]
fn client_secret_basic_adds_an_authorization_header() {
    let request =
        build_device_token_request("client_secret_basic", "c1", Some("s1"), "dc1", None).unwrap();

    assert_eq!(
        request.headers,
        pairs(&[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "application/json"),
            ("Authorization", "Basic YzE6czE="),
        ])
    );
    assert_eq!(
        request.params,
        pairs(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", "dc1"),
        ])
    );
}

#[test]
fn a_resource_is_added_last() {
    let request = build_device_token_request(
        "client_secret_post",
        "c1",
        Some("s1"),
        "dc1",
        Some("https://example.com/mcp"),
    )
    .unwrap();

    assert_eq!(
        request.params,
        pairs(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", "dc1"),
            ("client_id", "c1"),
            ("client_secret", "s1"),
            ("resource", "https://example.com/mcp"),
        ])
    );
}

#[test]
fn an_unsupported_method_is_an_error() {
    let result = build_device_token_request("private_key_jwt", "c1", None, "dc1", None);

    assert_eq!(
        result,
        Err("Unsupported client authentication method: private_key_jwt".to_string())
    );
}
