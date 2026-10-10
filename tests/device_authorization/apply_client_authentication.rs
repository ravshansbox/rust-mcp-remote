use rust_mcp_remote::device_authorization::apply_client_authentication;

fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[test]
fn client_secret_basic_puts_the_credentials_on_the_authorization_header() {
    let mut headers = pairs(&[("content-type", "application/x-www-form-urlencoded")]);
    let mut params = pairs(&[("grant_type", "client_credentials")]);

    apply_client_authentication(
        "client_secret_basic",
        "c1",
        Some("s1"),
        &mut headers,
        &mut params,
    )
    .unwrap();

    assert_eq!(
        headers,
        pairs(&[
            ("content-type", "application/x-www-form-urlencoded"),
            ("Authorization", "Basic YzE6czE="),
        ])
    );
    assert_eq!(params, pairs(&[("grant_type", "client_credentials")]));
}

#[test]
fn client_secret_basic_without_a_secret_is_an_error() {
    let mut headers = Vec::new();
    let mut params = Vec::new();

    let result =
        apply_client_authentication("client_secret_basic", "c1", None, &mut headers, &mut params);

    assert_eq!(
        result,
        Err("client_secret_basic authentication requires a client_secret".to_string())
    );
    assert!(headers.is_empty());
}

#[test]
fn client_secret_post_puts_the_credentials_in_the_body() {
    let mut headers = Vec::new();
    let mut params = pairs(&[("grant_type", "client_credentials")]);

    apply_client_authentication(
        "client_secret_post",
        "c1",
        Some("s1"),
        &mut headers,
        &mut params,
    )
    .unwrap();

    assert!(headers.is_empty());
    assert_eq!(
        params,
        pairs(&[
            ("grant_type", "client_credentials"),
            ("client_id", "c1"),
            ("client_secret", "s1"),
        ])
    );
}

#[test]
fn client_secret_post_without_a_secret_sends_only_the_client_id() {
    let mut headers = Vec::new();
    let mut params = Vec::new();

    apply_client_authentication("client_secret_post", "c1", None, &mut headers, &mut params)
        .unwrap();

    assert_eq!(params, pairs(&[("client_id", "c1")]));
}

#[test]
fn none_sends_only_the_client_id_and_replaces_an_existing_one() {
    let mut headers = Vec::new();
    let mut params = pairs(&[
        ("client_id", "old"),
        ("scope", "read"),
        ("client_id", "older"),
    ]);

    apply_client_authentication("none", "c1", Some("s1"), &mut headers, &mut params).unwrap();

    assert_eq!(params, pairs(&[("client_id", "c1"), ("scope", "read")]));
}

#[test]
fn an_unknown_method_is_an_error() {
    let mut headers = Vec::new();
    let mut params = Vec::new();

    let result = apply_client_authentication(
        "private_key_jwt",
        "c1",
        Some("s1"),
        &mut headers,
        &mut params,
    );

    assert_eq!(
        result,
        Err("Unsupported client authentication method: private_key_jwt".to_string())
    );
    assert!(params.is_empty());
}
