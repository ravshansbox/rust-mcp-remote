use rust_mcp_remote::client_credentials::build_client_credentials_request;

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

const MISSING_SECRET: &str = "The client_credentials grant needs a client secret. Supply one with --static-oauth-client-info, which accepts `@path/to/file.json` and `${ENV_VAR}` placeholders so the secret need not sit in the command line.";

#[test]
fn refuses_without_a_client_secret() {
    for client_secret in [None, Some("")] {
        let result = build_client_credentials_request(
            "client_secret_post",
            "my-client",
            client_secret,
            None,
            None,
        );

        assert_eq!(result.unwrap_err(), MISSING_SECRET);
    }
}

#[test]
fn sends_the_grant_type_and_credentials_in_the_body_for_client_secret_post() {
    let request = build_client_credentials_request(
        "client_secret_post",
        "my-client",
        Some("s3cret"),
        None,
        None,
    )
    .expect("request");

    assert_eq!(
        request.headers,
        pairs(&[
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "application/json"),
        ])
    );
    assert_eq!(
        request.params,
        pairs(&[
            ("grant_type", "client_credentials"),
            ("client_id", "my-client"),
            ("client_secret", "s3cret"),
        ])
    );
}

#[test]
fn sends_basic_authorization_for_client_secret_basic() {
    let request = build_client_credentials_request(
        "client_secret_basic",
        "my-client",
        Some("s3cret"),
        None,
        None,
    )
    .expect("request");

    assert_eq!(
        request.headers.last(),
        Some(&(
            "Authorization".to_string(),
            "Basic bXktY2xpZW50OnMzY3JldA==".to_string()
        ))
    );
    assert_eq!(
        request.params,
        pairs(&[("grant_type", "client_credentials")])
    );
}

#[test]
fn adds_scope_and_resource_when_given() {
    let request = build_client_credentials_request(
        "client_secret_post",
        "my-client",
        Some("s3cret"),
        Some("read write"),
        Some("https://mcp.example.com/mcp"),
    )
    .expect("request");

    assert_eq!(
        request.params,
        pairs(&[
            ("grant_type", "client_credentials"),
            ("client_id", "my-client"),
            ("client_secret", "s3cret"),
            ("scope", "read write"),
            ("resource", "https://mcp.example.com/mcp"),
        ])
    );
}

#[test]
fn leaves_out_an_empty_scope() {
    let request = build_client_credentials_request(
        "client_secret_post",
        "my-client",
        Some("s3cret"),
        Some(""),
        None,
    )
    .expect("request");

    assert!(!request.params.iter().any(|(name, _)| name == "scope"));
}

#[test]
fn passes_on_an_unsupported_authentication_method() {
    let result = build_client_credentials_request(
        "private_key_jwt",
        "my-client",
        Some("s3cret"),
        None,
        None,
    );

    assert_eq!(
        result.unwrap_err(),
        "Unsupported client authentication method: private_key_jwt"
    );
}
