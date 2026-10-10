use rust_mcp_remote::client_credentials::check_token_endpoint_to;
use serde_json::{Value, json};

fn check(metadata: Value) -> (Result<String, String>, String) {
    let mut console = Vec::new();
    let result = check_token_endpoint_to(&mut console, &metadata);
    (result, String::from_utf8(console).expect("utf8"))
}

#[test]
fn accepts_an_https_endpoint_and_logs_its_origin() {
    let (result, output) = check(json!({
        "issuer": "https://auth.example.com",
        "token_endpoint": "https://auth.example.com/token",
    }));

    assert_eq!(result, Ok("https://auth.example.com/token".to_string()));
    assert!(output.ends_with(
        "Requesting a token from https://auth.example.com with the client_credentials grant\n"
    ));
}

#[test]
fn says_so_when_there_is_no_token_endpoint() {
    for metadata in [
        json!({ "issuer": "https://auth.example.com" }),
        json!({ "token_endpoint": 42 }),
        json!({ "token_endpoint": null }),
    ] {
        let (result, output) = check(metadata);

        assert_eq!(
            result,
            Err("The authorization server metadata has no token endpoint".to_string())
        );
        assert_eq!(output, "");
    }
}

#[test]
fn refuses_to_send_the_secret_over_plain_http() {
    let (result, output) = check(json!({ "token_endpoint": "http://auth.example.com:8080/token" }));

    assert_eq!(
        result,
        Err("Refusing to send the client secret to http://auth.example.com:8080 over http. The client_credentials grant needs an https token endpoint.".to_string())
    );
    assert_eq!(output, "");
}

#[test]
fn allows_plain_http_to_localhost_and_127_0_0_1() {
    for endpoint in ["http://localhost:3000/token", "http://127.0.0.1/token"] {
        let (result, _) = check(json!({ "token_endpoint": endpoint }));

        assert_eq!(result, Ok(endpoint.to_string()));
    }
}

#[test]
fn refuses_plain_http_to_the_ipv6_loopback() {
    let (result, _) = check(json!({ "token_endpoint": "http://[::1]/token" }));

    assert_eq!(
        result,
        Err("Refusing to send the client secret to http://[::1] over http. The client_credentials grant needs an https token endpoint.".to_string())
    );
}

#[test]
fn rejects_an_endpoint_that_is_not_a_url() {
    let (result, output) = check(json!({ "token_endpoint": "not a url" }));

    assert_eq!(result, Err("Invalid URL".to_string()));
    assert_eq!(output, "");
}
