use std::collections::BTreeMap;

use rust_mcp_remote::node_oauth_client_provider::apply_authorize_params;
use url::Url;

fn authorization_url(query: &str) -> Url {
    Url::parse(&format!("https://auth.example.com/authorize?{query}")).unwrap()
}

#[test]
fn extra_parameters_are_added_to_the_url() {
    let mut url = authorization_url("client_id=abc");
    let authorize_params = BTreeMap::from([
        (
            "audience".to_string(),
            "https://api.example.com".to_string(),
        ),
        ("prompt".to_string(), "consent".to_string()),
    ]);

    apply_authorize_params(&mut url, &authorize_params);

    assert_eq!(
        url.query(),
        Some("client_id=abc&audience=https%3A%2F%2Fapi.example.com&prompt=consent")
    );
}

#[test]
fn an_extra_parameter_replaces_one_already_in_the_url() {
    let mut url = authorization_url("prompt=login&client_id=abc&prompt=none");
    let authorize_params = BTreeMap::from([("prompt".to_string(), "consent".to_string())]);

    apply_authorize_params(&mut url, &authorize_params);

    assert_eq!(url.query(), Some("prompt=consent&client_id=abc"));
}

#[test]
fn no_extra_parameters_leave_the_url_unchanged() {
    let mut url = authorization_url("client_id=abc&scope=a%20b");

    apply_authorize_params(&mut url, &BTreeMap::new());

    assert_eq!(url.query(), Some("client_id=abc&scope=a%20b"));
}
