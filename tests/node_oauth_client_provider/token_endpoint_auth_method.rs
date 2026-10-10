use rust_mcp_remote::node_oauth_client_provider::token_endpoint_auth_method;
use serde_json::json;

#[test]
fn uses_none_without_metadata() {
    assert_eq!(token_endpoint_auth_method(None), "none");
}

#[test]
fn uses_none_when_the_list_is_missing_empty_or_not_an_array() {
    assert_eq!(token_endpoint_auth_method(Some(&json!({}))), "none");
    assert_eq!(
        token_endpoint_auth_method(Some(&json!({"token_endpoint_auth_methods_supported": []}))),
        "none"
    );
    assert_eq!(
        token_endpoint_auth_method(Some(
            &json!({"token_endpoint_auth_methods_supported": "client_secret_post"})
        )),
        "none"
    );
}

#[test]
fn prefers_none_when_offered() {
    assert_eq!(
        token_endpoint_auth_method(Some(&json!({
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"]
        }))),
        "none"
    );
}

#[test]
fn prefers_client_secret_post_over_client_secret_basic() {
    assert_eq!(
        token_endpoint_auth_method(Some(&json!({
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
        }))),
        "client_secret_post"
    );
}

#[test]
fn uses_client_secret_basic_when_it_is_the_only_one_it_can_perform() {
    assert_eq!(
        token_endpoint_auth_method(Some(&json!({
            "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic"]
        }))),
        "client_secret_basic"
    );
}

#[test]
fn falls_back_to_none_when_nothing_offered_can_be_performed() {
    assert_eq!(
        token_endpoint_auth_method(Some(&json!({
            "token_endpoint_auth_methods_supported": ["private_key_jwt", 1, null]
        }))),
        "none"
    );
}
