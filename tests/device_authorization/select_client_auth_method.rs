use rust_mcp_remote::device_authorization::select_client_auth_method;
use serde_json::json;

#[test]
fn uses_the_registered_method_when_the_server_supports_it() {
    let client = json!({ "client_id": "c", "client_secret": "s", "token_endpoint_auth_method": "client_secret_post" });
    assert_eq!(
        select_client_auth_method(&client, &["client_secret_basic", "client_secret_post"]),
        "client_secret_post"
    );
}

#[test]
fn uses_the_registered_method_when_the_server_lists_nothing() {
    let client = json!({ "client_id": "c", "token_endpoint_auth_method": "client_secret_post" });
    assert_eq!(
        select_client_auth_method(&client, &[]),
        "client_secret_post"
    );
}

#[test]
fn ignores_a_registered_method_the_server_does_not_support() {
    let client = json!({ "client_id": "c", "client_secret": "s", "token_endpoint_auth_method": "client_secret_post" });
    assert_eq!(
        select_client_auth_method(&client, &["client_secret_basic"]),
        "client_secret_basic"
    );
}

#[test]
fn ignores_an_unknown_registered_method() {
    let client = json!({ "client_id": "c", "token_endpoint_auth_method": "private_key_jwt" });
    assert_eq!(select_client_auth_method(&client, &[]), "none");
}

#[test]
fn defaults_by_secret_when_the_server_lists_nothing() {
    assert_eq!(
        select_client_auth_method(&json!({ "client_id": "c", "client_secret": "s" }), &[]),
        "client_secret_basic"
    );
    assert_eq!(
        select_client_auth_method(&json!({ "client_id": "c" }), &[]),
        "none"
    );
}

#[test]
fn prefers_basic_then_post_for_a_confidential_client() {
    let client = json!({ "client_id": "c", "client_secret": "s" });
    assert_eq!(
        select_client_auth_method(
            &client,
            &["none", "client_secret_post", "client_secret_basic"]
        ),
        "client_secret_basic"
    );
    assert_eq!(
        select_client_auth_method(&client, &["none", "client_secret_post"]),
        "client_secret_post"
    );
    assert_eq!(select_client_auth_method(&client, &["none"]), "none");
}

#[test]
fn falls_back_when_no_supported_method_matches() {
    let methods = ["private_key_jwt"];
    assert_eq!(
        select_client_auth_method(&json!({ "client_id": "c", "client_secret": "s" }), &methods),
        "client_secret_post"
    );
    assert_eq!(
        select_client_auth_method(&json!({ "client_id": "c" }), &methods),
        "none"
    );
}

#[test]
fn counts_a_null_secret_as_present() {
    let client = json!({ "client_id": "c", "client_secret": null });
    assert_eq!(
        select_client_auth_method(&client, &[]),
        "client_secret_basic"
    );
}
