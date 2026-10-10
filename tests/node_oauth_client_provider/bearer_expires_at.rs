use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rust_mcp_remote::node_oauth_client_provider::bearer_expires_at;
use serde_json::json;

fn jwt_with_payload(payload: &str) -> String {
    format!(
        "{}.{}.signature",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(payload)
    )
}

#[test]
fn uses_the_stored_expiry_without_use_id_token() {
    let tokens = json!({
        "access_token": "access",
        "id_token": jwt_with_payload(r#"{"exp":1700000000}"#),
        "expires_at": 1_800_000_000_000_u64,
    });
    assert_eq!(bearer_expires_at(false, &tokens), Some(1_800_000_000_000.0));
}

#[test]
fn uses_the_id_token_expiry_with_use_id_token() {
    let tokens = json!({
        "access_token": "access",
        "id_token": jwt_with_payload(r#"{"exp":1700000000}"#),
        "expires_at": 1_800_000_000_000_u64,
    });
    assert_eq!(bearer_expires_at(true, &tokens), Some(1_700_000_000_000.0));
}

#[test]
fn falls_back_to_the_stored_expiry_when_the_id_token_has_no_exp() {
    let tokens = json!({
        "access_token": "access",
        "id_token": jwt_with_payload(r#"{"sub":"user"}"#),
        "expires_at": 1_800_000_000_000_u64,
    });
    assert_eq!(bearer_expires_at(true, &tokens), Some(1_800_000_000_000.0));
}

#[test]
fn uses_the_stored_expiry_when_there_is_no_id_token() {
    let tokens = json!({ "access_token": "access", "expires_at": 1_800_000_000_000_u64 });
    assert_eq!(bearer_expires_at(true, &tokens), Some(1_800_000_000_000.0));
}

#[test]
fn uses_the_stored_expiry_when_the_id_token_is_empty() {
    let tokens = json!({ "access_token": "access", "id_token": "", "expires_at": 5 });
    assert_eq!(bearer_expires_at(true, &tokens), Some(5.0));
}

#[test]
fn returns_none_when_nothing_records_an_expiry() {
    let tokens = json!({ "access_token": "access" });
    assert_eq!(bearer_expires_at(false, &tokens), None);
    assert_eq!(bearer_expires_at(true, &tokens), None);
}
