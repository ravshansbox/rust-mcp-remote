use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rust_mcp_remote::node_oauth_client_provider::jwt_expires_at;

fn jwt_with_payload(payload: &str) -> String {
    format!(
        "{}.{}.signature",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(payload)
    )
}

#[test]
fn reads_the_exp_claim_as_milliseconds() {
    let token = jwt_with_payload(r#"{"sub":"user","exp":1700000000}"#);
    assert_eq!(jwt_expires_at(&token), Some(1_700_000_000_000.0));
}

#[test]
fn keeps_a_fractional_exp_claim() {
    let token = jwt_with_payload(r#"{"exp":1.5}"#);
    assert_eq!(jwt_expires_at(&token), Some(1500.0));
}

#[test]
fn returns_none_without_a_payload_segment() {
    assert_eq!(jwt_expires_at("opaque-access-token"), None);
    assert_eq!(jwt_expires_at("header."), None);
}

#[test]
fn returns_none_when_exp_is_not_a_number() {
    assert_eq!(
        jwt_expires_at(&jwt_with_payload(r#"{"exp":"1700000000"}"#)),
        None
    );
    assert_eq!(jwt_expires_at(&jwt_with_payload(r#"{"sub":"user"}"#)), None);
}

#[test]
fn returns_none_when_the_payload_is_not_json() {
    assert_eq!(jwt_expires_at(&jwt_with_payload("not json")), None);
    assert_eq!(jwt_expires_at("header.!!!.signature"), None);
}

#[test]
fn accepts_a_padded_payload() {
    let padded = base64::engine::general_purpose::URL_SAFE.encode(r#"{"exp":12}"#);
    assert_eq!(
        jwt_expires_at(&format!("header.{padded}.sig")),
        Some(12000.0)
    );
}
