use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::logging::debug_log;

const URL_SAFE_ANY_PADDING: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

const TOKEN_ENDPOINT_AUTH_METHOD_PREFERENCE: [&str; 3] =
    ["none", "client_secret_post", "client_secret_basic"];

pub fn token_endpoint_auth_method(authorization_server_metadata: Option<&Value>) -> &'static str {
    let Some(supported) = authorization_server_metadata
        .and_then(|metadata| metadata.get("token_endpoint_auth_methods_supported"))
        .and_then(Value::as_array)
        .filter(|supported| !supported.is_empty())
    else {
        return "none";
    };

    let Some(method) = TOKEN_ENDPOINT_AUTH_METHOD_PREFERENCE
        .into_iter()
        .find(|candidate| {
            supported
                .iter()
                .any(|value| value.as_str() == Some(candidate))
        })
    else {
        debug_log(
            "Authorization server advertises no token endpoint auth method this client can perform",
            &[json!({ "token_endpoint_auth_methods_supported": supported })],
        );
        return "none";
    };

    if method != "none" {
        debug_log(
            "Registering with the token endpoint auth method the authorization server advertises",
            &[json!({
                "token_endpoint_auth_method": method,
                "token_endpoint_auth_methods_supported": supported,
            })],
        );
    }
    method
}

pub fn code_challenge_for(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

pub fn jwt_expires_at(token: &str) -> Option<f64> {
    let payload = token
        .split('.')
        .nth(1)
        .filter(|payload| !payload.is_empty())?;
    let bytes = URL_SAFE_ANY_PADDING.decode(payload).ok()?;
    let claims: Value = serde_json::from_str(&String::from_utf8_lossy(&bytes)).ok()?;
    claims.get("exp")?.as_f64().map(|exp| exp * 1000.0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthError {
    pub code: String,
    pub message: String,
}

pub fn stale_client_registration_error(value: &Value) -> Option<OAuthError> {
    let response = value.as_object()?;
    let code = response
        .get("error")
        .and_then(Value::as_str)
        .filter(|code| matches!(*code, "invalid_client" | "unauthorized_client"))?;
    let message = response
        .get("error_description")
        .and_then(Value::as_str)
        .unwrap_or("Cached OAuth client registration is no longer valid");
    Some(OAuthError {
        code: code.to_string(),
        message: message.to_string(),
    })
}

pub fn is_issued_state(state: &str) -> bool {
    (1..=64).contains(&state.len())
        && state
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
