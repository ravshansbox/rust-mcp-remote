use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

const URL_SAFE_ANY_PADDING: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

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
