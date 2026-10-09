use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const BASE64_SENTINEL_PREFIX: &str = "=?base64?";
const BASE64_SENTINEL_SUFFIX: &str = "?=";

pub fn encode_mcp_header_value(value: &str) -> String {
    let visible = |byte: &u8| (0x21..=0x7e).contains(byte);
    let bytes = value.as_bytes();
    let header_safe = bytes.first().is_some_and(visible)
        && bytes.last().is_some_and(visible)
        && bytes
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte) || *byte == b'\t');
    let looks_encoded =
        value.starts_with(BASE64_SENTINEL_PREFIX) && value.ends_with(BASE64_SENTINEL_SUFFIX);

    if header_safe && !looks_encoded {
        value.to_string()
    } else {
        format!(
            "{BASE64_SENTINEL_PREFIX}{}{BASE64_SENTINEL_SUFFIX}",
            STANDARD.encode(value)
        )
    }
}
