use url::{ParseError, Url};

const PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";

pub fn build_protected_resource_metadata_urls(
    resource_url: &str,
) -> Result<Vec<String>, ParseError> {
    let url = Url::parse(resource_url)?;
    let origin = url.origin().ascii_serialization();
    let path = url.path().strip_suffix('/').unwrap_or(url.path());

    let mut urls = Vec::new();
    if !path.is_empty() && path != "/" {
        urls.push(format!("{origin}{PROTECTED_RESOURCE_PATH}{path}"));
    }
    urls.push(format!("{origin}{PROTECTED_RESOURCE_PATH}"));
    Ok(urls)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WwwAuthenticateParams {
    pub resource_metadata_url: Option<String>,
    pub scope: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub fn parse_www_authenticate_header(header: &str) -> WwwAuthenticateParams {
    let mut result = WwwAuthenticateParams::default();
    let param_string = strip_bearer_prefix(header);
    let bytes = param_string.as_bytes();

    let mut position = 0;
    while position < bytes.len() {
        match match_param(param_string, position) {
            Some((key, value, end)) => {
                let field = match key {
                    "resource_metadata" => Some(&mut result.resource_metadata_url),
                    "scope" => Some(&mut result.scope),
                    "error" => Some(&mut result.error),
                    "error_description" => Some(&mut result.error_description),
                    _ => None,
                };
                if let Some(field) = field {
                    *field = Some(value.to_string());
                }
                position = end;
            }
            None => position += 1,
        }
    }
    result
}

fn strip_bearer_prefix(header: &str) -> &str {
    let Some(prefix) = header.get(..6) else {
        return header;
    };
    if !prefix.eq_ignore_ascii_case("Bearer") {
        return header;
    }
    let rest = &header[6..];
    let trimmed = rest.trim_start();
    if trimmed.len() == rest.len() {
        header
    } else {
        trimmed
    }
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn match_param(text: &str, start: usize) -> Option<(&str, &str, usize)> {
    let bytes = text.as_bytes();
    let key_end = start
        + bytes[start..]
            .iter()
            .take_while(|&&byte| is_word_byte(byte))
            .count();
    if key_end == start || bytes.get(key_end) != Some(&b'=') {
        return None;
    }
    let key = &text[start..key_end];
    let value_start = key_end + 1;

    if bytes.get(value_start) == Some(&b'"')
        && let Some(length) = bytes[value_start + 1..]
            .iter()
            .position(|&byte| byte == b'"')
    {
        let value_end = value_start + 1 + length;
        return Some((key, &text[value_start + 1..value_end], value_end + 1));
    }

    let value_end = value_start
        + bytes[value_start..]
            .iter()
            .take_while(|&&byte| is_word_byte(byte) || byte == b'-')
            .count();
    if value_end == value_start {
        return None;
    }
    Some((key, &text[value_start..value_end], value_end))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Option<Vec<String>>,
    pub scopes_supported: Option<Vec<String>>,
    pub bearer_methods_supported: Option<Vec<String>>,
    pub resource_signing_alg_values_supported: Option<Vec<String>>,
    pub resource_documentation: Option<String>,
    pub resource_name: Option<String>,
}

pub fn get_authorization_server_url(metadata: &ProtectedResourceMetadata) -> Option<&str> {
    metadata
        .authorization_servers
        .as_ref()?
        .first()
        .map(String::as_str)
}
