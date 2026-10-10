use std::time::Duration;

use serde_json::{Value, json};
use url::{ParseError, Url};

use crate::logging::debug_log;

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

/// `getAuthorizationServerUrl` for metadata held as raw JSON, the way discovery returns it.
pub fn authorization_server_url_of(metadata: &Value) -> Option<&str> {
    metadata
        .get("authorization_servers")?
        .as_array()?
        .first()?
        .as_str()
}

/// JavaScript truthiness, which decides whether a fetched document counts as found.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

async fn fetch_protected_resource_metadata_from_url(metadata_url: &str) -> Option<Value> {
    debug_log(
        "Fetching Protected Resource Metadata",
        &[json!({ "metadataUrl": metadata_url })],
    );

    let report_error = |error: String| {
        debug_log(
            "Error fetching Protected Resource Metadata",
            &[json!({ "error": error, "metadataUrl": metadata_url })],
        );
    };

    let request = crate::streamable_http::redirect_following_client()
        .get(metadata_url)
        .header("Accept", "application/json")
        .header("Accept-Encoding", "identity")
        .timeout(Duration::from_secs(5));
    let response = crate::streamable_http::within_headers_timeout(request.send()).await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            report_error(error.to_string());
            return None;
        }
    };

    let status = response.status();
    if !status.is_success() {
        if status.as_u16() == 404 {
            debug_log(
                "Protected Resource Metadata not found (404)",
                &[json!({ "metadataUrl": metadata_url })],
            );
        } else {
            debug_log(
                "Failed to fetch Protected Resource Metadata",
                &[json!({
                    "status": status.as_u16(),
                    "statusText": status.canonical_reason().unwrap_or_default(),
                })],
            );
        }
        return None;
    }

    let metadata = match response.json::<Value>().await {
        Ok(metadata) => metadata,
        Err(error) => {
            report_error(error.to_string());
            return None;
        }
    };
    // `metadata.resource` on a JSON null throws in TS, which lands in the same catch
    if metadata.is_null() {
        report_error("Cannot read properties of null (reading 'resource')".to_string());
        return None;
    }

    debug_log(
        "Successfully fetched Protected Resource Metadata",
        &[json!({
            "resource": metadata.get("resource"),
            "authorizationServers": metadata.get("authorization_servers"),
            "scopesSupported": metadata.get("scopes_supported"),
        })],
    );
    is_truthy(&metadata).then_some(metadata)
}

/// Finds the RFC 9728 metadata for `resource_url`: the `resource_metadata` URL from a
/// WWW-Authenticate challenge first, then the path-specific and root well-known URLs.
pub async fn discover_protected_resource_metadata(
    resource_url: &str,
    www_authenticate_header: Option<&str>,
) -> Option<Value> {
    debug_log(
        "Starting Protected Resource Metadata discovery",
        &[json!({
            "resourceUrl": resource_url,
            "hasWWWAuthenticateHeader": www_authenticate_header.is_some_and(|h| !h.is_empty()),
        })],
    );

    if let Some(header) = www_authenticate_header.filter(|header| !header.is_empty()) {
        let params = parse_www_authenticate_header(header);
        if let Some(url) = params.resource_metadata_url.filter(|url| !url.is_empty()) {
            debug_log(
                "Using resource_metadata URL from WWW-Authenticate header",
                &[json!({ "url": url })],
            );
            if let Some(metadata) = fetch_protected_resource_metadata_from_url(&url).await {
                return Some(metadata);
            }
            debug_log(
                "Failed to fetch from WWW-Authenticate URL, falling back to well-known discovery",
                &[],
            );
        }
    }

    // An unparseable resource URL makes TS's `new URL` throw; here it is simply nothing found
    let well_known_urls = build_protected_resource_metadata_urls(resource_url).ok()?;
    for url in &well_known_urls {
        if let Some(metadata) = fetch_protected_resource_metadata_from_url(url).await {
            return Some(metadata);
        }
    }

    debug_log(
        "Protected Resource Metadata discovery failed - no metadata found",
        &[],
    );
    None
}
