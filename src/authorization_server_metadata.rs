use std::time::Duration;

use serde_json::{Value, json};
use url::{ParseError, Url};

use crate::logging::debug_log;

const OAUTH_PATH: &str = "/.well-known/oauth-authorization-server";
const OIDC_PATH: &str = "/.well-known/openid-configuration";

pub fn get_metadata_url(server_url: &str) -> Result<String, ParseError> {
    Ok(get_metadata_urls(server_url)?.remove(0))
}

pub fn get_metadata_urls(server_url: &str) -> Result<Vec<String>, ParseError> {
    let url = Url::parse(server_url)?;
    let origin = url.origin().ascii_serialization();
    let pathname = url.path().trim_end_matches('/');

    if pathname.is_empty() {
        return Ok(vec![
            format!("{origin}{OAUTH_PATH}"),
            format!("{origin}{OIDC_PATH}"),
        ]);
    }

    Ok(vec![
        format!("{origin}{OAUTH_PATH}{pathname}"),
        format!("{origin}{OAUTH_PATH}"),
        format!("{origin}{OIDC_PATH}{pathname}"),
        format!("{origin}{pathname}{OIDC_PATH}"),
    ])
}

/// Tries each well-known location in turn and returns the first metadata document found.
pub async fn fetch_authorization_server_metadata(server_url: &str) -> Option<Value> {
    let candidates = get_metadata_urls(server_url).ok()?;

    debug_log(
        "Fetching authorization server metadata",
        &[json!({ "serverUrl": server_url, "candidates": candidates })],
    );

    for metadata_url in &candidates {
        if let Some(metadata) = fetch_metadata_from(metadata_url).await {
            return Some(metadata);
        }
    }

    debug_log(
        "No authorization server metadata found at any candidate URL",
        &[json!({ "serverUrl": server_url, "candidates": candidates })],
    );
    None
}

async fn fetch_metadata_from(metadata_url: &str) -> Option<Value> {
    let response = crate::streamable_http::redirect_following_client()
        .get(metadata_url)
        .header("Accept", "application/json")
        .header("Accept-Encoding", "identity")
        .timeout(Duration::from_secs(5))
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            debug_log(
                "Error fetching authorization server metadata",
                &[json!({ "error": error.to_string(), "metadataUrl": metadata_url })],
            );
            return None;
        }
    };

    let status = response.status();
    if !status.is_success() {
        if status.as_u16() == 404 {
            debug_log(
                "Authorization server metadata endpoint not found (404)",
                &[json!({ "metadataUrl": metadata_url })],
            );
        } else {
            debug_log(
                "Failed to fetch authorization server metadata",
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
            debug_log(
                "Error fetching authorization server metadata",
                &[json!({ "error": error.to_string(), "metadataUrl": metadata_url })],
            );
            return None;
        }
    };

    let scopes_supported = metadata.get("scopes_supported");
    debug_log(
        "Successfully fetched authorization server metadata",
        &[json!({
            "issuer": metadata.get("issuer"),
            "scopes_supported": scopes_supported,
            "scopeCount": scopes_supported.and_then(Value::as_array).map_or(0, Vec::len),
        })],
    );
    Some(metadata)
}
