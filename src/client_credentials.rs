use serde_json::Value;

use crate::device_authorization::{FormRequest, apply_client_authentication, form_headers};
use crate::logging::log_to;

pub fn check_token_endpoint_to(
    console: &mut impl std::io::Write,
    metadata: &Value,
) -> Result<String, String> {
    let Some(token_endpoint) = metadata.get("token_endpoint").and_then(Value::as_str) else {
        return Err("The authorization server metadata has no token endpoint".to_string());
    };
    let endpoint = url::Url::parse(token_endpoint).map_err(|_| "Invalid URL".to_string())?;
    let origin = endpoint.origin().ascii_serialization();
    if endpoint.scheme() != "https"
        && !matches!(endpoint.host_str(), Some("localhost" | "127.0.0.1"))
    {
        return Err(format!(
            "Refusing to send the client secret to {origin} over {}. The client_credentials grant needs an https token endpoint.",
            endpoint.scheme()
        ));
    }
    log_to(
        console,
        &format!("Requesting a token from {origin} with the client_credentials grant"),
        &[],
    );
    Ok(token_endpoint.to_string())
}

pub fn build_client_credentials_request(
    auth_method: &str,
    client_id: &str,
    client_secret: Option<&str>,
    scope: Option<&str>,
    resource: Option<&str>,
) -> Result<FormRequest, String> {
    if client_secret.is_none_or(str::is_empty) {
        return Err("The client_credentials grant needs a client secret. Supply one with --static-oauth-client-info, which accepts `@path/to/file.json` and `${ENV_VAR}` placeholders so the secret need not sit in the command line.".to_string());
    }
    let mut headers = form_headers();
    let mut params = vec![("grant_type".to_string(), "client_credentials".to_string())];
    apply_client_authentication(
        auth_method,
        client_id,
        client_secret,
        &mut headers,
        &mut params,
    )?;
    if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
        params.push(("scope".to_string(), scope.to_string()));
    }
    if let Some(resource) = resource {
        params.push(("resource".to_string(), resource.to_string()));
    }
    Ok(FormRequest { headers, params })
}
