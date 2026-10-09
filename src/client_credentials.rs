use serde_json::Value;

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
