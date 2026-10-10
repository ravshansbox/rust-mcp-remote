use serde_json::Value;

use crate::auth::parse_tokens;
use crate::device_authorization::{
    FormRequest, apply_client_authentication, form_headers, post_form, select_client_auth_method,
};
use crate::logging::{debug_log, log, log_to};

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

pub fn token_request_failure_message(status: u16, body: Option<&Value>) -> String {
    let field = |name: &str| body.and_then(|body| body.get(name)).and_then(Value::as_str);
    let detail: String = field("error_description")
        .or_else(|| field("error"))
        .unwrap_or("unknown error")
        .chars()
        .take(500)
        .collect();
    format!("The client_credentials token request failed (HTTP {status}): {detail}")
}

pub fn client_credentials_request_debug_details(
    token_endpoint: &str,
    auth_method: &str,
    scope: Option<&str>,
    resource: Option<&str>,
) -> Value {
    let mut details = serde_json::Map::new();
    details.insert("tokenEndpoint".to_string(), Value::from(token_endpoint));
    details.insert("authMethod".to_string(), Value::from(auth_method));
    if let Some(scope) = scope {
        details.insert("scope".to_string(), Value::from(scope));
    }
    if let Some(resource) = resource {
        details.insert("resource".to_string(), Value::from(resource));
    }
    Value::Object(details)
}

/// Signs in as the software itself with the client_credentials grant.
pub async fn authorize_with_client_credentials(
    metadata: &Value,
    client_information: &Value,
    scope: Option<&str>,
    resource: Option<&url::Url>,
) -> Result<Value, String> {
    let token_endpoint = check_token_endpoint_to(&mut std::io::stderr(), metadata)?;
    let supported_methods: Vec<&str> = metadata
        .get("token_endpoint_auth_methods_supported")
        .and_then(Value::as_array)
        .map(|methods| methods.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let auth_method = select_client_auth_method(client_information, &supported_methods);
    let resource = resource.map(url::Url::as_str);
    let request = build_client_credentials_request(
        auth_method,
        client_information
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        client_information
            .get("client_secret")
            .and_then(Value::as_str),
        scope,
        resource,
    )?;

    debug_log(
        "Requesting a token with the client_credentials grant",
        &[client_credentials_request_debug_details(
            &token_endpoint,
            auth_method,
            scope,
            resource,
        )],
    );

    let response = post_form(&token_endpoint, &request).await?;
    let body = serde_json::from_str::<Value>(&response.body).ok();
    if !(200..300).contains(&response.status) {
        return Err(token_request_failure_message(
            response.status,
            body.as_ref(),
        ));
    }

    let tokens = parse_tokens(&body.unwrap_or(Value::Null)).map_err(|error| error.to_string())?;
    log("Signed in with the client_credentials grant", &[]);
    Ok(tokens)
}
