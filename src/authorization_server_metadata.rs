use url::{ParseError, Url};

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
