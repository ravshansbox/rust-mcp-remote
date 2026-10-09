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
