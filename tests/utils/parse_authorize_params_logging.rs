use crate::{arguments, console_text};
use rust_mcp_remote::utils::parse_authorize_params_to;

#[test]
fn warns_that_a_resource_param_only_reaches_the_authorization_request() {
    let mut console = Vec::new();

    let result = parse_authorize_params_to(
        &mut console,
        &arguments(&["--authorize-param", "resource=https://api.example.com"]),
    )
    .expect("params");

    assert_eq!(
        result.get("resource").map(String::as_str),
        Some("https://api.example.com")
    );
    assert_eq!(
        console_text(console),
        format!(
            "[{}] Warning: --authorize-param resource=... only applies to the authorization request. Use --resource so the token request agrees.\n",
            std::process::id()
        )
    );
}

#[test]
fn writes_nothing_for_other_params() {
    let mut console = Vec::new();

    parse_authorize_params_to(
        &mut console,
        &arguments(&["--authorize-param", "audience=https://api.example.com"]),
    )
    .expect("params");

    assert!(console.is_empty());
}
