use rust_mcp_remote::utils::{DEFAULT_CALLBACK_PATH, build_redirect_url};

#[test]
fn default_callback_path_is_oauth_callback() {
    assert_eq!(DEFAULT_CALLBACK_PATH, "/oauth/callback");
    assert_eq!(
        build_redirect_url("localhost", 8080, DEFAULT_CALLBACK_PATH),
        "http://localhost:8080/oauth/callback"
    );
}

#[test]
fn custom_callback_path_is_appended_as_is() {
    assert_eq!(
        build_redirect_url("127.0.0.1", 3335, "/custom/cb"),
        "http://127.0.0.1:3335/custom/cb"
    );
    assert_eq!(
        build_redirect_url("localhost", 1, "cb"),
        "http://localhost:1cb"
    );
    assert_eq!(build_redirect_url("localhost", 0, ""), "http://localhost:0");
}

#[test]
fn host_is_not_bracketed_or_escaped() {
    assert_eq!(build_redirect_url("::1", 65535, "/x"), "http://::1:65535/x");
}
