use std::sync::Arc;

use rust_mcp_remote::utils::{capture_cookies, cookie_header_for, set_cookies_enabled};

use crate::GLOBAL_STATE;
use crate::test_server::{reply, serve};

/// Serves one reply that sets `set_cookie` and returns its URL along with the response.
async fn response_setting(set_cookie: &'static str) -> (String, reqwest::Response) {
    let (url, _requests) = serve(Arc::new(move |_| {
        reply(200, &[("set-cookie", set_cookie)], "{}")
    }))
    .await;
    let response = reqwest::get(&url).await.unwrap();
    (url, response)
}

#[test]
fn the_flag_gates_both_capturing_and_reading_the_jar() {
    let _guard = GLOBAL_STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let runtime = tokio::runtime::Runtime::new().expect("runtime");

    set_cookies_enabled(false);
    let (ignored_url, response) = runtime.block_on(response_setting("ignored=1; Path=/"));
    capture_cookies(&ignored_url, &response);
    set_cookies_enabled(true);
    assert_eq!(cookie_header_for(&ignored_url), None);

    let (url, response) = runtime.block_on(response_setting("session=abc; Path=/"));
    capture_cookies(&url, &response);
    assert_eq!(cookie_header_for(&url).as_deref(), Some("session=abc"));

    set_cookies_enabled(false);
    let hidden = cookie_header_for(&url);
    set_cookies_enabled(true);
    assert_eq!(hidden, None);
    assert_eq!(cookie_header_for(&url).as_deref(), Some("session=abc"));
}
