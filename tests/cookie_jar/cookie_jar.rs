use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rust_mcp_remote::cookie_jar::CookieJar;

#[test]
fn a_cookie_the_server_set_comes_back_on_the_next_request() {
    let mut jar = CookieJar::new();
    jar.capture("https://mcp.example.com/mcp", &["AWSALB=node-1; Path=/"]);

    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("AWSALB=node-1")
    );
}

#[test]
fn several_cookies_are_sent_together() {
    let mut jar = CookieJar::new();
    jar.capture(
        "https://mcp.example.com/mcp",
        &[
            "AWSALB=node-1; Path=/",
            "AWSALBCORS=node-1; Path=/; SameSite=None",
        ],
    );

    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("AWSALB=node-1; AWSALBCORS=node-1")
    );
}

#[test]
fn a_cookie_is_replaced_when_the_server_sets_it_again() {
    let mut jar = CookieJar::new();
    jar.capture(
        "https://mcp.example.com/mcp",
        &["AWSALB=node-1; Path=/", "other=1; Path=/"],
    );
    jar.capture("https://mcp.example.com/mcp", &["AWSALB=node-2; Path=/"]);

    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("AWSALB=node-2; other=1")
    );
}

#[test]
fn nothing_is_sent_to_a_server_that_set_nothing() {
    let mut jar = CookieJar::new();
    assert_eq!(jar.header("https://mcp.example.com/mcp"), None);

    jar.capture("https://mcp.example.com/mcp", &[]);
    assert_eq!(jar.header("https://mcp.example.com/mcp"), None);
}

#[test]
fn a_cookie_stays_with_the_origin_that_set_it() {
    let mut jar = CookieJar::new();
    jar.capture(
        "https://mcp.example.com/mcp",
        &["session=secret; Path=/; Domain=.example.com"],
    );

    assert_eq!(jar.header("https://other.example.com/mcp"), None);
    assert_eq!(jar.header("http://mcp.example.com/mcp"), None);
    assert_eq!(jar.header("https://mcp.example.com:8443/mcp"), None);
    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("session=secret")
    );
}

#[test]
fn a_cookie_scoped_to_a_path_is_sent_below_it_but_not_beside_it() {
    let mut jar = CookieJar::new();
    jar.capture("https://mcp.example.com/", &["stick=1; Path=/mcp"]);

    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("stick=1")
    );
    assert_eq!(
        jar.header("https://mcp.example.com/mcp/messages")
            .as_deref(),
        Some("stick=1")
    );
    assert_eq!(jar.header("https://mcp.example.com/mcp-admin"), None);
    assert_eq!(jar.header("https://mcp.example.com/other"), None);
}

#[test]
fn a_cookie_with_no_path_defaults_to_the_directory_it_came_from() {
    let mut jar = CookieJar::new();
    jar.capture("https://mcp.example.com/app/sse", &["stick=1"]);

    assert_eq!(
        jar.header("https://mcp.example.com/app/messages")
            .as_deref(),
        Some("stick=1")
    );
    assert_eq!(jar.header("https://mcp.example.com/elsewhere"), None);
}

#[test]
fn a_cookie_from_the_root_applies_everywhere_on_that_origin() {
    let mut jar = CookieJar::new();
    jar.capture("https://mcp.example.com/sse", &["stick=1"]);

    assert_eq!(
        jar.header("https://mcp.example.com/messages").as_deref(),
        Some("stick=1")
    );
}

#[test]
fn a_cookie_re_sent_already_expired_is_a_deletion() {
    let mut jar = CookieJar::new();
    jar.capture("https://mcp.example.com/mcp", &["stick=1; Path=/"]);
    jar.capture(
        "https://mcp.example.com/mcp",
        &["stick=1; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"],
    );

    assert_eq!(jar.header("https://mcp.example.com/mcp"), None);
}

#[test]
fn max_age_zero_deletes_too() {
    let mut jar = CookieJar::new();
    jar.capture("https://mcp.example.com/mcp", &["stick=1; Path=/"]);
    jar.capture(
        "https://mcp.example.com/mcp",
        &["stick=1; Path=/; Max-Age=0"],
    );

    assert_eq!(jar.header("https://mcp.example.com/mcp"), None);
}

#[test]
fn max_age_is_preferred_to_expires() {
    let mut jar = CookieJar::new();
    jar.capture(
        "https://mcp.example.com/mcp",
        &["stick=1; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=3600"],
    );

    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("stick=1")
    );
}

#[test]
fn a_cookie_is_dropped_once_its_lifetime_runs_out() {
    let now = Arc::new(Mutex::new(SystemTime::now()));
    let clock = Arc::clone(&now);
    let mut jar = CookieJar::with_clock(move || *clock.lock().unwrap());
    jar.capture(
        "https://mcp.example.com/mcp",
        &["stick=1; Path=/; Max-Age=60"],
    );
    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("stick=1")
    );

    *now.lock().unwrap() += Duration::from_secs(61);
    assert_eq!(jar.header("https://mcp.example.com/mcp"), None);
}

#[test]
fn a_cookie_with_no_expiry_lasts_as_long_as_the_process() {
    let mut jar = CookieJar::new();
    jar.capture(
        "https://mcp.example.com/mcp",
        &["stick=1; Path=/; HttpOnly; Secure; SameSite=Lax"],
    );

    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("stick=1")
    );
}

#[test]
fn a_set_cookie_that_is_malformed_is_ignored() {
    for header in ["AWSALB", "=node-1; Path=/", ""] {
        let mut jar = CookieJar::new();
        jar.capture("https://mcp.example.com/mcp", &[header]);

        assert_eq!(
            jar.header("https://mcp.example.com/mcp"),
            None,
            "{header:?}"
        );
    }
}

#[test]
fn an_unreadable_expiry_leaves_the_cookie_alone_rather_than_dropping_it() {
    let mut jar = CookieJar::new();
    jar.capture(
        "https://mcp.example.com/mcp",
        &["stick=1; Path=/; Expires=not-a-date; Max-Age=nonsense"],
    );

    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("stick=1")
    );
}

#[test]
fn a_value_containing_an_equals_sign_survives_intact() {
    let mut jar = CookieJar::new();
    jar.capture("https://mcp.example.com/mcp", &["AWSALB=aGVsbG8=; Path=/"]);

    assert_eq!(
        jar.header("https://mcp.example.com/mcp").as_deref(),
        Some("AWSALB=aGVsbG8=")
    );
}
