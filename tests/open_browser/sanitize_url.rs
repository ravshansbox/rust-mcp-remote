use rust_mcp_remote::open_browser::{encode_uri_component, sanitize_url};

#[test]
fn encode_uri_component_keeps_only_the_unreserved_marks() {
    assert_eq!(encode_uri_component("a-_.!~*'()z"), "a-_.!~*'()z");
    assert_eq!(encode_uri_component("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
}

#[test]
fn an_ordinary_authorization_url_keeps_its_meaning() {
    assert_eq!(
        sanitize_url(
            "https://auth.example.com/oauth/authorize?response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A3334%2Foauth%2Fcallback&scope=openid+email"
        ),
        Ok("https://auth.example.com/oauth/authorize?response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A3334%2Foauth%2Fcallback&scope=openid%20email".to_owned())
    );
}

#[test]
fn refuses_schemes_other_than_http_and_https() {
    assert_eq!(
        sanitize_url("file:///etc/passwd"),
        Err("Invalid url to pass to open(): file:///etc/passwd".to_owned())
    );
    assert!(sanitize_url("javascript:alert(1)").is_err());
    assert!(sanitize_url("not a url").is_err());
}

#[test]
fn refuses_a_hostname_that_would_need_encoding() {
    assert!(sanitize_url("http://[::1]:8080/").is_err());
}

#[test]
fn re_encodes_the_path_query_and_fragment() {
    assert_eq!(
        sanitize_url("https://example.com/a b/c$d?flag&x=$(id)#frag ment"),
        Ok("https://example.com/a%2520b/c%24d?flag&x=%24(id)#frag%2520ment".to_owned())
    );
}

#[test]
fn drops_an_empty_query_and_fragment() {
    assert_eq!(
        sanitize_url("https://example.com/?#"),
        Ok("https://example.com/".to_owned())
    );
}

#[test]
fn encodes_the_userinfo_again() {
    assert_eq!(
        sanitize_url("https://us%20er:p@ss@example.com/"),
        Ok("https://us%2520er:p%2540ss@example.com/".to_owned())
    );
}
