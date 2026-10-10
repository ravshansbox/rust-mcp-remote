use rust_mcp_remote::node_oauth_client_provider::{code_verifier_file, owns_pending_flow};
use url::Url;

#[test]
fn code_verifier_file_is_named_after_the_state() {
    assert_eq!(code_verifier_file("abc123"), "code_verifier_abc123.txt");
}

#[test]
fn any_flow_is_owned_when_none_is_pending() {
    let authorization_url =
        Url::parse("https://auth.example.com/authorize?code_challenge=xyz").unwrap();
    assert!(owns_pending_flow(&authorization_url, None));
}

#[test]
fn flow_with_the_pending_challenge_is_owned() {
    let authorization_url =
        Url::parse("https://auth.example.com/authorize?code_challenge=xyz&code_challenge=other")
            .unwrap();
    assert!(owns_pending_flow(&authorization_url, Some("xyz")));
}

#[test]
fn flow_with_another_challenge_is_not_owned() {
    let authorization_url =
        Url::parse("https://auth.example.com/authorize?code_challenge=other").unwrap();
    assert!(!owns_pending_flow(&authorization_url, Some("xyz")));
}

#[test]
fn flow_without_a_challenge_is_not_owned_when_one_is_pending() {
    let authorization_url = Url::parse("https://auth.example.com/authorize").unwrap();
    assert!(!owns_pending_flow(&authorization_url, Some("xyz")));
}
