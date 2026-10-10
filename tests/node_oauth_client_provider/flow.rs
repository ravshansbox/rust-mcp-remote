use rust_mcp_remote::node_oauth_client_provider::{
    NodeOAuthClientProvider, OAuthProviderOptions, PendingFlow,
};
use url::Url;

fn provider() -> NodeOAuthClientProvider {
    NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://auth.example.com".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: "abc123".to_string(),
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn flow_state_is_the_own_state_without_an_incoming_state() {
    let provider = provider();
    assert_eq!(provider.flow_state(), provider.state);
}

#[test]
fn an_issued_incoming_state_becomes_the_flow_state() {
    let mut provider = provider();
    provider.use_authorization_state("other-flow-1");
    assert_eq!(provider.incoming_state.as_deref(), Some("other-flow-1"));
    assert_eq!(provider.flow_state(), "other-flow-1");
}

#[test]
fn a_state_this_client_could_not_have_issued_is_ignored() {
    let mut provider = provider();
    provider.use_authorization_state("not/issued");
    assert_eq!(provider.incoming_state, None);
    assert_eq!(provider.flow_state(), provider.state);
}

#[test]
fn any_redirect_is_owned_without_a_pending_challenge() {
    let provider = provider();
    let url = Url::parse("https://auth.example.com/authorize?code_challenge=abc").unwrap();
    assert!(provider.owns_pending_flow(&url));
}

#[test]
fn only_the_redirect_with_the_pending_challenge_is_owned() {
    let mut provider = provider();
    provider.pending_flow = Some(PendingFlow {
        state: "flow".to_string(),
        started_at: 0.0,
        challenge: Some("kept".to_string()),
    });
    let kept = Url::parse("https://auth.example.com/authorize?code_challenge=kept").unwrap();
    let other = Url::parse("https://auth.example.com/authorize?code_challenge=other").unwrap();
    assert!(provider.owns_pending_flow(&kept));
    assert!(!provider.owns_pending_flow(&other));
}
