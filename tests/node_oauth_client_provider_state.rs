use rust_mcp_remote::node_oauth_client_provider::{
    CONCURRENT_FLOW_WINDOW_MS, NodeOAuthClientProvider, OAuthProviderOptions,
};

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
fn first_call_starts_a_new_flow_with_a_fresh_state() {
    let mut provider = provider();
    let initial = provider.state.clone();
    let state = provider.next_state(1_000.0);
    assert_ne!(state, initial);
    assert_eq!(provider.state, state);
    let pending = provider.pending_flow.as_ref().unwrap();
    assert_eq!(pending.state, state);
    assert_eq!(pending.started_at, 1_000.0);
    assert_eq!(pending.challenge, None);
}

#[test]
fn starting_a_flow_drops_the_incoming_state() {
    let mut provider = provider();
    provider.incoming_state = Some("earlier".to_string());
    provider.next_state(1_000.0);
    assert_eq!(provider.incoming_state, None);
}

#[test]
fn concurrent_calls_join_the_flow_being_started() {
    let mut provider = provider();
    let first = provider.next_state(1_000.0);
    provider.incoming_state = Some("kept".to_string());
    let second = provider.next_state(1_000.0 + CONCURRENT_FLOW_WINDOW_MS - 1.0);
    assert_eq!(second, first);
    assert_eq!(provider.incoming_state.as_deref(), Some("kept"));
    assert_eq!(provider.pending_flow.as_ref().unwrap().started_at, 1_000.0);
}

#[test]
fn calls_after_the_window_start_a_new_flow() {
    let mut provider = provider();
    let first = provider.next_state(1_000.0);
    let second = provider.next_state(1_000.0 + CONCURRENT_FLOW_WINDOW_MS);
    assert_ne!(second, first);
    assert_eq!(
        provider.pending_flow.as_ref().unwrap().started_at,
        1_000.0 + CONCURRENT_FLOW_WINDOW_MS
    );
}
