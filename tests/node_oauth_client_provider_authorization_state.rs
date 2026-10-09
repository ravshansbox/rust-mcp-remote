use rust_mcp_remote::node_oauth_client_provider::{flow_state, use_authorization_state};

#[test]
fn issued_state_is_recorded() {
    let mut incoming_state = None;
    use_authorization_state("abc-123", &mut incoming_state);
    assert_eq!(incoming_state.as_deref(), Some("abc-123"));
}

#[test]
fn state_this_client_could_not_have_issued_is_ignored() {
    let mut incoming_state = Some("previous".to_string());
    use_authorization_state("not/issued", &mut incoming_state);
    assert_eq!(incoming_state.as_deref(), Some("previous"));
}

#[test]
fn empty_state_is_ignored() {
    let mut incoming_state = None;
    use_authorization_state("", &mut incoming_state);
    assert_eq!(incoming_state, None);
}

#[test]
fn flow_state_prefers_the_incoming_state() {
    assert_eq!(flow_state(Some("incoming"), "own"), "incoming");
}

#[test]
fn flow_state_falls_back_to_the_own_state() {
    assert_eq!(flow_state(None, "own"), "own");
}
