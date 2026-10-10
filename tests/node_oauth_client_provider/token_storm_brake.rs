use rust_mcp_remote::node_oauth_client_provider::TokenStormBrake;

#[test]
fn twenty_token_writes_inside_thirty_seconds_are_allowed() {
    let mut brake = TokenStormBrake::default();
    for write in 0..20 {
        assert!(
            brake
                .guard_against_token_storm(1_000.0 + write as f64)
                .is_ok()
        );
    }
}

#[test]
fn the_twenty_first_token_write_inside_thirty_seconds_is_stopped() {
    let mut brake = TokenStormBrake::default();
    for write in 0..20 {
        brake
            .guard_against_token_storm(1_000.0 + write as f64)
            .unwrap();
    }
    let error = brake.guard_against_token_storm(2_000.0).unwrap_err();
    assert_eq!(
        error,
        "Stopped after 20 token exchanges in 30s. The tokens being issued are not accepted by the MCP server - check that its audience and scopes match, or sign in again."
    );
}

#[test]
fn token_writes_older_than_thirty_seconds_no_longer_count() {
    let mut brake = TokenStormBrake::default();
    for write in 0..20 {
        brake
            .guard_against_token_storm(1_000.0 + write as f64)
            .unwrap();
    }
    assert!(brake.guard_against_token_storm(31_000.0).is_ok());
    assert!(brake.guard_against_token_storm(31_001.0).is_ok());
}

#[test]
fn a_stopped_write_is_not_recorded() {
    let mut brake = TokenStormBrake::default();
    for _ in 0..20 {
        brake.guard_against_token_storm(1_000.0).unwrap();
    }
    assert!(brake.guard_against_token_storm(2_000.0).is_err());
    assert!(brake.in_token_storm(30_999.0));
    assert!(!brake.in_token_storm(31_000.0));
}
