use rust_mcp_remote::node_oauth_client_provider::AuthorizationStormBrake;

#[test]
fn five_sign_ins_inside_thirty_seconds_are_allowed() {
    let mut brake = AuthorizationStormBrake::default();
    for start in 0..5 {
        assert!(
            brake
                .guard_against_authorization_storm(1_000.0 + start as f64)
                .is_ok()
        );
    }
}

#[test]
fn the_sixth_sign_in_inside_thirty_seconds_is_stopped() {
    let mut brake = AuthorizationStormBrake::default();
    for start in 0..5 {
        brake
            .guard_against_authorization_storm(1_000.0 + start as f64)
            .unwrap();
    }
    let error = brake
        .guard_against_authorization_storm(2_000.0)
        .unwrap_err();
    assert_eq!(
        error,
        "Stopped after 5 sign-ins in 30s, none of which completed. Opening another browser tab would only repeat it - check that the server accepts the tokens this client is being issued."
    );
}

#[test]
fn sign_ins_older_than_thirty_seconds_no_longer_count() {
    let mut brake = AuthorizationStormBrake::default();
    for start in 0..5 {
        brake
            .guard_against_authorization_storm(1_000.0 + start as f64)
            .unwrap();
    }
    assert!(brake.guard_against_authorization_storm(31_000.0).is_ok());
    assert!(brake.guard_against_authorization_storm(31_001.0).is_ok());
}

#[test]
fn a_stopped_sign_in_is_not_recorded() {
    let mut brake = AuthorizationStormBrake::default();
    for _ in 0..5 {
        brake.guard_against_authorization_storm(1_000.0).unwrap();
    }
    assert!(brake.guard_against_authorization_storm(2_000.0).is_err());
    for _ in 0..5 {
        assert!(brake.guard_against_authorization_storm(31_000.0).is_ok());
    }
}
