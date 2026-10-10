use rust_mcp_remote::node_oauth_client_provider::is_token_expired;

#[test]
fn a_token_well_before_its_expiry_is_not_expired() {
    assert!(!is_token_expired(Some(1_000_000.0), 900_000.0));
}

#[test]
fn a_token_within_sixty_seconds_of_its_expiry_is_expired() {
    assert!(is_token_expired(Some(1_000_000.0), 940_000.0));
    assert!(!is_token_expired(Some(1_000_000.0), 939_999.0));
}

#[test]
fn a_token_past_its_expiry_is_expired() {
    assert!(is_token_expired(Some(1_000_000.0), 2_000_000.0));
}

#[test]
fn a_token_without_an_expiry_is_not_expired() {
    assert!(!is_token_expired(None, 2_000_000.0));
}

#[test]
fn a_zero_or_nan_expiry_counts_as_missing() {
    assert!(!is_token_expired(Some(0.0), 2_000_000.0));
    assert!(!is_token_expired(Some(f64::NAN), 2_000_000.0));
}
