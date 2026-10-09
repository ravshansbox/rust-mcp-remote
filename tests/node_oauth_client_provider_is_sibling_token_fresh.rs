use rust_mcp_remote::node_oauth_client_provider::is_sibling_token_fresh;

#[test]
fn a_token_well_before_its_expiry_is_fresh() {
    assert!(is_sibling_token_fresh(Some(1_000_000.0), 900_000.0));
}

#[test]
fn a_token_within_sixty_seconds_of_its_expiry_is_not_fresh() {
    assert!(!is_sibling_token_fresh(Some(1_000_000.0), 940_000.0));
    assert!(is_sibling_token_fresh(Some(1_000_000.0), 939_999.0));
}

#[test]
fn a_token_without_an_expiry_is_not_fresh() {
    assert!(!is_sibling_token_fresh(None, 0.0));
}

#[test]
fn a_zero_or_nan_expiry_is_not_fresh() {
    assert!(!is_sibling_token_fresh(Some(0.0), 0.0));
    assert!(!is_sibling_token_fresh(Some(f64::NAN), 0.0));
}
