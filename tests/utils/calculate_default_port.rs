use rust_mcp_remote::utils::calculate_default_port;

#[test]
fn port_comes_from_the_first_four_hex_digits() {
    assert_eq!(calculate_default_port("0000abcdef"), Some(3335));
    assert_eq!(calculate_default_port("00ff"), Some(3335 + 255));
    assert_eq!(
        calculate_default_port("1234567890abcdef"),
        Some(3335 + 0x1234)
    );
}

#[test]
fn port_wraps_to_stay_below_49152() {
    assert_eq!(calculate_default_port("b2f8"), Some(3335));
    assert_eq!(
        calculate_default_port("ffff"),
        Some(3335 + (0xffff % 45816))
    );
    assert_eq!(calculate_default_port("b2f7"), Some(49150));
}

#[test]
fn hex_digits_are_case_insensitive() {
    assert_eq!(
        calculate_default_port("ABCD"),
        calculate_default_port("abcd")
    );
}

#[test]
fn parsing_stops_at_the_first_non_hex_character() {
    assert_eq!(calculate_default_port("1g23"), Some(3335 + 1));
    assert_eq!(calculate_default_port("ab"), Some(3335 + 0xab));
}

#[test]
fn a_hash_without_leading_hex_digits_has_no_port() {
    assert_eq!(calculate_default_port(""), None);
    assert_eq!(calculate_default_port("zzzz"), None);
}
