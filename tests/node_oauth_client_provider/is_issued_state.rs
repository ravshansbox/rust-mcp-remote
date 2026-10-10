use rust_mcp_remote::node_oauth_client_provider::is_issued_state;

#[test]
fn accepts_letters_digits_and_hyphens() {
    assert!(is_issued_state("abc-XYZ-0123456789"));
}

#[test]
fn accepts_a_uuid() {
    assert!(is_issued_state("3f2504e0-4f89-11d3-9a0c-0305e82c3301"));
}

#[test]
fn accepts_one_character() {
    assert!(is_issued_state("a"));
}

#[test]
fn accepts_sixty_four_characters() {
    assert!(is_issued_state(&"a".repeat(64)));
}

#[test]
fn rejects_an_empty_state() {
    assert!(!is_issued_state(""));
}

#[test]
fn rejects_sixty_five_characters() {
    assert!(!is_issued_state(&"a".repeat(65)));
}

#[test]
fn rejects_path_characters() {
    assert!(!is_issued_state("../etc"));
    assert!(!is_issued_state("a/b"));
}

#[test]
fn rejects_underscore_and_trailing_newline() {
    assert!(!is_issued_state("a_b"));
    assert!(!is_issued_state("abc\n"));
}

#[test]
fn rejects_non_ascii_letters() {
    assert!(!is_issued_state("é"));
}
