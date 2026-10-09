use rust_mcp_remote::node_oauth_client_provider::code_challenge_for;

#[test]
fn matches_the_rfc_7636_example() {
    assert_eq!(
        code_challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn hashes_an_empty_verifier_without_padding() {
    assert_eq!(
        code_challenge_for(""),
        "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
    );
}
