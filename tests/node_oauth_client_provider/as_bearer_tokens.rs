use rust_mcp_remote::node_oauth_client_provider::as_bearer_tokens;
use serde_json::json;

#[test]
fn no_tokens_stay_none() {
    let mut warned_about_missing_id_token = false;
    assert_eq!(
        as_bearer_tokens(true, &mut warned_about_missing_id_token, None),
        None
    );
}

#[test]
fn tokens_are_unchanged_without_use_id_token() {
    let mut warned_about_missing_id_token = false;
    let tokens = json!({ "access_token": "access", "id_token": "id", "refresh_token": "refresh" });
    assert_eq!(
        as_bearer_tokens(
            false,
            &mut warned_about_missing_id_token,
            Some(tokens.clone())
        ),
        Some(tokens)
    );
    assert!(!warned_about_missing_id_token);
}

#[test]
fn the_id_token_is_presented_as_the_access_token() {
    let mut warned_about_missing_id_token = false;
    let tokens = json!({ "access_token": "access", "id_token": "id", "refresh_token": "refresh" });
    assert_eq!(
        as_bearer_tokens(true, &mut warned_about_missing_id_token, Some(tokens)),
        Some(json!({ "access_token": "id", "id_token": "id", "refresh_token": "refresh" }))
    );
    assert!(!warned_about_missing_id_token);
}

#[test]
fn a_missing_id_token_leaves_the_access_token_and_warns() {
    let mut warned_about_missing_id_token = false;
    let tokens = json!({ "access_token": "access", "refresh_token": "refresh" });
    assert_eq!(
        as_bearer_tokens(
            true,
            &mut warned_about_missing_id_token,
            Some(tokens.clone())
        ),
        Some(tokens)
    );
    assert!(warned_about_missing_id_token);
}

#[test]
fn an_empty_id_token_counts_as_missing() {
    let mut warned_about_missing_id_token = false;
    let tokens = json!({ "access_token": "access", "id_token": "" });
    assert_eq!(
        as_bearer_tokens(
            true,
            &mut warned_about_missing_id_token,
            Some(tokens.clone())
        ),
        Some(tokens)
    );
    assert!(warned_about_missing_id_token);
}
