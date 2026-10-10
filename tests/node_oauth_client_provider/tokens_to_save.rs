use rust_mcp_remote::node_oauth_client_provider::tokens_to_save;
use serde_json::json;

const NOW: f64 = 1_000_000.0;

#[test]
fn a_new_token_gets_an_absolute_expiry_from_expires_in() {
    let tokens = json!({ "access_token": "a", "token_type": "Bearer", "expires_in": 60 });

    assert_eq!(
        tokens_to_save(&tokens, "read", NOW),
        json!({ "access_token": "a", "token_type": "Bearer", "expires_in": 60, "expires_at": 1_060_000.0, "requested_scope": "read" })
    );
}

#[test]
fn a_stored_expiry_is_kept_rather_than_restarted() {
    let tokens = json!({ "access_token": "a", "expires_in": 60, "expires_at": 5 });

    assert_eq!(tokens_to_save(&tokens, "read", NOW)["expires_at"], json!(5));
}

#[test]
fn a_null_stored_expiry_is_recomputed_from_expires_in() {
    let tokens = json!({ "access_token": "a", "expires_in": 60, "expires_at": null });

    assert_eq!(
        tokens_to_save(&tokens, "read", NOW)["expires_at"],
        json!(1_060_000.0)
    );
}

#[test]
fn a_token_without_a_usable_expires_in_is_saved_without_an_expiry() {
    for expires_in in [json!(0), json!(null)] {
        let tokens = json!({ "access_token": "a", "expires_in": expires_in });

        let saved = tokens_to_save(&tokens, "read", NOW);

        assert!(saved.get("expires_at").is_none(), "{expires_in}");
    }
}

#[test]
fn the_requested_scope_replaces_any_stored_one() {
    let tokens = json!({ "access_token": "a", "requested_scope": "old" });

    assert_eq!(
        tokens_to_save(&tokens, "new", NOW)["requested_scope"],
        json!("new")
    );
}
