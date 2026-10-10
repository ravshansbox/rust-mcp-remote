use rust_mcp_remote::protocol_era::{
    can_fulfil_input_request, client_declared_capability_for, is_dropped_in_modern_era,
    is_input_required_result, is_modern_only_notification, local_answer_for,
};
use serde_json::json;

#[test]
fn methods_retired_in_the_modern_era_are_answered_locally_with_an_empty_result() {
    for method in [
        "ping",
        "resources/subscribe",
        "resources/unsubscribe",
        "logging/setLevel",
    ] {
        assert_eq!(local_answer_for(method), Some(json!({})), "{method}");
    }
}

#[test]
fn other_methods_are_not_answered_locally() {
    for method in ["tools/list", "toString", "__proto__", ""] {
        assert_eq!(local_answer_for(method), None, "{method}");
    }
}

#[test]
fn handshake_and_roots_change_notifications_are_dropped() {
    assert!(is_dropped_in_modern_era("notifications/initialized"));
    assert!(is_dropped_in_modern_era("notifications/roots/list_changed"));
    assert!(!is_dropped_in_modern_era("notifications/cancelled"));
}

#[test]
fn only_the_subscription_acknowledgement_is_modern_only() {
    assert!(is_modern_only_notification(
        "notifications/subscriptions/acknowledged"
    ));
    assert!(!is_modern_only_notification(
        "notifications/resources/updated"
    ));
}

#[test]
fn a_result_is_input_required_only_when_tagged_so() {
    assert!(is_input_required_result(
        &json!({ "resultType": "input_required" })
    ));
    assert!(!is_input_required_result(
        &json!({ "resultType": "complete" })
    ));
    assert!(!is_input_required_result(&json!({})));
    assert!(!is_input_required_result(&json!(null)));
    assert!(!is_input_required_result(&json!("input_required")));
}

#[test]
fn sampling_roots_and_form_elicitation_can_be_fulfilled() {
    assert!(can_fulfil_input_request("sampling/createMessage", None));
    assert!(can_fulfil_input_request("roots/list", None));
    assert!(can_fulfil_input_request("elicitation/create", None));
    assert!(can_fulfil_input_request(
        "elicitation/create",
        Some(&json!({ "mode": "form" }))
    ));
}

#[test]
fn url_elicitation_and_unknown_methods_cannot_be_fulfilled() {
    assert!(!can_fulfil_input_request(
        "elicitation/create",
        Some(&json!({ "mode": "url" }))
    ));
    assert!(!can_fulfil_input_request("tools/call", None));
}

#[test]
fn a_question_needs_the_matching_declared_capability() {
    let capabilities = json!({ "sampling": {}, "roots": null });
    let capabilities = capabilities.as_object();

    assert!(client_declared_capability_for(
        "sampling/createMessage",
        capabilities
    ));
    assert!(client_declared_capability_for("roots/list", capabilities));
    assert!(!client_declared_capability_for(
        "elicitation/create",
        capabilities
    ));
    assert!(!client_declared_capability_for("tools/call", capabilities));
    assert!(!client_declared_capability_for(
        "sampling/createMessage",
        None
    ));
}
