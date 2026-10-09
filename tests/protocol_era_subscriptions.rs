use rust_mcp_remote::protocol_era::{
    MAX_INPUT_REQUESTS_PER_ROUND, MAX_INPUT_REQUIRED_ROUNDS, input_required_retry_params,
    subscription_filter_for, unacknowledged_subscriptions,
};
use serde_json::{Map, Value, json};

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("not an object"),
    }
}

#[test]
fn the_filter_asks_only_for_the_changes_the_server_announces() {
    let capabilities = object(json!({
        "tools": { "listChanged": true },
        "prompts": { "listChanged": false },
        "resources": { "listChanged": 1 },
        "logging": {}
    }));
    assert_eq!(
        subscription_filter_for(Some(&capabilities), &[]),
        Some(json!({ "toolsListChanged": true, "resourcesListChanged": true }))
    );
}

#[test]
fn the_filter_includes_resource_subscriptions_when_there_are_any() {
    let resources = ["file:///a".to_string(), "file:///b".to_string()];
    assert_eq!(
        subscription_filter_for(None, &resources),
        Some(json!({ "resourceSubscriptions": ["file:///a", "file:///b"] }))
    );
}

#[test]
fn there_is_no_filter_when_the_server_announces_no_changes() {
    let capabilities = object(json!({ "tools": {}, "prompts": { "listChanged": null } }));
    assert_eq!(subscription_filter_for(Some(&capabilities), &[]), None);
    assert_eq!(subscription_filter_for(None, &[]), None);
}

#[test]
fn notification_types_the_server_did_not_acknowledge_are_reported() {
    let requested = object(json!({
        "toolsListChanged": true,
        "promptsListChanged": true,
        "resourcesListChanged": true,
        "resourceSubscriptions": ["file:///a", "file:///b"]
    }));
    let acknowledged = json!({
        "toolsListChanged": true,
        "promptsListChanged": false,
        "resourceSubscriptions": ["file:///a"]
    });
    assert_eq!(
        unacknowledged_subscriptions(&requested, Some(&acknowledged)),
        vec![
            "promptsListChanged",
            "resourcesListChanged",
            "resourceSubscriptions"
        ]
    );
}

#[test]
fn a_full_acknowledgement_leaves_nothing_missing() {
    let requested = object(json!({
        "toolsListChanged": true,
        "resourceSubscriptions": ["file:///a"]
    }));
    let acknowledged = json!({
        "toolsListChanged": true,
        "resourceSubscriptions": ["file:///b", "file:///a"]
    });
    assert!(unacknowledged_subscriptions(&requested, Some(&acknowledged)).is_empty());
}

#[test]
fn resource_subscriptions_that_are_not_a_list_count_as_unacknowledged() {
    let requested = object(json!({ "resourceSubscriptions": ["file:///a"] }));
    let acknowledged = json!({ "resourceSubscriptions": "file:///a" });
    assert_eq!(
        unacknowledged_subscriptions(&requested, Some(&acknowledged)),
        vec!["resourceSubscriptions"]
    );
}

#[test]
fn a_missing_or_non_object_acknowledgement_reports_nothing() {
    let requested = object(json!({ "toolsListChanged": true }));
    for acknowledged in [
        None,
        Some(json!(null)),
        Some(json!("yes")),
        Some(json!(false)),
    ] {
        assert!(
            unacknowledged_subscriptions(&requested, acknowledged.as_ref()).is_empty(),
            "{acknowledged:?}"
        );
    }
}

#[test]
fn retry_params_carry_the_responses_and_the_request_state_verbatim() {
    let original = json!({ "name": "search", "inputResponses": { "old": 1 } });
    let responses = object(json!({ "q1": { "action": "accept" } }));
    assert_eq!(
        input_required_retry_params(Some(&original), &responses, Some(" opaque==\n")),
        json!({
            "name": "search",
            "inputResponses": { "q1": { "action": "accept" } },
            "requestState": " opaque==\n"
        })
    );
}

#[test]
fn retry_params_leave_out_empty_responses_and_a_missing_request_state() {
    let original = json!({ "name": "search", "inputResponses": { "old": 1 } });
    assert_eq!(
        input_required_retry_params(Some(&original), &Map::new(), None),
        original
    );
}

#[test]
fn retry_params_start_from_nothing_when_there_were_no_original_params() {
    assert_eq!(
        input_required_retry_params(None, &Map::new(), Some("")),
        json!({ "requestState": "" })
    );
}

#[test]
fn round_and_request_limits_match_the_original() {
    assert_eq!(MAX_INPUT_REQUIRED_ROUNDS, 10);
    assert_eq!(MAX_INPUT_REQUESTS_PER_ROUND, 8);
}
