use rust_mcp_remote::utils::MessageTransformer;
use serde_json::{Value, json};

fn tagging_response_transformer() -> MessageTransformer {
    MessageTransformer::new(
        None,
        Some(Box::new(|request: &Value, response: &Value| {
            let mut tagged = response.clone();
            tagged["result"]["for"] = request["method"].clone();
            Ok(tagged)
        })),
    )
}

#[test]
fn response_is_transformed_with_its_original_request() {
    let mut transformer = tagging_response_transformer();
    let mut console = Vec::new();
    transformer.intercept_request_to(&mut console, json!({"id": 1, "method": "tools/list"}));
    let response = transformer.intercept_response_to(&mut console, json!({"id": 1, "result": {}}));
    assert_eq!(response, json!({"id": 1, "result": {"for": "tools/list"}}));
}

#[test]
fn response_is_paired_only_once() {
    let mut transformer = tagging_response_transformer();
    let mut console = Vec::new();
    transformer.intercept_request_to(&mut console, json!({"id": 1, "method": "tools/list"}));
    transformer.intercept_response_to(&mut console, json!({"id": 1, "result": {}}));
    let second = transformer.intercept_response_to(&mut console, json!({"id": 1, "result": {}}));
    assert_eq!(second, json!({"id": 1, "result": {}}));
}

#[test]
fn string_and_number_ids_are_kept_apart() {
    let mut transformer = tagging_response_transformer();
    let mut console = Vec::new();
    transformer.intercept_request_to(&mut console, json!({"id": 1, "method": "tools/list"}));
    let response =
        transformer.intercept_response_to(&mut console, json!({"id": "1", "result": {}}));
    assert_eq!(response, json!({"id": "1", "result": {}}));
}

#[test]
fn messages_that_are_not_requests_are_not_remembered() {
    let mut transformer = tagging_response_transformer();
    let mut console = Vec::new();
    transformer.intercept_request_to(&mut console, json!({"id": 1, "result": {}}));
    transformer.intercept_request_to(&mut console, json!({"id": null, "method": "x"}));
    let response = transformer.intercept_response_to(&mut console, json!({"id": 1, "result": {}}));
    assert_eq!(response, json!({"id": 1, "result": {}}));
}

#[test]
fn request_transform_can_block_or_replace() {
    let mut transformer = MessageTransformer::new(
        Some(Box::new(|request: &Value| {
            if request["method"] == "tools/call" {
                Ok(None)
            } else {
                let mut changed = request.clone();
                changed["changed"] = json!(true);
                Ok(Some(changed))
            }
        })),
        None,
    );
    let mut console = Vec::new();
    let blocked =
        transformer.intercept_request_to(&mut console, json!({"id": 1, "method": "tools/call"}));
    let replaced =
        transformer.intercept_request_to(&mut console, json!({"id": 2, "method": "ping"}));
    assert_eq!(blocked, None);
    assert_eq!(
        replaced,
        Some(json!({"id": 2, "method": "ping", "changed": true}))
    );
}

#[test]
fn failing_transform_forwards_the_message_unchanged_and_logs() {
    let mut transformer = MessageTransformer::new(
        Some(Box::new(|_: &Value| Err("boom".to_string()))),
        Some(Box::new(|_: &Value, _: &Value| Err("bang".to_string()))),
    );
    let mut console = Vec::new();
    let request =
        transformer.intercept_request_to(&mut console, json!({"id": 1, "method": "ping"}));
    let response = transformer.intercept_response_to(&mut console, json!({"id": 1, "result": {}}));
    assert_eq!(request, Some(json!({"id": 1, "method": "ping"})));
    assert_eq!(response, json!({"id": 1, "result": {}}));
    let output = String::from_utf8(console).unwrap();
    assert!(output.contains("Error transforming message, forwarding it unchanged: boom"));
    assert!(output.contains("Error transforming message, forwarding it unchanged: bang"));
}

#[test]
fn release_frees_the_held_request() {
    let mut transformer = tagging_response_transformer();
    let mut console = Vec::new();
    transformer.intercept_request_to(&mut console, json!({"id": 1, "method": "tools/list"}));
    transformer.release(&json!(1), None);
    let response = transformer.intercept_response_to(&mut console, json!({"id": 1, "result": {}}));
    assert_eq!(response, json!({"id": 1, "result": {}}));
}

#[test]
fn release_with_only_keeps_a_replacement_request() {
    let mut transformer = tagging_response_transformer();
    let mut console = Vec::new();
    let stale = json!({"id": 1, "method": "tools/list"});
    transformer.intercept_request_to(&mut console, stale.clone());
    transformer.intercept_request_to(&mut console, json!({"id": 1, "method": "prompts/list"}));
    transformer.release(&json!(1), Some(&stale));
    let response = transformer.intercept_response_to(&mut console, json!({"id": 1, "result": {}}));
    assert_eq!(
        response,
        json!({"id": 1, "result": {"for": "prompts/list"}})
    );
}
