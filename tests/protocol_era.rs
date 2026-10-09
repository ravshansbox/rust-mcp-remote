use rust_mcp_remote::protocol_era::{TranslatedResult, translate_modern_result};
use serde_json::json;

#[test]
fn the_result_type_tag_is_dropped() {
    let translated = translate_modern_result(json!({ "resultType": "complete", "tools": [] }));

    assert_eq!(translated, TranslatedResult::Result(json!({ "tools": [] })));
}

#[test]
fn a_result_with_no_type_is_passed_through() {
    let translated = translate_modern_result(json!({ "tools": [] }));

    assert_eq!(translated, TranslatedResult::Result(json!({ "tools": [] })));
}

#[test]
fn a_request_for_more_input_is_reported_as_an_error() {
    let translated =
        translate_modern_result(json!({ "resultType": "input_required", "inputRequests": [] }));

    let TranslatedResult::Error { code, message } = translated else {
        panic!("expected an error, got {translated:?}");
    };
    assert_eq!(code, -32603);
    assert!(message.contains("multi-round-trip"));
}

#[test]
fn a_result_type_from_a_future_revision_is_reported() {
    let translated = translate_modern_result(json!({ "resultType": "something-new" }));

    let TranslatedResult::Error { code, message } = translated else {
        panic!("expected an error, got {translated:?}");
    };
    assert_eq!(code, -32603);
    assert!(message.ends_with(": something-new"));
}

#[test]
fn a_result_that_is_not_an_object_is_passed_through() {
    assert_eq!(
        translate_modern_result(json!(null)),
        TranslatedResult::Result(json!(null))
    );
    assert_eq!(
        translate_modern_result(json!("text")),
        TranslatedResult::Result(json!("text"))
    );
}
