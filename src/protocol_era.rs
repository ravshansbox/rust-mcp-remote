use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum TranslatedResult {
    Result(Value),
    Error { code: i64, message: String },
}

pub fn translate_modern_result(result: Value) -> TranslatedResult {
    let Value::Object(mut rest) = result else {
        return TranslatedResult::Result(result);
    };

    match rest.remove("resultType") {
        None => TranslatedResult::Result(Value::Object(rest)),
        Some(Value::String(result_type)) if result_type == "complete" => {
            TranslatedResult::Result(Value::Object(rest))
        }
        Some(Value::String(result_type)) if result_type == "input_required" => {
            TranslatedResult::Error {
                code: -32603,
                message: "The remote server asked for more input mid-request (a 2026-07-28 multi-round-trip request). \
                    The local client speaks a protocol revision with no way to answer that, so the request cannot be completed."
                    .to_string(),
            }
        }
        Some(result_type) => {
            let result_type = match result_type {
                Value::String(text) => text,
                other => other.to_string(),
            };
            TranslatedResult::Error {
                code: -32603,
                message: format!(
                    "The remote server returned a result of an unrecognised type: {result_type}"
                ),
            }
        }
    }
}
