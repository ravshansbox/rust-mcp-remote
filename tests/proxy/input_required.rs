//! Ports the utils.test.ts scenarios under 'Feature: Bridging the modern surfaces a 2025-era
//! client has never heard of' that cover the multi-round-trip `input_required` exchange
//! (`driveInputRequired`) and re-addressing cancellations to its retry leg.

use super::*;
use rust_mcp_remote::connect::StreamReconnectHook;
use rust_mcp_remote::protocol_era::ProtocolMode;

fn auto() -> ProxyOptions {
    ProxyOptions {
        protocol_mode: ProtocolMode::Auto,
        ..ProxyOptions::default()
    }
}

/// Starts a proxy bridging a client that declared `sampling` only to a modern server.
async fn bridged(options: ProxyOptions) -> Harness {
    let mut harness = start(options);
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "initialize", "id": "init-1", "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"sampling": {}},
            "clientInfo": {"name": "host", "version": "1.0.0"}}}),
    );
    let probe = next(&mut harness.server.sent).await;
    assert_eq!(probe["method"], "server/discover");
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": probe["id"], "result": {
            "supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}}}),
    );
    assert_eq!(next(&mut harness.client.sent).await["id"], "init-1");
    harness
}

fn request(method: &str, id: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "method": method, "id": id, "params": params})
}

fn cancel(id: &str) -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": id}})
}

/// The server answers the request it was sent by asking the client `method` first.
fn ask(harness: &Harness, sent: &Value, method: &str) {
    from_server(
        harness,
        json!({"jsonrpc": "2.0", "id": sent["id"], "result": {
            "resultType": "input_required",
            "inputRequests": {"ask": {"method": method, "params": {}}}}}),
    );
}

/// Sends a request, has the server ask for sampling, and returns the question the client got.
async fn start_exchange(harness: &mut Harness, method: &str, id: &str) -> Value {
    from_client(harness, request(method, id, json!({"name": "x"})));
    let sent = next(&mut harness.server.sent).await;
    assert_eq!(sent["id"], id);
    ask(harness, &sent, "sampling/createMessage");
    let question = next(&mut harness.client.sent).await;
    assert_eq!(question["method"], "sampling/createMessage");
    question
}

fn answer(harness: &Harness, question: &Value) {
    from_client(
        harness,
        json!({"jsonrpc": "2.0", "id": question["id"], "result": {"role": "assistant"}}),
    );
}

#[tokio::test]
async fn a_mid_request_question_is_put_to_the_client_as_the_request_it_does_understand() {
    let mut harness = bridged(auto()).await;
    from_client(
        &harness,
        request("tools/call", "call-1", json!({"name": "search"})),
    );
    let call = next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": call["id"], "result": {
            "resultType": "input_required",
            "requestState": "opaque-state",
            "inputRequests": {"ask": {"method": "sampling/createMessage", "params": {"messages": []}}}}}),
    );

    // The embedded question is put to the client as an ordinary server-initiated request
    let question = next(&mut harness.client.sent).await;
    assert_eq!(question["method"], "sampling/createMessage");
    assert_eq!(question["params"], json!({"messages": []}));
    assert!(
        question["id"]
            .as_str()
            .unwrap()
            .starts_with("mcp-remote-input-")
    );
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": question["id"], "result": {"role": "assistant", "content": {"type": "text", "text": "hi"}}}),
    );

    // The retry carries the answer and echoes the server's opaque state back untouched
    let retry = next(&mut harness.server.sent).await;
    assert_eq!(retry["method"], "tools/call");
    assert_ne!(retry["id"], "call-1");
    assert_eq!(
        retry["params"]["inputResponses"]["ask"],
        json!({"role": "assistant", "content": {"type": "text", "text": "hi"}})
    );
    assert_eq!(retry["params"]["requestState"], "opaque-state");
    assert_eq!(retry["params"]["name"], "search");
    assert_eq!(
        retry["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": retry["id"], "result": {"resultType": "complete", "content": [{"type": "text", "text": "done"}]}}),
    );

    // The client is answered once, on the request it actually sent
    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], "call-1");
    assert_eq!(
        answer["result"],
        json!({"content": [{"type": "text", "text": "done"}]})
    );
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn a_server_asking_again_gets_a_second_round() {
    let mut harness = bridged(auto()).await;
    let question = start_exchange(&mut harness, "tools/call", "call-1").await;
    answer(&harness, &question);
    let retry = next(&mut harness.server.sent).await;
    ask(&harness, &retry, "sampling/createMessage");

    let second = next(&mut harness.client.sent).await;
    assert_eq!(second["method"], "sampling/createMessage");
    assert_ne!(second["id"], question["id"]);
    answer(&harness, &second);
    let second_retry = next(&mut harness.server.sent).await;
    assert_ne!(second_retry["id"], retry["id"]);
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": second_retry["id"], "result": {"content": []}}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": "call-1", "result": {"content": []}})
    );
}

#[tokio::test]
async fn an_error_on_the_retry_leg_is_the_clients_answer() {
    let mut harness = bridged(auto()).await;
    let question = start_exchange(&mut harness, "tools/call", "call-1").await;
    answer(&harness, &question);
    let retry = next(&mut harness.server.sent).await;
    let error = json!({"code": -32602, "message": "bad input"});
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": retry["id"], "error": error}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": "call-1", "error": error})
    );
}

#[tokio::test]
async fn a_mid_request_question_is_given_the_time_an_answer_actually_takes() {
    // Well past the budget an initialize is allowed, and the question is still open
    let mut harness = bridged(ProxyOptions {
        initialize_timeout: Duration::from_millis(20),
        ..auto()
    })
    .await;
    let question = start_exchange(&mut harness, "tools/call", "call-1").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    nothing_more(&mut harness.client.sent).await;

    answer(&harness, &question);
    let retry = next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": retry["id"], "result": {"resultType": "complete", "content": []}}),
    );
    assert_eq!(next(&mut harness.client.sent).await["id"], "call-1");
}

#[tokio::test]
async fn settle_what_this_proxy_is_waiting_on_when_the_connection_goes() {
    let mut harness = bridged(auto()).await;
    start_exchange(&mut harness, "tools/call", "call-1").await;

    // The transport goes away while the question is still out
    harness.server.events.send(TransportEvent::Close).unwrap();

    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], "call-1");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap()
            .contains("connection closed")
    );
}

#[tokio::test]
async fn a_tool_the_user_hid_stays_hidden_even_when_the_answer_arrives_across_a_round_trip() {
    let mut harness = bridged(ProxyOptions {
        ignored_tools: vec!["secret".to_owned()],
        ..auto()
    })
    .await;
    let question = start_exchange(&mut harness, "tools/list", "list-1").await;
    answer(&harness, &question);
    let retry = next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": retry["id"], "result": {
            "resultType": "complete", "tools": [{"name": "keepme"}, {"name": "secret"}]}}),
    );

    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], "list-1");
    assert_eq!(answer["result"]["tools"], json!([{"name": "keepme"}]));
}

#[tokio::test]
async fn a_server_asking_for_input_but_naming_none_does_not_get_the_tool_run_again() {
    let mut harness = bridged(auto()).await;
    from_client(
        &harness,
        request("tools/call", "call-1", json!({"name": "sendEmail"})),
    );
    let call = next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": call["id"], "result": {"resultType": "input_required"}}),
    );

    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], "call-1");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap()
            .contains("named none")
    );
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn too_many_questions_at_once_are_refused() {
    let mut harness = bridged(auto()).await;
    from_client(&harness, request("tools/call", "call-1", json!({})));
    let call = next(&mut harness.server.sent).await;
    let questions: serde_json::Map<String, Value> = (0..9)
        .map(|n| {
            (
                format!("q{n}"),
                json!({"method": "sampling/createMessage", "params": {}}),
            )
        })
        .collect();
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": call["id"], "result": {
            "resultType": "input_required", "inputRequests": questions}}),
    );

    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], "call-1");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap()
            .contains("embedded 9 questions")
    );
}

#[tokio::test]
async fn a_client_is_not_asked_for_something_it_never_said_it_could_do() {
    let mut harness = bridged(auto()).await;
    from_client(&harness, request("tools/call", "call-1", json!({})));
    let call = next(&mut harness.server.sent).await;
    ask(&harness, &call, "roots/list");

    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], "call-1");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap()
            .contains("did not declare")
    );
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn a_question_this_proxy_cannot_put_to_a_2025_era_client_is_reported_not_dropped() {
    let mut harness = bridged(auto()).await;
    from_client(&harness, request("tools/call", "call-1", json!({})));
    let call = next(&mut harness.server.sent).await;
    ask(&harness, &call, "something/new");

    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], "call-1");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot put to a 2025-era client")
    );
}

#[tokio::test]
async fn a_client_refusing_the_question_fails_the_request() {
    let mut harness = bridged(auto()).await;
    let question = start_exchange(&mut harness, "tools/call", "call-1").await;
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": question["id"], "error": {"code": -1, "message": "User rejected"}}),
    );

    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], "call-1");
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap()
            .contains("the local client refused sampling/createMessage")
    );
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_cancellation_reaches_the_leg_the_server_is_actually_running() {
    let mut harness = bridged(auto()).await;
    let question = start_exchange(&mut harness, "tools/call", "call-1").await;
    answer(&harness, &question);
    let retry = next(&mut harness.server.sent).await;

    from_client(&harness, cancel("call-1"));

    let cancelled = next(&mut harness.server.sent).await;
    assert_eq!(cancelled["method"], "notifications/cancelled");
    assert_eq!(cancelled["params"]["requestId"], retry["id"]);
}

#[tokio::test]
async fn a_cancelled_exchange_is_answered_once_by_the_cancellation_and_not_by_the_server() {
    let mut harness = bridged(auto()).await;
    let question = start_exchange(&mut harness, "tools/call", "call-1").await;
    answer(&harness, &question);
    let retry = next(&mut harness.server.sent).await;

    from_client(&harness, cancel("call-1"));
    next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": retry["id"], "result": {"resultType": "complete", "content": []}}),
    );

    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn cancelling_before_the_server_has_anything_in_flight_still_ends_the_exchange() {
    let mut harness = bridged(auto()).await;
    let question = start_exchange(&mut harness, "tools/call", "call-1").await;

    // Cancelled while the question is still out, so there is no leg to re-address it to
    from_client(&harness, cancel("call-1"));

    // The client answers anyway and the exchange runs to completion
    answer(&harness, &question);
    let retry = next(&mut harness.server.sent).await;
    assert!(retry["params"].get("inputResponses").is_some());
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": retry["id"], "result": {"resultType": "complete", "content": []}}),
    );

    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn a_superseded_exchange_does_not_answer_the_request_that_replaced_it() {
    let mut harness = bridged(auto()).await;

    // The first exchange starts, and is then abandoned
    let first_question = start_exchange(&mut harness, "tools/call", "X").await;
    from_client(&harness, cancel("X"));

    // The client reuses the id for a new call, which runs an exchange of its own
    let second_question = start_exchange(&mut harness, "tools/call", "X").await;

    // The second exchange finishes first
    answer(&harness, &second_question);
    let second_retry = next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": second_retry["id"], "result": {"resultType": "complete", "content": [{"text": "SECOND"}]}}),
    );
    let answered = next(&mut harness.client.sent).await;
    assert_eq!(answered["id"], "X");
    assert_eq!(answered["result"]["content"], json!([{"text": "SECOND"}]));

    // Now the stranded first exchange finishes, and says nothing
    answer(&harness, &first_question);
    let first_retry = next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": first_retry["id"], "result": {"resultType": "complete", "content": [{"text": "FIRST"}]}}),
    );
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn a_stranded_exchange_does_not_free_the_request_that_reused_its_id() {
    let mut harness = bridged(ProxyOptions {
        ignored_tools: vec!["secret".to_owned()],
        ..auto()
    })
    .await;

    // An exchange starts under id X, then is abandoned
    let question = start_exchange(&mut harness, "tools/list", "X").await;
    from_client(&harness, cancel("X"));

    // The client reuses X for a fresh request identical to the first, which the server has not
    // answered yet
    from_client(&harness, request("tools/list", "X", json!({"name": "x"})));
    assert_eq!(next(&mut harness.server.sent).await["id"], "X");

    // The stranded exchange runs all the way to an answer, which is dropped - and must not take
    // the new request's hold with it
    answer(&harness, &question);
    let retry = next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": retry["id"], "result": {"resultType": "complete", "tools": [{"name": "stale"}]}}),
    );
    nothing_more(&mut harness.client.sent).await;

    // Now the server answers the request that actually owns X
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": "X", "result": {
            "resultType": "complete", "tools": [{"name": "keep"}, {"name": "secret"}]}}),
    );
    let answer = next(&mut harness.client.sent).await;
    assert_eq!(answer["id"], "X");
    assert_eq!(answer["result"], json!({"tools": [{"name": "keep"}]}));
}

#[tokio::test]
async fn a_request_for_more_input_on_an_exchange_already_over_is_not_answered_twice() {
    let slot: StreamReconnectHook = Arc::default();
    let mut harness = bridged(ProxyOptions {
        stream_reconnect: Some(Arc::clone(&slot)),
        reinitialize_timeout: Duration::from_millis(50),
        ..auto()
    })
    .await;
    from_client(&harness, request("tools/call", "call-1", json!({})));
    let call = next(&mut harness.server.sent).await;

    // The stream drops, which fails the request in flight
    let hook = slot.lock().unwrap().clone().expect("the proxy set no hook");
    hook();
    let failed = next(&mut harness.client.sent).await;
    assert_eq!(failed["id"], "call-1");
    assert!(failed.get("error").is_some());

    // The server's answer arrives after the session already failed the request
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": call["id"], "result": {"resultType": "input_required", "inputRequests": {}}}),
    );
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn a_cancellation_does_not_leave_the_retry_mapping_behind_for_the_next_request() {
    let mut harness = bridged(auto()).await;

    // A first exchange gets as far as a retry leg, then is cancelled
    let first = start_exchange(&mut harness, "tools/call", "Y").await;
    answer(&harness, &first);
    next(&mut harness.server.sent).await;
    from_client(&harness, cancel("Y"));
    assert_eq!(
        next(&mut harness.server.sent).await["method"],
        "notifications/cancelled"
    );

    // A new exchange under the same id, cancelled before any leg exists
    start_exchange(&mut harness, "tools/call", "Y").await;
    from_client(&harness, cancel("Y"));

    // Nothing further goes to the server: there is no leg of this exchange to cancel
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_late_answer_to_a_question_given_up_on_goes_nowhere() {
    let mut harness = bridged(auto()).await;
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-input-99", "result": {}}),
    );
    nothing_more(&mut harness.server.sent).await;
    nothing_more(&mut harness.client.sent).await;
}
