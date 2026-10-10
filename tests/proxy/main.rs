//! Tests for the `proxy` module, gathered into one test binary.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rust_mcp_remote::proxy::{
    AuthHook, BoxFuture, ProxyOptions, ProxyTransport, SendError, mcp_proxy,
};
use rust_mcp_remote::stdio::TransportEvent;
use serde_json::{Value, json};
use tokio::sync::mpsc;

mod era_bridging;
mod input_required;
mod stream_reconnect;
mod subscription;

/// An in-memory transport: what the proxy sends is recorded on `sent`, and
/// `fail_with` makes every send fail, and `fail_next` fails the next few.
/// Closing it emits `Close` on its events.
#[derive(Clone)]
struct FakeTransport {
    sent: mpsc::UnboundedSender<Value>,
    events: mpsc::UnboundedSender<TransportEvent>,
    fail_with: Arc<Mutex<Option<SendError>>>,
    fail_next: Arc<Mutex<VecDeque<SendError>>>,
    session_id: Arc<Mutex<Option<String>>>,
    send_delay: Arc<Mutex<Option<Duration>>>,
    protocol_version: Arc<Mutex<Option<String>>>,
    closed: Arc<Mutex<bool>>,
    /// An SSE transport's POST endpoint; when set, each sent message records it as `sentTo`.
    endpoint: Arc<Mutex<Option<String>>>,
}

struct Side {
    transport: FakeTransport,
    sent: mpsc::UnboundedReceiver<Value>,
    events: mpsc::UnboundedSender<TransportEvent>,
}

impl ProxyTransport for FakeTransport {
    fn send_message(&self, message: Value) -> BoxFuture<Result<(), SendError>> {
        let transport = self.clone();
        Box::pin(async move {
            let delay = *transport.send_delay.lock().unwrap();
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            if let Some(error) = transport.fail_with.lock().unwrap().clone() {
                return Err(error);
            }
            if let Some(error) = transport.fail_next.lock().unwrap().pop_front() {
                return Err(error);
            }
            let mut message = message;
            if let Some(endpoint) = transport.endpoint.lock().unwrap().clone() {
                message["sentTo"] = json!(endpoint);
            }
            let _ = transport.sent.send(message);
            Ok(())
        })
    }

    fn close_transport(&self) {
        let mut closed = self.closed.lock().unwrap();
        if !*closed {
            *closed = true;
            let _ = self.events.send(TransportEvent::Close);
        }
    }

    fn set_protocol_version(&self, version: String) {
        *self.protocol_version.lock().unwrap() = Some(version);
    }

    fn session_id(&self) -> Option<String> {
        self.session_id.lock().unwrap().clone()
    }

    fn clear_session_id(&self) {
        *self.session_id.lock().unwrap() = None;
    }

    fn post_endpoint(&self) -> Option<String> {
        self.endpoint.lock().unwrap().clone()
    }
}

fn fake() -> (Side, mpsc::UnboundedReceiver<TransportEvent>) {
    let (sent, sent_receiver) = mpsc::unbounded_channel();
    let (events, events_receiver) = mpsc::unbounded_channel();
    let transport = FakeTransport {
        sent,
        events: events.clone(),
        fail_with: Arc::default(),
        fail_next: Arc::default(),
        session_id: Arc::default(),
        send_delay: Arc::default(),
        protocol_version: Arc::default(),
        closed: Arc::default(),
        endpoint: Arc::default(),
    };
    (
        Side {
            transport,
            sent: sent_receiver,
            events,
        },
        events_receiver,
    )
}

struct Harness {
    client: Side,
    server: Side,
    proxy: tokio::task::JoinHandle<()>,
}

fn start(options: ProxyOptions) -> Harness {
    let (client, client_events) = fake();
    let (server, server_events) = fake();
    let proxy = tokio::spawn(mcp_proxy(
        client.transport.clone(),
        client_events,
        server.transport.clone(),
        server_events,
        options,
    ));
    Harness {
        client,
        server,
        proxy,
    }
}

async fn next(receiver: &mut mpsc::UnboundedReceiver<Value>) -> Value {
    tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timed out waiting for a message")
        .expect("channel closed")
}

async fn nothing_more(receiver: &mut mpsc::UnboundedReceiver<Value>) {
    let result = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;
    assert!(result.is_err(), "unexpected message: {result:?}");
}

fn from_client(harness: &Harness, message: Value) {
    harness
        .client
        .events
        .send(TransportEvent::Message(message))
        .unwrap();
}

fn from_server(harness: &Harness, message: Value) {
    harness
        .server
        .events
        .send(TransportEvent::Message(message))
        .unwrap();
}

fn initialize(id: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "client", "version": "1"}}})
}

#[tokio::test]
async fn forwards_initialize_with_a_marked_client_name_and_applies_the_negotiated_version() {
    let mut harness = start(ProxyOptions::default());
    from_client(&harness, initialize(json!(1)));

    let forwarded = next(&mut harness.server.sent).await;
    assert_eq!(
        forwarded["params"]["clientInfo"]["name"],
        "client (via mcp-remote 0.1.38)"
    );

    let response = json!({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18", "capabilities": {}}});
    from_server(&harness, response.clone());
    assert_eq!(next(&mut harness.client.sent).await, response);
    assert_eq!(
        harness
            .server
            .transport
            .protocol_version
            .lock()
            .unwrap()
            .as_deref(),
        Some("2025-06-18")
    );
}

#[tokio::test]
async fn filters_ignored_tools_out_of_tools_list_and_blocks_their_calls() {
    let mut harness = start(ProxyOptions {
        ignored_tools: vec!["delete*".to_owned()],
        ..ProxyOptions::default()
    });

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "read"}, {"name": "deleteAll"}]}}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "read"}]}})
    );

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "deleteAll"}}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": 3, "error": {"code": -32603, "message": "Tool \"deleteAll\" is not available"}})
    );
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn a_tools_list_response_whose_request_id_is_a_string_is_not_paired_with_a_numeric_one() {
    let mut harness = start(ProxyOptions {
        ignored_tools: vec!["secret".to_owned()],
        ..ProxyOptions::default()
    });
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"}),
    );
    next(&mut harness.server.sent).await;
    let response = json!({"jsonrpc": "2.0", "id": "7", "result": {"tools": [{"name": "secret"}]}});
    from_server(&harness, response.clone());
    assert_eq!(next(&mut harness.client.sent).await, response);
}

#[tokio::test]
async fn answers_a_request_the_server_refused_with_an_mcp_remote_error() {
    let mut harness = start(ProxyOptions::default());
    *harness.server.transport.fail_with.lock().unwrap() =
        Some("Error POSTing to endpoint: boom".to_owned().into());

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "x"}}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": 4, "error": {"code": -32001, "message": "mcp-remote: Error POSTing to endpoint: boom"}})
    );

    // A notification has nobody to answer
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 4}}),
    );
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn refuses_requests_in_the_proxys_own_id_namespace_from_either_side() {
    let mut harness = start(ProxyOptions::default());
    let refusal = json!({"jsonrpc": "2.0", "id": "mcp-remote-1", "error": {"code": -32600,
        "message": "mcp-remote reserves request ids beginning with \"mcp-remote-\""}});

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-1", "method": "ping"}),
    );
    assert_eq!(next(&mut harness.client.sent).await, refusal);
    nothing_more(&mut harness.server.sent).await;

    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-1", "method": "ping"}),
    );
    assert_eq!(next(&mut harness.server.sent).await, refusal);
    nothing_more(&mut harness.client.sent).await;

    // A stray answer in the namespace goes to neither side
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-9", "result": {}}),
    );
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-9", "result": {}}),
    );
    nothing_more(&mut harness.client.sent).await;
    nothing_more(&mut harness.server.sent).await;
}

#[tokio::test]
async fn forwards_server_requests_and_client_answers_untouched() {
    let mut harness = start(ProxyOptions::default());
    let request =
        json!({"jsonrpc": "2.0", "id": 10, "method": "sampling/createMessage", "params": {}});
    from_server(&harness, request.clone());
    assert_eq!(next(&mut harness.client.sent).await, request);

    let answer = json!({"jsonrpc": "2.0", "id": 10, "result": {"content": []}});
    from_client(&harness, answer.clone());
    assert_eq!(next(&mut harness.server.sent).await, answer);
}

#[tokio::test]
async fn holds_later_messages_until_notifications_initialized_is_delivered() {
    let mut harness = start(ProxyOptions::default());
    *harness.server.transport.send_delay.lock().unwrap() = Some(Duration::from_millis(200));
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    // Without the barrier this one would be sent at the same time, and could overtake
    tokio::time::sleep(Duration::from_millis(50)).await;
    *harness.server.transport.send_delay.lock().unwrap() = None;
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}),
    );

    assert_eq!(
        next(&mut harness.server.sent).await["method"],
        "notifications/initialized"
    );
    assert_eq!(next(&mut harness.server.sent).await["method"], "tools/list");
}

#[tokio::test]
async fn fails_an_initialize_the_server_accepted_but_never_answered() {
    let mut harness = start(ProxyOptions {
        initialize_timeout: Duration::from_millis(100),
        ..ProxyOptions::default()
    });
    from_client(&harness, initialize(json!("init")));
    next(&mut harness.server.sent).await;
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": "init", "error": {"code": -32001,
            "message": "mcp-remote: timed out after 0.1s waiting for the remote server to answer 'initialize'"}})
    );
}

#[tokio::test]
async fn closing_the_client_closes_the_server_and_ends_the_proxy() {
    let harness = start(ProxyOptions::default());
    harness.client.transport.close_transport();
    tokio::time::timeout(Duration::from_secs(5), harness.proxy)
        .await
        .expect("proxy did not end")
        .unwrap();
    assert!(*harness.server.transport.closed.lock().unwrap());
}

#[tokio::test]
async fn closing_the_server_closes_the_client_and_ends_the_proxy() {
    let harness = start(ProxyOptions::default());
    harness.server.transport.close_transport();
    tokio::time::timeout(Duration::from_secs(5), harness.proxy)
        .await
        .expect("proxy did not end")
        .unwrap();
    assert!(*harness.client.transport.closed.lock().unwrap());
}

/// A hook that counts its calls, waits `delay`, and then answers `result`.
fn counting_hook(
    calls: &Arc<AtomicUsize>,
    delay: Duration,
    result: Result<(), String>,
) -> AuthHook {
    let calls = Arc::clone(calls);
    Arc::new(move || {
        calls.fetch_add(1, Ordering::SeqCst);
        let result = result.clone();
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            result
        })
    })
}

fn unauthorized() -> SendError {
    SendError::Unauthorized("Unauthorized".to_owned())
}

#[tokio::test]
async fn completes_a_sign_in_for_a_refused_request_and_retries_it() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut harness = start(ProxyOptions {
        reauthorize: Some(counting_hook(&calls, Duration::ZERO, Ok(()))),
        ..ProxyOptions::default()
    });
    harness
        .server
        .transport
        .fail_next
        .lock()
        .unwrap()
        .push_back(unauthorized());

    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    from_client(&harness, request.clone());
    assert_eq!(next(&mut harness.server.sent).await, request);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn several_refused_requests_share_one_sign_in() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut harness = start(ProxyOptions {
        reauthorize: Some(counting_hook(&calls, Duration::from_millis(100), Ok(()))),
        ..ProxyOptions::default()
    });
    harness
        .server
        .transport
        .fail_next
        .lock()
        .unwrap()
        .extend([unauthorized(), unauthorized()]);

    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    );
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 2, "method": "prompts/list"}),
    );
    let mut ids = vec![
        next(&mut harness.server.sent).await["id"].clone(),
        next(&mut harness.server.sent).await["id"].clone(),
    ];
    ids.sort_by_key(|id| id.as_i64());
    assert_eq!(ids, vec![json!(1), json!(2)]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failed_sign_in_is_answered_with_its_error_and_a_second_refusal_is_not_retried() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut harness = start(ProxyOptions {
        reauthorize: Some(counting_hook(
            &calls,
            Duration::ZERO,
            Err("Authentication timed out".to_owned()),
        )),
        ..ProxyOptions::default()
    });
    harness
        .server
        .transport
        .fail_next
        .lock()
        .unwrap()
        .push_back(unauthorized());
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "mcp-remote: Authentication timed out"}})
    );

    // Signed in, but refused again: the retry is answered with the second refusal
    let calls = Arc::new(AtomicUsize::new(0));
    let mut harness = start(ProxyOptions {
        reauthorize: Some(counting_hook(&calls, Duration::ZERO, Ok(()))),
        ..ProxyOptions::default()
    });
    *harness.server.transport.fail_with.lock().unwrap() = Some(unauthorized());
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": 2, "error": {"code": -32001, "message": "mcp-remote: Unauthorized"}})
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn discards_a_token_refused_right_after_it_was_issued_then_signs_in_again() {
    let forgets = Arc::new(AtomicUsize::new(0));
    let sign_ins = Arc::new(AtomicUsize::new(0));
    let mut harness = start(ProxyOptions {
        forget_rejected_authorization: Some(counting_hook(&forgets, Duration::ZERO, Ok(()))),
        reauthorize: Some(counting_hook(&sign_ins, Duration::ZERO, Ok(()))),
        ..ProxyOptions::default()
    });
    harness.server.transport.fail_next.lock().unwrap().extend([
        SendError::Http {
            status: 401,
            message: "Server returned 401 after successful authentication".to_owned(),
        },
        unauthorized(),
    ]);

    let request =
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "x"}});
    from_client(&harness, request.clone());
    assert_eq!(next(&mut harness.server.sent).await, request);
    assert_eq!(forgets.load(Ordering::SeqCst), 1);
    assert_eq!(sign_ins.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn re_establishes_an_expired_session_and_resends_the_request() {
    let mut harness = start(ProxyOptions::default());
    from_client(&harness, initialize(json!(0)));
    let forwarded_initialize = next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": 0, "result": {"protocolVersion": "2025-03-26", "capabilities": {}}}),
    );
    next(&mut harness.client.sent).await;

    *harness.server.transport.session_id.lock().unwrap() = Some("dead".to_owned());
    harness
        .server
        .transport
        .fail_next
        .lock()
        .unwrap()
        .push_back(SendError::Http {
            status: 404,
            message: "Error POSTing to endpoint: Session not found".to_owned(),
        });
    let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    from_client(&harness, request.clone());

    let reinitialize = next(&mut harness.server.sent).await;
    let mut expected = forwarded_initialize.clone();
    expected["id"] = json!("mcp-remote-reinit-1");
    assert_eq!(reinitialize, expected);
    assert_eq!(*harness.server.transport.session_id.lock().unwrap(), None);
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-reinit-1", "result": {"protocolVersion": "2025-06-18", "capabilities": {}}}),
    );

    assert_eq!(
        next(&mut harness.server.sent).await,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
    );
    assert_eq!(next(&mut harness.server.sent).await, request);
    assert_eq!(
        harness
            .server
            .transport
            .protocol_version
            .lock()
            .unwrap()
            .as_deref(),
        Some("2025-06-18")
    );
    // The client never hears about the re-initialize
    nothing_more(&mut harness.client.sent).await;
}

#[tokio::test]
async fn a_404_without_a_session_or_a_refused_reinitialize_is_answered_with_the_error() {
    let mut harness = start(ProxyOptions::default());
    harness
        .server
        .transport
        .fail_next
        .lock()
        .unwrap()
        .push_back(SendError::Http {
            status: 404,
            message: "Error POSTing to endpoint: Not Found".to_owned(),
        });
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "mcp-remote: Error POSTing to endpoint: Not Found"}})
    );

    // With a session but no initialize seen, there is nothing to replay
    *harness.server.transport.session_id.lock().unwrap() = Some("dead".to_owned());
    harness
        .server
        .transport
        .fail_next
        .lock()
        .unwrap()
        .push_back(SendError::Http {
            status: 404,
            message: "Session not found".to_owned(),
        });
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": 2, "error": {"code": -32001,
            "message": "mcp-remote: no initialize request was seen, cannot re-establish the session"}})
    );
}

#[tokio::test]
async fn a_rejected_reinitialize_fails_the_request() {
    let mut harness = start(ProxyOptions::default());
    from_client(&harness, initialize(json!(0)));
    next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": 0, "result": {"protocolVersion": "2025-03-26"}}),
    );
    next(&mut harness.client.sent).await;

    *harness.server.transport.session_id.lock().unwrap() = Some("dead".to_owned());
    harness
        .server
        .transport
        .fail_next
        .lock()
        .unwrap()
        .push_back(SendError::Http {
            status: 404,
            message: "Session not found".to_owned(),
        });
    from_client(
        &harness,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
    );
    next(&mut harness.server.sent).await;
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-reinit-1", "error": {"code": -32600, "message": "nope"}}),
    );
    assert_eq!(
        next(&mut harness.client.sent).await,
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32001,
            "message": "mcp-remote: server rejected re-initialize: {\"code\":-32600,\"message\":\"nope\"}"}})
    );
}

#[tokio::test]
async fn keep_alive_pings_the_server_and_keeps_the_answers_from_the_client() {
    let mut harness = start(ProxyOptions {
        keep_alive: Some(Duration::from_millis(50)),
        ..ProxyOptions::default()
    });
    let ping = next(&mut harness.server.sent).await;
    assert_eq!(
        ping,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-keepalive-1", "method": "ping"})
    );
    from_server(
        &harness,
        json!({"jsonrpc": "2.0", "id": "mcp-remote-keepalive-1", "result": {}}),
    );
    assert_eq!(
        next(&mut harness.server.sent).await["id"],
        "mcp-remote-keepalive-2"
    );
    nothing_more(&mut harness.client.sent).await;

    // A failed ping is reported, not escalated: pinging goes on
    *harness.server.transport.fail_with.lock().unwrap() = Some("down".to_owned().into());
    tokio::time::sleep(Duration::from_millis(120)).await;
    *harness.server.transport.fail_with.lock().unwrap() = None;
    assert!(
        next(&mut harness.server.sent).await["id"]
            .as_str()
            .unwrap()
            .starts_with("mcp-remote-keepalive-")
    );
}

#[tokio::test]
async fn keep_alive_stops_when_a_side_closes() {
    let mut harness = start(ProxyOptions {
        keep_alive: Some(Duration::from_millis(30)),
        ..ProxyOptions::default()
    });
    next(&mut harness.server.sent).await;
    harness.client.transport.close_transport();
    tokio::time::timeout(Duration::from_secs(5), &mut harness.proxy)
        .await
        .expect("proxy did not end")
        .unwrap();
    while harness.server.sent.try_recv().is_ok() {}
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(harness.server.sent.try_recv().is_err());
}
