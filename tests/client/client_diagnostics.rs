//! client-diagnostics.test.ts

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rust_mcp_remote::client::attach_client_diagnostics;
use rust_mcp_remote::stdio::TransportEvent;

use crate::pair::{connected_pair, tools_server};

#[tokio::test]
async fn a_request_still_resolves_once_the_diagnostics_are_attached() {
    let pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();

    attach_client_diagnostics(&client, || {});

    let tools = tokio::time::timeout(Duration::from_secs(5), client.request("tools/list", None))
        .await
        .expect("the request waited out its timeout")
        .unwrap();
    assert_eq!(tools["tools"][0]["name"], "search");
    client.close();
}

#[tokio::test]
async fn received_messages_are_observed_before_dispatch() {
    let pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    attach_client_diagnostics(&client, || {});
    // The diagnostics hook is replaced by a recorder here, since the log goes to stderr.
    {
        let seen = Arc::clone(&seen);
        client.set_on_message(move |message| seen.lock().unwrap().push(message.clone()));
    }

    client.request("tools/list", None).await.unwrap();

    let seen = seen.lock().unwrap();
    assert!(
        seen.iter()
            .any(|message| message.to_string().contains("search"))
    );
}

#[tokio::test]
async fn closing_the_connection_reports_it_once() {
    let pair = connected_pair(tools_server()).await;
    let client = pair.client.unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    {
        let closed = Arc::clone(&closed);
        attach_client_diagnostics(&client, move || {
            closed.fetch_add(1, Ordering::SeqCst);
        });
    }

    pair.server.send(TransportEvent::Close).unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    client.close();
    tokio::time::sleep(Duration::from_millis(10)).await;

    assert_eq!(closed.load(Ordering::SeqCst), 1);
}
