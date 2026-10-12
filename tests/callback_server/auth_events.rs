//! The process-wide `AuthEvents` emitter the callback servers share.

use rust_mcp_remote::callback_server::{AuthEvent, AuthEvents};
use tokio::sync::broadcast::error::TryRecvError;

fn received(code: &str) -> AuthEvent {
    AuthEvent::CodeReceived {
        code: code.to_owned(),
        state: None,
    }
}

#[test]
fn every_clone_shares_one_channel_and_subscribers_only_see_later_events() {
    let events = AuthEvents::new();
    // Emitting with no subscriber is a silent no-op, and the event is not buffered.
    events.emit(received("before"));

    let mut first = events.subscribe();
    let mut second = events.clone().subscribe();
    events
        .clone()
        .emit(AuthEvent::CodeFailed("denied".to_owned()));
    events.emit(received("after"));

    for subscriber in [&mut first, &mut second] {
        assert_eq!(
            subscriber.try_recv().unwrap(),
            AuthEvent::CodeFailed("denied".to_owned())
        );
        assert_eq!(subscriber.try_recv().unwrap(), received("after"));
        assert_eq!(subscriber.try_recv(), Err(TryRecvError::Empty));
    }
}
