//! isRejectedAfterAuthorizing and forgetRejectedAuthorization: telling a refused token from a
//! missing one, and discarding the refused token.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rust_mcp_remote::auth::{AuthError, AuthOptions, AuthResult};
use rust_mcp_remote::connect::{
    RemoteAuth, forget_rejected_authorization, is_rejected_after_authorizing,
};
use rust_mcp_remote::streamable_http::{BoxFuture, TransportError, TransportOAuth};
use serde_json::Value;

struct Forgetting {
    forgets: AtomicUsize,
    result: Result<(), String>,
}

impl TransportOAuth for Forgetting {
    fn tokens(&self) -> BoxFuture<Option<Value>> {
        Box::pin(async { None })
    }

    fn auth(&self, _options: AuthOptions) -> BoxFuture<Result<AuthResult, AuthError>> {
        panic!("forgetting a token should not run auth()")
    }
}

impl RemoteAuth for Forgetting {
    fn transport_oauth(&self) -> Arc<dyn TransportOAuth> {
        panic!("forgetting a token should not need the transport's OAuth")
    }

    fn forget_tokens(&self) -> BoxFuture<Result<(), String>> {
        self.forgets.fetch_add(1, Ordering::SeqCst);
        let result = self.result.clone();
        Box::pin(async move { result })
    }

    fn use_authorization_state(&self, _state: &str) {}
}

#[test]
fn only_an_http_401_counts_as_rejected_after_authorizing() {
    let http = |status| TransportError::Http {
        status,
        message: "refused".to_owned(),
    };
    assert!(is_rejected_after_authorizing(&http(401)));
    assert!(!is_rejected_after_authorizing(&http(403)));
    // The SDK's UnauthorizedError means no token was sent, not that one was refused.
    assert!(!is_rejected_after_authorizing(
        &TransportError::Unauthorized("401 Unauthorized".to_owned())
    ));
    assert!(!is_rejected_after_authorizing(&TransportError::Other(
        "HTTP 401".to_owned()
    )));
}

#[tokio::test]
async fn forgetting_a_rejected_authorization_discards_the_tokens_once() {
    let auth = Forgetting {
        forgets: AtomicUsize::new(0),
        result: Ok(()),
    };
    forget_rejected_authorization(&auth).await;
    assert_eq!(auth.forgets.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failure_to_discard_the_tokens_is_not_raised() {
    let auth = Forgetting {
        forgets: AtomicUsize::new(0),
        result: Err("disk full".to_owned()),
    };
    forget_rejected_authorization(&auth).await;
    assert_eq!(auth.forgets.load(Ordering::SeqCst), 1);
}
