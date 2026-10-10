use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rust_mcp_remote::node_oauth_client_provider::{NodeOAuthClientProvider, OAuthProviderOptions};

fn provider() -> NodeOAuthClientProvider {
    NodeOAuthClientProvider::new(OAuthProviderOptions {
        server_url: "https://mcp.example.com/mcp".to_string(),
        callback_port: 3334,
        host: "localhost".to_string(),
        server_url_hash: "renew-client-credentials-test".to_string(),
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn passes_the_resource_server_url_and_scope_to_auth() {
    let provider = provider();
    let received = Mutex::new(None);

    let result = provider.renew_client_credentials(Some("read write"), |server_url, scope| {
        *received.lock().unwrap() = Some((server_url.to_string(), scope.map(str::to_string)));
        Ok(())
    });

    assert_eq!(result, Ok(()));
    assert_eq!(
        received.into_inner().unwrap(),
        Some((
            "https://mcp.example.com/mcp".to_string(),
            Some("read write".to_string())
        ))
    );
}

#[test]
fn concurrent_callers_share_one_renewal() {
    let provider = provider();
    let attempts = AtomicUsize::new(0);

    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            provider.renew_client_credentials(None, |_, _| {
                attempts.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(300));
                Err("first failed".to_string())
            })
        });
        std::thread::sleep(Duration::from_millis(100));
        let second = scope.spawn(|| {
            provider.renew_client_credentials(None, |_, _| {
                attempts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });
        (first.join().unwrap(), second.join().unwrap())
    });

    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(first, Err("first failed".to_string()));
    assert_eq!(second, Err("first failed".to_string()));
}

#[test]
fn a_later_caller_renews_again_once_the_attempt_is_over() {
    let provider = provider();

    let first = provider.renew_client_credentials(None, |_, _| Err("failed".to_string()));
    let second = provider.renew_client_credentials(None, |_, _| Ok(()));

    assert_eq!(first, Err("failed".to_string()));
    assert_eq!(second, Ok(()));
}
