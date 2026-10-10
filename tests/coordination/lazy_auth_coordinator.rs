//! Ports of coordination.test.ts 'Two 401s arriving in the same tick'.

use std::sync::Arc;

use rust_mcp_remote::callback_server::{AuthEvents, CallbackServerError};
use rust_mcp_remote::coordination::{CoordinationError, create_lazy_auth_coordinator};

use crate::run_in_config_dir;

#[test]
fn concurrent_callers_share_one_flow_instead_of_racing_for_the_callback_port() {
    run_in_config_dir("mcp-remote-lazy", || async {
        let coordinator = create_lazy_auth_coordinator(
            "lazy-shared",
            "/oauth/callback",
            0,
            AuthEvents::new(),
            5000,
            false,
        );

        let (first, second) = tokio::join!(
            coordinator.initialize_auth(false),
            coordinator.initialize_auth(false)
        );

        let (first, second) = (first.unwrap(), second.unwrap());
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!first.skip_browser_auth);
    });
}

#[test]
fn a_failed_attempt_is_not_cached_so_a_retry_can_still_succeed() {
    run_in_config_dir("mcp-remote-lazy", || async {
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let blocked_port = blocker.local_addr().unwrap().port();
        let coordinator = create_lazy_auth_coordinator(
            "lazy-retry",
            "/oauth/callback",
            blocked_port,
            AuthEvents::new(),
            5000,
            true,
        );

        let error = coordinator.initialize_auth(false).await.err().unwrap();
        assert_eq!(
            error,
            CoordinationError::CallbackServer(CallbackServerError::AddrInUse {
                requested_port: blocked_port
            })
        );

        drop(blocker);
        let retried = coordinator.initialize_auth(false).await.unwrap();
        assert_eq!(retried.actual_port, blocked_port);
    });
}

#[test]
fn a_forced_refresh_releases_the_old_server_and_coordinates_again() {
    run_in_config_dir("mcp-remote-lazy", || async {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let coordinator = create_lazy_auth_coordinator(
            "lazy-refresh",
            "/oauth/callback",
            port,
            AuthEvents::new(),
            5000,
            true,
        );

        let first = coordinator.initialize_auth(false).await.unwrap();
        let reused = coordinator.initialize_auth(false).await.unwrap();
        assert!(Arc::ptr_eq(&first, &reused));

        // Without releasing its own server first, the fresh attempt would find itself on the
        // port and follow itself
        let refreshed = coordinator.initialize_auth(true).await.unwrap();
        assert!(!Arc::ptr_eq(&first, &refreshed));
        assert!(!refreshed.skip_browser_auth);
        assert_eq!(refreshed.actual_port, port);
    });
}
