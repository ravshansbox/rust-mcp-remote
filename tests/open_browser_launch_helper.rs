use std::time::{Duration, Instant};

use rust_mcp_remote::open_browser::{HELPER_SETTLE_MS, launch_helper};

#[test]
fn waits_half_a_second_for_a_helper_to_fail() {
    assert_eq!(HELPER_SETTLE_MS, 500);
}

#[test]
fn counts_a_helper_that_exits_with_success_as_launched() {
    assert!(launch_helper("true", &[]));
}

#[test]
fn counts_a_helper_that_exits_with_failure_as_not_launched() {
    assert!(!launch_helper("false", &[]));
}

#[test]
fn counts_a_helper_that_cannot_start_as_not_launched() {
    assert!(!launch_helper("/nonexistent/browser-helper", &[]));
}

#[test]
fn counts_a_helper_still_running_after_the_settle_time_as_launched() {
    let started = Instant::now();

    assert!(launch_helper("sleep", &["5".to_string()]));

    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(HELPER_SETTLE_MS));
    assert!(elapsed < Duration::from_secs(5));
}
