use std::time::{Duration, UNIX_EPOCH};

use rust_mcp_remote::logging::{format_debug_message, format_log_line, iso_timestamp};

#[test]
fn iso_timestamp_matches_javascript_to_iso_string() {
    assert_eq!(iso_timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
    assert_eq!(
        iso_timestamp(UNIX_EPOCH + Duration::from_millis(1_760_097_296_789)),
        "2025-10-10T11:54:56.789Z"
    );
    assert_eq!(
        iso_timestamp(UNIX_EPOCH + Duration::from_millis(951_782_400_000)),
        "2000-02-29T00:00:00.000Z"
    );
    assert_eq!(
        iso_timestamp(UNIX_EPOCH + Duration::from_millis(4_102_444_799_999)),
        "2099-12-31T23:59:59.999Z"
    );
}

#[test]
fn iso_timestamp_truncates_below_a_millisecond() {
    assert_eq!(
        iso_timestamp(UNIX_EPOCH + Duration::from_micros(1_999)),
        "1970-01-01T00:00:00.001Z"
    );
}

#[test]
fn iso_timestamp_handles_times_before_the_epoch() {
    assert_eq!(
        iso_timestamp(UNIX_EPOCH - Duration::from_millis(1)),
        "1969-12-31T23:59:59.999Z"
    );
}

#[test]
fn debug_message_starts_with_timestamp_and_pid() {
    assert_eq!(
        format_debug_message("2025-10-10T11:54:56.789Z", 4242, "Connecting"),
        "[2025-10-10T11:54:56.789Z][4242] Connecting"
    );
}

#[test]
fn log_line_starts_with_pid() {
    assert_eq!(
        format_log_line(4242, "Proxy established"),
        "[4242] Proxy established"
    );
}
