use rust_mcp_remote::sse::{EventSourceParser, SseEvent, SseItem};

fn event(id: Option<&str>, name: Option<&str>, data: &str) -> SseItem {
    SseItem::Event(SseEvent {
        id: id.map(str::to_owned),
        event: name.map(str::to_owned),
        data: data.to_owned(),
    })
}

#[test]
fn dispatches_an_event_at_a_blank_line() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"id: 7\nevent: message\ndata: {\"a\":1}\n\n"),
        vec![event(Some("7"), Some("message"), "{\"a\":1}")]
    );
}

#[test]
fn joins_data_lines_with_newlines_and_accepts_any_line_ending() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"data: one\r\ndata:two\rdata\r\n\r\n"),
        vec![event(None, None, "one\ntwo\n")]
    );
}

#[test]
fn keeps_an_unfinished_line_for_the_next_chunk_including_a_trailing_cr() {
    let mut parser = EventSourceParser::new();
    assert!(parser.feed(b"da").is_empty());
    assert!(parser.feed(b"ta: x\r").is_empty());
    assert_eq!(parser.feed(b"\n\r\n"), vec![event(None, None, "x")]);
}

#[test]
fn splits_a_multibyte_character_across_chunks_without_damage() {
    let mut parser = EventSourceParser::new();
    let bytes = "data: \u{00e9}\n\n".as_bytes();
    assert!(parser.feed(&bytes[..7]).is_empty());
    assert_eq!(
        parser.feed(&bytes[7..]),
        vec![event(None, None, "\u{00e9}")]
    );
}

#[test]
fn ignores_comments_and_events_without_data_and_clears_the_id_after_dispatch() {
    let mut parser = EventSourceParser::new();
    assert!(parser.feed(b": ping\n\nid: 1\n\n").is_empty());
    assert_eq!(parser.feed(b"data: a\n\n"), vec![event(None, None, "a")]);
}

#[test]
fn reports_retry_and_rejects_bad_fields() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"retry: 250\nretry: soon\nbogus: 1\n"),
        vec![
            SseItem::Retry(250),
            SseItem::Error("Invalid `retry` value: \"soon\"".to_owned()),
            SseItem::Error("Unknown field \"bogus\"".to_owned()),
        ]
    );
}

#[test]
fn drops_a_leading_bom_and_ids_containing_nul() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"\xEF\xBB\xBFid: a\0b\ndata: x\n\n"),
        vec![event(None, None, "x")]
    );
}

#[test]
fn an_empty_event_field_means_no_event_name() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"event:\ndata: x\n\n"),
        vec![event(None, None, "x")]
    );
}

#[test]
fn truncates_a_long_unknown_field_name_to_twenty_characters() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"abcdefghijklmnopqrstuvwxyz: 1\n"),
        vec![SseItem::Error(
            "Unknown field \"abcdefghijklmnopqrst\u{2026}\"".to_owned()
        )]
    );
}

#[test]
fn strips_only_one_leading_space_from_a_value() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"data:  x \n\n"),
        vec![event(None, None, " x ")]
    );
}

#[test]
fn an_empty_retry_value_is_an_error() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"retry:\n"),
        vec![SseItem::Error("Invalid `retry` value: \"\"".to_owned())]
    );
}

#[test]
fn keeps_a_bom_that_is_not_at_the_start_of_the_stream() {
    let mut parser = EventSourceParser::new();
    assert!(parser.feed(b"data: a").is_empty());
    assert_eq!(
        parser.feed(b"\xEF\xBB\xBF\n\n"),
        vec![event(None, None, "a\u{feff}")]
    );
}

#[test]
fn an_empty_data_line_still_dispatches_an_event() {
    let mut parser = EventSourceParser::new();
    assert_eq!(parser.feed(b"data:\n\n"), vec![event(None, None, "")]);
    assert_eq!(
        parser.feed(b"data\ndata\n\n"),
        vec![event(None, None, "\n")]
    );
}

#[test]
fn a_retry_too_large_for_u64_saturates() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"retry: 99999999999999999999999\n"),
        vec![SseItem::Retry(u64::MAX)]
    );
}

#[test]
fn an_empty_first_chunk_does_not_stop_the_bom_being_dropped() {
    let mut parser = EventSourceParser::new();
    assert!(parser.feed(b"").is_empty());
    assert_eq!(
        parser.feed(b"\xEF\xBB\xBFdata: x\n\n"),
        vec![event(None, None, "x")]
    );
}

#[test]
fn an_unfinished_event_is_kept_until_its_blank_line() {
    let mut parser = EventSourceParser::new();
    assert!(parser.feed(b"id: 3\ndata: a\n").is_empty());
    assert_eq!(parser.feed(b"\n"), vec![event(Some("3"), None, "a")]);
}

#[test]
fn a_value_keeps_every_colon_after_the_first() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"data: a:b: c\n\n"),
        vec![event(None, None, "a:b: c")]
    );
}

#[test]
fn an_empty_id_is_kept_as_an_empty_string() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"id:\ndata: x\n\n"),
        vec![event(Some(""), None, "x")]
    );
}

#[test]
fn a_signed_retry_value_is_an_error() {
    let mut parser = EventSourceParser::new();
    assert_eq!(
        parser.feed(b"retry: -1\nretry: +5\n"),
        vec![
            SseItem::Error("Invalid `retry` value: \"-1\"".to_owned()),
            SseItem::Error("Invalid `retry` value: \"+5\"".to_owned()),
        ]
    );
}

#[test]
fn an_event_name_without_data_does_not_carry_over_to_the_next_event() {
    let mut parser = EventSourceParser::new();
    assert!(parser.feed(b"event: endpoint\n\n").is_empty());
    assert_eq!(parser.feed(b"data: a\n\n"), vec![event(None, None, "a")]);
}
