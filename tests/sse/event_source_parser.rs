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
