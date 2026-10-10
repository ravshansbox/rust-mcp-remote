use rust_mcp_remote::stdio::{ReadBuffer, serialize_message};
use serde_json::json;

#[test]
fn empty_buffer_has_no_message() {
    let mut buffer = ReadBuffer::default();
    assert!(buffer.read_message().is_none());
}

#[test]
fn partial_line_waits_for_newline() {
    let mut buffer = ReadBuffer::default();
    buffer.append(br#"{"jsonrpc":"2.0","id":1,"#);
    assert!(buffer.read_message().is_none());
    buffer.append(b"\"method\":\"ping\"}\n");
    assert_eq!(
        buffer.read_message().unwrap().unwrap(),
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    );
    assert!(buffer.read_message().is_none());
}

#[test]
fn reads_several_messages_from_one_chunk_and_strips_carriage_return() {
    let mut buffer = ReadBuffer::default();
    buffer.append(
        b"{\"jsonrpc\":\"2.0\",\"method\":\"a\"}\r\n{\"jsonrpc\":\"2.0\",\"method\":\"b\"}\n",
    );
    assert_eq!(buffer.read_message().unwrap().unwrap()["method"], "a");
    assert_eq!(buffer.read_message().unwrap().unwrap()["method"], "b");
    assert!(buffer.read_message().is_none());
}

#[test]
fn invalid_json_line_is_an_error_and_is_consumed() {
    let mut buffer = ReadBuffer::default();
    buffer.append(b"not json\n{\"jsonrpc\":\"2.0\",\"method\":\"ok\"}\n");
    assert!(buffer.read_message().unwrap().is_err());
    assert_eq!(buffer.read_message().unwrap().unwrap()["method"], "ok");
}

#[test]
fn multibyte_character_split_across_chunks_is_joined() {
    let mut buffer = ReadBuffer::default();
    let line = "{\"jsonrpc\":\"2.0\",\"method\":\"é\"}\n".as_bytes();
    let split = line.iter().position(|byte| *byte == 0xC3).unwrap() + 1;
    buffer.append(&line[..split]);
    assert!(buffer.read_message().is_none());
    buffer.append(&line[split..]);
    assert_eq!(buffer.read_message().unwrap().unwrap()["method"], "é");
}

#[test]
fn clear_drops_buffered_bytes() {
    let mut buffer = ReadBuffer::default();
    buffer.append(b"{\"jsonrpc\":\"2.0\",\"method\":\"a\"}\n");
    buffer.clear();
    assert!(buffer.read_message().is_none());
}

#[test]
fn serialize_message_is_json_followed_by_newline() {
    assert_eq!(
        serialize_message(&json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n"
    );
}
