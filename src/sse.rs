/// One dispatched Server-Sent Event, as eventsource-parser reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub id: Option<String>,
    pub event: Option<String>,
    pub data: String,
}

/// What feeding a chunk produced, in place of eventsource-parser's
/// onEvent/onRetry/onError callbacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseItem {
    Event(SseEvent),
    Retry(u64),
    Error(String),
}

/// A streaming Server-Sent Events parser that follows eventsource-parser 3
/// (the parser behind the SDK's EventSourceParserStream): lines end at CR, LF
/// or CRLF, a leading BOM is dropped, `id` is cleared after each dispatch, and
/// an unfinished last line is dropped when the stream ends.
#[derive(Debug, Default)]
pub struct EventSourceParser {
    pending: Vec<u8>,
    seen_first_chunk: bool,
    id: Option<String>,
    event: Option<String>,
    data: String,
    data_lines: usize,
}

impl EventSourceParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Vec<SseItem> {
        let mut chunk = chunk;
        if !self.seen_first_chunk && !chunk.is_empty() {
            self.seen_first_chunk = true;
            chunk = chunk.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(chunk);
        }
        self.pending.extend_from_slice(chunk);

        let mut items = Vec::new();
        let mut start = 0;
        while let Some(offset) = self.pending[start..]
            .iter()
            .position(|byte| *byte == b'\r' || *byte == b'\n')
        {
            let end = start + offset;
            // A CR at the very end may be the first half of a CRLF
            if self.pending[end] == b'\r' && end + 1 == self.pending.len() {
                break;
            }
            let line = String::from_utf8_lossy(&self.pending[start..end]).into_owned();
            start = end + 1;
            if self.pending[end] == b'\r' && self.pending.get(start) == Some(&b'\n') {
                start += 1;
            }
            self.parse_line(&line, &mut items);
        }
        self.pending.drain(..start);
        items
    }

    fn parse_line(&mut self, line: &str, items: &mut Vec<SseItem>) {
        if line.is_empty() {
            if self.data_lines > 0 {
                items.push(SseItem::Event(SseEvent {
                    id: self.id.take(),
                    event: self.event.take(),
                    data: std::mem::take(&mut self.data),
                }));
            }
            self.id = None;
            self.event = None;
            self.data.clear();
            self.data_lines = 0;
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };
        match field {
            "event" => self.event = (!value.is_empty()).then(|| value.to_owned()),
            "data" => {
                if self.data_lines > 0 {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.data_lines += 1;
            }
            "id" => {
                if !value.contains('\0') {
                    self.id = Some(value.to_owned());
                }
            }
            "retry" => {
                if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
                    items.push(SseItem::Retry(value.parse().unwrap_or(u64::MAX)));
                } else {
                    items.push(SseItem::Error(format!(
                        "Invalid `retry` value: \"{value}\""
                    )));
                }
            }
            _ => {
                let shown = if field.chars().count() > 20 {
                    format!("{}\u{2026}", field.chars().take(20).collect::<String>())
                } else {
                    field.to_owned()
                };
                items.push(SseItem::Error(format!("Unknown field \"{shown}\"")));
            }
        }
    }
}
