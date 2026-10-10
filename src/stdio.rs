use serde_json::Value;

#[derive(Default)]
pub struct ReadBuffer {
    buffer: Vec<u8>,
}

impl ReadBuffer {
    pub fn append(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
    }

    pub fn read_message(&mut self) -> Option<Result<Value, serde_json::Error>> {
        let index = self.buffer.iter().position(|byte| *byte == b'\n')?;
        let line_bytes: Vec<u8> = self.buffer.drain(..=index).collect();
        let line = String::from_utf8_lossy(&line_bytes[..index]);
        let line = line.strip_suffix('\r').unwrap_or(&line);
        Some(serde_json::from_str(line))
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

pub fn serialize_message(message: &Value) -> String {
    format!("{message}\n")
}
