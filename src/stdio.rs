use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

pub const STDIO_DEFAULT_MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024;

pub struct ReadBuffer {
    buffer: Vec<u8>,
    max_buffer_size: usize,
}

impl Default for ReadBuffer {
    fn default() -> Self {
        Self::with_max_buffer_size(STDIO_DEFAULT_MAX_BUFFER_SIZE)
    }
}

impl ReadBuffer {
    pub fn with_max_buffer_size(max_buffer_size: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_buffer_size,
        }
    }

    pub fn append(&mut self, chunk: &[u8]) -> Result<(), String> {
        if self.buffer.len() + chunk.len() > self.max_buffer_size {
            self.clear();
            return Err(format!(
                "ReadBuffer exceeded maximum size of {} bytes",
                self.max_buffer_size
            ));
        }
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    /// Returns the next complete line as a JSON-RPC message. Lines that are not
    /// JSON at all are skipped; JSON that is not a JSON-RPC message is an error.
    pub fn read_message(&mut self) -> Option<Result<Value, String>> {
        loop {
            let index = self.buffer.iter().position(|byte| *byte == b'\n')?;
            let line_bytes: Vec<u8> = self.buffer.drain(..=index).collect();
            let line = String::from_utf8_lossy(&line_bytes[..index]);
            let line = line.strip_suffix('\r').unwrap_or(&line);
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                return Some(deserialize_message(value));
            }
        }
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

fn deserialize_message(value: Value) -> Result<Value, String> {
    let is_message = value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && (value.get("method").is_some_and(Value::is_string)
            || (value.get("id").is_some()
                && (value.get("result").is_some() || value.get("error").is_some())));
    if is_message {
        Ok(value)
    } else {
        Err(format!("Invalid JSON-RPC message: {value}"))
    }
}

pub fn serialize_message(message: &Value) -> String {
    format!("{message}\n")
}

/// What a transport reports to its owner, in place of the SDK's
/// onmessage/onerror/onclose callbacks.
#[derive(Debug, Clone, PartialEq)]
pub enum TransportEvent {
    Message(Value),
    Error(String),
    Close,
}

struct ServerInner<W> {
    writer: Mutex<W>,
    closed: AtomicBool,
    events: mpsc::UnboundedSender<TransportEvent>,
    reader: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl<W> ServerInner<W> {
    fn close(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(reader) = self.reader.lock().ok().and_then(|mut handle| handle.take()) {
            reader.abort();
        }
        let _ = self.events.send(TransportEvent::Close);
    }
}

/// Server transport for stdio: reads newline-delimited JSON-RPC from `reader`
/// (stdin) and writes to `writer` (stdout). It closes itself when the reader
/// reaches end-of-file, like the SDK v2 StdioServerTransport.
pub struct StdioServerTransport<W> {
    inner: Arc<ServerInner<W>>,
}

impl<W> Clone for StdioServerTransport<W> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl StdioServerTransport<tokio::io::Stdout> {
    pub fn start_stdio() -> (Self, mpsc::UnboundedReceiver<TransportEvent>) {
        Self::start(
            tokio::io::stdin(),
            tokio::io::stdout(),
            STDIO_DEFAULT_MAX_BUFFER_SIZE,
        )
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> StdioServerTransport<W> {
    pub fn start<R: AsyncRead + Unpin + Send + 'static>(
        mut reader: R,
        writer: W,
        max_buffer_size: usize,
    ) -> (Self, mpsc::UnboundedReceiver<TransportEvent>) {
        let (events, receiver) = mpsc::unbounded_channel();
        let inner = Arc::new(ServerInner {
            writer: Mutex::new(writer),
            closed: AtomicBool::new(false),
            events,
            reader: std::sync::Mutex::new(None),
        });
        let task_inner = Arc::clone(&inner);
        let handle = tokio::spawn(async move {
            let mut read_buffer = ReadBuffer::with_max_buffer_size(max_buffer_size);
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                let count = match reader.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(count) => count,
                    Err(error) => {
                        let _ = task_inner
                            .events
                            .send(TransportEvent::Error(error.to_string()));
                        break;
                    }
                };
                if let Err(error) = read_buffer.append(&chunk[..count]) {
                    let _ = task_inner.events.send(TransportEvent::Error(error));
                    break;
                }
                while let Some(message) = read_buffer.read_message() {
                    let event = match message {
                        Ok(message) => TransportEvent::Message(message),
                        Err(error) => TransportEvent::Error(error),
                    };
                    let _ = task_inner.events.send(event);
                }
            }
            task_inner.close();
        });
        if let Ok(mut reader) = inner.reader.lock() {
            if inner.closed.load(Ordering::SeqCst) {
                handle.abort();
            } else {
                *reader = Some(handle);
            }
        }
        (Self { inner }, receiver)
    }

    pub async fn send(&self, message: &Value) -> Result<(), String> {
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err("StdioServerTransport is closed".to_owned());
        }
        let json = serialize_message(message);
        let mut writer = self.inner.writer.lock().await;
        let result = async {
            writer.write_all(json.as_bytes()).await?;
            writer.flush().await
        }
        .await;
        result.map_err(|error| {
            let message = error.to_string();
            drop(writer);
            let _ = self
                .inner
                .events
                .send(TransportEvent::Error(message.clone()));
            self.inner.close();
            message
        })
    }

    pub fn close(&self) {
        self.inner.close();
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }
}
