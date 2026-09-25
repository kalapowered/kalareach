//! The private exchange between a native bridge and the worker's endpoint.
//!
//! One connection per bridge process. It opens with the hello the registration builds and a
//! declaration of which bridge this is; the worker authenticates the connection against the launch
//! and the installation and, only if it admits it, answers with one admission frame. Everything
//! after that is one JSON document per line, in both directions, each at most
//! [`MAX_MESSAGE_BYTES`], which is the bound the Claude Code connector package declares for this
//! exchange.
//!
//! A line longer than the bound is not skipped or truncated: the exchange ends. A frame that
//! arrives in pieces is read whole or not at all, so a document that was cut short is never
//! handed on as though it were complete.

use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::io::{AsyncWriteExt as _, BufReader};

use crate::registration::{Bridge, Endpoint, FramingName, Registration, RegistrationError};

/// The most one message on the exchange may carry, in bytes, not counting its newline.
///
/// It is `max_message_bytes` from the Claude Code connector package's `connector.json`, and the
/// same bound the worker's gateway reads a native frame with.
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

/// Why the exchange could not be used.
#[derive(Debug)]
pub enum ExchangeError {
    /// The registration could not be read or used.
    Registration(RegistrationError),
    /// The worker's endpoint could not be reached.
    Unreachable {
        /// Where it was looked for.
        endpoint: String,
        /// What connecting said.
        detail: String,
    },
    /// The worker closed the connection without admitting this bridge.
    Refused,
    /// The worker did not answer in time.
    TimedOut,
    /// Reading or writing the connection failed.
    Broken {
        /// What failed.
        detail: String,
    },
    /// A message was longer than the exchange's bound.
    Oversized {
        /// How many bytes it had reached when it was given up.
        bytes: usize,
    },
    /// A message was not the JSON object the exchange carries.
    Malformed {
        /// What was wrong with it.
        detail: String,
    },
}

impl std::fmt::Display for ExchangeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration(error) => error.fmt(formatter),
            Self::Unreachable { endpoint, detail } => {
                write!(
                    formatter,
                    "the worker at {endpoint} could not be reached: {detail}"
                )
            }
            Self::Refused => formatter
                .write_str("the worker closed the connection without admitting this bridge"),
            Self::TimedOut => formatter.write_str("the worker did not answer in time"),
            Self::Broken { detail } => write!(formatter, "the exchange failed: {detail}"),
            Self::Oversized { bytes } => write!(
                formatter,
                "a message reached {bytes} bytes, past the exchange's bound of {MAX_MESSAGE_BYTES}"
            ),
            Self::Malformed { detail } => write!(formatter, "a message {detail}"),
        }
    }
}

impl std::error::Error for ExchangeError {}

impl From<RegistrationError> for ExchangeError {
    fn from(error: RegistrationError) -> Self {
        Self::Registration(error)
    }
}

/// The receiving half of an exchange.
pub struct Incoming {
    reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
}

/// The sending half of an exchange.
pub struct Outgoing {
    writer: Box<dyn AsyncWrite + Unpin + Send>,
}

/// One bridge's connection to the worker, both halves.
pub struct Exchange {
    incoming: Incoming,
    outgoing: Outgoing,
}

impl Exchange {
    /// Connects to the registration's endpoint and writes the hello that declares this bridge.
    ///
    /// Nothing else is written here; the worker's answer is [`Exchange::admitted`]. A hook writes
    /// its one observation straight after the hello, as a pipelined request is written: the worker
    /// reads nothing past the hello until it has authenticated the connection. A worker that
    /// refuses closes the connection without reading further, and that can happen before the
    /// observation is written, so a write behind the hello can find the connection gone. A caller
    /// that writes ahead therefore reads the worker's answer before it counts a failed write.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError`] when the registration does not frame as JSON lines, the endpoint
    /// cannot be reached, or the hello cannot be written.
    pub async fn open(registration: &Registration, bridge: Bridge) -> Result<Self, ExchangeError> {
        if registration.framing != FramingName::JsonLines {
            return Err(ExchangeError::Registration(RegistrationError::Malformed {
                detail: "names a framing other than the JSON lines this bridge speaks".to_owned(),
            }));
        }
        let (reader, writer) = connect(&registration.endpoint).await?;
        let mut exchange = Self {
            incoming: Incoming {
                reader: BufReader::new(reader),
            },
            outgoing: Outgoing { writer },
        };
        let hello = registration.hello(Some(bridge))?;
        exchange.outgoing.write_line(hello.expose()).await?;
        Ok(exchange)
    }

    /// Waits for the worker to say it admitted this bridge.
    ///
    /// The worker answers an admitted connection with one frame, `{"kr_bridge":{"admitted":...}}`,
    /// and closes a refused one without a word, so a refusal tells the connecting side nothing it
    /// could use to try again differently.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError::Refused`] when the connection closes first, [`ExchangeError::TimedOut`]
    /// when nothing arrives within `within`, and [`ExchangeError::Malformed`] for any other frame.
    pub async fn admitted(&mut self, within: Duration) -> Result<(), ExchangeError> {
        let frame = tokio::time::timeout(within, self.incoming.receive())
            .await
            .map_err(|_| ExchangeError::TimedOut)?
            .map_err(|error| match error {
                ExchangeError::Broken { .. } => ExchangeError::Refused,
                other => other,
            })?
            .ok_or(ExchangeError::Refused)?;
        if frame
            .get("kr_bridge")
            .and_then(|admission| admission.get("admitted"))
            .is_some_and(serde_json::Value::is_string)
        {
            Ok(())
        } else {
            Err(ExchangeError::Malformed {
                detail: "arrived where the worker's admission belongs".to_owned(),
            })
        }
    }

    /// Writes one message.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError::Oversized`] for a message past the bound, and
    /// [`ExchangeError::Broken`] when the write fails.
    pub async fn send(&mut self, message: &serde_json::Value) -> Result<(), ExchangeError> {
        self.outgoing.send(message).await
    }

    /// Reads one message, or `None` when the worker has closed the connection.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError`] when the message is past the bound or is not a JSON object.
    pub async fn receive(&mut self) -> Result<Option<serde_json::Value>, ExchangeError> {
        self.incoming.receive().await
    }

    /// Separates the two directions, so each can be served by its own task.
    #[must_use]
    pub fn split(self) -> (Incoming, Outgoing) {
        (self.incoming, self.outgoing)
    }
}

impl Incoming {
    /// Reads one message, or `None` when the worker has closed the connection.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError`] when the message is past the bound or is not a JSON object.
    pub async fn receive(&mut self) -> Result<Option<serde_json::Value>, ExchangeError> {
        let Some(line) = read_line(&mut self.reader).await? else {
            return Ok(None);
        };
        let value: serde_json::Value =
            serde_json::from_slice(&line).map_err(|error| ExchangeError::Malformed {
                detail: format!("is not JSON: {error}"),
            })?;
        if !value.is_object() {
            return Err(ExchangeError::Malformed {
                detail: "is JSON but not an object".to_owned(),
            });
        }
        Ok(Some(value))
    }
}

impl Outgoing {
    /// Writes one message.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError::Oversized`] for a message past the bound, and
    /// [`ExchangeError::Broken`] when the write fails.
    pub async fn send(&mut self, message: &serde_json::Value) -> Result<(), ExchangeError> {
        let body = serde_json::to_vec(message).map_err(|error| ExchangeError::Malformed {
            detail: format!("cannot be written: {error}"),
        })?;
        self.write_line(&body).await
    }

    /// Closes this direction, so the worker reads the end of what this bridge sends.
    pub async fn close(&mut self) {
        let _ = self.writer.shutdown().await;
    }

    async fn write_line(&mut self, body: &[u8]) -> Result<(), ExchangeError> {
        if body.len() > MAX_MESSAGE_BYTES {
            return Err(ExchangeError::Oversized { bytes: body.len() });
        }
        if body.contains(&b'\n') {
            return Err(ExchangeError::Malformed {
                detail: "carries a newline, which would end it early".to_owned(),
            });
        }
        let broken = |error: std::io::Error| ExchangeError::Broken {
            detail: error.to_string(),
        };
        self.writer.write_all(body).await.map_err(broken)?;
        self.writer.write_all(b"\n").await.map_err(broken)?;
        self.writer.flush().await.map_err(broken)
    }
}

/// Reads one line of at most [`MAX_MESSAGE_BYTES`] and its newline, without the newline.
///
/// `None` is a connection that ended cleanly between lines. A connection that ends in the middle
/// of a line has sent a message nobody can know is whole, and that is an error rather than a
/// shorter message.
async fn read_line<R>(reader: &mut R) -> Result<Option<Vec<u8>>, ExchangeError>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let limit = u64::try_from(MAX_MESSAGE_BYTES + 1).unwrap_or(u64::MAX);
    let read = (&mut *reader)
        .take(limit)
        .read_until(b'\n', &mut line)
        .await
        .map_err(|error| ExchangeError::Broken {
            detail: error.to_string(),
        })?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(Some(line));
    }
    if line.len() > MAX_MESSAGE_BYTES {
        return Err(ExchangeError::Oversized { bytes: line.len() });
    }
    Err(ExchangeError::Broken {
        detail: "the connection ended in the middle of a message".to_owned(),
    })
}

type Halves = (
    Box<dyn AsyncRead + Unpin + Send>,
    Box<dyn AsyncWrite + Unpin + Send>,
);

async fn connect(endpoint: &Endpoint) -> Result<Halves, ExchangeError> {
    match endpoint {
        #[cfg(unix)]
        Endpoint::PrivateSocket(path) => {
            let stream = tokio::net::UnixStream::connect(path)
                .await
                .map_err(|error| ExchangeError::Unreachable {
                    endpoint: path.display().to_string(),
                    detail: error.to_string(),
                })?;
            let (reader, writer) = stream.into_split();
            Ok((Box::new(reader), Box::new(writer)))
        }
        #[cfg(not(unix))]
        Endpoint::PrivateSocket(path) => Err(ExchangeError::Unreachable {
            endpoint: path.display().to_string(),
            detail: "this platform has no private socket".to_owned(),
        }),
        Endpoint::Loopback(address) => {
            let stream = tokio::net::TcpStream::connect(address)
                .await
                .map_err(|error| ExchangeError::Unreachable {
                    endpoint: address.to_string(),
                    detail: error.to_string(),
                })?;
            let (reader, writer) = stream.into_split();
            Ok((Box::new(reader), Box::new(writer)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn lines(input: &[u8]) -> Vec<Result<Option<Vec<u8>>, String>> {
        let mut reader = BufReader::new(input);
        let mut read = Vec::new();
        loop {
            let next = read_line(&mut reader)
                .await
                .map_err(|error| error.to_string());
            let done = !matches!(next, Ok(Some(_)));
            read.push(next);
            if done {
                return read;
            }
        }
    }

    #[tokio::test]
    async fn a_line_is_read_whole_and_a_cut_one_is_refused() {
        let read = lines(b"{\"a\":1}\n{\"b\":2}\n").await;
        assert_eq!(read[0], Ok(Some(b"{\"a\":1}".to_vec())));
        assert_eq!(read[1], Ok(Some(b"{\"b\":2}".to_vec())));
        assert_eq!(read[2], Ok(None));

        let cut = lines(b"{\"a\":1}\n{\"b\":").await;
        assert!(cut[1].as_ref().is_err_and(|error| error.contains("middle")));
    }

    #[tokio::test]
    async fn a_line_past_the_bound_ends_the_exchange() {
        let mut oversized = vec![b'x'; MAX_MESSAGE_BYTES + 1];
        oversized.push(b'\n');
        let read = lines(&oversized).await;
        assert!(read[0].as_ref().is_err_and(|error| error.contains("bound")));

        // Exactly the bound is a message.
        let mut largest = vec![b'x'; MAX_MESSAGE_BYTES];
        largest.push(b'\n');
        let read = lines(&largest).await;
        assert_eq!(
            read[0].as_ref().map(|line| line.as_ref().map(Vec::len)),
            Ok(Some(MAX_MESSAGE_BYTES))
        );
    }

    #[tokio::test]
    async fn only_a_json_object_is_a_message() {
        for (input, accepted) in [
            (&b"{\"method\":\"x\"}\n"[..], true),
            (&b"[1,2]\n"[..], false),
            (&b"not json\n"[..], false),
        ] {
            let mut incoming = Incoming {
                reader: BufReader::new(Box::new(input) as Box<dyn AsyncRead + Unpin + Send>),
            };
            assert_eq!(
                incoming.receive().await.is_ok(),
                accepted,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[tokio::test]
    async fn a_message_past_the_bound_or_with_a_newline_is_not_written() {
        let mut outgoing = Outgoing {
            writer: Box::new(tokio::io::sink()),
        };
        let oversized = serde_json::Value::String("x".repeat(MAX_MESSAGE_BYTES));
        assert!(matches!(
            outgoing.send(&oversized).await,
            Err(ExchangeError::Oversized { .. })
        ));
        assert!(matches!(
            outgoing.write_line(b"{}\n{}").await,
            Err(ExchangeError::Malformed { .. })
        ));
        outgoing
            .send(&serde_json::json!({"method": "x"}))
            .await
            .expect("an ordinary message is written");
    }
}
