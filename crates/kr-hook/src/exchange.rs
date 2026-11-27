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
    ///
    /// This says that the connection ended and that no admission came. It does not say why: a
    /// worker that refused the bridge, one that could not place the process that connected and one
    /// that died after it accepted the connection all read the same here, and so does the
    /// operating system's own close of what a worker left open. It is the one answer to that event
    /// whichever side was first, for the error kinds that [`kr_ipc::error::peer_has_gone`]
    /// recognises: a read of the admission that finds the connection closed, and a write of the
    /// hello that fails with one of those kinds, are the same refusal. A hello write that fails
    /// with any other kind is [`ExchangeError::Broken`]; [`Exchange::open`] says what that leaves
    /// out.
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
    /// The worker's close can also come before the hello itself is written: the connection is made
    /// before the hello is built, and the worker may accept it, find nothing it can admit and close
    /// it in between. A hello that finds the connection closed by the other end is
    /// [`ExchangeError::Refused`], the same answer as a read of the admission that finds it closed.
    /// What counts as closed by the other end is the one rule of [`kr_ipc::error::peer_has_gone`],
    /// the rule every other write, read and shutdown of a local stream follows: a broken pipe, a
    /// reset, and "not connected", which a write that races the close gets on macOS. That claims
    /// that the connection closed and that no admission came. It does not claim why: a worker that
    /// died after it accepted the connection leaves the same error behind as one that refused the
    /// bridge. A write that fails for any other reason stays [`ExchangeError::Broken`] with the
    /// system's words.
    ///
    /// The rule reads the error's kind, so it reaches only the errors that the standard library
    /// gives a kind. On Windows, the standard library of the toolchain this repository pins reads
    /// a named pipe's broken-pipe (109) and no-data (232) errors as a broken pipe, which the rule
    /// recognises. It gives the "pipe is not connected" error (233) the kind `Uncategorized`, which
    /// the rule does not recognise. That is the error a client's write gets after the server
    /// forcibly disconnects the pipe, as the example for disconnecting a pipe in the Tokio
    /// documentation shows. A hello write that fails with it is [`ExchangeError::Broken`] with the
    /// system's words, not a refusal. Which of these errors a hello write gets when the server
    /// end of the pipe is simply closed has not been measured.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError`] when the registration does not frame as JSON lines, the endpoint
    /// cannot be reached, or the hello cannot be written. The write of the hello is
    /// [`ExchangeError::Refused`] when it fails with an error that
    /// [`kr_ipc::error::peer_has_gone`] recognises, which is how a close by the worker before the
    /// hello was written reads, and [`ExchangeError::Broken`] when it fails with any other.
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
        exchange.introduce(hello.expose()).await?;
        Ok(exchange)
    }

    /// Writes the hello, and says a connection the other end had already closed is a refusal.
    async fn introduce(&mut self, hello: &[u8]) -> Result<(), ExchangeError> {
        check_line(hello)?;
        self.outgoing.put(hello).await.map_err(|error| {
            if kr_ipc::error::peer_has_gone(&error) {
                ExchangeError::Refused
            } else {
                ExchangeError::Broken {
                    detail: error.to_string(),
                }
            }
        })
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
        check_line(body)?;
        self.put(body).await.map_err(|error| ExchangeError::Broken {
            detail: error.to_string(),
        })
    }

    /// Writes one checked message and its newline.
    async fn put(&mut self, body: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(body).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await
    }
}

/// Refuses a message the exchange could not carry whole: one past the bound, or one that holds a
/// newline, which would end it early.
fn check_line(body: &[u8]) -> Result<(), ExchangeError> {
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(ExchangeError::Oversized { bytes: body.len() });
    }
    if body.contains(&b'\n') {
        return Err(ExchangeError::Malformed {
            detail: "carries a newline, which would end it early".to_owned(),
        });
    }
    Ok(())
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
        #[cfg(windows)]
        Endpoint::NamedPipe(name) => {
            let unreachable = |detail: String| ExchangeError::Unreachable {
                endpoint: format!("{}{name}", crate::registration::PIPE_PREFIX),
                detail,
            };
            // The client opens the pipe for identification only and refuses a pipe whose own list
            // is not this account's, so a pipe another account created first is never written to.
            let address = kr_ipc::paths::Endpoint::from_name(name.clone())
                .map_err(|error| unreachable(error.to_string()))?;
            let connection = kr_ipc::endpoint::Connection::connect(&address)
                .await
                .map_err(|error| unreachable(error.to_string()))?;
            let (reader, writer) = tokio::io::split(connection);
            Ok((Box::new(reader), Box::new(writer)))
        }
        #[cfg(not(windows))]
        Endpoint::NamedPipe(name) => Err(ExchangeError::Unreachable {
            endpoint: format!("{}{name}", crate::registration::PIPE_PREFIX),
            detail: "this platform has no named pipe".to_owned(),
        }),
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

    /// On Windows the endpoint a registration names is a local pipe: the bridge opens it with the
    /// client the host's own listener is proved against, and its first frame is the hello that
    /// names the launch's credential and this process as the operating system reads it.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_bridge_reaches_the_pipe_its_registration_names_and_says_who_it_is() {
        use tokio::io::AsyncBufReadExt as _;
        let directory = std::env::temp_dir().join(format!("kr-exch-{}", kr_ipc::new_uuid()));
        kr_ipc::paths::create_private_directory(&directory).expect("a private directory is made");
        let fresh: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect();
        let name = format!("kr-a-{fresh}");
        let credential = "cd".repeat(32);
        let credential_path = directory.join("credential");
        kr_ipc::paths::create_new_owner_only_file(&credential_path, credential.as_bytes())
            .expect("the credential is written");
        let registration_path = directory.join("registration");
        kr_ipc::paths::write_owner_only_file(
            &registration_path,
            format!(
                "endpoint={}{name}\nprofile=lp-1\ninstance=i\npid=1\nstart=2\ncredential={}\n\
                 framing=json_lines\n",
                crate::registration::PIPE_PREFIX,
                credential_path.display()
            )
            .as_bytes(),
        )
        .expect("the registration is written");

        let listener = kr_ipc::endpoint::Listener::bind(
            &kr_ipc::paths::Endpoint::from_name(name).expect("a usable name"),
        )
        .expect("the pipe binds");
        let registration = Registration::read(
            &crate::registration::Paths {
                registration: registration_path,
            },
            Duration::from_secs(5),
        )
        .expect("the registration reads");
        let opening = tokio::spawn(async move {
            Exchange::open(
                &registration,
                Bridge {
                    application: "claude-code".into(),
                    surface: "hook",
                },
            )
            .await
            .expect("the exchange opens")
        });
        let (connection, peer) = listener
            .accept()
            .await
            .expect("the pipe accepts the bridge");
        assert_eq!(
            peer.pid,
            Some(std::process::id()),
            "the kernel names the connecting process"
        );
        let mut reader = tokio::io::BufReader::new(connection);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .expect("the hello is read");
        let hello: serde_json::Value = serde_json::from_str(&line).expect("the hello is JSON");
        assert_eq!(hello["kr_hello"]["credential"], credential);
        assert_eq!(hello["kr_hello"]["pid"], u64::from(std::process::id()));
        assert_eq!(hello["kr_hello"]["bridge"]["application"], "claude-code");
        drop(opening.await.expect("the exchange task finishes"));
        let _ = std::fs::remove_dir_all(&directory);
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

    /// What a stand-in for the worker does with a connection once it has accepted it.
    #[cfg(unix)]
    #[derive(Clone, Copy, Debug)]
    enum WorkerAction {
        /// Closes it without reading a byte, as a worker does that refuses a connection it cannot
        /// place before it has looked at what the connection sent.
        ClosesUnread,
        /// Takes nothing more from it but keeps it open until the bridge is done.
        #[cfg(target_os = "linux")]
        StopsReading,
        /// Reads the whole hello and closes the connection, as a worker does that refuses the
        /// bridge after it has checked it.
        ReadsTheHelloThenCloses,
    }

    /// Writes a bridge's hello to a stand-in worker that does `action` with its connection, waits
    /// for the worker's answer, and returns what the exchange made of the two.
    ///
    /// The order of the hello's write and the worker's close is made certain here rather than
    /// waited for. The hello is nearly as large as the exchange allows, which is more than a socket
    /// holds, so its write cannot complete until the worker reads it. A worker that never reads is
    /// therefore met by a write that is still waiting when the worker closes, whatever the
    /// scheduler does, and nothing but the worker's close or shutdown ends that write.
    ///
    /// That holds where the two buffers of a local socket hold less than the hello, about 1 MiB.
    /// The system's default sizes on macOS and Linux do, by a wide margin; this code does not set
    /// or read the sizes, so a host that raised them past the hello would let the write finish
    /// before the close, and the cases would then pass without reaching a failed write.
    #[cfg(unix)]
    async fn bridge_meets(action: WorkerAction) -> Result<(), ExchangeError> {
        let host = kr_ipc::testing::TempHost::create();
        let path = host.root().join("endpoint");
        let listener = tokio::net::UnixListener::bind(&path).expect("the endpoint binds");
        let credential = host.root().join("credential");
        kr_ipc::paths::create_new_owner_only_file(&credential, "0".repeat(64).as_bytes())
            .expect("the credential is the owner's alone");
        let paths = crate::registration::Paths {
            registration: host.root().join("registration"),
        };
        kr_ipc::paths::write_owner_only_file(
            &paths.registration,
            format!(
                "endpoint={}\nprofile=p\ninstance=i\npid=1\nstart=1\ncredential={}\n\
                 framing=json_lines\n",
                path.display(),
                credential.display()
            )
            .as_bytes(),
        )
        .expect("the registration");
        let registration =
            Registration::read(&paths, Duration::from_secs(5)).expect("the registration reads");
        let bridge = Bridge {
            application: "x".repeat(MAX_MESSAGE_BYTES - 4096).into(),
            surface: "hook",
        };

        let bridging = async {
            let mut exchange = Exchange::open(&registration, bridge).await?;
            exchange.admitted(Duration::from_secs(10)).await
        };
        let worker = async {
            let (stream, _) = listener.accept().await.expect("the worker accepts");
            match action {
                WorkerAction::ClosesUnread => {
                    drop(stream);
                    None::<std::os::unix::net::UnixStream>
                }
                #[cfg(target_os = "linux")]
                WorkerAction::StopsReading => {
                    let stream = stream.into_std().expect("the connection is a plain socket");
                    stream
                        .shutdown(std::net::Shutdown::Read)
                        .expect("the read side shuts");
                    Some(stream)
                }
                WorkerAction::ReadsTheHelloThenCloses => {
                    let mut reader = BufReader::new(stream);
                    let mut hello = Vec::new();
                    reader
                        .read_until(b'\n', &mut hello)
                        .await
                        .expect("the hello arrives");
                    assert!(hello.starts_with(br#"{"kr_hello":"#));
                    None
                }
            }
        };
        let (answer, _held) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(bridging, worker)
        })
        .await
        .expect("the exchange and the worker both finish");
        answer
    }

    /// A worker that refuses a connection can close it before it reads the hello, and the hello's
    /// write then finds the connection gone. The worker closed the connection without admitting the
    /// bridge, which is what the exchange says of every other order of the same event.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_worker_that_closes_before_it_reads_the_hello_is_a_refusal() {
        let answer = bridge_meets(WorkerAction::ClosesUnread).await;
        assert!(
            matches!(answer, Err(ExchangeError::Refused)),
            "a close before the hello is read is a refusal: {answer:?}"
        );
    }

    /// The same event with the worker's end still open but shut for reading.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_worker_that_stops_reading_before_the_hello_is_read_is_a_refusal() {
        let answer = bridge_meets(WorkerAction::StopsReading).await;
        assert!(
            matches!(answer, Err(ExchangeError::Refused)),
            "a worker that takes nothing more is a refusal: {answer:?}"
        );
    }

    /// A writer whose every write fails with the kind it was given, as a connection does that the
    /// other end has closed or that the system has failed.
    struct FailingWriter(std::io::ErrorKind);

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::from(self.0)))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// What the exchange makes of a hello of `size` bytes whose write fails with `kind`.
    async fn introduction_failing_with(kind: std::io::ErrorKind, size: usize) -> ExchangeError {
        let mut exchange = Exchange {
            incoming: Incoming {
                reader: BufReader::new(Box::new(tokio::io::empty())),
            },
            outgoing: Outgoing {
                writer: Box::new(FailingWriter(kind)),
            },
        };
        exchange
            .introduce(&vec![b'x'; size])
            .await
            .expect_err("the write fails")
    }

    /// Each kind that the IPC crate's one rule reads as a peer that has gone is the refusal when it
    /// is what the write of the hello answers, whatever the system's words for it are: a broken
    /// pipe, a reset, and "not connected", which a write that races the close gets on macOS.
    #[tokio::test]
    async fn each_kind_of_a_closed_connection_is_a_refusal_when_the_hello_is_written() {
        for kind in [
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::NotConnected,
        ] {
            let error = introduction_failing_with(kind, 8).await;
            assert!(
                matches!(error, ExchangeError::Refused),
                "{kind:?} is a closed connection: {error:?}"
            );
        }
    }

    /// A write that fails for any other reason is not a closed connection, and keeps the system's
    /// words, as does a hello the exchange refuses to write at all, even where the writer would have
    /// said the connection was closed.
    #[tokio::test]
    async fn a_write_that_fails_for_another_reason_keeps_its_own_words() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::WriteZero,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::Other,
        ] {
            let error = introduction_failing_with(kind, 8).await;
            assert!(
                matches!(&error, ExchangeError::Broken { detail }
                    if *detail == std::io::Error::from(kind).to_string()),
                "{kind:?} stays a failure of the exchange, with the system's words: {error:?}"
            );
        }
        let oversized =
            introduction_failing_with(std::io::ErrorKind::BrokenPipe, MAX_MESSAGE_BYTES + 1).await;
        assert!(
            matches!(oversized, ExchangeError::Oversized { .. }),
            "a hello past the bound is never written: {oversized:?}"
        );
    }

    /// Whichever side is first, the worker's close is the same event and the exchange says it in
    /// the same words: the hook prints them after its own name, and exits and answers the same
    /// whatever they are.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_orders_of_a_refusal_say_the_same_words() {
        let expected = "the worker closed the connection without admitting this bridge";
        let orders = [
            WorkerAction::ClosesUnread,
            WorkerAction::ReadsTheHelloThenCloses,
            #[cfg(target_os = "linux")]
            WorkerAction::StopsReading,
        ];
        for order in orders {
            let said = bridge_meets(order)
                .await
                .expect_err("the bridge is not admitted")
                .to_string();
            assert_eq!(said, expected, "{order:?}");
        }
    }

    /// A worker that reads the hello and then closes is a refusal too, from the read that follows.
    /// This case holds the read side of the same answer and is green with or without the mapping of
    /// a failed hello write.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_worker_that_reads_the_hello_and_closes_is_a_refusal() {
        let answer = bridge_meets(WorkerAction::ReadsTheHelloThenCloses).await;
        assert!(
            matches!(answer, Err(ExchangeError::Refused)),
            "a close after the hello is read is a refusal: {answer:?}"
        );
    }
}
