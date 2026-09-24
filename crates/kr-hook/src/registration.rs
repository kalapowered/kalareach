//! Where a launch's registration is, what it says, and the hello this forwarder builds from it.
//!
//! The worker publishes two files for every launch it makes. The registration file is the small
//! file section 11 prefers: where to connect, which launch, which process the worker expects, and
//! how the connection frames. It carries nothing secret. The credential file holds the launch's
//! private exchange, and the worker writes it owner-only into an owner-only directory.
//!
//! The environment names the two files and nothing more. [`REGISTRATION_VARIABLE`] and
//! [`CREDENTIAL_VARIABLE`] are paths; a session identifier in the environment is carried in the
//! hello so a person debugging can see what the application thought it was, and it is never
//! authority. A process whose environment names no registration is outside a KalaReach launch, and
//! says so rather than guessing at a socket.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_crypto::secret::SecretVec;

/// The variable that names the registration file.
pub const REGISTRATION_VARIABLE: &str = "KR_REGISTRATION";

/// The variable that names the owner-only file holding the launch's private exchange.
pub const CREDENTIAL_VARIABLE: &str = "KR_CREDENTIAL";

/// The variable that names the session a command is running inside.
///
/// It is read into the hello as a diagnostic and never used to decide anything.
pub const SESSION_VARIABLE: &str = "KR_SESSION";

/// The longest registration file this forwarder reads.
///
/// The worker writes six short lines. Anything longer is not a registration it wrote.
pub const MAX_REGISTRATION_BYTES: u64 = 4096;

/// The longest credential file this forwarder reads.
pub const MAX_CREDENTIAL_BYTES: u64 = 256;

/// The length of a launch credential, in hexadecimal characters.
pub const CREDENTIAL_HEX_LENGTH: usize = 64;

/// How often a file the worker has not written yet is looked for again.
const LOOK_AGAIN: Duration = Duration::from_millis(20);

/// Every field the worker's registration names, each on a line of its own; `framing` is written
/// last.
pub const REGISTRATION_FIELDS: [&str; 6] =
    ["endpoint", "profile", "instance", "pid", "start", "framing"];

/// Why a registration could not be used.
#[derive(Debug)]
pub enum RegistrationError {
    /// The environment names a registration but no credential file.
    NoCredentialNamed,
    /// A file named by the environment did not appear in time.
    Missing {
        /// The file.
        path: PathBuf,
        /// How long it was waited for.
        waited: Duration,
    },
    /// The registration was there, and not yet a whole record, until the wait ended.
    Incomplete {
        /// The file.
        path: PathBuf,
        /// How long it was waited for.
        waited: Duration,
    },
    /// A file could not be read.
    Unreadable {
        /// The file.
        path: PathBuf,
        /// What reading it said.
        detail: String,
    },
    /// The credential file is open to somebody other than this user.
    Exposed {
        /// The file.
        path: PathBuf,
    },
    /// The registration does not say something this forwarder needs, or says it wrongly.
    Malformed {
        /// What is wrong with it.
        detail: String,
    },
    /// This process could not read its own identity from the operating system.
    Unidentified {
        /// What the operating system said.
        detail: String,
    },
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCredentialNamed => write!(
                formatter,
                "{REGISTRATION_VARIABLE} names a registration and {CREDENTIAL_VARIABLE} names no \
                 credential file"
            ),
            Self::Missing { path, waited } => write!(
                formatter,
                "{} did not appear within {} ms",
                path.display(),
                waited.as_millis()
            ),
            Self::Incomplete { path, waited } => write!(
                formatter,
                "{} was not a whole registration within {} ms",
                path.display(),
                waited.as_millis()
            ),
            Self::Unreadable { path, detail } => {
                write!(formatter, "{} could not be read: {detail}", path.display())
            }
            Self::Exposed { path } => write!(
                formatter,
                "{} can be read by somebody other than this user, so it is not presented",
                path.display()
            ),
            Self::Malformed { detail } => write!(formatter, "the registration {detail}"),
            Self::Unidentified { detail } => {
                write!(formatter, "this process cannot be identified: {detail}")
            }
        }
    }
}

impl std::error::Error for RegistrationError {}

/// The two files one launch published, as the environment names them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    /// The registration file.
    pub registration: PathBuf,
    /// The owner-only credential file.
    pub credential: PathBuf,
}

impl Paths {
    /// Reads the two paths from this process's environment.
    ///
    /// Returns `None` when the environment names no registration, which is a process outside any
    /// KalaReach launch. A session identifier alone does not change that: it is not a registration
    /// and it is not a credential.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrationError::NoCredentialNamed`] when a registration is named without a
    /// credential file.
    pub fn from_environment() -> Result<Option<Self>, RegistrationError> {
        let Some(registration) = std::env::var_os(REGISTRATION_VARIABLE) else {
            return Ok(None);
        };
        let credential =
            std::env::var_os(CREDENTIAL_VARIABLE).ok_or(RegistrationError::NoCredentialNamed)?;
        Ok(Some(Self {
            registration: PathBuf::from(registration),
            credential: PathBuf::from(credential),
        }))
    }
}

/// Where the worker's endpoint for this launch is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A socket file inside the worker's owner-only runtime directory.
    PrivateSocket(PathBuf),
    /// Loopback, where the platform has no private socket.
    Loopback(SocketAddr),
}

impl Endpoint {
    /// Reads the endpoint as the registration renders it.
    ///
    /// A private socket is an absolute path and loopback is an address and a port. An address that
    /// is not loopback is refused: nothing this forwarder connects to may be reachable from
    /// another machine.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrationError::Malformed`] for anything else.
    pub fn parse(text: &str) -> Result<Self, RegistrationError> {
        if let Ok(address) = text.parse::<SocketAddr>() {
            if !address.ip().is_loopback() {
                return Err(RegistrationError::Malformed {
                    detail: format!("names {address}, which is not a loopback address"),
                });
            }
            return Ok(Self::Loopback(address));
        }
        let path = Path::new(text);
        if cfg!(unix) && path.is_absolute() {
            return Ok(Self::PrivateSocket(path.to_path_buf()));
        }
        Err(RegistrationError::Malformed {
            detail: format!("names the endpoint {text:?}, which is neither a socket nor loopback"),
        })
    }
}

/// How the worker frames the connection this registration is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramingName {
    /// One JSON document per line.
    JsonLines,
    /// A decimal byte length, a newline, then that many bytes.
    LengthPrefixed,
    /// Header lines, a blank line, then a body of the declared length.
    ContentLength,
}

impl FramingName {
    fn parse(text: &str) -> Result<Self, RegistrationError> {
        match text {
            "json_lines" => Ok(Self::JsonLines),
            "length_prefixed" => Ok(Self::LengthPrefixed),
            "content_length" => Ok(Self::ContentLength),
            other => Err(RegistrationError::Malformed {
                detail: format!("names the framing {other:?}, which this forwarder does not know"),
            }),
        }
    }

    /// Wraps one body the way this framing does.
    #[must_use]
    pub fn encode(self, body: &[u8]) -> Vec<u8> {
        match self {
            Self::JsonLines => {
                let mut framed = Vec::with_capacity(body.len() + 1);
                framed.extend_from_slice(body);
                framed.push(b'\n');
                framed
            }
            Self::LengthPrefixed => {
                let mut framed = format!("{}\n", body.len()).into_bytes();
                framed.extend_from_slice(body);
                framed
            }
            Self::ContentLength => {
                let mut framed = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
                framed.extend_from_slice(body);
                framed
            }
        }
    }
}

/// Which native bridge a connection is, as its hello declares it.
///
/// The worker validates the declaration against the installation it recorded for the launch: the
/// application the installed registration invokes this forwarder for, and the surfaces it
/// registered. A declaration is a claim for the worker to check, not a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bridge {
    /// The application whose registration started this process.
    pub application: &'static str,
    /// Which of its registrations it was.
    pub surface: &'static str,
}

/// One launch's registration, read.
pub struct Registration {
    /// Where to connect.
    pub endpoint: Endpoint,
    /// How the connection frames.
    pub framing: FramingName,
    /// The launch credential, as the hexadecimal the credential file holds.
    credential: SecretVec,
}

impl std::fmt::Debug for Registration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Registration")
            .field("endpoint", &self.endpoint)
            .field("framing", &self.framing)
            .field("credential", &"<redacted>")
            .finish()
    }
}

impl Registration {
    /// Reads both files, waiting up to `within` for the worker to finish writing them.
    ///
    /// The worker writes the registration after it knows which process it started, so a process
    /// started with the registration's path in its environment can look before the file exists.
    /// The worker publishes the registration whole, by a rename, and last, after the credential; a
    /// read that finds the registration empty or cut short is still read again rather than acted
    /// on. The wait is bounded, and it ends as soon as the registration is whole.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrationError`] when a file does not appear, cannot be read, is open to other
    /// users, or does not say what a registration says.
    pub fn read(paths: &Paths, within: Duration) -> Result<Self, RegistrationError> {
        let deadline = Instant::now() + within;
        let text = wait_for_whole(&paths.registration, deadline, within)?;
        let credential = wait_for(&paths.credential, MAX_CREDENTIAL_BYTES, deadline, within)?;
        let credential = SecretVec::new(credential);
        check_owner_only(&paths.credential)?;
        let mut endpoint = None;
        let mut framing = FramingName::JsonLines;
        for line in text.lines() {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            match name.trim() {
                "endpoint" => endpoint = Some(Endpoint::parse(value.trim())?),
                "framing" => framing = FramingName::parse(value.trim())?,
                _ => {}
            }
        }
        let endpoint = endpoint.ok_or_else(|| RegistrationError::Malformed {
            detail: "names no endpoint".to_owned(),
        })?;
        let credential = trimmed(credential);
        if credential.len() != CREDENTIAL_HEX_LENGTH
            || !credential.expose().iter().all(u8::is_ascii_hexdigit)
        {
            return Err(RegistrationError::Malformed {
                detail: format!("credential is not {CREDENTIAL_HEX_LENGTH} hexadecimal characters"),
            });
        }
        Ok(Self {
            endpoint,
            framing,
            credential,
        })
    }

    /// Builds the hello this process writes before anything else, unframed.
    ///
    /// It names the credential, this process by the operating system's own reading of it, the
    /// session identifier the environment carries (a diagnostic), and the bridge this connection
    /// is when it is one. The body is assembled in the host's zeroising buffer at its final size,
    /// because it holds the credential.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrationError::Unidentified`] when this process's identity cannot be read.
    pub fn hello(&self, bridge: Option<Bridge>) -> Result<SecretVec, RegistrationError> {
        let identity =
            kr_ipc::identity::process_start_identity(std::process::id()).map_err(|error| {
                RegistrationError::Unidentified {
                    detail: error.to_string(),
                }
            })?;
        let session = std::env::var(SESSION_VARIABLE).ok();
        let mut rest = serde_json::Map::new();
        rest.insert("pid".to_owned(), serde_json::json!(identity.pid.get()));
        rest.insert(
            "start".to_owned(),
            serde_json::json!(identity.start_value.get()),
        );
        rest.insert("session".to_owned(), serde_json::json!(session));
        rest.insert("headers".to_owned(), serde_json::json!({}));
        if let Some(bridge) = bridge {
            rest.insert(
                "bridge".to_owned(),
                serde_json::json!({
                    "application": bridge.application,
                    "surface": bridge.surface,
                }),
            );
        }
        let rest = serde_json::Value::Object(rest).to_string();
        // `{"kr_hello":{"credential":"<hex>",` then the rest of the object without its opening
        // brace. The credential is hexadecimal, so it needs no escaping.
        let opening: &[u8] = br#"{"kr_hello":{"credential":""#;
        let middle: &[u8] = br#"","#;
        let tail = rest.as_bytes().get(1..).unwrap_or_default();
        let mut body = Vec::with_capacity(
            opening.len() + self.credential.len() + middle.len() + tail.len() + 1,
        );
        body.extend_from_slice(opening);
        body.extend_from_slice(self.credential.expose());
        body.extend_from_slice(middle);
        body.extend_from_slice(tail);
        body.push(b'}');
        Ok(SecretVec::new(body))
    }
}

/// Reads the registration, waiting until the deadline for it to be a whole record.
fn wait_for_whole(
    path: &Path,
    deadline: Instant,
    within: Duration,
) -> Result<String, RegistrationError> {
    let mut seen = false;
    loop {
        // Whether the deadline has passed is decided before the read, so the last read is taken
        // after it: a registration published whole by then is found.
        let expired = Instant::now() >= deadline;
        match read_bounded(path, MAX_REGISTRATION_BYTES) {
            Ok(content) => {
                if let Some(text) = String::from_utf8(content).ok().filter(|text| whole(text)) {
                    return Ok(text);
                }
                seen = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RegistrationError::Unreadable {
                    path: path.to_path_buf(),
                    detail: error.to_string(),
                });
            }
        }
        if expired {
            let path = path.to_path_buf();
            return Err(if seen {
                RegistrationError::Incomplete {
                    path,
                    waited: within,
                }
            } else {
                RegistrationError::Missing {
                    path,
                    waited: within,
                }
            });
        }
        std::thread::sleep(LOOK_AGAIN);
    }
}

/// Whether registration text is a whole record: every field the worker writes, and the line break
/// that ends the last one.
#[must_use]
pub fn whole(text: &str) -> bool {
    text.ends_with('\n')
        && REGISTRATION_FIELDS.iter().all(|field| {
            text.lines().any(|line| {
                line.split_once('=')
                    .is_some_and(|(name, _)| name.trim() == *field)
            })
        })
}

/// Reads one file the worker writes, waiting for it until the deadline.
fn wait_for(
    path: &Path,
    limit: u64,
    deadline: Instant,
    within: Duration,
) -> Result<Vec<u8>, RegistrationError> {
    loop {
        let expired = Instant::now() >= deadline;
        match read_bounded(path, limit) {
            Ok(content) => return Ok(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if expired {
                    return Err(RegistrationError::Missing {
                        path: path.to_path_buf(),
                        waited: within,
                    });
                }
                std::thread::sleep(LOOK_AGAIN);
            }
            Err(error) => {
                return Err(RegistrationError::Unreadable {
                    path: path.to_path_buf(),
                    detail: error.to_string(),
                });
            }
        }
    }
}

/// Reads at most `limit` bytes of one file, and refuses a file longer than that.
fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut content = Vec::new();
    file.take(limit + 1).read_to_end(&mut content)?;
    if content.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("it is longer than {limit} bytes"),
        ));
    }
    Ok(content)
}

/// Refuses a credential file somebody other than this user can read.
///
/// The worker writes the file owner-only into an owner-only directory. One that is open to another
/// account is not a file this forwarder presents: the exchange it holds is already somebody else's
/// too.
#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<(), RegistrationError> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = std::fs::metadata(path).map_err(|error| RegistrationError::Unreadable {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    if metadata.uid() != kr_ipc::paths::current_uid() || metadata.mode() & 0o077 != 0 {
        return Err(RegistrationError::Exposed {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Where the platform has no mode bits to read, the worker publishes no credential file, and one
/// that is there was written by the host's own protected publication or not at all.
#[cfg(not(unix))]
fn check_owner_only(_path: &Path) -> Result<(), RegistrationError> {
    Ok(())
}

/// Drops the whitespace around a credential without leaving an unwiped copy of it.
fn trimmed(credential: SecretVec) -> SecretVec {
    let bytes = credential.expose();
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |last| last + 1);
    let mut kept = Vec::with_capacity(end.saturating_sub(start));
    kept.extend_from_slice(bytes.get(start..end).unwrap_or_default());
    SecretVec::new(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_path_and_loopback_are_endpoints_and_nothing_else_is() {
        if cfg!(unix) {
            assert_eq!(
                Endpoint::parse("/run/kr/a-1.sock").expect("a socket"),
                Endpoint::PrivateSocket(PathBuf::from("/run/kr/a-1.sock"))
            );
        }
        assert_eq!(
            Endpoint::parse("127.0.0.1:49152").expect("loopback"),
            Endpoint::Loopback("127.0.0.1:49152".parse().expect("an address"))
        );
        assert!(Endpoint::parse("[::1]:49152").is_ok());
        for refused in [
            "0.0.0.0:49152",
            "192.0.2.7:49152",
            "example.test:49152",
            "a-1.sock",
            "",
        ] {
            assert!(Endpoint::parse(refused).is_err(), "{refused:?} is refused");
        }
    }

    /// Only a whole record is a registration: every field, and the line break after the last.
    #[test]
    fn a_registration_is_whole_only_when_every_field_and_the_last_line_break_are_there() {
        let complete = "endpoint=/run/kr/a.sock\nprofile=lp-1\ninstance=i\npid=1\nstart=2\n\
                        framing=json_lines\n";
        assert!(whole(complete));
        assert!(!whole(""));
        assert!(!whole(complete.trim_end()));
        assert!(!whole(&complete[..complete.len() / 2]));
        assert!(!whole(
            complete
                .strip_suffix("framing=json_lines\n")
                .expect("the last line")
        ));
    }

    #[test]
    fn each_framing_the_worker_names_is_known() {
        for (name, framing) in [
            ("json_lines", FramingName::JsonLines),
            ("length_prefixed", FramingName::LengthPrefixed),
            ("content_length", FramingName::ContentLength),
        ] {
            assert_eq!(FramingName::parse(name).expect("known"), framing);
        }
        assert!(FramingName::parse("xml").is_err());
        assert_eq!(FramingName::JsonLines.encode(b"{}"), b"{}\n");
        assert_eq!(FramingName::LengthPrefixed.encode(b"{}"), b"2\n{}");
        assert_eq!(
            FramingName::ContentLength.encode(b"{}"),
            b"Content-Length: 2\r\n\r\n{}"
        );
    }

    #[test]
    fn whitespace_around_a_credential_is_dropped() {
        let kept = trimmed(SecretVec::new(b"  ab12\n".to_vec()));
        assert_eq!(kept.expose(), b"ab12");
        assert!(trimmed(SecretVec::new(b" \n".to_vec())).is_empty());
    }
}
