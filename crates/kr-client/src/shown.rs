//! Text a diagnostic may show, and the only ways input becomes it.
//!
//! An error message, a `Debug` rendering, a panic, a log field and a line a command prints about a
//! failure or a stored record all reach places their reader did not choose: a terminal someone is
//! sharing, a log that is kept, a report somebody attaches. What this library and the command line
//! take in can carry secrets there: a person's drafts, settings and answers, an address with a user
//! name and a password in front of its host, the bytes a service or a host sent, a file on disk. A
//! decoder's own failure quotes what it was reading, so the path from input to a rendering is often
//! a failure nobody meant to print.
//!
//! So text in a diagnostic is one type, [`Shown`], and it can be built in only four ways:
//!
//! * this program's own words, a `&'static str`;
//! * [`Shown::compose`] over a template of this program's own and parts that are [`Plain`], which
//!   is what [`shown!`](crate::shown!) writes;
//! * a reducer, which turns one kind of input into what may be said of it: [`Shown::address`],
//!   [`Shown::cbor`], [`Shown::json`], [`Shown::io`], [`Shown::frame`], [`Shown::ipc`],
//!   [`Shown::transport`], [`Shown::crypto`], [`Shown::pairing`], [`Shown::qr_payload`],
//!   [`Shown::task`], and for paths [`Shown::root`], [`Shown::within`] and [`Shown::stored`];
//! * a door for text somebody wrote for a person and that is shown on purpose, each taking the one
//!   value it is for: [`Shown::protocol`], [`Shown::service`] and [`Shown::package`].
//!
//! There is no conversion from a `String`. Text that arrived is never a `Shown` until one of these
//! decided what of it may be said, and the decision is in one place for each kind of input.
//!
//! # What `Plain` claims
//!
//! A type is [`Plain`] when its `Display` cannot carry text from input: a number, a switch, this
//! program's words, an identifier that is a UUID or a counter, a code or a state from a fixed
//! vocabulary, an origin that is a scheme, a host and a port by construction. Every such claim is in
//! this file or in the command line's own `shown.rs`, and nowhere else, so the set of claims is one
//! place to read. A path is not `Plain`: a name found in a directory is whatever somebody put there.
//!
//! # How a failure type is held to this
//!
//! Every `Display` in this crate and the command line comes from `thiserror`, over fields that are
//! `Shown`, `Plain`, [`IoFault`] or another failure of the crate, or from
//! [`display_as_said!`](crate::display_as_said!) over [`Said::said`], which returns a `Shown`. An
//! error's `Debug` is its `Display`, through [`debug_as_display!`](crate::debug_as_display!). A test
//! reads both crates' sources and holds every failure type and every `Display` to that, so a new one
//! is held from the day it is written rather than by somebody remembering to add it to a list.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt;
use std::path::Path;

use kr_cbor::CborError;
use kr_crypto::CryptoError;
use kr_ipc::IpcError;
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::FrameError;
use kr_transport::TransportError;
use kr_transport::error::RelayRefusalKind;

/// Text a diagnostic may show.
///
/// See the [module](self) for the only ways one is made. It is read with `Display`, and its
/// `Debug` is the same text quoted.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Shown(Cow<'static, str>);

impl Shown {
    /// This program's own words.
    #[must_use]
    pub const fn said(text: &'static str) -> Self {
        Self(Cow::Borrowed(text))
    }

    /// A template of this program's own with each bare `{}` filled by the next part.
    ///
    /// Sound by its types: the template is this program's text, and a part can only be a value
    /// whose `Display` cannot carry input. `{{` and `}}` are a brace. [`shown!`](crate::shown!)
    /// checks at compile time that every hole is a bare `{}` and that there is one part for each,
    /// so a template that names a variable, formats one another way or miscounts does not build;
    /// called directly, a hole with no part left is written as nothing and a part with no hole is
    /// left out.
    #[must_use]
    pub fn compose(template: &'static str, parts: &[&dyn Plain]) -> Self {
        use fmt::Write as _;

        let mut text = String::with_capacity(template.len() + 16 * parts.len());
        let mut parts = parts.iter();
        let mut characters = template.chars().peekable();
        while let Some(character) = characters.next() {
            match (character, characters.peek()) {
                ('{', Some('{')) | ('}', Some('}')) => {
                    text.push(character);
                    characters.next();
                }
                ('{', Some('}')) => {
                    characters.next();
                    if let Some(part) = parts.next() {
                        let _ = write!(text, "{part}");
                    }
                }
                _ => text.push(character),
            }
        }
        Self(Cow::Owned(text))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The text, owned.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0.into_owned()
    }

    /// Values already decided, one after another with a separator of this program's own.
    #[must_use]
    pub fn joined(parts: impl IntoIterator<Item = Self>, separator: &'static str) -> Self {
        Self::decided(
            parts
                .into_iter()
                .map(Self::into_string)
                .collect::<Vec<_>>()
                .join(separator),
        )
    }

    /// A number, in sixteen hexadecimal digits.
    #[must_use]
    pub fn hexadecimal(value: u64) -> Self {
        Self::decided(format!("{value:016x}"))
    }

    /// Text a reducer or a door in this file has already decided may be said.
    fn decided(text: String) -> Self {
        Self(Cow::Owned(text))
    }

    /* ---------------------------------------------------------------------- */
    /* Reducers                                                                 */
    /* ---------------------------------------------------------------------- */

    /// An address as a diagnostic may name it: the scheme, the host and the port.
    ///
    /// An address may carry a user name and a password in front of its host, and one that does is
    /// carrying a credential in a field that reads like configuration, so it is not printed at all;
    /// neither is the path, the query or the fragment of any address. An address that cannot be
    /// parsed is not printed either, because what cannot be taken apart cannot be shown to be safe.
    #[must_use]
    pub fn address(origin: &str) -> Self {
        match url::Url::parse(origin) {
            Ok(address) if address.username().is_empty() && address.password().is_none() => {
                match (address.host_str(), address.port()) {
                    (Some(host), Some(port)) => {
                        Self::decided(format!("{}://{host}:{port}", address.scheme()))
                    }
                    (Some(host), None) => Self::decided(format!("{}://{host}", address.scheme())),
                    (None, _) => Self::said("<not an address>"),
                }
            }
            Ok(_) | Err(_) => Self::said("<not printed>"),
        }
    }

    /// What a KR-CBOR-1 failure says: the rule it broke and where in the bytes, when the rule has a
    /// place.
    ///
    /// A decoder's own message names what it rejected: a map key, a value, a serde message quoting
    /// the field it was reading, and a location path built out of the map keys above it. None of
    /// that is here. What somebody diagnosing damaged bytes needs is the kind of fault and the
    /// offset, and none of what the bytes held.
    #[must_use]
    pub fn cbor(error: &CborError) -> Self {
        use CborError as Fault;

        let rule = error.rule();
        match error {
            Fault::UnexpectedEnd { offset }
            | Fault::NonShortestInteger { offset }
            | Fault::NonShortestLength { offset }
            | Fault::IndefiniteLength { offset }
            | Fault::BreakOutsideIndefinite { offset }
            | Fault::ReservedAdditionalInfo { offset, .. }
            | Fault::Tag { offset, .. }
            | Fault::Float { offset }
            | Fault::Undefined { offset }
            | Fault::SimpleValue { offset, .. }
            | Fault::NonTextMapKey { offset }
            | Fault::InvalidUtf8 { offset } => crate::shown!("{} at byte {}", rule, *offset),
            Fault::TrailingBytes { count } => {
                crate::shown!("{}: {} bytes follow the value", rule, *count)
            }
            Fault::InputTooLarge { len, limit } => {
                crate::shown!("{}: {} bytes against a limit of {}", rule, *len, *limit)
            }
            Fault::CollectionLimit { len, limit } | Fault::LengthLimit { len, limit } => {
                crate::shown!("{}: {} against a limit of {}", rule, *len, *limit)
            }
            Fault::DepthLimit { limit } | Fault::CountLimit { limit } => {
                crate::shown!("{}: over the limit of {}", rule, *limit)
            }
            _ => crate::shown!("{}", rule),
        }
    }

    /// What a JSON failure says: which kind of failure it was and where in the document, in the
    /// words [`crate::services::json::Unreadable`] says of an answer, so a failure reads the same
    /// wherever it arose.
    ///
    /// `serde_json` names the value it rejected in its own message, and that value is a request
    /// body, an answer or a stored token. Both of what this keeps are useful to somebody diagnosing
    /// a mismatch, and neither is anything the document held.
    #[must_use]
    pub fn json(error: &serde_json::Error) -> Self {
        crate::shown!("{}", crate::services::json::Unreadable::from(error))
    }

    /// What an I/O failure says: its kind, and the operating system's code when it has one.
    ///
    /// An I/O failure can carry anything as its payload: a library puts a message there, and a
    /// reader passed in from elsewhere can put the bytes it failed on. So a payload is not said
    /// unless it is a `Shown` this program put there itself.
    #[must_use]
    pub fn io(error: &std::io::Error) -> Self {
        if let Some(code) = error.raw_os_error() {
            return crate::shown!("{} (os error {})", error.kind(), code);
        }
        if let Some(said) = error
            .get_ref()
            .and_then(|payload| payload.downcast_ref::<Self>())
        {
            return said.clone();
        }
        crate::shown!("{}", error.kind())
    }

    /// What a frame failure says: its size or shape, and a decode failure through [`Self::cbor`].
    #[must_use]
    pub fn frame(error: &FrameError) -> Self {
        match error {
            FrameError::PayloadTooLarge { len, limit } => {
                crate::shown!("frame of {} bytes exceeds the {}-byte limit", *len, *limit)
            }
            FrameError::EmptyPayload => Self::said("a frame payload cannot be empty"),
            FrameError::Incomplete { needed } => crate::shown!("{} more byte(s) needed", *needed),
            FrameError::HeaderTooLarge { len, limit } => crate::shown!(
                "stream header of {} bytes exceeds the {}-byte limit",
                *len,
                *limit
            ),
            FrameError::Cbor(error) => Self::cbor(error),
        }
    }

    /// What a local connection's failure says.
    ///
    /// A path is said as [`Self::host_path`] says it: the configured roots whole, and below them
    /// only the names this installation's tree writes. What a peer offered, what a marker on disk
    /// named and what the operating system described are not said; I/O goes through [`Self::io`]
    /// and frames through [`Self::frame`].
    #[must_use]
    pub fn ipc(error: &IpcError) -> Self {
        match error {
            IpcError::Io {
                operation,
                path,
                source,
            } => crate::shown!(
                "{} {}: {}",
                *operation,
                Self::host_path(path),
                Self::io(source)
            ),
            IpcError::Socket { operation, source } => {
                crate::shown!("{}: {}", *operation, Self::io(source))
            }
            IpcError::DirectoryNotOwnerOnly {
                path,
                expected_uid,
                found_uid,
                found_mode,
            } => crate::shown!(
                "{} must be owned by user {} with mode 0700, found owner {} and mode {}",
                Self::host_path(path),
                *expected_uid,
                *found_uid,
                Self::decided(format!("{found_mode:04o}"))
            ),
            IpcError::DirectoryAccessRefused { path, .. } => {
                crate::shown!("{} is not owner-only", Self::host_path(path))
            }
            IpcError::SocketPathTooLong { path, len, limit } => crate::shown!(
                "socket path {} is {} bytes, over the {}-byte platform limit",
                Self::host_path(path),
                *len,
                *limit
            ),
            IpcError::PeerRejected {
                peer_uid,
                owner_uid,
            } => crate::shown!(
                "peer user {} may not use an endpoint owned by user {}",
                *peer_uid,
                *owner_uid
            ),
            IpcError::PeerUnknown { source } => crate::shown!(
                "the operating system did not report the peer's credentials: {}",
                Self::io(source)
            ),
            IpcError::Frame(error) => crate::shown!("frame: {}", Self::frame(error)),
            IpcError::PeerClosed => Self::said("the peer closed the connection"),
            IpcError::UnexpectedMessage(what) => crate::shown!("unexpected message: {}", *what),
            IpcError::VersionMismatch { .. } => {
                Self::said("no shared protocol major: the peer offered none this host speaks")
            }
            IpcError::EnvironmentPrefixCollision { path, .. } => crate::shown!(
                "{} belongs to another environment than the one asked for",
                Self::host_path(path)
            ),
            IpcError::TruncatedFrame { received, expected } => crate::shown!(
                "the stream ended after {} of {} bytes of a frame",
                *received,
                *expected
            ),
            IpcError::UntrustedFile { path, reason } => {
                crate::shown!("{}: {}", Self::host_path(path), *reason)
            }
            IpcError::IdentityUnavailable { what, .. } => {
                crate::shown!("{} is not available", *what)
            }
            _ => Self::said("the local connection failed"),
        }
    }

    /// What a connection's failure says.
    ///
    /// What a relay, a peer or a configuration wrote is not said, and neither is the text the
    /// connection library gives for a failure of its own, which carries addresses: a refusing relay
    /// is named by its host and the kind of refusal, and a handshake refusal by the protocol
    /// error's own message, which [`Self::protocol`] says.
    #[must_use]
    pub fn transport(error: &TransportError) -> Self {
        match error {
            TransportError::Configuration { kind, .. } => {
                crate::shown!("the configured value is not a usable {}", *kind)
            }
            TransportError::Bind(_) => Self::said("the iroh endpoint could not be bound"),
            TransportError::Connect(_) => Self::said("the connection could not be established"),
            TransportError::RelayRefused(refusal) => {
                let because = match refusal.kind {
                    RelayRefusalKind::AllowanceSpent => " because the relay allowance is spent",
                    RelayRefusalKind::Stopping => " because it is stopping",
                    _ => "",
                };
                let mut said = format!(
                    "the relay {} refused this endpoint{because}",
                    Self::address(refusal.relay.as_str())
                );
                let alternatives = refusal
                    .alternatives
                    .iter()
                    .map(|alternative| alternative.describe())
                    .collect::<Vec<_>>();
                if let Some((last, rest)) = alternatives.split_last() {
                    said.push_str("; a new connection may need ");
                    if !rest.is_empty() {
                        said.push_str(&rest.join(", "));
                        said.push_str(" or ");
                    }
                    said.push_str(last);
                }
                Self::decided(said)
            }
            TransportError::Stream(_) => Self::said("the stream failed"),
            TransportError::Closed(_) => Self::said("the peer closed the connection"),
            TransportError::Frame(error) => {
                crate::shown!("the frame was refused: {}", Self::frame(error))
            }
            TransportError::Cbor(error) => {
                crate::shown!("the message was not canonical: {}", Self::cbor(error))
            }
            TransportError::Handshake(error) => crate::shown!(
                "the handshake failed: {}: {}",
                error.code,
                Self::protocol(error)
            ),
            TransportError::Crypto(error) => {
                crate::shown!("the connection proof failed: {}", Self::crypto(error))
            }
            TransportError::Inactive => {
                Self::said("the peer was silent for longer than the inactivity threshold")
            }
            TransportError::LimitExceeded { what, limit } => {
                crate::shown!("{} exceeds its limit of {}", *what, *limit)
            }
            TransportError::ControlLost => {
                Self::said("the control stream ended, revoking every associated data stream")
            }
            _ => Self::said("the connection failed"),
        }
    }

    /// What a cryptographic failure says.
    ///
    /// The names these failures carry are this program's own, and an authentication failure says
    /// only what did not authenticate. What a secret store's platform said and the name a stored
    /// secret is kept under are not said; an encoding failure goes through [`Self::cbor`].
    #[must_use]
    pub fn crypto(error: &CryptoError) -> Self {
        match error {
            CryptoError::LibraryUnavailable { code } => crate::shown!(
                "libsodium could not initialise (sodium_init returned {})",
                *code
            ),
            CryptoError::Library { name, code } => crate::shown!("{} returned {}", *name, *code),
            CryptoError::LibraryMismatch {
                name,
                expected,
                actual,
            } => crate::shown!(
                "{} is {} bytes in the linked libsodium, not {}",
                *name,
                *actual,
                *expected
            ),
            CryptoError::Authentication { what } => {
                crate::shown!("{} did not authenticate", *what)
            }
            CryptoError::Truncated {
                what,
                minimum,
                actual,
            } => crate::shown!(
                "{} is {} bytes, under the {}-byte minimum",
                *what,
                *actual,
                *minimum
            ),
            CryptoError::TooLarge {
                what,
                limit,
                actual,
            } => crate::shown!(
                "{} is {} bytes, over the {}-byte limit",
                *what,
                *actual,
                *limit
            ),
            CryptoError::MissingFinalRecord => {
                Self::said("the encrypted object ended without its final authenticated record")
            }
            CryptoError::RecordsAfterFinal => {
                Self::said("the encrypted object carries records after its final one")
            }
            CryptoError::HashMismatch { what } => {
                crate::shown!("{} does not match the declared hash", *what)
            }
            CryptoError::BindingMismatch { what } => {
                crate::shown!("{} does not match the authenticated value", *what)
            }
            CryptoError::Encoding(error) => Self::cbor(error),
            CryptoError::SecretStore { .. } => Self::said("the secret store failed"),
            CryptoError::RotationExhausted => Self::said(
                "this collection's keys are at their last rotation and cannot rotate again",
            ),
            CryptoError::StoredSecretLength {
                expected, actual, ..
            } => crate::shown!("a stored secret is {} bytes, not {}", *actual, *expected),
            _ => Self::said("a cryptographic operation failed"),
        }
    }

    /// What a pairing failure says: its fixed words and numbers. What a rendezvous service, a
    /// store or a peer wrote is named by its kind, and a refusal by the code it carried.
    #[must_use]
    pub fn pairing(error: &kr_pairing::PairingError) -> Self {
        use kr_pairing::PairingError as Failure;

        match error {
            Failure::MalformedCode => {
                Self::said("a pairing code is ten characters from the Bitcoin Base58 alphabet")
            }
            Failure::AuthenticationFailed => Self::said("the pairing could not be authenticated"),
            Failure::Expired => Self::said("the invitation expired"),
            Failure::Consumed { .. } => Self::said("the invitation is no longer open"),
            Failure::AlreadyCommitted => Self::said("the invitation was already committed"),
            Failure::EarlyData => Self::said("a pairing mutation cannot arrive in early data"),
            Failure::AttemptsExhausted => {
                Self::said("the invitation has no confirmation attempts left")
            }
            Failure::ClientAttemptsExhausted => {
                Self::said("this code has no attempts left on this device; ask for a new one")
            }
            Failure::CandidateLocked => {
                Self::said("another candidate is already awaiting owner approval")
            }
            Failure::WrongPhase { expected, actual } => crate::shown!(
                "a pairing message arrived in the {} phase, which expects {}",
                *actual,
                *expected
            ),
            Failure::ReplayedSequence { sequence } => crate::shown!(
                "a pairing message repeated or skipped sequence number {}",
                *sequence
            ),
            Failure::TooLarge {
                what,
                limit,
                actual,
            } => crate::shown!(
                "{} is {} bytes, over the {}-byte limit",
                *what,
                *actual,
                *limit
            ),
            Failure::ContextMismatch { what } => crate::shown!("{} does not match", *what),
            Failure::EndpointMismatch { side } => crate::shown!(
                "the live {} endpoint is not the one the pairing authenticated",
                *side
            ),
            Failure::NotIssuingOwner => {
                Self::said("only the issuing owner can confirm or cancel this invitation")
            }
            Failure::OwnerConfirmationRequired => {
                Self::said("this action needs a fresh owner confirmation")
            }
            Failure::GrantNotPermitted { reason } => {
                crate::shown!("the proposed grant is not permitted: {}", *reason)
            }
            Failure::RendezvousUnavailable { .. } => {
                Self::said("the rendezvous service is unavailable")
            }
            Failure::RendezvousConfiguration { .. } => {
                Self::said("the rendezvous origin is not configured correctly")
            }
            Failure::Store { .. } => Self::said("the pairing store failed"),
            Failure::Refused { code, .. } => crate::shown!("the pairing was refused: {}", *code),
            Failure::Crypto(error) => Self::crypto(error),
            Failure::Encoding(error) => Self::cbor(error),
            _ => Self::said("the pairing failed"),
        }
    }

    /// What an invitation's QR payload that could not be read says: the rule it broke, a member
    /// that failed by its name, and its size or its version.
    ///
    /// The mode a payload named and why one of its members failed are not said. Both are the
    /// payload's own text, and a direct invitation's payload carries its pairing secret.
    #[must_use]
    pub fn qr_payload(error: &kr_protocol::pairing::QrPayloadError) -> Self {
        use kr_protocol::pairing::QrPayloadError as Fault;

        match error {
            Fault::Encoding(error) => crate::shown!(
                "the QR payload is not canonical KR-CBOR-1: {}",
                Self::cbor(error)
            ),
            Fault::Malformed(what) => crate::shown!("the QR payload is malformed: {}", *what),
            Fault::UnsupportedMode { .. } => {
                Self::said("the QR payload names a mode this build does not read")
            }
            Fault::UnsupportedVersion { version } => crate::shown!(
                "unsupported QR payload version {}; this build reads version 1",
                *version
            ),
            Fault::TooLarge { len, limit } => crate::shown!(
                "the QR payload is {} bytes, over the {}-byte limit",
                *len,
                *limit
            ),
            Fault::InvalidMember { member, .. } => {
                crate::shown!("the QR payload carries an invalid {}", *member)
            }
        }
    }

    /// What a task that ended abnormally says: whether it panicked or was cancelled, never what a
    /// panic said.
    #[must_use]
    pub fn task(error: &tokio::task::JoinError) -> Self {
        if error.is_panic() {
            Self::said("a task panicked")
        } else if error.is_cancelled() {
            Self::said("a task was cancelled")
        } else {
            Self::said("a task ended abnormally")
        }
    }

    /// A sync collection's name as a diagnostic may say it: the object's kind, one of the
    /// protocol's own, and its identifier. Any other name is replaced.
    #[must_use]
    pub fn collection(name: &str) -> Self {
        name.split_once('/')
            .and_then(|(kind, object)| {
                let kind = kr_protocol::sync::SyncObjectKind::ALL
                    .into_iter()
                    .find(|known| known.as_str() == kind)?;
                identifier(object)
                    .then(|| crate::shown!("{}/{}", kind, Self::decided(object.to_owned())))
            })
            .unwrap_or_else(|| Self::said("[a collection name]"))
    }

    /// A terminal type as the environment names one (`TERM`): said when it is one of the terminfo
    /// names this build lists, and replaced otherwise.
    ///
    /// A terminal type is text the environment holds, so what may be said of one is a closed list
    /// rather than a shape: a shape would pass whatever was put there in that shape.
    #[must_use]
    pub fn terminfo(name: &str) -> Self {
        TERMINFO_NAMES
            .iter()
            .find(|known| **known == name)
            .map_or_else(
                || Self::said("[a terminal type this build does not list]"),
                |known| Self::said(known),
            )
    }

    /// The path of a request this client makes: each segment that is a word of the adapters' own
    /// paths or an identifier, and a placeholder for any other.
    #[must_use]
    pub fn route(path: &str) -> Self {
        let segments = path
            .split('/')
            .map(|segment| {
                if segment.is_empty() {
                    Self::said("")
                } else if let Some(word) = route_word(segment) {
                    Self::said(word)
                } else if identifier(segment) {
                    Self::decided(segment.to_owned())
                } else {
                    Self::said("[a segment]")
                }
            })
            .collect::<Vec<_>>();
        Self::joined(segments, "/")
    }

    /* ---------------------------------------------------------------------- */
    /* Paths                                                                    */
    /* ---------------------------------------------------------------------- */

    /// A directory or file this program was configured with or derived itself: a runtime, state or
    /// store directory, or a path built from those, fixed names and identifiers.
    ///
    /// It is said whole, because where a store is kept is what somebody diagnosing it needs. A name
    /// found by listing a directory is not this: [`Self::stored`] is.
    #[must_use]
    pub fn root(path: &Path) -> Self {
        Self::decided(path.display().to_string())
    }

    /// A fixed name this program writes under a directory it was configured with.
    #[must_use]
    pub fn within(root: &Path, name: &'static str) -> Self {
        Self::decided(root.join(name).display().to_string())
    }

    /// A file in a store: said whole when its name is one the store writes, and otherwise as its
    /// directory and a placeholder.
    ///
    /// A name the store writes is one of its fixed `names`, or an identifier (a UUID, hexadecimal or
    /// decimal digits) followed by the store's own `extensions`, each of them one of that list, with
    /// a leading dot for a partial file. Anything else in a store's directory was put there by
    /// something other than the store, and its name is whatever that was.
    #[must_use]
    pub fn stored(path: &Path, names: &[&'static str], extensions: &[&'static str]) -> Self {
        let named = path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| names.contains(&name) || written_by_a_store(name, extensions));
        if named {
            return Self::root(path);
        }
        match path.parent() {
            Some(directory) => Self::decided(format!(
                "{}/[a name this store did not write]",
                directory.display()
            )),
            None => Self::said("[a name this store did not write]"),
        }
    }

    /// A path in this installation's tree, as a failure of a local connection names it.
    ///
    /// A directory this installation is configured with, its runtime root or its state root, is said
    /// whole, because where the installation keeps its state is what somebody diagnosing it needs.
    /// Below it, and anywhere outside it, each name is said only when it is an identifier or one the
    /// tree writes; any other is replaced, because a directory listing can have found it.
    #[must_use]
    pub fn host_path(path: &Path) -> Self {
        let roots = kr_ipc::paths::HostPaths::discover()
            .map(|paths| {
                vec![
                    paths.runtime_root().to_path_buf(),
                    paths.state_root().to_path_buf(),
                ]
            })
            .unwrap_or_default();
        let root = roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count());
        let (start, rest) = match root {
            Some(root) => (
                root.display().to_string(),
                path.strip_prefix(root).unwrap_or(path),
            ),
            None => (String::new(), path),
        };
        let pieces = rest
            .components()
            .map(|component| match component {
                std::path::Component::Prefix(prefix) => Piece::Prefix(path_prefix(prefix.kind())),
                std::path::Component::RootDir => Piece::Root,
                std::path::Component::CurDir => Piece::Name("."),
                std::path::Component::ParentDir => Piece::Name(".."),
                std::path::Component::Normal(name) => Piece::Name(
                    name.to_str()
                        .and_then(|name| {
                            HOST_TREE_NAMES
                                .iter()
                                .find(|known| **known == name)
                                .copied()
                                .or_else(|| {
                                    written_by_a_store(name, HOST_TREE_EXTENSIONS).then_some(name)
                                })
                        })
                        .unwrap_or("[a name]"),
                ),
            })
            .collect::<Vec<_>>();
        Self::decided(assemble(start, &pieces, std::path::MAIN_SEPARATOR_STR))
    }

    /* ---------------------------------------------------------------------- */
    /* Doors                                                                    */
    /* ---------------------------------------------------------------------- */

    /// A protocol error's message.
    ///
    /// Section 23 makes it plain text for a person that never carries credentials or command text.
    /// A host writes it under that contract, and this library puts in it only a `Shown` of its own
    /// or a service's refusal through [`Self::service`].
    #[must_use]
    pub fn protocol(error: &ProtocolError) -> Self {
        Self::decided(error.message.clone())
    }

    /// A managed service's refusal message, which the service writes to be shown to a person.
    #[must_use]
    pub fn service(message: &ServiceMessage) -> Self {
        Self::decided(message.0.clone())
    }

    /// Text a package declares about one of its controls, written for the person the control is
    /// shown to.
    #[must_use]
    pub fn package(text: &ControlText) -> Self {
        Self::decided(text.0.clone())
    }

    /// A sentence a host check composed, as the host's own export rule says it to another reader:
    /// its words when this process composed it from its own literals, numbers and closed terms, and
    /// its class and length when it arrived from a document or a reply.
    #[must_use]
    pub fn sentence(sentence: &kr_protocol::hostinfo::export::Sentence) -> Self {
        Self::decided(kr_protocol::hostinfo::export::stated(sentence))
    }

    /// The signal a closure record says ended a session's shell, as the platform names it: one of
    /// the descriptions platforms give signals, or a signal's own name, with the number a platform
    /// puts after it. Anything else is replaced.
    ///
    /// The record's field holds what the host's worker wrote, so what may be said of it is the
    /// closed list of names a platform uses rather than a shape a name could be written in.
    #[must_use]
    pub fn signal(record: &kr_protocol::session::ClosureRecord) -> Option<Self> {
        let name = record.root_signal.as_ref()?;
        let known = |text: &str| SIGNAL_NAMES.iter().find(|known| **known == text).copied();
        let number = |text: &str| {
            (!text.is_empty() && text.len() <= 3 && text.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| text.parse::<u16>().ok())
                .flatten()
        };
        let said = if let Some(word) = known(name) {
            Some(Self::said(word))
        } else if let Some((word, count)) = name.split_once(": ") {
            known(word)
                .zip(number(count))
                .map(|(word, count)| crate::shown!("{}: {}", word, count))
        } else if let Some((word, count)) = name.rsplit_once(' ') {
            NUMBERED_SIGNAL_NAMES
                .iter()
                .find(|known| **known == word)
                .zip(number(count))
                .map(|(word, count)| crate::shown!("{} {}", *word, count))
        } else {
            None
        };
        Some(said.unwrap_or_else(|| Self::said("[a signal name this build does not list]")))
    }
}

impl From<&'static str> for Shown {
    fn from(text: &'static str) -> Self {
        Self::said(text)
    }
}

impl fmt::Display for Shown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for Shown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, formatter)
    }
}

/// A `Shown` can be the payload of an I/O failure this program makes, which [`Shown::io`] says.
impl std::error::Error for Shown {}

/// Whether a name is one a store writes: an identifier, then identifiers or `extensions`.
///
/// A leading dot is allowed, for a store's partial files. The first part after it has to be an
/// identifier: a UUID, at least eight hexadecimal digits, or decimal digits. Every later part is an
/// identifier or one of the store's own extensions.
fn written_by_a_store(name: &str, extensions: &[&str]) -> bool {
    let name = name.strip_prefix('.').unwrap_or(name);
    let mut parts = name.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    identifier(first) && parts.all(|part| identifier(part) || extensions.contains(&part))
}

/// One part of a path as [`Shown::host_path`] says it.
enum Piece<'a> {
    /// A prefix, as [`path_prefix`] says it.
    Prefix(String),
    /// The root directory.
    Root,
    /// A name, or its placeholder.
    Name(&'a str),
}

/// Joins the parts of a path after `start` with `separator`, as text: a placeholder is kept where a
/// path joined by the platform would treat the root that follows it as starting over.
fn assemble(mut said: String, pieces: &[Piece<'_>], separator: &str) -> String {
    let mut separated = said.is_empty() || said.ends_with(separator);
    for piece in pieces {
        match piece {
            // A drive's prefix and a name after it with no root between are a path relative to
            // that drive, so no separator goes between them.
            Piece::Prefix(prefix) => {
                said.push_str(prefix);
                separated = true;
            }
            Piece::Root => {
                said.push_str(separator);
                separated = true;
            }
            Piece::Name(name) => {
                if !separated {
                    said.push_str(separator);
                }
                said.push_str(name);
                separated = false;
            }
        }
    }
    said
}

/// What a path's prefix says outside a configured root: a drive's letter, and a placeholder for a
/// server, a share or a device, whose names are whatever somebody gave them.
fn path_prefix(prefix: std::path::Prefix<'_>) -> String {
    match prefix {
        std::path::Prefix::Disk(letter) | std::path::Prefix::VerbatimDisk(letter)
            if letter.is_ascii_alphabetic() =>
        {
            format!("{}:", char::from(letter))
        }
        _ => "[a network or device path]".to_owned(),
    }
}

/// The word `segment` is in one of the paths the service adapters call, if it is one.
fn route_word(segment: &str) -> Option<&'static str> {
    use crate::services::{account, authority, mailbox, relay, sync, voice};

    const PATHS: [&str; 15] = [
        sync::SYNC_EXCHANGE_PATH,
        authority::AUTHORITY_SYNC_PATH,
        mailbox::MAILBOX_DELIVER_PATH,
        mailbox::MAILBOX_READ_PATH,
        mailbox::MAILBOX_ACKNOWLEDGE_PATH,
        account::AUTHORIZE_PATH,
        account::TOKEN_PATH,
        account::REVOKE_PATH,
        account::USERINFO_PATH,
        account::USAGE_PATH,
        relay::RELAY_LEASE_PATH,
        relay::RELAY_LEASE_REVOKE_PATH,
        voice::VOICE_SESSIONS_PATH,
        voice::VOICE_METADATA_PATH,
        // What the voice adapter adds after a call's identifier.
        "/control/close",
    ];
    PATHS
        .iter()
        .flat_map(|path| path.split('/'))
        .find(|word| !word.is_empty() && *word == segment)
}

/// The terminfo names a terminal type is said as. Any other is replaced.
const TERMINFO_NAMES: &[&str] = &[
    "alacritty",
    "ansi",
    "contour",
    "cygwin",
    "dumb",
    "foot",
    "foot-direct",
    "gnome",
    "gnome-256color",
    "iterm2",
    "konsole",
    "konsole-256color",
    "linux",
    "mintty",
    "ms-terminal",
    "putty",
    "putty-256color",
    "rxvt",
    "rxvt-256color",
    "rxvt-unicode",
    "rxvt-unicode-256color",
    "screen",
    "screen-256color",
    "screen.xterm-256color",
    "st",
    "st-256color",
    "tmux",
    "tmux-256color",
    "vt100",
    "vt102",
    "vt220",
    "vt320",
    "wezterm",
    "xterm",
    "xterm-16color",
    "xterm-256color",
    "xterm-color",
    "xterm-direct",
    "xterm-ghostty",
    "xterm-kitty",
    "xterm-new",
];

/// How platforms describe the signals that end a process, and the signals' own names.
const SIGNAL_NAMES: &[&str] = &[
    "Abort trap",
    "Aborted",
    "Alarm clock",
    "Bad system call",
    "Broken pipe",
    "Bus error",
    "CPU time limit exceeded",
    "Child exited",
    "Continued",
    "Cputime limit exceeded",
    "EMT trap",
    "File size limit exceeded",
    "Filesize limit exceeded",
    "Floating point exception",
    "Hangup",
    "I/O possible",
    "IOT trap",
    "Illegal instruction",
    "Information request",
    "Interrupt",
    "Killed",
    "Power failure",
    "Profiling timer expired",
    "Quit",
    "Resource lost",
    "Segmentation fault",
    "Stack fault",
    "Stopped",
    "Stopped (signal)",
    "Stopped (tty input)",
    "Stopped (tty output)",
    "Suspended",
    "Suspended (signal)",
    "Terminated",
    "Trace/BPT trap",
    "Trace/breakpoint trap",
    "Urgent I/O condition",
    "User defined signal 1",
    "User defined signal 2",
    "Virtual timer expired",
    "Window changed",
    "Window size changes",
    "SIGABRT",
    "SIGALRM",
    "SIGBUS",
    "SIGCHLD",
    "SIGCONT",
    "SIGEMT",
    "SIGFPE",
    "SIGHUP",
    "SIGILL",
    "SIGINFO",
    "SIGINT",
    "SIGIO",
    "SIGKILL",
    "SIGPIPE",
    "SIGPROF",
    "SIGPWR",
    "SIGQUIT",
    "SIGSEGV",
    "SIGSTKFLT",
    "SIGSTOP",
    "SIGSYS",
    "SIGTERM",
    "SIGTRAP",
    "SIGTSTP",
    "SIGTTIN",
    "SIGTTOU",
    "SIGURG",
    "SIGUSR1",
    "SIGUSR2",
    "SIGVTALRM",
    "SIGWINCH",
    "SIGXCPU",
    "SIGXFSZ",
];

/// The descriptions a platform gives with a signal's number after them, such as the name a signal
/// has when the platform has no description for it.
const NUMBERED_SIGNAL_NAMES: &[&str] = &["Real-time signal", "Signal", "Unknown signal"];

/// The names this installation's tree writes under its roots.
const HOST_TREE_NAMES: &[&str] = &[
    "run",
    "state",
    "environments",
    "environment",
    "environment-id",
    "sessions",
    "workers",
    "jobs",
    "spool",
    "secrets",
    "registry.sqlite",
    "controller.lock",
    "c.sock",
    "r.sock",
    "account-token.json",
];

/// The extensions a file named by an identifier carries in this installation's tree.
const HOST_TREE_EXTENSIONS: &[&str] = &["kr", "log", "sock", "lock", "json"];

/// A UUID, eight or more hexadecimal digits, or decimal digits.
fn identifier(part: &str) -> bool {
    let hex = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit());
    let uuid = {
        let groups = part.split('-').collect::<Vec<_>>();
        groups.len() == 5
            && groups
                .iter()
                .zip([8, 4, 4, 4, 12])
                .all(|(group, length)| group.len() == length && hex(group))
    };
    uuid || (part.len() >= 8 && part.len() <= 128 && hex(part))
        || (!part.is_empty() && part.len() <= 20 && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// A managed service's refusal message.
///
/// Only this crate's service readers make one, from the `message` of a refusal a service sent, so
/// [`Shown::service`] cannot be handed anything else.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceMessage(String);

impl ServiceMessage {
    /// The message of a refusal a service sent.
    pub(crate) const fn from_refusal(message: String) -> Self {
        Self(message)
    }
}

impl fmt::Debug for ServiceMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&Shown::service(self), formatter)
    }
}

/// Text a package declares about one of its controls: the reason it gives a person for a control
/// that is shown and not usable, or the name of a fact its condition turns on.
///
/// Only [`crate::controls`] makes one, from what a control declares.
#[derive(Clone, PartialEq, Eq)]
pub struct ControlText(String);

impl ControlText {
    /// What a control declares.
    pub(crate) const fn declared(text: String) -> Self {
        Self(text)
    }
}

impl fmt::Debug for ControlText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&Shown::package(self), formatter)
    }
}

/// An I/O failure, held so that only what [`Shown::io`] says of it is ever rendered.
///
/// It is not a [`std::error::Error`], so it is never a failure's `source()`: a logger that walks a
/// source chain would otherwise print the payload that this type exists to keep out.
pub struct IoFault(std::io::Error);

impl IoFault {
    /// What kind of failure it was.
    #[must_use]
    pub fn kind(&self) -> std::io::ErrorKind {
        self.0.kind()
    }

    /// The operating system's code for it, when it came from the operating system.
    #[must_use]
    pub fn raw_os_error(&self) -> Option<i32> {
        self.0.raw_os_error()
    }
}

impl From<std::io::Error> for IoFault {
    fn from(error: std::io::Error) -> Self {
        Self(error)
    }
}

impl fmt::Display for IoFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Shown::io(&self.0), formatter)
    }
}

impl fmt::Debug for IoFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("IoFault")
            .field(&Shown::io(&self.0))
            .finish()
    }
}

/* -------------------------------------------------------------------------- */
/* Plain                                                                      */
/* -------------------------------------------------------------------------- */

/// A value whose `Display` cannot carry text from input.
///
/// Implemented only here and in the command line's own `shown.rs`: see the [module](self).
pub trait Plain: fmt::Display {}

/// The part [`shown!`](crate::shown!) passes for one argument, which has to be [`Plain`].
#[doc(hidden)]
#[must_use]
pub fn plain<T: Plain>(value: &T) -> &dyn Plain {
    value
}

/// How many holes a template has, when every hole is a bare `{}` and every other brace is doubled.
#[doc(hidden)]
#[must_use]
pub const fn holes(template: &str) -> Option<usize> {
    let bytes = template.as_bytes();
    let mut index = 0;
    let mut count = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' if index + 1 < bytes.len() && bytes[index + 1] == b'{' => index += 2,
            b'{' if index + 1 < bytes.len() && bytes[index + 1] == b'}' => {
                count += 1;
                index += 2;
            }
            b'}' if index + 1 < bytes.len() && bytes[index + 1] == b'}' => index += 2,
            b'{' | b'}' => return None,
            _ => index += 1,
        }
    }
    Some(count)
}

/// One, for counting a macro's parts.
#[doc(hidden)]
#[must_use]
pub const fn one(_part: &str) -> usize {
    1
}

/// Builds a [`Shown`] from a template of this program's own and [`Plain`] parts.
///
/// `shown!("{} is at revision {}", draft_id, revision)`. Every hole is a bare `{}`, filled by the
/// next part in order: a hole that names a variable (`{name}`), a position (`{0}`) or a format
/// (`{:?}`) does not build, and neither does a template with more or fewer holes than parts.
#[macro_export]
macro_rules! shown {
    ($template:literal $(,)?) => {{
        const _: () = ::core::assert!(
            ::core::matches!($crate::shown::holes($template), ::core::option::Option::Some(0)),
            "a shown! template has one bare {{}} for each part and no other braces"
        );
        $crate::shown::Shown::compose($template, &[])
    }};
    ($template:literal, $($part:expr),+ $(,)?) => {{
        const _: () = ::core::assert!(
            ::core::matches!(
                $crate::shown::holes($template),
                ::core::option::Option::Some(holes)
                    if holes == 0 $(+ $crate::shown::one(::core::stringify!($part)))+
            ),
            "a shown! template has one bare {{}} for each part and no other braces"
        );
        $crate::shown::Shown::compose($template, &[$($crate::shown::plain(&$part)),+])
    }};
}

/// A value whose `Display` is what [`Said::said`] returns.
pub trait Said {
    /// What this value says.
    fn said(&self) -> Shown;
}

/// Gives each type the `Display` its [`Said`] implementation writes, and nothing else.
#[macro_export]
macro_rules! display_as_said {
    ($($name:ty),+ $(,)?) => {$(
        impl ::core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&$crate::shown::Said::said(self), formatter)
            }
        }
    )+};
}

/// Gives each failure type a `Debug` that is its name and its `Display`, never its fields.
#[macro_export]
macro_rules! debug_as_display {
    ($($name:ident),+ $(,)?) => {$(
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter
                    .debug_tuple(::core::stringify!($name))
                    .field(&::std::string::ToString::to_string(self))
                    .finish()
            }
        }
    )+};
}

macro_rules! plain {
    ($($name:ty),+ $(,)?) => {$( impl Plain for $name {} )+};
}

// Numbers and switches.
plain!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f64, bool
);
// This program's words, and what a reducer or a door decided.
plain!(&'static str, Shown, IoFault, std::io::ErrorKind);
// Identifiers that are a UUID, and identifiers that are a counter: whatever arrived, their text is
// hexadecimal digits and dashes, or decimal digits.
plain!(
    kr_protocol::scalars::Uuid,
    kr_protocol::scalars::U64,
    kr_protocol::ids::ActionId,
    kr_protocol::ids::AttachmentId,
    kr_protocol::ids::DeviceId,
    kr_protocol::ids::DraftId,
    kr_protocol::ids::EnvironmentId,
    kr_protocol::ids::GrantId,
    kr_protocol::ids::InstallationId,
    kr_protocol::ids::QuestionId,
    kr_protocol::ids::SessionId,
    kr_protocol::ids::SyncCollectionId,
    kr_protocol::ids::SyncConflictId,
    kr_protocol::ids::SyncObjectId,
    kr_protocol::ids::SyncRevisionId,
    kr_protocol::ids::DraftRevision,
    kr_protocol::ids::QuestionRevision,
    kr_protocol::ids::SessionEpoch,
    kr_protocol::ids::SyncKeyEpoch,
    kr_protocol::ids::RequestId,
);
// This crate's own failures: each says only `Shown` and `Plain` values, which the source test holds
// every failure type to.
plain!(
    crate::error::ClientError,
    crate::services::json::Unreadable,
    crate::drafts::DraftError,
    crate::sync::SyncError,
    crate::sync::membership::MembershipError,
    crate::recovery::RecoveryError,
    crate::answers::AnswerError,
    crate::recovery::MaterialName,
    crate::answers::Retired,
    crate::cursors::RestorationStep,
    crate::cursors::OutOfOrder,
    crate::drafts::NotSubmittable,
    crate::sync::membership::PlanRefusal,
    crate::encoder::Unsupported,
    crate::viewport::NotSwitching,
    crate::controls::Hidden,
    crate::controls::NotInvocable,
    crate::sync::RequestRevision,
    crate::services::SyncRevision,
    crate::services::SyncRecoveryId,
    crate::services::SyncPosition,
    crate::services::account::AttemptId,
    crate::services::voice::VoiceRefusalReason,
    crate::services::voice::VoiceCommand,
);
// Codes, states and names from a fixed vocabulary, and an origin that is a scheme, a host and a port
// by construction.
plain!(
    kr_protocol::error::ErrorCode,
    kr_protocol::method::Method,
    kr_protocol::method::MethodVersion,
    kr_protocol::question::QuestionState,
    kr_protocol::question::QuestionKind,
    kr_protocol::session::SessionState,
    kr_protocol::sync::SyncObjectKind,
    kr_protocol::service::ServiceRequestSigner,
    kr_protocol::service::GatewayOrigin,
    kr_plugin_sdk::predicate::PredicateError,
    kr_protocol::sync::SyncObjectError,
    kr_protocol::sync::RecoveryBundleError,
    kr_protocol::collection_keys::CollectionKeyRecordError,
    kr_protocol::pairing::PairingTextError,
    kr_protocol::identity::EnrolmentError,
);
// An exit status is a code or a signal, which the operating system reports and names.
plain!(std::process::ExitStatus);
// A terminal probe failure is one of the terminal library's fixed reasons.
#[cfg(feature = "terminal")]
plain!(kr_term::error::ProbeFailure);

#[cfg(test)]
pub(crate) mod marker;

#[cfg(test)]
mod tests {
    use super::*;
    use marker::MARKER;

    #[test]
    fn a_template_fills_its_holes_in_order_and_keeps_doubled_braces() {
        assert_eq!(
            crate::shown!("{} of {} {{kept}}", 3_u64, 4_u64).as_str(),
            "3 of 4 {kept}"
        );
        assert_eq!(crate::shown!("nothing to fill").as_str(), "nothing to fill");
        assert_eq!(holes("{} {} {{}}"), Some(2));
        assert_eq!(holes("{name}"), None);
        assert_eq!(holes("{0}"), None);
        assert_eq!(holes("{:?}"), None);
        assert_eq!(holes("a lone }"), None);
    }

    #[test]
    fn an_address_keeps_the_scheme_the_host_and_the_port_and_nothing_else() {
        for origin in [
            format!("https://{MARKER}:{MARKER}@reach.example"),
            format!("https://{MARKER}@reach.example"),
            MARKER.to_owned(),
        ] {
            let said = Shown::address(&origin);
            assert!(!said.as_str().contains(MARKER), "{said}");
            assert_eq!(said.as_str(), "<not printed>");
        }
        for (origin, expected) in [
            (
                format!("https://reach.example:8443/{MARKER}?{MARKER}#{MARKER}"),
                "https://reach.example:8443",
            ),
            (
                format!("https://reach.example/{MARKER}"),
                "https://reach.example",
            ),
        ] {
            assert_eq!(Shown::address(&origin).as_str(), expected);
        }
    }

    #[test]
    fn a_cbor_failure_names_its_rule_and_its_place_and_nothing_it_read() {
        let failures = [
            CborError::DuplicateKey {
                key: MARKER.to_owned(),
            },
            CborError::UnsortedMapKeys {
                previous: MARKER.to_owned(),
                current: MARKER.to_owned(),
            },
            CborError::UnknownField {
                at: format!("Draft at /{MARKER}"),
                field: MARKER.to_owned(),
            },
            CborError::UnknownVariant {
                at: MARKER.to_owned(),
                tag: MARKER.to_owned(),
                variant: MARKER.to_owned(),
            },
            CborError::UnnegotiatedExtension {
                at: MARKER.to_owned(),
                extension: MARKER.to_owned(),
            },
            CborError::Deserialize {
                message: format!("invalid type: string \"{MARKER}\", expected u64"),
            },
            CborError::Serialize {
                message: MARKER.to_owned(),
            },
        ];
        for failure in &failures {
            let said = Shown::cbor(failure);
            assert!(!said.as_str().contains(MARKER), "{failure:?} said {said}");
            assert_eq!(said.as_str(), failure.rule(), "the class, and nothing else");
        }
        // The neutral control: a failure with a place says the class and the place.
        assert_eq!(
            Shown::cbor(&CborError::UnexpectedEnd { offset: 12 }).as_str(),
            "unexpected_end at byte 12"
        );
        assert_eq!(
            Shown::cbor(&CborError::TrailingBytes { count: 3 }).as_str(),
            "trailing_bytes: 3 bytes follow the value"
        );
    }

    #[test]
    fn an_io_failure_names_its_kind_and_its_code_and_no_payload() {
        let custom = std::io::Error::other(MARKER);
        assert_eq!(Shown::io(&custom).as_str(), "other error");
        let own = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            crate::shown!("a record of {} bytes", 7_u64),
        );
        assert_eq!(Shown::io(&own).as_str(), "a record of 7 bytes");
        let os = std::io::Error::from_raw_os_error(2);
        let said = Shown::io(&os).into_string();
        assert!(said.ends_with("(os error 2)"), "{said}");
        let fault = IoFault::from(std::io::Error::other(MARKER));
        assert!(!format!("{fault} {fault:?} {fault:#?}").contains(MARKER));
    }

    #[test]
    fn a_stored_name_is_said_only_when_the_store_wrote_it() {
        // Written with `/` and joined with the platform's own separator, which on Windows are two
        // different characters; the rendering says the platform's own throughout.
        let root = Path::new("/state/answers");
        let separator = std::path::MAIN_SEPARATOR;
        let directory = format!("{separator}state{separator}answers");
        let written = root.join("0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.answer");
        assert_eq!(
            Shown::stored(&written, &[], &["answer", "partial"]).as_str(),
            format!("{directory}{separator}0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.answer")
        );
        let partial_name =
            ".0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.partial";
        assert_eq!(
            Shown::stored(&root.join(partial_name), &[], &["answer", "partial"]).as_str(),
            format!("{directory}{separator}{partial_name}")
        );
        assert_eq!(
            Shown::stored(&root.join("lock"), &["lock"], &[]).as_str(),
            format!("{directory}{separator}lock")
        );
        assert_eq!(
            Shown::within(root, "lock").as_str(),
            format!("{directory}{separator}lock")
        );
        assert_eq!(
            Shown::root(&root.join("lock")).as_str(),
            format!("{directory}{separator}lock")
        );
        // An extension the store does not write is not said, whatever its letters: a name is only
        // an identifier followed by the store's own extensions.
        for planted in [
            format!("{MARKER}.answer"),
            format!("0e1f9a2b.{MARKER}.answer"),
            "123.private-password.answer".to_owned(),
            "0e1f9a2b.answer.kr-marker".to_owned(),
        ] {
            let said = Shown::stored(&root.join(&planted), &["lock"], &["answer", "partial"]);
            assert!(!said.as_str().contains(MARKER), "{said}");
            assert!(!said.as_str().contains("password"), "{said}");
            assert_eq!(
                said.as_str(),
                format!("{directory}{separator}[a name this store did not write]")
            );
        }
    }

    /// A path in this installation's tree is said by its configured root and the names the tree
    /// writes; a name a listing could have found is replaced, below the root and outside it.
    #[test]
    fn a_host_path_says_only_its_root_and_the_names_the_tree_writes() {
        let tree = std::path::PathBuf::from("/nowhere/configured")
            .join("environments")
            .join(MARKER)
            .join("environment");
        let said = Shown::host_path(&tree);
        assert!(!said.as_str().contains(MARKER), "{said}");
        // One separator throughout, the platform's own.
        let separator = std::path::MAIN_SEPARATOR;
        assert_eq!(
            said.as_str(),
            format!(
                "{separator}[a name]{separator}[a name]{separator}environments{separator}[a name]\
                 {separator}environment"
            )
        );
        let descriptor = std::path::PathBuf::from("/[a name]")
            .join("sessions")
            .join("0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.kr");
        let said = Shown::host_path(&descriptor);
        assert!(
            said.as_str().ends_with(&format!(
                "sessions{separator}0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.kr"
            )),
            "{said}"
        );
    }

    /// A path prefix outside a configured root says a drive's letter, and never a server's, a
    /// share's or a device's name.
    #[test]
    fn a_path_prefix_says_a_drive_and_never_a_servers_name() {
        use std::ffi::OsStr;
        use std::path::Prefix;

        assert_eq!(path_prefix(Prefix::Disk(b'C')), "C:");
        assert_eq!(path_prefix(Prefix::VerbatimDisk(b'D')), "D:");
        for prefix in [
            Prefix::UNC(OsStr::new(MARKER), OsStr::new("share")),
            Prefix::VerbatimUNC(OsStr::new("server"), OsStr::new(MARKER)),
            Prefix::Verbatim(OsStr::new(MARKER)),
            Prefix::DeviceNS(OsStr::new(MARKER)),
        ] {
            assert_eq!(path_prefix(prefix), "[a network or device path]");
        }
    }

    /// A path outside a configured root keeps its prefix's placeholder when a root follows it, as
    /// a network path on Windows has one.
    #[test]
    fn a_placeholder_prefix_survives_the_root_after_it() {
        let pieces = [
            Piece::Prefix(path_prefix(std::path::Prefix::UNC(
                std::ffi::OsStr::new(MARKER),
                std::ffi::OsStr::new("share"),
            ))),
            Piece::Root,
            Piece::Name("[a name]"),
            Piece::Name("0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.kr"),
        ];
        assert_eq!(
            assemble(String::new(), &pieces, "\\"),
            "[a network or device path]\\[a name]\\0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b.kr"
        );
        assert_eq!(
            assemble(
                "/configured/root".to_owned(),
                &[Piece::Name("sessions")],
                "/"
            ),
            "/configured/root/sessions"
        );
        // A drive-relative path stays relative to its drive.
        assert_eq!(
            assemble(
                String::new(),
                &[Piece::Prefix("C:".to_owned()), Piece::Name("sessions")],
                "\\"
            ),
            "C:sessions"
        );
    }

    /// A terminal type is said when it is a terminfo name this build lists, and replaced otherwise,
    /// however it is spelled.
    #[test]
    fn a_terminal_type_is_said_only_when_this_build_lists_it() {
        for name in [
            "xterm-256color",
            "screen.xterm-256color",
            "tmux-256color",
            "dumb",
        ] {
            assert_eq!(Shown::terminfo(name).as_str(), name);
        }
        for name in [
            "",
            MARKER,
            "Xterm",
            "xterm 256",
            "xterm\u{1b}[31m",
            "xterm-256color2",
        ] {
            assert_eq!(
                Shown::terminfo(name).as_str(),
                "[a terminal type this build does not list]",
                "{name:?}"
            );
        }
    }

    /// A request path is said by the adapters' own words and identifiers; any other segment is
    /// replaced, however it is spelled.
    #[test]
    fn a_route_says_only_the_adapters_words_and_identifiers() {
        assert_eq!(
            Shown::route("/api/voice/sessions/0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b/close").as_str(),
            "/api/voice/sessions/0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b/close"
        );
        assert_eq!(
            Shown::route("/auth/oauth2/token").as_str(),
            "/auth/oauth2/token"
        );
        let said = Shown::route(&format!("/api/voice/sessions/{MARKER}/close"));
        assert_eq!(said.as_str(), "/api/voice/sessions/[a segment]/close");
        assert_eq!(
            Shown::collection("settings/0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b").as_str(),
            "settings/0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
        );
        for name in [
            format!("settings/{MARKER}"),
            format!("{MARKER}/0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"),
            MARKER.to_owned(),
        ] {
            assert_eq!(Shown::collection(&name).as_str(), "[a collection name]");
        }
    }

    /// A closure record's signal is said when it is a name platforms give a signal, with the number
    /// a platform puts after one, and replaced otherwise, however it is spelled.
    #[test]
    fn a_signal_is_said_only_as_a_platform_names_one() {
        let record = |signal: Option<&str>| kr_protocol::session::ClosureRecord {
            session_id: kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes(
                [7; 16],
            )),
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::RootSignal,
            root_exit_code: kr_protocol::scalars::Nullable::null(),
            root_signal: kr_protocol::scalars::Nullable(signal.map(ToOwned::to_owned)),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        };
        assert!(Shown::signal(&record(None)).is_none());
        for name in [
            "Killed: 9",
            "Killed",
            "Terminated: 15",
            "Real-time signal 3",
            "Signal 64",
            "SIGTERM",
        ] {
            assert_eq!(
                Shown::signal(&record(Some(name))).map(Shown::into_string),
                Some(name.to_owned())
            );
        }
        for name in [
            MARKER,
            "\u{1b}]0;title\u{7}",
            "Killed\n9",
            "Killed: nine",
            "Killed: 12345",
            "Signal kr-marker",
            "",
        ] {
            assert_eq!(
                Shown::signal(&record(Some(name))).map(Shown::into_string),
                Some("[a signal name this build does not list]".to_owned()),
                "{name:?}"
            );
        }
    }

    /// A host sentence composed here is said in its words; one that arrived from a document is said
    /// by its class and length, which is the host's own export rule.
    #[test]
    fn a_sentence_that_arrived_is_said_by_its_class_and_length() {
        let composed = kr_protocol::hostinfo::export::Sentence::new()
            .stated("revision ")
            .number(7);
        assert_eq!(Shown::sentence(&composed).as_str(), "revision 7");
        let arrived: kr_protocol::hostinfo::export::Sentence =
            serde_json::from_value(serde_json::json!(MARKER)).expect("a sentence on the wire");
        let said = Shown::sentence(&arrived);
        assert!(!said.as_str().contains(MARKER), "{said}");
        assert!(said.as_str().contains("14 bytes"), "{said}");
    }
}
