//! The wire between the control daemon and the description process.
//!
//! The description process is the daemon's own child, and the two talk over the child's standard
//! input and output. Every message is one frame of section 23's shape, a four-byte big-endian length
//! and one KR-CBOR-1 object, through the protocol's own codec at the control stream's bound. So the
//! length is checked before a byte of the payload is allocated, and the payload passes every byte
//! rule and its schema before anything reads it.
//!
//! | The daemon sends | The process answers |
//! | --- | --- |
//! | `hello`: the daemon's build and this wire's version | `ready`: its build, target, start identity, background class and how its memory ceiling is enforced |
//! | `load`: a profile by identifier and revision, its asset files and a deadline | `loaded`, or `load_ended` with why |
//! | `generate`: a prompt in its parts, the grammar, the limits, a deadline and the memory ceiling | `produced` with the bytes, or `ended` with why |
//! | `verify`: a profile's asset by name, the file to check and a deadline | `verified` with the result |
//! | `cancel`: the work with this identifier | `cancelling` at once, then that work's own answer, sooner |
//!
//! Every request that is answered carries an identifier and every answer to it repeats it, so an
//! answer the daemon is not waiting for is recognised and dropped rather than attributed to whatever
//! is running now. The daemon speaks to a process of its own release and this wire's version, and to
//! nothing else.
//!
//! The process's answers are untrusted. `produced` carries bytes, and
//! [`crate::output::validate`] decides whether they are a description.
//!
//! The sampler is not on this wire. KR-CBOR-1 has no floats, and the process does not need them sent:
//! it takes the sampler from the signed profile it loaded, which is the document the daemon selected,
//! because both come from one release.

use std::io::{ErrorKind, Read, Write};

use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, FrameCodec, FrameError, StreamKind};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::scalars::{Bytes, Nullable, U64};
use kr_protocol::wire::WireMessage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::priority::Applied;
use crate::prompt::Prompt;

/// This wire's version. A daemon and a process that disagree about it do not talk.
///
/// The second version added `verify` and `verified`, `cancelling`, and the way `ready` says its
/// memory ceiling is enforced. The third sends the prompt in its parts and the number of tokens it
/// may be, so the process, which holds the tokenizer, makes it fit. The fourth says in the prompt
/// what it asks for, a description or a summary of what changed, which the process needs to end
/// an answer the output bound stopped.
pub const WIRE_VERSION: u64 = 4;

/// This build's release, which the daemon and the process it starts share.
pub const RELEASE: &str = env!("CARGO_PKG_VERSION");

/// The codec every frame on this wire goes through: section 23's, at the control bound.
pub const CODEC: FrameCodec = FrameCodec::new(StreamKind::Control);

/// Returns whether a build identifier, `name/release`, names this build's release.
#[must_use]
pub fn same_release(build: &str) -> bool {
    build
        .rsplit_once('/')
        .is_some_and(|(name, release)| !name.is_empty() && release == RELEASE)
}

/// What the daemon sends the description process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// The first frame: who is speaking, in which version of this wire.
    Hello {
        /// The daemon's build identifier.
        build: String,
        /// The wire version the daemon speaks.
        wire: U64,
    },
    /// Load a profile's model, before any job for it is sent.
    Load {
        /// The request's identifier, repeated by its answer.
        id: U64,
        /// The profile, which the process finds in its own signed catalogue.
        profile_id: String,
        /// The profile's revision, which has to be the one the process's catalogue holds.
        revision: U64,
        /// Where each of the profile's files is.
        assets: Vec<AssetFile>,
        /// How long the load may take from the moment the process reads this, in milliseconds.
        deadline_ms: U64,
    },
    /// Run one job on the loaded model.
    Generate {
        /// The request's identifier, repeated by its answer.
        id: U64,
        /// The prompt, in its parts, which hold every piece of project text.
        prompt: Prompt,
        /// The grammar the sampler is held to.
        grammar: String,
        /// The job's bounds.
        limits: JobLimits,
        /// How long the job may take from the moment the process reads this, in milliseconds.
        deadline_ms: U64,
        /// The resident set past which the job is ended rather than finished, in bytes.
        ceiling_bytes: U64,
    },
    /// Check one of a profile's files against the size and digest the process's own catalogue
    /// records for it.
    ///
    /// The expected size and digest are never sent: a daemon that named them would be telling the
    /// process what to accept. The process hashes the file under its own background class, and
    /// answers `verified` with how it came out.
    Verify {
        /// The request's identifier, repeated by its answer.
        id: U64,
        /// The profile, which the process finds in its own signed catalogue.
        profile_id: String,
        /// The profile's revision, which has to be the one the process's catalogue holds.
        revision: U64,
        /// The file's name, as the profile records it.
        file_name: String,
        /// Where the file is on this host.
        path: String,
        /// How long the check may take from the moment the process reads this, in milliseconds.
        deadline_ms: U64,
    },
    /// Stop the work with this identifier. The process says at once that it is stopping it, and
    /// the work's own answer says how it ended.
    Cancel {
        /// The work to stop.
        id: U64,
    },
}

/// One of a profile's files, where the daemon keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssetFile {
    /// The file's name, as the profile records it.
    pub file_name: String,
    /// Where it is on this host.
    pub path: String,
}

/// One job's bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobLimits {
    /// The context window, in tokens.
    pub context_tokens: U64,
    /// The output bound, in tokens.
    pub max_output_tokens: U64,
    /// How many tokens the prompt may be, beside the answer's bound.
    pub prompt_tokens: U64,
    /// How many processor threads the job may use.
    pub cpu_threads: U64,
}

/// What the description process answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Answer {
    /// The answer to `hello`: what this process is.
    Ready {
        /// The process's build identifier.
        build: String,
        /// The wire version the process speaks.
        wire: U64,
        /// The target it was built for, which a profile has to list.
        target: String,
        /// The process's own start identity, when the platform would say.
        identity: Nullable<ProcessStartIdentity>,
        /// The background class the process runs its model under.
        background: Background,
        /// How the process's memory ceiling is enforced: `sampler` when the daemon's own reading
        /// of the process ends it past the ceiling, and nothing the platform enforces besides.
        ceiling: String,
    },
    /// The model is loaded.
    Loaded {
        /// The load's identifier.
        id: U64,
        /// How long the load took in the process, in milliseconds.
        load_ms: U64,
        /// The process's resident set once it was loaded, in bytes.
        rss_bytes: U64,
    },
    /// The load ended with no model.
    LoadEnded {
        /// The load's identifier.
        id: U64,
        /// Why.
        why: LoadEnd,
        /// What the process said, when it said anything.
        detail: Nullable<String>,
    },
    /// A job produced bytes, which nothing has trusted yet.
    Produced {
        /// The job's identifier.
        id: U64,
        /// What the model produced.
        bytes: Bytes,
        /// Where the job's time went.
        phases: Phases,
        /// The process's largest resident set during the job, in bytes.
        peak_rss_bytes: U64,
    },
    /// A job ended with nothing.
    Ended {
        /// The job's identifier.
        id: U64,
        /// Why.
        why: JobEnd,
        /// What the process said, when it said anything.
        detail: Nullable<String>,
    },
    /// A file was checked.
    Verified {
        /// The check's identifier.
        id: U64,
        /// How it came out.
        result: VerifyResult,
        /// What the process said, when it said anything.
        detail: Nullable<String>,
    },
    /// The control thread has read a cancellation of this work, which is still running.
    ///
    /// It says the process is listening, and nothing about when the work will stop: the work's own
    /// answer says that. A process whose control thread does not say it has read a cancellation is
    /// one that is not reading.
    Cancelling {
        /// The work being cancelled.
        id: U64,
    },
}

impl Answer {
    /// Returns the identifier of the work this answers, which `ready` has none of.
    #[must_use]
    pub const fn id(&self) -> Option<u64> {
        match self {
            Self::Ready { .. } => None,
            Self::Loaded { id, .. }
            | Self::LoadEnded { id, .. }
            | Self::Produced { id, .. }
            | Self::Ended { id, .. }
            | Self::Verified { id, .. }
            | Self::Cancelling { id } => Some(id.get()),
        }
    }
}

/// The background class a process applied, as it reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Background {
    /// The mechanism, by its stable name.
    pub mechanism: String,
    /// Whether the processor class was changed.
    pub cpu: bool,
    /// Whether an IO class was changed.
    pub io: bool,
    /// Why nothing was applied, when nothing was.
    pub why: Nullable<String>,
}

impl From<Applied> for Background {
    fn from(applied: Applied) -> Self {
        Self {
            mechanism: applied.mechanism.as_str().to_owned(),
            cpu: applied.cpu,
            io: applied.io,
            why: Nullable(applied.why.map(str::to_owned)),
        }
    }
}

/// Why a load ended with no model.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LoadEnd {
    /// It was cancelled.
    Cancelled,
    /// It passed its deadline.
    DeadlineExceeded,
    /// Another description process held this environment's lock until the deadline.
    LockHeld,
    /// The process would not load this: a profile its catalogue does not hold.
    Refused,
    /// A file of the profile is missing, cannot be read or is not the one the profile records.
    Assets,
    /// The runtime could not load it.
    Failed,
}

impl LoadEnd {
    /// Returns the stable name this ending is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::LockHeld => "lock_held",
            Self::Refused => "refused",
            Self::Assets => "assets",
            Self::Failed => "failed",
        }
    }
}

/// Why a job ended with nothing.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum JobEnd {
    /// It was cancelled.
    Cancelled,
    /// It passed its deadline.
    DeadlineExceeded,
    /// The process's resident set passed the ceiling, and the job was ended between tokens.
    MemoryCeiling,
    /// No model was loaded.
    NotLoaded,
    /// The process would not run it: more work was waiting than it holds.
    Refused,
    /// The runtime failed.
    Failed,
}

impl JobEnd {
    /// Returns the stable name this ending is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::MemoryCeiling => "memory_ceiling",
            Self::NotLoaded => "not_loaded",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }
}

/// How the check of one file came out.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum VerifyResult {
    /// The file is the one the profile records: its size and its digest.
    Verified,
    /// The file is not the one the profile records.
    Mismatch,
    /// The file could not be read.
    Unreadable,
    /// The check was cancelled.
    Cancelled,
    /// The check passed its deadline.
    DeadlineExceeded,
    /// The process would not check it: a profile or a file its catalogue does not hold, or more
    /// work waiting than it holds.
    Refused,
}

impl VerifyResult {
    /// Returns the stable name this result is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
            Self::Unreadable => "unreadable",
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Refused => "refused",
        }
    }
}

/// Where one job's time went.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Phases {
    /// How many tokens the prompt was.
    pub prompt_tokens: U64,
    /// How long reading the prompt took, in milliseconds.
    pub prompt_ms: U64,
    /// How long choosing tokens took, in milliseconds.
    pub sampling_ms: U64,
    /// How long producing the chosen tokens took, in milliseconds.
    pub decode_ms: U64,
}

/// Why a frame could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The stream ended inside a frame.
    #[error("the stream ended {read} bytes into a frame of {expected}")]
    Truncated {
        /// How many bytes of the frame arrived.
        read: usize,
        /// How many there were to be, as far as the stream had said.
        expected: usize,
    },
    /// A frame broke the codec's rules or its payload was not a message of this wire.
    #[error("a frame was refused: {0}")]
    Frame(FrameError),
    /// The stream itself failed.
    #[error("the stream failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Frames one message.
///
/// # Errors
///
/// Returns [`WireError::Frame`] when the message cannot be represented or is over the bound.
pub fn frame_of<T: Serialize + ?Sized>(message: &T) -> Result<Vec<u8>, WireError> {
    CODEC.encode_message(message).map_err(WireError::Frame)
}

/// Writes one message as one frame, and flushes it.
///
/// # Errors
///
/// Returns [`WireError::Frame`] for a message that cannot be framed, and [`WireError::Io`] when the
/// stream refuses the bytes.
pub fn write_message<T: Serialize + ?Sized>(
    writer: &mut impl Write,
    message: &T,
) -> Result<(), WireError> {
    let frame = frame_of(message)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

/// Reads one whole frame's payload, or `None` when the stream ends between frames.
///
/// The length is checked against the bound before the payload is allocated or read. A stream that
/// ends anywhere inside a frame, in its length or in its payload, is a truncated frame rather than
/// an end: the peer said it was sending more and did not.
///
/// # Errors
///
/// Returns [`WireError::Truncated`] for a frame cut short, [`WireError::Frame`] for a length the
/// codec refuses, and [`WireError::Io`] when the stream fails.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, WireError> {
    let mut prefix = [0_u8; FRAME_LENGTH_PREFIX_LEN];
    let read = read_up_to(reader, &mut prefix)?;
    if read == 0 {
        return Ok(None);
    }
    if read < FRAME_LENGTH_PREFIX_LEN {
        return Err(WireError::Truncated {
            read,
            expected: FRAME_LENGTH_PREFIX_LEN,
        });
    }
    let length = CODEC.decode_length(prefix).map_err(WireError::Frame)?;
    let mut payload = vec![0_u8; length];
    let read = read_up_to(reader, &mut payload)?;
    if read < length {
        return Err(WireError::Truncated {
            read: FRAME_LENGTH_PREFIX_LEN + read,
            expected: FRAME_LENGTH_PREFIX_LEN + length,
        });
    }
    Ok(Some(payload))
}

/// Reads one message, or `None` when the stream ends between frames.
///
/// # Errors
///
/// As [`read_frame`], and [`WireError::Frame`] when the payload is not a canonical message of the
/// expected shape.
pub fn read_message<T: WireMessage>(reader: &mut impl Read) -> Result<Option<T>, WireError> {
    let Some(payload) = read_frame(reader)? else {
        return Ok(None);
    };
    kr_protocol::wire::decode(&payload, &StreamKind::Control.cbor_limits())
        .map(Some)
        .map_err(|error| WireError::Frame(FrameError::Cbor(error)))
}

/// Reads until the buffer is full or the stream ends, and returns how much was read.
fn read_up_to(reader: &mut impl Read, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}
