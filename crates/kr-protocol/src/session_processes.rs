//! The processes a session's worker had recorded, each read against the operating system, and the
//! method that answers it.
//!
//! A session's worker keeps a record of the processes it owns: the root shell, the servers it
//! started for the session and the processes seen below them. The daemon reads that record and
//! asks the operating system, through its own process interfaces, what each recorded process is
//! now. No tool's output and no terminal text is read.
//!
//! * **`recorded` is the label.** The answer lists what the worker had recorded at its last write,
//!   each identity checked at the moment of the call. It is not a live enumeration: a process that
//!   started and ended between two of the worker's observations is not in it, nor is one that left
//!   the boundary the worker watches before it was seen. The record carries no time, so the
//!   method's documentation states the worker's cadence instead.
//! * **A process is its start, not its number.** A row holds the process identifier together with
//!   the start the kernel recorded for it, so a number that was reused is another process and the
//!   recorded one reads as `ended`.
//! * **Facts only for a process that ran throughout.** A running row may hold its parent, as an
//!   identity, and the base name of its executable. Both are read between two questions about the
//!   recorded identity and kept only when the process answered running at both.
//! * **The boot decides what a start means.** Start values mean nothing in another boot. A record
//!   of an earlier boot lists every row as `ended`; a record that names no boot, or one that cannot
//!   be compared with this boot, lists every row as `unknown`, and neither is asked about.
//! * **The answer is bounded.** At most [`MAX_PROCESS_ROWS`] rows, the root first, then the servers,
//!   then the rest by start; the rest are counted in [`SessionProcessesResult::omitted`]. Names,
//!   the boundary, the control group and each limit are cut on a character boundary.
//! * **A name is application text.** A client escapes control characters before it shows one.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::identity::ProcessStartIdentity;
use crate::ids::SessionId;
use crate::scalars::{Nullable, U64};

/// How many rows an answer lists. The worker's record holds up to this many processes, and twice as
/// many while one of its observations is out.
pub const MAX_PROCESS_ROWS: usize = 1024;

/// The longest executable name a row keeps, in bytes.
pub const MAX_PROCESS_NAME_BYTES: usize = 255;

/// How many of the record's limits an answer keeps, besides the sentences the host adds.
pub const MAX_PROCESS_LIMITS: usize = 16;

/// The longest limit an answer keeps, in bytes.
pub const MAX_PROCESS_LIMIT_BYTES: usize = 512;

/// The longest statement of the worker's boundary an answer keeps, in bytes.
pub const MAX_PROCESS_BOUNDARY_BYTES: usize = 512;

/// The longest control group an answer keeps, in bytes.
pub const MAX_PROCESS_CGROUP_BYTES: usize = 4096;

/// Parameters of `session.processes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionProcessesParams {
    /// The session whose processes are listed.
    pub session_id: SessionId,
}

/// What the list is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessListing {
    /// What the session's worker recorded at its last write, each identity checked against the
    /// operating system at the moment of the call.
    Recorded,
}

/// How the boot the record was written in compares with this boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessBoot {
    /// The same boot: the recorded start values mean what the kernel reads now.
    Same,
    /// An earlier boot: no recorded process can still be running.
    Earlier,
    /// The record names no boot, so its start values cannot be tied to one.
    Unrecorded,
    /// The record's boot and this boot cannot be compared.
    Incomparable,
}

/// What a listed process is to the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRole {
    /// The session's root shell.
    Root,
    /// A process the worker started for the session besides its root shell: an application's
    /// server.
    Backend,
    /// A process seen below the root or a server.
    Descendant,
}

/// What the operating system says of a recorded process now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStanding {
    /// The recorded process runs, and ran from the first question to the last.
    Running,
    /// The recorded process is gone, or its number belongs to another process now.
    Ended,
    /// Nothing established either: the operating system did not answer, the record cannot be tied
    /// to this boot, or the identity cannot tell two processes apart.
    Unknown,
}

/// One recorded process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionProcess {
    /// The process identifier and the start the kernel recorded for it.
    pub process: ProcessStartIdentity,
    /// What it is to the session.
    pub role: ProcessRole,
    /// What the operating system says of it now.
    pub state: ProcessStanding,
    /// Its parent when it was read, as an identity, for a running row whose parent the platform
    /// gives. Null for every other row.
    pub parent: Nullable<ProcessStartIdentity>,
    /// The base name of its executable, for a running row whose executable the platform gives, as
    /// lossy UTF-8 of at most [`MAX_PROCESS_NAME_BYTES`] bytes. Null for every other row.
    pub name: Nullable<String>,
}

/// The result of `session.processes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionProcessesResult {
    /// The session.
    pub session_id: SessionId,
    /// What the list is.
    pub listing: ProcessListing,
    /// How the boot of the record compares with this one.
    pub boot: ProcessBoot,
    /// What the session's ownership rests on, in the worker's own words, cut at
    /// [`MAX_PROCESS_BOUNDARY_BYTES`] bytes.
    pub boundary: String,
    /// What cannot be established about the session's processes: the host's own sentences first,
    /// then at most [`MAX_PROCESS_LIMITS`] of the worker's, each cut at
    /// [`MAX_PROCESS_LIMIT_BYTES`] bytes, and a last sentence counting the worker's that were left
    /// out.
    pub limits: Vec<String>,
    /// The control group the worker ran in, on a platform that has them, cut at
    /// [`MAX_PROCESS_CGROUP_BYTES`] bytes.
    pub cgroup: Nullable<String>,
    /// The recorded processes: the root, then the servers, then the rest by start.
    pub processes: Vec<SessionProcess>,
    /// How many recorded processes are not listed, beyond [`MAX_PROCESS_ROWS`].
    pub omitted: U64,
}
