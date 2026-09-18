//! Session lifecycle types and the parameters of the session method group.
//!
//! Section 7 fixes the lifecycle as `creating -> live -> closing -> closed`. A live session may
//! have no attachments at all; presentation is not existence. Closure is a state with a durable
//! record, not the absence of a row: a closed session still answers `session.read` with its
//! closure record rather than starting anything.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

use crate::identity::{DesktopBinding, ProcessStartIdentity, WorkerProfile};
use crate::ids::{EnvironmentId, SessionEpoch, SessionId};
use crate::scalars::{Nullable, TimestampMs, U64};

/// The local alias a person types instead of a session UUID.
///
/// Display numbers are allocated in increasing order within one environment and are never reused,
/// so a number that named a closed session never names a different one later. The protocol
/// identity remains the UUID; the same number in two environments is ambiguous and the CLI refuses
/// to guess.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct DisplayNumber(pub U64);

impl DisplayNumber {
    /// Wraps a raw number.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(U64::new(value))
    }

    /// Returns the raw number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Display for DisplayNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl FromStr for DisplayNumber {
    type Err = core::num::ParseIntError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse::<u64>().map(Self::new)
    }
}

impl JsonSchema for DisplayNumber {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DisplayNumber".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::DisplayNumber".into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = U64::json_schema(generator);
        schema.insert(
            "description".to_owned(),
            "A local session alias, allocated in increasing order per environment and never reused."
                .into(),
        );
        schema
    }
}

/// The session lifecycle of section 7.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// The controller has reserved the session and the worker has not yet reported a live shell.
    Creating,
    /// The root shell is running. The session may have no attachments.
    Live,
    /// Closure has begun: input is rejected and owned processes are being stopped.
    Closing,
    /// Closure has finished and the closure record is final.
    Closed,
}

impl SessionState {
    /// Every state, in lifecycle order.
    pub const ALL: &'static [Self] = &[Self::Creating, Self::Live, Self::Closing, Self::Closed];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Live => "live",
            Self::Closing => "closing",
            Self::Closed => "closed",
        }
    }

    /// Returns the states this state may move to.
    #[must_use]
    pub const fn permitted_transitions(self) -> &'static [Self] {
        match self {
            Self::Creating => &[Self::Live, Self::Closing, Self::Closed],
            Self::Live => &[Self::Closing],
            Self::Closing => &[Self::Closed],
            Self::Closed => &[],
        }
    }

    /// Returns true when moving from this state to `next` is permitted.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        self.permitted_transitions().contains(&next)
    }

    /// Returns true when the session still owns a running worker.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Creating | Self::Live | Self::Closing)
    }

    /// Returns true when the session accepts input.
    #[must_use]
    pub const fn accepts_input(self) -> bool {
        matches!(self, Self::Live)
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How the root shell is integrated.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ShellMode {
    /// A KalaReach-qualified shell package with the reader mailbox, the pre-EOF hook and the
    /// fenced launch transaction.
    Managed,
    /// An explicitly selected stock shell. Create, attach, detach, close, transfer and terminal
    /// presentation all work. Empty-prompt Ctrl-D, fenced `shell.launch` and authoritative
    /// editor-buffer observation do not: Ctrl-D follows the shell's own behaviour and can close
    /// the session, and `kr detach` remains available.
    NativeCompat,
}

impl ShellMode {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::NativeCompat => "native_compat",
        }
    }

    /// Returns true when the mode claims the managed empty-prompt Ctrl-D and fenced launch.
    #[must_use]
    pub const fn claims_managed_editor(self) -> bool {
        matches!(self, Self::Managed)
    }
}

impl fmt::Display for ShellMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How a new session is presented locally.
///
/// The three are mutually exclusive. `attach` is the default when standard input and output are
/// terminals; otherwise the caller states one.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Presentation {
    /// Create and attach in the calling terminal.
    Attach,
    /// Create and open an installed terminal application running `kr attach`.
    Terminal,
    /// Create without any local terminal attachment.
    Invisible,
}

impl Presentation {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Terminal => "terminal",
            Self::Invisible => "invisible",
        }
    }
}

/// What the foreground of a session is doing.
///
/// Application state is reported separately from the lifecycle state and from transport
/// reachability; a busy agent and an unreachable client are different facts.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationState {
    /// The root shell is at a prompt.
    ShellReady,
    /// An agent is working.
    AgentBusy,
    /// A foreground application is waiting for input.
    AwaitingInput,
    /// A pending approval is waiting for a decision.
    AwaitingApproval,
}

/// Why a session closed.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ClosureReason {
    /// An authorised `session.close`.
    CloseRequested,
    /// The root shell exited normally, including through its own end-of-file behaviour.
    RootExit,
    /// The root shell was terminated by a signal.
    RootSignal,
    /// The root shell never started.
    RootLaunchFailed,
    /// The worker process ended without completing closure; the controller recorded the closure.
    WorkerCrash,
    /// The login session a desktop-bound worker was bound to ended.
    DesktopLost,
    /// The host is shutting down.
    HostShutdown,
}

impl ClosureReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloseRequested => "close_requested",
            Self::RootExit => "root_exit",
            Self::RootSignal => "root_signal",
            Self::RootLaunchFailed => "root_launch_failed",
            Self::WorkerCrash => "worker_crash",
            Self::DesktopLost => "desktop_lost",
            Self::HostShutdown => "host_shutdown",
        }
    }
}

/// How completely the closure covered the session's owned processes.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipCoverage {
    /// Every process the worker owned was accounted for.
    Complete,
    /// One or more owned processes could not be confirmed. The record never claims that every
    /// possible application was discovered.
    Incomplete,
}

/// Whether a result was recorded durably.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    /// The result is committed to the durable journal.
    Durable,
    /// The journal was unavailable, so the result used current in-memory authority and identities.
    /// Storage failure must not prevent an authorised stop; the response says so outright.
    Volatile,
}

/// One process the closure terminated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TerminatedProcess {
    /// The process and its start identity, so a reused identifier is not mistaken for it.
    pub identity: ProcessStartIdentity,
    /// The executable name, for diagnostics.
    pub name: Nullable<String>,
    /// True when the process needed forced termination after the grace period.
    pub forced: bool,
}

/// A resource that intentionally outlives the session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurvivingResource {
    /// What kind of resource it is.
    pub kind: String,
    /// A description for the user.
    pub detail: String,
}

/// The final record of one closed session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClosureRecord {
    /// The session that closed.
    pub session_id: SessionId,
    /// The epoch that closed.
    pub session_epoch: SessionEpoch,
    /// Why it closed.
    pub reason: ClosureReason,
    /// The root shell's exit status, when it exited normally.
    pub root_exit_code: Nullable<U64>,
    /// The signal that terminated the root shell, when one did, named as the platform names it.
    /// The host reports what it was told rather than inventing a number for it.
    pub root_signal: Nullable<String>,
    /// The owned processes the closure terminated, with their start identities.
    pub terminated: Vec<TerminatedProcess>,
    /// Resources known to survive, such as an explicitly brokered desktop resource.
    pub surviving: Vec<SurvivingResource>,
    /// Whether every owned process was accounted for.
    pub ownership_coverage: OwnershipCoverage,
    /// Whether the record was written durably.
    pub durability: Durability,
    /// When the session finished closing.
    pub closed_at_ms: TimestampMs,
}

/// One environment variable in a create request's snapshot.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentVariable {
    /// The name.
    pub name: String,
    /// The value.
    pub value: String,
}

/// A terminal geometry in columns and rows.
///
/// Every constraint of section 8 is checked by [`Dimensions::validate`] before anything is
/// allocated: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, all three at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dimensions {
    /// Columns, from 1 to 2,048.
    pub columns: U64,
    /// Rows, from 1 to 1,024.
    pub rows: U64,
}

/// Maximum columns a session may have.
pub const MAX_COLUMNS: u64 = 2_048;

/// Maximum rows a session may have.
pub const MAX_ROWS: u64 = 1_024;

/// Maximum cells a session may have.
///
/// The independent maxima need not be valid together; all three constraints apply at once.
pub const MAX_CELLS: u64 = 262_144;

/// The default geometry of a session created without a terminal attachment.
pub const INVISIBLE_DEFAULT_DIMENSIONS: Dimensions = Dimensions::new(120, 40);

/// A dimension constraint that a requested geometry violated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DimensionsError {
    /// Columns were zero or above the maximum.
    Columns {
        /// The requested columns.
        requested: u64,
        /// The maximum permitted.
        limit: u64,
    },
    /// Rows were zero or above the maximum.
    Rows {
        /// The requested rows.
        requested: u64,
        /// The maximum permitted.
        limit: u64,
    },
    /// The product of columns and rows exceeded the cell maximum.
    Cells {
        /// The requested cells, computed with checked multiplication.
        requested: u64,
        /// The maximum permitted.
        limit: u64,
    },
}

impl fmt::Display for DimensionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Columns { requested, limit } => {
                write!(
                    formatter,
                    "columns {requested} must be between 1 and {limit}"
                )
            }
            Self::Rows { requested, limit } => {
                write!(formatter, "rows {requested} must be between 1 and {limit}")
            }
            Self::Cells { requested, limit } => {
                write!(formatter, "cells {requested} must not exceed {limit}")
            }
        }
    }
}

impl std::error::Error for DimensionsError {}

impl Dimensions {
    /// Builds a geometry without checking it.
    #[must_use]
    pub const fn new(columns: u64, rows: u64) -> Self {
        Self {
            columns: U64::new(columns),
            rows: U64::new(rows),
        }
    }

    /// Returns the columns.
    #[must_use]
    pub const fn columns(self) -> u64 {
        self.columns.get()
    }

    /// Returns the rows.
    #[must_use]
    pub const fn rows(self) -> u64 {
        self.rows.get()
    }

    /// Checks the three constraints of section 8 before anything is allocated.
    ///
    /// All three apply at once and the cell count uses checked multiplication, so a geometry that
    /// satisfies the independent maxima can still be rejected.
    ///
    /// # Errors
    ///
    /// Returns the first violated constraint with its limit.
    pub const fn validate(self) -> Result<(), DimensionsError> {
        let columns = self.columns.get();
        let rows = self.rows.get();
        if columns == 0 || columns > MAX_COLUMNS {
            return Err(DimensionsError::Columns {
                requested: columns,
                limit: MAX_COLUMNS,
            });
        }
        if rows == 0 || rows > MAX_ROWS {
            return Err(DimensionsError::Rows {
                requested: rows,
                limit: MAX_ROWS,
            });
        }
        let Some(cells) = columns.checked_mul(rows) else {
            return Err(DimensionsError::Cells {
                requested: u64::MAX,
                limit: MAX_CELLS,
            });
        };
        if cells > MAX_CELLS {
            return Err(DimensionsError::Cells {
                requested: cells,
                limit: MAX_CELLS,
            });
        }
        Ok(())
    }

    /// Returns every constraint this geometry violates, in the order section 8 states them.
    ///
    /// [`Dimensions::validate`] stops at the first, which is what an error carries. A request can
    /// break more than one at a time - too many columns *and* too many cells - and a caller that
    /// wants to tell somebody everything that is wrong with what they asked for reads this.
    #[must_use]
    pub fn violations(self) -> Vec<DimensionsError> {
        let columns = self.columns.get();
        let rows = self.rows.get();
        let mut violated = Vec::new();
        if columns == 0 || columns > MAX_COLUMNS {
            violated.push(DimensionsError::Columns {
                requested: columns,
                limit: MAX_COLUMNS,
            });
        }
        if rows == 0 || rows > MAX_ROWS {
            violated.push(DimensionsError::Rows {
                requested: rows,
                limit: MAX_ROWS,
            });
        }
        // Zero cells break no cell bound, so a zero dimension is reported as the zero it is rather
        // than as a cell count as well.
        if columns > 0 && rows > 0 {
            match columns.checked_mul(rows) {
                Some(cells) if cells <= MAX_CELLS => {}
                Some(cells) => violated.push(DimensionsError::Cells {
                    requested: cells,
                    limit: MAX_CELLS,
                }),
                None => violated.push(DimensionsError::Cells {
                    requested: u64::MAX,
                    limit: MAX_CELLS,
                }),
            }
        }
        violated
    }
}

impl fmt::Display for Dimensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}x{}", self.columns, self.rows)
    }
}

/// What a client knows about one session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionSummary {
    /// The session identity.
    pub session_id: SessionId,
    /// The epoch. Fixed at 1 in this version.
    pub session_epoch: SessionEpoch,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The local alias.
    pub display_number: DisplayNumber,
    /// The lifecycle state.
    pub state: SessionState,
    /// How the root shell is integrated. A `native_compat` session is labelled everywhere it is
    /// reported.
    pub shell_mode: ShellMode,
    /// The executable actually launched as the root shell.
    pub shell_path: String,
    /// The working directory the root shell started in.
    pub cwd: String,
    /// How long the worker's execution context lasts.
    pub worker_profile: WorkerProfile,
    /// The login session a desktop-bound worker is tied to.
    pub desktop: DesktopBinding,
    /// When the session was created.
    pub created_at_ms: TimestampMs,
    /// The current canonical geometry.
    pub dimensions: Dimensions,
    /// How many attachments the session currently has. A live session may have none.
    pub attachment_count: U64,
    /// What the foreground is doing, where the host knows.
    pub application_state: Nullable<ApplicationState>,
    /// The root shell's process identity while the session is running.
    pub root_process: Nullable<ProcessStartIdentity>,
    /// The final record, once the session has closed.
    pub closure: Nullable<ClosureRecord>,
}

/// A palette a session can be started with, chosen before the shell has produced anything.
///
/// Section 8 fixes the palette at creation and records where it came from. A preset is what a
/// no-probe or invisible creation selects, because neither has a terminal whose colours could be
/// asked for; the probe form carries the foreground and background a client learned from its own
/// bounded probe of the terminal the person is sitting at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PaletteRequest {
    /// One of the two presets.
    Preset(PalettePreset),
    /// The colours a client shared from its bounded probe.
    Probe(ProbedPalette),
}

impl PaletteRequest {
    /// Whether this form needs a terminal to have been asked.
    ///
    /// An invisible creation has no terminal, so colours attributed to a probe of one would be an
    /// invented provenance rather than a shared measurement.
    #[must_use]
    pub const fn needs_a_terminal(self) -> bool {
        matches!(self, Self::Probe(_))
    }
}

/// One of the two palettes a creation can select without asking a terminal anything.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PalettePreset {
    /// Dark text on a light background.
    Light,
    /// Light text on a dark background.
    Dark,
}

impl PalettePreset {
    /// Both presets, in declaration order.
    pub const ALL: [Self; 2] = [Self::Light, Self::Dark];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

impl fmt::Display for PalettePreset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The default foreground and background a client's bounded probe established.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbedPalette {
    /// The default foreground the terminal reported.
    pub foreground: crate::projection::Rgb,
    /// The default background the terminal reported.
    pub background: crate::projection::Rgb,
}

/// Parameters of `session.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionCreateParams {
    /// The environment to create in.
    pub environment_id: EnvironmentId,
    /// How the session is presented locally.
    pub presentation: Presentation,
    /// The shell to launch. Null selects the environment's configured default.
    pub shell: Nullable<String>,
    /// The shell integration mode.
    pub shell_mode: ShellMode,
    /// The working directory. Null selects the caller's directory from the snapshot.
    pub cwd: Nullable<String>,
    /// The starting geometry. Null uses the invisible default of 120x40.
    pub dimensions: Nullable<Dimensions>,
    /// How long the worker's execution context should last.
    pub worker_profile: WorkerProfile,
    /// The creator's environment snapshot. The host filters terminal identity and reserved
    /// KalaReach variables out of it, and execution-context values take precedence over it.
    pub environment_snapshot: Vec<EnvironmentVariable>,
    /// The palette this session starts with. Null takes the profile default.
    ///
    /// This is the one moment the palette can be chosen: section 8 fixes it at creation, and
    /// afterwards only an authorised explicit change moves it. The provenance is recorded either
    /// way, so a palette query can say where the session's colours came from.
    pub palette: Nullable<PaletteRequest>,
}

impl SessionCreateParams {
    /// Why this request's palette does not suit the presentation it asks for, when it does not.
    ///
    /// An invisible session has no terminal, so colours attributed to a bounded probe of one would
    /// record a provenance nothing measured. Such a creation selects a preset instead.
    #[must_use]
    pub fn palette_refusal(&self) -> Option<String> {
        let request = self.palette.as_ref()?;
        (self.presentation == Presentation::Invisible && request.needs_a_terminal()).then(|| {
            "an invisible session has no terminal to probe, so its palette is a light or dark \
             preset rather than probed colours"
                .to_owned()
        })
    }
}

/// The result of `session.create`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionCreateResult {
    /// The created session.
    pub session: SessionSummary,
    /// The endpoint the creator can attach to without another controller call. Null when the
    /// session has already closed, which a repeated create token can return.
    pub endpoint: Nullable<String>,
    /// True when this result was replayed for a repeated create token rather than created now.
    pub deduplicated: bool,
    /// The presentation failure, when the session was created and its terminal could not be
    /// opened. The session above is real and usable; a failed presentation never retries
    /// execution and never creates a second session.
    pub presentation_error: Nullable<crate::error::ProtocolError>,
}

/// Parameters of `session.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionListParams {
    /// Restrict to one environment. Null lists every environment the caller may see.
    pub environment_id: Nullable<EnvironmentId>,
    /// Include sessions that have already closed.
    pub include_closed: bool,
}

/// The result of `session.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionListResult {
    /// The sessions, in display-number order.
    pub sessions: Vec<SessionSummary>,
}

/// Parameters of `session.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionReadParams {
    /// The session to read.
    pub session_id: SessionId,
}

/// The result of `session.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionReadResult {
    /// The session.
    pub session: SessionSummary,
    /// The endpoint a local client can attach to, while the session is running.
    pub endpoint: Nullable<String>,
}

/// Parameters of `session.close`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionCloseParams {
    /// The session to close.
    pub session_id: SessionId,
}

/// The result of `session.close`.
///
/// The initiating request receives this acceptance before the worker's own process can end.
/// Duplicate requests return the existing state rather than a second closure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionCloseResult {
    /// The session that is closing or has closed.
    pub session_id: SessionId,
    /// The state at the moment of the reply.
    pub state: SessionState,
    /// Whether the closure was recorded durably.
    pub durability: Durability,
    /// The final record, once closure has finished.
    pub closure: Nullable<ClosureRecord>,
}

#[cfg(test)]
mod tests {
    /// KR-REQ-08.44: the two forms a creation can name, spelled the way section 8 describes them.
    #[test]
    fn a_palette_request_is_either_a_preset_or_the_colours_a_probe_found() {
        use super::{PalettePreset, PaletteRequest, ProbedPalette};

        let preset = serde_json::to_value(PaletteRequest::Preset(PalettePreset::Light))
            .expect("a preset encodes");
        assert_eq!(preset, serde_json::json!({ "preset": "light" }));
        let probe = serde_json::to_value(PaletteRequest::Probe(ProbedPalette {
            foreground: crate::projection::Rgb {
                red: 0xd0,
                green: 0xd4,
                blue: 0xd8,
            },
            background: crate::projection::Rgb {
                red: 0x10,
                green: 0x12,
                blue: 0x18,
            },
        }))
        .expect("probed colours encode");
        assert_eq!(
            probe,
            serde_json::json!({
                "probe": {
                    "foreground": { "red": 208, "green": 212, "blue": 216 },
                    "background": { "red": 16, "green": 18, "blue": 24 },
                }
            })
        );
        assert!(
            PaletteRequest::Probe(ProbedPalette {
                foreground: crate::projection::Rgb {
                    red: 0,
                    green: 0,
                    blue: 0
                },
                background: crate::projection::Rgb {
                    red: 0,
                    green: 0,
                    blue: 0
                },
            })
            .needs_a_terminal()
        );
        assert!(!PaletteRequest::Preset(PalettePreset::Dark).needs_a_terminal());
    }

    /// KR-REQ-08.44: an invisible creation selects a preset, because it has nothing to probe.
    #[test]
    fn only_an_invisible_creation_refuses_a_probed_palette() {
        use super::{
            EnvironmentVariable, Nullable, PalettePreset, PaletteRequest, Presentation,
            ProbedPalette, SessionCreateParams, ShellMode,
        };

        let request = |presentation, palette| SessionCreateParams {
            environment_id: crate::ids::EnvironmentId::new(crate::scalars::Uuid::from_bytes(
                [7; 16],
            )),
            presentation,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::null(),
            dimensions: Nullable::null(),
            worker_profile: crate::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::<EnvironmentVariable>::new(),
            palette,
        };
        let probed = Nullable::some(PaletteRequest::Probe(ProbedPalette {
            foreground: crate::projection::Rgb {
                red: 1,
                green: 2,
                blue: 3,
            },
            background: crate::projection::Rgb {
                red: 4,
                green: 5,
                blue: 6,
            },
        }));
        assert!(
            request(Presentation::Invisible, probed.clone())
                .palette_refusal()
                .is_some()
        );
        assert!(
            request(Presentation::Attach, probed.clone())
                .palette_refusal()
                .is_none()
        );
        assert!(
            request(Presentation::Terminal, probed)
                .palette_refusal()
                .is_none()
        );
        assert!(
            request(
                Presentation::Invisible,
                Nullable::some(PaletteRequest::Preset(PalettePreset::Light))
            )
            .palette_refusal()
            .is_none()
        );
        assert!(
            request(Presentation::Invisible, Nullable::null())
                .palette_refusal()
                .is_none()
        );
    }

    /// KR-REQ-08.71: a request can break more than one constraint, and all of them are reportable.
    #[test]
    fn every_violated_constraint_is_reportable_and_the_error_carries_the_first() {
        use super::{DimensionsError, MAX_CELLS, MAX_COLUMNS, MAX_ROWS};

        assert!(Dimensions::new(80, 24).violations().is_empty());
        // Inside both independent maxima and outside the cell count, which is the case the "all
        // three at once" rule exists for.
        assert_eq!(
            Dimensions::new(MAX_COLUMNS, MAX_ROWS).violations(),
            vec![DimensionsError::Cells {
                requested: 2_097_152,
                limit: MAX_CELLS
            }]
        );
        // Two at once: too many columns and, with them, too many cells.
        assert_eq!(
            Dimensions::new(MAX_COLUMNS + 1, 1_000).violations(),
            vec![
                DimensionsError::Columns {
                    requested: MAX_COLUMNS + 1,
                    limit: MAX_COLUMNS
                },
                DimensionsError::Cells {
                    requested: 2_049_000,
                    limit: MAX_CELLS
                }
            ]
        );
        // Three at once, with a product that would wrap if it were not checked.
        assert_eq!(
            Dimensions::new(u64::MAX, u64::MAX).violations(),
            vec![
                DimensionsError::Columns {
                    requested: u64::MAX,
                    limit: MAX_COLUMNS
                },
                DimensionsError::Rows {
                    requested: u64::MAX,
                    limit: MAX_ROWS
                },
                DimensionsError::Cells {
                    requested: u64::MAX,
                    limit: MAX_CELLS
                }
            ]
        );
        // A zero dimension is the zero it is, and breaks no cell bound.
        assert_eq!(
            Dimensions::new(0, 24).violations(),
            vec![DimensionsError::Columns {
                requested: 0,
                limit: MAX_COLUMNS
            }]
        );
        // And the error carries the first of them, which is what a refusal names.
        assert_eq!(
            Dimensions::new(u64::MAX, u64::MAX).validate(),
            Err(DimensionsError::Columns {
                requested: u64::MAX,
                limit: MAX_COLUMNS
            })
        );
    }

    use super::*;

    #[test]
    fn the_lifecycle_runs_forward_only() {
        assert!(SessionState::Creating.can_transition_to(SessionState::Live));
        assert!(SessionState::Live.can_transition_to(SessionState::Closing));
        assert!(SessionState::Closing.can_transition_to(SessionState::Closed));
        assert!(!SessionState::Closed.can_transition_to(SessionState::Live));
        assert!(!SessionState::Live.can_transition_to(SessionState::Creating));
        assert!(!SessionState::Live.can_transition_to(SessionState::Closed));
    }

    #[test]
    fn all_three_dimension_constraints_apply_at_once() {
        assert!(Dimensions::new(120, 40).validate().is_ok());
        assert!(Dimensions::new(2_048, 1_024).validate().is_err());
        assert_eq!(
            Dimensions::new(0, 40).validate(),
            Err(DimensionsError::Columns {
                requested: 0,
                limit: MAX_COLUMNS
            })
        );
        assert_eq!(
            Dimensions::new(2_049, 40).validate(),
            Err(DimensionsError::Columns {
                requested: 2_049,
                limit: MAX_COLUMNS
            })
        );
        assert_eq!(
            Dimensions::new(120, 1_025).validate(),
            Err(DimensionsError::Rows {
                requested: 1_025,
                limit: MAX_ROWS
            })
        );
        // Both maxima are individually valid and the product is not.
        assert_eq!(
            Dimensions::new(2_048, 1_024).validate(),
            Err(DimensionsError::Cells {
                requested: 2_097_152,
                limit: MAX_CELLS
            })
        );
    }

    #[test]
    fn the_cell_count_cannot_overflow() {
        assert_eq!(
            Dimensions::new(u64::MAX, u64::MAX).validate(),
            Err(DimensionsError::Columns {
                requested: u64::MAX,
                limit: MAX_COLUMNS
            })
        );
    }

    #[test]
    fn native_compat_does_not_claim_the_managed_editor() {
        assert!(!ShellMode::NativeCompat.claims_managed_editor());
        assert!(ShellMode::Managed.claims_managed_editor());
    }
}
