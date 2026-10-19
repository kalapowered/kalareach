//! What a release keeps of the release before it, so that its control daemon can speak to a worker
//! that outlived an update.
//!
//! A worker keeps running across the update of the control daemon that started it, so a new daemon
//! meets workers built from an older release. Each release retains its own level
//! ([`THIS_LEVEL`]) and the one level before it ([`RETAINED_WORKER_LEVELS`]); a worker of any other
//! level holds an update back. For a retained level, the release keeps the surface that level
//! reads and writes (`crates/kr-protocol/retained/<level>/`): the definitions of the generated
//! schema reachable from [`SURFACE_ROOTS`], cut from the release when it was made.
//!
//! # What the check compares
//!
//! [`assess`] compares a retained surface with the surface this build has, definition by
//! definition, and every difference needs an entry in the level's tables: a [`Declared`] entry,
//! which says how a frame is rewritten on its way to and from that level, or a [`Compatible`]
//! entry, which says why nothing needs rewriting. An entry that matches no difference is stale and
//! fails the check too, so the tables hold exactly what the surfaces differ by. A difference in
//! what is frozen ([`FROZEN_ROOTS`], [`FROZEN_VARIANTS`]) can be covered by a [`Compatible`] entry
//! only: those are read before the level of the peer is known, or by a command that has no codec,
//! so no rewrite of them is applied.
//!
//! # What the codec does
//!
//! A [`Level`] is made from what a worker states about its build, and it is the only way to a
//! codec: [`Level::decode`] reads the payload of a frame under the level's surface before any
//! typed decoding, applies the entries' read rewrites, and only then lets this build's own
//! decoder read the result. [`Level::encode`] does the reverse: the entries' write rewrites, then a
//! check that the level's surface admits the frame, so a frame the level cannot read is refused by
//! name and nothing is sent.

pub mod surface;

use std::fmt;
use std::sync::OnceLock;

use kr_cbor::{CanonicalValue, Limits};
use thiserror::Error;

use crate::envelope::{ControlFrame, ParamsValue};
use crate::local::LocalBuild;
use crate::method::Method;
use crate::update::{CompatibilityLevel, THIS_LEVEL};
use crate::wire::{self, WireMessage};
pub use surface::{
    Difference, DifferenceKind, Plain, Refusal, Surface, SurfaceError, Visit, differences,
};

/// The levels besides its own that this release's control daemon speaks to a worker at.
///
/// Every entry has a directory `crates/kr-protocol/retained/<level>/` and a [`RetainedLevel`] in
/// [`RETAINED`]; `kr-protocol-gen --check` fails when the three disagree.
pub const RETAINED_WORKER_LEVELS: [CompatibilityLevel; 1] = [CompatibilityLevel::of(
    crate::hello::PackageVersion::new(0, 75, 0),
)];

/// The roots of the surface: the frames, the descriptor, and the parameters and results of the
/// reads the control daemon makes of a worker or interprets from its answers.
///
/// The lists a device is shown are the daemon's own answers and are not here, and neither are the
/// methods passed through for a device, whose parameters and results are opaque to the daemon.
pub const SURFACE_ROOTS: &[&str] = &[
    "ActionReadParams",
    "ActionReadResult",
    "AgentApprovalInspectParams",
    "AgentApprovalInspectResult",
    "ControlFrame",
    "EventsSnapshotParams",
    "EventsSnapshotResult",
    "QuestionReadOwnParams",
    "QuestionReadParams",
    "QuestionReadResult",
    "ReceiptResponse",
    "SessionCloseResult",
    "SessionReadParams",
    "SessionReadResult",
    "SessionScreenPreviewParams",
    "SessionScreenPreviewResult",
    "WorkerDescriptor",
];

/// The definitions, with everything they reach, that are read before the level of the peer is
/// known or by a command that has no codec: the opening frames, the proof of identity, the
/// envelopes of a request and its answer, and the probe that asks a worker whether a process is in
/// its session.
pub const FROZEN_ROOTS: &[&str] = &[
    "CallerToken",
    "ControlEvent",
    "LocalHello",
    "LocalHelloAck",
    "Outcome",
    "PluginRuntimeUnavailable",
    "ProtocolError",
    "QuestionId",
    "QuestionReadOwnParams",
    "Request",
    "Response",
    "WorkerVerifyChallenge",
    "WorkerVerifyProof",
];

/// The variants and members frozen in definitions that are otherwise the level's: the keys of the
/// frames above, the refusals that go out in this build's shape to a worker whose level is not
/// recorded, and the session a running worker's first question names, which the daemon reads before
/// it knows the level to read the rest under. Each is a place of a [`Difference`] up to the next
/// `.`, `#` or `[`.
pub const FROZEN_VARIANTS: &[&str] = &[
    "ControlFrame#key:draft_answer",
    "ControlFrame#key:draft_wanted",
    "ControlFrame#key:event",
    "ControlFrame#key:hello",
    "ControlFrame#key:hello_ack",
    "ControlFrame#key:plugin_runtime_state",
    "ControlFrame#key:plugin_runtime_wanted",
    "ControlFrame#key:rendezvous",
    "ControlFrame#key:request",
    "ControlFrame#key:response",
    "ControlFrame#key:verify_challenge",
    "ControlFrame#key:verify_proof",
    "DraftAnswer#key:refused",
    "DraftWanted.session_id",
    "PluginRuntimeState#key:unavailable",
    "PluginRuntimeWanted.session_id",
];

/// The protocol the plugin host speaks to the workers that register with it.
///
/// A worker connects to its environment's one plugin host directly, so a daemon of one release can
/// meet a host of another and a worker of one release a host of another. The name is part of what
/// a retained level records (`PLUGIN_HOST`), and a bump needs the retained levels to speak both.
/// A host and a worker of another protocol refuse each other at the handshake, and a descriptor
/// that names another protocol is not one a worker uses: the control daemon takes it away and
/// starts a runtime of its own. The second protocol adds the request that prepares an action.
pub const PLUGIN_HOST_PROTOCOL: &str = "kr-plugin-host/2";

/// The definition that names the parameters of a read the control daemon makes of a worker itself,
/// by the method it makes it with.
#[must_use]
pub const fn params_root(method: Method) -> Option<&'static str> {
    match method {
        Method::SessionRead => Some("SessionReadParams"),
        Method::SessionScreenPreview => Some("SessionScreenPreviewParams"),
        Method::QuestionRead => Some("QuestionReadParams"),
        Method::AgentApprovalInspect => Some("AgentApprovalInspectParams"),
        Method::EventsSnapshot => Some("EventsSnapshotParams"),
        Method::ActionRead => Some("ActionReadParams"),
        _ => None,
    }
}

/// A rewrite of the value of one definition on its way to or from a retained level.
pub type Rewrite = fn(&mut CanonicalValue) -> Result<(), String>;

/// A pair of canonical frames that a test runs through the rewrites: the frame as this build has
/// it, and as the retained level has it.
#[derive(Clone, Copy, Debug)]
pub struct Golden {
    /// The frame as this build writes and reads it.
    pub current: &'static [u8],
    /// The same frame as the retained level writes and reads it.
    pub retained: &'static [u8],
}

/// How a frame changes on its way to and from a retained level, for one difference.
#[derive(Clone, Copy, Debug)]
pub struct Declared {
    /// The place of the difference this entry covers, as [`Difference::at`] names it.
    pub at: &'static str,
    /// Applied to the value of the definition when this build writes a frame for the level.
    pub write: Rewrite,
    /// Applied to the value of the definition when this build reads a frame of the level.
    pub read: Rewrite,
    /// A pair of frames the rewrites turn into each other, both ways.
    pub golden: &'static [Golden],
}

/// Why a difference needs no rewrite.
#[derive(Clone, Copy, Debug)]
pub struct Compatible {
    /// The place of the difference this entry covers, as [`Difference::at`] names it.
    pub at: &'static str,
    /// Why: a reviewed statement of what makes it safe.
    pub reason: &'static str,
}

/// A level this release retains, with the surface it kept and the entries that cover what that
/// surface differs by.
#[derive(Debug)]
pub struct RetainedLevel {
    /// The level.
    pub level: CompatibilityLevel,
    /// The surface document the level was cut into.
    pub surface: &'static str,
    /// The release record (`RELEASE`).
    pub release: &'static str,
    /// The protocol name the plugin host spoke at that release (`PLUGIN_HOST`).
    pub plugin_host: &'static str,
    /// The differences that need a rewrite.
    pub declared: &'static [Declared],
    /// The differences that need none.
    pub compatible: &'static [Compatible],
    /// The table of public majors the release had (`PUBLIC_MAJORS`), where it had one.
    pub public_majors: Option<&'static str>,
    parsed: OnceLock<Surface>,
}

impl RetainedLevel {
    /// A level with the documents it was cut into and the entries that cover its differences.
    #[must_use]
    pub const fn new(
        level: CompatibilityLevel,
        surface: &'static str,
        release: &'static str,
        plugin_host: &'static str,
        declared: &'static [Declared],
        compatible: &'static [Compatible],
    ) -> Self {
        Self {
            level,
            surface,
            release,
            plugin_host,
            declared,
            compatible,
            public_majors: None,
            parsed: OnceLock::new(),
        }
    }

    /// This level with the table of public majors its release recorded.
    #[must_use]
    pub const fn with_public_majors(mut self, recorded: &'static str) -> Self {
        self.public_majors = Some(recorded);
        self
    }

    /// The surface this level kept.
    ///
    /// # Panics
    ///
    /// When the document is not a surface, which `kr-protocol-gen --check` and a test of this
    /// crate rule out.
    #[must_use]
    pub fn surface(&self) -> &Surface {
        self.parsed
            .get_or_init(|| Surface::parse(self.surface).expect("a retained surface is a surface"))
    }

    /// A field of the release record, which is lines of `name=value`.
    #[must_use]
    pub fn record(&self, name: &str) -> Option<&'static str> {
        record(self.release, name)
    }
}

/// The levels this release retains, in the order of [`RETAINED_WORKER_LEVELS`].
pub static RETAINED: [RetainedLevel; 1] = [RetainedLevel::new(
    RETAINED_WORKER_LEVELS[0],
    include_str!("../retained/0.75/surface.schema.json"),
    include_str!("../retained/0.75/RELEASE"),
    include_str!("../retained/0.75/PLUGIN_HOST"),
    &[],
    &[
        Compatible {
            at: "ControllerConnectionRole#const:checks",
            reason: "the control daemon declares this role only to a worker at its own level, which \
                     it chooses by level for the disclosed checks, so a worker of the retained \
                     level is never asked for one",
        },
        Compatible {
            at: "ControlFrame#key:desktop_checks",
            reason: "the control daemon writes this request only on a checks connection to a \
                     worker at its own level, and a worker of the retained level never receives \
                     it",
        },
        Compatible {
            at: "ControlFrame#key:desktop_checks_answer",
            reason: "only a worker at the daemon's own level answers the request, so a worker of \
                     the retained level never writes this frame",
        },
        Compatible {
            at: "WorkerLaunchSpec.root_command",
            reason: "A member that is absent from the wire unless the daemon starts a session to run \
                     a command. The specification of an ordinary session is byte for byte what a \
                     worker of the retained level reads, and a worker of that level that is sent \
                     one with a command refuses the specification as a frame it cannot read, so \
                     it starts no shell in place of the command.",
        },
        Compatible {
            at: "WorkerLaunchSpec.workflow",
            reason: "A member that is absent from the wire unless a workflow started the session, \
                     and sent only together with a root command, so a worker of the retained \
                     level never meets it without also refusing the specification for the command.",
        },
        Compatible {
            at: "WorkerLaunchSpec.start_not_after_boot_ms",
            reason: "A member that is absent from the wire unless a workflow started the session, \
                     and sent only to the worker the daemon started that session with. The \
                     specification of an ordinary session is byte for byte what a worker of the \
                     retained level reads, and a worker of that level that is sent one with the \
                     member refuses the specification as a frame it cannot read, so it starts \
                     nothing the daemon bounded.",
        },
        Compatible {
            at: "ForwardedMutation.workflow_run_id",
            reason: "A member that is absent from the wire except in a workflow's close of a session \
                     it started, which the daemon sends only to the worker it started that \
                     session's command on, never to a worker of the retained level. Every other \
                     forwarded mutation is byte for byte what that level reads.",
        },
        Compatible {
            at: "SessionSummary.root",
            reason: "A member that is absent from the wire for the interactive shell every other \
                     session has. Summaries travel from a worker to the daemon, and a worker of \
                     the retained level never writes this member, so this build's daemon reads \
                     what it writes as a session whose root is a shell. A summary that carries \
                     the member is written only by a worker of this build, for a session it was \
                     started to run a command in.",
        },
        Compatible {
            at: "ForwardedMutation.lease",
            reason: "A member that is absent from the wire unless the daemon forwards a paired \
                     device's mutation to a worker at this release's own level, which holds the \
                     dispatch to the lease. The daemon omits it on a link to a worker of the \
                     retained level, which refuses the frame that carries it, so every forwarded \
                     mutation that level reads is byte for byte what it read before. Such a worker \
                     enforces the generation fence, the authority revision the grant was validated \
                     at and the deadline the lease bounds, and the daemon alone holds the lease for \
                     it.",
        },
    ],
)
.with_public_majors(include_str!("../retained/0.75/PUBLIC_MAJORS"))];

/// A level of a test's own: the surface this release retains besides its own, with its definitions
/// changed by `edit`, and `declared` as the entries that cover what it differs by.
///
/// The surface a release keeps equals the one it has until the release changes it, so a test that
/// needs a level whose frames differ makes one. The level lives for the rest of the process.
///
/// # Panics
///
/// When the edited document is not a surface.
#[cfg(feature = "testing")]
pub fn a_level_of_the_tests_own(
    edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    declared: &'static [Declared],
) -> Level {
    let kept = &RETAINED[0];
    let mut document: serde_json::Value =
        serde_json::from_str(&kept.surface().render()).expect("a surface renders as a document");
    edit(
        document
            .get_mut("$defs")
            .and_then(serde_json::Value::as_object_mut)
            .expect("a surface has definitions"),
    );
    drop_what_no_root_reaches(&mut document);
    let text = serde_json::to_string(&document).expect("a document is text");
    Surface::parse(&text).expect("an edited surface is a surface");
    Level::retained(Box::leak(Box::new(RetainedLevel::new(
        kept.level,
        Box::leak(text.into_boxed_str()),
        kept.release,
        kept.plugin_host,
        declared,
        &[],
    ))))
}

/// Removes the definitions of a surface document that no root reaches any more, as an edit that
/// removes a variant leaves the definition it carried.
#[cfg(feature = "testing")]
fn drop_what_no_root_reaches(document: &mut serde_json::Value) {
    use std::collections::BTreeSet;

    fn references(value: &serde_json::Value, found: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(members) => {
                for (key, member) in members {
                    if key == "$ref" {
                        if let Some(name) = member
                            .as_str()
                            .and_then(|text| text.strip_prefix("#/$defs/"))
                        {
                            found.push(name.to_owned());
                        }
                    } else {
                        references(member, found);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    references(item, found);
                }
            }
            _ => {}
        }
    }

    let mut reached: BTreeSet<String> = document
        .get("roots")
        .and_then(serde_json::Value::as_array)
        .map(|roots| {
            roots
                .iter()
                .filter_map(|root| root.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut pending: Vec<String> = reached.iter().cloned().collect();
    while let Some(name) = pending.pop() {
        let mut found = Vec::new();
        if let Some(definition) = document.get("$defs").and_then(|defs| defs.get(&name)) {
            references(definition, &mut found);
        }
        for next in found {
            if reached.insert(next.clone()) {
                pending.push(next);
            }
        }
    }
    if let Some(definitions) = document
        .get_mut("$defs")
        .and_then(serde_json::Value::as_object_mut)
    {
        definitions.retain(|name, _| reached.contains(name));
    }
}

/// The value of `name` in a record of `name=value` lines.
#[must_use]
pub fn record<'a>(record: &'a str, name: &str) -> Option<&'a str> {
    record
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.trim())
}

/// The surface this build has, cut from its generated schema.
///
/// # Panics
///
/// When a root names no definition, which a test of this crate rules out.
#[must_use]
pub fn current() -> &'static Surface {
    static CURRENT: OnceLock<Surface> = OnceLock::new();
    CURRENT.get_or_init(|| {
        Surface::cut(&crate::schema::protocol_schema(), SURFACE_ROOTS)
            .expect("the surface roots are definitions of the generated schema")
    })
}

/// The levels among `named` that a control daemon of this build does not speak at: neither its own
/// nor one it retains.
///
/// A release's manifest says which levels its daemon retains, and an update reads it to decide
/// whether a live worker holds the update back. A manifest that names a level the daemon's code
/// does not retain would let an update go on over a worker the daemon cannot read, so a daemon
/// whose manifest names one does not start. A manifest that names fewer levels than the daemon
/// speaks at only holds more updates back.
#[must_use]
pub fn levels_not_spoken(named: &[CompatibilityLevel]) -> Vec<CompatibilityLevel> {
    let spoken = levels();
    named
        .iter()
        .copied()
        .filter(|level| !spoken.contains(level))
        .collect()
}

/// The levels of this release's control daemon: its own, then the ones it retains.
#[must_use]
pub fn levels() -> Vec<CompatibilityLevel> {
    std::iter::once(THIS_LEVEL)
        .chain(RETAINED_WORKER_LEVELS)
        .collect()
}

/* -------------------------------------------------------------------------------------------- */
/* The check                                                                                    */
/* -------------------------------------------------------------------------------------------- */

/// What comparing a retained surface with this build's found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Assessment {
    /// Differences no entry covers.
    pub uncovered: Vec<Difference>,
    /// Differences in what is frozen that only a [`Compatible`] entry may cover and that a
    /// [`Declared`] entry covers.
    pub rewritten_but_frozen: Vec<Difference>,
    /// Entries that match no difference.
    pub stale: Vec<&'static str>,
    /// Frozen definitions that the retained surface or this build's lacks, so that a change to
    /// them could not be seen.
    pub absent: Vec<String>,
}

impl Assessment {
    /// Whether the entries cover every difference and nothing else.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.uncovered.is_empty()
            && self.rewritten_but_frozen.is_empty()
            && self.stale.is_empty()
            && self.absent.is_empty()
    }
}

impl fmt::Display for Assessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for difference in &self.uncovered {
            writeln!(formatter, "not covered by an entry: {difference}")?;
        }
        for difference in &self.rewritten_but_frozen {
            writeln!(
                formatter,
                "frozen, so only a Compatible entry may cover it: {difference}"
            )?;
        }
        for at in &self.stale {
            writeln!(formatter, "an entry matches no difference: {at}")?;
        }
        for name in &self.absent {
            writeln!(
                formatter,
                "a frozen definition is not in both surfaces, so a change to it would not be seen: {name}"
            )?;
        }
        Ok(())
    }
}

/// Compares the surface a level kept with the surface this build has, against the level's entries.
#[must_use]
pub fn assess(
    old: &Surface,
    new: &Surface,
    declared: &[Declared],
    compatible: &[Compatible],
) -> Assessment {
    let frozen: std::collections::BTreeSet<String> = old
        .closure(
            &FROZEN_ROOTS
                .iter()
                .copied()
                .filter(|root| old.definition(root).is_some())
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default();
    let found = differences(old, new);
    let mut assessment = Assessment::default();
    for root in FROZEN_ROOTS {
        if old.definition(root).is_none() || new.definition(root).is_none() {
            assessment.absent.push((*root).to_owned());
        }
    }
    let mut matched: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for difference in &found {
        let is_frozen = frozen.contains(difference.definition())
            || FROZEN_VARIANTS
                .iter()
                .any(|variant| within(&difference.at, variant));
        let by_compatible = compatible.iter().find(|entry| entry.at == difference.at);
        let by_declared = declared.iter().find(|entry| entry.at == difference.at);
        if let Some(entry) = by_compatible {
            matched.insert(entry.at);
        }
        if let Some(entry) = by_declared {
            matched.insert(entry.at);
        }
        if is_frozen {
            if by_declared.is_some() {
                assessment.rewritten_but_frozen.push(difference.clone());
            } else if by_compatible.is_none() {
                assessment.uncovered.push(difference.clone());
            }
        } else if by_declared.is_none() && by_compatible.is_none() {
            assessment.uncovered.push(difference.clone());
        }
    }
    for entry in compatible {
        if !matched.contains(entry.at) {
            assessment.stale.push(entry.at);
        }
    }
    for entry in declared {
        if !matched.contains(entry.at) && !assessment.stale.contains(&entry.at) {
            assessment.stale.push(entry.at);
        }
    }
    assessment
}

/// Whether `at` is `place` or inside it: the next character, if any, begins a member, a variant or
/// a nesting.
fn within(at: &str, place: &str) -> bool {
    at.strip_prefix(place)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '#', '[']))
}

/// Compares every retained level with this build, as `kr-protocol-gen --check` does.
///
/// Returns what is wrong, or nothing.
///
/// # Errors
///
/// Returns one line for each problem.
pub fn check() -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let kept: Vec<CompatibilityLevel> = RETAINED.iter().map(|retained| retained.level).collect();
    if kept != RETAINED_WORKER_LEVELS {
        problems.push(format!(
            "RETAINED holds levels {kept:?}, and RETAINED_WORKER_LEVELS lists {RETAINED_WORKER_LEVELS:?}"
        ));
    }
    for retained in &RETAINED {
        let assessment = assess(
            retained.surface(),
            current(),
            retained.declared,
            retained.compatible,
        );
        for line in assessment.to_string().lines() {
            problems.push(format!("level {}: {line}", retained.level));
        }
        if retained.plugin_host.trim() != PLUGIN_HOST_PROTOCOL {
            problems.push(format!(
                "level {} kept the plugin host protocol {}, and this build speaks {PLUGIN_HOST_PROTOCOL}",
                retained.level,
                retained.plugin_host.trim()
            ));
        }
        if THIS_LEVEL <= retained.level {
            problems.push(format!(
                "level {} is not below this build's level {THIS_LEVEL}",
                retained.level
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/* -------------------------------------------------------------------------------------------- */
/* Levels and the codec                                                                         */
/* -------------------------------------------------------------------------------------------- */

/// A worker states a build at a level this release does not speak at, or none.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("{}", match stated {
    Some(build) => format!("{} with protocol {}", build.build_id, build.protocol_version),
    None => "a build that states no protocol version".to_owned(),
})]
pub struct UnretainedLevel {
    /// What the worker stated.
    pub stated: Option<LocalBuild>,
}

/// A level this release speaks to a worker at: its own, or one it retains.
#[derive(Clone, Copy, Debug)]
pub struct Level(Which);

#[derive(Clone, Copy, Debug)]
enum Which {
    This,
    Retained(&'static RetainedLevel),
}

impl PartialEq for Level {
    fn eq(&self, other: &Self) -> bool {
        self.level() == other.level()
    }
}

impl Eq for Level {}

/// Why a frame could not be read or written under a level.
#[derive(Debug, Error)]
pub enum CodecError {
    /// This build's own reading or writing refused it, or the bytes broke a rule.
    #[error(transparent)]
    Cbor(#[from] kr_cbor::CborError),
    /// The level has no counterpart for what this build would write, so nothing is sent.
    #[error("level {level} cannot read this: {refusal}")]
    NotInLevel {
        /// The level.
        level: CompatibilityLevel,
        /// What it lacks.
        refusal: Refusal,
    },
    /// The peer sent what the surface it is at does not admit.
    #[error("level {level} sent what its own surface does not admit: {refusal}")]
    OutsideLevel {
        /// The level.
        level: CompatibilityLevel,
        /// What is outside.
        refusal: Refusal,
    },
    /// The type read or written is not a root of the surface.
    #[error("{0} is not part of the surface a retained level keeps")]
    NotInSurface(String),
}

impl Level {
    /// The level a worker is at, from what it stated in its answer to the hello.
    ///
    /// # Errors
    ///
    /// Returns [`UnretainedLevel`] for a worker that states a build at a level this release does
    /// not speak at, and for one that states none.
    pub fn of(stated: Option<&LocalBuild>) -> Result<Self, UnretainedLevel> {
        let Some(build) = stated else {
            return Err(UnretainedLevel { stated: None });
        };
        if THIS_LEVEL.admits(build.protocol_version) {
            return Ok(Self(Which::This));
        }
        RETAINED
            .iter()
            .find(|retained| retained.level.admits(build.protocol_version))
            .map(|retained| Self(Which::Retained(retained)))
            .ok_or_else(|| UnretainedLevel {
                stated: Some(build.clone()),
            })
    }

    /// This release's own level.
    #[must_use]
    pub const fn this() -> Self {
        Self(Which::This)
    }

    /// A retained level, for a test that keeps a level of its own.
    #[must_use]
    pub const fn retained(retained: &'static RetainedLevel) -> Self {
        Self(Which::Retained(retained))
    }

    /// The compatibility level.
    #[must_use]
    pub const fn level(self) -> CompatibilityLevel {
        match self.0 {
            Which::This => THIS_LEVEL,
            Which::Retained(retained) => retained.level,
        }
    }

    /// Whether this is the release's own level.
    #[must_use]
    pub const fn is_this(self) -> bool {
        matches!(self.0, Which::This)
    }

    /// Reads the payload of one frame under this level.
    ///
    /// # Errors
    ///
    /// Returns what the bytes or this build's decoder refuse, and
    /// [`CodecError::OutsideLevel`] for a frame the level's surface does not admit.
    pub fn decode(self, payload: &[u8], limits: &Limits) -> Result<ControlFrame, CodecError> {
        match self.0 {
            Which::This => Ok(wire::decode::<ControlFrame>(payload, limits)?),
            Which::Retained(retained) => {
                let mut value = kr_cbor::decode(payload, limits)?;
                let mut reading = Rewriting::new(retained.declared, Direction::Read);
                retained
                    .surface()
                    .walk("ControlFrame", &mut value, &mut reading)
                    .map_err(|refusal| CodecError::OutsideLevel {
                        level: retained.level,
                        refusal,
                    })?;
                Ok(wire::from_value::<ControlFrame>(&value)?)
            }
        }
    }

    /// Writes one frame as the payload this level reads.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::NotInLevel`] for a frame the level cannot read, which is then not
    /// sent, and what this build's encoder refuses.
    pub fn encode(self, frame: &ControlFrame, limits: &Limits) -> Result<Vec<u8>, CodecError> {
        match self.0 {
            Which::This => Ok(kr_cbor::to_canonical_vec_within(frame, limits)?),
            Which::Retained(retained) => {
                let mut value = kr_cbor::to_canonical_value(frame)?;
                self.write("ControlFrame", &mut value, retained)?;
                value.check_limits(limits)?;
                Ok(kr_cbor::encode_within(&value, limits.max_message_len)?)
            }
        }
    }

    /// Reads a worker's answer, or the parameters of a request, as the type `T` under this level.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::NotInSurface`] for a type that is no root of the surface, what this
    /// build's decoder refuses, and [`CodecError::OutsideLevel`] for a value the level's surface
    /// does not admit. A value that does not decode is an error and is never passed on.
    pub fn decode_value<T: WireMessage>(self, value: &ParamsValue) -> Result<T, CodecError> {
        match self.0 {
            Which::This => Ok(value.to_typed::<T>()?),
            Which::Retained(retained) => {
                let root = T::schema_name().into_owned();
                if retained.surface().definition(&root).is_none() {
                    return Err(CodecError::NotInSurface(root));
                }
                let mut canonical = value.as_value().clone();
                let mut reading = Rewriting::new(retained.declared, Direction::Read);
                retained
                    .surface()
                    .walk(&root, &mut canonical, &mut reading)
                    .map_err(|refusal| CodecError::OutsideLevel {
                        level: retained.level,
                        refusal,
                    })?;
                Ok(wire::from_value::<T>(&canonical)?)
            }
        }
    }

    /// Writes the parameters of a request the control daemon makes of a worker as this level reads
    /// them.
    ///
    /// The daemon's own reads of a worker have parameters on the surface ([`params_root`]); every
    /// other method is passed through for a caller, whose parameters are opaque to the daemon and
    /// are written as they were given.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::NotInLevel`] for parameters the level cannot read.
    pub fn encode_params<T: serde::Serialize + ?Sized>(
        self,
        method: Method,
        params: &T,
    ) -> Result<ParamsValue, CodecError> {
        let mut value = kr_cbor::to_canonical_value(params)?;
        if let (Which::Retained(retained), Some(root)) = (self.0, params_root(method)) {
            self.write(root, &mut value, retained)?;
        }
        Ok(ParamsValue::new(value))
    }

    /// Writes parameters, or an answer, of the type `T` as this level reads them.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::NotInSurface`] for a type that is no root of the surface, and
    /// [`CodecError::NotInLevel`] for a value the level cannot read.
    pub fn encode_value<T: WireMessage>(self, message: &T) -> Result<ParamsValue, CodecError> {
        let mut value = kr_cbor::to_canonical_value(message)?;
        if let Which::Retained(retained) = self.0 {
            let root = T::schema_name().into_owned();
            if retained.surface().definition(&root).is_none() {
                return Err(CodecError::NotInSurface(root));
            }
            self.write(&root, &mut value, retained)?;
        }
        Ok(ParamsValue::new(value))
    }

    /// Runs each golden pair of the level's entries through its rewrites, both ways, and returns
    /// what does not come out as the pair says.
    #[must_use]
    pub fn golden_problems(self, limits: &Limits) -> Vec<String> {
        let Which::Retained(retained) = self.0 else {
            return Vec::new();
        };
        let mut problems = Vec::new();
        for entry in retained.declared {
            for (position, pair) in entry.golden.iter().enumerate() {
                let name = format!("{} golden pair {position}", entry.at);
                match (
                    self.decode_current(pair.current, limits)
                        .and_then(|frame| self.encode(&frame, limits)),
                    self.decode(pair.retained, limits)
                        .and_then(|frame| Level::this().encode(&frame, limits)),
                ) {
                    (Ok(written), Ok(read)) => {
                        if written != pair.retained {
                            problems.push(format!(
                                "{name}: written for the level, the frame is not the retained one"
                            ));
                        }
                        if read != pair.current {
                            problems.push(format!(
                                "{name}: read from the level, the frame is not the current one"
                            ));
                        }
                    }
                    (Err(error), _) | (_, Err(error)) => problems.push(format!("{name}: {error}")),
                }
            }
        }
        problems
    }

    fn decode_current(self, payload: &[u8], limits: &Limits) -> Result<ControlFrame, CodecError> {
        Level::this().decode(payload, limits)
    }

    fn write(
        self,
        root: &str,
        value: &mut CanonicalValue,
        retained: &'static RetainedLevel,
    ) -> Result<(), CodecError> {
        let mut writing = Rewriting::new(retained.declared, Direction::Write);
        current()
            .walk(root, value, &mut writing)
            .map_err(|refusal| CodecError::NotInLevel {
                level: retained.level,
                refusal,
            })?;
        retained
            .surface()
            .walk(root, value, &mut Plain)
            .map_err(|refusal| CodecError::NotInLevel {
                level: retained.level,
                refusal,
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Read,
    Write,
}

/// Applies the rewrites of the entries that name a definition, to each of its values once the walk
/// has read it.
struct Rewriting<'a> {
    declared: &'a [Declared],
    direction: Direction,
}

impl<'a> Rewriting<'a> {
    const fn new(declared: &'a [Declared], direction: Direction) -> Self {
        Self {
            declared,
            direction,
        }
    }
}

impl Visit for Rewriting<'_> {
    fn leave(&mut self, definition: &str, value: &mut CanonicalValue) -> Result<(), Refusal> {
        for entry in self.declared {
            let place = entry
                .at
                .find(['.', '#', '['])
                .map_or(entry.at, |end| &entry.at[..end]);
            if place != definition {
                continue;
            }
            let rewrite = match self.direction {
                Direction::Read => entry.read,
                Direction::Write => entry.write,
            };
            rewrite(value).map_err(|why| Refusal::Rewrite {
                definition: definition.to_owned(),
                why,
            })?;
        }
        Ok(())
    }
}

/// Removes the member `name` of the map `value` is, when it has one. For a rewrite.
pub fn remove_member(value: &mut CanonicalValue, name: &str) -> bool {
    let CanonicalValue::Map(map) = value else {
        return false;
    };
    let before = map.len();
    let entries: Vec<_> = std::mem::take(map)
        .into_entries()
        .into_iter()
        .filter(|(key, _)| key != name)
        .collect();
    let removed = entries.len() != before;
    *map = kr_cbor::CanonicalMap::from_sorted_entries(entries).unwrap_or_default();
    removed
}
