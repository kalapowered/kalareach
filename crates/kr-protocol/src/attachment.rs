//! Attachments, geometry ownership and the attachment method group.
//!
//! Section 8 separates three things a client might think of as one: observing a session, owning
//! its size and holding its input. An attachment observes. A geometry claim, ranked by join order,
//! owns rows and columns. The input lease, in [`crate::input`], owns what the application reads.
//! Opening a view therefore resizes nothing and steals nothing.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{AttachmentId, AttachmentOrdinal, GeometryEpoch, SessionId};
use crate::scalars::{CanonicalSet, Nullable, TimestampMs, U64};
use crate::session::Dimensions;

/// What an attachment observes.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AttachMode {
    /// Structured application state rather than terminal cells. A semantic attachment never
    /// claims geometry.
    Semantic,
    /// Terminal output, either as raw bytes in direct mode or as a projection.
    Terminal,
}

impl AttachMode {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Semantic => "semantic",
            Self::Terminal => "terminal",
        }
    }

    /// Returns true when an attachment in this mode may claim geometry.
    #[must_use]
    pub const fn may_claim_geometry(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

/// How a terminal attachment displays the canonical grid.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TerminalPresentationMode {
    /// The attachment's own size matches the canonical grid and it receives the filtered live byte
    /// stream unchanged.
    Direct,
    /// The attachment displays a clipped viewport of the canonical grid. A smaller display pans;
    /// a larger one leaves the unused area blank. Nothing is reflowed.
    Viewport,
}

impl TerminalPresentationMode {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Viewport => "viewport",
        }
    }
}

/// Why a terminal attachment is shown a viewport of the canonical grid rather than the live byte
/// stream.
///
/// Direct presentation needs every one of these conditions to hold, and an attachment that is not
/// direct is given one reason: the first in this order that does not hold. The order runs from what
/// lasts as long as the attachment stays as it is, its terminal and then its size, through where
/// its window is, to the session's own state, which passes by itself: the output leaving what a
/// terminal can be handed, a restoration that could not carry the screen, and forwarding waiting
/// for a parser boundary.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PresentationReason {
    /// The client declared no terminal profile, so what the session's output would do on its
    /// terminal is not known.
    NoTerminalProfile,
    /// The client declared a terminal profile this build has not qualified to take the session's
    /// output unchanged.
    UnqualifiedTerminalProfile,
    /// The attachment's own size is not the session's canonical size.
    SizeMismatch,
    /// The attachment's window is above the live screen, on rows the session retained.
    HistoryWindow,
    /// The session's output is no longer something a physical terminal can be handed.
    StreamNotCarryable,
    /// The screen the attachment was last given could not carry the state the application
    /// addresses next.
    RestorationIncomplete,
    /// Forwarding waits for the session's output to reach a parser-ground boundary.
    AwaitingParserBoundary,
}

impl PresentationReason {
    /// Every reason, in the order the first that holds is reported.
    pub const ALL: [Self; 7] = [
        Self::NoTerminalProfile,
        Self::UnqualifiedTerminalProfile,
        Self::SizeMismatch,
        Self::HistoryWindow,
        Self::StreamNotCarryable,
        Self::RestorationIncomplete,
        Self::AwaitingParserBoundary,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoTerminalProfile => "no_terminal_profile",
            Self::UnqualifiedTerminalProfile => "unqualified_terminal_profile",
            Self::SizeMismatch => "size_mismatch",
            Self::HistoryWindow => "history_window",
            Self::StreamNotCarryable => "stream_not_carryable",
            Self::RestorationIncomplete => "restoration_incomplete",
            Self::AwaitingParserBoundary => "awaiting_parser_boundary",
        }
    }

    /// Returns what the reason means, for a person.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NoTerminalProfile => {
                "its client declared no terminal profile, so what the session's output would do on \
                 its terminal is not known"
            }
            Self::UnqualifiedTerminalProfile => {
                "the terminal profile its client declared is not one this build has qualified"
            }
            Self::SizeMismatch => "its size is not the session's",
            Self::HistoryWindow => "its window is above the live screen",
            Self::StreamNotCarryable => {
                "the session's output is no longer something a terminal can be handed as it is"
            }
            Self::RestorationIncomplete => {
                "the screen it was last given could not carry everything the application addresses"
            }
            Self::AwaitingParserBoundary => {
                "forwarding waits for the session's output to reach the end of a sequence"
            }
        }
    }
}

/// What an attachment asks to be able to do.
///
/// A request is not a grant. The host intersects these with the actor's rights, and an attachment
/// identifier is never permission on its own.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentCapability {
    /// Receive terminal output.
    ObserveTerminal,
    /// Receive structured application state.
    ObserveSemantic,
    /// Hold the input lease and write input.
    Input,
    /// Register a geometry claim and resize while owner.
    Geometry,
}

impl AttachmentCapability {
    /// Every capability, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::ObserveTerminal,
        Self::ObserveSemantic,
        Self::Input,
        Self::Geometry,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObserveTerminal => "observe_terminal",
            Self::ObserveSemantic => "observe_semantic",
            Self::Input => "input",
            Self::Geometry => "geometry",
        }
    }
}

/// Parameters of `session.attach`.
///
/// The request does not bypass grants and does not acquire a remote input lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionAttachParams {
    /// The session to attach to.
    pub session_id: SessionId,
    /// What this attachment observes.
    pub mode: AttachMode,
    /// Whether this attachment registers a geometry claim. Semantic mode requires false.
    pub claim_geometry: bool,
    /// The attachment's physical dimensions, required in terminal mode.
    pub dimensions: Nullable<Dimensions>,
    /// The terminal profile this attachment presents.
    pub terminal_profile_id: Nullable<String>,
    /// The observation and input capabilities the attachment asks for.
    pub requested: CanonicalSet<AttachmentCapability>,
}

/// Who owns the session's rows and columns.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeometryState {
    /// The current owner. Null when no eligible claim exists and the last geometry is retained.
    pub owner: Nullable<AttachmentId>,
    /// The epoch, advanced by every ownership change and explicit transfer.
    pub epoch: GeometryEpoch,
    /// The canonical geometry the pseudo-terminal is currently set to.
    pub dimensions: Dimensions,
}

/// One attachment of a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentSummary {
    /// The attachment identity, independent of the device behind it.
    pub attachment_id: AttachmentId,
    /// The monotonic join order that decides size-owner succession.
    pub ordinal: AttachmentOrdinal,
    /// What this attachment observes.
    pub mode: AttachMode,
    /// Whether this attachment holds an eligible geometry claim.
    pub claim_geometry: bool,
    /// The attachment's own physical dimensions, reported even when it is not the owner.
    pub dimensions: Nullable<Dimensions>,
    /// How the attachment displays the canonical grid.
    pub presentation: Nullable<TerminalPresentationMode>,
    /// Why a terminal attachment is shown a viewport, when it is.
    ///
    /// Section 8 asks every presentation to be reported with its reason. A direct attachment needs
    /// none and an attachment that is not a terminal has no presentation, so both leave this out,
    /// and a direct attachment's summary is byte for byte what a client built before reasons
    /// expects. A worker built before reasons leaves it out of every summary, and a reader takes
    /// that as no reason reported rather than as a direct presentation: `presentation` says which
    /// the attachment is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation_reason: Option<PresentationReason>,
    /// The terminal profile it presents.
    pub terminal_profile_id: Nullable<String>,
    /// The capabilities the host granted, which are the requested ones intersected with the
    /// actor's rights.
    pub granted: CanonicalSet<AttachmentCapability>,
    /// When it joined.
    pub attached_at_ms: TimestampMs,
}

/// The result of `session.attach`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionAttachResult {
    /// The new attachment.
    pub attachment: AttachmentSummary,
    /// Who owns the geometry after this attachment joined.
    pub geometry: GeometryState,
    /// The output cursor this attachment's stream starts from. A client subscribes from a cursor
    /// before it installs a snapshot.
    pub output_cursor: U64,
}

/// Parameters of `session.detach`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionDetachParams {
    /// The attachment to remove. Null asks the host for the originating attachment.
    ///
    /// Section 7's `kr detach` takes no identifier inside its own context, and the host is the
    /// only place that knows what that context is: the attachment whose input the root editor
    /// accepted the line under, recorded through the fence at acceptance. A caller that names
    /// nothing gets that attachment or `AMBIGUOUS_ATTACHMENT`, never a guess and never whichever
    /// client happens to hold the input lease when the command runs.
    pub attachment_id: Nullable<AttachmentId>,
    /// The capability the accepted line this caller runs from was given.
    ///
    /// Presented where no attachment is named: it says which line the caller belongs to, which no
    /// reading of the caller's own process can. Null from a caller that was given none, and a
    /// request that names neither is refused rather than attributed.
    ///
    /// It is absent from the wire when there is none, so a request that names its attachment, or
    /// one from a caller holding no capability, is byte for byte what a worker built before this
    /// field expects. That matters because a worker is not replaced with the daemon and the
    /// command-line tool beside it: an upgrade leaves every live session's worker running the
    /// build that started it, and that build refuses a field it does not know. Absent is read
    /// back as null, which is what a caller presenting nothing means, so a request from a build
    /// before this field is answered exactly as one from a caller that holds none.
    ///
    /// Remove the default and the omission once no worker from a build before this field can
    /// still be running, which is when every session that was live across the upgrade has closed.
    #[serde(default, skip_serializing_if = "no_capability")]
    pub line_token: Nullable<String>,
}

/// Returns whether a detach presents no line capability.
fn no_capability(line_token: &Nullable<String>) -> bool {
    !line_token.is_present()
}

/// The result of `session.detach`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionDetachResult {
    /// The attachment that was removed.
    pub attachment_id: AttachmentId,
    /// Who owns the geometry after succession.
    pub geometry: GeometryState,
    /// How many attachments remain. A live session may have none.
    pub remaining: U64,
}

/// Where an attachment's window sits in the session's rows.
///
/// A window is normally on the live screen, which is what no position at all means. A client
/// looking through its scrollback names where it is looking instead, and the host installs the
/// history pages that cover it. Scrolling is a presentation choice and never touches the input
/// lease: section 8 puts passive scrollback with focus events and terminal replies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ViewportPosition {
    /// The stable identifier of the first row shown, taken from the pages the client holds.
    Row(U64),
    /// How many rows above the live screen's first row the window starts.
    ///
    /// For a client that has not yet been given a row identifier to name. The host resolves it
    /// against the live screen at the moment of the report and answers with the row it landed on,
    /// so the window stays where the person put it while the session goes on writing.
    Above(U64),
}

/// Parameters of `attachment.viewport`.
///
/// Every terminal attachment reports its own physical dimensions, whether or not it owns the size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentViewportParams {
    /// The reporting attachment.
    pub attachment_id: AttachmentId,
    /// Its current physical dimensions.
    pub dimensions: Dimensions,
    /// Where its window sits. Null is the live screen.
    pub position: Nullable<ViewportPosition>,
}

/// The result of `attachment.viewport`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentViewportResult {
    /// The canonical geometry, which a viewport report never changes.
    pub geometry: GeometryState,
    /// How this attachment now displays the canonical grid.
    pub presentation: TerminalPresentationMode,
    /// Where the window ended up, as a row identifier, or null for the live screen.
    ///
    /// A request above the oldest row the session still holds is answered with the oldest one
    /// there is rather than refused, and a request at or below the live screen's first row is
    /// answered with the live screen. Either way this says where the window actually is.
    pub position: Nullable<ViewportPosition>,
}

/// Parameters of `attachment.configure`.
///
/// Withdrawing or adding an authorised claim does not change the session identity and cannot
/// displace an existing owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachmentConfigureParams {
    /// The attachment to reconfigure.
    pub attachment_id: AttachmentId,
    /// Whether it holds a geometry claim after this call.
    pub claim_geometry: bool,
}

/// Parameters of `terminal.resize`.
///
/// Only the current geometry owner changes the pseudo-terminal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TerminalResizeParams {
    /// The attachment asking for the resize.
    pub attachment_id: AttachmentId,
    /// The new canonical geometry.
    pub dimensions: Dimensions,
    /// The geometry epoch the caller believes is current.
    pub expected_geometry_epoch: GeometryEpoch,
}

/// Parameters of `terminal.geometry.transfer`.
///
/// This is the deliberate "use this terminal's size" action. Ordinary attach and input takeover
/// never move size ownership.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TerminalGeometryTransferParams {
    /// The eligible attachment that should own the size.
    pub attachment_id: AttachmentId,
    /// The geometry epoch the caller believes is current.
    pub expected_geometry_epoch: GeometryEpoch,
}

/// The result of any operation that can change geometry ownership.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeometryResult {
    /// The geometry after the operation.
    pub geometry: GeometryState,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A window is named either by a row it holds or by how far above the live page it starts.
    #[test]
    fn a_viewport_position_is_a_row_or_a_distance_above_the_live_page() {
        assert_eq!(
            serde_json::to_value(ViewportPosition::Row(U64::new(4_096))).expect("encodes"),
            serde_json::json!({ "row": "4096" })
        );
        assert_eq!(
            serde_json::to_value(ViewportPosition::Above(U64::new(23))).expect("encodes"),
            serde_json::json!({ "above": "23" })
        );
    }

    #[test]
    fn semantic_attachments_cannot_claim_geometry() {
        assert!(!AttachMode::Semantic.may_claim_geometry());
        assert!(AttachMode::Terminal.may_claim_geometry());
    }

    /// A detach that presents no capability is the request a worker built before it expects.
    ///
    /// Both directions of the upgrade window are here: what this build sends when there is no
    /// capability carries no such field, and what a build before it sends is read back as the
    /// caller presenting none.
    #[test]
    fn a_detach_with_no_capability_is_the_request_an_earlier_build_speaks() {
        let attachment_id = AttachmentId::new(crate::scalars::Uuid::from_bytes([0xA7; 16]));
        let named = SessionDetachParams {
            attachment_id: Nullable::some(attachment_id),
            line_token: Nullable::null(),
        };
        assert_eq!(
            serde_json::to_value(&named).expect("encodes"),
            serde_json::json!({ "attachment_id": attachment_id }),
            "a request that names its attachment carries no capability field at all"
        );

        let presented = SessionDetachParams {
            attachment_id: Nullable::null(),
            line_token: Nullable::some("a-line-capability".to_owned()),
        };
        assert_eq!(
            serde_json::to_value(&presented).expect("encodes"),
            serde_json::json!({
                "attachment_id": serde_json::Value::Null,
                "line_token": "a-line-capability",
            }),
            "and one that presents a capability carries it"
        );

        let earlier: SessionDetachParams =
            serde_json::from_value(serde_json::json!({ "attachment_id": attachment_id }))
                .expect("a request from a build before the capability still reads");
        assert_eq!(earlier.attachment_id, Nullable::some(attachment_id));
        assert!(
            !earlier.line_token.is_present(),
            "a caller whose build has no capability presents none"
        );

        let unqualified: SessionDetachParams =
            serde_json::from_value(serde_json::json!({ "attachment_id": serde_json::Value::Null }))
                .expect("and so does one that named nothing");
        assert!(!unqualified.attachment_id.is_present());
        assert!(!unqualified.line_token.is_present());
    }
    /// KR-REQ-08.02: a viewport carries its reason, a direct attachment carries none and is encoded
    /// as it was before reasons existed, and a summary from a worker built before reasons still
    /// reads, as one with no reason reported.
    #[test]
    fn a_viewport_says_why_and_a_direct_attachment_is_encoded_as_before() {
        let summary = |presentation, reason| AttachmentSummary {
            attachment_id: crate::ids::AttachmentId::new(crate::scalars::Uuid::from_bytes([7; 16])),
            ordinal: crate::ids::AttachmentOrdinal::new(1),
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            presentation: Nullable::some(presentation),
            presentation_reason: reason,
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            granted: CanonicalSet::new(),
            attached_at_ms: TimestampMs::new(1),
        };
        let direct =
            serde_json::to_value(summary(TerminalPresentationMode::Direct, None)).expect("encodes");
        assert_eq!(direct["presentation"], "direct");
        assert!(
            direct.get("presentation_reason").is_none(),
            "a direct attachment has no reason to carry: {direct}"
        );
        let projected = serde_json::to_value(summary(
            TerminalPresentationMode::Viewport,
            Some(PresentationReason::SizeMismatch),
        ))
        .expect("encodes");
        assert_eq!(projected["presentation"], "viewport");
        assert_eq!(projected["presentation_reason"], "size_mismatch");
        for reason in PresentationReason::ALL {
            assert_eq!(
                serde_json::to_value(reason).expect("encodes"),
                serde_json::json!(reason.as_str()),
                "the wire word is the one as_str names"
            );
            assert!(!reason.describe().is_empty());
        }

        let mut earlier = projected;
        earlier
            .as_object_mut()
            .expect("an object")
            .remove("presentation_reason");
        let read: AttachmentSummary =
            serde_json::from_value(earlier).expect("a summary from a build before reasons reads");
        assert_eq!(
            read.presentation.as_ref(),
            Some(&TerminalPresentationMode::Viewport)
        );
        assert_eq!(read.presentation_reason, None, "with no reason reported");
    }
}
