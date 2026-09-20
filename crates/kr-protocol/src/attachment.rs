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
    pub line_token: Nullable<String>,
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
}
