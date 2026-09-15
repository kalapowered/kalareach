//! Attachments and who owns the session's rows and columns.
//!
//! Three things people confuse for one are kept apart here and in [`crate::input`]: observing a
//! session, owning its size, and holding its input. Opening a view does none of the other two.
//!
//! Size ownership follows join order. The first eligible geometry claim owns rows and columns; if
//! that attachment leaves or withdraws its claim, the **oldest remaining** eligible claim succeeds
//! and supplies its own dimensions. With no eligible claim the last geometry is retained, so a
//! session with nobody watching keeps the size its shell is running at. A phone opening a passive
//! view therefore cannot resize a desktop TUI, and neither can an input takeover: moving the size
//! is a separate, deliberate action.

use std::collections::BTreeMap;

use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentSummary, GeometryState, SessionAttachParams,
    TerminalPresentationMode,
};
use kr_protocol::ids::{AttachmentId, AttachmentOrdinal, GeometryEpoch};
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_protocol::session::Dimensions;

use crate::error::{Result, WorkerError};

/// One attachment of a session.
#[derive(Clone, Debug)]
pub struct Attachment {
    /// The attachment identity.
    pub id: AttachmentId,
    /// Its join order.
    pub ordinal: u64,
    /// What it observes.
    pub mode: AttachMode,
    /// Whether it holds an eligible geometry claim.
    pub claim_geometry: bool,
    /// Its own physical dimensions.
    pub dimensions: Option<Dimensions>,
    /// The terminal profile it presents.
    pub terminal_profile_id: Option<String>,
    /// The capabilities the host granted it.
    pub granted: CanonicalSet<AttachmentCapability>,
    /// When it joined.
    pub attached_at_ms: TimestampMs,
}

impl Attachment {
    /// Returns true when this attachment may enter the size-ownership order.
    ///
    /// Eligibility needs three things at once: a terminal attachment, a registered claim, and the
    /// geometry right. Reporting a viewport is none of them.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        self.mode.may_claim_geometry()
            && self.claim_geometry
            && self.granted.contains(&AttachmentCapability::Geometry)
            && self.dimensions.is_some()
    }

    fn to_wire(&self, geometry: Dimensions) -> AttachmentSummary {
        AttachmentSummary {
            attachment_id: self.id,
            ordinal: AttachmentOrdinal::new(self.ordinal),
            mode: self.mode,
            claim_geometry: self.claim_geometry,
            dimensions: Nullable(self.dimensions),
            presentation: Nullable(self.presentation(geometry)),
            terminal_profile_id: Nullable(self.terminal_profile_id.clone()),
            granted: self.granted.clone(),
            attached_at_ms: self.attached_at_ms,
        }
    }

    fn presentation(&self, geometry: Dimensions) -> Option<TerminalPresentationMode> {
        if self.mode != AttachMode::Terminal {
            return None;
        }
        // Terminal wrapping and cursor coordinates depend on the number of columns, so only a
        // terminal of exactly the canonical size can take the live byte stream unchanged. Anything
        // else displays a clipped viewport of the canonical grid; nothing is reflowed.
        match self.dimensions {
            Some(own) if own == geometry => Some(TerminalPresentationMode::Direct),
            Some(_) => Some(TerminalPresentationMode::Viewport),
            None => None,
        }
    }
}

/// Every attachment of one session, and the geometry they compete for.
#[derive(Debug)]
pub struct AttachmentTable {
    attachments: BTreeMap<u64, Attachment>,
    by_id: BTreeMap<AttachmentId, u64>,
    next_ordinal: u64,
    owner: Option<AttachmentId>,
    epoch: u64,
    dimensions: Dimensions,
}

/// What changed when an attachment joined, left or was reconfigured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeometryChange {
    /// The geometry after the operation.
    pub state: GeometryState,
    /// True when the pseudo-terminal must be resized to match.
    pub resize_required: bool,
}

impl AttachmentTable {
    /// Builds an empty table at a starting geometry.
    #[must_use]
    pub fn new(dimensions: Dimensions) -> Self {
        Self {
            attachments: BTreeMap::new(),
            by_id: BTreeMap::new(),
            next_ordinal: 0,
            owner: None,
            epoch: 0,
            dimensions,
        }
    }

    /// Returns the current geometry and its owner.
    #[must_use]
    pub fn geometry(&self) -> GeometryState {
        GeometryState {
            owner: Nullable(self.owner),
            epoch: GeometryEpoch::new(self.epoch),
            dimensions: self.dimensions,
        }
    }

    /// Returns the canonical dimensions.
    #[must_use]
    pub const fn dimensions(&self) -> Dimensions {
        self.dimensions
    }

    /// Returns how many attachments the session has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.attachments.len()
    }

    /// Returns true when the session has no attachments. A live session may have none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attachments.is_empty()
    }

    /// Returns every attachment in join order.
    pub fn iter(&self) -> impl Iterator<Item = &Attachment> {
        self.attachments.values()
    }

    /// Returns one attachment.
    #[must_use]
    pub fn get(&self, id: AttachmentId) -> Option<&Attachment> {
        self.by_id
            .get(&id)
            .and_then(|ordinal| self.attachments.get(ordinal))
    }

    /// Renders every attachment for the wire.
    #[must_use]
    pub fn summaries(&self) -> Vec<AttachmentSummary> {
        self.attachments
            .values()
            .map(|attachment| attachment.to_wire(self.dimensions))
            .collect()
    }

    /// Adds an attachment.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] when a terminal attachment supplies no dimensions,
    /// when a semantic attachment claims geometry, or when the dimensions violate a constraint.
    pub fn attach(
        &mut self,
        params: &SessionAttachParams,
        granted: CanonicalSet<AttachmentCapability>,
        id: AttachmentId,
        now: TimestampMs,
    ) -> Result<(AttachmentSummary, GeometryChange)> {
        if params.claim_geometry && !params.mode.may_claim_geometry() {
            return Err(WorkerError::InvalidArgument(
                "a semantic attachment cannot claim geometry".to_owned(),
            ));
        }
        let dimensions = match (params.mode, params.dimensions.as_ref()) {
            (AttachMode::Terminal, None) => {
                return Err(WorkerError::InvalidArgument(
                    "a terminal attachment states its dimensions".to_owned(),
                ));
            }
            (_, Some(dimensions)) => {
                dimensions.validate()?;
                Some(*dimensions)
            }
            (_, None) => None,
        };
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        let attachment = Attachment {
            id,
            ordinal,
            mode: params.mode,
            claim_geometry: params.claim_geometry,
            dimensions,
            terminal_profile_id: params.terminal_profile_id.as_ref().cloned(),
            granted,
            attached_at_ms: now,
        };
        let eligible = attachment.is_eligible();
        self.attachments.insert(ordinal, attachment);
        self.by_id.insert(id, ordinal);
        // Only an unowned session hands the size to a new claim. An existing owner keeps it: a
        // second terminal opening is not a reason to resize the one already running.
        let change = if eligible && self.owner.is_none() {
            self.install_owner(Some(id))
        } else {
            GeometryChange {
                state: self.geometry(),
                resize_required: false,
            }
        };
        let summary = self
            .get(id)
            .expect("the attachment was just inserted")
            .to_wire(self.dimensions);
        Ok((summary, change))
    }

    /// Removes an attachment and runs succession.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownAttachment`] when the identifier is not present.
    pub fn detach(&mut self, id: AttachmentId) -> Result<GeometryChange> {
        let ordinal = self.by_id.remove(&id).ok_or_else(|| unknown(id))?;
        self.attachments.remove(&ordinal);
        if self.owner == Some(id) {
            return Ok(self.succeed());
        }
        Ok(GeometryChange {
            state: self.geometry(),
            resize_required: false,
        })
    }

    /// Adds or withdraws a geometry claim.
    ///
    /// Withdrawal runs succession. Adding a claim never displaces an existing owner.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownAttachment`] when the identifier is not present, and
    /// [`WorkerError::InvalidArgument`] when the attachment may not claim geometry.
    pub fn configure(&mut self, id: AttachmentId, claim_geometry: bool) -> Result<GeometryChange> {
        let ordinal = *self.by_id.get(&id).ok_or_else(|| unknown(id))?;
        {
            let attachment = self
                .attachments
                .get_mut(&ordinal)
                .ok_or_else(|| unknown(id))?;
            if claim_geometry && !attachment.mode.may_claim_geometry() {
                return Err(WorkerError::InvalidArgument(
                    "a semantic attachment cannot claim geometry".to_owned(),
                ));
            }
            if claim_geometry && !attachment.granted.contains(&AttachmentCapability::Geometry) {
                return Err(WorkerError::InvalidArgument(
                    "this attachment does not hold the geometry right".to_owned(),
                ));
            }
            attachment.claim_geometry = claim_geometry;
        }
        if !claim_geometry && self.owner == Some(id) {
            return Ok(self.succeed());
        }
        if claim_geometry && self.owner.is_none() {
            return Ok(self.install_owner(Some(id)));
        }
        Ok(GeometryChange {
            state: self.geometry(),
            resize_required: false,
        })
    }

    /// Records an attachment's own physical dimensions.
    ///
    /// Every terminal attachment reports these, owner or not. A report never changes the canonical
    /// geometry; it only decides whether that attachment can take the live byte stream directly.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownAttachment`] when the identifier is not present, and a
    /// dimension failure when the report violates a constraint.
    pub fn viewport(
        &mut self,
        id: AttachmentId,
        dimensions: Dimensions,
    ) -> Result<TerminalPresentationMode> {
        dimensions.validate()?;
        let ordinal = *self.by_id.get(&id).ok_or_else(|| unknown(id))?;
        let canonical = self.dimensions;
        let attachment = self
            .attachments
            .get_mut(&ordinal)
            .ok_or_else(|| unknown(id))?;
        attachment.dimensions = Some(dimensions);
        attachment.presentation(canonical).ok_or_else(|| {
            WorkerError::InvalidArgument(
                "a semantic attachment has no terminal presentation".to_owned(),
            )
        })
    }

    /// Changes the canonical geometry at the owner's request.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::NotGeometryOwner`] when the caller does not own the size or names a
    /// stale epoch, and a dimension failure when the request violates a constraint.
    pub fn resize(
        &mut self,
        id: AttachmentId,
        dimensions: Dimensions,
        expected_epoch: u64,
    ) -> Result<GeometryChange> {
        dimensions.validate()?;
        if self.owner != Some(id) || self.epoch != expected_epoch {
            return Err(WorkerError::NotGeometryOwner);
        }
        let ordinal = *self.by_id.get(&id).ok_or_else(|| unknown(id))?;
        if let Some(attachment) = self.attachments.get_mut(&ordinal) {
            attachment.dimensions = Some(dimensions);
        }
        self.dimensions = dimensions;
        self.epoch += 1;
        Ok(GeometryChange {
            state: self.geometry(),
            resize_required: true,
        })
    }

    /// Hands size ownership to an eligible attachment.
    ///
    /// This is the deliberate "use this terminal's size" action. It applies the new owner's own
    /// dimensions and advances the epoch, so every attachment learns about it at once.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownAttachment`] for an unknown target,
    /// [`WorkerError::NotGeometryOwner`] for a stale epoch, and
    /// [`WorkerError::InvalidArgument`] when the target is not eligible.
    pub fn transfer(&mut self, id: AttachmentId, expected_epoch: u64) -> Result<GeometryChange> {
        if self.epoch != expected_epoch {
            return Err(WorkerError::NotGeometryOwner);
        }
        let attachment = self.get(id).ok_or_else(|| unknown(id))?;
        if !attachment.is_eligible() {
            return Err(WorkerError::InvalidArgument(
                "the selected attachment holds no eligible geometry claim".to_owned(),
            ));
        }
        Ok(self.install_owner(Some(id)))
    }

    fn succeed(&mut self) -> GeometryChange {
        // The oldest remaining eligible claim succeeds. With none, the last geometry is retained
        // and the next eligible claimant takes it.
        let next = self
            .attachments
            .values()
            .find(|attachment| attachment.is_eligible())
            .map(|attachment| attachment.id);
        self.install_owner(next)
    }

    fn install_owner(&mut self, owner: Option<AttachmentId>) -> GeometryChange {
        let previous = self.dimensions;
        self.owner = owner;
        if let Some(id) = owner
            && let Some(dimensions) = self.get(id).and_then(|attachment| attachment.dimensions)
        {
            self.dimensions = dimensions;
        }
        self.epoch += 1;
        GeometryChange {
            state: self.geometry(),
            resize_required: self.dimensions != previous,
        }
    }
}

fn unknown(id: AttachmentId) -> WorkerError {
    WorkerError::UnknownAttachment {
        attachment: id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    fn identifier(byte: u8) -> AttachmentId {
        AttachmentId::new(Uuid::from_bytes([byte; 16]))
    }

    fn capabilities(items: &[AttachmentCapability]) -> CanonicalSet<AttachmentCapability> {
        let mut set = CanonicalSet::new();
        for item in items {
            set.insert(*item);
        }
        set
    }

    fn terminal(columns: u64, rows: u64, claim: bool) -> SessionAttachParams {
        SessionAttachParams {
            session_id: kr_protocol::ids::SessionId::new(Uuid::NIL),
            mode: AttachMode::Terminal,
            claim_geometry: claim,
            dimensions: Nullable::some(Dimensions::new(columns, rows)),
            terminal_profile_id: Nullable::null(),
            requested: capabilities(&[
                AttachmentCapability::ObserveTerminal,
                AttachmentCapability::Geometry,
            ]),
        }
    }

    fn attach(table: &mut AttachmentTable, id: u8, params: &SessionAttachParams) -> GeometryChange {
        table
            .attach(
                params,
                capabilities(&[
                    AttachmentCapability::ObserveTerminal,
                    AttachmentCapability::Geometry,
                ]),
                identifier(id),
                TimestampMs::new(u64::from(id)),
            )
            .expect("attaches")
            .1
    }

    #[test]
    fn the_first_eligible_claim_owns_the_size() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        let change = attach(&mut table, 1, &terminal(100, 30, true));
        assert_eq!(change.state.owner.as_ref(), Some(&identifier(1)));
        assert_eq!(change.state.dimensions, Dimensions::new(100, 30));
        assert!(change.resize_required);
    }

    #[test]
    fn a_second_terminal_does_not_take_the_size() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(100, 30, true));
        let change = attach(&mut table, 2, &terminal(200, 50, true));
        assert_eq!(change.state.owner.as_ref(), Some(&identifier(1)));
        assert_eq!(change.state.dimensions, Dimensions::new(100, 30));
        assert!(!change.resize_required);
    }

    #[test]
    fn a_passive_view_never_resizes_the_session() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(100, 30, true));
        let change = attach(&mut table, 2, &terminal(40, 20, false));
        assert_eq!(change.state.dimensions, Dimensions::new(100, 30));
        assert_eq!(
            table
                .viewport(identifier(2), Dimensions::new(40, 20))
                .expect("reports"),
            TerminalPresentationMode::Viewport
        );
        assert_eq!(table.geometry().dimensions, Dimensions::new(100, 30));
    }

    #[test]
    fn the_oldest_remaining_claim_succeeds_the_owner() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(100, 30, true));
        attach(&mut table, 2, &terminal(90, 25, true));
        attach(&mut table, 3, &terminal(80, 20, true));
        let change = table.detach(identifier(1)).expect("detaches");
        assert_eq!(change.state.owner.as_ref(), Some(&identifier(2)));
        assert_eq!(change.state.dimensions, Dimensions::new(90, 25));
    }

    #[test]
    fn with_no_eligible_claim_the_last_geometry_is_retained() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(100, 30, true));
        let change = table.detach(identifier(1)).expect("detaches");
        assert!(!change.state.owner.is_present());
        assert_eq!(change.state.dimensions, Dimensions::new(100, 30));
        // The next eligible claimant then takes it.
        let change = attach(&mut table, 2, &terminal(64, 16, true));
        assert_eq!(change.state.owner.as_ref(), Some(&identifier(2)));
        assert_eq!(change.state.dimensions, Dimensions::new(64, 16));
    }

    #[test]
    fn withdrawing_a_claim_runs_succession_and_adding_one_does_not_displace() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(100, 30, true));
        attach(&mut table, 2, &terminal(90, 25, false));
        // Adding a claim while someone owns the size changes nothing.
        let change = table.configure(identifier(2), true).expect("configures");
        assert_eq!(change.state.owner.as_ref(), Some(&identifier(1)));
        // Withdrawing the owner's claim hands it to the oldest remaining one.
        let change = table.configure(identifier(1), false).expect("configures");
        assert_eq!(change.state.owner.as_ref(), Some(&identifier(2)));
        assert_eq!(change.state.dimensions, Dimensions::new(90, 25));
    }

    #[test]
    fn only_the_owner_resizes_and_only_at_the_current_epoch() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(100, 30, true));
        attach(&mut table, 2, &terminal(90, 25, true));
        let epoch = table.geometry().epoch.get();
        assert!(matches!(
            table.resize(identifier(2), Dimensions::new(10, 10), epoch),
            Err(WorkerError::NotGeometryOwner)
        ));
        assert!(matches!(
            table.resize(identifier(1), Dimensions::new(10, 10), epoch + 5),
            Err(WorkerError::NotGeometryOwner)
        ));
        let change = table
            .resize(identifier(1), Dimensions::new(110, 35), epoch)
            .expect("resizes");
        assert_eq!(change.state.dimensions, Dimensions::new(110, 35));
        assert!(change.resize_required);
        assert_eq!(change.state.epoch.get(), epoch + 1);
    }

    #[test]
    fn a_transfer_moves_the_size_and_an_input_takeover_does_not() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(100, 30, true));
        attach(&mut table, 2, &terminal(60, 20, true));
        let epoch = table.geometry().epoch.get();
        assert!(matches!(
            table.transfer(identifier(2), epoch + 3),
            Err(WorkerError::NotGeometryOwner)
        ));
        let change = table.transfer(identifier(2), epoch).expect("transfers");
        assert_eq!(change.state.owner.as_ref(), Some(&identifier(2)));
        assert_eq!(change.state.dimensions, Dimensions::new(60, 20));
    }

    #[test]
    fn an_attachment_without_the_geometry_right_is_not_eligible() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        let params = terminal(100, 30, true);
        let change = table
            .attach(
                &params,
                capabilities(&[AttachmentCapability::ObserveTerminal]),
                identifier(9),
                TimestampMs::new(1),
            )
            .expect("attaches")
            .1;
        assert!(!change.state.owner.is_present());
        assert_eq!(change.state.dimensions, Dimensions::new(120, 40));
    }

    #[test]
    fn a_semantic_attachment_cannot_claim_geometry() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        let params = SessionAttachParams {
            mode: AttachMode::Semantic,
            claim_geometry: true,
            dimensions: Nullable::null(),
            ..terminal(1, 1, true)
        };
        assert!(matches!(
            table.attach(
                &params,
                capabilities(&[AttachmentCapability::Geometry]),
                identifier(4),
                TimestampMs::new(1)
            ),
            Err(WorkerError::InvalidArgument(_))
        ));
    }

    #[test]
    fn an_equal_sized_terminal_takes_the_live_stream_directly() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(120, 40, true));
        assert_eq!(
            table
                .viewport(identifier(1), Dimensions::new(120, 40))
                .expect("reports"),
            TerminalPresentationMode::Direct
        );
    }

    #[test]
    fn invalid_dimensions_are_refused_before_anything_changes() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(120, 40, true));
        let epoch = table.geometry().epoch.get();
        assert!(matches!(
            table.resize(identifier(1), Dimensions::new(2_048, 1_024), epoch),
            Err(WorkerError::Dimensions(_))
        ));
        assert_eq!(table.geometry().dimensions, Dimensions::new(120, 40));
    }
}
