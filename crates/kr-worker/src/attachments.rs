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
    /// Whether the screen this attachment was last given carried everything a terminal continuing
    /// the raw stream needs.
    ///
    /// It starts true, because an attachment that has been given nothing has lost nothing. Every
    /// restoration rendered for it sets it again, and one that could not carry the state the
    /// application will address keeps the attachment on a projection instead, where the host paints
    /// the canonical screen rather than trusting the terminal to already match it.
    pub restoration_continues: bool,
    /// Whether this attachment is waiting for a parser-ground boundary before it may forward.
    ///
    /// It starts false: an attachment that has been given nothing is not waiting for anything, and
    /// the host settles the answer before it serves the attachment anything at all. Forwarding may
    /// only *begin* at a boundary, so this is about the moment the transition would happen rather
    /// than about the attachment, and it is cleared the moment a boundary arrives.
    pub forwarding_held: bool,
    /// The stable row this attachment's window starts at, when it is looking above the live page.
    ///
    /// `None` is the live screen, which is where every attachment starts. It is a row identifier
    /// rather than a distance, because the live screen moves whenever the application writes and a
    /// window measured from it would slide away from what the person is reading.
    pub history_top_row: Option<i64>,
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

    fn to_wire(&self, geometry: Dimensions, carryable: bool) -> AttachmentSummary {
        AttachmentSummary {
            attachment_id: self.id,
            ordinal: AttachmentOrdinal::new(self.ordinal),
            mode: self.mode,
            claim_geometry: self.claim_geometry,
            dimensions: Nullable(self.dimensions),
            presentation: Nullable(self.presentation(geometry, carryable)),
            terminal_profile_id: Nullable(self.terminal_profile_id.clone()),
            granted: self.granted.clone(),
            attached_at_ms: self.attached_at_ms,
        }
    }

    /// Returns how this attachment is shown the session.
    ///
    /// Direct mode is qualified on three things together, and each one alone is not enough:
    ///
    /// * **The size.** Wrapping and cursor coordinates depend on the column count, so only a
    ///   terminal of exactly the canonical size can take the byte stream unchanged.
    /// * **The profile.** A client declares which terminal it is after probing it, and the name it
    ///   declares has to be one this build has qualified against the kr-vt/1 output the session
    ///   produces. Without a declaration the host does not know what those bytes would do there,
    ///   and `--no-probe` is exactly the case where the client chose not to find out; with an
    ///   unqualified one the host knows, and the answer is that they would not do the right thing.
    /// * **The stream.** The engine reports when the output stops being something a physical
    ///   terminal can be handed at all, and `carryable` is that answer.
    /// * **The screen it was given.** A terminal continues the stream from the screen the host drew
    ///   it. A restoration that could not carry the state the application is about to address (a
    ///   pending wrap, a saved cursor of the other buffer, the virtual title stack) leaves that
    ///   terminal disagreeing with the canonical grid, and the next byte lands in the wrong place.
    ///   Such an attachment keeps a projection, where the host paints the screen.
    /// * **Where the parser stands.** Forwarding may only *begin* at a parser-ground boundary, so
    ///   an attachment waiting for one is held in a projection until it arrives. This is the one
    ///   condition that is about a moment rather than about the attachment.
    ///
    /// Everything else displays a clipped viewport of the canonical grid; nothing is reflowed.
    fn presentation(
        &self,
        geometry: Dimensions,
        carryable: bool,
    ) -> Option<TerminalPresentationMode> {
        if self.mode != AttachMode::Terminal {
            return None;
        }
        match self.dimensions {
            Some(own)
                if carryable
                    && self.restoration_continues
                    && !self.forwarding_held
                    // A window above the live page is not the live byte stream, whatever this
                    // terminal's size is: what it shows is rows the session retained, which no
                    // stream of what the application is writing now can produce.
                    && self.history_top_row.is_none()
                    && own == geometry
                    && self
                        .terminal_profile_id
                        .as_deref()
                        .is_some_and(is_qualified_terminal) =>
            {
                Some(TerminalPresentationMode::Direct)
            }
            Some(_) => Some(TerminalPresentationMode::Viewport),
            None => None,
        }
    }
}

/// The terminal names this build will hand its own output stream to unchanged.
///
/// The session writes the kr-vt/1 profile, and `kr_term::terminfo` describes that profile as the
/// `xterm-256color` entry with the kr-vt/1 deltas. A terminal that implements that entry can take
/// the stream; one that does not is shown a rendering of the canonical grid instead, which needs
/// nothing of it beyond cursor addressing and colour.
///
/// What the list rests on is stated rather than implied: each of these terminals implements the
/// `xterm-256color` entry the kr-vt/1 profile is written against, and the profile's own conformance
/// corpus has been run against the engine's output rather than against each of these terminals.
/// That is weaker than a per-terminal measurement, and it is why the list is short and why anything
/// outside it is projected. `TERM=dumb` and `TERM=vt100` are outside it because they do not
/// implement that entry at all.
///
/// A name reaching here is the client's own report of what it probed, which is a claim rather than
/// a measurement: `TERM` names a terminfo entry, not a build or a configuration of it.
pub const QUALIFIED_TERMINALS: &[&str] = &[
    "xterm-256color",
    "xterm-kitty",
    "wezterm",
    "alacritty",
    "foot",
    "ghostty",
    "tmux-256color",
    "screen-256color",
];

/// Returns whether this build has qualified a terminal to take the session's stream unchanged.
#[must_use]
pub fn is_qualified_terminal(name: &str) -> bool {
    QUALIFIED_TERMINALS.contains(&name)
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
    /// Whether the output stream is still something a physical terminal can be handed.
    ///
    /// The terminal engine decides it; the table holds the answer because every presentation
    /// depends on it and a summary has to report the same thing the delivery path does.
    carryable: bool,
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
            carryable: true,
        }
    }

    /// Records whether the output stream is still one a physical terminal can be handed.
    ///
    /// Returns whether the answer changed, which is what tells the caller that every attachment's
    /// presentation has to be looked at again.
    pub fn set_carryable(&mut self, carryable: bool) -> bool {
        let changed = self.carryable != carryable;
        self.carryable = carryable;
        changed
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

    /// Restores the geometry a change was refused from, with an epoch that tells the truth.
    ///
    /// A change the kernel refused never happened, and a change that never happened did not
    /// advance an epoch. Putting the epoch back is what stops a refused resize from invalidating
    /// every client's next request.
    ///
    /// An ownership change that *did* happen is the exception. A succession runs because the owner
    /// gave up the claim it owned by - it detached, or it withdrew that claim - and that part
    /// happened whatever the kernel then said about the successor's size. An attachment holding no
    /// eligible claim is not an owner, so the size goes back unowned, which is a state the next
    /// eligible claim can act on, rather than to one that has left and cannot be reached or to one
    /// that would then still be resizing a session it gave up. That is an ownership change, and the
    /// wire contract says every ownership change advances the epoch - otherwise a client holding
    /// the state from before the claim went could still transfer the size against it.
    pub fn restore_geometry(&mut self, previous: &GeometryState) {
        let owner = previous.owner.0.filter(|owner| {
            self.get(*owner)
                .is_some_and(|attachment| attachment.is_eligible())
        });
        self.epoch = if owner == previous.owner.0 {
            previous.epoch.get()
        } else {
            self.epoch.saturating_add(1)
        };
        self.owner = owner;
        self.dimensions = previous.dimensions;
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
            .map(|attachment| attachment.to_wire(self.dimensions, self.carryable))
            .collect()
    }

    /// Decides whether this table can admit the attachment these parameters ask for.
    ///
    /// Nothing changes here, and that is what it is for. Section 9 requires every refusal the host
    /// can decide to be a rejection decided *before* the dispatch marker, so this is called twice:
    /// once by the admission path with nothing written yet, and once by [`Self::attach`] itself,
    /// where it also produces the dimensions the attachment is recorded with. Two copies of these
    /// rules would be two rules.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] when the session is full, when a semantic
    /// attachment claims geometry, when a terminal attachment states no dimensions, or when the
    /// dimensions themselves are not ones this host serves.
    pub fn admissible(&self, params: &SessionAttachParams) -> Result<Option<Dimensions>> {
        // A session serves a bounded number of attachments. The bound is the protocol's, and it
        // is checked before an identifier is allocated so a refused attach leaves nothing behind.
        if self.attachments.len() >= kr_protocol::limits::MAX_CONCURRENT_ATTACHMENTS {
            return Err(WorkerError::InvalidArgument(format!(
                "this session already has its maximum of {} attachments",
                kr_protocol::limits::MAX_CONCURRENT_ATTACHMENTS
            )));
        }
        if params.claim_geometry && !params.mode.may_claim_geometry() {
            return Err(WorkerError::InvalidArgument(
                "a semantic attachment cannot claim geometry".to_owned(),
            ));
        }
        match (params.mode, params.dimensions.as_ref()) {
            (AttachMode::Terminal, None) => Err(WorkerError::InvalidArgument(
                "a terminal attachment states its dimensions".to_owned(),
            )),
            (_, Some(dimensions)) => {
                admit(*dimensions)?;
                Ok(Some(*dimensions))
            }
            (_, None) => Ok(None),
        }
    }

    /// Decides whether one attachment may be given the geometry.
    ///
    /// The eligibility half of [`Self::transfer`], for the same reason [`Self::admissible`] exists:
    /// a transfer to an attachment that holds no eligible claim is a refusal this host can decide,
    /// and deciding it inside the effect would make it an uncertain outcome instead of a rejection.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownAttachment`] when the identifier names no attachment of this
    /// session, and [`WorkerError::InvalidArgument`] when it holds no eligible geometry claim.
    pub fn transferable(&self, id: AttachmentId) -> Result<()> {
        let attachment = self.get(id).ok_or_else(|| unknown(id))?;
        if attachment.is_eligible() {
            Ok(())
        } else {
            Err(WorkerError::InvalidArgument(
                "the selected attachment holds no eligible geometry claim".to_owned(),
            ))
        }
    }

    /// Adds an attachment.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::admissible`] refuses, and [`WorkerError::ResourceUnavailable`]
    /// when the session has exhausted its join order.
    pub fn attach(
        &mut self,
        params: &SessionAttachParams,
        granted: CanonicalSet<AttachmentCapability>,
        id: AttachmentId,
        now: TimestampMs,
    ) -> Result<(AttachmentSummary, GeometryChange)> {
        let dimensions = self.admissible(params)?;
        // Join order is what decides succession, so an ordinal that wrapped would put a new
        // attachment in front of older claims - or land on an occupied entry. The counter is
        // refused before it is spent rather than allowed to come round.
        let ordinal = self.next_ordinal;
        self.next_ordinal =
            self.next_ordinal
                .checked_add(1)
                .ok_or_else(|| WorkerError::ResourceUnavailable {
                    detail: "this session has exhausted its join order and can admit no more \
                         attachments"
                        .to_owned(),
                })?;
        let attachment = Attachment {
            id,
            ordinal,
            mode: params.mode,
            claim_geometry: params.claim_geometry,
            dimensions,
            terminal_profile_id: params.terminal_profile_id.as_ref().cloned(),
            granted,
            attached_at_ms: now,
            restoration_continues: true,
            forwarding_held: false,
            history_top_row: None,
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
            .to_wire(self.dimensions, self.carryable);
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
        self.check_configure(id, claim_geometry)?;
        let ordinal = *self.by_id.get(&id).ok_or_else(|| unknown(id))?;
        {
            let attachment = self
                .attachments
                .get_mut(&ordinal)
                .ok_or_else(|| unknown(id))?;
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
        history_top_row: Option<i64>,
    ) -> Result<TerminalPresentationMode> {
        self.check_viewport(id, dimensions)?;
        let ordinal = *self.by_id.get(&id).ok_or_else(|| unknown(id))?;
        let canonical = self.dimensions;
        {
            let attachment = self
                .attachments
                .get_mut(&ordinal)
                .ok_or_else(|| unknown(id))?;
            attachment.dimensions = Some(dimensions);
            attachment.history_top_row = history_top_row;
        }
        let carryable = self.carryable;
        let attachment = self
            .attachments
            .get_mut(&ordinal)
            .ok_or_else(|| unknown(id))?;
        attachment
            .presentation(canonical, carryable)
            .ok_or_else(|| {
                WorkerError::InvalidArgument(
                    "a semantic attachment has no terminal presentation".to_owned(),
                )
            })
    }

    /// Brings every window back to the live screen.
    ///
    /// A buffer switch is what this is for. The buffer a full-screen application takes keeps no
    /// history and numbers its rows from its own beginning, so a window above the shell's live
    /// page has nothing to be above any more; it comes back to the live screen with the screen
    /// that program took, rather than waiting to be restored to rows the person has left.
    pub fn clear_history_windows(&mut self) {
        for attachment in self.attachments.values_mut() {
            attachment.history_top_row = None;
        }
    }

    /// The stable row one attachment's window starts at, or `None` for the live screen.
    #[must_use]
    pub fn history_top_row(&self, id: AttachmentId) -> Option<i64> {
        let ordinal = self.by_id.get(&id)?;
        self.attachments.get(ordinal)?.history_top_row
    }

    /// Returns every terminal attachment being shown a rendering rather than the raw stream.
    #[must_use]
    pub fn projected(&self) -> Vec<(AttachmentId, Dimensions)> {
        let canonical = self.dimensions;
        self.attachments
            .values()
            .filter_map(|attachment| {
                let own = attachment.dimensions?;
                match attachment.presentation(canonical, self.carryable) {
                    Some(TerminalPresentationMode::Viewport) => Some((attachment.id, own)),
                    _ => None,
                }
            })
            .collect()
    }

    /// Records whether the screen an attachment was just given continues the raw stream.
    ///
    /// Every restoration rendered for an attachment passes through here, because the answer is a
    /// property of that screen rather than of the session: the same grid restores completely for
    /// one terminal and not for another the moment a pending wrap or a saved cursor appears.
    pub fn note_restoration(&mut self, id: AttachmentId, continues: bool) {
        let Some(ordinal) = self.by_id.get(&id) else {
            return;
        };
        if let Some(attachment) = self.attachments.get_mut(ordinal) {
            attachment.restoration_continues = continues;
        }
    }

    /// Records whether one attachment is being held out of live byte forwarding.
    ///
    /// Returns whether this changed the answer, so a caller can resynchronise the attachments whose
    /// presentation moved and leave the others alone.
    pub fn hold_forwarding(&mut self, id: AttachmentId, held: bool) -> bool {
        let Some(ordinal) = self.by_id.get(&id) else {
            return false;
        };
        let Some(attachment) = self.attachments.get_mut(ordinal) else {
            return false;
        };
        let changed = attachment.forwarding_held != held;
        attachment.forwarding_held = held;
        changed
    }

    /// Returns whether a restoration for this attachment may change its keyboard protocols.
    ///
    /// Only an attachment that declared what terminal it is may have them changed. That
    /// declaration is what says the client asked the terminal about itself before anything
    /// happened to it, and therefore that it can put back exactly what it found; an attachment
    /// that asked nothing, which is what `--no-probe` chooses, is served a screen that leaves its
    /// keyboard alone, because nothing could restore what installing one would take away.
    #[must_use]
    pub fn keyboard_control(&self, id: AttachmentId) -> crate::render::Keyboard {
        if self
            .by_id
            .get(&id)
            .and_then(|ordinal| self.attachments.get(ordinal))
            .is_some_and(|attachment| attachment.terminal_profile_id.is_some())
        {
            crate::render::Keyboard::Install
        } else {
            crate::render::Keyboard::Withhold
        }
    }

    /// Returns what this attachment's input path can put on the wire.
    ///
    /// A semantic attachment builds its keys from the logical key and its modifiers through the
    /// shared encoder, so it produces whichever protocol is in force. A terminal attachment sends
    /// what its terminal sends, so what it offers is what that terminal implements, which is why
    /// the declaration matters: `crate::input::KEYBOARD_PROTOCOLS` says what a named terminal is
    /// known to implement, and a name outside it still sends the ordinary encoding.
    ///
    /// `None` is an attachment that declared nothing, which is what `--no-probe` chooses. Nothing
    /// was established about it in either direction, so section 8 does not let it hold the lease
    /// over an application expecting any particular encoding - the ordinary one included, because a
    /// terminal nobody was allowed to ask about is as likely to have been left in an enhanced
    /// protocol by whatever ran before it.
    ///
    /// The outer `Option` answers whether the attachment exists; the inner one answers whether
    /// anything is established about its keys.
    #[must_use]
    pub fn encoders(&self, id: AttachmentId) -> Option<Option<crate::input::Encoders>> {
        let attachment = self
            .by_id
            .get(&id)
            .and_then(|ordinal| self.attachments.get(ordinal))?;
        if attachment.mode != AttachMode::Terminal {
            return Some(Some(crate::input::Encoders::TYPED));
        }
        Some(
            attachment
                .terminal_profile_id
                .as_deref()
                .map(crate::input::terminal_encoders),
        )
    }

    /// Returns whether this attachment can deliver the encoding the application has negotiated.
    ///
    /// This is the question `input.acquire` asks before it hands over the keys, and the same
    /// question every mid-session mode change asks again of whoever holds them.
    #[must_use]
    pub fn supplies_encoding(
        &self,
        id: AttachmentId,
        required: kr_term::modes::KeyboardEncoding,
    ) -> bool {
        self.encoders(id)
            .flatten()
            .is_some_and(|encoders| encoders.supplies(required))
    }

    /// Returns an attachment's own physical dimensions, when it has reported them.
    ///
    /// The outer `Option` says whether the attachment exists; the inner one says whether it has
    /// reported a size. A semantic attachment never does, and a terminal attachment reports one
    /// when it joins.
    #[must_use]
    pub fn own_dimensions(&self, id: AttachmentId) -> Option<Option<Dimensions>> {
        let ordinal = self.by_id.get(&id)?;
        self.attachments
            .get(ordinal)
            .map(|attachment| attachment.dimensions)
    }

    /// Decides whether one attachment may take or drop a geometry claim.
    ///
    /// Nothing changes here. Section 9 requires a refusal the host can decide to be a rejection
    /// decided before the dispatch marker, so this is called by the admission path and by
    /// [`Self::configure`] itself.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownAttachment`] when the identifier names no attachment, and
    /// [`WorkerError::InvalidArgument`] when a semantic attachment claims geometry or the
    /// attachment does not hold the geometry right.
    pub fn check_configure(&self, id: AttachmentId, claim_geometry: bool) -> Result<()> {
        let attachment = self.get(id).ok_or_else(|| unknown(id))?;
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
        Ok(())
    }

    /// Decides whether one attachment may report a viewport of these dimensions.
    ///
    /// Nothing changes here, for the same reason [`Self::check_configure`] exists. A semantic
    /// attachment has no terminal presentation at all, so a viewport report from one is a refusal
    /// this host can decide rather than an effect that fails part way.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownAttachment`] when the identifier names no attachment, and
    /// [`WorkerError::InvalidArgument`] when the dimensions violate a constraint or the attachment
    /// has no terminal presentation.
    pub fn check_viewport(&self, id: AttachmentId, dimensions: Dimensions) -> Result<()> {
        admit(dimensions)?;
        let attachment = self.get(id).ok_or_else(|| unknown(id))?;
        if attachment
            .presentation(self.dimensions, self.carryable)
            .is_none()
        {
            return Err(WorkerError::InvalidArgument(
                "a semantic attachment has no terminal presentation".to_owned(),
            ));
        }
        Ok(())
    }

    /// Checks a resize without changing anything.
    ///
    /// The caller asks the kernel between this and [`AttachmentTable::resize`], so a refused
    /// terminal operation leaves no record of a size the session never had.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`AttachmentTable::resize`].
    pub fn check_resize(
        &self,
        id: AttachmentId,
        dimensions: Dimensions,
        expected_epoch: u64,
    ) -> Result<()> {
        admit(dimensions)?;
        if self.owner != Some(id) || self.epoch != expected_epoch {
            return Err(WorkerError::NotGeometryOwner);
        }
        Ok(())
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
        admit(dimensions)?;
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
        self.transferable(id)?;
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

/// Checks a geometry and names every constraint it violates.
///
/// Section 8 asks for the violated limits, and a request can break more than one at a time: too
/// many columns and, with them, too many cells. One violation is reported as the dimension failure
/// it is; several are reported together, because telling somebody about the first and leaving them
/// to discover the rest one refusal at a time is not telling them.
pub(crate) fn admit(dimensions: Dimensions) -> Result<()> {
    let violations = dimensions.violations();
    match violations.len() {
        0 => Ok(()),
        1 => Err(WorkerError::Dimensions(violations[0])),
        _ => Err(WorkerError::InvalidArgument(
            violations
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        )),
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
            // A client that probed its terminal declares what it found. Direct mode needs that
            // declaration, so the tests that are about direct mode carry one.
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
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
                .viewport(identifier(2), Dimensions::new(40, 20), None)
                .expect("reports"),
            TerminalPresentationMode::Viewport
        );
        assert_eq!(table.geometry().dimensions, Dimensions::new(100, 30));
    }

    /// KR-REQ-06.03: the oldest remaining claim by join order succeeds the size owner.
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

    /// KR-REQ-06.03: every attachment has its own identifier and a join ordinal that only grows,
    /// and succession follows join order rather than the identifiers' own order. An attachment that
    /// leaves and joins again takes a new, later ordinal instead of its old place.
    #[test]
    fn succession_follows_the_join_ordinal_rather_than_the_identifier() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        let join = |table: &mut AttachmentTable, id: u8| {
            table
                .attach(
                    &terminal(80, 24, true),
                    capabilities(&[
                        AttachmentCapability::ObserveTerminal,
                        AttachmentCapability::Geometry,
                    ]),
                    identifier(id),
                    TimestampMs::new(u64::from(id)),
                )
                .expect("attaches")
                .0
        };
        // The identifiers run the other way from the order of joining.
        let ordinals: Vec<u64> = [9u8, 5, 1]
            .into_iter()
            .map(|id| join(&mut table, id).ordinal.get())
            .collect();
        assert!(
            ordinals.windows(2).all(|pair| pair[0] < pair[1]),
            "join order only grows: {ordinals:?}"
        );
        assert_eq!(table.geometry().owner.as_ref(), Some(&identifier(9)));

        // The second to join succeeds the first, not the smallest identifier.
        let change = table.detach(identifier(9)).expect("detaches");
        assert_eq!(change.state.owner.as_ref(), Some(&identifier(5)));

        // Joining again is joining last.
        let rejoined = join(&mut table, 9);
        assert!(rejoined.ordinal.get() > ordinals[2]);
        let change = table.detach(identifier(5)).expect("detaches");
        assert_eq!(
            change.state.owner.as_ref(),
            Some(&identifier(1)),
            "the attachment that joined again is now the newest"
        );
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
                .viewport(identifier(1), Dimensions::new(120, 40), None)
                .expect("reports"),
            TerminalPresentationMode::Direct
        );
    }

    #[test]
    fn a_terminal_this_build_has_not_qualified_is_projected() {
        // Knowing the name is not the same as having established what this session's output does
        // there. `TERM=dumb` is the clearest case: it is a real name and it cannot take the stream.
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        let unqualified = SessionAttachParams {
            terminal_profile_id: Nullable::some("dumb".to_owned()),
            ..terminal(120, 40, true)
        };
        attach(&mut table, 1, &unqualified);
        assert_eq!(
            table
                .viewport(identifier(1), Dimensions::new(120, 40), None)
                .expect("reports"),
            TerminalPresentationMode::Viewport
        );
    }

    #[test]
    fn a_terminal_that_was_not_probed_is_projected_whatever_size_it_is() {
        // `--no-probe` withholds the declaration, and a host that does not know what terminal it is
        // talking to does not hand it a byte stream and hope.
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        let unprobed = SessionAttachParams {
            terminal_profile_id: Nullable::null(),
            ..terminal(120, 40, true)
        };
        attach(&mut table, 1, &unprobed);
        assert_eq!(
            table
                .viewport(identifier(1), Dimensions::new(120, 40), None)
                .expect("reports"),
            TerminalPresentationMode::Viewport
        );
    }

    #[test]
    fn a_stream_the_engine_cannot_carry_projects_every_terminal() {
        let mut table = AttachmentTable::new(Dimensions::new(120, 40));
        attach(&mut table, 1, &terminal(120, 40, true));
        assert!(table.set_carryable(false), "the answer changed");
        assert_eq!(
            table
                .viewport(identifier(1), Dimensions::new(120, 40), None)
                .expect("reports"),
            TerminalPresentationMode::Viewport
        );
        assert_eq!(table.projected().len(), 1);
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
