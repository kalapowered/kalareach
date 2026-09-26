//! The shared host-side history filter.
//!
//! Section 10 says a grant's history lower bound is enforced **once**, in shared host-side
//! filtering, and then names the surfaces that share it: event pages, terminal and semantic
//! snapshots, loaded conversations, attachment references, exports, summaries,
//! changed-since-last-visit and voice context. One filter, eight callers. A surface that built its
//! own would be the one place a bound was forgotten, and nothing outside it would know.
//!
//! So there is one decision in this module, [`HistoryFilter::admit_at`], and everything else calls
//! it. [`Surface`] names which caller is asking, so evidence says where content was withheld
//! rather than only that it was, and so a surface added later has to be listed here before it can
//! be filtered at all.
//!
//! # What the filter refuses to be talked out of
//!
//! * **A later snapshot authorises nothing.** Content is admitted by *when it was produced*, never
//!   by when it was read, re-read or summarised. [`HistoryFilter::admit_derived`] takes the source
//!   interval the derived thing was built from, and the timestamp on the derivation itself is
//!   never consulted.
//! * **Derived data names its source.** [`Provenance`] travels with a summary, an export or a
//!   changed-since-last-visit answer. When that interval crosses the viewer's bound the answer is
//!   recomputed from the part the viewer may see, or omitted when nothing is left.
//! * **The live-screen exception is the visible screen and nothing else.** A grant that includes
//!   it reaches [`Surface::TerminalSnapshot`] for the screen that is showing. Inactive buffers,
//!   scrollback and the backing transcript stay outside it until the content is actually displayed
//!   or separately granted.
//! * **Bytes need their own grant.** A viewer that may see an attachment *reference* still needs
//!   `files.read` for the bytes, and the two are separate questions here.
//!
//! # The seam
//!
//! A caller builds one [`ViewerScope`] from the grant the host already checked, then asks this
//! module. Nothing constructs a scope from a role, a label or a capability: [`ViewerScope::owner`]
//! is the local owner's own authority, and [`ViewerScope::from_history`] is the only other way in:
//! [`ViewerScope::from_grant`] builds on it, and a worker builds on it from the scope the control
//! daemon sends with a forwarded read, since a worker holds no grants of its own.

use std::collections::BTreeSet;

use kr_protocol::gateway::{PendingKind, PendingState};
use kr_protocol::grant::{Grant, HistoryScope};
use kr_protocol::ids::{PendingResourceId, QuestionId};
use kr_protocol::rights::ActionRight;
use kr_protocol::sharing::LiveScreenPreview;

mod preview;

pub use preview::live_screen_preview;

/// Which caller is asking the filter.
///
/// The list is closed on purpose. Section 10 names these surfaces, and a ninth one cannot be
/// filtered without being added here, which is the point: a surface that is not listed is a
/// surface nobody decided about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Surface {
    /// A page of retained events, `history.page` and the event stream behind it.
    EventPage,
    /// A terminal snapshot: the projected screen a client installs.
    TerminalSnapshot,
    /// A semantic snapshot: the structured view an adapter produced.
    SemanticSnapshot,
    /// A conversation loaded from a previous turn.
    LoadedConversation,
    /// An attachment reference. The bytes behind it need their own file grant as well.
    AttachmentReference,
    /// An export of session content.
    Export,
    /// A generated summary.
    Summary,
    /// The changed-since-last-visit view.
    ChangedSinceLastVisit,
    /// The context offered to a voice request.
    VoiceContext,
}

impl Surface {
    /// Every surface the filter serves.
    pub const ALL: [Self; 9] = [
        Self::EventPage,
        Self::TerminalSnapshot,
        Self::SemanticSnapshot,
        Self::LoadedConversation,
        Self::AttachmentReference,
        Self::Export,
        Self::Summary,
        Self::ChangedSinceLastVisit,
        Self::VoiceContext,
    ];

    /// A stable name for evidence and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventPage => "event_page",
            Self::TerminalSnapshot => "terminal_snapshot",
            Self::SemanticSnapshot => "semantic_snapshot",
            Self::LoadedConversation => "loaded_conversation",
            Self::AttachmentReference => "attachment_reference",
            Self::Export => "export",
            Self::Summary => "summary",
            Self::ChangedSinceLastVisit => "changed_since_last_visit",
            Self::VoiceContext => "voice_context",
        }
    }

    /// Whether the live-screen exception reaches this surface.
    ///
    /// Only the terminal snapshot draws the screen. A grant whose whole history authority is the
    /// live-screen exception reads nothing on any other surface, because there is nothing there
    /// that is the visible screen.
    #[must_use]
    pub const fn is_the_visible_screen(self) -> bool {
        matches!(self, Self::TerminalSnapshot)
    }
}

impl std::fmt::Display for Surface {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why content did not reach a viewer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WithheldReason {
    /// It was produced before this grant's history lower bound.
    BeforeHistoryBound,
    /// This grant reaches no retained history at all: only the live screen and what follows it.
    NoRetainedHistory,
    /// It is not the visible screen, and the live-screen exception is all this grant carries.
    OutsideTheVisibleScreen,
    /// It is a question or approval created before the bound that this grant does not name.
    NotNamedByTheGrant,
    /// The bytes need their own file grant, which this grant does not carry.
    NoFileGrant,
    /// It is derived from an interval that crosses this viewer's scope, and could not be
    /// recomputed inside it.
    SourceIntervalOutsideScope,
    /// This grant carries no `session.view`, so there is no session content to filter.
    NoSessionView,
}

impl WithheldReason {
    /// A stable name for evidence and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeHistoryBound => "before_history_bound",
            Self::NoRetainedHistory => "no_retained_history",
            Self::OutsideTheVisibleScreen => "outside_the_visible_screen",
            Self::NotNamedByTheGrant => "not_named_by_the_grant",
            Self::NoFileGrant => "no_file_grant",
            Self::SourceIntervalOutsideScope => "source_interval_outside_scope",
            Self::NoSessionView => "no_session_view",
        }
    }
}

impl std::fmt::Display for WithheldReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The interval derived content was built from.
///
/// Both ends are UTC milliseconds, and `from_ms` is the earliest source the derivation read. A
/// summary that names no interval is not a summary this filter can serve: nothing could say
/// whether its sources were inside the viewer's scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceInterval {
    /// The earliest source, in UTC milliseconds.
    pub from_ms: u64,
    /// The latest source, in UTC milliseconds.
    pub to_ms: u64,
}

impl SourceInterval {
    /// Builds an interval, putting its ends in order.
    #[must_use]
    pub const fn new(from_ms: u64, to_ms: u64) -> Self {
        if from_ms <= to_ms {
            Self { from_ms, to_ms }
        } else {
            Self {
                from_ms: to_ms,
                to_ms: from_ms,
            }
        }
    }

    /// An interval covering one instant.
    #[must_use]
    pub const fn at(at_ms: u64) -> Self {
        Self {
            from_ms: at_ms,
            to_ms: at_ms,
        }
    }
}

/// What derived content was built from, and which resources it read.
///
/// The resource names are opaque to this module: a caller puts in whatever identifies its sources
/// in its own vocabulary, and gets them back beside the answer so the derived data can name them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    /// The interval the derivation read.
    pub interval: SourceInterval,
    /// The resources it read, as the caller names them.
    pub resources: Vec<String>,
}

impl Provenance {
    /// A provenance over one interval and no named resources.
    #[must_use]
    pub const fn over(interval: SourceInterval) -> Self {
        Self {
            interval,
            resources: Vec::new(),
        }
    }
}

/// What the filter says about one piece of derived content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DerivedDecision {
    /// Serve it. Its whole source interval is inside the viewer's scope.
    Serve {
        /// The provenance to publish beside it. Derived data identifies its source interval.
        provenance: Provenance,
    },
    /// Recompute it from this interval, which is the part of its sources the viewer may see.
    ///
    /// The existing text is not served: it was built from content this viewer has no authority
    /// over, and a newer timestamp on it does not change that.
    Recompute {
        /// The interval to build the replacement from.
        interval: SourceInterval,
    },
    /// Omit it. Nothing in its sources is inside the viewer's scope.
    Omit {
        /// Why.
        reason: WithheldReason,
    },
}

/// One run of content the filter kept back, as evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Withheld {
    /// Which surface asked.
    pub surface: Surface,
    /// Why it was kept back.
    pub reason: WithheldReason,
    /// How many items.
    pub count: u64,
    /// The earliest item's timestamp, when there was one.
    pub earliest_ms: Option<u64>,
    /// The latest item's timestamp, when there was one.
    pub latest_ms: Option<u64>,
}

/// What one surface may serve, and what it could not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Filtered<T> {
    /// Which surface asked.
    pub surface: Surface,
    /// What the viewer may see, in the order it arrived.
    pub kept: Vec<T>,
    /// What it may not, grouped by reason.
    pub withheld: Vec<Withheld>,
}

impl<T> Filtered<T> {
    /// How many items were kept back, across every reason.
    #[must_use]
    pub fn withheld_entries(&self) -> u64 {
        self.withheld
            .iter()
            .map(|withheld| withheld.count)
            .fold(0, u64::saturating_add)
    }

    /// Returns true when nothing was kept back.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.withheld.is_empty()
    }
}

/// Something the filter can place in time.
///
/// A caller implements it for its own item rather than converting into a type of this module's, so
/// filtering never copies a session's content to decide about it.
pub trait Timed {
    /// When this item was produced, in UTC milliseconds.
    fn produced_at_ms(&self) -> u64;
}

impl Timed for u64 {
    fn produced_at_ms(&self) -> u64 {
        *self
    }
}

/// What one viewer may see.
///
/// Built from the grant the host has already checked. It is deliberately not built from a role, a
/// label or a capability: section 25 forbids authorising from a role label, and section 10 makes a
/// capability feasibility rather than authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewerScope {
    /// The earliest content this viewer may see. `None` means no retained history at all.
    lower_bound_ms: Option<u64>,
    /// Whether the visible screen is included.
    include_live_screen: bool,
    /// Current questions this viewer's grant names explicitly.
    named_questions: BTreeSet<QuestionId>,
    /// Current approvals it names explicitly, by the broker's resource identity.
    named_approvals: BTreeSet<PendingResourceId>,
    /// Whether it carries `session.view`.
    session_view: bool,
    /// Whether it carries `files.read`, which attachment and file bytes need on their own.
    files_read: bool,
    /// Whether this is the host owner's own authority rather than a grant.
    unrestricted: bool,
}

impl ViewerScope {
    /// The host owner's own authority: every surface, every interval, the whole screen.
    ///
    /// This is the local owner in front of the machine, whose authority is the operating-system
    /// account the session already runs as. It is never derived from a grant, and a grant can
    /// never produce it.
    #[must_use]
    pub fn owner() -> Self {
        Self {
            lower_bound_ms: Some(0),
            include_live_screen: true,
            named_questions: BTreeSet::new(),
            named_approvals: BTreeSet::new(),
            session_view: true,
            files_read: true,
            unrestricted: true,
        }
    }

    /// The scope a caller forwarded from the control daemon has at this worker.
    ///
    /// A worker does not hold the grant the daemon checked; what it knows is that the caller
    /// reached it through the daemon rather than being the local owner. Section 10's live-screen
    /// exception is the most such a caller ever reaches here, so that is what this scope is: the
    /// visible screen and what happens after it. A caller whose grant reaches further is still
    /// served no more than this by this worker, because the worker has nothing to check the
    /// further reach against.
    ///
    /// `at_ms` is the moment the caller attached. Content produced from then on is inside the
    /// scope; anything older is not, which is what "the selected live screen and future events"
    /// means for a worker that cannot see the grant.
    #[must_use]
    pub fn forwarded(at_ms: u64) -> Self {
        Self {
            lower_bound_ms: Some(at_ms),
            include_live_screen: true,
            named_questions: BTreeSet::new(),
            named_approvals: BTreeSet::new(),
            session_view: true,
            files_read: false,
            unrestricted: false,
        }
    }

    /// The scope a grant gives its holder.
    ///
    /// The grant's history scope, with the two rights the filter reads taken from the grant
    /// itself.
    #[must_use]
    pub fn from_grant(grant: &Grant) -> Self {
        Self {
            files_read: grant.permits(ActionRight::FilesRead),
            ..Self::from_history(&grant.history, grant.permits(ActionRight::SessionView))
        }
    }

    /// The scope a grant's history scope gives, where `session_view` says whether the grant
    /// carries `session.view`.
    ///
    /// The one place a history scope becomes a viewer's scope, and everything the filter decides
    /// comes from here. A worker builds one from the scope the control daemon sends with a
    /// forwarded read, knowing `session.view` from the rights the daemon checked for the method.
    /// File bytes need `files.read` of their own, which a scope alone never carries, so a scope
    /// built here reads none.
    #[must_use]
    pub fn from_history(history: &HistoryScope, session_view: bool) -> Self {
        Self {
            lower_bound_ms: history.lower_bound_ms.as_ref().map(|bound| bound.get()),
            include_live_screen: history.include_live_screen,
            named_questions: history.named_questions.iter().copied().collect(),
            named_approvals: history.named_approvals.iter().copied().collect(),
            session_view,
            files_read: false,
            unrestricted: false,
        }
    }

    /// The scope of a live view that began at `from_ms`.
    ///
    /// A view that goes on receiving what happens after it began reaches, under section 10's
    /// live-screen exception, the screen that is showing and what follows it. So a scope that keeps
    /// no retained history and includes the live screen reaches what is recorded from `from_ms` on,
    /// and nothing older. A scope with a bound keeps its bound, and one without the live screen
    /// keeps reaching no retained content at all.
    #[must_use]
    pub fn live_from(self, from_ms: u64) -> Self {
        if self.lower_bound_ms.is_none() && self.include_live_screen {
            Self {
                lower_bound_ms: Some(from_ms),
                ..self
            }
        } else {
            self
        }
    }

    /// Returns true when this is the host owner's own unrestricted authority.
    #[must_use]
    pub const fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }

    /// Returns true when the viewer may read session content at all.
    #[must_use]
    pub const fn sees_the_session(&self) -> bool {
        self.session_view
    }

    /// Returns true when the viewer may read file and attachment bytes.
    #[must_use]
    pub const fn reads_files(&self) -> bool {
        self.files_read
    }

    /// Returns true when the visible screen is included.
    #[must_use]
    pub const fn includes_the_live_screen(&self) -> bool {
        self.include_live_screen
    }

    /// The earliest content this viewer may see, when it reaches retained history at all.
    #[must_use]
    pub const fn lower_bound_ms(&self) -> Option<u64> {
        self.lower_bound_ms
    }

    /// How much of the screen a restoration may carry for this viewer.
    ///
    /// The unrestricted owner is drawn the whole screen. Anybody else is drawn the visible screen
    /// alone, because that is the most section 10's exception ever reaches and a grant with more
    /// history still does not gain the buffer that is not showing.
    #[must_use]
    pub const fn screen_scope(&self) -> crate::render::Scope {
        if self.unrestricted {
            crate::render::Scope::WholeScreen
        } else {
            crate::render::Scope::LiveScreen
        }
    }
}

/// The filter itself: one scope, one decision, nine surfaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryFilter {
    scope: ViewerScope,
}

impl HistoryFilter {
    /// Builds a filter for one viewer.
    #[must_use]
    pub const fn new(scope: ViewerScope) -> Self {
        Self { scope }
    }

    /// The scope this filter enforces.
    #[must_use]
    pub const fn scope(&self) -> &ViewerScope {
        &self.scope
    }

    /// The one decision. Everything else in this module calls it.
    ///
    /// `produced_at_ms` is when the content was produced, never when it was read, re-read or
    /// summarised: a snapshot taken now from a screen painted an hour ago is an hour-old screen,
    /// and stamping the snapshot with the current time would make every bound meaningless.
    ///
    /// # Errors
    ///
    /// Returns the reason the content is outside this viewer's scope.
    pub fn admit_at(
        &self,
        surface: Surface,
        produced_at_ms: u64,
    ) -> std::result::Result<(), WithheldReason> {
        if !self.scope.session_view {
            return Err(WithheldReason::NoSessionView);
        }
        if self.scope.unrestricted {
            return Ok(());
        }
        match self.scope.lower_bound_ms {
            // No retained history. The live screen is the only content such a grant reaches, and
            // only on the surface that draws it.
            None => {
                if self.scope.include_live_screen && surface.is_the_visible_screen() {
                    Ok(())
                } else if self.scope.include_live_screen {
                    Err(WithheldReason::OutsideTheVisibleScreen)
                } else {
                    Err(WithheldReason::NoRetainedHistory)
                }
            }
            Some(bound) if produced_at_ms >= bound => Ok(()),
            // Older than the bound. The live-screen exception still reaches the visible screen:
            // what is on it now is what is being shared, whenever it was printed.
            Some(_) => {
                if self.scope.include_live_screen && surface.is_the_visible_screen() {
                    Ok(())
                } else {
                    Err(WithheldReason::BeforeHistoryBound)
                }
            }
        }
    }

    /// Filters a run of content for one surface.
    ///
    /// The items keep their order and their identity: what comes back is what the caller put in,
    /// minus what this viewer may not see, with one evidence entry per reason.
    pub fn filter<T: Timed>(
        &self,
        surface: Surface,
        items: impl IntoIterator<Item = T>,
    ) -> Filtered<T> {
        let mut kept = Vec::new();
        let mut withheld: Vec<Withheld> = Vec::new();
        for item in items {
            let at = item.produced_at_ms();
            match self.admit_at(surface, at) {
                Ok(()) => kept.push(item),
                Err(reason) => record(&mut withheld, surface, reason, at),
            }
        }
        withheld.sort_by_key(|entry| entry.reason);
        Filtered {
            surface,
            kept,
            withheld,
        }
    }

    /// Decides about derived content from the interval it was built from.
    ///
    /// A summary generated a moment ago from an hour-old conversation is an hour-old conversation:
    /// the decision reads [`Provenance::interval`] and never the moment of derivation. When part
    /// of the interval is inside the viewer's scope the answer is [`DerivedDecision::Recompute`]
    /// with that part, because serving the original text would serve the part that is not.
    #[must_use]
    pub fn admit_derived(&self, surface: Surface, provenance: &Provenance) -> DerivedDecision {
        if !self.scope.session_view {
            return DerivedDecision::Omit {
                reason: WithheldReason::NoSessionView,
            };
        }
        if self.scope.unrestricted {
            return DerivedDecision::Serve {
                provenance: provenance.clone(),
            };
        }
        let Some(bound) = self.scope.lower_bound_ms else {
            // No retained history: derived content has no interval this viewer may read, whatever
            // the live-screen exception says. The exception is the screen itself, not a summary of
            // what used to be on it.
            return DerivedDecision::Omit {
                reason: WithheldReason::NoRetainedHistory,
            };
        };
        if provenance.interval.from_ms >= bound {
            return DerivedDecision::Serve {
                provenance: provenance.clone(),
            };
        }
        if provenance.interval.to_ms < bound {
            return DerivedDecision::Omit {
                reason: WithheldReason::BeforeHistoryBound,
            };
        }
        let _ = surface;
        DerivedDecision::Recompute {
            interval: SourceInterval::new(bound, provenance.interval.to_ms),
        }
    }

    /// Decides about one current question, which an invitation may name explicitly.
    ///
    /// A named question is permitted whenever it was created, which is the whole of section 10's
    /// exception: the invitation permits those exact current decisions, not the conversation they
    /// came from. An unnamed question follows the ordinary bound.
    ///
    /// # Errors
    ///
    /// Returns the reason the question is outside this viewer's scope.
    pub fn admit_question(
        &self,
        question_id: QuestionId,
        created_at_ms: u64,
    ) -> std::result::Result<(), WithheldReason> {
        if self.scope.named_questions.contains(&question_id) && self.scope.session_view {
            return Ok(());
        }
        self.admit_at(Surface::LoadedConversation, created_at_ms)
            .map_err(|reason| match reason {
                WithheldReason::BeforeHistoryBound
                | WithheldReason::NoRetainedHistory
                | WithheldReason::OutsideTheVisibleScreen => WithheldReason::NotNamedByTheGrant,
                other => other,
            })
    }

    /// Decides about one approval request, which an invitation may name while it is current.
    ///
    /// Section 10 permits the exact *current* decisions an invitation names, not their earlier
    /// conversation. So a named approval is admitted however early it was recorded only while it
    /// can still be decided, pending or claimed; once it has ended it is an old record like any
    /// other, and the ordinary bound decides. `resource_id` is the one resource the broker
    /// arbitrates for the request, which is what a grant names; an upstream's own identifier would
    /// not do, since two connections both call their first request `1`.
    ///
    /// # Errors
    ///
    /// Returns the reason the approval is outside this viewer's scope.
    pub fn admit_approval(
        &self,
        resource_id: PendingResourceId,
        recorded_at_ms: u64,
        state: PendingState,
    ) -> std::result::Result<(), WithheldReason> {
        let named = self.scope.named_approvals.contains(&resource_id);
        if named && !state.is_terminal() && self.scope.session_view {
            return Ok(());
        }
        self.admit_at(Surface::LoadedConversation, recorded_at_ms)
            .map_err(|reason| match reason {
                WithheldReason::BeforeHistoryBound
                | WithheldReason::NoRetainedHistory
                | WithheldReason::OutsideTheVisibleScreen => WithheldReason::NotNamedByTheGrant,
                other => other,
            })
    }

    /// Decides about one resource the broker arbitrates: an approval, a reverse call or an action
    /// this host prepared against the upstream.
    ///
    /// The pending-resource snapshot and every transition that follows it are decided here, so
    /// neither carries what the approval record read would withhold. An approval is decided as
    /// [`Self::admit_approval`] decides it: named and current, else by the bound. A name is for an
    /// approval, so a reverse call and an upstream action are decided by that same bound, whatever
    /// the grant names. `kind` is what the resource is now, since a request becomes an approval
    /// when a decoder interprets it, and `recorded_at_ms` is when the broker recorded it, which
    /// never changes.
    ///
    /// # Errors
    ///
    /// Returns the reason the resource is outside this viewer's scope.
    pub fn admit_resource(
        &self,
        kind: PendingKind,
        resource_id: PendingResourceId,
        recorded_at_ms: u64,
        state: PendingState,
    ) -> std::result::Result<(), WithheldReason> {
        match kind {
            PendingKind::Approval => self.admit_approval(resource_id, recorded_at_ms, state),
            PendingKind::ReverseRpc | PendingKind::UpstreamAction => {
                self.admit_at(Surface::LoadedConversation, recorded_at_ms)
            }
        }
    }

    /// Decides about one attachment's bytes.
    ///
    /// Two questions, both of which have to be answered: the reference is inside the history
    /// scope, and the viewer holds `files.read` for the bytes behind it. Section 10 keeps them
    /// apart, so a viewer that may see that an attachment exists does not thereby receive it.
    ///
    /// # Errors
    ///
    /// Returns the reason the bytes are outside this viewer's scope.
    pub fn admit_attachment_bytes(
        &self,
        produced_at_ms: u64,
    ) -> std::result::Result<(), WithheldReason> {
        self.admit_at(Surface::AttachmentReference, produced_at_ms)?;
        if self.scope.files_read {
            Ok(())
        } else {
            Err(WithheldReason::NoFileGrant)
        }
    }

    /// How much of the screen a snapshot installation may carry for this viewer.
    ///
    /// Snapshot installation goes through the filtered projection, never the worker's unrestricted
    /// internal state, so this is the only thing that decides it.
    #[must_use]
    pub const fn screen_scope(&self) -> crate::render::Scope {
        self.scope.screen_scope()
    }

    /// Builds the live-screen preview an issuer is shown before an invitation exists.
    ///
    /// Bounded by [`kr_protocol::sharing::MAX_PREVIEW_LINES`] and
    /// [`kr_protocol::sharing::MAX_PREVIEW_LINE_CHARS`], and marked when it was cut, so the issuer
    /// is never shown a preview that quietly says less than the recipient will see.
    #[must_use]
    pub fn preview_live_screen<'a>(
        &self,
        lines: impl IntoIterator<Item = &'a str>,
    ) -> Option<LiveScreenPreview> {
        if !self.scope.include_live_screen {
            return None;
        }
        Some(live_screen_preview(lines))
    }
}

fn record(withheld: &mut Vec<Withheld>, surface: Surface, reason: WithheldReason, at_ms: u64) {
    if let Some(entry) = withheld
        .iter_mut()
        .find(|entry| entry.reason == reason && entry.surface == surface)
    {
        entry.count = entry.count.saturating_add(1);
        entry.earliest_ms = Some(entry.earliest_ms.map_or(at_ms, |held| held.min(at_ms)));
        entry.latest_ms = Some(entry.latest_ms.map_or(at_ms, |held| held.max(at_ms)));
        return;
    }
    withheld.push(Withheld {
        surface,
        reason,
        count: 1,
        earliest_ms: Some(at_ms),
        latest_ms: Some(at_ms),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId};
    use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};

    fn grant(history: HistoryScope, actions: &[ActionRight]) -> Grant {
        Grant {
            grant_id: GrantId::new(Uuid::from_bytes([1; 16])),
            parent_grant_id: Nullable::null(),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
            recipient_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: actions.iter().copied().collect(),
            history,
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        }
    }

    fn bounded(bound_ms: u64, live_screen: bool) -> HistoryScope {
        HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(bound_ms)),
            include_live_screen: live_screen,
            named_questions: CanonicalSet::from_iter([]),
            named_approvals: CanonicalSet::from_iter([]),
        }
    }

    fn filter_at(bound_ms: u64, live_screen: bool) -> HistoryFilter {
        HistoryFilter::new(ViewerScope::from_grant(&grant(
            bounded(bound_ms, live_screen),
            &[ActionRight::SessionView],
        )))
    }

    #[test]
    fn every_surface_shares_one_bound() {
        let filter = filter_at(1_000, false);
        for surface in Surface::ALL {
            assert_eq!(
                filter.admit_at(surface, 999),
                Err(WithheldReason::BeforeHistoryBound),
                "{surface} served content older than the bound"
            );
            assert_eq!(filter.admit_at(surface, 1_000), Ok(()));
        }
    }

    #[test]
    fn a_summary_made_now_from_old_content_is_not_newly_authorised() {
        let filter = filter_at(1_000, false);
        let provenance = Provenance::over(SourceInterval::new(10, 900));
        assert_eq!(
            filter.admit_derived(Surface::Summary, &provenance),
            DerivedDecision::Omit {
                reason: WithheldReason::BeforeHistoryBound
            },
            "a derivation's own timestamp never authorises its sources"
        );
    }

    #[test]
    fn a_summary_that_straddles_the_bound_is_recomputed_from_the_part_inside_it() {
        let filter = filter_at(1_000, false);
        let provenance = Provenance::over(SourceInterval::new(500, 2_000));
        assert_eq!(
            filter.admit_derived(Surface::ChangedSinceLastVisit, &provenance),
            DerivedDecision::Recompute {
                interval: SourceInterval::new(1_000, 2_000)
            }
        );
    }

    #[test]
    fn a_summary_wholly_inside_the_bound_is_served_with_its_provenance() {
        let filter = filter_at(1_000, false);
        let provenance = Provenance {
            interval: SourceInterval::new(1_500, 2_000),
            resources: vec!["session:events".to_owned()],
        };
        assert_eq!(
            filter.admit_derived(Surface::Summary, &provenance),
            DerivedDecision::Serve {
                provenance: provenance.clone()
            },
            "derived data names the interval and the resources it was built from"
        );
    }

    #[test]
    fn the_live_screen_exception_reaches_the_screen_and_nothing_else() {
        let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
            HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: true,
                named_questions: CanonicalSet::from_iter([]),
                named_approvals: CanonicalSet::from_iter([]),
            },
            &[ActionRight::SessionView],
        )));
        assert_eq!(filter.admit_at(Surface::TerminalSnapshot, 0), Ok(()));
        for surface in Surface::ALL
            .into_iter()
            .filter(|surface| !surface.is_the_visible_screen())
        {
            assert_eq!(
                filter.admit_at(surface, 0),
                Err(WithheldReason::OutsideTheVisibleScreen),
                "{surface} served content to a live-only grant"
            );
        }
        assert_eq!(
            filter.screen_scope(),
            crate::render::Scope::LiveScreen,
            "the exception is the visible screen, never the buffer that is not showing"
        );
    }

    #[test]
    fn a_named_question_is_permitted_although_it_predates_the_bound() {
        let named = QuestionId::new(Uuid::from_bytes([7; 16]));
        let other = QuestionId::new(Uuid::from_bytes([8; 16]));
        let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
            HistoryScope {
                lower_bound_ms: Nullable::some(TimestampMs::new(1_000)),
                include_live_screen: false,
                named_questions: CanonicalSet::from_iter([named]),
                named_approvals: CanonicalSet::from_iter([]),
            },
            &[ActionRight::SessionView],
        )));
        assert_eq!(filter.admit_question(named, 10), Ok(()));
        assert_eq!(
            filter.admit_question(other, 10),
            Err(WithheldReason::NotNamedByTheGrant),
            "naming one decision does not open the conversation it came from"
        );
    }

    #[test]
    fn attachment_bytes_need_their_own_file_grant() {
        let viewer = HistoryFilter::new(ViewerScope::from_grant(&grant(
            bounded(0, false),
            &[ActionRight::SessionView],
        )));
        assert_eq!(
            viewer.admit_at(Surface::AttachmentReference, 10),
            Ok(()),
            "the reference is inside the history scope"
        );
        assert_eq!(
            viewer.admit_attachment_bytes(10),
            Err(WithheldReason::NoFileGrant)
        );

        let reviewer = HistoryFilter::new(ViewerScope::from_grant(&grant(
            bounded(0, false),
            &[ActionRight::SessionView, ActionRight::FilesRead],
        )));
        assert_eq!(reviewer.admit_attachment_bytes(10), Ok(()));
    }

    #[test]
    fn filtering_names_what_it_kept_back_and_how_much() {
        let filter = filter_at(1_000, false);
        let filtered = filter.filter(Surface::EventPage, [10_u64, 900, 1_000, 2_000]);
        assert_eq!(filtered.kept, vec![1_000, 2_000]);
        assert_eq!(filtered.withheld_entries(), 2);
        assert!(!filtered.is_complete());
        let entry = filtered.withheld.first().expect("one reason");
        assert_eq!(entry.reason, WithheldReason::BeforeHistoryBound);
        assert_eq!(entry.earliest_ms, Some(10));
        assert_eq!(entry.latest_ms, Some(900));
    }

    #[test]
    fn a_grant_without_session_view_reads_nothing() {
        let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
            bounded(0, true),
            &[ActionRight::FilesRead],
        )));
        for surface in Surface::ALL {
            assert_eq!(
                filter.admit_at(surface, u64::MAX),
                Err(WithheldReason::NoSessionView)
            );
        }
    }

    #[test]
    fn the_owner_is_drawn_the_whole_screen_and_a_grant_never_is() {
        assert_eq!(
            HistoryFilter::new(ViewerScope::owner()).screen_scope(),
            crate::render::Scope::WholeScreen
        );
        assert_eq!(
            filter_at(0, true).screen_scope(),
            crate::render::Scope::LiveScreen
        );
    }

    #[test]
    fn a_preview_exists_only_when_the_issuer_included_the_screen() {
        assert!(filter_at(0, false).preview_live_screen(["hello"]).is_none());
        let preview = filter_at(0, true)
            .preview_live_screen(["hello"])
            .expect("the issuer included the screen");
        assert_eq!(preview.lines, vec!["hello".to_owned()]);
        assert!(!preview.truncated);
    }
}
