//! The reading seam: session facts, filtered once by the shared host-side filter.
//!
//! Section 10 enforces the grant's history lower bound **once**, in `kr_worker::history_filter`,
//! with voice context one of its eight named callers. That is what happens here, on this side of
//! the crate boundary, because only this side may reach the filter. The viewer scope is built from
//! the requesting device's grant and from nothing else, so a selection can never use the host
//! owner's broader history: `ViewerScope::owner()` is not called in this module and the seam has
//! no shape that could ask for it.

use std::sync::Arc;

use kr_protocol::grant::Grant;
use kr_protocol::ids::{ApprovalRequestId, SessionId};
use kr_protocol::scalars::Digest256;
use kr_voice::seams::{
    ContextItem, ContextRequest, ContextSource, GatheredContext, SelectedItem, VoiceFuture,
    WithheldRun,
};
use kr_worker::history_filter::{HistoryFilter, Surface, Timed, ViewerScope};

/// What this host can say about one session, before any filtering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionSnapshot {
    /// The session's description, with the moment it describes.
    pub description: Option<ContextItem>,
    /// The current working directory.
    pub working_directory: Option<ContextItem>,
    /// The active application.
    pub active_application: Option<ContextItem>,
    /// Summaries of the decisions waiting on a person.
    pub pending_decisions: Vec<ContextItem>,
    /// Semantic messages, oldest first.
    pub recent_messages: Vec<ContextItem>,
    /// Content from classes the person selected.
    pub selected: Vec<SelectedItem>,
    /// The resources it was read from, as this host names them.
    pub resources: Vec<String>,
    /// What this host could not read at all, so a gap is visible rather than silent.
    pub unavailable: Vec<WithheldRun>,
}

/// Where the session facts come from.
///
/// Declared here rather than taken as a closure so the one implementation that reaches the
/// registry and the worker is a named type a reader can find.
pub trait SessionFacts: Send + Sync + std::fmt::Debug {
    /// Everything this host can say about one session.
    fn snapshot<'a>(&'a self, session_id: SessionId) -> VoiceFuture<'a, SessionSnapshot>;

    /// The digest of one approval request's details, as this host holds them.
    fn approval_digest<'a>(
        &'a self,
        session_id: SessionId,
        approval_request_id: &'a ApprovalRequestId,
    ) -> VoiceFuture<'a, Option<Digest256>>;
}

/// The context source: session facts through the shared host-side filter.
#[derive(Debug)]
pub struct FilteredContext {
    facts: Arc<dyn SessionFacts>,
}

impl FilteredContext {
    /// Builds the seam over one source of session facts.
    #[must_use]
    pub const fn new(facts: Arc<dyn SessionFacts>) -> Self {
        Self { facts }
    }
}

/// One item, so the filter can place it in time.
struct Placed(ContextItem);

impl Timed for Placed {
    fn produced_at_ms(&self) -> u64 {
        self.0.produced_at_ms
    }
}

/// Runs one run of items through the filter and records what it kept back.
fn admit(
    filter: &HistoryFilter,
    items: Vec<ContextItem>,
    withheld: &mut Vec<WithheldRun>,
) -> Vec<ContextItem> {
    let filtered = filter.filter(Surface::VoiceContext, items.into_iter().map(Placed));
    for run in &filtered.withheld {
        withheld.push(WithheldRun {
            reason: run.reason.to_string(),
            count: run.count,
        });
    }
    filtered.kept.into_iter().map(|placed| placed.0).collect()
}

/// The same for one optional item.
fn admit_one(
    filter: &HistoryFilter,
    item: Option<ContextItem>,
    withheld: &mut Vec<WithheldRun>,
) -> Option<ContextItem> {
    admit(filter, item.into_iter().collect(), withheld)
        .into_iter()
        .next()
}

impl ContextSource for FilteredContext {
    fn gather<'a>(&'a self, request: &'a ContextRequest) -> VoiceFuture<'a, GatheredContext> {
        Box::pin(async move {
            let snapshot = self.facts.snapshot(request.session_id).await?;
            // One scope, built from the grant the host already checked. Nothing here builds a
            // scope from a role, a label, a capability or the host owner's own authority.
            let filter = HistoryFilter::new(scope_of(&request.grant));
            let mut withheld = snapshot.unavailable.clone();

            // Selecting a class is a person saying they want it, not authority to read it. File
            // contents and attachment bytes need the grant's own file right on top of the history
            // bound, which is the filter's `admit_attachment_bytes` question rather than its
            // timestamp one.
            let mut selected: Vec<SelectedItem> = Vec::new();
            for entry in snapshot.selected {
                let needs_file_right = matches!(
                    entry.class,
                    kr_protocol::voice::VoiceContextClass::FileContents
                        | kr_protocol::voice::VoiceContextClass::AttachmentBytes
                );
                if needs_file_right
                    && let Err(reason) = filter.admit_attachment_bytes(entry.item.produced_at_ms)
                {
                    withheld.push(WithheldRun {
                        reason: format!("{}: {reason}", entry.class),
                        count: 1,
                    });
                    continue;
                }
                if let Some(item) = admit_one(&filter, Some(entry.item), &mut withheld) {
                    selected.push(SelectedItem {
                        class: entry.class,
                        item,
                    });
                }
            }

            Ok(GatheredContext {
                session_description: admit_one(&filter, snapshot.description, &mut withheld),
                working_directory: admit_one(&filter, snapshot.working_directory, &mut withheld),
                active_application: admit_one(&filter, snapshot.active_application, &mut withheld),
                pending_decisions: admit(&filter, snapshot.pending_decisions, &mut withheld),
                recent_messages: admit(&filter, snapshot.recent_messages, &mut withheld),
                selected,
                resources: snapshot.resources,
                withheld,
            })
        })
    }

    fn approval_details<'a>(
        &'a self,
        session_id: SessionId,
        approval_request_id: &'a ApprovalRequestId,
    ) -> VoiceFuture<'a, Option<Digest256>> {
        self.facts.approval_digest(session_id, approval_request_id)
    }
}

/// The viewer scope for one grant.
///
/// A separate function so there is exactly one place this module builds a scope, and so a reader
/// can see that the only input is the grant.
fn scope_of(grant: &Grant) -> ViewerScope {
    ViewerScope::from_grant(grant)
}
