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
use kr_protocol::session::SessionSummary;
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

/// What this host can say about one session, with the moment each fact was produced.
///
/// The moment is the whole point. A grant's history lower bound is checked against the time
/// content was *produced*, so a fact carried under the time it was *read* would let a retained
/// summary of a session that closed long ago pass a bound written afterwards. The shell a session
/// runs, its display number and the directory it started in are all fixed when the session is
/// created, so the creation time is theirs, and a session's retained summary keeps it after the
/// session closes. What the summary cannot place in time — the foreground, which changes while the
/// session runs and carries no moment of its own — is named as missing rather than carried.
#[must_use]
pub fn snapshot_of(summary: &SessionSummary, session_id: SessionId) -> SessionSnapshot {
    let created_at_ms = summary.created_at_ms.get();
    let at_creation = |text: String| ContextItem::new(text, created_at_ms);
    SessionSnapshot {
        // The session's own description is the shell it runs and where it runs it. Both are facts
        // this daemon holds itself, so the description never rests on something it would have to
        // ask a worker for.
        description: (!summary.shell_path.is_empty()).then(|| {
            at_creation(format!(
                "session {} running {}",
                summary.display_number, summary.shell_path
            ))
        }),
        working_directory: (!summary.cwd.is_empty()).then(|| at_creation(summary.cwd.clone())),
        active_application: None,
        pending_decisions: Vec::new(),
        recent_messages: Vec::new(),
        selected: Vec::new(),
        resources: vec![format!("session:{session_id}")],
        unavailable: vec![
            WithheldRun {
                reason: "this host does not hold the worker's semantic history".to_owned(),
                count: 0,
            },
            WithheldRun {
                reason: "this host cannot say when the foreground last changed".to_owned(),
                count: 1,
            },
        ],
    }
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

/// Runs one snapshot through the shared host-side filter under one grant's scope.
///
/// Every read of a session's content that voice serves goes through here, whether it was asked for
/// as context or produced as the result of an effect: a bound applied on one path and not the
/// other is a bound with a way round it.
#[must_use]
pub fn filtered(snapshot: SessionSnapshot, grant: &Grant) -> GatheredContext {
    // One scope, built from the grant the host already checked. Nothing here builds a scope from
    // a role, a label, a capability or the host owner's own authority.
    let filter = HistoryFilter::new(scope_of(grant));
    let mut withheld = snapshot.unavailable.clone();

    // Selecting a class is a person saying they want it, not authority to read it. File contents
    // and attachment bytes need the grant's own file right on top of the history bound, which is
    // the filter's `admit_attachment_bytes` question rather than its timestamp one.
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

    GatheredContext {
        session_description: admit_one(&filter, snapshot.description, &mut withheld),
        working_directory: admit_one(&filter, snapshot.working_directory, &mut withheld),
        active_application: admit_one(&filter, snapshot.active_application, &mut withheld),
        pending_decisions: admit(&filter, snapshot.pending_decisions, &mut withheld),
        recent_messages: admit(&filter, snapshot.recent_messages, &mut withheld),
        selected,
        resources: snapshot.resources,
        withheld,
    }
}

impl ContextSource for FilteredContext {
    fn gather<'a>(&'a self, request: &'a ContextRequest) -> VoiceFuture<'a, GatheredContext> {
        Box::pin(async move {
            let snapshot = self.facts.snapshot(request.session_id).await?;
            Ok(filtered(snapshot, &request.grant))
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

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::identity::{DesktopBinding, WorkerProfile};
    use kr_protocol::ids::{AuthorityRevision, DeviceId, EnvironmentId, GrantId, SessionEpoch};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, U64, Uuid};
    use kr_protocol::session::{
        ClosureReason, ClosureRecord, DisplayNumber, Durability, OwnershipCoverage, SessionState,
        ShellMode,
    };

    fn session_id() -> SessionId {
        SessionId::new(Uuid::from_bytes([0xa1; 16]))
    }

    fn summary(created_at_ms: u64) -> SessionSummary {
        SessionSummary {
            session_id: session_id(),
            session_epoch: SessionEpoch::new(1),
            environment_id: EnvironmentId::new(Uuid::from_bytes([0xe0; 16])),
            display_number: DisplayNumber::new(3),
            state: SessionState::Live,
            shell_mode: ShellMode::Managed,
            shell_path: "/bin/zsh".to_owned(),
            cwd: "/work/kalareach".to_owned(),
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            created_at_ms: kr_protocol::scalars::TimestampMs::new(created_at_ms),
            dimensions: kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS,
            attachment_count: U64::ZERO,
            application_state: Nullable::some(kr_protocol::session::ApplicationState::AgentBusy),
            root_process: Nullable::null(),
            closure: Nullable::null(),
        }
    }

    /// KR-REQ-15.20: a fact carries the moment it was produced, which for the shell and the
    /// directory is the moment the session was created.
    #[test]
    fn a_session_fact_carries_the_moment_the_session_was_created() {
        let snapshot = snapshot_of(&summary(1_000), session_id());
        let description = snapshot.description.expect("a description");
        assert_eq!(description.produced_at_ms, 1_000);
        assert!(description.text.contains("/bin/zsh"), "{description:?}");
        let directory = snapshot.working_directory.expect("a working directory");
        assert_eq!(directory.produced_at_ms, 1_000);
    }

    /// KR-REQ-15.20: the foreground has no moment this host can name, so it is reported as
    /// unavailable rather than carried under the moment it was read.
    #[test]
    fn the_foreground_is_reported_as_missing_rather_than_timed_by_the_read() {
        let snapshot = snapshot_of(&summary(1_000), session_id());
        assert!(snapshot.active_application.is_none());
        assert!(
            snapshot
                .unavailable
                .iter()
                .any(|run| run.reason.contains("foreground")),
            "{:?}",
            snapshot.unavailable
        );
    }

    /// A source of session facts a test hands to the filter.
    #[derive(Debug)]
    struct Facts(SessionSnapshot);

    impl SessionFacts for Facts {
        fn snapshot<'a>(&'a self, _session_id: SessionId) -> VoiceFuture<'a, SessionSnapshot> {
            let snapshot = self.0.clone();
            Box::pin(async move { Ok(snapshot) })
        }

        fn approval_digest<'a>(
            &'a self,
            _session_id: SessionId,
            _approval_request_id: &'a ApprovalRequestId,
        ) -> VoiceFuture<'a, Option<Digest256>> {
            Box::pin(async move { Ok(None) })
        }
    }

    fn device_grant(lower_bound_ms: u64) -> Grant {
        Grant {
            grant_id: GrantId::new(Uuid::from_bytes([1; 16])),
            parent_grant_id: Nullable::null(),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
            recipient_device_id: DeviceId::new(Uuid::from_bytes([0xf1; 16])),
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: [ActionRight::SessionView].into_iter().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::some(TimestampMs::new(lower_bound_ms)),
                include_live_screen: true,
                named_questions: CanonicalSet::from_iter([]),
                named_approvals: CanonicalSet::from_iter([]),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        }
    }

    /// KR-REQ-15.20: the gathering runs through the shared host-side filter under a scope built
    /// from the requesting device's own grant, so content produced before that grant's history
    /// begins is kept back and counted rather than carried.
    #[tokio::test]
    async fn content_older_than_the_requesting_devices_bound_is_kept_back() {
        let facts = Facts(SessionSnapshot {
            description: Some(ContextItem::new("session 3 running /bin/zsh", 500)),
            working_directory: Some(ContextItem::new("/work", 2_000)),
            recent_messages: vec![
                ContextItem::new("before the bound", 500),
                ContextItem::new("after the bound", 2_500),
            ],
            ..SessionSnapshot::default()
        });
        let source = FilteredContext::new(Arc::new(facts));
        let gathered = source
            .gather(&ContextRequest {
                session_id: session_id(),
                grant: device_grant(1_000),
                selected: CanonicalSet::from_iter([]),
            })
            .await
            .expect("the gathering runs");

        assert!(
            gathered.session_description.is_none(),
            "a description produced before this device's history begins is not carried"
        );
        assert_eq!(
            gathered.working_directory.expect("the directory").text,
            "/work"
        );
        assert_eq!(
            gathered
                .recent_messages
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["after the bound"]
        );
        assert!(
            gathered.withheld.iter().any(|run| run.count > 0),
            "what was kept back is counted: {:?}",
            gathered.withheld
        );
    }

    /// KR-REQ-15.20: a closed session's retained summary keeps its own creation time, so a grant
    /// whose history begins after that session ended sees none of it.
    #[test]
    fn a_retained_summary_of_a_closed_session_stays_behind_a_later_history_bound() {
        let closed = SessionSummary {
            state: SessionState::Closed,
            application_state: Nullable::null(),
            closure: Nullable::some(ClosureRecord {
                session_id: session_id(),
                session_epoch: SessionEpoch::new(1),
                reason: ClosureReason::RootExit,
                root_exit_code: Nullable::some(U64::ZERO),
                root_signal: Nullable::null(),
                terminated: Vec::new(),
                surviving: Vec::new(),
                ownership_coverage: OwnershipCoverage::Complete,
                durability: Durability::Durable,
                closed_at_ms: kr_protocol::scalars::TimestampMs::new(2_000),
            }),
            ..summary(1_000)
        };
        let snapshot = snapshot_of(&closed, session_id());
        let bound = 1_500;
        assert!(
            snapshot.description.expect("a description").produced_at_ms < bound,
            "the summary is the one the session had, not one produced by reading it now"
        );
        assert!(
            snapshot
                .working_directory
                .expect("a directory")
                .produced_at_ms
                < bound
        );
    }
}
