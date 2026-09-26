//! The shared host-side history filter, through the projection a client is actually installed.
//!
//! Section 10 puts the whole of a grant's history authority in one place and then names nine
//! surfaces that share it. These tests take a real terminal engine, print content at known
//! moments, and ask the filter for each surface, because the property at stake is what a viewer
//! *receives* rather than what a predicate returns.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.49 | `one_filter_covers_every_surface_a_grant_reaches`, `a_summary_made_now_from_pre_cutoff_content_is_withheld_or_recomputed`, `derived_data_names_the_interval_and_resources_it_was_built_from` |
//! | KR-REQ-10.50 | `a_live_only_invitation_is_installed_the_visible_screen_only_when_the_issuer_selected_it`, `the_live_screen_exception_never_reaches_the_buffer_that_is_not_showing`, `attachment_bytes_need_their_own_file_grant`, `voice_context_intersects_the_requesting_device_scope` |
//! | KR-REQ-10.51 | `a_named_question_is_permitted_and_previewed_although_it_predates_the_cutoff`, `a_named_approval_is_excepted_only_while_it_is_current`, `a_pending_resource_snapshot_does_not_bypass_the_filter_without_that_scope` |

use kr_protocol::gateway::PendingState;
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{
    AuthorityRevision, DeviceId, GrantId, PendingResourceId, QuestionId, SessionId,
};
use kr_protocol::projection::{ProjectedBuffer, ProjectionEvent, ProjectionResetReason};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, U64, Uuid};
use kr_term::lane::LaneGate;
use kr_worker::history_filter::{
    DerivedDecision, HistoryFilter, Provenance, SourceInterval, Surface, ViewerScope,
    WithheldReason, live_screen_preview,
};
use kr_worker::projection::{TerminalEngine, Window};
use kr_worker::render::Scope;

/// The moment a grant's history begins. Everything printed before it is out of scope.
const CUTOFF_MS: u64 = 10_000;

fn question_id(byte: u8) -> QuestionId {
    QuestionId::new(Uuid::from_bytes([byte; 16]))
}

/// The resource the broker arbitrates for one approval, which is how a grant names it.
fn approval_resource(byte: u8) -> PendingResourceId {
    PendingResourceId::new(Uuid::from_bytes([byte; 16]))
}

fn dimensions(columns: u64, rows: u64) -> kr_protocol::session::Dimensions {
    kr_protocol::session::Dimensions {
        columns: U64::new(columns),
        rows: U64::new(rows),
    }
}

/// A grant with the history scope and actions a test needs.
fn grant(history: HistoryScope, actions: &[ActionRight]) -> Grant {
    Grant {
        grant_id: GrantId::new(Uuid::from_bytes([1; 16])),
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
        recipient_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::These {
            session_ids: [SessionId::new(Uuid::from_bytes([4; 16]))]
                .into_iter()
                .collect(),
        },
        actions: actions.iter().copied().collect(),
        history,
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    }
}

fn scope(
    lower_bound_ms: Option<u64>,
    include_live_screen: bool,
    named_questions: &[QuestionId],
    named_approvals: &[PendingResourceId],
) -> HistoryScope {
    HistoryScope {
        lower_bound_ms: Nullable(lower_bound_ms.map(TimestampMs::new)),
        include_live_screen,
        named_questions: named_questions.iter().copied().collect(),
        named_approvals: named_approvals.iter().copied().collect(),
    }
}

/// One retained item, with the moment it was produced.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    at_ms: u64,
    text: &'static str,
}

impl kr_worker::history_filter::Timed for Entry {
    fn produced_at_ms(&self) -> u64 {
        self.at_ms
    }
}

fn retained() -> Vec<Entry> {
    vec![
        Entry {
            at_ms: 1_000,
            text: "an api key printed before the invitation",
        },
        Entry {
            at_ms: 9_999,
            text: "the last line before the cutoff",
        },
        Entry {
            at_ms: CUTOFF_MS,
            text: "the first line the viewer may see",
        },
        Entry {
            at_ms: 20_000,
            text: "and everything after it",
        },
    ]
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.49: one filter, every surface, and derived content decided by its sources
// ---------------------------------------------------------------------------------------------

#[test]
fn one_filter_covers_every_surface_a_grant_reaches() {
    let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(CUTOFF_MS), false, &[], &[]),
        &[ActionRight::SessionView, ActionRight::FilesRead],
    )));

    for surface in Surface::ALL {
        let filtered = filter.filter(surface, retained());
        assert_eq!(
            filtered.kept.len(),
            2,
            "{surface} served the wrong amount: {:?}",
            filtered.kept
        );
        assert!(
            !filtered
                .kept
                .iter()
                .any(|entry| entry.text.contains("api key")),
            "{surface} served content from before the cutoff"
        );
        assert_eq!(
            filtered.withheld_entries(),
            2,
            "{surface} did not say what it kept back"
        );
        let withheld = filtered.withheld.first().expect("one reason");
        assert_eq!(withheld.reason, WithheldReason::BeforeHistoryBound);
        assert_eq!(withheld.earliest_ms, Some(1_000));
        assert_eq!(withheld.latest_ms, Some(9_999));
        assert_eq!(withheld.surface, surface, "evidence names the surface");
    }
}

#[test]
fn a_summary_made_now_from_pre_cutoff_content_is_withheld_or_recomputed() {
    let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(CUTOFF_MS), false, &[], &[]),
        &[ActionRight::SessionView],
    )));

    // A summary generated at this very moment, from a conversation that ended before the cutoff.
    // Its own timestamp is the newest thing on this host; it authorises nothing.
    let old = Provenance::over(SourceInterval::new(1_000, 9_000));
    assert_eq!(
        filter.admit_derived(Surface::Summary, &old),
        DerivedDecision::Omit {
            reason: WithheldReason::BeforeHistoryBound
        },
        "a later summary does not make old content newly authorised"
    );

    // One that straddles the cutoff is rebuilt from the part inside it, rather than served as it
    // stands: the text it holds was written from sources this viewer may not see.
    let straddling = Provenance::over(SourceInterval::new(5_000, 20_000));
    assert_eq!(
        filter.admit_derived(Surface::ChangedSinceLastVisit, &straddling),
        DerivedDecision::Recompute {
            interval: SourceInterval::new(CUTOFF_MS, 20_000)
        }
    );

    // And one wholly inside it is served.
    let inside = Provenance::over(SourceInterval::new(12_000, 20_000));
    assert!(matches!(
        filter.admit_derived(Surface::Summary, &inside),
        DerivedDecision::Serve { .. }
    ));
}

#[test]
fn derived_data_names_the_interval_and_resources_it_was_built_from() {
    let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(CUTOFF_MS), false, &[], &[]),
        &[ActionRight::SessionView],
    )));
    let provenance = Provenance {
        interval: SourceInterval::new(12_000, 20_000),
        resources: vec!["session:events".to_owned(), "attachment:9f2b".to_owned()],
    };
    let DerivedDecision::Serve { provenance: named } =
        filter.admit_derived(Surface::Export, &provenance)
    else {
        panic!("an export inside the scope is served");
    };
    assert_eq!(named.interval, provenance.interval);
    assert_eq!(
        named.resources, provenance.resources,
        "what is served names the resources it was built from"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.50: the live-screen exception, through the projection
// ---------------------------------------------------------------------------------------------

/// A terminal that printed something before the invitation, then switched to an application.
fn engine_with_two_buffers() -> TerminalEngine {
    let mut engine = TerminalEngine::new(dimensions(80, 24)).expect("a canonical grid");
    let mut stream = Vec::new();
    stream.extend_from_slice(b"AWS_SECRET_ACCESS_KEY=printed-before-the-invitation\r\n");
    stream.extend_from_slice(b"\x1b[?1049h");
    stream.extend_from_slice(b"the application's screen\r\n");
    engine.feed(0, &stream, LaneGate::default(), 0);
    engine
}

fn installed_buffers(engine: &mut TerminalEngine, scope: Scope) -> Vec<ProjectedBuffer> {
    let (update, _) = engine
        .projection_install(
            Window::live(dimensions(80, 24)),
            ProjectionResetReason::Attached,
            LaneGate::default(),
            0,
            kr_worker::output::DEFAULT_SEND_QUEUE_BYTES,
            scope,
        )
        .expect("a snapshot");
    let mut buffers: Vec<ProjectedBuffer> = update
        .events
        .iter()
        .filter_map(|outgoing| match &outgoing.event {
            ProjectionEvent::Rows(page) => Some(page.buffer),
            _ => None,
        })
        .collect();
    buffers.sort_unstable();
    buffers.dedup();
    buffers
}

#[test]
fn a_live_only_invitation_is_installed_the_visible_screen_only_when_the_issuer_selected_it() {
    // The exclusion case. No live screen in the grant, so the terminal-snapshot surface serves
    // nothing at all: there is no retained history and no exception to fall back on. Nothing is
    // installed for such a viewer, which is why there is no projection to inspect here: the
    // refusal happens before an installation is asked for.
    let without = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(None, false, &[], &[]),
        &[ActionRight::SessionView],
    )));
    assert_eq!(
        without.admit_at(Surface::TerminalSnapshot, 0),
        Err(WithheldReason::NoRetainedHistory),
        "an invitation that did not select the screen is served no screen"
    );
    assert!(
        without.preview_live_screen(["anything"]).is_none(),
        "and its issuer is shown no screen preview, because none is being shared"
    );

    // The inclusion case. The issuer selected it and was shown what is on it.
    let with = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(None, true, &[], &[]),
        &[ActionRight::SessionView],
    )));
    assert_eq!(with.admit_at(Surface::TerminalSnapshot, 0), Ok(()));
    let preview = with
        .preview_live_screen(["the application's screen", "$ "])
        .expect("the issuer is shown the screen");
    assert_eq!(
        preview.lines,
        vec!["the application's screen".to_owned(), "$ ".to_owned()],
        "the preview is the text, not a description of it"
    );

    // And the installation goes through the filtered projection, never the unrestricted state.
    let mut engine = engine_with_two_buffers();
    assert_eq!(
        installed_buffers(&mut engine, with.screen_scope()),
        vec![ProjectedBuffer::Alternate],
        "the visible screen, and nothing else"
    );
}

#[test]
fn the_live_screen_exception_never_reaches_the_buffer_that_is_not_showing() {
    let invited = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(None, true, &[], &[]),
        &[ActionRight::SessionView],
    )));
    let mut engine = engine_with_two_buffers();
    let buffers = installed_buffers(&mut engine, invited.screen_scope());
    assert!(
        !buffers.contains(&ProjectedBuffer::Primary),
        "what the shell left behind is not the visible screen: {buffers:?}"
    );

    // Not even a grant with retained history gets the other buffer through a projection: the
    // exception is the screen, and a grant is never drawn the unrestricted state.
    let deep = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(0), true, &[], &[]),
        &[ActionRight::SessionView],
    )));
    assert_eq!(deep.screen_scope(), Scope::LiveScreen);
    assert_eq!(
        installed_buffers(&mut engine, deep.screen_scope()),
        vec![ProjectedBuffer::Alternate]
    );

    // The host owner in front of the machine is a different matter: its authority is the operating
    // system account the session already runs as.
    assert_eq!(
        HistoryFilter::new(ViewerScope::owner()).screen_scope(),
        Scope::WholeScreen
    );
    let both = installed_buffers(&mut engine, Scope::WholeScreen);
    assert!(both.contains(&ProjectedBuffer::Primary));
    assert!(both.contains(&ProjectedBuffer::Alternate));

    // Scrollback and the backing transcript are the other surfaces, and the exception does not
    // reach them either.
    for surface in [
        Surface::EventPage,
        Surface::LoadedConversation,
        Surface::Export,
    ] {
        assert_eq!(
            invited.admit_at(surface, 0),
            Err(WithheldReason::OutsideTheVisibleScreen),
            "{surface} served a live-only invitation"
        );
    }
}

#[test]
fn attachment_bytes_need_their_own_file_grant() {
    let viewer = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(CUTOFF_MS), true, &[], &[]),
        &[ActionRight::SessionView],
    )));
    // The reference is inside the history scope, so the viewer may see that an attachment exists.
    assert_eq!(
        viewer.admit_at(Surface::AttachmentReference, 20_000),
        Ok(())
    );
    // The bytes are a separate question, and the answer is no.
    assert_eq!(
        viewer.admit_attachment_bytes(20_000),
        Err(WithheldReason::NoFileGrant)
    );

    let reviewer = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(CUTOFF_MS), true, &[], &[]),
        &[ActionRight::SessionView, ActionRight::FilesRead],
    )));
    assert_eq!(reviewer.admit_attachment_bytes(20_000), Ok(()));
    // And the file grant does not reach back past the history bound either: both hold at once.
    assert_eq!(
        reviewer.admit_attachment_bytes(1_000),
        Err(WithheldReason::BeforeHistoryBound)
    );
}

#[test]
fn voice_context_intersects_the_requesting_device_scope() {
    let device = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(CUTOFF_MS), false, &[], &[]),
        &[ActionRight::SessionView],
    )));
    let filtered = device.filter(Surface::VoiceContext, retained());
    assert_eq!(filtered.kept.len(), 2);
    assert!(
        !filtered
            .kept
            .iter()
            .any(|entry| entry.text.contains("api key")),
        "voice context is the device's scope, not the host owner's broader history"
    );

    // The host owner's own scope does reach it, which is what makes the narrowing meaningful
    // rather than an accident of the fixture.
    let owner = HistoryFilter::new(ViewerScope::owner());
    assert_eq!(
        owner.filter(Surface::VoiceContext, retained()).kept.len(),
        4
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-10.51: named current questions and approvals
// ---------------------------------------------------------------------------------------------

#[test]
fn a_named_question_is_permitted_and_previewed_although_it_predates_the_cutoff() {
    let named = question_id(7);
    let unnamed = question_id(8);
    let approval = approval_resource(0x71);
    let other_approval = approval_resource(0x72);

    let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(
            Some(CUTOFF_MS),
            false,
            &[named],
            std::slice::from_ref(&approval),
        ),
        &[ActionRight::SessionView],
    )));

    // Created long before the cutoff, and permitted because the invitation names it. The approval
    // is decided by the filter's rule for a name a grant carries, while it is still pending.
    assert_eq!(filter.admit_question(named, 1_000), Ok(()));
    assert_eq!(
        filter.admit_approval(approval, 1_000, PendingState::Pending),
        Ok(())
    );

    // The conversation those decisions came from is not thereby opened.
    assert_eq!(
        filter
            .filter(Surface::LoadedConversation, retained())
            .kept
            .len(),
        2,
        "naming a decision permits that decision, not its earlier conversation"
    );

    // And another question from the same period is not named, so it is not permitted.
    assert_eq!(
        filter.admit_question(unnamed, 1_000),
        Err(WithheldReason::NotNamedByTheGrant)
    );
    assert_eq!(
        filter.admit_approval(other_approval, 1_000, PendingState::Pending),
        Err(WithheldReason::NotNamedByTheGrant)
    );

    // The issuer previews what is being named. The preview is the text, bounded and marked when it
    // was cut, so an issuer is never shown less than the recipient will see without being told.
    let preview = live_screen_preview(["Approve: rm -rf /var/tmp/build", "y/N"]);
    assert_eq!(preview.lines.len(), 2);
    assert!(!preview.truncated);
}

/// Section 10 permits the exact current decisions an invitation names. A named approval is
/// excepted from the bound while it can still be decided, pending or claimed, and loses the
/// exception in every state that ends it; an approval nothing names meets the bound in every state.
/// A grant that keeps no retained history reaches a current named approval and nothing else, and a
/// grant without `session.view` reaches none, named or not.
#[test]
fn a_named_approval_is_excepted_only_while_it_is_current() {
    let named = approval_resource(0x73);
    let unnamed = approval_resource(0x74);
    let before = CUTOFF_MS - 5_000;
    let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(CUTOFF_MS), false, &[], std::slice::from_ref(&named)),
        &[ActionRight::SessionView],
    )));
    for state in PendingState::ALL.iter().copied() {
        let decided = filter.admit_approval(named, before, state);
        if state.is_terminal() {
            assert_eq!(
                decided,
                Err(WithheldReason::NotNamedByTheGrant),
                "an ended approval is an old record: {state:?}"
            );
        } else {
            assert_eq!(decided, Ok(()), "a current named approval: {state:?}");
        }
        assert_eq!(
            filter.admit_approval(unnamed, before, state),
            Err(WithheldReason::NotNamedByTheGrant),
            "nothing names it: {state:?}"
        );
        assert_eq!(
            filter.admit_approval(unnamed, CUTOFF_MS, state),
            Ok(()),
            "{state:?}"
        );
        assert_eq!(
            filter.admit_approval(named, CUTOFF_MS + 1, state),
            Ok(()),
            "{state:?}"
        );
    }

    let live_only = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(None, true, &[], std::slice::from_ref(&named)),
        &[ActionRight::SessionView],
    )));
    assert_eq!(
        live_only.admit_approval(named, before, PendingState::Claimed),
        Ok(())
    );
    assert_eq!(
        live_only.admit_approval(named, before, PendingState::Expired),
        Err(WithheldReason::NotNamedByTheGrant)
    );
    assert_eq!(
        live_only.admit_approval(unnamed, CUTOFF_MS + 1, PendingState::Pending),
        Err(WithheldReason::NotNamedByTheGrant)
    );

    let blind = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(0), true, &[], std::slice::from_ref(&named)),
        &[ActionRight::FilesRead],
    )));
    assert_eq!(
        blind.admit_approval(named, before, PendingState::Pending),
        Err(WithheldReason::NoSessionView)
    );
}

/// The scope a worker builds from what a forwarded read carries is the grant's history scope and
/// nothing more: it sees the session only when the caller says the grant does, and it never reads
/// file bytes, which need `files.read` of their own. A grant keeps its own `files.read`.
#[test]
fn a_scope_from_a_history_reads_no_file_bytes_and_sees_the_session_only_when_told() {
    let history = scope(Some(CUTOFF_MS), false, &[], &[]);
    let told = HistoryFilter::new(ViewerScope::from_history(&history, true));
    assert_eq!(told.admit_at(Surface::SemanticSnapshot, CUTOFF_MS), Ok(()));
    assert_eq!(
        told.admit_at(Surface::SemanticSnapshot, CUTOFF_MS - 1),
        Err(WithheldReason::BeforeHistoryBound)
    );
    assert_eq!(
        told.admit_attachment_bytes(CUTOFF_MS),
        Err(WithheldReason::NoFileGrant)
    );
    let untold = HistoryFilter::new(ViewerScope::from_history(&history, false));
    assert_eq!(
        untold.admit_at(Surface::SemanticSnapshot, CUTOFF_MS),
        Err(WithheldReason::NoSessionView)
    );
    assert!(
        ViewerScope::from_grant(&grant(
            history,
            &[ActionRight::SessionView, ActionRight::FilesRead]
        ))
        .reads_files()
    );
}

#[test]
fn a_pending_resource_snapshot_does_not_bypass_the_filter_without_that_scope() {
    let pending = question_id(7);
    let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(CUTOFF_MS), false, &[], &[]),
        &[ActionRight::SessionView],
    )));

    // A question that is still pending now, created before the cutoff. Being pending is not an
    // exception: without the named scope the ordinary bound applies.
    assert_eq!(
        filter.admit_question(pending, 1_000),
        Err(WithheldReason::NotNamedByTheGrant)
    );
    // One created after the cutoff is served on the ordinary rule, named or not.
    assert_eq!(filter.admit_question(pending, 20_000), Ok(()));

    // And a snapshot taken now of that pending resource carries the same answer, because the
    // decision reads when the content was produced rather than when the snapshot was taken.
    assert_eq!(
        filter.admit_at(Surface::SemanticSnapshot, 1_000),
        Err(WithheldReason::BeforeHistoryBound)
    );
    let taken_now = Provenance::over(SourceInterval::at(1_000));
    assert_eq!(
        filter.admit_derived(Surface::SemanticSnapshot, &taken_now),
        DerivedDecision::Omit {
            reason: WithheldReason::BeforeHistoryBound
        }
    );
}

/// A grant that carries no `session.view` reads nothing, whatever else it names.
#[test]
fn a_grant_without_session_view_reaches_no_surface() {
    let filter = HistoryFilter::new(ViewerScope::from_grant(&grant(
        scope(Some(0), true, &[question_id(7)], &[]),
        &[ActionRight::FilesRead],
    )));
    for surface in Surface::ALL {
        assert_eq!(
            filter.admit_at(surface, u64::MAX),
            Err(WithheldReason::NoSessionView),
            "{surface} served a grant with no session view"
        );
    }
    assert_eq!(
        filter.admit_question(question_id(7), 0),
        Err(WithheldReason::NoSessionView),
        "a named question is still session content"
    );
}

/// The named sets are exactly the grant's, and a scope is built from nothing else.
#[test]
fn a_scope_comes_from_the_grant_and_never_from_a_label() {
    let held = grant(
        scope(Some(CUTOFF_MS), true, &[question_id(7)], &[]),
        &[ActionRight::SessionView, ActionRight::FilesRead],
    );
    let from_grant = ViewerScope::from_grant(&held);
    assert_eq!(from_grant.lower_bound_ms(), Some(CUTOFF_MS));
    assert!(from_grant.includes_the_live_screen());
    assert!(from_grant.sees_the_session());
    assert!(from_grant.reads_files());
    assert!(!from_grant.is_unrestricted());

    // Narrowing the grant narrows the scope, because the scope is the grant.
    let narrowed = Grant {
        actions: CanonicalSet::from_iter([ActionRight::SessionView]),
        ..held
    };
    assert!(!ViewerScope::from_grant(&narrowed).reads_files());
}
