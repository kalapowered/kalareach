//! The environment feature store: one inbox across every session, what one caller may see of it,
//! acknowledgement by revision, timers that wait for their origin to be read, sessions whose live
//! conditions end with them, the workflow journal's alerts, content fingerprints, recovery of a
//! source that ran ahead, actions answered from their records, and a store that reopens exactly as
//! it was written.

use kr_attention::event::{ApplicationNotice, EventCursor, EventKind, Fingerprint, SourceEvent};
use kr_attention::host::{ActionKey, Answer, Mutation, Performed};
use kr_attention::{
    Attention, Claimant, Content, DeviceScope, HostReading, Liveness, Origin, Outcome, Viewer,
};
use kr_protocol::attention::{
    AttentionAutomationSubject, AttentionItem, AttentionItemRevision, AttentionKey,
    AttentionReadParams, AttentionRule, AttentionSource, DEDUPLICATION_WINDOW_MS, IDLE_REMINDER_MS,
    QuietHours, ReviewSubject,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, AgentTurnId, ApprovalRequestId, GrantId, PluginId, QuestionId, SessionId, WorkflowId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

const NOON: u64 = 12 * 60 * 60 * 1_000;

fn actor(name: &str) -> ActorId {
    ActorId::new(name).expect("an actor identifier")
}

fn session(byte: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([byte; 16]))
}

fn question(byte: u8) -> QuestionId {
    QuestionId::new(Uuid::from_bytes([byte; 16]))
}

fn grant(byte: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([byte; 16]))
}

fn boot() -> kr_attention::time::BootMark {
    kr_attention::time::BootMark::from_bytes([7; 16])
}

fn reading(continuous_ms: u64) -> HostReading {
    HostReading::new(boot(), continuous_ms, NOON + continuous_ms, true)
}

fn unknown(_: &ProcessStartIdentity) -> Liveness {
    Liveness::Unknown
}

fn opener() -> Claimant<'static> {
    Claimant::new(
        ProcessStartIdentity::new(1, ProcessStartSource::LinuxProcStat, 1_001),
        &unknown,
    )
}

fn engine() -> Attention {
    Attention::in_memory(reading(0), &opener()).expect("an in-memory feature store")
}

fn all_read(_: &Origin) -> Option<u64> {
    Some(u64::MAX)
}

fn fingerprint(text: &str) -> Fingerprint {
    use sha2::Digest as _;
    Fingerprint::from_bytes(sha2::Sha256::digest(text.as_bytes()).into())
}

fn in_session(
    session_id: SessionId,
    source: AttentionSource,
    sequence: u64,
    at_ms: u64,
    kind: EventKind,
) -> SourceEvent {
    SourceEvent::new(
        EventCursor::in_session(session_id, source, sequence),
        TimestampMs::new(NOON + at_ms),
        kind,
    )
}

fn pending(session_id: SessionId, sequence: u64, at_ms: u64, id: QuestionId) -> SourceEvent {
    in_session(
        session_id,
        AttentionSource::Questions,
        sequence,
        at_ms,
        EventKind::QuestionPending {
            question_id: id,
            session_id,
            verified: true,
            pending_since_ms: TimestampMs::new(NOON + at_ms),
            pending_since_anchor: Some(kr_attention::time::Anchor::new(boot(), at_ms)),
            summary: "which branch?".to_owned(),
        },
    )
}

fn answered(session_id: SessionId, sequence: u64, at_ms: u64, id: QuestionId) -> SourceEvent {
    in_session(
        session_id,
        AttentionSource::Questions,
        sequence,
        at_ms,
        EventKind::QuestionResolved {
            question_id: id,
            session_id,
            answered: true,
        },
    )
}

fn approval(session_id: SessionId, sequence: u64, request: &str) -> SourceEvent {
    in_session(
        session_id,
        AttentionSource::Receipts,
        sequence,
        1_000,
        EventKind::ApprovalRequested {
            request_id: ApprovalRequestId::new(request).expect("an identifier"),
            session_id,
            summary: "write /etc/hosts".to_owned(),
        },
    )
}

fn approval_resolved(session_id: SessionId, sequence: u64, request: &str) -> SourceEvent {
    in_session(
        session_id,
        AttentionSource::Receipts,
        sequence,
        2_000,
        EventKind::ApprovalResolved {
            request_id: ApprovalRequestId::new(request).expect("an identifier"),
            session_id,
        },
    )
}

fn notice(
    session_id: SessionId,
    sequence: u64,
    at_ms: u64,
    body: &str,
    fingerprint: Option<Fingerprint>,
) -> SourceEvent {
    in_session(
        session_id,
        AttentionSource::HostEvents,
        sequence,
        at_ms,
        EventKind::ApplicationNotice {
            session_id,
            notice: ApplicationNotice {
                id: None,
                title: None,
                body: body.to_owned(),
                lease_held: false,
                fingerprint,
            },
        },
    )
}

fn turn(session_id: SessionId, sequence: u64, name: &str) -> SourceEvent {
    in_session(
        session_id,
        AttentionSource::Semantic,
        sequence,
        3_000,
        EventKind::TurnCompleted {
            session_id,
            turn_id: AgentTurnId::new(name).expect("an identifier"),
            version: 1,
            change_set: None,
            summary: "rewrote the parser".to_owned(),
        },
    )
}

fn workflow(byte: u8, revision: u64) -> AttentionAutomationSubject {
    AttentionAutomationSubject::Workflow {
        workflow_id: WorkflowId::new(Uuid::from_bytes([byte; 16])),
        revision: U64::new(revision),
    }
}

fn paused(
    sequence: u64,
    subject: AttentionAutomationSubject,
    under: Option<GrantId>,
) -> SourceEvent {
    SourceEvent::new(
        EventCursor::new(AttentionSource::Automation, sequence),
        TimestampMs::new(NOON + 4_000),
        EventKind::AutomationPaused {
            subject,
            reason: "max_concurrent_runs".to_owned(),
            grant_id: under,
        },
    )
}

fn resumed(sequence: u64, subject: AttentionAutomationSubject) -> SourceEvent {
    SourceEvent::new(
        EventCursor::new(AttentionSource::Automation, sequence),
        TimestampMs::new(NOON + 5_000),
        EventKind::AutomationResumed { subject },
    )
}

fn owner_inbox(attention: &Attention) -> Vec<AttentionItem> {
    attention
        .inbox(&actor("local:501"), &Viewer::Owner, true)
        .expect("the store is this owner's")
}

fn page(session_id: Option<SessionId>) -> AttentionReadParams {
    AttentionReadParams {
        session_id: Nullable(session_id),
        include_acknowledged: true,
        max_items: U64::new(50),
        after: Nullable::null(),
    }
}

fn raised(outcomes: &[Outcome]) -> Vec<AttentionRule> {
    outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Raised { rule, .. } => Some(*rule),
            _ => None,
        })
        .collect()
}

fn feed(attention: &mut Attention, events: &[SourceEvent], at: u64) {
    for event in events {
        attention
            .apply(event, reading(at))
            .expect("the store records the decision");
    }
}

fn at_revision(attention: &Attention, key: &AttentionKey) -> AttentionItemRevision {
    AttentionItemRevision {
        key: key.clone(),
        revision: U64::new(
            attention
                .engine()
                .expect("the store is this owner's")
                .item(key)
                .expect("the item is held")
                .revision,
        ),
    }
}

// ----- One inbox across sessions -----------------------------------------------------------

/// KR-REQ-18.01: one attention inbox across every session of the environment, narrowed to one
/// session on request.
#[test]
fn one_inbox_holds_every_session_and_a_filter_narrows_it() {
    let mut attention = engine();
    feed(
        &mut attention,
        &[
            pending(session(1), 1, 0, question(1)),
            pending(session(2), 1, 0, question(2)),
        ],
        0,
    );
    let items = owner_inbox(&attention);
    assert_eq!(
        items.len(),
        2,
        "both sessions' requests are in the one inbox"
    );
    let sessions: Vec<_> = items.iter().map(|item| item.session_id.0).collect();
    assert!(sessions.contains(&Some(session(1))) && sessions.contains(&Some(session(2))));

    let narrowed = attention
        .read(
            &actor("local:501"),
            &Viewer::Owner,
            &page(Some(session(2))),
            reading(0),
            Content::Whole,
        )
        .expect("the page is served");
    assert_eq!(narrowed.result.items.len(), 1);
    assert_eq!(
        narrowed.result.items[0].session_id,
        Nullable::some(session(2))
    );
}

/// An upstream request identifier is the connector's own, so two sessions can use the same one.
#[test]
fn one_upstream_approval_identifier_in_two_sessions_is_two_items() {
    let mut attention = engine();
    feed(
        &mut attention,
        &[
            approval(session(1), 1, "req-1"),
            approval(session(2), 1, "req-1"),
        ],
        0,
    );
    assert_eq!(owner_inbox(&attention).len(), 2, "two requests, two items");
    feed(
        &mut attention,
        &[approval_resolved(session(1), 2, "req-1")],
        1_000,
    );
    let left = owner_inbox(&attention);
    assert_eq!(
        left.len(),
        1,
        "resolving one session's request leaves the other's"
    );
    assert_eq!(left[0].session_id, Nullable::some(session(2)));
}

/// KR-REQ-24.11: a gap is recorded against the origin that lost the range, and only that origin's
/// unresolved items become uncertain.
#[test]
fn a_gap_is_uncertain_only_in_the_origin_that_lost_it() {
    let mut attention = engine();
    feed(
        &mut attention,
        &[
            pending(session(1), 1, 0, question(1)),
            pending(session(2), 1, 0, question(2)),
            // Session one's ledger jumps from one to five: three records went.
            pending(session(1), 5, 0, question(3)),
        ],
        0,
    );
    let gaps = attention.gaps().expect("the store is this owner's");
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].session_id, Nullable::some(session(1)));
    assert_eq!(gaps[0].from_sequence, U64::new(2));
    assert_eq!(gaps[0].to_sequence, Nullable::some(U64::new(5)));
    for item in owner_inbox(&attention) {
        if item.session_id.0 == Some(session(2)) {
            assert!(!item.uncertain, "another session's items are not touched");
        }
    }
    assert!(
        owner_inbox(&attention)
            .iter()
            .any(|item| item.session_id.0 == Some(session(1)) && item.uncertain),
        "the item the missing range could have resolved says the host cannot tell"
    );
}

// ----- What one caller may see ---------------------------------------------------------------

/// KR-REQ-23.45: a paired device sees what its grant admits: its sessions with `session.view`,
/// the automation items of workflows acting under its own grant with `automation.manage`, and the
/// environment's own items only with `host.manage`. A continuation or a gap outside that scope is
/// answered as if it did not exist.
#[test]
fn a_device_sees_what_its_grant_admits_and_nothing_else() {
    let mut attention = engine();
    feed(
        &mut attention,
        &[
            pending(session(1), 1, 0, question(1)),
            pending(session(2), 1, 0, question(2)),
            // Session two loses a range, which is something about session two.
            pending(session(2), 4, 0, question(3)),
            // A record of session two's that names session one is still session two's record, and
            // its text is read from session two.
            in_session(
                session(2),
                AttentionSource::HostEvents,
                1,
                0,
                EventKind::AdapterFailed {
                    plugin_id: PluginId::new("git").expect("an identifier"),
                    session_id: Some(session(1)),
                    detail: "the index is locked".to_owned(),
                },
            ),
            paused(3, workflow(1, 1), Some(grant(1))),
            paused(8, workflow(2, 1), Some(grant(2))),
            paused(9, workflow(3, 1), None),
            SourceEvent::new(
                EventCursor::new(AttentionSource::Receipts, 1),
                TimestampMs::new(NOON),
                EventKind::HostContactLost {
                    detail: "the relay closed".to_owned(),
                },
            ),
        ],
        0,
    );
    assert_eq!(
        owner_inbox(&attention).len(),
        8,
        "the owner sees everything"
    );

    let admits_one = |candidate: SessionId| candidate == session(1);
    let device = Viewer::Device(DeviceScope {
        grant_id: grant(1),
        session_view: true,
        automation_manage: true,
        host_manage: false,
        admits_session: &admits_one,
    });
    let seen = attention
        .read(
            &actor("device:phone"),
            &device,
            &page(None),
            reading(0),
            Content::Narrowed,
        )
        .expect("the page is served");
    assert_eq!(
        seen.result.items.len(),
        2,
        "its session's item and its own workflow's"
    );
    assert!(
        seen.result
            .items
            .iter()
            .any(|item| item.session_id.0 == Some(session(1)))
    );
    assert!(
        seen.result
            .items
            .iter()
            .any(|item| item.automation.0 == Some(workflow(1, 1)))
    );
    assert!(
        seen.result.gaps.is_empty(),
        "a gap in a session it may not see is not shown"
    );

    // A key it may not see is not one a page can continue after, and says nothing more.
    let hidden = owner_inbox(&attention)
        .into_iter()
        .find(|item| item.session_id.0 == Some(session(2)))
        .expect("session two's item");
    let continued = attention.read(
        &actor("device:phone"),
        &device,
        &AttentionReadParams {
            after: Nullable::some(hidden.key.clone()),
            ..page(None)
        },
        reading(0),
        Content::Narrowed,
    );
    assert!(matches!(
        continued,
        Err(kr_attention::Error::UnknownContinuation { .. })
    ));

    // Without the rights, nothing of either kind.
    let viewer_only = Viewer::Device(DeviceScope {
        grant_id: grant(1),
        session_view: false,
        automation_manage: false,
        host_manage: true,
        admits_session: &admits_one,
    });
    let host_only = attention
        .inbox(&actor("device:phone"), &viewer_only, true)
        .expect("the store is this owner's");
    assert_eq!(host_only.len(), 1, "only the environment's own item");
    assert_eq!(host_only[0].rule, AttentionRule::HostContactLost);

    // A device that may see both sessions sees what session two raised about session one.
    let admits_both = |candidate: SessionId| candidate == session(1) || candidate == session(2);
    let both = Viewer::Device(DeviceScope {
        grant_id: grant(1),
        session_view: true,
        automation_manage: false,
        host_manage: false,
        admits_session: &admits_both,
    });
    let across = attention
        .inbox(&actor("device:phone"), &both, true)
        .expect("the store is this owner's");
    assert!(
        across
            .iter()
            .any(|item| item.rule == AttentionRule::AdapterFailed
                && item.session_id.0 == Some(session(1)))
    );

    // The workflow journal's own words are the host's, and a caller that is served no session text
    // is still served them.
    let automation = seen
        .result
        .items
        .iter()
        .find(|item| item.rule == AttentionRule::AutomationPaused)
        .expect("its workflow's item");
    assert!(automation.summary.is_present());
    assert!(
        seen.texts.is_empty(),
        "no session text is pointed at for a narrowed caller"
    );
}

/// KR-REQ-23.45: the same scope bounds review state and acknowledgement. A device is shown the review
/// work of the sessions it may see, cannot continue a page after a subject outside them, is told a
/// subject outside them does not exist, and acknowledging an item outside them records nothing and
/// says nothing about it, whatever revision it names.
#[test]
fn review_state_and_acknowledgement_keep_to_the_same_scope() {
    let mut attention = engine();
    feed(
        &mut attention,
        &[turn(session(1), 1, "turn-1"), turn(session(2), 1, "turn-2")],
        0,
    );
    let admits_one = |candidate: SessionId| candidate == session(1);
    let device = Viewer::Device(DeviceScope {
        grant_id: grant(1),
        session_view: true,
        automation_manage: false,
        host_manage: false,
        admits_session: &admits_one,
    });
    let phone = actor("device:phone");

    let (states, more) = attention
        .review_states(&phone, &device, None, None, 50)
        .expect("the page is served");
    assert!(!more);
    assert_eq!(states.len(), 1, "only its own session's review work");
    assert_eq!(
        kr_attention::review::subject_session(&states[0].subject),
        session(1)
    );

    let hidden = ReviewSubject::CompletedTurn {
        session_id: session(2),
        turn_id: AgentTurnId::new("turn-2").expect("an identifier"),
    };
    assert!(
        attention
            .review_state(&phone, &Viewer::Owner, &hidden)
            .expect("the store is this owner's")
            .is_some(),
        "the owner sees it"
    );
    assert_eq!(
        attention
            .review_state(&phone, &device, &hidden)
            .expect("the store is this owner's"),
        None,
        "the device is answered as if it did not exist"
    );
    assert!(matches!(
        attention.review_states(&phone, &device, None, Some(&hidden), 50),
        Err(kr_attention::Error::UnknownContinuation { .. })
    ));
    assert!(matches!(
        attention.acknowledge_review(&phone, &device, &hidden, 1, reading(0)),
        Err(kr_attention::Error::UnknownReviewSubject { .. })
    ));

    let item = owner_inbox(&attention)
        .into_iter()
        .find(|item| item.session_id.0 == Some(session(2)))
        .expect("session two's review item");
    for revision in [item.revision.get(), item.revision.get() + 10] {
        let answer = attention
            .acknowledge(
                &phone,
                &device,
                &[AttentionItemRevision {
                    key: item.key.clone(),
                    revision: U64::new(revision),
                }],
                reading(0),
            )
            .expect("the store records the request");
        assert!(answer.acknowledged.is_empty());
        assert_eq!(answer.stale, vec![item.key.clone()]);
        assert_eq!(answer.revision.get(), 0, "and nothing was recorded");
    }
}

// ----- Acknowledgement by revision ---------------------------------------------------------

/// KR-REQ-23.45: an acknowledgement covers the revision it names and no later one, records nothing
/// for a stale revision, refuses a revision the host never handed out, and affects only the actor
/// that made it.
#[test]
fn an_acknowledgement_covers_the_revision_it_names_and_no_later_one() {
    let mut attention = engine();
    let first = notice(
        session(1),
        1,
        0,
        "build finished",
        Some(fingerprint("build finished")),
    );
    feed(&mut attention, &[first], 0);
    let key = owner_inbox(&attention)[0].key.clone();
    let seen = at_revision(&attention, &key);

    let phone = actor("device:phone");
    let done = attention
        .acknowledge(
            &phone,
            &Viewer::Owner,
            std::slice::from_ref(&seen),
            reading(1_000),
        )
        .expect("the store records the acknowledgement");
    assert_eq!(done.acknowledged, vec![key.clone()]);
    assert!(done.stale.is_empty());
    let revision_after_first = done.revision;

    // The same condition again, past its window: a new occurrence nobody has seen.
    let again = notice(
        session(1),
        2,
        0,
        "build finished",
        Some(fingerprint("build finished")),
    );
    feed(&mut attention, &[again], DEDUPLICATION_WINDOW_MS + 5_000);
    let outstanding = attention
        .inbox(&phone, &Viewer::Owner, false)
        .expect("the store is this owner's");
    assert_eq!(
        outstanding.len(),
        1,
        "a later occurrence is outstanding again"
    );
    assert!(outstanding[0].revision.get() > seen.revision.get());

    // Naming the old revision records nothing and says so.
    let stale = attention
        .acknowledge(&phone, &Viewer::Owner, &[seen], reading(70_000))
        .expect("a stale acknowledgement is answered");
    assert!(stale.acknowledged.is_empty());
    assert_eq!(stale.stale, vec![key.clone()]);
    assert_eq!(
        attention
            .inbox(&phone, &Viewer::Owner, false)
            .expect("the store is this owner's")
            .len(),
        1,
        "still outstanding"
    );

    // A revision past the item's own is one the host never handed out: the whole request is
    // refused and nothing about it is written.
    let current = at_revision(&attention, &key);
    let ahead = AttentionItemRevision {
        key: key.clone(),
        revision: U64::new(current.revision.get() + 100),
    };
    let before = attention
        .revision(&phone)
        .expect("the store is this owner's");
    assert!(matches!(
        attention.acknowledge(
            &phone,
            &Viewer::Owner,
            &[current.clone(), ahead],
            reading(71_000)
        ),
        Err(kr_attention::Error::RevisionAhead { .. })
    ));
    assert_eq!(
        attention
            .revision(&phone)
            .expect("the store is this owner's"),
        before,
        "nothing was recorded"
    );
    assert_eq!(
        before,
        revision_after_first.get(),
        "the stale request moved nothing either"
    );

    // Another actor's view is its own.
    assert_eq!(
        attention
            .inbox(&actor("local:501"), &Viewer::Owner, false)
            .expect("the store is this owner's")
            .len(),
        1
    );
}

/// A condition that ends and comes back is new work, even for an actor that acknowledged the first.
#[test]
fn a_condition_that_ends_and_returns_is_outstanding_again() {
    let mut attention = engine();
    feed(&mut attention, &[approval(session(1), 1, "req-1")], 0);
    let key = owner_inbox(&attention)[0].key.clone();
    let seen = at_revision(&attention, &key);
    attention
        .acknowledge(
            &actor("device:phone"),
            &Viewer::Owner,
            std::slice::from_ref(&seen),
            reading(0),
        )
        .expect("the store records the acknowledgement");
    feed(
        &mut attention,
        &[
            approval_resolved(session(1), 2, "req-1"),
            approval(session(1), 3, "req-1"),
        ],
        1_000,
    );
    let back = attention
        .inbox(&actor("device:phone"), &Viewer::Owner, false)
        .expect("the store is this owner's");
    assert_eq!(back.len(), 1, "the returned condition is outstanding");
    assert_eq!(back[0].key, key, "under the same key");
    assert!(
        back[0].revision.get() > seen.revision.get(),
        "at a later revision"
    );
}

// ----- Timers wait for their origin ----------------------------------------------------------

/// KR-REQ-25.03: a reminder is decided only against an origin the host has read up to the moment
/// it fell due.
#[test]
fn a_reminder_waits_for_its_origin_to_be_read_to_the_end() {
    let mut attention = engine();
    feed(&mut attention, &[pending(session(1), 1, 0, question(1))], 0);
    let due = IDLE_REMINDER_MS + 1;

    let nothing_read = |_: &Origin| None;
    let outcomes = attention
        .tick(reading(due), &nothing_read)
        .expect("the store records the decision");
    assert!(raised(&outcomes).is_empty(), "no certificate, no reminder");

    let read_before_due = |_: &Origin| Some(IDLE_REMINDER_MS - 1);
    let outcomes = attention
        .tick(reading(due), &read_before_due)
        .expect("the store records the decision");
    assert!(
        raised(&outcomes).is_empty(),
        "a page read before the reminder fell due cannot decide it"
    );

    let read_after_due = |_: &Origin| Some(due);
    let outcomes = attention
        .tick(reading(due), &read_after_due)
        .expect("the store records the decision");
    assert_eq!(raised(&outcomes), vec![AttentionRule::InputIdleReminder]);
}

/// KR-REQ-25.03: an answer on a page the host has not read yet never becomes a reminder.
#[test]
fn an_answer_on_a_page_not_yet_read_never_becomes_a_reminder() {
    let mut attention = engine();
    attention
        .rebuild(&[pending(session(1), 1, 0, question(1))], reading(0))
        .expect("the store records the page");
    // The first page stopped short: the host cannot say it has read everything.
    let nothing_read = |_: &Origin| None;
    let outcomes = attention
        .tick(reading(IDLE_REMINDER_MS * 2), &nothing_read)
        .expect("the store records the decision");
    assert!(raised(&outcomes).is_empty());
    // The next page carries the answer, and then the origin is read to the end.
    attention
        .rebuild(
            &[answered(session(1), 2, 1_000, question(1))],
            reading(IDLE_REMINDER_MS * 2),
        )
        .expect("the store records the page");
    let outcomes = attention
        .tick(reading(IDLE_REMINDER_MS * 2), &all_read)
        .expect("the store records the decision");
    assert!(
        raised(&outcomes).is_empty(),
        "the request was answered, so nothing is owed"
    );
    assert!(owner_inbox(&attention).is_empty());
}

/// KR-REQ-25.03: a page the host reads late is decided at the moment it certifies. A request read
/// long after it began is not reminded about while its answer may be on the next page, and a store
/// reopened in between decides the same.
#[test]
fn a_late_page_decides_its_reminder_at_the_moment_it_certifies() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let mut attention =
        Attention::open(&path, reading(0), &opener()).expect("the feature store opens");
    // A request pending since 0, on a page the host reads at 400 seconds.
    attention
        .rebuild(&[pending(session(1), 1, 0, question(1))], reading(400_000))
        .expect("the store records the page");
    let before_due = |_: &Origin| Some(IDLE_REMINDER_MS - 1);
    let outcomes = attention
        .tick(reading(400_000), &before_due)
        .expect("the store records the decision");
    assert!(
        raised(&outcomes).is_empty(),
        "at the moment the page certifies, the request had waited less than the interval"
    );

    drop(attention);
    let mut attention =
        Attention::open(&path, reading(400_000), &opener()).expect("the feature store opens");
    let outcomes = attention
        .tick(reading(400_000), &before_due)
        .expect("the store records the decision");
    assert!(raised(&outcomes).is_empty(), "and the same after a reopen");

    // The next page carries the answer, and nothing is owed.
    attention
        .rebuild(
            &[answered(session(1), 2, 350_000, question(1))],
            reading(400_000),
        )
        .expect("the store records the page");
    let outcomes = attention
        .tick(reading(400_000), &all_read)
        .expect("the store records the decision");
    assert!(raised(&outcomes).is_empty());
    assert!(
        owner_inbox(&attention)
            .iter()
            .all(|item| item.rule != AttentionRule::InputIdleReminder)
    );
}

/// KR-REQ-25.03: a request's record decides whose reading its reminder waits for and whose text
/// the reminder carries; the session it names stays the one it is about, and a device needs both.
#[test]
fn a_reminder_belongs_to_the_session_whose_record_raised_it() {
    let mut attention = engine();
    // Session one's record of a request that names session two.
    feed(
        &mut attention,
        &[in_session(
            session(1),
            AttentionSource::Questions,
            1,
            0,
            EventKind::QuestionPending {
                question_id: question(1),
                session_id: session(2),
                verified: true,
                pending_since_ms: TimestampMs::new(NOON),
                pending_since_anchor: Some(kr_attention::time::Anchor::new(boot(), 0)),
                summary: "which branch?".to_owned(),
            },
        )],
        0,
    );
    assert_eq!(
        attention
            .next_deadline_of(&Origin::Session(session(2)), reading(0))
            .expect("the store is this owner's"),
        None,
        "nothing of session two's is waiting on time"
    );
    let due = IDLE_REMINDER_MS + 1;
    let only_two = |origin: &Origin| (*origin == Origin::Session(session(2))).then_some(u64::MAX);
    let outcomes = attention
        .tick(reading(due), &only_two)
        .expect("the store records the decision");
    assert!(
        raised(&outcomes).is_empty(),
        "the named session's reading decides nothing"
    );
    let only_one = |origin: &Origin| (*origin == Origin::Session(session(1))).then_some(u64::MAX);
    let outcomes = attention
        .tick(reading(due), &only_one)
        .expect("the store records the decision");
    assert_eq!(raised(&outcomes), vec![AttentionRule::InputIdleReminder]);
    let reminder = attention
        .engine()
        .expect("the store is this owner's")
        .items()
        .find(|item| item.rule == AttentionRule::InputIdleReminder)
        .cloned()
        .expect("the reminder");
    assert_eq!(reminder.origin, Origin::Session(session(1)));
    assert_eq!(reminder.session_id, Some(session(2)));
    assert_eq!(
        reminder.text.record().map(|record| record.origin),
        Some(Origin::Session(session(1)))
    );
    let admits_two = |candidate: SessionId| candidate == session(2);
    let device = Viewer::Device(DeviceScope {
        grant_id: grant(1),
        session_view: true,
        automation_manage: false,
        host_manage: false,
        admits_session: &admits_two,
    });
    assert!(
        attention
            .inbox(&actor("device:phone"), &device, true)
            .expect("the store is this owner's")
            .is_empty(),
        "a device that sees only the named session sees neither the request nor its reminder"
    );
}

/// Two origins read to different points: each is decided against its own.
#[test]
fn unequal_backlogs_decide_only_the_origin_that_is_read() {
    let mut attention = engine();
    feed(
        &mut attention,
        &[
            pending(session(1), 1, 0, question(1)),
            pending(session(2), 1, 0, question(2)),
        ],
        0,
    );
    let only_one = |origin: &Origin| (*origin == Origin::Session(session(1))).then_some(u64::MAX);
    let outcomes = attention
        .tick(reading(IDLE_REMINDER_MS + 1), &only_one)
        .expect("the store records the decision");
    assert_eq!(raised(&outcomes), vec![AttentionRule::InputIdleReminder]);
    let reminders: Vec<_> = owner_inbox(&attention)
        .into_iter()
        .filter(|item| item.rule == AttentionRule::InputIdleReminder)
        .collect();
    assert_eq!(reminders.len(), 1);
    assert_eq!(reminders[0].session_id, Nullable::some(session(1)));
}

// ----- Sessions that end ---------------------------------------------------------------------

/// KR-REQ-24.11: a closing session decides no timer and hands off no announcement; its end takes
/// its live conditions out of the inbox as ended rather than answered, keeps its review work and
/// its gaps, takes nothing more from it, and changes nothing when repeated.
#[test]
fn a_session_that_ends_ends_its_live_conditions_and_keeps_its_review_work() {
    let mut attention = engine();
    feed(
        &mut attention,
        &[
            pending(session(1), 1, 0, question(1)),
            approval(session(1), 1, "req-1"),
            turn(session(1), 1, "turn-1"),
            // A gap in session one's ledger.
            pending(session(1), 4, 0, question(2)),
            pending(session(2), 1, 0, question(3)),
        ],
        0,
    );
    // While session one is closing, nothing of it is handed off and none of its timers decided.
    let closing = |origin: &Origin| (*origin != Origin::Session(session(1))).then_some(u64::MAX);
    let offered = attention
        .take_announcements(&|item| item.session_id != Some(session(1)))
        .expect("the store is this owner's");
    assert!(offered.iter().all(|one| one.session_id != Some(session(1))));
    attention
        .tick(reading(IDLE_REMINDER_MS + 1), &closing)
        .expect("the store records the decision");
    assert!(
        owner_inbox(&attention).iter().all(|item| {
            item.rule != AttentionRule::InputIdleReminder || item.session_id.0 != Some(session(1))
        }),
        "no reminder for the closing session"
    );

    let outcomes = attention
        .finalise(session(1), reading(IDLE_REMINDER_MS + 2))
        .expect("the store records the end");
    let ended = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Outcome::Ended { .. }))
        .count();
    assert_eq!(
        ended, 3,
        "two requests and the approval end with the session"
    );
    assert!(
        outcomes
            .iter()
            .all(|outcome| matches!(outcome, Outcome::Ended { .. })),
        "and none of them is answered or resolved"
    );
    let left = owner_inbox(&attention);
    assert!(
        left.iter()
            .any(|item| item.rule == AttentionRule::ReviewReady
                && item.session_id.0 == Some(session(1))),
        "completed work awaiting review outlives the session"
    );
    assert!(
        left.iter()
            .any(|item| item.session_id.0 == Some(session(2))),
        "another session is not touched"
    );
    assert!(
        attention
            .gaps()
            .expect("the store is this owner's")
            .iter()
            .any(|gap| gap.session_id.0 == Some(session(1))),
        "the gap stays"
    );

    // Nothing more is taken from a session that has ended, and ending it again changes nothing.
    let late = attention
        .apply(
            &pending(session(1), 5, 0, question(4)),
            reading(IDLE_REMINDER_MS + 3),
        )
        .expect("the store records the decision");
    assert!(late.is_empty());
    assert_eq!(
        attention
            .engine()
            .expect("the store is this owner's")
            .consumed(Origin::Session(session(1)), AttentionSource::Questions),
        Some(4)
    );
    let again = attention
        .finalise(session(1), reading(IDLE_REMINDER_MS + 4))
        .expect("the store records the end");
    assert!(again.is_empty());
}

/// A session that has ended is read to the end for good: what it left is decided without waiting.
#[test]
fn a_session_that_has_ended_is_read_to_the_end_for_good() {
    let mut attention = engine();
    attention
        .rebuild(&[turn(session(1), 1, "turn-1")], reading(0))
        .expect("the store records the page");
    attention
        .finalise(session(1), reading(0))
        .expect("the store records the end");
    let nothing_read = |_: &Origin| None;
    let outcomes = attention
        .tick(reading(1_000), &nothing_read)
        .expect("the store records the decision");
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Notified { .. })),
        "the review work it left is announced"
    );
}

// ----- The workflow journal's alerts ---------------------------------------------------------

/// The attention item half of KR-REQ-25.16 and KR-REQ-17.57: a workflow or a chain paused by its
/// own limits raises one item, a resume ends it, and the journal's numbering, which holds other
/// events between the alerts, is not a gap.
#[test]
fn the_workflow_journal_s_numbering_has_holes_that_are_not_gaps() {
    let mut attention = engine();
    let chain = AttentionAutomationSubject::CausalChain {
        causal_root_id: kr_protocol::ids::CausalRootId::new(Uuid::from_bytes([6; 16])),
    };
    let outcomes = attention
        .apply(&paused(3, workflow(1, 2), Some(grant(1))), reading(0))
        .expect("the store records the decision");
    assert_eq!(raised(&outcomes), vec![AttentionRule::AutomationPaused]);
    let outcomes = attention
        .apply(&paused(9, chain.clone(), Some(grant(1))), reading(1_000))
        .expect("the store records the decision");
    assert_eq!(raised(&outcomes), vec![AttentionRule::AutomationPaused]);
    assert!(
        attention
            .gaps()
            .expect("the store is this owner's")
            .is_empty(),
        "six other events between two alerts are not a range retention took"
    );
    let items = owner_inbox(&attention);
    assert_eq!(items.len(), 2);
    for item in &items {
        assert!(item.trusted);
        assert!(item.session_id.0.is_none());
        assert!(
            item.summary.is_present(),
            "the journal's own words are kept"
        );
    }
    // A repeat of the same pause is the same item.
    attention
        .apply(&paused(11, workflow(1, 2), Some(grant(1))), reading(2_000))
        .expect("the store records the decision");
    assert_eq!(owner_inbox(&attention).len(), 2);
    // The revision enabled again ends its item; the chain's stays.
    let outcomes = attention
        .apply(&resumed(15, workflow(1, 2)), reading(3_000))
        .expect("the store records the decision");
    assert!(matches!(outcomes.as_slice(), [Outcome::Resolved { .. }]));
    let left = owner_inbox(&attention);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].automation, Nullable::some(chain));
}

/// KR-REQ-24.11: a source whose record of this store's position ran ahead of the store is recovered
/// in one write: what it still holds is replayed, the rest is a gap, and a failed write is repeated
/// rather than half done.
#[test]
fn a_recovery_replays_what_is_left_and_marks_the_rest_as_a_gap_in_one_write() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let mut attention =
        Attention::open(&path, reading(0), &opener()).expect("the feature store opens");
    attention
        .apply(&paused(3, workflow(1, 1), Some(grant(1))), reading(0))
        .expect("the store records the decision");

    // Another holder keeps the file's write lock, so the recovery's write is refused.
    let blocker = rusqlite::Connection::open(&path).expect("a second connection");
    blocker
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("the write lock");
    let refused = attention.recover_source(
        Origin::Environment,
        AttentionSource::Automation,
        &[paused(9, workflow(2, 1), Some(grant(1)))],
        12,
        reading(1_000),
    );
    assert!(refused.is_err(), "the write is refused");
    assert!(
        attention
            .gaps()
            .expect("the store is this owner's")
            .is_empty(),
        "and nothing of the recovery is kept"
    );
    assert_eq!(
        attention
            .engine()
            .expect("the store is this owner's")
            .consumed(Origin::Environment, AttentionSource::Automation),
        Some(3)
    );
    blocker.execute_batch("ROLLBACK;").expect("the lock goes");
    drop(blocker);

    // The host stops before it tries again, and the store it opens is where it was.
    drop(attention);
    let mut attention =
        Attention::open(&path, reading(1_500), &opener()).expect("the feature store opens");
    assert!(
        attention
            .gaps()
            .expect("the store is this owner's")
            .is_empty()
    );
    assert_eq!(
        attention
            .engine()
            .expect("the store is this owner's")
            .consumed(Origin::Environment, AttentionSource::Automation),
        Some(3)
    );

    let outcomes = attention
        .recover_source(
            Origin::Environment,
            AttentionSource::Automation,
            &[paused(9, workflow(2, 1), Some(grant(1)))],
            12,
            reading(2_000),
        )
        .expect("the recovery is written");
    assert!(raised(&outcomes).contains(&AttentionRule::AutomationPaused));
    let gaps = attention.gaps().expect("the store is this owner's");
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].from_sequence, U64::new(4));
    assert_eq!(gaps[0].to_sequence, Nullable::some(U64::new(13)));
    assert!(gaps[0].session_id.0.is_none());
    assert!(
        owner_inbox(&attention).iter().all(|item| item.uncertain),
        "every unresolved automation item is uncertain, the replayed one included"
    );
    assert_eq!(
        attention
            .engine()
            .expect("the store is this owner's")
            .consumed(Origin::Environment, AttentionSource::Automation),
        Some(12)
    );
}

// ----- Content fingerprints ------------------------------------------------------------------

/// KR-REQ-25.03: a notice is one condition whether or not its text came with it, so identical
/// notices fold inside the window under privacy mode too; a notice with neither an identifier nor a
/// fingerprint is its own record.
#[test]
fn a_notice_is_one_condition_whether_or_not_its_text_came_with_it() {
    let mut attention = engine();
    let print = fingerprint("deployment finished");
    feed(
        &mut attention,
        &[
            notice(session(1), 1, 0, "deployment finished", Some(print)),
            // The same notice with its text withheld.
            notice(session(1), 2, 1_000, "", Some(print)),
        ],
        0,
    );
    let items = owner_inbox(&attention);
    assert_eq!(items.len(), 1, "one condition");
    assert_eq!(items[0].occurrences, U64::new(2));

    feed(
        &mut attention,
        &[
            notice(session(1), 3, 2_000, "", None),
            notice(session(1), 4, 3_000, "", None),
        ],
        2_000,
    );
    assert_eq!(
        owner_inbox(&attention).len(),
        3,
        "two notices with nothing to know them by are two records"
    );
}

/// An adapter that fails for two sessions is a failure in each: each is shown to whoever sees its
/// session, and each ends with its own session's recovery.
#[test]
fn an_adapter_failing_for_two_sessions_is_two_failures() {
    let mut attention = engine();
    let git = || PluginId::new("git").expect("an identifier");
    let failed = |session_id: SessionId| {
        in_session(
            session_id,
            AttentionSource::HostEvents,
            1,
            0,
            EventKind::AdapterFailed {
                plugin_id: git(),
                session_id: Some(session_id),
                detail: "the index is locked".to_owned(),
            },
        )
    };
    feed(&mut attention, &[failed(session(1)), failed(session(2))], 0);
    let failures = |attention: &Attention| -> Vec<AttentionItem> {
        owner_inbox(attention)
            .into_iter()
            .filter(|item| item.rule == AttentionRule::AdapterFailed)
            .collect()
    };
    assert_eq!(failures(&attention).len(), 2);

    let admits_one = |candidate: SessionId| candidate == session(1);
    let device = Viewer::Device(DeviceScope {
        grant_id: grant(1),
        session_view: true,
        automation_manage: false,
        host_manage: false,
        admits_session: &admits_one,
    });
    let seen = attention
        .inbox(&actor("device:phone"), &device, true)
        .expect("the store is this owner's");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].session_id.0, Some(session(1)));

    feed(
        &mut attention,
        &[in_session(
            session(2),
            AttentionSource::HostEvents,
            2,
            1_000,
            EventKind::AdapterRecovered { plugin_id: git() },
        )],
        1_000,
    );
    let left = failures(&attention);
    assert_eq!(
        left.len(),
        1,
        "session two's recovery ends session two's failure"
    );
    assert_eq!(left[0].session_id.0, Some(session(1)));
}

/// A notice with neither an identifier nor a fingerprint is its own record, and a record is named
/// by its origin as well as its place: two sessions' records about one session never fold.
#[test]
fn notices_without_an_identity_from_two_origins_stay_apart() {
    let mut attention = engine();
    let notice_from = |origin: SessionId| {
        in_session(
            origin,
            AttentionSource::HostEvents,
            1,
            0,
            EventKind::ApplicationNotice {
                session_id: session(3),
                notice: ApplicationNotice {
                    id: None,
                    title: None,
                    body: "build finished".to_owned(),
                    lease_held: false,
                    fingerprint: None,
                },
            },
        )
    };
    feed(
        &mut attention,
        &[notice_from(session(1)), notice_from(session(2))],
        0,
    );
    assert_eq!(
        owner_inbox(&attention)
            .iter()
            .filter(|item| item.rule == AttentionRule::ApplicationNotice)
            .count(),
        2
    );
}

/// KR-REQ-24.11: the store holds none of a session's text, so privacy mode has nothing to remove
/// from it and nothing a later read could restore.
#[test]
fn the_store_keeps_none_of_a_session_s_text() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    {
        let mut attention =
            Attention::open(&path, reading(0), &opener()).expect("the feature store opens");
        let secret_question = SourceEvent::new(
            EventCursor::in_session(session(1), AttentionSource::Questions, 1),
            TimestampMs::new(NOON),
            EventKind::QuestionPending {
                question_id: question(1),
                session_id: session(1),
                verified: true,
                pending_since_ms: TimestampMs::new(NOON),
                pending_since_anchor: None,
                summary: "ZEPHYRQUESTION".to_owned(),
            },
        );
        let secret_notice = notice(
            session(1),
            1,
            0,
            "ZEPHYRNOTICE",
            Some(fingerprint("ZEPHYRNOTICE")),
        );
        let secret_command = in_session(
            session(1),
            AttentionSource::Receipts,
            1,
            0,
            EventKind::CommandCompleted {
                session_id: session(1),
                command: "ZEPHYRCOMMAND".to_owned(),
                exit_code: 1,
            },
        );
        feed(
            &mut attention,
            &[secret_question, secret_notice, secret_command],
            0,
        );
        attention
            .tick(reading(IDLE_REMINDER_MS + 1), &all_read)
            .expect("the store records the decision");
        assert_eq!(owner_inbox(&attention).len(), 4);
    }
    let mut stored = Vec::new();
    for name in ["attention.db", "attention.db-wal"] {
        if let Ok(bytes) = std::fs::read(directory.path().join(name)) {
            stored.extend(bytes);
        }
    }
    assert!(!stored.is_empty());
    for secret in ["ZEPHYRQUESTION", "ZEPHYRNOTICE", "ZEPHYRCOMMAND"] {
        assert!(
            !stored
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "{secret} is not in the store"
        );
    }
}

// ----- Actions ---------------------------------------------------------------------------------

fn action(id: &str, digest: u8) -> ActionKey {
    ActionKey {
        actor: actor("device:phone"),
        action_id: id.to_owned(),
        method: "attention.acknowledge".to_owned(),
        digest: vec![digest; 32],
    }
}

/// An action is performed once, in the write that records it: a repeat is answered from the
/// record, a different request under the same identity is refused, and an action whose admission
/// lapsed is not performed and leaves no record.
#[test]
fn an_action_is_performed_once_and_answered_from_its_record() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let mut attention =
        Attention::open(&path, reading(0), &opener()).expect("the feature store opens");
    feed(&mut attention, &[approval(session(1), 1, "req-1")], 0);
    let key = owner_inbox(&attention)[0].key.clone();
    let items = [at_revision(&attention, &key)];

    let encode = |answer: &Answer| format!("{answer:?}").into_bytes();
    let first = attention
        .perform(
            &action("a-1", 1),
            Mutation::Acknowledge {
                viewer: &Viewer::Owner,
                items: &items,
            },
            reading(1_000),
            || Ok(()),
            encode,
        )
        .expect("the action is performed");
    let Performed::Done(Answer::Acknowledged(result)) = first else {
        panic!("a first performance answers with the effect");
    };
    assert_eq!(result.acknowledged, vec![key.clone()]);

    let repeat = attention
        .perform(
            &action("a-1", 1),
            Mutation::Acknowledge {
                viewer: &Viewer::Owner,
                items: &items,
            },
            reading(2_000),
            || panic!("a repeat is not admitted again"),
            encode,
        )
        .expect("a repeat is answered");
    let Performed::Retained(record) = repeat else {
        panic!("a repeat is answered from the record");
    };
    assert_eq!(record.answer, encode(&Answer::Acknowledged(result)));

    assert!(matches!(
        attention.perform(
            &action("a-1", 2),
            Mutation::QuietHours(None),
            reading(3_000),
            || Ok(()),
            encode,
        ),
        Err(kr_attention::Error::ActionConflict { .. })
    ));

    let lapsed = attention.perform(
        &action("a-2", 3),
        Mutation::QuietHours(Some(QuietHours {
            start_minute: U64::new(0),
            end_minute: U64::new(60),
            zone: Nullable::null(),
        })),
        reading(4_000),
        || {
            Err(kr_attention::Error::StoreUnreadable {
                field: "the admission lapsed",
            })
        },
        encode,
    );
    assert!(lapsed.is_err());
    assert!(
        attention
            .answered(&actor("device:phone"), "a-2")
            .expect("the records are readable")
            .is_none(),
        "a refused action leaves no record"
    );
    assert!(
        attention
            .engine()
            .expect("the store is this owner's")
            .quiet_hours()
            .is_none(),
        "and no effect"
    );

    // A lapsed admission is the answer whatever else is wrong with the request: a revision the host
    // never handed out and a version it never held are not weighed under authority that has gone.
    let lapse = || -> kr_attention::Result<()> {
        Err(kr_attention::Error::StoreUnreadable {
            field: "the admission lapsed",
        })
    };
    let ahead = [AttentionItemRevision {
        key: key.clone(),
        revision: U64::new(items[0].revision.get() + 5),
    }];
    assert!(matches!(
        attention.perform(
            &action("a-3", 4),
            Mutation::Acknowledge {
                viewer: &Viewer::Owner,
                items: &ahead,
            },
            reading(4_000),
            lapse,
            encode,
        ),
        Err(kr_attention::Error::StoreUnreadable { .. })
    ));
    let never = ReviewSubject::CompletedTurn {
        session_id: session(1),
        turn_id: AgentTurnId::new("turn-9").expect("an identifier"),
    };
    assert!(matches!(
        attention.perform(
            &action("a-4", 5),
            Mutation::Review {
                viewer: &Viewer::Owner,
                subject: &never,
                version: 7,
            },
            reading(4_000),
            lapse,
            encode,
        ),
        Err(kr_attention::Error::StoreUnreadable { .. })
    ));
    for id in ["a-3", "a-4"] {
        assert!(
            attention
                .answered(&actor("device:phone"), id)
                .expect("the records are readable")
                .is_none()
        );
    }

    // The record outlives the value that wrote it, and goes when its time is up.
    drop(attention);
    let mut reopened =
        Attention::open(&path, reading(5_000), &opener()).expect("the feature store opens");
    assert!(
        reopened
            .answered(&actor("device:phone"), "a-1")
            .expect("the records are readable")
            .is_some()
    );
    assert_eq!(
        reopened
            .forget_actions_before(NOON + 1_001)
            .expect("the records go"),
        1
    );
    assert!(
        reopened
            .answered(&actor("device:phone"), "a-1")
            .expect("the records are readable")
            .is_none()
    );
}

// ----- A store that reopens as it was written ------------------------------------------------

/// KR-REQ-24.11: a write changes the rows that changed and no others: one actor's acknowledgement
/// of one item writes that acknowledgement, that actor's revision and the owner's claim.
#[test]
fn a_write_changes_only_the_rows_that_changed() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let mut attention =
        Attention::open(&path, reading(0), &opener()).expect("the feature store opens");
    feed(
        &mut attention,
        &[
            pending(session(1), 1, 0, question(1)),
            approval(session(2), 1, "req-1"),
            turn(session(3), 1, "turn-1"),
        ],
        0,
    );
    attention
        .acknowledge_visit(&actor("local:501"), session(3), 1, Vec::new())
        .expect("the store records the visit");

    // Every row written from here on is counted, table by table.
    let watcher = rusqlite::Connection::open(&path).expect("a second connection");
    let tables: Vec<String> = {
        let mut statement = watcher
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'attention_%'",
            )
            .expect("the tables are listed");
        statement
            .query_map([], |row| row.get(0))
            .expect("the tables are listed")
            .collect::<Result<_, _>>()
            .expect("the tables are listed")
    };
    assert!(tables.len() > 15, "every table the store keeps");
    watcher
        .execute_batch("CREATE TABLE written (name TEXT NOT NULL);")
        .expect("the count is kept");
    for table in &tables {
        for change in ["INSERT", "UPDATE", "DELETE"] {
            watcher
                .execute_batch(&format!(
                    "CREATE TRIGGER written_{table}_{change} AFTER {change} ON {table}
                     BEGIN INSERT INTO written VALUES ('{table}'); END;"
                ))
                .expect("the count is kept");
        }
    }

    let key = owner_inbox(&attention)
        .into_iter()
        .find(|item| item.session_id.0 == Some(session(2)))
        .expect("session two's approval")
        .key;
    let items = [at_revision(&attention, &key)];
    attention
        .acknowledge(
            &actor("device:phone"),
            &Viewer::Owner,
            &items,
            reading(1_000),
        )
        .expect("the store records the acknowledgement");

    let written: Vec<(String, i64)> = {
        let mut statement = watcher
            .prepare("SELECT name, COUNT(*) FROM written GROUP BY name ORDER BY name")
            .expect("the count is read");
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("the count is read")
            .collect::<Result<_, _>>()
            .expect("the count is read")
    };
    assert_eq!(
        written,
        vec![
            ("attention_actors".to_owned(), 1),
            ("attention_item_acks".to_owned(), 1),
            ("attention_owner".to_owned(), 1),
        ]
    );
}

/// What a store keeps of its state, in a form two stores can be compared by.
fn kept(attention: &Attention) -> String {
    let engine = attention.engine().expect("the store is this owner's");
    let items: Vec<_> = engine
        .items()
        .map(|item| {
            format!(
                "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{:?}|{:?}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{:?}|{}|{}",
                item.key,
                item.rule,
                item.source,
                item.origin,
                item.session_id,
                item.text,
                item.grant,
                item.automation,
                item.revision,
                item.routing,
                item.level,
                item.steps_taken,
                item.occurrences,
                item.first_seen_ms,
                item.last_seen_ms,
                item.notification,
                item.anchor,
                item.last_notified_ms,
                item.announced_anchor,
                item.announced_level,
                item.announcements,
                item.pending_handoff,
                item.uncertain,
                item.deferred,
            )
        })
        .collect();
    let pending: Vec<_> = engine
        .pending_inputs()
        .iter()
        .map(|(question_id, input)| {
            format!(
                "{question_id}|{}|{:?}|{:?}|{}",
                input.session_id, input.record, input.pending_since_ms, input.reminded
            )
        })
        .collect();
    let actors: Vec<_> = ["device:phone", "local:501"]
        .into_iter()
        .map(|name| {
            attention
                .revision(&actor(name))
                .expect("the store is this owner's")
        })
        .collect();
    format!(
        "items {items:?}\nacks {:?}\nactors {actors:?}\nconsumed {:?}\ngaps {:?}\npending {pending:?}\nquiet {:?}\nfinalised {:?}\nrevision {}\nannouncement {}\ndropped {}\nsessions {:?}\nsubjects {:?}\nreviews {:?}",
        engine.all_acknowledgements(),
        engine.all_consumed(),
        engine.gaps(),
        engine.quiet_hours(),
        engine.finalised(),
        engine.next_revision(),
        engine.next_announcement(),
        engine.dropped(),
        attention
            .visits()
            .expect("the store is this owner's")
            .sessions(),
        attention
            .reviews()
            .expect("the store is this owner's")
            .subjects()
            .collect::<Vec<_>>(),
        attention
            .reviews()
            .expect("the store is this owner's")
            .all_acknowledgements(),
    )
}

/// A small deterministic stream of choices.
struct Choices(u64);

impl Choices {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % bound
    }
}

/// KR-REQ-24.11: whatever sequence of events, timers, acknowledgements, visits, reviews and endings
/// a store is given, each write changes only the rows that changed, and a store reopened from the
/// file holds exactly what the value that wrote it held.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one arm per kind of change the stream can make"
)]
fn a_store_reopens_exactly_as_it_was_written() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let mut attention =
        Attention::open(&path, reading(0), &opener()).expect("the feature store opens");
    let mut choices = Choices(0x5eed);
    let mut sequences = [[0u64; 4]; 4];
    let mut outbox = 0u64;
    let sessions = [session(1), session(2), session(3)];
    let mut at = 0;
    for step in 0..600u64 {
        at += 7_000 + choices.next(20_000);
        let now = reading(at);
        let pick = usize::try_from(choices.next(3)).expect("a small index");
        let session_id = sessions[pick];
        let mut next = |source: usize, jump: u64| {
            sequences[pick][source] += 1 + jump;
            sequences[pick][source]
        };
        match choices.next(15) {
            0 => {
                let id = QuestionId::new(Uuid::from_bytes(
                    [u8::try_from(choices.next(8)).expect("small"); 16],
                ));
                let sequence = next(0, 0);
                attention
                    .apply(&pending(session_id, sequence, at, id), now)
                    .expect("recorded");
            }
            1 => {
                let id = QuestionId::new(Uuid::from_bytes(
                    [u8::try_from(choices.next(8)).expect("small"); 16],
                ));
                let sequence = next(0, 0);
                attention
                    .apply(&answered(session_id, sequence, at, id), now)
                    .expect("recorded");
            }
            2 => {
                let body = format!("notice {}", choices.next(4));
                let sequence = next(1, choices.next(3) / 2);
                attention
                    .apply(
                        &notice(session_id, sequence, at, &body, Some(fingerprint(&body))),
                        now,
                    )
                    .expect("recorded");
            }
            3 => {
                let request = format!("req-{}", choices.next(3));
                let sequence = next(2, 0);
                attention
                    .apply(&approval(session_id, sequence, &request), now)
                    .expect("recorded");
            }
            4 => {
                let request = format!("req-{}", choices.next(3));
                let sequence = next(2, 0);
                attention
                    .apply(&approval_resolved(session_id, sequence, &request), now)
                    .expect("recorded");
            }
            5 => {
                let name = format!("turn-{}", choices.next(5));
                let sequence = next(3, 0);
                attention
                    .apply(&turn(session_id, sequence, &name), now)
                    .expect("recorded");
            }
            6 => {
                attention.tick(now, &all_read).expect("recorded");
            }
            7 => {
                let items = owner_inbox(&attention);
                if let Some(item) = items.get(usize::try_from(choices.next(4)).expect("small")) {
                    let revision = at_revision(&attention, &item.key);
                    attention
                        .acknowledge(&actor("device:phone"), &Viewer::Owner, &[revision], now)
                        .expect("recorded");
                }
            }
            8 => {
                attention
                    .acknowledge_visit(&actor("local:501"), session_id, choices.next(6), Vec::new())
                    .expect("recorded");
            }
            9 => {
                let subject = ReviewSubject::CompletedTurn {
                    session_id,
                    turn_id: AgentTurnId::new(format!("turn-{}", choices.next(5)))
                        .expect("an identifier"),
                };
                // A subject the host does not hold is refused; either answer is fine here.
                let _ = attention.acknowledge_review(
                    &actor("local:501"),
                    &Viewer::Owner,
                    &subject,
                    1,
                    now,
                );
            }
            10 => {
                let taken = attention
                    .take_announcements(&|_| true)
                    .expect("the store is this owner's");
                let settled: Vec<_> = taken.into_iter().map(|one| (one.key, one.number)).collect();
                attention.settle_announcements(&settled).expect("recorded");
            }
            11 => {
                if choices.next(10) == 0 {
                    attention.finalise(session_id, now).expect("recorded");
                }
            }
            12 => {
                // The workflow journal's numbering has holes that are not gaps.
                outbox += 1 + choices.next(4);
                let subject = workflow(u8::try_from(choices.next(3)).expect("small"), 1);
                let event = if choices.next(3) == 0 {
                    resumed(outbox, subject)
                } else {
                    let under = (choices.next(2) == 0).then(|| grant(1));
                    paused(outbox, subject, under)
                };
                attention.apply(&event, now).expect("recorded");
            }
            13 => {
                // A range of one session's notices that can never be read.
                let from = sequences[pick][1] + 1;
                attention
                    .note_gap(
                        Origin::Session(session_id),
                        AttentionSource::HostEvents,
                        from,
                        None,
                    )
                    .expect("recorded");
            }
            _ => {
                let window = (choices.next(2) == 0).then(|| QuietHours {
                    start_minute: U64::new(choices.next(1_440)),
                    end_minute: U64::new(choices.next(1_440)),
                    zone: Nullable::null(),
                });
                attention.set_quiet_hours(window).expect("recorded");
            }
        }
        if step % 50 == 49 {
            let before = kept(&attention);
            drop(attention);
            attention =
                Attention::open(&path, reading(at), &opener()).expect("the feature store opens");
            assert_eq!(
                kept(&attention),
                before,
                "the store reopened as it was written after step {step}"
            );
        }
    }
    assert!(
        !owner_inbox(&attention).is_empty(),
        "the stream left work in the inbox"
    );
}
