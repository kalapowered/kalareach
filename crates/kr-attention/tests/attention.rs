//! The attention engine against section 25's rule set, section 24's reconstruction rule and
//! section 14's binding of a review acknowledgement to a version.

use std::collections::BTreeSet;

use kr_attention::engine::Outcome;
use kr_attention::event::{ApplicationNotice, EventCursor, EventKind, SourceEvent};
use kr_attention::host::summary_of;
use kr_attention::rule::{ADAPTER_ESCALATION_MS, REMINDER_INTERVAL_MS, RULES, rule};
use kr_attention::{Attention, HostReading};
use kr_protocol::attention::{
    AttentionKey, AttentionLevel, AttentionRouting, AttentionRule, AttentionSource,
    IDLE_REMINDER_MS, LogViewState, NotificationState, QuietHours, ReviewSubject,
};
use kr_protocol::ids::{
    ActorId, AgentTurnId, ApprovalRequestId, ChangeSetId, PluginId, QuestionId, SessionId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

/// A wall-clock moment at noon UTC, so a quiet window either side of it is unambiguous.
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

fn reading(continuous_ms: u64) -> HostReading {
    HostReading::new(continuous_ms, NOON + continuous_ms, true)
}

fn event(source: AttentionSource, sequence: u64, at_ms: u64, kind: EventKind) -> SourceEvent {
    SourceEvent::new(
        EventCursor::new(source, sequence),
        TimestampMs::new(at_ms),
        kind,
    )
}

fn approval(sequence: u64, at_ms: u64, request: &str) -> SourceEvent {
    event(
        AttentionSource::Receipts,
        sequence,
        at_ms,
        EventKind::ApprovalRequested {
            request_id: ApprovalRequestId::new(request).expect("an identifier"),
            session_id: session(1),
            summary: "write /etc/hosts".to_owned(),
        },
    )
}

fn approval_resolved(sequence: u64, at_ms: u64, request: &str) -> SourceEvent {
    event(
        AttentionSource::Receipts,
        sequence,
        at_ms,
        EventKind::ApprovalResolved {
            request_id: ApprovalRequestId::new(request).expect("an identifier"),
        },
    )
}

fn pending_question(
    sequence: u64,
    at_ms: u64,
    id: QuestionId,
    verified: bool,
    pending_since_ms: u64,
) -> SourceEvent {
    event(
        AttentionSource::Questions,
        sequence,
        at_ms,
        EventKind::QuestionPending {
            question_id: id,
            session_id: session(1),
            verified,
            pending_since_ms: TimestampMs::new(pending_since_ms),
            summary: "which branch?".to_owned(),
        },
    )
}

fn notice(sequence: u64, at_ms: u64, body: &str, lease_held: bool) -> SourceEvent {
    event(
        AttentionSource::HostEvents,
        sequence,
        at_ms,
        EventKind::ApplicationNotice {
            session_id: session(1),
            notice: ApplicationNotice {
                id: None,
                title: None,
                body: body.to_owned(),
                lease_held,
            },
        },
    )
}

fn key(id: AttentionRule, subject: &str) -> AttentionKey {
    AttentionKey::of(id, subject).expect("a well-formed key")
}

fn raised(outcomes: &[Outcome]) -> BTreeSet<AttentionRule> {
    outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Raised { rule, .. } => Some(*rule),
            _ => None,
        })
        .collect()
}

fn notified(outcomes: &[Outcome]) -> Vec<&AttentionKey> {
    outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Notified { key, .. } | Outcome::Released { key, .. } => Some(key),
            _ => None,
        })
        .collect()
}

fn engine() -> Attention {
    Attention::in_memory(reading(0)).expect("an in-memory feature store")
}

// ----- The rule set ------------------------------------------------------------------------

#[test]
fn every_rule_in_the_set_is_raised_by_the_typed_event_it_covers() {
    let mut attention = engine();
    let mut seen = BTreeSet::new();
    let mut at = 0;
    let mut step = |events: Vec<SourceEvent>, attention: &mut Attention, seen: &mut BTreeSet<_>| {
        for source in events {
            at += 60_001;
            let outcomes = attention
                .apply(&source, reading(at))
                .expect("the store records the decision");
            seen.extend(raised(&outcomes));
        }
    };
    step(
        vec![
            approval(1, 1_000, "req-1"),
            event(
                AttentionSource::Receipts,
                2,
                2_000,
                EventKind::CommandCompleted {
                    session_id: session(1),
                    command: "cargo test".to_owned(),
                    exit_code: 101,
                },
            ),
            pending_question(1, 3_000, question(9), true, 3_000),
            event(
                AttentionSource::Semantic,
                1,
                4_000,
                EventKind::TurnCompleted {
                    session_id: session(1),
                    turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
                    version: 1,
                    change_set: None,
                    summary: "rewrote the parser".to_owned(),
                },
            ),
            event(
                AttentionSource::Semantic,
                2,
                5_000,
                EventKind::AdapterFailed {
                    plugin_id: PluginId::new("git").expect("an identifier"),
                    session_id: Some(session(1)),
                    detail: "the helper exited".to_owned(),
                },
            ),
            event(
                AttentionSource::Semantic,
                3,
                6_000,
                EventKind::HostContactLost {
                    detail: "the relay closed".to_owned(),
                },
            ),
            notice(1, 7_000, "build finished", false),
        ],
        &mut attention,
        &mut seen,
    );
    // The idle reminder is the one rule a timer raises rather than an event.
    let outcomes = attention
        .tick(reading(at + IDLE_REMINDER_MS))
        .expect("the store records the decision");
    seen.extend(raised(&outcomes));

    let expected: BTreeSet<_> = RULES.iter().map(|rule| rule.id).collect();
    assert_eq!(seen, expected, "every rule in the set was exercised");
}

#[test]
fn a_command_that_succeeded_raises_nothing() {
    let mut attention = engine();
    let outcomes = attention
        .apply(
            &event(
                AttentionSource::Receipts,
                1,
                1_000,
                EventKind::CommandCompleted {
                    session_id: session(1),
                    command: "true".to_owned(),
                    exit_code: 0,
                },
            ),
            reading(0),
        )
        .expect("the store records the decision");
    assert!(outcomes.is_empty());
    assert!(attention.inbox(&actor("local:501"), true).is_empty());
}

#[test]
fn a_condition_that_ends_leaves_the_inbox() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    assert_eq!(attention.inbox(&actor("local:501"), true).len(), 1);
    let outcomes = attention
        .apply(&approval_resolved(2, 2_000, "req-1"), reading(1_000))
        .expect("the store records the decision");
    assert!(matches!(outcomes.as_slice(), [Outcome::Resolved { .. }]));
    assert!(attention.inbox(&actor("local:501"), true).is_empty());
}

// ----- De-duplication ----------------------------------------------------------------------

#[test]
fn a_repeat_inside_the_sixty_second_window_is_counted_rather_than_announced() {
    let mut attention = engine();
    let first = attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    assert_eq!(notified(&first).len(), 1);

    let inside = attention
        .apply(&approval(2, 2_000, "req-1"), reading(59_999))
        .expect("the store records the decision");
    assert!(
        notified(&inside).is_empty(),
        "a repeat inside the window is not announced"
    );
    assert!(matches!(
        inside.as_slice(),
        [Outcome::Repeated { occurrences: 2, .. }]
    ));
    let item = attention.inbox(&actor("local:501"), true).remove(0);
    assert_eq!(item.occurrences, U64::new(2));
    assert_eq!(item.notification, NotificationState::Suppressed);

    let outside = attention
        .apply(&approval(3, 3_000, "req-1"), reading(60_000))
        .expect("the store records the decision");
    assert_eq!(
        notified(&outside).len(),
        1,
        "the window has passed, so the condition is announced again"
    );
    let item = attention.inbox(&actor("local:501"), true).remove(0);
    assert_eq!(item.occurrences, U64::new(3));
}

// ----- Quiet hours -------------------------------------------------------------------------

/// A window that covers noon, which every reading in these tests falls inside.
fn quiet_over_noon() -> QuietHours {
    QuietHours {
        start_minute: U64::new(11 * 60),
        end_minute: U64::new(13 * 60),
        zone: Nullable::some("Africa/Johannesburg".to_owned()),
    }
}

#[test]
fn an_announcement_inside_quiet_hours_is_deferred_and_released_when_they_end() {
    let mut attention = engine();
    attention
        .set_quiet_hours(Some(quiet_over_noon()), reading(0))
        .expect("the store records the window");
    let outcomes = attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    assert!(
        matches!(
            outcomes.as_slice(),
            [Outcome::Raised { .. }, Outcome::Deferred { .. }]
        ),
        "an announcement is held rather than sent: {outcomes:?}"
    );

    // The item is in the inbox throughout, at the level its rule asks for.
    let item = attention.inbox(&actor("local:501"), true).remove(0);
    assert_eq!(item.level, AttentionLevel::Urgent);
    assert_eq!(item.notification, NotificationState::Deferred);

    // One hour later the window has ended and the held announcement is released.
    let after = HostReading::new(3_600_000, NOON + 3_600_000, true);
    assert!(!attention.engine().quiet_now(after));
    let released = attention
        .tick(after)
        .expect("the store records the release");
    assert!(
        released
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Released { .. })),
        "the held announcement is released rather than dropped: {released:?}"
    );
    let item = attention.inbox(&actor("local:501"), true).remove(0);
    assert_eq!(item.notification, NotificationState::Delivered);
}

#[test]
fn clearing_quiet_hours_releases_what_they_were_holding() {
    let mut attention = engine();
    attention
        .set_quiet_hours(Some(quiet_over_noon()), reading(0))
        .expect("the store records the window");
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    let released = attention
        .set_quiet_hours(None, reading(1_000))
        .expect("the store records the window");
    assert!(matches!(released.as_slice(), [Outcome::Released { .. }]));
}

#[test]
fn quiet_hours_are_not_enforced_on_a_clock_this_host_cannot_prove() {
    let mut attention = engine();
    attention
        .set_quiet_hours(Some(quiet_over_noon()), reading(0))
        .expect("the store records the window");
    let unproven = HostReading::new(0, NOON, false);
    assert!(!attention.engine().quiet_now(unproven));
    let outcomes = attention
        .apply(&approval(1, 1_000, "req-1"), unproven)
        .expect("the store records the decision");
    assert_eq!(
        notified(&outcomes).len(),
        1,
        "an unprovable clock delivers rather than withholds: {outcomes:?}"
    );
    let read = attention.read(&actor("local:501"), true, unproven);
    assert!(!read.quiet_hours_provable);
    assert!(!read.quiet_now);
    assert!(
        read.quiet_hours.is_present(),
        "the window is still configured"
    );
}

// ----- The idle reminder -------------------------------------------------------------------

#[test]
fn the_idle_reminder_counts_from_the_request_rather_than_from_the_last_output() {
    let mut attention = engine();
    attention
        .apply(
            &pending_question(1, 1_000, question(9), true, 1_000),
            reading(0),
        )
        .expect("the store records the decision");

    // Output keeps arriving, which is not what the interval counts.
    for (sequence, at) in [(2_u64, 60_000_u64), (3, 120_000), (4, 180_000)] {
        attention
            .apply(
                &event(
                    AttentionSource::Receipts,
                    sequence,
                    1_000 + at,
                    EventKind::CommandCompleted {
                        session_id: session(1),
                        command: "true".to_owned(),
                        exit_code: 0,
                    },
                ),
                reading(at),
            )
            .expect("the store records the decision");
    }

    let early = attention
        .tick(reading(IDLE_REMINDER_MS - 1))
        .expect("the store records the decision");
    assert!(
        raised(&early).is_empty(),
        "the interval has not passed: {early:?}"
    );

    let due = attention
        .tick(reading(IDLE_REMINDER_MS))
        .expect("the store records the decision");
    assert!(raised(&due).contains(&AttentionRule::InputIdleReminder));
    let reminder = attention
        .inbox(&actor("local:501"), true)
        .into_iter()
        .find(|item| item.rule == AttentionRule::InputIdleReminder)
        .expect("the reminder is in the inbox");
    assert_eq!(reminder.level, AttentionLevel::Urgent);
}

#[test]
fn a_request_already_pending_when_the_engine_sees_it_is_reminded_on_its_own_interval() {
    let mut attention = engine();
    // The request became pending four minutes before the host recorded the event.
    attention
        .apply(
            &pending_question(1, 240_000, question(9), true, 0),
            reading(240_000),
        )
        .expect("the store records the decision");
    let early = attention
        .tick(reading(IDLE_REMINDER_MS - 1))
        .expect("the store records the decision");
    assert!(raised(&early).is_empty());
    let due = attention
        .tick(reading(IDLE_REMINDER_MS))
        .expect("the store records the decision");
    assert!(
        raised(&due).contains(&AttentionRule::InputIdleReminder),
        "the five minutes count from the request, not from when the host saw it"
    );
}

#[test]
fn an_answered_request_is_never_reminded_about() {
    let mut attention = engine();
    attention
        .apply(
            &pending_question(1, 1_000, question(9), true, 1_000),
            reading(0),
        )
        .expect("the store records the decision");
    attention
        .apply(
            &event(
                AttentionSource::Questions,
                2,
                2_000,
                EventKind::QuestionResolved {
                    question_id: question(9),
                    answered: true,
                },
            ),
            reading(1_000),
        )
        .expect("the store records the decision");
    let due = attention
        .tick(reading(IDLE_REMINDER_MS * 2))
        .expect("the store records the decision");
    assert!(raised(&due).is_empty(), "nothing is waiting: {due:?}");
    assert!(attention.inbox(&actor("local:501"), true).is_empty());
}

#[test]
fn an_unverified_request_never_becomes_attention_work() {
    let mut attention = engine();
    let outcomes = attention
        .apply(
            &pending_question(1, 1_000, question(9), false, 1_000),
            reading(0),
        )
        .expect("the store records the decision");
    assert!(outcomes.is_empty());
    let due = attention
        .tick(reading(IDLE_REMINDER_MS * 2))
        .expect("the store records the decision");
    assert!(due.is_empty(), "an unverified claim is not reminded about");
}

// ----- Escalation --------------------------------------------------------------------------

#[test]
fn an_unattended_adapter_failure_climbs_to_urgent_and_an_acknowledged_one_does_not() {
    let mut attention = engine();
    let failure = event(
        AttentionSource::Semantic,
        1,
        1_000,
        EventKind::AdapterFailed {
            plugin_id: PluginId::new("git").expect("an identifier"),
            session_id: Some(session(1)),
            detail: "the helper exited".to_owned(),
        },
    );
    attention
        .apply(&failure, reading(0))
        .expect("the store records the decision");
    let item = attention.inbox(&actor("local:501"), true).remove(0);
    assert_eq!(item.level, AttentionLevel::Notable);

    let climbed = attention
        .tick(reading(ADAPTER_ESCALATION_MS))
        .expect("the store records the decision");
    assert!(
        climbed.iter().any(|outcome| matches!(
            outcome,
            Outcome::Escalated {
                from: AttentionLevel::Notable,
                to: AttentionLevel::Urgent,
                ..
            }
        )),
        "the failure climbed its ladder: {climbed:?}"
    );

    // A second failure, acknowledged straight away, never climbs.
    let mut attention = engine();
    attention
        .apply(&failure, reading(0))
        .expect("the store records the decision");
    attention
        .acknowledge(
            &actor("local:501"),
            &[key(AttentionRule::AdapterFailed, "git")],
            reading(1),
        )
        .expect("the store records the acknowledgement");
    let quiet = attention
        .tick(reading(ADAPTER_ESCALATION_MS))
        .expect("the store records the decision");
    assert!(quiet.is_empty(), "somebody has seen it: {quiet:?}");
}

#[test]
fn an_unanswered_approval_is_announced_again_at_its_rule_s_interval() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    let quiet = attention
        .tick(reading(REMINDER_INTERVAL_MS - 1))
        .expect("the store records the decision");
    assert!(notified(&quiet).is_empty());
    let due = attention
        .tick(reading(REMINDER_INTERVAL_MS))
        .expect("the store records the decision");
    assert_eq!(notified(&due).len(), 1, "the approval is still waiting");
}

#[test]
fn the_next_deadline_is_the_earliest_timer_the_host_has_to_wake_for() {
    let mut attention = engine();
    attention
        .apply(
            &pending_question(1, 1_000, question(9), true, 1_000),
            reading(0),
        )
        .expect("the store records the decision");
    assert_eq!(
        attention.engine().next_deadline(reading(0)),
        Some(IDLE_REMINDER_MS),
        "the idle reminder is the only timer"
    );
}

// ----- Application notices -----------------------------------------------------------------

#[test]
fn an_application_notice_is_untrusted_and_is_never_a_pending_approval() {
    let mut attention = engine();
    let outcomes = attention
        .apply(
            &notice(1, 1_000, "approve the deployment? [y/n]", false),
            reading(0),
        )
        .expect("the store records the decision");
    assert_eq!(
        raised(&outcomes),
        BTreeSet::from([AttentionRule::ApplicationNotice])
    );
    let item = attention.inbox(&actor("local:501"), true).remove(0);
    assert!(!item.trusted, "any process can print one");
    assert_eq!(item.level, AttentionLevel::Informational);
    assert_eq!(item.rule, AttentionRule::ApplicationNotice);
    assert!(
        !attention
            .inbox(&actor("local:501"), true)
            .iter()
            .any(|item| item.rule == AttentionRule::PendingApproval),
        "nothing a notice says makes it an approval"
    );
}

#[test]
fn a_notice_with_no_lease_holder_goes_to_the_owner_policy_and_stays_in_attention() {
    let mut attention = engine();
    attention
        .apply(&notice(1, 1_000, "build finished", false), reading(0))
        .expect("the store records the decision");
    let item = attention.inbox(&actor("local:501"), true).remove(0);
    assert_eq!(item.routing, AttentionRouting::OwnerPolicy);

    let mut attention = engine();
    attention
        .apply(&notice(1, 1_000, "build finished", true), reading(0))
        .expect("the store records the decision");
    let item = attention.inbox(&actor("local:501"), true).remove(0);
    assert_eq!(
        item.routing,
        AttentionRouting::LeaseHolder,
        "a lease holder is the destination section 8 gives it"
    );
    assert_eq!(
        attention.inbox(&actor("local:501"), true).len(),
        1,
        "it is retained in Attention either way"
    );
}

#[test]
fn an_untrusted_notice_never_reaches_an_urgent_level_however_long_it_waits() {
    let mut attention = engine();
    attention
        .apply(&notice(1, 1_000, "build finished", false), reading(0))
        .expect("the store records the decision");
    attention
        .tick(reading(IDLE_REMINDER_MS * 12))
        .expect("the store records the decision");
    let item = attention.inbox(&actor("local:501"), true).remove(0);
    assert_eq!(item.level, AttentionLevel::Informational);
    assert_eq!(rule(AttentionRule::ApplicationNotice).repeat_ms, None);
}

// ----- Acknowledgement ---------------------------------------------------------------------

#[test]
fn an_acknowledgement_affects_only_the_actor_that_made_it() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    let acknowledged = attention
        .acknowledge(
            &actor("device:phone"),
            &[key(AttentionRule::PendingApproval, "req-1")],
            reading(1_000),
        )
        .expect("the store records the acknowledgement");
    assert_eq!(acknowledged.len(), 1);
    assert!(attention.inbox(&actor("device:phone"), false).is_empty());
    assert_eq!(
        attention.inbox(&actor("local:501"), false).len(),
        1,
        "another actor has not seen it"
    );
}

#[test]
fn a_later_occurrence_is_work_an_earlier_acknowledgement_does_not_cover() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    attention
        .acknowledge(
            &actor("device:phone"),
            &[key(AttentionRule::PendingApproval, "req-1")],
            reading(1_000),
        )
        .expect("the store records the acknowledgement");
    assert!(attention.inbox(&actor("device:phone"), false).is_empty());
    attention
        .apply(&approval(2, 100_000, "req-1"), reading(90_000))
        .expect("the store records the decision");
    assert_eq!(
        attention.inbox(&actor("device:phone"), false).len(),
        1,
        "the condition happened again"
    );
}

#[test]
fn acknowledging_a_key_the_host_holds_no_item_for_records_nothing() {
    let mut attention = engine();
    let acknowledged = attention
        .acknowledge(
            &actor("device:phone"),
            &[key(AttentionRule::PendingApproval, "never-raised")],
            reading(0),
        )
        .expect("the store records the acknowledgement");
    assert!(acknowledged.is_empty());
}

// ----- Review state ------------------------------------------------------------------------

fn turn_completed(sequence: u64, at_ms: u64, version: u64) -> SourceEvent {
    event(
        AttentionSource::Semantic,
        sequence,
        at_ms,
        EventKind::TurnCompleted {
            session_id: session(1),
            turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
            version,
            change_set: Some(ChangeSetId::new(Uuid::from_bytes([5; 16]))),
            summary: "rewrote the parser".to_owned(),
        },
    )
}

fn turn_subject() -> ReviewSubject {
    ReviewSubject::CompletedTurn {
        session_id: session(1),
        turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
    }
}

#[test]
fn a_review_acknowledgement_binds_the_version_it_was_made_against() {
    let mut attention = engine();
    attention
        .apply(&turn_completed(1, 1_000, 1), reading(0))
        .expect("the store records the decision");
    let state = attention
        .acknowledge_review(&actor("local:501"), &turn_subject(), 1, reading(1_000))
        .expect("the version is one the host holds");
    assert_eq!(state.acknowledged_version, Nullable::some(U64::new(1)));
    assert!(!state.outstanding);

    attention
        .apply(&turn_completed(2, 2_000, 2), reading(2_000))
        .expect("the store records the decision");
    let states = attention.review_states(&actor("local:501"), session(1));
    let turn = states
        .iter()
        .find(|state| matches!(state.subject, ReviewSubject::CompletedTurn { .. }))
        .expect("the turn is a subject");
    assert_eq!(turn.current_version, U64::new(2));
    assert_eq!(turn.acknowledged_version, Nullable::some(U64::new(1)));
    assert!(
        turn.outstanding,
        "a new change is new review work the old acknowledgement does not cover"
    );
}

#[test]
fn a_review_acknowledgement_names_a_version_the_host_holds() {
    let mut attention = engine();
    assert!(
        attention
            .acknowledge_review(&actor("local:501"), &turn_subject(), 1, reading(0))
            .is_err(),
        "there is no such subject yet"
    );
    attention
        .apply(&turn_completed(1, 1_000, 1), reading(0))
        .expect("the store records the decision");
    assert!(
        attention
            .acknowledge_review(&actor("local:501"), &turn_subject(), 2, reading(0))
            .is_err(),
        "version two was never presented"
    );
}

#[test]
fn a_review_acknowledgement_is_per_actor() {
    let mut attention = engine();
    attention
        .apply(&turn_completed(1, 1_000, 1), reading(0))
        .expect("the store records the decision");
    attention
        .acknowledge_review(&actor("local:501"), &turn_subject(), 1, reading(1_000))
        .expect("the version is one the host holds");
    let other = attention
        .reviews()
        .state(&actor("device:phone"), &turn_subject())
        .expect("the subject exists for every actor");
    assert!(other.outstanding, "another actor has not reviewed it");
    assert_eq!(other.acknowledged_version, Nullable::null());
}

#[test]
fn a_turn_that_captured_a_change_set_gives_both_subjects_the_same_version() {
    let mut attention = engine();
    attention
        .apply(&turn_completed(1, 1_000, 3), reading(0))
        .expect("the store records the decision");
    let states = attention.review_states(&actor("local:501"), session(1));
    assert_eq!(states.len(), 2);
    for state in states {
        assert_eq!(state.current_version, U64::new(3));
        assert!(state.outstanding);
    }
}

// ----- Changed since the last visit --------------------------------------------------------

#[test]
fn changed_since_a_visit_compares_the_acknowledged_cursor_with_the_current_events() {
    let mut attention = engine();
    for (sequence, version) in [(1_u64, 1_u64), (2, 2), (3, 3)] {
        attention
            .apply(
                &turn_completed(sequence, 1_000 * sequence, version),
                reading(0),
            )
            .expect("the store records the decision");
    }
    let all = attention.changed_since(&actor("local:501"), 100, 0);
    assert_eq!(all.from_cursor, 0);
    assert_eq!(
        all.changes.len(),
        6,
        "a turn and its change set, three times"
    );
    assert!(!all.more);

    attention
        .acknowledge_visit(&actor("local:501"), all.to_cursor, Vec::new())
        .expect("the store records the visit");
    let nothing = attention.changed_since(&actor("local:501"), 100, 0);
    assert!(nothing.changes.is_empty());
    assert!(nothing.omitted.is_empty());

    attention
        .apply(&turn_completed(4, 4_000, 4), reading(0))
        .expect("the store records the decision");
    let latest = attention.changed_since(&actor("local:501"), 100, 0);
    assert_eq!(latest.changes.len(), 2);
    assert_eq!(latest.from_cursor, all.to_cursor);
}

#[test]
fn a_visit_cursor_never_goes_backwards() {
    let mut attention = engine();
    attention
        .apply(&turn_completed(1, 1_000, 1), reading(0))
        .expect("the store records the decision");
    attention
        .acknowledge_visit(&actor("local:501"), 2, Vec::new())
        .expect("the store records the visit");
    let visit = attention
        .acknowledge_visit(&actor("local:501"), 0, Vec::new())
        .expect("the store records the visit");
    assert_eq!(visit.cursor, 2);
    assert_eq!(visit.revision, 2, "each visit is its own revision");
}

#[test]
fn a_summary_travels_beside_the_events_and_names_the_interval_it_came_from() {
    let mut attention = engine();
    attention
        .apply(&turn_completed(1, 1_000, 1), reading(0))
        .expect("the store records the decision");
    attention
        .summarise(summary_of(
            "the parser was rewritten",
            "local-summariser/1",
            0,
            2,
            TimestampMs::new(1_000),
            TimestampMs::new(2_000),
        ))
        .expect("the store records the summary");
    let changed = attention.changed_since(&actor("local:501"), 100, 0);
    let summary = changed.summary.expect("a summary covers the interval");
    assert_eq!(summary.from_cursor, U64::new(0));
    assert_eq!(summary.to_cursor, U64::new(2));
    assert_eq!(summary.model, "local-summariser/1");
    assert_eq!(
        changed.changes.len(),
        2,
        "the authoritative events are unchanged by the summary beside them"
    );
}

// ----- Gaps --------------------------------------------------------------------------------

#[test]
fn a_gap_in_the_retained_events_is_never_an_answered_approval() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    // The records that would have said what happened to it were evicted.
    let outcomes = attention
        .apply(&approval(9, 9_000, "req-2"), reading(1_000))
        .expect("the store records the decision");
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::GapRecorded { .. })),
        "the missing range is stated: {outcomes:?}"
    );
    let first = attention
        .inbox(&actor("local:501"), true)
        .into_iter()
        .find(|item| item.key == key(AttentionRule::PendingApproval, "req-1"))
        .expect("the first approval is still in the inbox");
    assert!(
        first.uncertain,
        "the host cannot say whether the missing range answered it"
    );
    let gaps = attention.gaps();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].from_sequence, U64::new(2));
    assert_eq!(gaps[0].to_sequence, U64::new(9));
}

#[test]
fn a_gap_in_one_source_does_not_cast_doubt_on_another_source_s_items() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    attention
        .apply(&notice(1, 1_000, "build finished", false), reading(0))
        .expect("the store records the decision");
    attention
        .apply(&notice(9, 9_000, "build failed", false), reading(1_000))
        .expect("the store records the decision");
    let approval_item = attention
        .inbox(&actor("local:501"), true)
        .into_iter()
        .find(|item| item.rule == AttentionRule::PendingApproval)
        .expect("the approval is in the inbox");
    assert!(
        !approval_item.uncertain,
        "a range of terminal notices says nothing about an approval"
    );
}

// ----- Reconstruction ----------------------------------------------------------------------

fn replayable_events() -> Vec<SourceEvent> {
    vec![
        approval(1, 1_000, "req-1"),
        approval(2, 2_000, "req-2"),
        approval_resolved(3, 3_000, "req-1"),
        turn_completed(1, 4_000, 1),
        notice(1, 5_000, "build finished", false),
    ]
}

#[test]
fn replaying_the_retained_events_twice_gives_one_inbox() {
    let mut attention = engine();
    let events = replayable_events();
    attention
        .rebuild(&events, reading(0))
        .expect("the store records the rebuild");
    let once = attention.inbox(&actor("local:501"), true);
    let changes_once = attention.changed_since(&actor("local:501"), 100, 0).changes;

    let again = attention
        .rebuild(&events, reading(1_000))
        .expect("the store records the rebuild");
    assert!(again.is_empty(), "nothing was consumed twice: {again:?}");
    assert_eq!(attention.inbox(&actor("local:501"), true), once);
    assert_eq!(
        attention.changed_since(&actor("local:501"), 100, 0).changes,
        changes_once
    );
}

#[test]
fn a_rebuild_from_nothing_lands_where_the_live_engine_did() {
    let mut live = engine();
    let events = replayable_events();
    for source in &events {
        live.apply(source, reading(0))
            .expect("the store records the decision");
    }

    let mut rebuilt = engine();
    rebuilt
        .rebuild(&events, reading(0))
        .expect("the store records the rebuild");

    assert_eq!(
        rebuilt.inbox(&actor("local:501"), true),
        live.inbox(&actor("local:501"), true)
    );
    assert_eq!(
        rebuilt.review_states(&actor("local:501"), session(1)),
        live.review_states(&actor("local:501"), session(1))
    );
}

#[test]
fn a_replay_that_starts_past_the_consumed_cursor_records_the_range_it_skipped() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    let outcomes = attention
        .rebuild(&[approval(5, 5_000, "req-5")], reading(1_000))
        .expect("the store records the rebuild");
    let gap = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            Outcome::GapRecorded { gap } => Some(*gap),
            _ => None,
        })
        .expect("the skipped range is stated");
    assert_eq!(gap.from_sequence, U64::new(2));
    assert_eq!(gap.to_sequence, U64::new(5));
}

#[test]
fn the_state_comes_back_as_it_was_after_the_store_is_reopened() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let items;
    let states;
    {
        let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
        attention
            .rebuild(&replayable_events(), reading(0))
            .expect("the store records the rebuild");
        attention
            .acknowledge_review(&actor("local:501"), &turn_subject(), 1, reading(1_000))
            .expect("the version is one the host holds");
        attention
            .acknowledge(
                &actor("local:501"),
                &[key(AttentionRule::PendingApproval, "req-2")],
                reading(1_000),
            )
            .expect("the store records the acknowledgement");
        attention
            .set_quiet_hours(Some(quiet_over_noon()), reading(1_000))
            .expect("the store records the window");
        items = attention.inbox(&actor("local:501"), true);
        states = attention.review_states(&actor("local:501"), session(1));
    }

    let reopened = Attention::open(&path, reading(10_000)).expect("the feature store reopens");
    assert_eq!(reopened.inbox(&actor("local:501"), true), items);
    assert_eq!(
        reopened.review_states(&actor("local:501"), session(1)),
        states
    );
    assert_eq!(
        reopened.engine().quiet_hours(),
        Some(&quiet_over_noon()),
        "the configured window survives"
    );
    assert_eq!(
        reopened.engine().consumed(AttentionSource::Receipts),
        Some(3),
        "the consumed cursors survive, so a replay is still idempotent"
    );
}

// ----- Log views ---------------------------------------------------------------------------

fn view(id: &str, offset: u64, filter: &str) -> LogViewState {
    LogViewState {
        view_id: id.to_owned(),
        source_offset: U64::new(offset),
        filter: filter.to_owned(),
    }
}

#[test]
fn a_log_view_keeps_its_offset_and_filter_across_a_reconnect() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    {
        let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
        attention
            .acknowledge_visit(
                &actor("local:501"),
                0,
                vec![view("build", 4_096, "level=error")],
            )
            .expect("the store records the visit");
    }
    let reopened = Attention::open(&path, reading(10_000)).expect("the feature store reopens");
    let changed = reopened.changed_since(&actor("local:501"), 100, 0);
    assert_eq!(changed.views.len(), 1);
    assert_eq!(changed.views[0].view.source_offset, U64::new(4_096));
    assert_eq!(changed.views[0].view.filter, "level=error");
    assert!(changed.views[0].gap.as_ref().is_none());
}

#[test]
fn switching_to_another_view_loses_neither_one_s_position() {
    let mut attention = engine();
    attention
        .acknowledge_visit(
            &actor("local:501"),
            0,
            vec![view("build", 10, "level=error")],
        )
        .expect("the store records the visit");
    attention
        .acknowledge_visit(&actor("local:501"), 0, vec![view("deploy", 99, "unit=web")])
        .expect("the store records the visit");
    let changed = attention.changed_since(&actor("local:501"), 100, 0);
    let mut held: Vec<_> = changed
        .views
        .iter()
        .map(|retained| {
            (
                retained.view.view_id.clone(),
                retained.view.source_offset.get(),
                retained.view.filter.clone(),
            )
        })
        .collect();
    held.sort();
    assert_eq!(
        held,
        vec![
            ("build".to_owned(), 10, "level=error".to_owned()),
            ("deploy".to_owned(), 99, "unit=web".to_owned()),
        ]
    );
}

#[test]
fn a_view_whose_range_retention_took_is_served_from_the_oldest_byte_and_told_about_the_gap() {
    let mut attention = engine();
    attention
        .acknowledge_visit(
            &actor("local:501"),
            0,
            vec![view("build", 100, "level=error")],
        )
        .expect("the store records the visit");
    // Retention has moved the oldest readable output past where the view was reading.
    let changed = attention.changed_since(&actor("local:501"), 100, 500);
    let retained = &changed.views[0];
    assert_eq!(retained.view.source_offset, U64::new(500));
    assert_eq!(retained.view.filter, "level=error", "the filter is kept");
    assert_eq!(retained.requested_offset, Nullable::some(U64::new(100)));
    let gap = retained.gap.as_ref().expect("the evicted range is stated");
    assert_eq!(gap.from_cursor, U64::new(100));
    assert_eq!(gap.to_cursor, U64::new(500));
}

// ----- The inbox read ----------------------------------------------------------------------

#[test]
fn the_inbox_read_carries_the_escalation_the_quiet_window_and_the_gaps_together() {
    let mut attention = engine();
    attention
        .set_quiet_hours(Some(quiet_over_noon()), reading(0))
        .expect("the store records the window");
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    attention
        .apply(&approval(9, 9_000, "req-9"), reading(1_000))
        .expect("the store records the decision");
    let read = attention.read(&actor("local:501"), true, reading(1_000));
    assert_eq!(read.items.len(), 2);
    assert!(read.quiet_now);
    assert!(read.quiet_hours_provable);
    assert_eq!(read.gaps.len(), 1);
    assert!(
        read.items
            .iter()
            .all(|item| item.level == AttentionLevel::Urgent),
        "an urgent pending approval stays in the inbox during quiet hours"
    );
    assert!(
        read.items
            .iter()
            .all(|item| item.notification == NotificationState::Deferred),
        "what quiet hours suppress is the audible delivery, not the item"
    );
}
