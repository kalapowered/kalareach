//! The attention engine against section 25's rule set, section 24's reconstruction rule and
//! section 14's binding of a review acknowledgement to a version.

use std::collections::BTreeSet;

use kr_attention::engine::Outcome;
use kr_attention::event::{ApplicationNotice, EventCursor, EventKind, SourceEvent};
use kr_attention::host::summary_of;
use kr_attention::key::DERIVED_MARKER;
use kr_attention::rule::{ADAPTER_ESCALATION_MS, REMINDER_INTERVAL_MS, RULES, rule};
use kr_attention::{Attention, HostReading};
use kr_protocol::attention::{
    AttentionItem, AttentionKey, AttentionLevel, AttentionReadParams, AttentionRouting,
    AttentionRule, AttentionSource, IDLE_REMINDER_MS, LogViewState, MAX_ATTENTION_SUMMARY_LEN,
    MAX_RETAINED_ATTENTION_ITEMS, MAX_RETAINED_LOG_VIEWS, MAX_RETAINED_REVIEW_SUBJECTS,
    NotificationState, QuietHours, ReviewSubject,
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

/// Builds an event `at_ms` after noon, so every recorded moment and every reading are on one
/// clock. A host records an event and reads its own wall clock from the same source; a fixture
/// that mixed two scales would make a five-minute interval look like half a day.
fn event(source: AttentionSource, sequence: u64, at_ms: u64, kind: EventKind) -> SourceEvent {
    SourceEvent::new(
        EventCursor::new(source, sequence),
        TimestampMs::new(NOON + at_ms),
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

fn command(sequence: u64, at_ms: u64, line: &str, exit_code: i32) -> SourceEvent {
    event(
        AttentionSource::Receipts,
        sequence,
        at_ms,
        EventKind::CommandCompleted {
            session_id: session(1),
            command: line.to_owned(),
            exit_code,
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
            pending_since_ms: TimestampMs::new(NOON + pending_since_ms),
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

fn adapter_failed(sequence: u64, at_ms: u64) -> SourceEvent {
    event(
        AttentionSource::Semantic,
        sequence,
        at_ms,
        EventKind::AdapterFailed {
            plugin_id: PluginId::new("git").expect("an identifier"),
            session_id: Some(session(1)),
            detail: "the helper exited".to_owned(),
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

fn whole_inbox(attention: &Attention) -> Vec<AttentionItem> {
    attention.inbox(&actor("local:501"), true)
}

// ----- The rule set ------------------------------------------------------------------------

#[test]
fn every_rule_in_the_set_is_raised_by_the_typed_event_it_covers() {
    let mut attention = engine();
    let mut seen = BTreeSet::new();
    let mut at = 0;
    let events = vec![
        approval(1, 1_000, "req-1"),
        command(2, 2_000, "cargo test", 101),
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
        adapter_failed(2, 5_000),
        event(
            AttentionSource::Semantic,
            3,
            6_000,
            EventKind::HostContactLost {
                detail: "the relay closed".to_owned(),
            },
        ),
        notice(1, 7_000, "build finished", false),
    ];
    for source in events {
        at += 60_001;
        let outcomes = attention
            .apply(&source, reading(at))
            .expect("the store records the decision");
        seen.extend(raised(&outcomes));
    }
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
        .apply(&command(1, 1_000, "true", 0), reading(0))
        .expect("the store records the decision");
    assert!(outcomes.is_empty());
    assert!(whole_inbox(&attention).is_empty());
}

#[test]
fn a_condition_that_ends_leaves_the_inbox() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    assert_eq!(whole_inbox(&attention).len(), 1);
    let outcomes = attention
        .apply(&approval_resolved(2, 2_000, "req-1"), reading(1_000))
        .expect("the store records the decision");
    assert!(matches!(outcomes.as_slice(), [Outcome::Resolved { .. }]));
    assert!(whole_inbox(&attention).is_empty());
}

#[test]
fn a_subject_a_key_cannot_carry_still_reaches_attention() {
    let mut attention = engine();
    let long = "cargo test ".repeat(200);
    attention
        .apply(&command(1, 1_000, "make\nall", 2), reading(0))
        .expect("the store records the decision");
    attention
        .apply(&command(2, 2_000, &long, 3), reading(61_000))
        .expect("the store records the decision");
    attention
        .apply(&notice(1, 3_000, &"body ".repeat(300), false), reading(0))
        .expect("the store records the decision");
    let items = whole_inbox(&attention);
    assert_eq!(items.len(), 3, "nothing was consumed and then dropped");
    for item in &items {
        assert!(
            item.summary.len() <= MAX_ATTENTION_SUMMARY_LEN,
            "the display text is bounded"
        );
    }
    assert!(
        items
            .iter()
            .filter(|item| item.rule == AttentionRule::CommandFailed)
            .all(|item| item.key.as_str().contains(DERIVED_MARKER)),
        "a subject a key cannot carry is derived rather than refused"
    );
}

#[test]
fn a_record_no_rule_covers_moves_the_cursor_and_nothing_else() {
    let mut attention = engine();
    let outcomes = attention
        .apply(
            &event(AttentionSource::Receipts, 1, 1_000, EventKind::Observed),
            reading(0),
        )
        .expect("the store records the decision");
    assert!(outcomes.is_empty());
    assert_eq!(
        attention.engine().consumed(AttentionSource::Receipts),
        Some(1)
    );
    let next = attention
        .apply(&approval(2, 2_000, "req-1"), reading(1_000))
        .expect("the store records the decision");
    assert!(
        !next
            .iter()
            .any(|outcome| matches!(outcome, Outcome::GapRecorded { .. })),
        "a consumed record is not a gap: {next:?}"
    );
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
    let item = whole_inbox(&attention).remove(0);
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
    assert_eq!(whole_inbox(&attention).remove(0).occurrences, U64::new(3));
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
    let item = whole_inbox(&attention).remove(0);
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
    assert_eq!(
        whole_inbox(&attention).remove(0).notification,
        NotificationState::Delivered
    );
}

#[test]
fn a_repeat_that_falls_inside_quiet_hours_is_deferred_once_rather_than_on_every_tick() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    attention
        .set_quiet_hours(Some(quiet_over_noon()), reading(1_000))
        .expect("the store records the window");

    let due = attention
        .tick(reading(REMINDER_INTERVAL_MS))
        .expect("the store records the decision");
    assert!(
        matches!(due.as_slice(), [Outcome::Deferred { .. }]),
        "the repeat is held: {due:?}"
    );
    // The deadline is the end of the window rather than an interval that has already run, so the
    // host waits for the release instead of waking on every tick.
    let deadline = attention
        .engine()
        .next_deadline(reading(REMINDER_INTERVAL_MS))
        .expect("a deferred item waits for the window to end");
    assert!(
        deadline > REMINDER_INTERVAL_MS,
        "the next wake is the release, not an expired repeat"
    );
    for step in 1..4 {
        let again = attention
            .tick(reading(REMINDER_INTERVAL_MS + step))
            .expect("the store records the decision");
        assert!(again.is_empty(), "nothing is re-decided: {again:?}");
    }
}

#[test]
fn an_item_that_escalated_and_was_released_is_announced_once() {
    let mut attention = engine();
    attention
        .set_quiet_hours(Some(quiet_over_noon()), reading(0))
        .expect("the store records the window");
    attention
        .apply(&adapter_failed(1, 1_000), reading(0))
        .expect("the store records the decision");
    // Long enough for the ladder, and past the end of the window.
    let after = HostReading::new(3_600_000, NOON + 3_600_000, true);
    let outcomes = attention
        .tick(after)
        .expect("the store records the decision");
    let announcements = outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                Outcome::Notified { .. } | Outcome::Deferred { .. } | Outcome::Released { .. }
            )
        })
        .count();
    assert_eq!(
        announcements, 1,
        "one decision per item per tick: {outcomes:?}"
    );
    assert!(
        outcomes.iter().any(|outcome| matches!(
            outcome,
            Outcome::Released {
                level: AttentionLevel::Urgent,
                ..
            }
        )),
        "and it goes out at the level the item now stands at: {outcomes:?}"
    );
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
    let read = attention
        .read(&actor("local:501"), &page(), unproven)
        .expect("the page is served");
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
            .apply(&command(sequence, 1_000 + at, "true", 0), reading(at))
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
    let reminder = whole_inbox(&attention)
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
    assert!(whole_inbox(&attention).is_empty());
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
fn an_unattended_adapter_failure_climbs_to_urgent() {
    let mut attention = engine();
    attention
        .apply(&adapter_failed(1, 1_000), reading(0))
        .expect("the store records the decision");
    assert_eq!(
        whole_inbox(&attention).remove(0).level,
        AttentionLevel::Notable
    );

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
}

#[test]
fn one_actor_s_acknowledgement_does_not_silence_the_host_s_reminder() {
    let mut attention = engine();
    attention
        .apply(&adapter_failed(1, 1_000), reading(0))
        .expect("the store records the decision");
    attention
        .acknowledge(
            &actor("device:phone"),
            &[key(AttentionRule::AdapterFailed, "git")],
            reading(1),
        )
        .expect("the store records the acknowledgement");
    let climbed = attention
        .tick(reading(ADAPTER_ESCALATION_MS))
        .expect("the store records the decision");
    assert!(
        climbed.iter().any(|outcome| matches!(
            outcome,
            Outcome::Escalated {
                to: AttentionLevel::Urgent,
                ..
            }
        )),
        "the condition still stands, so the ladder still climbs: {climbed:?}"
    );
    assert_eq!(
        attention.inbox(&actor("local:501"), false).len(),
        1,
        "and another actor still has it to look at"
    );
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
    let item = whole_inbox(&attention).remove(0);
    assert!(!item.trusted, "any process can print one");
    assert_eq!(item.level, AttentionLevel::Informational);
    assert_eq!(item.rule, AttentionRule::ApplicationNotice);
    assert!(
        !whole_inbox(&attention)
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
    assert_eq!(
        whole_inbox(&attention).remove(0).routing,
        AttentionRouting::OwnerPolicy
    );

    let mut attention = engine();
    attention
        .apply(&notice(1, 1_000, "build finished", true), reading(0))
        .expect("the store records the decision");
    assert_eq!(
        whole_inbox(&attention).remove(0).routing,
        AttentionRouting::LeaseHolder,
        "a lease holder is the destination section 8 gives it"
    );
    assert_eq!(
        whole_inbox(&attention).len(),
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
    assert_eq!(
        whole_inbox(&attention).remove(0).level,
        AttentionLevel::Informational
    );
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
    assert_eq!(acknowledged.acknowledged.len(), 1);
    assert_eq!(acknowledged.revision, U64::new(1));
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
    assert!(acknowledged.acknowledged.is_empty());
}

// ----- The inbox bound and its page ---------------------------------------------------------

fn page() -> AttentionReadParams {
    AttentionReadParams {
        session_id: session(1),
        include_acknowledged: true,
        max_items: U64::new(50),
        after: Nullable::null(),
    }
}

#[test]
fn the_inbox_stays_inside_its_bound_and_says_how_much_it_let_go_of() {
    let mut attention = engine();
    let bound = MAX_RETAINED_ATTENTION_ITEMS;
    for index in 0..bound + 10 {
        attention
            .apply(
                &notice(index + 1, 1_000 + index, &format!("notice {index}"), false),
                reading(index * 61_000),
            )
            .expect("the store records the decision");
    }
    let items = whole_inbox(&attention);
    assert_eq!(items.len(), usize::try_from(bound).expect("a small bound"));
    let read = attention
        .read(&actor("local:501"), &page(), reading(0))
        .expect("the page is served");
    assert_eq!(read.dropped, U64::new(10), "and it says what it let go of");
    assert!(
        read.more,
        "a page of fifty is not the whole of five hundred"
    );
    assert_eq!(read.items.len(), 50);
}

#[test]
fn a_page_continues_after_the_key_it_was_given() {
    let mut attention = engine();
    for index in 0..5 {
        attention
            .apply(
                &notice(index + 1, 1_000 + index, &format!("notice {index}"), false),
                reading(index * 61_000),
            )
            .expect("the store records the decision");
    }
    let first = attention
        .read(
            &actor("local:501"),
            &AttentionReadParams {
                max_items: U64::new(2),
                ..page()
            },
            reading(0),
        )
        .expect("the page is served");
    assert_eq!(first.items.len(), 2);
    assert!(first.more);
    let next = attention
        .read(
            &actor("local:501"),
            &AttentionReadParams {
                max_items: U64::new(2),
                after: Nullable::some(first.items[1].key.clone()),
                ..page()
            },
            reading(0),
        )
        .expect("the page is served");
    assert_eq!(next.items.len(), 2);
    assert_ne!(next.items[0].key, first.items[0].key);
    assert_ne!(next.items[0].key, first.items[1].key);
}

#[test]
fn an_urgent_item_outlives_an_informational_one_when_the_bound_bites() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 500, "req-1"), reading(0))
        .expect("the store records the decision");
    let bound = MAX_RETAINED_ATTENTION_ITEMS;
    for index in 0..bound {
        attention
            .apply(
                &notice(index + 1, 1_000 + index, &format!("notice {index}"), false),
                reading((index + 1) * 61_000),
            )
            .expect("the store records the decision");
    }
    assert!(
        whole_inbox(&attention)
            .iter()
            .any(|item| item.rule == AttentionRule::PendingApproval),
        "the oldest item is kept because it is the most urgent"
    );
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
            change_set: Some((ChangeSetId::new(Uuid::from_bytes([5; 16])), version)),
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
    let answer = attention
        .acknowledge_review(&actor("local:501"), &turn_subject(), 1, reading(1_000))
        .expect("the version is one the host holds");
    assert_eq!(
        answer.review.acknowledged_version,
        Nullable::some(U64::new(1))
    );
    assert!(!answer.review.outstanding);
    assert_eq!(answer.revision, U64::new(1));

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
fn completing_a_review_takes_its_waiting_item_out_of_that_actor_s_inbox() {
    let mut attention = engine();
    attention
        .apply(&turn_completed(1, 1_000, 1), reading(0))
        .expect("the store records the decision");
    assert_eq!(attention.inbox(&actor("local:501"), false).len(), 1);
    attention
        .acknowledge_review(&actor("local:501"), &turn_subject(), 1, reading(1_000))
        .expect("the version is one the host holds");
    assert!(
        attention.inbox(&actor("local:501"), false).is_empty(),
        "review state and the inbox say one thing"
    );
    assert_eq!(
        attention.inbox(&actor("device:phone"), false).len(),
        1,
        "and only for the actor that reviewed it"
    );

    attention
        .apply(&turn_completed(2, 200_000, 2), reading(120_000))
        .expect("the store records the decision");
    assert_eq!(
        attention.inbox(&actor("local:501"), false).len(),
        1,
        "a later version is work again"
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
    assert_eq!(
        attention.revision(&actor("local:501")),
        0,
        "a refused acknowledgement records nothing"
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
fn a_change_set_captured_outside_a_turn_is_review_work_of_its_own() {
    let mut attention = engine();
    attention
        .apply(
            &event(
                AttentionSource::Semantic,
                1,
                1_000,
                EventKind::ChangeSetCaptured {
                    session_id: session(1),
                    change_set_id: ChangeSetId::new(Uuid::from_bytes([7; 16])),
                    version: 4,
                    summary: "captured the workspace".to_owned(),
                },
            ),
            reading(0),
        )
        .expect("the store records the decision");
    let subject = ReviewSubject::ChangeSet {
        session_id: session(1),
        change_set_id: ChangeSetId::new(Uuid::from_bytes([7; 16])),
    };
    let state = attention
        .reviews()
        .state(&actor("local:501"), &subject)
        .expect("the change set is a subject");
    assert_eq!(state.current_version, U64::new(4));
    assert!(state.outstanding);
    attention
        .acknowledge_review(&actor("local:501"), &subject, 4, reading(1_000))
        .expect("the version is one the host holds");
}

#[test]
fn a_turn_s_change_set_carries_its_own_version() {
    let mut attention = engine();
    attention
        .apply(
            &event(
                AttentionSource::Semantic,
                1,
                1_000,
                EventKind::TurnCompleted {
                    session_id: session(1),
                    turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
                    version: 2,
                    change_set: Some((ChangeSetId::new(Uuid::from_bytes([5; 16])), 9)),
                    summary: "rewrote the parser".to_owned(),
                },
            ),
            reading(0),
        )
        .expect("the store records the decision");
    let states = attention.review_states(&actor("local:501"), session(1));
    let versions: Vec<_> = states
        .iter()
        .map(|state| state.current_version.get())
        .collect();
    assert_eq!(versions, vec![2, 9], "each subject is at its own version");
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
    assert_eq!(visit.acknowledged_cursor, U64::new(2));
    assert_eq!(visit.revision, U64::new(2), "each visit is a revision");
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

#[test]
fn a_range_a_retained_source_lost_is_shown_in_what_changed_since_a_visit() {
    let mut attention = engine();
    attention
        .apply(&turn_completed(1, 1_000, 1), reading(0))
        .expect("the store records the decision");
    // Semantic sequences two to eight were evicted before the host could read them.
    attention
        .apply(&turn_completed(9, 9_000, 2), reading(120_000))
        .expect("the store records the decision");
    let changed = attention.changed_since(&actor("local:501"), 100, 0);
    let omitted = changed
        .omitted
        .iter()
        .find(|gap| gap.source == AttentionSource::Semantic && gap.from_sequence == U64::new(2))
        .expect("the missing range is stated rather than closed over");
    assert_eq!(omitted.to_sequence, U64::new(9));
    assert!(
        !changed.changes.is_empty(),
        "and what did survive is still shown"
    );

    // An actor that has already visited past the gap is not told about it again.
    attention
        .acknowledge_visit(&actor("local:501"), changed.to_cursor, Vec::new())
        .expect("the store records the visit");
    assert!(
        attention
            .changed_since(&actor("local:501"), 100, 0)
            .omitted
            .is_empty()
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
    let first = whole_inbox(&attention)
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
    let approval_item = whole_inbox(&attention)
        .into_iter()
        .find(|item| item.rule == AttentionRule::PendingApproval)
        .expect("the approval is in the inbox");
    assert!(
        !approval_item.uncertain,
        "a range of terminal notices says nothing about an approval"
    );
    assert_eq!(approval_item.source, AttentionSource::Receipts);
}

#[test]
fn a_first_record_past_the_start_of_a_source_says_what_it_missed() {
    let mut attention = engine();
    let outcomes = attention
        .apply(&approval(9, 9_000, "req-9"), reading(0))
        .expect("the store records the decision");
    let gap = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            Outcome::GapRecorded { gap } => Some(*gap),
            _ => None,
        })
        .expect("the missing prefix is stated");
    assert_eq!(gap.from_sequence, U64::new(1));
    assert_eq!(gap.to_sequence, U64::new(9));

    // A host that knows the engine is starting partway through says so instead.
    let mut attention = engine();
    attention
        .start_from(AttentionSource::Receipts, 8)
        .expect("the store records the cursor");
    let outcomes = attention
        .apply(&approval(9, 9_000, "req-9"), reading(0))
        .expect("the store records the decision");
    assert!(
        !outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::GapRecorded { .. })),
        "nothing was missed: {outcomes:?}"
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
    let once = whole_inbox(&attention);
    let changes_once = attention.changed_since(&actor("local:501"), 100, 0).changes;

    let again = attention
        .rebuild(&events, reading(1_000))
        .expect("the store records the rebuild");
    assert!(again.is_empty(), "nothing was consumed twice: {again:?}");
    assert_eq!(whole_inbox(&attention), once);
    assert_eq!(
        attention.changed_since(&actor("local:501"), 100, 0).changes,
        changes_once
    );
}

#[test]
fn a_rebuild_announces_nothing_and_keeps_each_item_s_own_age() {
    let mut attention = engine();
    // The events are an hour old by the time the host reads them back.
    let now = reading(3_600_000);
    let outcomes = attention
        .rebuild(&replayable_events(), now)
        .expect("the store records the rebuild");
    assert!(
        !outcomes.iter().any(|outcome| matches!(
            outcome,
            Outcome::Notified { .. } | Outcome::Deferred { .. } | Outcome::Released { .. }
        )),
        "history is not a notification: {outcomes:?}"
    );
    for item in whole_inbox(&attention) {
        assert_eq!(item.notification, NotificationState::Pending);
    }
    // And the first tick after it decides what still needs saying.
    let decided = attention.tick(now).expect("the store records the decision");
    assert!(
        decided
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Notified { .. })),
        "the approval that is still outstanding is announced: {decided:?}"
    );
}

#[test]
fn a_rebuild_from_nothing_holds_the_same_items_as_the_live_engine() {
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

    let keys = |attention: &Attention| -> Vec<AttentionKey> {
        whole_inbox(attention)
            .into_iter()
            .map(|item| item.key)
            .collect()
    };
    assert_eq!(keys(&rebuilt), keys(&live));
    assert_eq!(
        rebuilt.review_states(&actor("local:501"), session(1)),
        live.review_states(&actor("local:501"), session(1))
    );
    assert_eq!(
        rebuilt.changed_since(&actor("local:501"), 100, 0).changes,
        live.changed_since(&actor("local:501"), 100, 0).changes
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
        items = whole_inbox(&attention);
        states = attention.review_states(&actor("local:501"), session(1));
        assert_eq!(attention.revision(&actor("local:501")), 2);
    }

    let reopened = Attention::open(&path, reading(10_000)).expect("the feature store reopens");
    assert_eq!(whole_inbox(&reopened), items);
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
    assert_eq!(
        reopened.revision(&actor("local:501")),
        2,
        "and so does the per-actor revision"
    );
}

#[test]
fn an_item_restored_after_a_restart_keeps_the_time_it_had_already_waited() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    {
        let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
        attention
            .apply(&adapter_failed(1, 0), reading(0))
            .expect("the store records the decision");
        assert_eq!(
            whole_inbox(&attention).remove(0).level,
            AttentionLevel::Notable
        );
    }
    // The machine restarted; the failure had already stood for the whole escalation interval.
    let after_restart = HostReading::new(1_000, NOON + ADAPTER_ESCALATION_MS, true);
    let mut reopened = Attention::open(&path, after_restart).expect("the feature store reopens");
    let climbed = reopened
        .tick(after_restart)
        .expect("the store records the decision");
    assert!(
        climbed.iter().any(|outcome| matches!(
            outcome,
            Outcome::Escalated {
                to: AttentionLevel::Urgent,
                ..
            }
        )),
        "the ladder is where the wall clock says it should be: {climbed:?}"
    );
}

#[test]
fn a_write_that_fails_leaves_the_engine_where_it_was() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    let before = whole_inbox(&attention);

    // Somebody else is holding the store for writing.
    let blocker = rusqlite::Connection::open(&path).expect("a second connection");
    blocker
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("the lock is taken");

    let refused = attention.apply(&approval(2, 2_000, "req-2"), reading(61_000));
    assert!(
        refused.is_err(),
        "the write could not happen, so neither could the decision"
    );
    assert_eq!(
        whole_inbox(&attention),
        before,
        "a decision this host could not write down did not happen"
    );
    assert_eq!(
        attention.engine().consumed(AttentionSource::Receipts),
        Some(1),
        "so the same record can be offered again"
    );

    blocker
        .execute_batch("COMMIT")
        .expect("the lock is released");
    let outcomes = attention
        .apply(&approval(2, 2_000, "req-2"), reading(61_000))
        .expect("the store records the decision the second time");
    assert_eq!(
        raised(&outcomes),
        BTreeSet::from([AttentionRule::PendingApproval]),
        "and the retry raises what the refused attempt would have: {outcomes:?}"
    );
}

#[test]
fn a_stored_value_this_build_cannot_read_back_exactly_is_refused() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    {
        let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
        attention
            .apply(&turn_completed(1, 1_000, 1), reading(0))
            .expect("the store records the decision");
    }
    // A version no unsigned reader wrote. Reading it back as nought would close review work the
    // host had not done, so the store refuses it.
    let connection = rusqlite::Connection::open(&path).expect("a second connection");
    connection
        .execute("UPDATE attention_review_subjects SET version = -3", [])
        .expect("the row is written");
    drop(connection);
    assert!(
        Attention::open(&path, reading(0)).is_err(),
        "a value that cannot come back as it went in is refused"
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
fn the_view_a_client_used_last_is_the_one_the_bound_keeps() {
    let mut attention = engine();
    let bound = usize::try_from(MAX_RETAINED_LOG_VIEWS).expect("a small bound");
    for index in 0..bound {
        attention
            .acknowledge_visit(
                &actor("local:501"),
                0,
                vec![view(&format!("view-{index}"), index as u64, "")],
            )
            .expect("the store records the visit");
    }
    // The oldest view is used again, and then one more view is opened.
    attention
        .acknowledge_visit(
            &actor("local:501"),
            0,
            vec![view("view-0", 500, "level=warn")],
        )
        .expect("the store records the visit");
    attention
        .acknowledge_visit(&actor("local:501"), 0, vec![view("view-new", 1, "")])
        .expect("the store records the visit");

    let changed = attention.changed_since(&actor("local:501"), 100, 0);
    let ids: Vec<_> = changed
        .views
        .iter()
        .map(|retained| retained.view.view_id.clone())
        .collect();
    assert_eq!(ids.len(), bound);
    assert!(
        ids.contains(&"view-0".to_owned()),
        "the view the client just used is kept: {ids:?}"
    );
    assert!(
        !ids.contains(&"view-1".to_owned()),
        "the least used one goes"
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

// ----- The delivery handoff -----------------------------------------------------------------

#[test]
fn a_decided_announcement_waits_to_be_taken_and_survives_a_restart() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    {
        let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
        attention
            .apply(&approval(1, 1_000, "req-1"), reading(0))
            .expect("the store records the decision");
        assert_eq!(attention.awaiting_delivery(), 1);
        assert!(whole_inbox(&attention)[0].awaiting_delivery);
    }
    // The host died before it sent anything. The decision is still there to be taken.
    let mut reopened = Attention::open(&path, reading(10_000)).expect("the feature store reopens");
    assert_eq!(reopened.awaiting_delivery(), 1);
    let taken = reopened
        .take_announcements()
        .expect("the store records that they were taken");
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].rule, AttentionRule::PendingApproval);
    assert_eq!(reopened.awaiting_delivery(), 0);
    assert!(!whole_inbox(&reopened)[0].awaiting_delivery);
}

#[test]
fn a_release_quiet_hours_let_through_is_an_announcement_waiting_to_be_taken() {
    let mut attention = engine();
    attention
        .set_quiet_hours(Some(quiet_over_noon()), reading(0))
        .expect("the store records the window");
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    assert_eq!(attention.awaiting_delivery(), 0, "nothing has gone out yet");
    attention
        .set_quiet_hours(None, reading(1_000))
        .expect("the store records the window");
    assert_eq!(
        attention.awaiting_delivery(),
        1,
        "the released announcement is waiting to be taken rather than lost"
    );
}

// ----- Deadlines and escalation across calls -------------------------------------------------

#[test]
fn an_item_nobody_has_decided_about_is_due_now() {
    let mut attention = engine();
    let now = reading(3_600_000);
    attention
        .rebuild(&[approval(1, 1_000, "req-1")], now)
        .expect("the store records the rebuild");
    assert_eq!(
        attention.engine().next_deadline(now),
        Some(now.continuous_ms),
        "a rebuilt item still owes a decision, so the host wakes for it at once"
    );
}

#[test]
fn an_escalation_waits_out_the_de_duplication_window() {
    let mut attention = engine();
    attention
        .apply(&adapter_failed(1, 1_000), reading(0))
        .expect("the store records the decision");
    // The same failure again, one second before the ladder is due, which announces it.
    attention
        .apply(
            &adapter_failed(2, ADAPTER_ESCALATION_MS - 1_000),
            reading(ADAPTER_ESCALATION_MS - 1_000),
        )
        .expect("the store records the decision");

    let climbed = attention
        .tick(reading(ADAPTER_ESCALATION_MS))
        .expect("the store records the decision");
    assert!(
        climbed
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Escalated { .. })),
        "the level moves at once: {climbed:?}"
    );
    assert!(
        notified(&climbed).is_empty(),
        "but the announcement waits out the window: {climbed:?}"
    );
    let deadline = attention
        .engine()
        .next_deadline(reading(ADAPTER_ESCALATION_MS))
        .expect("the held announcement is a deadline");
    assert_eq!(deadline, ADAPTER_ESCALATION_MS - 1_000 + 60_000);
    let due = attention
        .tick(reading(deadline))
        .expect("the store records the decision");
    assert_eq!(notified(&due).len(), 1, "and goes out when it ends");
}

#[test]
fn a_replayed_occurrence_outside_the_window_is_decided_after_the_rebuild() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let later = command(2, 120_000, "cargo test", 101);
    {
        let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
        attention
            .apply(&command(1, 1_000, "cargo test", 101), reading(0))
            .expect("the store records the decision");
        attention
            .take_announcements()
            .expect("the store records that it was taken");
    }
    // The host restarts and replays the retained events, which now include a later failure of the
    // same command. The rule announces once, so nothing but the new occurrence owes a decision.
    let now = reading(180_000);
    let mut reopened = Attention::open(&path, now).expect("the feature store reopens");
    reopened
        .rebuild(&[command(1, 1_000, "cargo test", 101), later], now)
        .expect("the store records the rebuild");
    assert_eq!(
        reopened.engine().next_deadline(now),
        Some(now.continuous_ms),
        "the new occurrence owes a decision"
    );
    let decided = reopened.tick(now).expect("the store records the decision");
    assert_eq!(
        notified(&decided).len(),
        1,
        "and it is announced rather than hidden behind the earlier one: {decided:?}"
    );
}

// ----- Bounds -------------------------------------------------------------------------------

#[test]
fn a_fresh_notice_does_not_displace_an_urgent_approval_merely_by_being_newest() {
    let mut attention = engine();
    let bound = MAX_RETAINED_ATTENTION_ITEMS;
    for index in 0..bound {
        attention
            .apply(
                &approval(index + 1, 1_000 + index, &format!("req-{index}")),
                reading(index * 61_000),
            )
            .expect("the store records the decision");
    }
    assert_eq!(
        whole_inbox(&attention).len(),
        usize::try_from(bound).expect("a small bound")
    );
    let outcomes = attention
        .apply(
            &notice(1, 9_000_000, "build finished", false),
            reading(bound * 61_000),
        )
        .expect("the store records the decision");
    assert!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Dropped { .. })),
        "something had to go: {outcomes:?}"
    );
    assert!(
        !whole_inbox(&attention)
            .iter()
            .any(|item| item.rule == AttentionRule::ApplicationNotice),
        "and the least urgent thing in the inbox is the notice that had just arrived"
    );
}

#[test]
fn a_review_subject_an_inbox_item_still_points_at_is_never_let_go_of() {
    let mut attention = engine();
    // One turn, whose item says it is waiting to be reviewed, and then enough separately captured
    // change sets to take the subject table past its bound.
    attention
        .apply(&turn_completed(1, 1_000, 1), reading(0))
        .expect("the store records the decision");
    for index in 0..MAX_RETAINED_REVIEW_SUBJECTS + 10 {
        let sequence = u64::try_from(index).expect("a small index") + 2;
        attention
            .apply(
                &event(
                    AttentionSource::Semantic,
                    sequence,
                    2_000 + sequence,
                    EventKind::ChangeSetCaptured {
                        session_id: session(1),
                        change_set_id: ChangeSetId::new(Uuid::from_bytes([
                            u8::try_from(index % 251).expect("a byte"),
                            u8::try_from(index / 251).expect("a byte"),
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            0,
                            9,
                        ])),
                        version: 1,
                        summary: "captured the workspace".to_owned(),
                    },
                ),
                reading(0),
            )
            .expect("the store records the decision");
    }
    let state = attention
        .reviews()
        .state(&actor("local:501"), &turn_subject())
        .expect("the turn the inbox still points at is still a subject");
    assert!(state.outstanding);
    attention
        .acknowledge_review(&actor("local:501"), &turn_subject(), 1, reading(1_000))
        .expect("and the review it says is waiting can be completed");
}

#[test]
fn a_page_that_continues_after_a_key_the_inbox_no_longer_holds_is_refused() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    let gone = key(AttentionRule::PendingApproval, "req-gone");
    let refused = attention.read(
        &actor("local:501"),
        &AttentionReadParams {
            after: Nullable::some(gone),
            ..page()
        },
        reading(0),
    );
    assert!(
        refused.is_err(),
        "starting again at the beginning would repeat what the client already has"
    );
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
    let read = attention
        .read(&actor("local:501"), &page(), reading(1_000))
        .expect("the page is served");
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
