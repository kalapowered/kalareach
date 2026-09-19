//! The attention engine against section 25's rule set, section 24's reconstruction rule and
//! section 14's binding of a review acknowledgement to a version.

use std::collections::BTreeSet;

use kr_attention::engine::Outcome;
use kr_attention::event::{ApplicationNotice, EventCursor, EventKind, SourceEvent};
use kr_attention::host::summary_of;
use kr_attention::key::DERIVED_MARKER;
use kr_attention::rule::{ADAPTER_ESCALATION_MS, REMINDER_INTERVAL_MS, RULES, rule};
use kr_attention::{Attention, Content, HostReading};
use kr_protocol::attention::{
    AttentionItem, AttentionKey, AttentionLevel, AttentionReadParams, AttentionRouting,
    AttentionRule, AttentionSource, DEDUPLICATION_WINDOW_MS, IDLE_REMINDER_MS, LogViewState,
    MAX_ATTENTION_SUMMARY_LEN, MAX_RETAINED_ACTORS, MAX_RETAINED_ATTENTION_ITEMS,
    MAX_RETAINED_LOG_VIEWS, MAX_RETAINED_PENDING_INPUTS, MAX_REVIEW_SUBJECTS, NotificationState,
    QuietHours, ReviewState, ReviewSubject,
};
use kr_protocol::ids::{
    ActorId, AgentTurnId, ApprovalRequestId, ChangeSetId, PluginId, QuestionId, SessionId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

/// More review subjects than any page returns, for a test that the table keeps every one of them.
const MANY_SUBJECTS: usize = 510;

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

/// One question per index, distinct however many are asked for.
fn nth_question(index: usize) -> QuestionId {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&u64::try_from(index).expect("a small index").to_be_bytes());
    QuestionId::new(Uuid::from_bytes(bytes))
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

/// The key one rule and one subject land on, derived the way the engine derives it.
fn key(attention: &Attention, id: AttentionRule, subject: &str) -> AttentionKey {
    attention.key_for(id, subject)
}

/// Takes every outstanding announcement and settles it, which is what a delivery consumer does
/// once it has recorded one durably. Until that happens the inbox holds the item the decision
/// belongs to, so a test about the bound settles first.
fn deliver(attention: &mut Attention) {
    let taken: Vec<_> = attention
        .take_announcements()
        .into_iter()
        .map(|one| (one.key, one.number))
        .collect();
    attention
        .settle_announcements(&taken)
        .expect("the store records the settlements");
}

/// The body of the notice this index raises, so a key and its event agree.
fn notice_body(sequence: u64) -> String {
    if sequence == 1 {
        "the first notice".to_owned()
    } else {
        format!("notice {sequence}")
    }
}

/// The key an unidentified notice of session one lands on.
fn notice_key(attention: &Attention, body: &str) -> AttentionKey {
    key(
        attention,
        AttentionRule::ApplicationNotice,
        &format!("{}|{body}", session(1)),
    )
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
    attention.inbox(&actor("local:501"), true, Content::Whole)
}

/// Every review subject of one session, as one page the bound admits.
fn review_states(attention: &Attention, who: &str, in_session: SessionId) -> Vec<ReviewState> {
    attention
        .review_states(&actor(who), in_session, None, MAX_REVIEW_SUBJECTS)
        .expect("a page that starts at the oldest is never a continuation")
        .0
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
            item.summary
                .as_ref()
                .is_some_and(|summary| summary.len() <= MAX_ATTENTION_SUMMARY_LEN),
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
        .set_quiet_hours(Some(quiet_over_noon()))
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
        .set_quiet_hours(Some(quiet_over_noon()))
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
        .set_quiet_hours(Some(quiet_over_noon()))
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
        .set_quiet_hours(Some(quiet_over_noon()))
        .expect("the store records the window");
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    attention
        .set_quiet_hours(None)
        .expect("the store records the window");
    // Clearing the window announces nothing by itself: the release is a timer decision, and the
    // deadline the engine reports while anything is deferred is now.
    assert_eq!(
        attention.engine().next_deadline(reading(1_000)),
        Some(1_000),
        "the host is told to come back at once"
    );
    let released = attention
        .tick(reading(1_000))
        .expect("the store records the decision");
    assert!(matches!(released.as_slice(), [Outcome::Released { .. }]));
}

#[test]
fn quiet_hours_are_not_enforced_on_a_clock_this_host_cannot_prove() {
    let mut attention = engine();
    attention
        .set_quiet_hours(Some(quiet_over_noon()))
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
        .read(&actor("local:501"), &page(), unproven, Content::Whole)
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
                    session_id: session(1),
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
            &[key(&attention, AttentionRule::AdapterFailed, "git")],
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
        attention
            .inbox(&actor("local:501"), false, Content::Whole)
            .len(),
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
            &[key(&attention, AttentionRule::PendingApproval, "req-1")],
            reading(1_000),
        )
        .expect("the store records the acknowledgement");
    assert_eq!(acknowledged.acknowledged.len(), 1);
    assert_eq!(acknowledged.revision, U64::new(1));
    assert!(
        attention
            .inbox(&actor("device:phone"), false, Content::Whole)
            .is_empty()
    );
    assert_eq!(
        attention
            .inbox(&actor("local:501"), false, Content::Whole)
            .len(),
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
            &[key(&attention, AttentionRule::PendingApproval, "req-1")],
            reading(1_000),
        )
        .expect("the store records the acknowledgement");
    assert!(
        attention
            .inbox(&actor("device:phone"), false, Content::Whole)
            .is_empty()
    );
    attention
        .apply(&approval(2, 100_000, "req-1"), reading(90_000))
        .expect("the store records the decision");
    assert_eq!(
        attention
            .inbox(&actor("device:phone"), false, Content::Whole)
            .len(),
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
            &[key(
                &attention,
                AttentionRule::PendingApproval,
                "never-raised",
            )],
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
        // A delivery consumer has recorded each decision, so what is left is a record of a
        // condition rather than work in flight, which is what the bound is a bound on.
        deliver(&mut attention);
    }
    let items = whole_inbox(&attention);
    assert_eq!(items.len(), usize::try_from(bound).expect("a small bound"));
    let read = attention
        .read(&actor("local:501"), &page(), reading(0), Content::Whole)
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
            Content::Whole,
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
            Content::Whole,
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

#[test]
fn the_bound_never_forgets_a_condition_somebody_is_still_waiting_on() {
    let mut attention = engine();
    let bound = MAX_RETAINED_ATTENTION_ITEMS;
    for index in 0..bound + 20 {
        attention
            .apply(
                &approval(index + 1, 1_000 + index, &format!("req-{index}")),
                reading(index * 61_000),
            )
            .expect("the store records the decision");
    }
    let items = whole_inbox(&attention);
    assert_eq!(
        items.len(),
        usize::try_from(bound).expect("a small bound") + 20,
        "the inbox goes over its bound rather than forgetting an unanswered approval"
    );
    assert_eq!(
        attention
            .read(&actor("local:501"), &page(), reading(0), Content::Whole)
            .expect("the page is served")
            .dropped,
        U64::new(0),
        "and nothing was let go of"
    );
}

#[test]
fn a_caller_the_host_cannot_narrow_is_served_the_record_without_the_session_s_text() {
    let mut attention = engine();
    attention
        .apply(
            &command(1, 1_000, "cargo test --workspace", 101),
            reading(0),
        )
        .expect("the store records the decision");
    attention
        .apply(&turn_completed(1, 2_000, 1), reading(61_000))
        .expect("the store records the decision");
    attention
        .summarise(summary_of(
            "the parser was rewritten",
            "local-summariser/1",
            0,
            2,
            TimestampMs::new(NOON + 1_000),
            TimestampMs::new(NOON + 2_000),
        ))
        .expect("the store records the summary");

    let whole = attention.inbox(&actor("device:phone"), true, Content::Whole);
    assert!(whole.iter().all(|item| item.summary.is_present()));
    let narrowed = attention.inbox(&actor("device:phone"), true, Content::Narrowed);
    assert_eq!(narrowed.len(), whole.len(), "the same items");
    for item in &narrowed {
        assert_eq!(item.summary, Nullable::null(), "without the session's text");
        assert!(item.occurrences.get() >= 1, "with the host's own record");
    }

    let changed = attention.changed_since(&actor("device:phone"), 100, 0, Content::Narrowed);
    assert!(!changed.changes.is_empty());
    assert!(
        changed
            .changes
            .iter()
            .all(|change| change.summary == Nullable::null())
    );
    assert!(
        changed.summary.is_none(),
        "and not a paraphrase of it either"
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
    let states = review_states(&attention, "local:501", session(1));
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
    assert_eq!(
        attention
            .inbox(&actor("local:501"), false, Content::Whole)
            .len(),
        1
    );
    attention
        .acknowledge_review(&actor("local:501"), &turn_subject(), 1, reading(1_000))
        .expect("the version is one the host holds");
    assert!(
        attention
            .inbox(&actor("local:501"), false, Content::Whole)
            .is_empty(),
        "review state and the inbox say one thing"
    );
    assert_eq!(
        attention
            .inbox(&actor("device:phone"), false, Content::Whole)
            .len(),
        1,
        "and only for the actor that reviewed it"
    );

    attention
        .apply(&turn_completed(2, 200_000, 2), reading(120_000))
        .expect("the store records the decision");
    assert_eq!(
        attention
            .inbox(&actor("local:501"), false, Content::Whole)
            .len(),
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
    let states = review_states(&attention, "local:501", session(1));
    let mut versions: Vec<_> = states
        .iter()
        .map(|state| state.current_version.get())
        .collect();
    versions.sort_unstable();
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
    let all = attention.changed_since(&actor("local:501"), 100, 0, Content::Whole);
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
    let nothing = attention.changed_since(&actor("local:501"), 100, 0, Content::Whole);
    assert!(nothing.changes.is_empty());
    assert!(nothing.omitted.is_empty());

    attention
        .apply(&turn_completed(4, 4_000, 4), reading(0))
        .expect("the store records the decision");
    let latest = attention.changed_since(&actor("local:501"), 100, 0, Content::Whole);
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
    let changed = attention.changed_since(&actor("local:501"), 100, 0, Content::Whole);
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
    let changed = attention.changed_since(&actor("local:501"), 100, 0, Content::Whole);
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
            .changed_since(&actor("local:501"), 100, 0, Content::Whole)
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
        .find(|item| item.key == key(&attention, AttentionRule::PendingApproval, "req-1"))
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
    let changes_once = attention
        .changed_since(&actor("local:501"), 100, 0, Content::Whole)
        .changes;

    let again = attention
        .rebuild(&events, reading(1_000))
        .expect("the store records the rebuild");
    assert!(again.is_empty(), "nothing was consumed twice: {again:?}");
    assert_eq!(whole_inbox(&attention), once);
    assert_eq!(
        attention
            .changed_since(&actor("local:501"), 100, 0, Content::Whole)
            .changes,
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

    // Two stores derive their keys under two secrets, so what is compared is the conditions the
    // items stand for rather than the names this store happened to give them.
    let conditions = |attention: &Attention| -> Vec<(AttentionRule, String, AttentionLevel)> {
        let mut held: Vec<_> = whole_inbox(attention)
            .into_iter()
            .map(|item| (item.rule, item.summary.0.unwrap_or_default(), item.level))
            .collect();
        held.sort();
        held
    };
    assert_eq!(conditions(&rebuilt), conditions(&live));
    assert_eq!(
        review_states(&rebuilt, "local:501", session(1)),
        review_states(&live, "local:501", session(1))
    );
    assert_eq!(
        rebuilt
            .changed_since(&actor("local:501"), 100, 0, Content::Whole)
            .changes,
        live.changed_since(&actor("local:501"), 100, 0, Content::Whole)
            .changes
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
                &[key(&attention, AttentionRule::PendingApproval, "req-2")],
                reading(1_000),
            )
            .expect("the store records the acknowledgement");
        attention
            .set_quiet_hours(Some(quiet_over_noon()))
            .expect("the store records the window");
        items = whole_inbox(&attention);
        states = review_states(&attention, "local:501", session(1));
        assert_eq!(attention.revision(&actor("local:501")), 2);
    }

    let reopened = Attention::open(&path, reading(10_000)).expect("the feature store reopens");
    assert_eq!(whole_inbox(&reopened), items);
    assert_eq!(review_states(&reopened, "local:501", session(1)), states);
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
        // The producer vouched for the clock its record was stamped on, which is what lets the
        // interval be measured against a later reading rather than started again.
        attention
            .apply(
                &SourceEvent::proven(
                    EventCursor::new(AttentionSource::Semantic, 1),
                    TimestampMs::new(NOON),
                    EventKind::AdapterFailed {
                        plugin_id: PluginId::new("git").expect("an identifier"),
                        session_id: Some(session(1)),
                        detail: "the helper exited".to_owned(),
                    },
                ),
                reading(0),
            )
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
    let changed = reopened.changed_since(&actor("local:501"), 100, 0, Content::Whole);
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
    let changed = attention.changed_since(&actor("local:501"), 100, 0, Content::Whole);
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

    let changed = attention.changed_since(&actor("local:501"), 100, 0, Content::Whole);
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
    let changed = attention.changed_since(&actor("local:501"), 100, 500, Content::Whole);
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
    let taken = reopened.take_announcements();
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].rule, AttentionRule::PendingApproval);
    assert_eq!(
        reopened.awaiting_delivery(),
        1,
        "asking forgets nothing: a consumer that died between the asking and its own record gets \
         the same answer again"
    );
    reopened
        .settle_announcements(&[(taken[0].key.clone(), taken[0].number)])
        .expect("the store records that it was settled");
    assert_eq!(reopened.awaiting_delivery(), 0);
    assert!(!whole_inbox(&reopened)[0].awaiting_delivery);
}

#[test]
fn a_release_quiet_hours_let_through_is_an_announcement_waiting_to_be_taken() {
    let mut attention = engine();
    attention
        .set_quiet_hours(Some(quiet_over_noon()))
        .expect("the store records the window");
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    assert_eq!(attention.awaiting_delivery(), 0, "nothing has gone out yet");
    attention
        .set_quiet_hours(None)
        .expect("the store records the window");
    attention
        .tick(reading(1_000))
        .expect("the store records the decision");
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
        let taken = attention.take_announcements();
        attention
            .settle_announcements(
                &taken
                    .iter()
                    .map(|announcement| (announcement.key.clone(), announcement.number))
                    .collect::<Vec<_>>(),
            )
            .expect("the store records that it was settled");
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
    deliver(&mut attention);
    assert_eq!(
        whole_inbox(&attention).len(),
        usize::try_from(bound).expect("a small bound")
    );
    attention
        .apply(
            &notice(1, 9_000_000, "build finished", false),
            reading(bound * 61_000),
        )
        .expect("the store records the decision");
    // The notice's own decision is taken first: a decision nobody has recorded is work in flight,
    // and weighing the item against the rest is what happens once it is a record of a condition.
    deliver(&mut attention);
    // Past the notice's own de-duplication window, so its item is a record of a condition rather
    // than the only thing that remembers the window.
    let outcomes = attention
        .tick(reading(bound * 61_000 + DEDUPLICATION_WINDOW_MS + 1))
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
    for index in 0..MANY_SUBJECTS {
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

fn change_set_events(count: usize, from: u64) -> Vec<SourceEvent> {
    (0..count)
        .map(|index| {
            let sequence = u64::try_from(index).expect("a small index") + from;
            event(
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
            )
        })
        .collect()
}

#[test]
fn a_turn_whose_name_a_key_cannot_carry_is_protected_like_any_other() {
    // A turn identifier that carries the key's own separator, and one long enough that the key is
    // a digest of it rather than the name itself.
    for name in ["part|two", &"t".repeat(200)] {
        let mut attention = engine();
        let turn_id = AgentTurnId::new(name).expect("an identifier");
        attention
            .apply(
                &event(
                    AttentionSource::Semantic,
                    1,
                    1_000,
                    EventKind::TurnCompleted {
                        session_id: session(1),
                        turn_id: turn_id.clone(),
                        version: 1,
                        change_set: None,
                        summary: "rewrote the parser".to_owned(),
                    },
                ),
                reading(0),
            )
            .expect("the store records the decision");
        for source in change_set_events(MANY_SUBJECTS, 2) {
            attention
                .apply(&source, reading(0))
                .expect("the store records the decision");
        }
        let subject = ReviewSubject::CompletedTurn {
            session_id: session(1),
            turn_id,
        };
        assert!(
            attention
                .reviews()
                .state(&actor("local:501"), &subject)
                .is_some(),
            "{name:?} is still a subject the inbox points at"
        );
    }
}

#[test]
fn a_subject_an_actor_has_acknowledged_is_never_let_go_of() {
    let mut attention = engine();
    let early = ChangeSetId::new(Uuid::from_bytes([200; 16]));
    attention
        .apply(
            &event(
                AttentionSource::Semantic,
                1,
                1_000,
                EventKind::ChangeSetCaptured {
                    session_id: session(1),
                    change_set_id: early,
                    version: 1,
                    summary: "captured the workspace".to_owned(),
                },
            ),
            reading(0),
        )
        .expect("the store records the decision");
    let subject = ReviewSubject::ChangeSet {
        session_id: session(1),
        change_set_id: early,
    };
    attention
        .acknowledge_review(&actor("local:501"), &subject, 1, reading(1_000))
        .expect("the version is one the host holds");

    for source in change_set_events(MANY_SUBJECTS, 2) {
        attention
            .apply(&source, reading(0))
            .expect("the store records the decision");
    }
    let state = attention
        .reviews()
        .state(&actor("local:501"), &subject)
        .expect("what an actor read is still there to be read back");
    assert_eq!(state.acknowledged_version, Nullable::some(U64::new(1)));
}

#[test]
fn one_more_actor_than_the_store_admits_is_refused_rather_than_displacing_one() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    let key = key(&attention, AttentionRule::PendingApproval, "req-1");
    for index in 0..MAX_RETAINED_ACTORS {
        attention
            .acknowledge(
                &actor(&format!("device:{index}")),
                std::slice::from_ref(&key),
                reading(1_000),
            )
            .expect("the store admits it");
    }
    let refused = attention.acknowledge(
        &actor("device:one-too-many"),
        std::slice::from_ref(&key),
        reading(1_000),
    );
    assert!(refused.is_err(), "a new actor past the bound is refused");
    assert_eq!(
        attention.revision(&actor("device:0")),
        1,
        "and nothing an actor already here recorded was deleted to make room"
    );
    attention
        .acknowledge(
            &actor("device:0"),
            std::slice::from_ref(&key),
            reading(2_000),
        )
        .expect("an actor already here is always admitted");
}

#[test]
fn a_page_that_continues_after_a_key_the_inbox_no_longer_holds_is_refused() {
    let mut attention = engine();
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    let gone = key(&attention, AttentionRule::PendingApproval, "req-gone");
    let refused = attention.read(
        &actor("local:501"),
        &AttentionReadParams {
            after: Nullable::some(gone),
            ..page()
        },
        reading(0),
        Content::Whole,
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
        .set_quiet_hours(Some(quiet_over_noon()))
        .expect("the store records the window");
    attention
        .apply(&approval(1, 1_000, "req-1"), reading(0))
        .expect("the store records the decision");
    attention
        .apply(&approval(9, 9_000, "req-9"), reading(1_000))
        .expect("the store records the decision");
    let read = attention
        .read(&actor("local:501"), &page(), reading(1_000), Content::Whole)
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

// ----- What a key carries ---------------------------------------------------------------------

#[test]
fn a_key_carries_none_of_the_text_the_condition_came_from() {
    // A key reaches every caller that may read the inbox at all, including one the host cannot
    // narrow retained content to. So the text a condition came from cannot travel inside it.
    let mut attention = engine();
    let secret = "deploying with token hunter2";
    for source in [
        command(1, 1_000, secret, 101),
        notice(1, 2_000, secret, false),
    ] {
        attention
            .apply(&source, reading(0))
            .expect("the store records the decision");
    }
    let items = whole_inbox(&attention);
    let keys: Vec<_> = items.iter().map(|item| item.key.clone()).collect();
    assert_eq!(keys.len(), 2);
    for key in &keys {
        assert!(
            !key.as_str().contains("hunter2") && !key.as_str().contains("deploying"),
            "the subject does not travel inside its key: {key}"
        );
        let derived = key
            .as_str()
            .split_once('|')
            .expect("a key names its rule")
            .1;
        assert!(derived.starts_with(DERIVED_MARKER));
    }
    // And a caller the host cannot narrow gets neither the text nor a key carrying it.
    let narrowed = attention.inbox(&actor("device:phone"), true, Content::Narrowed);
    assert!(narrowed.iter().all(|item| item.summary.0.is_none()));
    assert!(
        narrowed
            .iter()
            .all(|item| !item.key.as_str().contains("hunter2"))
    );
    // The derivation is still the engine's own, so acknowledging by the key it gave works.
    let command_key = items
        .iter()
        .find(|item| item.rule == AttentionRule::CommandFailed)
        .expect("the command is in the inbox")
        .key
        .clone();
    assert_eq!(
        command_key,
        key(
            &attention,
            AttentionRule::CommandFailed,
            &format!("{}|{secret}", session(1))
        )
    );
}

// ----- Announcement identity ------------------------------------------------------------------

#[test]
fn an_announcement_identity_is_never_given_out_twice() {
    // A condition that ends and comes back is a new item, and its first announcement is not the
    // one a consumer recorded before. Settling the old identity must not settle the new decision.
    let mut attention = engine();
    let lost = |sequence: u64, at_ms: u64| {
        event(
            AttentionSource::Semantic,
            sequence,
            at_ms,
            EventKind::HostContactLost {
                detail: "the relay closed".to_owned(),
            },
        )
    };
    attention
        .apply(&lost(1, 1_000), reading(0))
        .expect("the store records the decision");
    let first = attention.take_announcements();
    assert_eq!(first.len(), 1);
    attention
        .apply(
            &event(
                AttentionSource::Semantic,
                2,
                2_000,
                EventKind::HostContactRestored,
            ),
            reading(1_000),
        )
        .expect("the store records the decision");
    assert_eq!(attention.awaiting_delivery(), 0, "the condition ended");
    attention
        .apply(&lost(3, 3_000), reading(2_000))
        .expect("the store records the decision");
    let second = attention.take_announcements();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].key, first[0].key, "the same condition");
    assert_ne!(
        second[0].number, first[0].number,
        "but not the same decision"
    );

    // The consumer that recorded the first one settles it late. The second is still outstanding.
    attention
        .settle_announcements(&[(first[0].key.clone(), first[0].number)])
        .expect("the store records the settlement");
    assert_eq!(
        attention.awaiting_delivery(),
        1,
        "an identity from before the condition returned settles nothing after it"
    );
    attention
        .settle_announcements(&[(second[0].key.clone(), second[0].number)])
        .expect("the store records the settlement");
    assert_eq!(attention.awaiting_delivery(), 0);
}

#[test]
fn an_announcement_identity_keeps_going_forward_across_a_restart() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let taken;
    {
        let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
        attention
            .apply(&command(1, 1_000, "cargo test", 101), reading(0))
            .expect("the store records the decision");
        taken = attention.take_announcements();
        assert_eq!(taken.len(), 1);
    }
    let mut reopened = Attention::open(&path, reading(10_000)).expect("the feature store reopens");
    reopened
        .apply(&notice(1, 2_000, "build finished", false), reading(10_000))
        .expect("the store records the decision");
    let after = reopened.take_announcements();
    let fresh = after
        .iter()
        .find(|one| one.rule == AttentionRule::ApplicationNotice)
        .expect("the notice decided an announcement");
    assert_ne!(
        fresh.number, taken[0].number,
        "no identity this store has given out comes back after a restart"
    );
}

// ----- What the bound may never let go of -----------------------------------------------------

#[test]
fn a_decision_no_consumer_has_settled_is_never_let_go_of() {
    // A notice is the most droppable thing in the set. One with an announcement nobody has taken
    // is still the only record of that decision, so the bound holds it rather than losing it.
    let mut attention = engine();
    attention
        .apply(&notice(1, 1_000, "the first notice", false), reading(0))
        .expect("the store records the decision");
    let held = notice_key(&attention, "the first notice");
    assert_eq!(attention.awaiting_delivery(), 1);
    let bound = MAX_RETAINED_ATTENTION_ITEMS;
    for sequence in 2..=bound + 10 {
        attention
            .apply(
                &notice(
                    sequence,
                    1_000 + sequence,
                    &format!("notice {sequence}"),
                    false,
                ),
                reading(sequence * 60_001),
            )
            .expect("the store records the decision");
        // Everything after the first is taken and settled at once, so only the first is held.
        let taken = attention.take_announcements();
        let settled: Vec<_> = taken
            .iter()
            .filter(|one| one.key != held)
            .map(|one| (one.key.clone(), one.number))
            .collect();
        attention
            .settle_announcements(&settled)
            .expect("the store records the settlements");
    }
    assert!(
        whole_inbox(&attention).iter().any(|item| item.key == held),
        "the item whose decision nobody has taken is still there"
    );
    assert_eq!(attention.awaiting_delivery(), 1);
}

#[test]
fn a_decision_quiet_hours_are_holding_is_never_let_go_of() {
    let mut attention = engine();
    attention
        .set_quiet_hours(Some(quiet_over_noon()))
        .expect("the store records the window");
    attention
        .apply(&notice(1, 1_000, "the first notice", false), reading(0))
        .expect("the store records the decision");
    let held = notice_key(&attention, "the first notice");
    assert!(
        whole_inbox(&attention)
            .iter()
            .any(|item| item.key == held && item.notification == NotificationState::Deferred),
        "the window is holding its announcement"
    );
    let bound = MAX_RETAINED_ATTENTION_ITEMS;
    for sequence in 2..=bound + 10 {
        attention
            .apply(
                &command(
                    sequence,
                    1_000 + sequence,
                    &format!("cargo test {sequence}"),
                    101,
                ),
                reading(sequence * 60_001),
            )
            .expect("the store records the decision");
    }
    assert!(
        whole_inbox(&attention).iter().any(|item| item.key == held),
        "a held announcement is work in flight, not a record of one"
    );
}

// ----- Review work the host has just been told about ------------------------------------------

#[test]
fn review_work_the_host_has_just_recorded_is_never_the_one_the_bound_lets_go_of() {
    // Every older subject has been read, so none of them may be let go of. The new capture is the
    // only unprotected one, and answering a capture by deleting it would lose review work outright.
    let mut attention = engine();
    let who = actor("local:501");
    let captured = |sequence: u64, byte: u8, version: u64| {
        event(
            AttentionSource::Semantic,
            sequence,
            1_000 + sequence,
            EventKind::ChangeSetCaptured {
                session_id: session(1),
                change_set_id: ChangeSetId::new(Uuid::from_bytes([byte; 16])),
                version,
                summary: "rewrote the parser".to_owned(),
            },
        )
    };
    let bound = u64::try_from(MANY_SUBJECTS).expect("a small bound");
    for sequence in 1..=bound {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&sequence.to_be_bytes());
        let change_set_id = ChangeSetId::new(Uuid::from_bytes(bytes));
        attention
            .apply(
                &event(
                    AttentionSource::Semantic,
                    sequence,
                    1_000 + sequence,
                    EventKind::ChangeSetCaptured {
                        session_id: session(1),
                        change_set_id,
                        version: 1,
                        summary: "rewrote the parser".to_owned(),
                    },
                ),
                reading(sequence),
            )
            .expect("the store records the decision");
        attention
            .acknowledge_review(
                &who,
                &ReviewSubject::ChangeSet {
                    session_id: session(1),
                    change_set_id,
                },
                1,
                reading(sequence),
            )
            .expect("the actor reads it");
    }
    attention
        .apply(&captured(bound + 1, 0xee, 3), reading(bound + 1))
        .expect("the store records the decision");
    let fresh = ReviewSubject::ChangeSet {
        session_id: session(1),
        change_set_id: ChangeSetId::new(Uuid::from_bytes([0xee; 16])),
    };
    let state = attention
        .reviews()
        .state(&who, &fresh)
        .expect("the capture the host was just told about is review work it holds");
    assert_eq!(state.current_version, U64::new(3));
    assert!(state.outstanding);
}

#[test]
fn a_review_read_is_one_bounded_page_that_continues_where_the_last_one_ended() {
    let mut attention = engine();
    let who = actor("local:501");
    let total = MAX_REVIEW_SUBJECTS + 5;
    for sequence in 1..=total {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&sequence.to_be_bytes());
        attention
            .apply(
                &event(
                    AttentionSource::Semantic,
                    sequence,
                    1_000 + sequence,
                    EventKind::ChangeSetCaptured {
                        session_id: session(1),
                        change_set_id: ChangeSetId::new(Uuid::from_bytes(bytes)),
                        version: 1,
                        summary: "rewrote the parser".to_owned(),
                    },
                ),
                reading(sequence),
            )
            .expect("the store records the decision");
    }
    let (first, more) = attention
        .review_states(&who, session(1), None, MAX_REVIEW_SUBJECTS * 4)
        .expect("a page from the oldest");
    assert_eq!(
        first.len(),
        usize::try_from(MAX_REVIEW_SUBJECTS).expect("a small bound"),
        "a caller cannot ask for more than the page bound"
    );
    assert!(more, "and it says there is more");
    let last = first.last().expect("a page").subject.clone();
    let (second, more) = attention
        .review_states(&who, session(1), Some(&last), MAX_REVIEW_SUBJECTS)
        .expect("a page that continues");
    assert_eq!(second.len(), 5);
    assert!(!more, "that is the end of the list");
    assert!(
        second.iter().all(|state| !first.contains(state)),
        "the second page is what the first did not carry"
    );

    // A continuation this session no longer holds is refused rather than restarting the list.
    let unknown = ReviewSubject::ChangeSet {
        session_id: session(1),
        change_set_id: ChangeSetId::new(Uuid::from_bytes([0xfe; 16])),
    };
    assert!(matches!(
        attention.review_states(&who, session(1), Some(&unknown), MAX_REVIEW_SUBJECTS),
        Err(kr_attention::Error::UnknownContinuation { .. })
    ));
}

// ----- What a resolution still knows ----------------------------------------------------------

#[test]
fn a_question_answered_after_its_reminder_record_left_is_still_a_change() {
    // The reminder record is a working set with a bound. The answer is a change since somebody's
    // last visit whether or not that record is still there, so the resolution carries its session.
    let mut attention = engine();
    let bound = MAX_RETAINED_PENDING_INPUTS;
    let first = nth_question(1);
    for index in 1..=bound {
        let sequence = u64::try_from(index).expect("a small index");
        attention
            .apply(
                &pending_question(sequence, sequence, nth_question(index), true, sequence),
                reading(sequence),
            )
            .expect("the store records the decision");
    }
    // Every reminder has been raised, so the oldest record is one the bound may take.
    attention
        .tick(reading(IDLE_REMINDER_MS * 2))
        .expect("the store records the decisions");
    let sequence = u64::try_from(bound).expect("a small bound") + 1;
    attention
        .apply(
            &pending_question(sequence, sequence, nth_question(bound + 1), true, sequence),
            reading(IDLE_REMINDER_MS * 2),
        )
        .expect("the store records the decision");
    assert!(
        !attention.engine().pending_inputs().contains_key(&first),
        "the oldest reminded record is the one the bound took"
    );
    assert!(
        attention.engine().pending_inputs().len() <= bound,
        "the bound held"
    );
    let before = attention
        .changed_since(&actor("local:501"), 500, 0, Content::Whole)
        .changes
        .len();
    attention
        .apply(
            &event(
                AttentionSource::Questions,
                sequence + 1,
                sequence + 1,
                EventKind::QuestionResolved {
                    question_id: first,
                    session_id: session(1),
                    answered: true,
                },
            ),
            reading(IDLE_REMINDER_MS * 3),
        )
        .expect("the store records the decision");
    let after = attention.changed_since(&actor("local:501"), 500, 0, Content::Whole);
    assert_eq!(
        after.changes.len(),
        before + 1,
        "the answer is a change since a visit whatever the reminder record holds"
    );
    assert!(
        after
            .changes
            .iter()
            .any(|change| change.kind
                == kr_protocol::attention::SemanticChangeKind::QuestionAnswered)
    );
}

// ----- What the bound may never let go of, continued ------------------------------------------

#[test]
fn a_condition_nobody_has_decided_about_yet_is_never_let_go_of() {
    // The bound is enforced as an item is raised, before anything has been decided about it. An
    // item that is the only droppable thing there is must still survive that, or the newest
    // condition is the one the inbox always loses.
    let mut attention = engine();
    let bound = MAX_RETAINED_ATTENTION_ITEMS;
    for sequence in 1..=bound {
        attention
            .apply(
                &notice(
                    sequence,
                    1_000 + sequence,
                    &format!("notice {sequence}"),
                    false,
                ),
                reading(sequence * 60_001),
            )
            .expect("the store records the decision");
    }
    // Nothing has been settled, so every item there is protected already.
    assert_eq!(
        attention.awaiting_delivery(),
        usize::try_from(bound).expect("a small bound")
    );
    let newest = notice_key(&attention, "the newest notice");
    attention
        .apply(
            &notice(bound + 1, 2_000 + bound, "the newest notice", false),
            reading((bound + 1) * 60_001),
        )
        .expect("the store records the decision");
    assert!(
        whole_inbox(&attention)
            .iter()
            .any(|item| item.key == newest),
        "the condition that has just arrived is not the one the bound takes"
    );

    // The same holds on the replay path, where nothing is decided until the tick.
    let mut rebuilt = engine();
    let events: Vec<_> = (1..=bound + 1)
        .map(|sequence| {
            notice(
                sequence,
                1_000 + sequence,
                &format!("replayed {sequence}"),
                false,
            )
        })
        .collect();
    rebuilt
        .rebuild(&events, reading(0))
        .expect("the store records the rebuild");
    assert_eq!(
        whole_inbox(&rebuilt).len(),
        usize::try_from(bound).expect("a small bound") + 1,
        "a rebuild decides nothing, so it lets go of nothing"
    );
}

// ----- Review work is not retention's to take -------------------------------------------------

#[test]
fn review_work_survives_every_event_that_follows_it() {
    // Protection that lasted only for the event that recorded a subject would be no protection:
    // the next record of any kind would take it away before a client could read it.
    let mut attention = engine();
    let who = actor("local:501");
    for index in 1..=MANY_SUBJECTS {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&u64::try_from(index).expect("a small index").to_be_bytes());
        let change_set_id = ChangeSetId::new(Uuid::from_bytes(bytes));
        let sequence = u64::try_from(index).expect("a small index");
        attention
            .apply(
                &event(
                    AttentionSource::Semantic,
                    sequence,
                    1_000 + sequence,
                    EventKind::ChangeSetCaptured {
                        session_id: session(1),
                        change_set_id,
                        version: 1,
                        summary: "rewrote the parser".to_owned(),
                    },
                ),
                reading(sequence),
            )
            .expect("the store records the decision");
        attention
            .acknowledge_review(
                &who,
                &ReviewSubject::ChangeSet {
                    session_id: session(1),
                    change_set_id,
                },
                1,
                reading(sequence),
            )
            .expect("the actor reads it");
    }
    let fresh = ChangeSetId::new(Uuid::from_bytes([0xee; 16]));
    let sequence = u64::try_from(MANY_SUBJECTS).expect("a small bound") + 1;
    attention
        .apply(
            &event(
                AttentionSource::Semantic,
                sequence,
                2_000 + sequence,
                EventKind::ChangeSetCaptured {
                    session_id: session(1),
                    change_set_id: fresh,
                    version: 3,
                    summary: "rewrote the parser".to_owned(),
                },
            ),
            reading(sequence),
        )
        .expect("the store records the decision");
    // Any event at all, of any kind, that follows the capture.
    attention
        .apply(
            &event(
                AttentionSource::Semantic,
                sequence + 1,
                2_000 + sequence,
                EventKind::Observed,
            ),
            reading(sequence + 1),
        )
        .expect("the store records the decision");
    let subject = ReviewSubject::ChangeSet {
        session_id: session(1),
        change_set_id: fresh,
    };
    let state = attention
        .reviews()
        .state(&who, &subject)
        .expect("review work the host was told about is review work it still holds");
    assert_eq!(state.current_version, U64::new(3));
    assert!(state.outstanding);
    attention
        .acknowledge_review(&who, &subject, 3, reading(sequence + 2))
        .expect("and it can still be acknowledged");
}

#[test]
fn a_new_version_does_not_move_a_subject_under_a_page_that_is_continuing() {
    // A page continues by the order the host first heard of a subject. Continuing by the recorded
    // moment would skip a subject that moved behind the continuation and repeat one that moved
    // ahead of it.
    let mut attention = engine();
    let who = actor("local:501");
    let first = ChangeSetId::new(Uuid::from_bytes([1; 16]));
    let second = ChangeSetId::new(Uuid::from_bytes([2; 16]));
    let captured = |sequence: u64, at_ms: u64, id: ChangeSetId, version: u64| {
        event(
            AttentionSource::Semantic,
            sequence,
            at_ms,
            EventKind::ChangeSetCaptured {
                session_id: session(1),
                change_set_id: id,
                version,
                summary: "rewrote the parser".to_owned(),
            },
        )
    };
    for source in [captured(1, 1_000, first, 1), captured(2, 2_000, second, 1)] {
        attention
            .apply(&source, reading(0))
            .expect("the store records the decision");
    }
    let (page, more) = attention
        .review_states(&who, session(1), None, 1)
        .expect("a page from the oldest");
    assert_eq!(page.len(), 1);
    assert!(more);
    let after = page[0].subject.clone();

    // The subject the client was just given moves to the newest recorded moment.
    attention
        .apply(&captured(3, 3_000, first, 2), reading(0))
        .expect("the store records the decision");
    let (next, more) = attention
        .review_states(&who, session(1), Some(&after), MAX_REVIEW_SUBJECTS)
        .expect("a page that continues");
    assert!(!more);
    assert_eq!(
        next.len(),
        1,
        "the subject behind the continuation is still served: {next:?}"
    );
    assert!(matches!(
        next[0].subject,
        ReviewSubject::ChangeSet { change_set_id, .. } if change_set_id == second
    ));
}

// ----- What retention may not take from a decision --------------------------------------------

#[test]
fn a_settled_decision_is_kept_until_its_window_has_run() {
    // The item is the whole of what the engine remembers a de-duplication window by. Letting go of
    // one inside its window would announce the same condition twice in under a minute.
    let mut attention = engine();
    let bound = MAX_RETAINED_ATTENTION_ITEMS;
    let first = notice_key(&attention, "the first notice");
    for sequence in 1..=bound + 1 {
        attention
            .apply(
                &notice(sequence, sequence, &notice_body(sequence), false),
                reading(1_000),
            )
            .expect("the store records the decision");
    }
    // Every decision has been recorded by a consumer, so nothing is waiting on delivery.
    deliver(&mut attention);
    let inside = attention
        .tick(reading(2_000))
        .expect("the store records the decision");
    assert!(
        !inside
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Dropped { .. })),
        "nothing is let go of inside its own window: {inside:?}"
    );
    assert!(whole_inbox(&attention).iter().any(|item| item.key == first));

    // Past the window it is a record of a condition, and the bound may have it.
    let outside = attention
        .tick(reading(DEDUPLICATION_WINDOW_MS + 2_000))
        .expect("the store records the decision");
    assert!(
        outside
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Dropped { .. })),
        "and past it the bound bites: {outside:?}"
    );
}

// ----- A record arriving late -----------------------------------------------------------------

#[test]
fn a_turn_version_the_host_already_holds_reopens_no_review_and_announces_nothing() {
    let mut attention = engine();
    let who = actor("local:501");
    attention
        .apply(&turn_completed(1, 1_000, 2), reading(0))
        .expect("the store records the decision");
    let subject = ReviewSubject::CompletedTurn {
        session_id: session(1),
        turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
    };
    attention
        .acknowledge_review(&who, &subject, 2, reading(1_000))
        .expect("the actor reads it");
    assert!(
        attention.inbox(&who, false, Content::Whole).is_empty(),
        "the review is complete, so nothing is waiting for this actor"
    );
    let before = attention
        .changed_since(&who, 500, 0, Content::Whole)
        .changes
        .len();

    // The same turn at a version the host has already passed, arriving late under its own cursor.
    let outcomes = attention
        .apply(&turn_completed(2, 2_000, 1), reading(2_000))
        .expect("the store records the decision");
    assert!(
        raised(&outcomes).is_empty() && notified(&outcomes).is_empty(),
        "a record the host already holds is consumed and nothing else: {outcomes:?}"
    );
    assert!(
        attention.inbox(&who, false, Content::Whole).is_empty(),
        "and the completed review stays complete"
    );
    assert_eq!(
        attention
            .changed_since(&who, 500, 0, Content::Whole)
            .changes
            .len(),
        before,
        "a version nobody moved is not a change since a visit"
    );
    let state = attention
        .reviews()
        .state(&who, &subject)
        .expect("the subject is still there");
    assert_eq!(state.current_version, U64::new(2));
    assert!(!state.outstanding);
    // And it was consumed: the next event is not read as a range retention took.
    assert_eq!(
        attention.engine().consumed(AttentionSource::Semantic),
        Some(2)
    );
}

#[test]
fn a_subject_recorded_after_a_reopen_takes_the_next_place_in_the_page() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let captured = |sequence: u64, byte: u8| {
        event(
            AttentionSource::Semantic,
            sequence,
            1_000 + sequence,
            EventKind::ChangeSetCaptured {
                session_id: session(1),
                change_set_id: ChangeSetId::new(Uuid::from_bytes([byte; 16])),
                version: 1,
                summary: "rewrote the parser".to_owned(),
            },
        )
    };
    {
        let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
        attention
            .apply(&captured(1, 1), reading(0))
            .expect("the store records the decision");
    }
    let mut reopened = Attention::open(&path, reading(1_000)).expect("the feature store reopens");
    reopened
        .apply(&captured(2, 2), reading(1_000))
        .expect("the store records the decision");
    let (page, more) = reopened
        .review_states(&actor("local:501"), session(1), None, MAX_REVIEW_SUBJECTS)
        .expect("a page from the oldest");
    assert!(!more);
    let order: Vec<_> = page
        .iter()
        .map(|state| match &state.subject {
            ReviewSubject::ChangeSet { change_set_id, .. } => *change_set_id,
            ReviewSubject::CompletedTurn { .. } => panic!("a change set was recorded"),
        })
        .collect();
    assert_eq!(
        order,
        vec![
            ChangeSetId::new(Uuid::from_bytes([1; 16])),
            ChangeSetId::new(Uuid::from_bytes([2; 16]))
        ],
        "the one recorded after the reopen takes the place after it, not beside it"
    );
}

// ----- A record arriving late, continued ------------------------------------------------------

/// A turn and its change set at versions of their own, so a late one of each can be told apart.
fn turn_with_change_set(
    sequence: u64,
    at_ms: u64,
    turn_version: u64,
    change_set_version: u64,
) -> SourceEvent {
    event(
        AttentionSource::Semantic,
        sequence,
        at_ms,
        EventKind::TurnCompleted {
            session_id: session(1),
            turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
            version: turn_version,
            change_set: Some((
                ChangeSetId::new(Uuid::from_bytes([5; 16])),
                change_set_version,
            )),
            summary: "rewrote the parser".to_owned(),
        },
    )
}

#[test]
fn a_late_turn_beside_a_newer_change_set_still_records_the_change_set() {
    // Each version an event names is weighed on its own. The turn is a record the host already
    // holds, so nothing about it moves; the change set is one it has not seen, so all of it does.
    for replay in [false, true] {
        let mut attention = engine();
        let who = actor("local:501");
        let first = turn_with_change_set(1, 1_000, 2, 1);
        let late = turn_with_change_set(2, 2_000, 1, 2);
        if replay {
            attention
                .rebuild(std::slice::from_ref(&first), reading(0))
                .expect("the store records the rebuild");
        } else {
            attention
                .apply(&first, reading(0))
                .expect("the store records the decision");
        }
        let change_set = ReviewSubject::ChangeSet {
            session_id: session(1),
            change_set_id: ChangeSetId::new(Uuid::from_bytes([5; 16])),
        };
        attention
            .acknowledge_review(&who, &change_set, 1, reading(1_000))
            .expect("the actor reads it");
        let before = attention
            .changed_since(&who, 500, 0, Content::Whole)
            .changes
            .len();

        if replay {
            attention
                .rebuild(std::slice::from_ref(&late), reading(2_000))
                .expect("the store records the rebuild");
        } else {
            attention
                .apply(&late, reading(2_000))
                .expect("the store records the decision");
        }
        let state = attention
            .reviews()
            .state(&who, &change_set)
            .expect("the change set is a subject the host holds");
        assert_eq!(
            state.current_version,
            U64::new(2),
            "the change set the host had not seen moved, whatever the turn beside it said"
        );
        assert!(state.outstanding, "and it is review work again");
        assert_eq!(
            attention
                .changed_since(&who, 500, 0, Content::Whole)
                .changes
                .len(),
            before + 1,
            "the capture is one change since a visit, and the late turn is none"
        );
        let turn = attention
            .reviews()
            .state(
                &who,
                &ReviewSubject::CompletedTurn {
                    session_id: session(1),
                    turn_id: AgentTurnId::new("turn-1").expect("an identifier"),
                },
            )
            .expect("the turn is still a subject");
        assert_eq!(
            turn.current_version,
            U64::new(2),
            "and the turn did not move"
        );
    }
}

// ----- What a clock nobody could prove may not anchor -----------------------------------------

#[test]
fn an_announcement_stamped_on_an_unprovable_clock_is_not_measured_against_a_proved_one() {
    // The two readings are not on the same scale. Subtracting one from the other could make a
    // two-second-old announcement look an hour old, and the same condition would be announced
    // again inside its own de-duplication window.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    {
        let mut attention = Attention::open(&path, HostReading::new(0, 1_000, false))
            .expect("the feature store opens");
        attention
            .apply(
                &notice(1, 1_000, "build finished", false),
                HostReading::new(10_000, 1_000, false),
            )
            .expect("the store records the decision");
        assert_eq!(attention.awaiting_delivery(), 1, "it went out at once");
    }
    // Two seconds later on the machine's own clock, with the wall clock corrected and proved.
    let mut reopened = Attention::open(&path, HostReading::new(12_000, NOON, true))
        .expect("the feature store reopens");
    let outcomes = reopened
        .tick(HostReading::new(12_000, NOON, true))
        .expect("the store records the decision");
    assert!(
        notified(&outcomes).is_empty(),
        "an interval the host cannot measure starts again rather than reading as an hour: \
         {outcomes:?}"
    );
    let repeated = reopened
        .apply(
            &notice(2, 2_000, "build finished", false),
            HostReading::new(12_500, NOON + 500, true),
        )
        .expect("the store records the decision");
    assert!(
        notified(&repeated).is_empty(),
        "and the same condition inside the window is counted rather than announced: {repeated:?}"
    );
}

// ----- What a clock nobody could prove may not anchor, continued ------------------------------

#[test]
fn a_request_stamped_on_an_unprovable_clock_does_not_come_back_five_minutes_old() {
    // The reminder is measured from the moment the request became pending. A host that could not
    // prove its clock then cannot measure against that moment once it can: the wait starts again,
    // which raises the reminder late rather than the instant the session comes back.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    {
        let mut attention = Attention::open(&path, HostReading::new(0, 1_000, false))
            .expect("the feature store opens");
        attention
            .apply(
                &event(
                    AttentionSource::Questions,
                    1,
                    0,
                    EventKind::QuestionPending {
                        question_id: question(9),
                        session_id: session(1),
                        verified: true,
                        pending_since_ms: TimestampMs::new(1_000),
                        summary: "which branch?".to_owned(),
                    },
                ),
                HostReading::new(10_000, 1_000, false),
            )
            .expect("the store records the decision");
    }
    // Two seconds of the machine's own clock later, with the wall clock corrected an hour ahead.
    let mut reopened = Attention::open(&path, HostReading::new(12_000, 3_603_000, true))
        .expect("the feature store reopens");
    let decided = reopened
        .tick(HostReading::new(12_000, 3_603_000, true))
        .expect("the store records the decision");
    assert!(
        !raised(&decided).contains(&AttentionRule::InputIdleReminder),
        "two seconds is not five minutes, whatever subtracting one clock from the other says: \
         {decided:?}"
    );
    // And the reminder is still owed, at five minutes from where the wait started again.
    let late = reopened
        .tick(HostReading::new(
            12_000 + IDLE_REMINDER_MS + 1,
            3_603_000,
            true,
        ))
        .expect("the store records the decision");
    assert!(
        raised(&late).contains(&AttentionRule::InputIdleReminder),
        "the reminder is late rather than lost: {late:?}"
    );
}

#[test]
fn an_escalation_stamped_on_an_unprovable_clock_does_not_come_back_urgent() {
    // The moments are all noon-relative, so the wrong arithmetic would give an hour rather than a
    // negative number that clamps to nought and passes for the wrong reason.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    {
        let mut attention = Attention::open(&path, HostReading::new(0, NOON, false))
            .expect("the feature store opens");
        attention
            .apply(&adapter_failed(1, 0), HostReading::new(10_000, NOON, false))
            .expect("the store records the decision");
        assert_eq!(whole_inbox(&attention)[0].level, AttentionLevel::Notable);
    }
    let later = NOON + 3_602_000;
    let mut reopened =
        Attention::open(&path, HostReading::new(12_000, later, true)).expect("the store reopens");
    reopened
        .tick(HostReading::new(12_000, later, true))
        .expect("the store records the decision");
    assert_eq!(
        whole_inbox(&reopened)[0].level,
        AttentionLevel::Notable,
        "an adapter that failed two seconds ago has not been down for five minutes"
    );
    // And the escalation is late rather than lost.
    reopened
        .tick(HostReading::new(
            12_000 + ADAPTER_ESCALATION_MS + 1,
            later,
            true,
        ))
        .expect("the store records the decision");
    assert_eq!(whole_inbox(&reopened)[0].level, AttentionLevel::Urgent);
}

#[test]
fn a_moment_no_producer_vouched_for_is_not_measured_against_this_host_s_proved_clock() {
    // The event is consumed for the first time *after* the clock was corrected and proved. Its own
    // moment was taken before that, by a producer that said nothing about its clock, so the two
    // are not on one scale and the wait is measured inside the event instead.
    let mut attention = engine();
    attention
        .apply(
            &event(
                AttentionSource::Questions,
                1,
                0,
                EventKind::QuestionPending {
                    question_id: question(9),
                    session_id: session(1),
                    verified: true,
                    pending_since_ms: TimestampMs::new(NOON),
                    summary: "which branch?".to_owned(),
                },
            ),
            HostReading::new(12_000, NOON + 3_602_000, true),
        )
        .expect("the store records the decision");
    let decided = attention
        .tick(HostReading::new(12_000, NOON + 3_602_000, true))
        .expect("the store records the decision");
    assert!(
        !raised(&decided).contains(&AttentionRule::InputIdleReminder),
        "a wait nobody vouched for is not an hour: {decided:?}"
    );

    // A producer that *can* vouch for its own clock says so, and the wait counts from there.
    let mut vouched = engine();
    vouched
        .apply(
            &SourceEvent::proven(
                EventCursor::new(AttentionSource::Questions, 1),
                TimestampMs::new(NOON),
                EventKind::QuestionPending {
                    question_id: question(9),
                    session_id: session(1),
                    verified: true,
                    pending_since_ms: TimestampMs::new(NOON),
                    summary: "which branch?".to_owned(),
                },
            ),
            HostReading::new(12_000, NOON + 3_602_000, true),
        )
        .expect("the store records the decision");
    let owed = vouched
        .tick(HostReading::new(12_000, NOON + 3_602_000, true))
        .expect("the store records the decision");
    assert!(
        raised(&owed).contains(&AttentionRule::InputIdleReminder),
        "and a wait the producer vouched for is measured from where it started: {owed:?}"
    );
}

#[test]
fn a_store_that_holds_state_and_has_lost_its_key_secret_is_refused() {
    // Every key in it was derived under a secret this build cannot reproduce, so a resolution
    // would look for an item under a name nothing there carries and the condition would stay
    // outstanding for ever. Refusing says so; serving it would not.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    {
        let mut attention = Attention::open(&path, reading(0)).expect("the feature store opens");
        attention
            .apply(&approval(1, 1_000, "req-1"), reading(0))
            .expect("the store records the decision");
    }
    {
        let connection = rusqlite::Connection::open(&path).expect("the store is a database");
        connection
            .execute("DELETE FROM attention_key_secret", [])
            .expect("the row goes");
    }
    assert!(
        matches!(
            Attention::open(&path, reading(1_000)),
            Err(kr_attention::Error::StoreUnreadable { .. })
        ),
        "a store that lost the secret its keys were derived under is refused"
    );
}
