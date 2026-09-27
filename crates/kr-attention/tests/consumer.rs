//! The attention engine as a crash-safe consumer of the events it is given.
//!
//! Section 24: consumers persist their cursor and de-duplication state, and fan-out is
//! at-least-once and idempotent. The engine's position is `attention_consumed`, written by the
//! same transaction that writes the items, gaps and counters an event produced, so the position
//! and the effect are one fact. These tests prove it against both ways a consumer fails: it dies
//! after the transaction commits, and the transaction fails part way. The first is a real death:
//! this test binary is run again as a child process that applies an event and ends at once, by
//! `SIGKILL` where there is one, with no release and nothing flushed on the way out.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-24.20 | every `kr_req_24_20_` test here |

use std::path::Path;
use std::process::Command;

use kr_attention::event::{EventCursor, EventKind, SourceEvent};
use kr_attention::{Attention, Claimant, HostReading, Liveness, Origin, Viewer};
use kr_protocol::attention::{AttentionItem, AttentionSource};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{ActorId, QuestionId, SessionId};
use kr_protocol::scalars::{TimestampMs, Uuid};

const NOON: u64 = 12 * 60 * 60 * 1_000;

/// Where the consumer half finds the store it writes.
const STORE: &str = "KR_ATTENTION_CONSUMER_STORE";

/// The name of the consumer half, as the test harness selects it.
const CONSUMER_HALF: &str = "the_consumer_half_of_the_crash_test";

fn boot() -> kr_attention::time::BootMark {
    kr_attention::time::BootMark::from_bytes([7; 16])
}

fn reading(continuous_ms: u64) -> HostReading {
    HostReading::new(boot(), continuous_ms, NOON + continuous_ms, true)
}

fn process(number: u64) -> ProcessStartIdentity {
    ProcessStartIdentity::new(number, ProcessStartSource::LinuxProcStat, 1_000 + number)
}

/// The process the consumer half claims the store as.
fn the_consumer() -> ProcessStartIdentity {
    process(4242)
}

/// The process the host that starts again claims the store as.
fn the_host() -> ProcessStartIdentity {
    process(1)
}

fn unknown(_: &ProcessStartIdentity) -> Liveness {
    Liveness::Unknown
}

/// What the host that starts again is told about the consumer that died: it has ended.
fn the_consumer_has_ended(held: &ProcessStartIdentity) -> Liveness {
    if *held == the_consumer() {
        Liveness::Ended
    } else {
        Liveness::Unknown
    }
}

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn question() -> QuestionId {
    QuestionId::new(Uuid::from_bytes([2; 16]))
}

fn origin() -> Origin {
    Origin::Session(session())
}

/// The question source's event at `sequence`: the question becomes pending.
fn pending(sequence: u64) -> SourceEvent {
    SourceEvent::new(
        EventCursor::in_session(session(), AttentionSource::Questions, sequence),
        TimestampMs::new(NOON),
        EventKind::QuestionPending {
            question_id: question(),
            session_id: session(),
            verified: true,
            pending_since_ms: TimestampMs::new(NOON),
            pending_since_anchor: Some(kr_attention::time::Anchor::new(boot(), 0)),
            summary: "which branch?".to_owned(),
        },
    )
}

/// The question source's event at `sequence`: the question is answered.
fn answered(sequence: u64) -> SourceEvent {
    SourceEvent::new(
        EventCursor::in_session(session(), AttentionSource::Questions, sequence),
        TimestampMs::new(NOON + 2_000),
        EventKind::QuestionResolved {
            question_id: question(),
            session_id: session(),
            answered: true,
        },
    )
}

fn inbox(attention: &Attention) -> Vec<AttentionItem> {
    attention
        .inbox(
            &ActorId::new("local:501").expect("an actor"),
            &Viewer::Owner,
            true,
        )
        .expect("the store is this owner's")
}

fn position(attention: &Attention) -> Option<u64> {
    attention
        .engine()
        .expect("the store is this owner's")
        .consumed(origin(), AttentionSource::Questions)
}

/// The consumer half: applies the first event to the store `KR_ATTENTION_CONSUMER_STORE` names,
/// and dies. It does nothing at all unless the crash test started it.
#[test]
#[ignore = "the consumer half of the crash test, run only as that test's own child process"]
fn the_consumer_half_of_the_crash_test() {
    let Some(path) = std::env::var_os(STORE) else {
        return;
    };
    let mut attention = Attention::open(
        Path::new(&path),
        reading(0),
        &Claimant::new(the_consumer(), &unknown),
    )
    .expect("the consumer opens the store");
    attention
        .apply(&pending(1), reading(0))
        .expect("the event is applied, and its position committed with it");
    // A death, not an ending: nothing is released, nothing is dropped and nothing is flushed.
    die();
}

/// Ends this process the way a crash does: at once, with nothing run on the way out.
#[cfg(unix)]
fn die() -> ! {
    let _ = Command::new("kill")
        .args(["-9", &std::process::id().to_string()])
        .status();
    std::process::abort()
}

/// Ends this process at once, with nothing run on the way out.
#[cfg(not(unix))]
fn die() -> ! {
    std::process::exit(86)
}

#[test]
fn kr_req_24_20_a_consumer_that_dies_after_applying_an_event_applies_it_once() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let consumer = Command::new(std::env::current_exe().expect("this test binary"))
        .args([CONSUMER_HALF, "--exact", "--ignored", "--test-threads=1"])
        .env(STORE, &path)
        .output()
        .expect("the consumer runs");
    assert!(
        !consumer.status.success(),
        "the consumer died rather than finishing: {}: {}{}",
        consumer.status,
        String::from_utf8_lossy(&consumer.stdout),
        String::from_utf8_lossy(&consumer.stderr)
    );

    // The host starts again, and the dead consumer's claim is taken.
    let mut attention = Attention::open(
        &path,
        reading(1_000),
        &Claimant::new(the_host(), &the_consumer_has_ended),
    )
    .expect("the store the dead consumer held is taken");
    assert_eq!(
        position(&attention),
        Some(1),
        "the position committed with the effect survived the death"
    );
    let items = inbox(&attention);
    assert_eq!(items.len(), 1, "and so did the effect");
    let waiting = attention
        .awaiting_delivery()
        .expect("reads the announcements");

    // The source delivers at least once: the event the consumer died after comes again.
    let replayed = attention
        .apply(&pending(1), reading(1_000))
        .expect("the redelivery is taken");
    assert!(
        replayed.is_empty(),
        "a redelivered event changes nothing: {replayed:?}"
    );
    assert_eq!(
        inbox(&attention),
        items,
        "the same item, at the same revision"
    );
    assert_eq!(
        attention
            .awaiting_delivery()
            .expect("reads the announcements"),
        waiting,
        "no new announcement, and the one already decided stays as it was"
    );
    assert_eq!(position(&attention), Some(1));

    // And the next event is applied, once.
    let next = attention
        .apply(&answered(2), reading(2_000))
        .expect("the next event is taken");
    assert!(!next.is_empty(), "the next event is applied");
    assert_eq!(position(&attention), Some(2));
}

#[test]
fn kr_req_24_20_a_write_that_fails_part_way_leaves_neither_the_effect_nor_the_position() {
    // A write changes the position first and the counters after the items. A trigger that
    // refuses the counters row fails the write after the position and the item rows are already
    // changed inside its transaction, and the whole of it goes back: the event is offered again
    // and applied once.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("attention.db");
    let mut attention = Attention::open(&path, reading(0), &Claimant::new(the_host(), &unknown))
        .expect("the store opens");
    rusqlite::Connection::open(&path)
        .expect("a second connection")
        .execute_batch(
            "CREATE TRIGGER refuse_the_counters BEFORE INSERT ON attention_counters
             BEGIN SELECT RAISE(ABORT, 'the counters are refused'); END;",
        )
        .expect("the trigger");
    attention
        .apply(&pending(1), reading(0))
        .expect_err("the write fails part way");
    drop(attention);
    rusqlite::Connection::open(&path)
        .expect("a second connection")
        .execute_batch("DROP TRIGGER refuse_the_counters;")
        .expect("the trigger goes");

    let mut attention =
        Attention::open(&path, reading(1_000), &Claimant::new(the_host(), &unknown))
            .expect("the store opens again");
    assert_eq!(
        position(&attention),
        None,
        "the position went back with the effect"
    );
    assert!(
        inbox(&attention).is_empty(),
        "and the effect went back with the position"
    );
    let applied = attention
        .apply(&pending(1), reading(1_000))
        .expect("the event is taken the next time it is offered");
    assert!(!applied.is_empty(), "and applied then");
    assert_eq!(inbox(&attention).len(), 1);
    assert_eq!(position(&attention), Some(1));
}
