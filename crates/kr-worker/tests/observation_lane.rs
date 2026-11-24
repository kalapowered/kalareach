//! The worker's observation lane keeps promises that no timing of a running worker can show
//! deterministically: what it lost comes with the entry it hands over, older than that entry; and
//! the runtime's words are withheld once privacy mode has stood on the connection that carries
//! them, or a component on it was handed something made in privacy mode.
//!
//! The first is what keeps a component from being offered an entry newer than a loss before the
//! fresh snapshot the loss owes it, and an entry older than a loss from being offered after the
//! snapshot the loss owes. The second is what keeps words a component made from what it was handed
//! in privacy mode from reaching a report, however late they are read. Both are decided at the
//! lane's own interface, and the cases in kr-controller's `plugin_observation` show the same lane
//! at work in a running worker.

use std::sync::Arc;

use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId, PluginId, PublisherId};
use kr_protocol::scalars::{Digest256, Uuid};
use kr_worker::broker::PackageIdentity;
use kr_worker::broker::observation::{NativeFrame, ObservationLane, Outage, Tally};

/// A span of terminal output of `bytes` bytes.
fn span(bytes: usize) -> Arc<Vec<u8>> {
    Arc::new(vec![b'x'; bytes])
}

/// KR-REQ-11.38: what the lane lost comes with the entry it hands over, and it is older than that
/// entry. The pump applies the loss, and takes the snapshot the loss owes, before it offers the
/// entry; what is lost while it does is newer than the entry in hand and comes with the next one.
/// The lane is never left holding entries it will not hand over because it has lost something.
#[test]
fn kr_req_11_38_what_the_lane_lost_comes_with_the_entry_and_is_older_than_it() {
    let lane = ObservationLane::new();
    lane.set_wanted(false, true);
    // Five of a mebibyte into a lane that holds four: the two oldest are lost to make room.
    for _ in 0..5 {
        lane.push_terminal(&span(1024 * 1024), 1);
    }
    let first = lane.take();
    let loss = first.loss.expect("the loss comes with the entry");
    let entry = first
        .entry
        .expect("the lane hands over what it still holds");
    assert_eq!(loss.terminal.events, 2);
    assert_eq!(
        entry.seq(),
        loss.terminal.events,
        "what was lost is exactly what is older than the entry"
    );
    assert_eq!(lane.account().evicted.events, 2);

    // Lost while the entry is in hand: newer than it, so it comes with the next entry.
    for _ in 0..5 {
        lane.push_terminal(&span(1024 * 1024), 2);
    }
    lane.finish(&entry);
    let second = lane.take();
    let later = second
        .loss
        .expect("what was lost since comes with the next");
    let next = second
        .entry
        .expect("an entry is handed over while the lane loses");
    assert!(next.seq() > entry.seq());
    assert_eq!(
        later.terminal.events,
        next.seq() - entry.seq() - 1,
        "every entry between the two was lost, and none was handed over"
    );
    lane.finish(&next);
}

/// A request the upstream is waiting on, of `bytes` bytes: an entry the lane never loses for room.
fn request(bytes: usize) -> NativeFrame {
    NativeFrame {
        instance: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
        package: PackageIdentity {
            plugin_id: PluginId::new("kalareach.codex").expect("a plugin identifier"),
            publisher_id: PublisherId::new("kalareach").expect("a publisher identifier"),
            package_digest: Digest256::from_bytes([5; 32]),
        },
        handle: None,
        request_id: Some("request-1".to_owned()),
        recorded: None,
        bytes: Arc::from(vec![b'r'; bytes]),
    }
}

/// KR-REQ-11.38: a loss goes with the first entry that is newer than it, and waits for one where
/// none is. The lane loses ordinary entries before it loses a request, and refuses an entry larger
/// than itself whatever waits, so a loss can be newer than a request that waits, and the pump must
/// offer that request before it applies such a loss and takes the snapshot the loss owes, not after.
///
/// Three runs, each ending with the lane empty. A request fills the lane and an ordinary entry that
/// does not fit is lost after it: the request comes alone, then the loss. An ordinary entry is pushed
/// out by a request and another does not fit beside it: the first loss comes with the request, the
/// second after it. An entry larger than the lane is refused while an ordinary entry and a request
/// wait, and a later entry pushes the ordinary entry out: what was pushed out comes with the
/// request, what was refused with the entry pushed after it, though the refusal came first.
#[test]
fn kr_req_11_38_a_loss_goes_with_the_first_entry_newer_than_it() {
    const MIB: usize = 1024 * 1024;
    let lane = ObservationLane::new();
    lane.set_wanted(true, true);

    // The request holds three of the lane's four mebibytes, and two more do not fit beside it.
    lane.push_native(request(3 * MIB), 1);
    lane.push_terminal(&span(2 * MIB), 2);
    let first = lane.take();
    assert!(
        first.loss.is_none(),
        "the ordinary entry was lost after the request was pushed: {:?}",
        first.loss
    );
    let waiting = first.entry.expect("the request waits to be handed over");
    assert!(waiting.is_authoritative());
    lane.finish(&waiting);
    let second = lane.take();
    let lost = second
        .loss
        .expect("the loss is handed over once nothing older waits");
    assert_eq!(lost.terminal.events, 1);
    assert!(second.entry.is_none());

    // A request that pushes an ordinary entry out, and then an ordinary entry that does not fit
    // beside it: the first loss is older than the request and comes with it, the second is newer and
    // comes after it.
    lane.push_terminal(&span(3 * MIB), 3);
    lane.push_native(request(2 * MIB), 4);
    lane.push_terminal(&span(3 * MIB), 5);
    let third = lane.take();
    let older = third
        .loss
        .expect("what was pushed out before the request comes with it");
    assert_eq!(older.terminal.events, 1, "{older:?}");
    let handed = third.entry.expect("the request is handed over");
    assert!(handed.is_authoritative());
    lane.finish(&handed);
    let fourth = lane.take();
    let newer = fourth
        .loss
        .expect("what was lost after the request comes after it");
    assert_eq!(newer.terminal.events, 1, "{newer:?}");
    assert!(fourth.entry.is_none());

    // An entry larger than the lane is refused while an ordinary entry and a request wait, and the
    // next entry pushes the ordinary one out. The refusal is the newer loss though it came first.
    lane.push_terminal(&span(3 * MIB), 6);
    lane.push_native(request(MIB / 2), 7);
    lane.push_terminal(&span(5 * MIB), 8);
    lane.push_terminal(&span(MIB), 9);
    let fifth = lane.take();
    let pushed_out = fifth
        .loss
        .expect("the entry pushed out comes with the request");
    assert_eq!(pushed_out.terminal.events, 1, "{pushed_out:?}");
    assert!(pushed_out.terminal.bytes < 4 * MIB as u64, "{pushed_out:?}");
    let request_handed = fifth.entry.expect("the request is handed over");
    assert!(request_handed.is_authoritative());
    lane.finish(&request_handed);
    let sixth = lane.take();
    let refused = sixth
        .loss
        .expect("the refusal comes with the entry pushed after it");
    assert_eq!(refused.terminal.events, 1, "{refused:?}");
    assert!(refused.terminal.bytes > 4 * MIB as u64, "{refused:?}");
    let last = sixth
        .entry
        .expect("the entry pushed after the refusal is handed over");
    assert!(!last.is_authoritative());
    lane.finish(&last);
    let seventh = lane.take();
    assert!(seventh.loss.is_none() && seventh.entry.is_none());
}

/// KR-REQ-24.27: the runtime's words are withheld once privacy mode has been on since the link made
/// the connection, however privacy mode stands later, and until the link makes another; a connection
/// made while privacy mode is on is withheld from its start.
#[test]
fn kr_req_24_27_the_runtimes_words_are_withheld_for_the_life_of_a_connection_privacy_mode_has_stood_on()
 {
    let lane = ObservationLane::new();
    lane.began_connection();
    assert!(!lane.words_withheld(), "no privacy mode, no withholding");

    lane.set_private(true);
    assert!(lane.words_withheld());
    lane.set_private(false);
    assert!(
        lane.words_withheld(),
        "a notice read after privacy mode ended can describe what was handed over while it stood"
    );

    lane.began_connection();
    assert!(
        !lane.words_withheld(),
        "a new connection carries no old notice"
    );

    lane.set_private(true);
    lane.began_connection();
    assert!(
        lane.words_withheld(),
        "a connection made in privacy mode is withheld from its start"
    );
    lane.set_private(false);
    assert!(lane.words_withheld());
    lane.began_connection();
    assert!(!lane.words_withheld());

    // Handing a component something made in privacy mode taints the connection it goes on, however
    // the pump and the link interleaved: the pump may have read what it needed before the link made
    // this connection, and hands the entry over after.
    lane.expose(true);
    assert!(
        lane.words_withheld(),
        "private content reached a connection that was not withheld"
    );
    lane.began_connection();
    lane.expose(false);
    assert!(
        !lane.words_withheld(),
        "a hand-over of something not made in privacy mode, with it off, withholds nothing"
    );
}

/// An upstream frame nobody is waiting on, of `bytes` bytes.
fn news(bytes: usize) -> NativeFrame {
    NativeFrame {
        request_id: None,
        ..request(bytes)
    }
}

fn binding_of(byte: u8) -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([byte; 16]))
}

/// KR-REQ-24.24: a component that starts again holds nothing of what an earlier one missed, so the
/// loss the view held and the snapshot it owed are gone, and what the lane lost since is counted in
/// the outage instead.
#[test]
fn kr_req_24_24_a_component_that_starts_again_owes_no_snapshot_for_what_the_earlier_one_missed() {
    let lane = ObservationLane::new();
    let binding = binding_of(21);
    lane.began_connection();
    lane.set_ready(binding, lane.connection());
    lane.lose(binding, "an observation was passed over".to_owned());
    assert_eq!(lane.view(binding).and_then(|view| view.owes()), Some(1));

    lane.all_not_ready();
    lane.began_connection();
    lane.set_ready_for_rebuild(binding, lane.connection(), 0, 0);
    let view = lane.view(binding).expect("the view stays");
    assert_eq!(view.owes(), None, "a fresh component owes a snapshot");
    assert_eq!(view.loss_note, None);
    assert!(view.ready && view.rebuild_owed);
    assert!(lane.owing(tokio::time::Instant::now()).is_empty());
}

/// KR-REQ-24.24: a binding is registered again, and not for the first time, only while the lane
/// holds a view of it that was ever ready. A view the lane forgot is a first registration.
#[test]
fn kr_req_24_24_a_binding_the_lane_forgot_registers_as_a_first_one() {
    let lane = ObservationLane::new();
    let binding = binding_of(22);
    assert!(!lane.has_been_ready(binding));
    lane.began_connection();
    lane.set_ready(binding, lane.connection());
    assert!(lane.has_been_ready(binding));
    lane.all_not_ready();
    assert!(
        lane.has_been_ready(binding),
        "a runtime lost made the next registration a first one"
    );
    lane.forget(binding);
    assert!(!lane.has_been_ready(binding));
}

/// KR-REQ-24.24: what the pump takes off the lane for a binding whose runtime is away, or whose
/// baseline is owed, is counted by its payload bytes (not the lane's cost for the entry), a request
/// is not counted, and a binding that was never ready is counted nothing.
#[test]
fn kr_req_24_24_what_is_taken_while_the_runtime_is_away_is_counted_by_its_payload_bytes() {
    let lane = ObservationLane::new();
    lane.set_wanted(true, true);
    let binding = binding_of(23);
    let never = binding_of(24);
    lane.began_connection();
    lane.set_ready(binding, lane.connection());
    lane.all_not_ready();
    for _ in 0..3 {
        lane.push_native(news(100), 1);
    }
    lane.push_native(request(400), 1);
    for _ in 0..2 {
        lane.push_terminal(&span(500), 1);
    }
    while let Some(entry) = lane.take().entry {
        let counted = lane.count_passed(binding, &entry);
        assert_eq!(counted, !entry.is_authoritative());
        assert!(!lane.count_passed(never, &entry));
        lane.finish(&entry);
    }
    assert!(lane.count_dropped(
        binding,
        Tally {
            events: 2,
            bytes: 456
        }
    ));
    assert!(!lane.count_dropped(
        never,
        Tally {
            events: 1,
            bytes: 10
        }
    ));

    lane.began_connection();
    lane.set_ready_for_rebuild(binding, lane.connection(), 8, 1);
    let outage = lane.view(binding).expect("the view stays").outage;
    assert_eq!(
        outage,
        Outage {
            passed: Tally {
                events: 3,
                bytes: 300
            },
            terminal: Tally {
                events: 2,
                bytes: 1000
            },
            dropped: Tally {
                events: 2,
                bytes: 200
            },
            decode_queued: 8,
            decode_full: 1,
        }
    );
}

/// KR-REQ-24.24: the baseline is read after every entry older than the component's view has been
/// taken and counted, and before the first entry at or after it is offered, and not while the
/// binding is passed over for a time.
#[test]
fn kr_req_24_24_a_baseline_comes_after_the_older_entries_and_before_the_first_newer_one() {
    let lane = ObservationLane::new();
    lane.set_wanted(true, true);
    let binding = binding_of(25);
    let now = tokio::time::Instant::now();
    lane.began_connection();
    lane.set_ready(binding, lane.connection());
    lane.all_not_ready();
    lane.push_terminal(&span(10), 1);
    lane.push_terminal(&span(10), 1);
    lane.began_connection();
    lane.set_ready_for_rebuild(binding, lane.connection(), 0, 0);
    lane.push_terminal(&span(10), 1);
    let due = |entry: Option<u64>| lane.rebuilds_due(entry, now);
    assert!(
        due(Some(0)).is_empty() && due(Some(1)).is_empty(),
        "before the older entries are taken"
    );
    let connection = lane.connection();
    assert_eq!(due(Some(2)), vec![(binding, connection)]);
    assert_eq!(
        due(None),
        vec![(binding, connection)],
        "where no entry waits"
    );
    lane.go_silent(binding, now);
    assert!(
        due(Some(2)).is_empty(),
        "a binding passed over for a time is not due"
    );
}

/// KR-REQ-24.24: the baseline ends once, hands the outage back to be told, and moves the place from
/// which requests are offered again.
#[test]
fn kr_req_24_24_a_baseline_ends_once_and_hands_the_outage_back() {
    let lane = ObservationLane::new();
    let binding = binding_of(26);
    lane.began_connection();
    lane.set_ready(binding, lane.connection());
    lane.all_not_ready();
    lane.began_connection();
    let connection = lane.connection();
    lane.set_ready_for_rebuild(binding, connection, 2, 0);
    let outage = lane
        .finish_rebuild(binding, 17, connection)
        .expect("a baseline was owed");
    assert_eq!(outage.decode_queued, 2);
    let view = lane.view(binding).expect("the view stays");
    assert!(!view.rebuild_owed);
    assert_eq!(view.recorded_from, 17);
    assert_eq!(view.outage, Outage::default());
    assert_eq!(lane.finish_rebuild(binding, 99, connection), None);
    assert!(
        lane.rebuilds_due(None, tokio::time::Instant::now())
            .is_empty()
    );
}

/// KR-REQ-24.24: a baseline is owed to the registration it began on. A binding registered again on a
/// later connection, or not ready, is owed a baseline of its own, and the end of an earlier one
/// leaves it owed.
#[test]
fn kr_req_24_24_a_baseline_ends_only_for_the_registration_it_began_on() {
    let lane = ObservationLane::new();
    let binding = binding_of(27);
    lane.began_connection();
    lane.set_ready(binding, lane.connection());
    lane.all_not_ready();
    lane.began_connection();
    let first = lane.connection();
    lane.set_ready_for_rebuild(binding, first, 0, 0);
    assert!(lane.rebuild_owed_on(binding, first));

    // The runtime is lost and the component registered again on the next connection.
    lane.all_not_ready();
    assert!(
        !lane.rebuild_owed_on(binding, first) && lane.finish_rebuild(binding, 5, first).is_none(),
        "a component that is gone is owed nothing, and the end of its baseline changes nothing"
    );
    lane.began_connection();
    let second = lane.connection();
    lane.set_ready_for_rebuild(binding, second, 0, 0);
    assert!(
        !lane.rebuild_owed_on(binding, first),
        "the first registration's baseline is not the second's"
    );
    assert_eq!(
        lane.finish_rebuild(binding, 5, first),
        None,
        "the end of the first baseline leaves the second owed"
    );
    assert!(lane.rebuild_owed_on(binding, second));
    assert!(lane.finish_rebuild(binding, 6, second).is_some());
    assert!(!lane.rebuild_owed_on(binding, second));
}
