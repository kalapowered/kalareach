//! The worker's observation lane keeps promises that no timing of a running worker can show
//! deterministically: what it lost comes with the entry it hands over, older than that entry; a
//! state asked for before a change of privacy mode is not held after it; and the runtime's words are
//! withheld once privacy mode has stood on the connection that carries them.
//!
//! The first is what keeps a component from being offered an entry newer than a loss before the
//! fresh snapshot the loss owes it, and an entry older than a loss from being offered after the
//! snapshot the loss owes. The second is what keeps a state taken before privacy mode was turned on
//! from being kept through it. The third is what keeps words a component made from what it was
//! handed in privacy mode from reaching a report, however late they are read. All are decided at the
//! lane's own interface, and the cases in kr-controller's `plugin_observation` show the same lane at
//! work in a running worker.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.38 | `kr_req_11_38_what_the_lane_lost_comes_with_the_entry_and_is_older_than_it`, `kr_req_11_38_a_loss_goes_with_the_first_entry_newer_than_it` |
//! | KR-REQ-24.27 | `kr_req_24_27_a_state_asked_for_before_a_change_of_privacy_mode_is_not_held_after_it`, `kr_req_24_27_the_runtimes_words_are_withheld_for_the_life_of_a_connection_privacy_mode_has_stood_on` |

use std::sync::Arc;

use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId, PluginId, PublisherId};
use kr_protocol::scalars::{Digest256, Uuid};
use kr_worker::broker::PackageIdentity;
use kr_worker::broker::observation::{Held, NativeFrame, ObservationLane};

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

/// KR-REQ-24.27: a state a component was asked for while privacy mode stood one way is not held
/// once it has stood another, and one asked for under the present standing is.
#[test]
fn kr_req_24_27_a_state_asked_for_before_a_change_of_privacy_mode_is_not_held_after_it() {
    let lane = ObservationLane::new();
    let binding = BrokerBindingId::new(Uuid::from_bytes([7; 16]));
    // A view for the binding, as the link makes one when it registers the component.
    lane.set_ready(binding, true);
    let held = |state: &[u8]| Held {
        package_digest: Digest256::from_bytes([1; 32]),
        generation: 1,
        state: state.to_vec(),
    };

    // Asked for under the present standing: held.
    let epoch = lane.privacy_epoch();
    lane.hold(binding, held(b"before"), epoch);
    assert_eq!(lane.held_checkpoints().0, 1);

    // Asked for, then privacy mode turned on and off before the answer came back: not held.
    let stale = lane.privacy_epoch();
    lane.set_private(true);
    let _fenced = lane.fence();
    lane.set_private(false);
    assert_eq!(
        lane.held_checkpoints(),
        (0, 0),
        "the fence dropped the state"
    );
    lane.hold(binding, held(b"asked before"), stale);
    assert_eq!(
        lane.held_checkpoints(),
        (0, 0),
        "a state asked for before the change was held after it"
    );

    // Asked for after the change: held. A component marked as handed something made in privacy mode
    // is held no state of, however the state was asked for. And never while privacy mode is on.
    lane.hold(binding, held(b"asked after"), lane.privacy_epoch());
    assert_eq!(lane.held_checkpoints().0, 1);
    lane.expose(binding, true);
    lane.hold(binding, held(b"exposed"), lane.privacy_epoch());
    assert_eq!(
        lane.view(binding).map(|view| view.private_content),
        Some(true)
    );
    assert_eq!(
        lane.held_checkpoints().0,
        1,
        "the earlier state is the one held"
    );
    lane.set_private(true);
    lane.hold(binding, held(b"private"), lane.privacy_epoch());
    assert_eq!(
        lane.held_checkpoints().0,
        1,
        "the earlier state stays until the fence"
    );
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
    let binding = BrokerBindingId::new(Uuid::from_bytes([9; 16]));
    lane.expose(binding, true);
    assert!(
        lane.words_withheld(),
        "private content reached a connection that was not withheld"
    );
    lane.began_connection();
    lane.expose(binding, false);
    assert!(
        !lane.words_withheld(),
        "a hand-over of something not made in privacy mode, with it off, withholds nothing"
    );
}
