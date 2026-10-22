//! The worker's observation lane keeps two promises that no timing of a running worker can show
//! deterministically: what it lost comes with the entry it hands over, older than that entry, and a
//! state asked for before a change of privacy mode is not held after it.
//!
//! The first is what keeps a component from being offered an entry newer than a loss before the
//! fresh snapshot the loss owes it. The second is what keeps a state taken before privacy mode was turned
//! on from being kept through it. Both are decided at the lane's own interface, and the cases in
//! kr-controller's `plugin_observation` show the same lane at work in a running worker.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.38 | `kr_req_11_38_what_the_lane_lost_comes_with_the_entry_and_is_older_than_it` |
//! | KR-REQ-24.27 | `kr_req_24_27_a_state_asked_for_before_a_change_of_privacy_mode_is_not_held_after_it` |

use std::sync::Arc;

use kr_protocol::ids::BrokerBindingId;
use kr_protocol::scalars::{Digest256, Uuid};
use kr_worker::broker::observation::{Held, ObservationLane};

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
