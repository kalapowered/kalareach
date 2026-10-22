//! The worker's observation lane keeps two promises that no timing of a running worker can show
//! deterministically: nothing is handed over while a loss is waiting to be applied, and a state
//! asked for before a change of privacy mode is not held after it.
//!
//! The first is what keeps a component from being offered an entry between a loss and the fresh
//! snapshot the loss owes it. The second is what keeps a state taken before privacy mode was turned
//! on from being kept through it. Both are decided at the lane's own interface, and the cases in
//! kr-controller's `plugin_observation` show the same lane at work in a running worker.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.38 | `kr_req_11_38_a_loss_waiting_to_be_applied_holds_back_every_later_entry` |
//! | KR-REQ-24.27 | `kr_req_24_27_a_state_asked_for_before_a_change_of_privacy_mode_is_not_held_after_it` |

use std::sync::Arc;

use kr_protocol::ids::BrokerBindingId;
use kr_protocol::scalars::{Digest256, Uuid};
use kr_worker::broker::observation::{Held, ObservationLane};

/// A span of terminal output of `bytes` bytes.
fn span(bytes: usize) -> Arc<Vec<u8>> {
    Arc::new(vec![b'x'; bytes])
}

/// KR-REQ-11.38: when the lane loses an entry to make room, the loss is the pump's to apply before
/// it takes anything else. The lane hands over nothing while a loss waits, and hands over the oldest
/// entry it still holds once the loss has been taken.
#[test]
fn kr_req_11_38_a_loss_waiting_to_be_applied_holds_back_every_later_entry() {
    let lane = ObservationLane::new();
    lane.set_wanted(false, true);
    // Five mebibytes into a lane that holds four: the oldest are lost to make room.
    for _ in 0..5 {
        lane.push_terminal(&span(1024 * 1024), 1);
    }
    assert!(lane.account().evicted.events > 0, "the lane lost something");
    assert!(lane.loss_pending());
    assert!(
        lane.take().is_none(),
        "an entry was handed over while a loss was waiting"
    );

    let loss = lane.take_loss().expect("the loss is the pump's to take");
    assert!(loss.terminal.events > 0);
    assert!(!lane.loss_pending());
    let entry = lane
        .take()
        .expect("the lane hands over what it still holds");
    lane.finish(&entry);

    // A loss that arrives while the pump works on the next entry holds the one after it back too.
    let next = lane.take().expect("more is waiting");
    for _ in 0..5 {
        lane.push_terminal(&span(1024 * 1024), 2);
    }
    assert!(lane.loss_pending());
    lane.finish(&next);
    assert!(lane.take().is_none());
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

    // Asked for after the change: held. And never while privacy mode is on.
    lane.hold(binding, held(b"asked after"), lane.privacy_epoch());
    assert_eq!(lane.held_checkpoints().0, 1);
    lane.set_private(true);
    lane.hold(binding, held(b"private"), lane.privacy_epoch());
    assert_eq!(
        lane.held_checkpoints().0,
        1,
        "the earlier state stays until the fence"
    );
}
