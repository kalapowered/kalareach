//! The input lane's accounting at the domain: the ledger, the window, the guard of every accepted
//! write, the debt of every queued batch, the lane's registry and its ordered queue.
//!
//! A test plays the terminal's writer by taking what the domain has queued and dropping it, which
//! is what the writer does with a batch it is done with.

use std::time::{Duration, Instant};

use kr_protocol::envelope::{ControlEvent, ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::ids::{AttachmentId, ConnectionId, InputLeaseEpoch};
use kr_protocol::input::InputWriteResult;
use kr_protocol::local::{LaneCredit, LaneWindow};
use kr_protocol::scalars::U64;
use kr_protocol::session::SessionState;

use super::*;
use crate::fence::{Effects, Step};
use crate::input_lane::LaneQueue;
use crate::input_room::{Carried, LANE_WINDOW, ROOM};

/// A domain for a running session, and the identities that hold its lease in turn.
struct Rig {
    input: InputDomain,
    now: Instant,
}

/// One view of the session: an attachment, the connection it came in on, the epoch it holds and the
/// sequence its next write takes.
struct View {
    attachment: AttachmentId,
    connection: ConnectionId,
    epoch: u64,
    sequence: u64,
}

impl View {
    fn new() -> Self {
        Self {
            attachment: AttachmentId::new(kr_ipc::new_uuid()),
            connection: ConnectionId::new(kr_ipc::new_uuid()),
            epoch: 0,
            sequence: 0,
        }
    }
}

impl Rig {
    fn new() -> Self {
        let mut input = InputDomain::new(kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()));
        input.set_state(SessionState::Live);
        Self {
            input,
            now: Instant::now(),
        }
    }

    /// The view takes the keys, as a session takes them for an attachment.
    fn take(&mut self, view: &mut View) {
        self.input.close_framing_for_takeover();
        self.input.acquire(view.attachment, view.connection);
        self.input.end_lease(0);
        self.input.settle_ending(0);
        view.epoch = self.input.epoch();
        view.sequence = 0;
    }

    /// The view lets the keys go.
    fn release(&mut self, view: &View) {
        self.input.release(view.attachment, view.epoch);
        self.input.close_framing_for_takeover();
        self.input.end_lease(0);
        self.input.settle_ending(0);
    }

    /// A lane for the view, bound under its connection.
    fn bind(&mut self, view: &View) -> crate::input_lane::BoundLane {
        self.input
            .bind_lane(view.attachment, view.connection, || Ok(()))
            .expect("the lane binds")
    }

    /// One write of the view's, on the lane when it has one.
    fn write(
        &mut self,
        view: &mut View,
        lane: Option<crate::input_lane::LaneId>,
        bytes: &[u8],
    ) -> Result<Accepted> {
        let accepted = self.input.accept_entering(
            view.attachment,
            view.epoch,
            view.sequence,
            Entering::Bytes(bytes),
            InputAuthority {
                boot_ms: None,
                utc_ms: None,
            },
            self.now,
            lane.map(|lane| crate::input_lane::LaneFrame {
                lane,
                request_id: kr_protocol::ids::RequestId::new(1),
            }),
        )?;
        view.sequence += 1;
        Ok(accepted)
    }

    /// The writer writes everything that is queued, and is done with it.
    fn written(&mut self) -> usize {
        self.input
            .take_pending()
            .iter()
            .filter(|entry| !matches!(entry.batch, InputBatch::LeaseChanged))
            .count()
    }

    /// The sum that admission reads. It stays inside the room for the writes the cases here make; a
    /// held key that its timer has released is counted twice until its batch is done, and one case
    /// shows the sum passing the room by those entries.
    fn committed(&self) -> Cost {
        let ledger = self.input.ledger();
        ledger.held.plus(ledger.reserved).plus(ledger.promised)
    }

    fn assert_within_the_room(&self) {
        let committed = self.committed();
        assert!(
            committed.frames <= ROOM.frames && committed.bytes <= ROOM.bytes,
            "held, reserved and promised pass the room: {committed:?}"
        );
        let ledger = self.input.ledger();
        assert!(
            ledger.reserved.frames + ledger.outstanding.frames <= LANE_WINDOW.frames
                && ledger.reserved.bytes + ledger.outstanding.bytes <= LANE_WINDOW.bytes,
            "the window passes its bound: {ledger:?}"
        );
    }
}

fn credits(queue: &LaneQueue) -> Vec<ControlFrame> {
    queue.drain()
}

fn window_of(frame: &ControlFrame) -> &LaneWindow {
    match frame {
        ControlFrame::Event(ControlEvent::InputWindow(window)) => window,
        other => panic!("not a window event: {other:?}"),
    }
}

/// A local holder that types one key at a time into a program that reads gives the ledger nothing
/// that stays: the promise of each write is given back whole when its batch is done with.
#[test]
fn five_thousand_single_keys_of_a_local_holder_are_all_accepted_and_leave_nothing_held() {
    let mut rig = Rig::new();
    let mut view = View::new();
    rig.take(&mut view);
    for key in 0..5_000_u32 {
        rig.write(&mut view, None, b"k")
            .unwrap_or_else(|error| panic!("key {key} was refused: {error:?}"));
        rig.assert_within_the_room();
        assert_eq!(rig.written(), 1);
    }
    let ledger = rig.input.ledger();
    assert_eq!(ledger.promised, Cost::default(), "{ledger:?}");
    assert_eq!(ledger.held, Cost::default(), "{ledger:?}");
}

/// An Escape is held back by the recogniser and released by its own timer as an entry of its own.
/// Its promise must not be given back when that entry is queued, or the count of what is promised
/// falls below what is owed and admission reads too low.
#[test]
fn five_thousand_single_escapes_thirty_milliseconds_apart_leave_nothing_promised_or_held() {
    let mut rig = Rig::new();
    let mut view = View::new();
    rig.take(&mut view);
    let _ = rig.input.set_bracketed_paste(true);
    for _ in 0..5_000_u32 {
        rig.write(&mut view, None, b"\x1b")
            .expect("the key is accepted");
        assert_ne!(
            rig.input.ledger().promised,
            Cost::default(),
            "a held prefix is promised its later entry"
        );
        rig.now += Duration::from_millis(30);
        let (expired, _) = rig.input.expire_paste_prefix(rig.now);
        assert_eq!(expired, 1, "the timer releases the Escape");
        rig.assert_within_the_room();
        assert_eq!(rig.written(), 1);
    }
    let ledger = rig.input.ledger();
    assert_eq!(ledger.promised, Cost::default(), "{ledger:?}");
    assert_eq!(ledger.held, Cost::default(), "{ledger:?}");
}

/// A guard that is dropped inside a hold of the domain takes no lock and asks for the top-up, which
/// the end of that hold carries out.
#[test]
fn a_guard_dropped_in_a_hold_asks_for_the_top_up() {
    let mut rig = Rig::new();
    let mut view = View::new();
    rig.take(&mut view);
    let _ = rig.input.set_bracketed_paste(true);
    rig.write(&mut view, None, b"\x1b").expect("accepted");
    let room = rig.input.input_room();
    let _ = room.topup().take();
    rig.input.close_framing_for_takeover();
    assert!(
        room.topup().take(),
        "the prefix's guard was dropped by the takeover, which asks for a top-up"
    );
}

/// A top-up reads the flag before the counters, so a give-back that lands after the read asks for
/// another and is never lost.
#[test]
fn the_top_up_clears_its_flag_before_it_reads_the_counters() {
    let mut rig = Rig::new();
    let mut holder = View::new();
    rig.take(&mut holder);
    let lane = rig.bind(&holder);
    rig.write(&mut holder, Some(lane.id), b"k")
        .expect("accepted");
    let room = rig.input.input_room();
    room.topup().request();
    rig.input.top_up();
    assert!(!room.topup().take(), "the top-up took the request");
    // The writer's drop comes after: it lowers the counters and then asks.
    assert_eq!(rig.written(), 1);
    assert!(room.topup().take(), "the give-back asked again");
}

/// A frame within the window's reservation is admitted by that alone, though every other write is
/// refused because the room is otherwise full.
#[test]
fn a_lane_frame_within_the_reservation_is_admitted_when_the_room_is_otherwise_full() {
    let mut rig = Rig::new();
    let mut holder = View::new();
    rig.take(&mut holder);
    let lane = rig.bind(&holder);
    assert_eq!(lane.ready.frames as usize, LANE_WINDOW.frames);
    // Fill every entry the window did not reserve.
    let fill = ROOM.frames - LANE_WINDOW.frames;
    for _ in 0..fill {
        rig.input.queue_input(InputBatch::Reply {
            bytes: b"x".to_vec(),
            expires_at_ms: None,
        });
    }
    assert_eq!(rig.committed().frames, ROOM.frames);
    let mut local = View::new();
    local.epoch = holder.epoch;
    local.attachment = holder.attachment;
    local.sequence = holder.sequence;
    assert!(
        matches!(
            rig.write(&mut local, None, b"k"),
            Err(WorkerError::InputRoomFull { .. })
        ),
        "a write with no reservation finds the room full"
    );
    rig.write(&mut holder, Some(lane.id), b"k")
        .expect("the reservation pays for the lane's frame");
    rig.assert_within_the_room();
}

/// A frame that claims more than what is reserved is a breach: refused with its own words, and the
/// lane ends.
#[test]
fn a_lane_frame_beyond_the_credit_is_a_breach_and_ends_the_lane() {
    let mut rig = Rig::new();
    let mut holder = View::new();
    rig.take(&mut holder);
    let lane = rig.bind(&holder);
    let half = vec![b'a'; LANE_WINDOW.bytes / 2 - 100];
    rig.write(&mut holder, Some(lane.id), &half)
        .expect("within credit");
    rig.write(&mut holder, Some(lane.id), &half)
        .expect("within credit");
    let refused = rig.write(&mut holder, Some(lane.id), &half);
    match refused {
        Err(WorkerError::ResourceUnavailable { detail }) => {
            assert!(detail.contains("lane credit breach"), "{detail}");
        }
        other => panic!("not a breach: {other:?}"),
    }
    assert!(
        rig.write(&mut holder, Some(lane.id), b"k").is_err(),
        "the lane has ended"
    );
    assert_eq!(
        rig.input.ledger().reserved,
        Cost::default(),
        "its window ended with it"
    );
}

/// The sum of held, reserved and promised, which admission reads, can pass the room, and the queue
/// never does. A write whose Escape is held back promises its whole claim, and when the timer
/// releases the Escape the entry it becomes is held beside that promise until the batch is done:
/// one entry too many for each such write. A local write is admitted against the sum, so only the
/// last of them can leave the sum above the room, by one entry; a lane's frames are admitted against
/// the window alone, so each of the thirty-two that the window holds adds one. Held, reserved and
/// promised then read 4,128 against a room of 4,096, and the queue holds 2,048 entries.
#[test]
fn the_sum_the_ledger_reads_passes_the_room_by_one_entry_for_each_expired_prefix_and_the_queue_never_does()
 {
    let mut rig = Rig::new();
    let mut holder = View::new();
    rig.take(&mut holder);
    let _ = rig.input.set_bracketed_paste(true);
    // 2,016 ordinary writes that the writer has not taken: two entries each against the room.
    for index in 0..2_016_u32 {
        rig.write(&mut holder, None, b"k")
            .unwrap_or_else(|error| panic!("write {index} was refused: {error:?}"));
    }
    let lane = rig.bind(&holder);
    assert_eq!(rig.input.ledger().reserved.frames, 64, "the room left");
    // Thirty-two Escapes on the lane, each released by its timer while the writer stands.
    for _ in 0..32 {
        rig.write(&mut holder, Some(lane.id), b"\x1b")
            .expect("the window pays for the Escape");
        rig.now += Duration::from_millis(30);
        let (expired, _) = rig.input.expire_paste_prefix(rig.now);
        assert_eq!(expired, 1, "the timer releases the Escape");
    }
    let ledger = rig.input.ledger();
    // Entries are what runs out here: the bytes of one-byte writes leave most of the room's bytes.
    assert_eq!(ledger.reserved.frames, 0, "{ledger:?}");
    assert_eq!(ledger.free.frames, 0, "{ledger:?}");
    assert_eq!(
        (ledger.held.frames, ledger.promised.frames),
        (2_048, 2_080),
        "{ledger:?}"
    );
    let sum = ledger.held.frames + ledger.reserved.frames + ledger.promised.frames;
    assert_eq!(
        sum,
        ROOM.frames + 32,
        "the sum is over the room by the expired prefixes of the window's frames"
    );
    // What is really queued is what the writer will write, and it is inside the room.
    let queued = rig
        .input
        .pending
        .iter()
        .filter(|entry| {
            matches!(entry, Queued::Batch(carried) if !matches!(carried.batch, InputBatch::LeaseChanged))
        })
        .count();
    assert_eq!(queued, 2_048, "one entry for each write and each Escape");
    assert!(queued <= ROOM.frames);
}

/// A sequence in claim units: after a takeover the old entries stay charged, the new window
/// reserves what is free, 32 minimal frames are accepted, the old entries go, and the frames
/// finish. The window is whole again and never larger.
#[test]
fn a_window_is_never_larger_than_the_bound_whatever_the_stale_entries_do() {
    let mut rig = Rig::new();
    let (mut first, mut second) = (View::new(), View::new());
    rig.take(&mut first);
    let first_lane = rig.bind(&first);
    for _ in 0..8 {
        rig.write(&mut first, Some(first_lane.id), b"k")
            .expect("accepted");
    }
    rig.assert_within_the_room();
    // The takeover. The first view's entries are still queued: they are stale and charged.
    rig.take(&mut second);
    let second_lane = rig.bind(&second);
    rig.assert_within_the_room();
    let reserved = rig.input.ledger().reserved;
    assert_eq!(reserved.frames, LANE_WINDOW.frames, "{reserved:?}");
    for _ in 0..32 {
        rig.write(&mut second, Some(second_lane.id), b"k")
            .expect("accepted");
        rig.assert_within_the_room();
    }
    let ledger = rig.input.ledger();
    assert_eq!(ledger.outstanding.frames, 64, "{ledger:?}");
    assert_eq!(ledger.reserved.frames, 0, "{ledger:?}");
    // The writer reaches the stale entries and everything behind them, and is done.
    let entries = rig.input.take_pending();
    let (stale, current): (Vec<_>, Vec<_>) = entries.into_iter().partition(
        |entry| matches!(entry.batch, InputBatch::Lease { epoch, .. } if epoch == first.epoch),
    );
    drop(stale);
    rig.input.top_up();
    rig.assert_within_the_room();
    assert_eq!(
        rig.input.ledger().reserved.frames,
        0,
        "what was promised to the new frames is still theirs"
    );
    drop(current);
    rig.input.top_up();
    rig.assert_within_the_room();
    let ledger = rig.input.ledger();
    assert_eq!(ledger.outstanding.frames, 0, "{ledger:?}");
    assert_eq!(
        ledger.reserved.frames, LANE_WINDOW.frames,
        "not twice the window: {ledger:?}"
    );
}

/// A stale guard that drops after a takeover lowers the counter of its own window and not the new
/// one's.
#[test]
fn a_stale_guard_dropping_after_a_takeover_leaves_the_new_window_alone() {
    let mut rig = Rig::new();
    let (mut first, mut second) = (View::new(), View::new());
    rig.take(&mut first);
    let first_lane = rig.bind(&first);
    rig.write(&mut first, Some(first_lane.id), b"k")
        .expect("accepted");
    rig.take(&mut second);
    let second_lane = rig.bind(&second);
    for _ in 0..32 {
        rig.write(&mut second, Some(second_lane.id), b"k")
            .expect("accepted");
    }
    let before = rig.input.ledger();
    let entries = rig.input.take_pending();
    let (stale, current): (Vec<_>, Vec<_>) = entries.into_iter().partition(
        |entry| matches!(entry.batch, InputBatch::Lease { epoch, .. } if epoch == first.epoch),
    );
    assert_eq!(stale.len(), 1, "the first view's entry is queued");
    drop(stale);
    rig.input.top_up();
    let after = rig.input.ledger();
    assert_eq!(
        after.outstanding.frames, before.outstanding.frames,
        "{after:?}"
    );
    drop(current);
    rig.assert_within_the_room();
}

/// A batch the machine released behind a session step is held from that step, and queueing it does
/// not charge it again.
#[test]
fn a_batch_released_behind_a_session_step_is_held_from_that_step() {
    let mut rig = Rig::new();
    let removed = AttachmentId::new(kr_ipc::new_uuid());
    let batch = InputBatch::Lease {
        epoch: 1,
        bytes: b"released".to_vec(),
        paste: crate::session::PasteTransition::default(),
        authority_deadline_boot_ms: None,
        authority_utc_deadline_ms: None,
    };
    let applied = rig.input.apply_effects(Effects {
        steps: vec![
            Step::RemoveAttachment {
                attachment: removed,
                discarded: 0,
            },
            Step::Write(Carried::plain(batch)),
        ],
        ..Effects::default()
    });
    assert_eq!(applied.owed.len(), 2);
    assert_eq!(
        rig.input.ledger().held,
        Cost {
            frames: 1,
            bytes: 8
        },
        "counted from the step, before the session carries it out"
    );
    let mut outcome = crate::session::FenceOutcome::default();
    for step in applied.owed {
        let _ = rig.input.carry_out_step(step, &mut outcome);
    }
    assert_eq!(
        rig.input.ledger().held,
        Cost {
            frames: 1,
            bytes: 8
        },
        "not charged twice"
    );
    assert_eq!(rig.written(), 1);
    assert_eq!(rig.input.ledger().held, Cost::default());
}

/// The registry: a bind that names a parent whose withdrawal has begun is refused, a frame of a
/// lane whose parent has been cleared is refused, and replacing a lane leaves the parent alone.
#[test]
fn a_lane_binds_only_under_a_live_parent_and_stops_at_its_withdrawal() {
    let mut rig = Rig::new();
    let mut holder = View::new();
    rig.take(&mut holder);
    let lane = rig.bind(&holder);
    rig.write(&mut holder, Some(lane.id), b"a")
        .expect("accepted before the clear");

    rig.input.close_parent(holder.connection);
    assert!(
        rig.write(&mut holder, Some(lane.id), b"b").is_err(),
        "a frame after the clear is refused"
    );
    assert!(
        rig.input
            .bind_lane(holder.attachment, holder.connection, || Ok(()))
            .is_err(),
        "a bind between the clear and the end of the withdrawal starts refused"
    );
    assert_eq!(
        rig.input.ledger().reserved,
        Cost::default(),
        "the window ended with its lane"
    );
    rig.input.parent_withdrawn(holder.connection);
    rig.input
        .bind_lane(holder.attachment, holder.connection, || Ok(()))
        .expect("the mark is gone once the withdrawal is over");
}

/// What the service's own checks say, inside the same hold, refuses the bind too.
#[test]
fn a_bind_the_service_refuses_inside_the_hold_registers_nothing() {
    let mut rig = Rig::new();
    let view = View::new();
    let refused = rig.input.bind_lane(view.attachment, view.connection, || {
        Err(WorkerError::InvalidArgument("not the parent's".to_owned()))
    });
    assert!(refused.is_err());
    assert_eq!(rig.input.lane_count(), 0);
}

/// A newer lane for the attachment replaces the older, and the window with its outstanding claims
/// passes to it.
#[test]
fn a_newer_lane_replaces_the_older_under_a_live_lease_and_takes_its_window() {
    let mut rig = Rig::new();
    let mut holder = View::new();
    rig.take(&mut holder);
    let older = rig.bind(&holder);
    rig.write(&mut holder, Some(older.id), b"k")
        .expect("accepted");
    let newer = rig.bind(&holder);
    assert_eq!(newer.replaced.len(), 1, "the older lane is told to end");
    assert!(rig.write(&mut holder, Some(older.id), b"k").is_err());
    rig.write(&mut holder, Some(newer.id), b"k")
        .expect("the newer lane has the window");
    rig.assert_within_the_room();
    assert_eq!(rig.input.lane_count(), 1);
}

/// Acquire then bind, bind then acquire: each ends with the holder's lane holding a window, and
/// the answer names the epoch and the holder state first in the queue.
#[test]
fn every_order_of_acquire_and_bind_ends_with_a_window_and_the_answer_first() {
    // Acquire, then bind.
    let mut rig = Rig::new();
    let mut view = View::new();
    rig.take(&mut view);
    let lane = rig.bind(&view);
    assert!(lane.ready.holder);
    assert_eq!(lane.ready.epoch, InputLeaseEpoch::new(view.epoch));
    // Whatever the top-up queues after the bind is behind the answer.
    rig.input.top_up();
    let frames = credits(&lane.queue);
    assert!(
        matches!(frames.first(), Some(ControlFrame::InputLaneReady(_))),
        "{frames:?}"
    );

    // Bind, then acquire.
    let mut rig = Rig::new();
    let mut view = View::new();
    let lane = rig.bind(&view);
    assert!(!lane.ready.holder, "no window before the lease");
    rig.take(&mut view);
    let frames = credits(&lane.queue);
    assert!(
        matches!(frames.first(), Some(ControlFrame::InputLaneReady(_))),
        "{frames:?}"
    );
    let window = window_of(&frames[1]);
    assert!(window.holder);
    assert_eq!(window.epoch, InputLeaseEpoch::new(view.epoch));
    assert_eq!(window.frames as usize, LANE_WINDOW.frames);
}

/// The queue holds a credit back from a sum that is ahead of its window, and adds credits of one
/// epoch that follow that epoch's window state.
#[test]
fn a_credit_joins_a_sum_only_for_its_epoch_and_after_that_epochs_window() {
    let queue = LaneQueue::default();
    let credit = |epoch: u64, frames: u32| LaneCredit {
        epoch: InputLeaseEpoch::new(epoch),
        frames,
        bytes: U64::new(10),
    };
    let window = |epoch: u64| LaneWindow {
        epoch: InputLeaseEpoch::new(epoch),
        holder: true,
        frames: 1,
        bytes: U64::new(1),
        ended: kr_protocol::scalars::Nullable::null(),
    };
    queue.push_credit(credit(1, 2));
    queue.push_credit(credit(1, 3));
    queue.push_window(window(2));
    queue.push_credit(credit(2, 4));
    queue.push_credit(credit(2, 5));
    let frames = queue.drain();
    let shapes: Vec<(&str, u64, u32)> = frames
        .iter()
        .map(|frame| match frame {
            ControlFrame::Event(ControlEvent::InputCredit(c)) => {
                ("credit", c.epoch.get(), c.frames)
            }
            ControlFrame::Event(ControlEvent::InputWindow(w)) => {
                ("window", w.epoch.get(), w.frames)
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        shapes,
        vec![("credit", 1, 5), ("window", 2, 1), ("credit", 2, 9)]
    );
}

/// The ended notice of an epoch follows the answers of that epoch, in the order the domain changed.
#[test]
fn the_ended_notice_follows_a_late_answer_of_the_same_epoch() {
    let mut rig = Rig::new();
    let (mut first, mut second) = (View::new(), View::new());
    rig.take(&mut first);
    let lane = rig.bind(&first);
    let _ = lane.queue.drain();
    rig.write(&mut first, Some(lane.id), b"k")
        .expect("accepted");
    rig.input.lane_answer(
        lane.id,
        ControlFrame::Response(Response {
            request_id: kr_protocol::ids::RequestId::new(1),
            outcome: Outcome::Ok(
                ParamsValue::from_typed(&InputWriteResult {
                    sequence: kr_protocol::ids::InputSequence::new(0),
                    forwarded_bytes: U64::new(1),
                    held_prefix_bytes: U64::new(0),
                })
                .expect("encodes"),
            ),
        }),
    );
    rig.take(&mut second);
    let frames = lane.queue.drain();
    assert!(
        matches!(
            &frames[0],
            ControlFrame::Response(Response {
                outcome: Outcome::Ok(_),
                ..
            })
        ),
        "the answer first: {frames:?}"
    );
    let ended = window_of(&frames[1]);
    assert!(!ended.holder);
    assert_eq!(
        ended.ended.as_ref().map(|ended| ended.epoch),
        Some(InputLeaseEpoch::new(first.epoch))
    );
}

/// A release that leaves nobody holding ends the window and returns what it reserved.
#[test]
fn a_release_returns_the_reservation_to_the_room() {
    let mut rig = Rig::new();
    let mut view = View::new();
    rig.take(&mut view);
    let _lane = rig.bind(&view);
    assert_ne!(rig.input.ledger().reserved, Cost::default());
    rig.release(&view);
    assert_eq!(rig.input.ledger().reserved, Cost::default());
}

/// What a give-back that lands on another thread while a top-up runs leaves behind. The writer's
/// give-back takes no lock: it lowers the counters and then asks for a top-up. A top-up that read the
/// counters and only then cleared the request would erase a request made in between, and the window
/// would stay smaller than it should be with nothing left to ask for it. The task that serves the
/// requests runs a top-up whenever one is due, so once the writer is done and the last request has
/// been served the window is whole.
#[test]
fn a_give_back_on_another_thread_while_a_top_up_runs_is_never_lost() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    for _ in 0..4_000 {
        let mut rig = Rig::new();
        let mut view = View::new();
        rig.take(&mut view);
        let lane = rig.bind(&view);
        for _ in 0..3 {
            rig.write(&mut view, Some(lane.id), b"k").expect("accepted");
        }
        let batches = rig.input.take_pending();
        let room = rig.input.input_room();
        let shared = InputShared::new(rig.input);
        let finished = Arc::new(AtomicBool::new(false));
        let task = {
            let (shared, room, finished) = (
                Arc::clone(&shared),
                Arc::clone(&room),
                Arc::clone(&finished),
            );
            std::thread::spawn(move || {
                while !finished.load(Ordering::Acquire) {
                    if room.topup().is_due() {
                        shared.lock().top_up();
                    }
                }
            })
        };
        let writer = std::thread::spawn(move || {
            for batch in batches {
                std::thread::yield_now();
                drop(batch);
            }
        });
        writer.join().expect("the writer ran");
        finished.store(true, Ordering::Release);
        task.join().expect("the task ran");
        // The task's last pass serves a request that was made after its loop looked.
        if room.topup().is_due() {
            shared.lock().top_up();
        }
        let ledger = shared.lock().ledger();
        assert_eq!(
            ledger.reserved, LANE_WINDOW,
            "a give-back was lost: the window is smaller than the bound with every claim done with"
        );
    }
}

/// Credit never joins a sum of another epoch, and never joins past a window state of its own epoch:
/// what the host reads is each epoch's credit behind that epoch's window.
#[test]
fn a_credit_never_joins_across_epochs_or_past_a_window_state_of_its_own_epoch() {
    let queue = LaneQueue::default();
    let credit = |epoch: u64| LaneCredit {
        epoch: InputLeaseEpoch::new(epoch),
        frames: 1,
        bytes: U64::new(1),
    };
    let window = |epoch: u64| LaneWindow {
        epoch: InputLeaseEpoch::new(epoch),
        holder: true,
        frames: 1,
        bytes: U64::new(1),
        ended: kr_protocol::scalars::Nullable::null(),
    };
    queue.push_credit(credit(1));
    queue.push_credit(credit(2));
    queue.push_window(window(2));
    queue.push_credit(credit(2));
    let shapes: Vec<(&str, u64, u32)> = queue
        .drain()
        .iter()
        .map(|frame| match frame {
            ControlFrame::Event(ControlEvent::InputCredit(c)) => {
                ("credit", c.epoch.get(), c.frames)
            }
            ControlFrame::Event(ControlEvent::InputWindow(w)) => {
                ("window", w.epoch.get(), w.frames)
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        shapes,
        vec![
            ("credit", 1, 1),
            ("credit", 2, 1),
            ("window", 2, 1),
            ("credit", 2, 1)
        ]
    );
}

/// A give-back made outside any hold, as the writer makes it, is carried out by the end of the next
/// hold: the window is whole again and the host is told, with no top-up asked for by anyone else.
#[test]
fn the_end_of_a_hold_gives_the_window_back_what_a_drop_outside_a_hold_returned() {
    let mut rig = Rig::new();
    let mut view = View::new();
    rig.take(&mut view);
    let lane = rig.bind(&view);
    rig.write(&mut view, Some(lane.id), b"k").expect("accepted");
    let batches = rig.input.take_pending();
    let shared = InputShared::new(rig.input);
    lane.queue.drain();
    drop(batches);
    // The ledger is read inside the hold, and the hold's end then carries the request out.
    let during = shared.lock().ledger();
    assert!(
        during.reserved.frames < LANE_WINDOW.frames,
        "the window was already whole before the end of a hold"
    );
    assert_eq!(shared.lock().ledger().reserved, LANE_WINDOW);
    let told = lane.queue.drain();
    assert!(
        told.iter().any(|frame| matches!(
            frame,
            ControlFrame::Event(ControlEvent::InputCredit(credit)) if credit.frames == 2
        )),
        "the host was not told of the credit: {told:?}"
    );
}
