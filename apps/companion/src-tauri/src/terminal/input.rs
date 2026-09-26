//! What a raw terminal view sends the program it shows: control of the session's input, the wheel,
//! and keys.
//!
//! Control is the session's single input lease (section 8). A view takes it only when the person
//! asks, and taking it is an immediate takeover: whoever held it loses it, without being asked. The
//! view gives it back when the person looks around, when the view closes or ends, and at the first
//! write the session refuses. Every write carries the lease's epoch and the next number of the
//! view's ordered input stream, and once a write of an epoch is refused the view never writes under
//! that epoch again: some refusals take the write's number and some do not, so the stream's next
//! number is no longer known. Taking control again takes a new epoch, whose stream starts afresh.
//!
//! The page numbers its control requests, taking and giving back, in the order it makes them, and
//! names on every wheel turn and every key the take it made them under. The view takes a request
//! only if its number is above the last it took, and writes an input only while it holds the lease
//! for exactly the take the input names. So nothing the person did in one period of control is
//! written in another, whatever order the page's calls arrive in, and an answer for an epoch the
//! view no longer holds changes nothing.
//!
//! The wheel reaches the program only as the program asked for it: as wheel events at a cell of the
//! session's grid, while it reports the mouse, in the encoding it chose. A wheel never becomes arrow
//! keys.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use kr_client::encoder::{self, Modifiers, MouseAction, MouseEncoding, MouseEvent, WheelDirection};
use kr_client::projection::{ProjectedModeSpelling, Screen};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{InputLeaseEpoch, InputSequence, RequestId};
use kr_protocol::input::InputAcquireResult;
use kr_protocol::limits::MAX_INPUT_FRAME_LEN;
use serde::Deserialize;

use super::screen::{ControlState, TerminalControl, Wheel};

/// The terminal profile a view declares when it attaches.
///
/// It names this view rather than any terminal. The session takes a profile it has not measured to
/// send the ordinary encoding of keys, which is what a view sends: the terminal keys as the page
/// spells them, and mouse reports. It never hands a profile it has not qualified its live output, so
/// a view is always drawn the session's screen as a projection. Declaring no profile at all would
/// leave the session nothing to establish about the view's keys, and every takeover would be
/// refused.
pub(super) const PROFILE: &str = "kalareach-companion";

/// The most wheel turns one input carries.
///
/// A page of the tallest grid a session can have (1,024 rows) fits, and 1,024 of the longest
/// report a wheel turn makes are 16 KiB, well inside one input frame.
pub const MAX_TURNS: u16 = 1024;

/// What the command says when a view is sent a wheel turn or keys it may not write.
const NOT_CONTROLLING: &str = "This view does not control the program.";

/// What the command says when the view the page names has ended, or was never open.
pub(super) const ENDED: &str = "This view has ended, and took nothing.";

/// What the page says to a view, in the shape the page sends it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    /// Take control of the program, as the page's control request `number`.
    Take {
        /// The page's number for this request.
        number: u64,
    },
    /// Give control back, as the page's control request `number`.
    Release {
        /// The page's number for this request.
        number: u64,
    },
    /// Turn the program's wheel at a cell of the session's grid.
    Wheel {
        /// The number of the take the turn was made under.
        take: u64,
        /// The cell's column in the session's grid, from 0.
        column: u32,
        /// The cell's line of the live screen, from 0.
        line: u32,
        /// How many times, towards the person when positive.
        turns: Turns,
        /// Whether Shift was held.
        shift: bool,
        /// Whether Alt was held.
        alt: bool,
        /// Whether Control was held.
        control: bool,
    },
    /// Type these keys.
    Keys {
        /// The number of the take the keys were typed under.
        take: u64,
        /// What the keys send.
        keys: Keys,
    },
}

/// How many times a wheel turns: towards the person when positive, never not at all, and at most
/// [`MAX_TURNS`] either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "i32")]
pub struct Turns(i32);

impl TryFrom<i32> for Turns {
    type Error = String;

    fn try_from(turns: i32) -> Result<Self, String> {
        if turns == 0 || turns.unsigned_abs() > u32::from(MAX_TURNS) {
            return Err(format!(
                "a wheel turns between 1 and {MAX_TURNS} times either way, not {turns}"
            ));
        }
        Ok(Self(turns))
    }
}

impl Turns {
    /// Which way the wheel turns.
    const fn direction(self) -> WheelDirection {
        if self.0 > 0 {
            WheelDirection::Down
        } else {
            WheelDirection::Up
        }
    }

    /// How many times it turns.
    fn count(self) -> usize {
        usize::try_from(self.0.unsigned_abs()).unwrap_or(usize::MAX)
    }
}

/// What some keys send: never nothing, and no more than one input frame carries.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Keys(String);

impl TryFrom<String> for Keys {
    type Error = String;

    fn try_from(keys: String) -> Result<Self, String> {
        if keys.is_empty() {
            return Err("keys send something".to_owned());
        }
        if keys.len() > MAX_INPUT_FRAME_LEN {
            return Err(format!(
                "keys send at most {MAX_INPUT_FRAME_LEN} bytes at once, not {}",
                keys.len()
            ));
        }
        Ok(Self(keys))
    }
}

impl Keys {
    /// The bytes the keys send.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

/// Whether a wheel turn over `screen` reaches its program, and why not.
///
/// The program reports the mouse while DEC mode 1000, 1002 or 1003 is set. It chooses the encoding:
/// SGR with 1006, the original report otherwise, and UTF-8 coordinates with 1005, which 1006
/// overrides and which no encoder here writes.
#[must_use]
pub fn wheel_of(screen: &Screen) -> Wheel {
    let set = |mode| screen.mode(ProjectedModeSpelling::Dec, mode);
    if !(set(1000) || set(1002) || set(1003)) {
        Wheel::Unreported
    } else if set(1005) && !set(1006) {
        Wheel::Unwritable
    } else {
        Wheel::Reaches
    }
}

/// The reports `turns` of the wheel at `column` and `line` of `screen` make, with `modifiers` held,
/// or nothing when none reaches the program: it does not report the mouse, or not in an encoding
/// this view writes, the cell is outside the session's grid, or the original report has no room for
/// its column or line. Nothing is rounded: a cell the program cannot be told is no turn at all.
#[must_use]
pub fn wheel_reports(
    screen: &Screen,
    column: u32,
    line: u32,
    turns: Turns,
    modifiers: Modifiers,
) -> Option<Vec<u8>> {
    if wheel_of(screen) != Wheel::Reaches {
        return None;
    }
    if u64::from(column) >= screen.dimensions.columns.get()
        || u64::from(line) >= screen.dimensions.rows.get()
    {
        return None;
    }
    let encoding = if screen.mode(ProjectedModeSpelling::Dec, 1006) {
        MouseEncoding::Sgr
    } else {
        MouseEncoding::X10
    };
    let report = encoder::mouse(
        MouseEvent {
            action: MouseAction::Wheel(turns.direction()),
            column,
            row: line,
            modifiers,
        },
        encoding,
    )
    .ok()?;
    Some(report.repeat(turns.count()))
}

/// The lease a view holds, and the next number of its input stream.
#[derive(Clone, Copy, Debug)]
struct Held {
    epoch: InputLeaseEpoch,
    next: u64,
}

/// A call the lease owes the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owed {
    /// Ask for the lease.
    Acquire,
    /// Give back the lease at this epoch.
    Release(InputLeaseEpoch),
}

/// Where a write goes: the lease's epoch, and its number in the view's input stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Writing {
    pub epoch: InputLeaseEpoch,
    pub sequence: InputSequence,
}

/// Whether a view controls the program, and what it owes the session for it.
///
/// It converges on the newest control request the page made: taking control asks for the lease
/// once, while none is held and none is asked for; giving it back stops the writing at once and
/// releases what is held; a lease that arrives after the person gave control back is released as it
/// arrives, and restores nothing.
#[derive(Debug, Default)]
pub struct Lease {
    /// The number of the newest control request taken, 0 before the first.
    asked: u64,
    /// Whether that request asks for control, and nothing has ended it since.
    wanted: bool,
    /// The lease the view holds.
    held: Option<Held>,
    /// The acquire in flight.
    acquiring: Option<RequestId>,
    /// Leases the view holds and has to give back, oldest first.
    owed: VecDeque<InputLeaseEpoch>,
    /// The releases in flight. Their answers change nothing: a release the session refuses is of a
    /// lease the view no longer held.
    releasing: BTreeSet<RequestId>,
    /// The writes in flight, and the epoch each was written under.
    writes: BTreeMap<RequestId, InputLeaseEpoch>,
    /// Why control last ended or was refused, until a newer request.
    ended: Option<String>,
}

impl Lease {
    /// The page's control request `number`: a take when `take`, a release otherwise. A request
    /// whose number is not above the newest taken came after it, and changes nothing. Returns
    /// whether control changed.
    pub fn request(&mut self, number: u64, take: bool) -> bool {
        if number <= self.asked {
            return false;
        }
        self.asked = number;
        self.wanted = take;
        self.ended = None;
        if !take && let Some(held) = self.held.take() {
            self.owed.push_back(held.epoch);
        }
        true
    }

    /// The next call the lease owes the session, if any: leases to give back first, then the one
    /// acquire a take needs.
    pub fn owed(&mut self) -> Option<Owed> {
        if let Some(epoch) = self.owed.pop_front() {
            return Some(Owed::Release(epoch));
        }
        (self.wanted && self.held.is_none() && self.acquiring.is_none()).then_some(Owed::Acquire)
    }

    /// The view sent the call `owed` handed it, under `request`.
    pub fn sent(&mut self, call: Owed, request: RequestId) {
        match call {
            Owed::Acquire => self.acquiring = Some(request),
            Owed::Release(_) => {
                self.releasing.insert(request);
            }
        }
    }

    /// Whether `request` is one of the lease's calls, whose answer is the lease's.
    #[must_use]
    pub fn owns(&self, request: RequestId) -> bool {
        self.acquiring == Some(request)
            || self.releasing.contains(&request)
            || self.writes.contains_key(&request)
    }

    /// The session answered one of the lease's calls. Returns whether control changed.
    pub fn answered(
        &mut self,
        request: RequestId,
        outcome: Result<ParamsValue, ProtocolError>,
    ) -> bool {
        if self.acquiring == Some(request) {
            self.acquiring = None;
            return self.acquired(outcome);
        }
        if self.releasing.remove(&request) {
            return false;
        }
        if let Some(epoch) = self.writes.remove(&request)
            && let Err(refusal) = outcome
            && self.held.is_some_and(|held| held.epoch == epoch)
        {
            // The first refusal of a write ends this epoch, whatever became of its number. A lease
            // lost is not the view's to give back; any other it still holds, and gives back.
            self.held = None;
            self.wanted = false;
            if refusal.code != ErrorCode::LeaseLost {
                self.owed.push_back(epoch);
            }
            self.ended = Some(ended_by(&refusal));
            return true;
        }
        false
    }

    fn acquired(&mut self, outcome: Result<ParamsValue, ProtocolError>) -> bool {
        match outcome.map(|value| value.to_typed::<InputAcquireResult>()) {
            Ok(Ok(result)) => {
                if self.wanted {
                    self.held = Some(Held {
                        epoch: result.lease.epoch,
                        next: result.lease.next_sequence.get(),
                    });
                    true
                } else {
                    // Control was given back while the acquire was in flight.
                    self.owed.push_back(result.lease.epoch);
                    false
                }
            }
            Ok(Err(_)) => self.refused(
                "This view cannot take control: the session's answer could not be read.".to_owned(),
            ),
            Err(refusal) => self.refused(refused_take(&refusal)),
        }
    }

    /// The take in force was refused, for `why`.
    fn refused(&mut self, why: String) -> bool {
        if !self.wanted {
            return false;
        }
        self.wanted = false;
        self.ended = Some(why);
        true
    }

    /// Where a write made under the page's take `take` goes, or why it may not be written: the view
    /// has to hold the lease for exactly that take.
    ///
    /// # Errors
    ///
    /// Returns what the command says when the view does not control the program under `take`.
    pub fn write(&mut self, take: u64) -> Result<Writing, String> {
        match self.held.as_mut() {
            Some(held) if self.wanted && take == self.asked => {
                let sequence = InputSequence::new(held.next);
                held.next += 1;
                Ok(Writing {
                    epoch: held.epoch,
                    sequence,
                })
            }
            _ => Err(NOT_CONTROLLING.to_owned()),
        }
    }

    /// Whether a write made under the page's take `take` may be written now.
    #[must_use]
    pub fn controls(&self, take: u64) -> bool {
        self.held.is_some() && self.wanted && take == self.asked
    }

    /// The view wrote `request` under `epoch`.
    pub fn written(&mut self, request: RequestId, epoch: InputLeaseEpoch) {
        self.writes.insert(request, epoch);
    }

    /// What the page is told of control.
    #[must_use]
    pub fn control(&self) -> TerminalControl {
        TerminalControl {
            number: self.asked,
            state: if !self.wanted {
                ControlState::Watching
            } else if self.held.is_some() {
                ControlState::Controlling
            } else {
                ControlState::Taking
            },
            ended: self.ended.clone(),
        }
    }
}

/// Why a take was refused, in words for the person.
fn refused_take(refusal: &ProtocolError) -> String {
    if refusal.code == ErrorCode::InputIncompatible {
        "This view cannot take control: the program reads keys in a form the view does not send."
            .to_owned()
    } else {
        format!("This view cannot take control: {}", refusal.message)
    }
}

/// Why control ended at a refused write, in words for the person.
fn ended_by(refusal: &ProtocolError) -> String {
    if refusal.code == ErrorCode::LeaseLost {
        "Control ended: another view took it, or the program changed how it reads keys.".to_owned()
    } else {
        format!(
            "Control ended. The session refused this view's input: {}",
            refusal.message
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::input::InputLeaseState;
    use kr_protocol::scalars::{Nullable, U64};

    fn acquired(epoch: u64) -> Result<ParamsValue, ProtocolError> {
        Ok(ParamsValue::from_typed(&InputAcquireResult {
            lease: InputLeaseState {
                epoch: InputLeaseEpoch::new(epoch),
                holder: Nullable::null(),
                connection_id: Nullable::null(),
                next_sequence: InputSequence::new(0),
            },
            discarded_bytes: U64::ZERO,
            closed_open_paste: false,
        })
        .expect("an answer"))
    }

    fn refusal(code: ErrorCode) -> Result<ParamsValue, ProtocolError> {
        Err(ProtocolError::new(code, "no"))
    }

    fn written() -> Result<ParamsValue, ProtocolError> {
        Ok(ParamsValue::empty())
    }

    /// A lease that took control as request 1 and was given epoch 5.
    fn holding() -> Lease {
        let mut lease = Lease::default();
        lease.request(1, true);
        assert_eq!(lease.owed(), Some(Owed::Acquire));
        lease.sent(Owed::Acquire, RequestId::new(10));
        assert!(lease.answered(RequestId::new(10), acquired(5)));
        lease
    }

    #[test]
    fn the_page_shape_is_read_as_the_page_sends_it() {
        let read = |value: serde_json::Value| serde_json::from_value::<Input>(value);
        assert_eq!(
            read(serde_json::json!({"kind": "take", "number": 3})).expect("a take"),
            Input::Take { number: 3 }
        );
        assert!(
            read(serde_json::json!({"kind": "take", "number": 3, "view": "1"})).is_err(),
            "an unknown field"
        );
        assert!(read(serde_json::json!({"session_id": "a", "wheel": {"lines": 3}})).is_err());
        assert!(read(serde_json::json!({"session_id": "a", "bytes": "b"})).is_err());
        let wheel = |turns: i64| {
            read(serde_json::json!({
                "kind": "wheel", "take": 1, "column": 2, "line": 3, "turns": turns,
                "shift": false, "alt": false, "control": false,
            }))
        };
        assert!(wheel(0).is_err());
        assert!(wheel(1025).is_err());
        assert!(wheel(-1025).is_err());
        assert!(wheel(1024).is_ok());
        assert!(wheel(-1024).is_ok());
        let keys =
            |keys: String| read(serde_json::json!({"kind": "keys", "take": 1, "keys": keys}));
        assert!(keys(String::new()).is_err());
        assert!(keys("x".repeat(MAX_INPUT_FRAME_LEN + 1)).is_err());
        assert!(keys("x".repeat(MAX_INPUT_FRAME_LEN)).is_ok());
    }

    #[test]
    fn a_take_acquires_once_and_a_write_goes_under_its_epoch_in_order() {
        let mut lease = Lease::default();
        assert_eq!(lease.control().state, ControlState::Watching);
        assert!(lease.request(1, true));
        assert_eq!(lease.control().state, ControlState::Taking);
        assert_eq!(lease.owed(), Some(Owed::Acquire));
        lease.sent(Owed::Acquire, RequestId::new(10));
        assert_eq!(lease.owed(), None, "one acquire in flight");
        assert!(lease.request(2, true));
        assert_eq!(lease.owed(), None, "a second take asks nothing more");
        assert!(lease.answered(RequestId::new(10), acquired(5)));
        assert_eq!(lease.control().state, ControlState::Controlling);
        assert_eq!(lease.control().number, 2);
        assert!(lease.write(1).is_err(), "a write of the first take");
        let first = lease.write(2).expect("a write of the second");
        let second = lease.write(2).expect("and the next");
        assert_eq!((first.epoch.get(), first.sequence.get()), (5, 0));
        assert_eq!((second.epoch.get(), second.sequence.get()), (5, 1));
    }

    #[test]
    fn a_request_not_above_the_newest_changes_nothing() {
        let mut lease = Lease::default();
        assert!(lease.request(2, false));
        assert!(!lease.request(1, true));
        assert_eq!(lease.owed(), None);
        assert_eq!(lease.control().number, 2);
    }

    #[test]
    fn giving_back_stops_writing_and_releases_what_is_held() {
        let mut lease = holding();
        assert!(lease.request(2, false));
        assert!(lease.write(1).is_err());
        assert_eq!(lease.owed(), Some(Owed::Release(InputLeaseEpoch::new(5))));
        lease.sent(Owed::Release(InputLeaseEpoch::new(5)), RequestId::new(11));
        assert!(!lease.answered(RequestId::new(11), refusal(ErrorCode::LeaseLost)));
        assert_eq!(lease.control().state, ControlState::Watching);
        assert_eq!(lease.control().ended, None);
    }

    #[test]
    fn a_lease_that_arrives_after_giving_back_is_released_and_restores_nothing() {
        let mut lease = Lease::default();
        lease.request(1, true);
        lease.owed();
        lease.sent(Owed::Acquire, RequestId::new(10));
        lease.request(2, false);
        assert!(!lease.answered(RequestId::new(10), acquired(5)));
        assert_eq!(lease.control().state, ControlState::Watching);
        assert_eq!(lease.owed(), Some(Owed::Release(InputLeaseEpoch::new(5))));
        assert!(lease.write(1).is_err());
    }

    #[test]
    fn a_take_after_giving_back_while_the_acquire_is_in_flight_is_served_by_it() {
        let mut lease = Lease::default();
        lease.request(1, true);
        lease.owed();
        lease.sent(Owed::Acquire, RequestId::new(10));
        lease.request(2, false);
        lease.request(3, true);
        assert_eq!(
            lease.owed(),
            None,
            "the acquire in flight serves the newest take"
        );
        assert!(lease.answered(RequestId::new(10), acquired(5)));
        assert_eq!(lease.control().state, ControlState::Controlling);
        assert!(lease.write(1).is_err());
        assert_eq!(lease.write(3).expect("the newest take").epoch.get(), 5);
    }

    #[test]
    fn a_lost_lease_ends_control_and_gives_nothing_back() {
        let mut lease = holding();
        let writing = lease.write(1).expect("a write");
        lease.written(RequestId::new(12), writing.epoch);
        assert!(lease.answered(RequestId::new(12), refusal(ErrorCode::LeaseLost)));
        let control = lease.control();
        assert_eq!(control.state, ControlState::Watching);
        assert_eq!(
            control.ended.as_deref(),
            Some("Control ended: another view took it, or the program changed how it reads keys.")
        );
        assert_eq!(lease.owed(), None);
        assert!(lease.write(1).is_err());
        assert_eq!(lease.control().ended, control.ended, "the words stay");
    }

    #[test]
    fn another_refused_write_ends_control_and_gives_the_epoch_back() {
        let mut lease = holding();
        let first = lease.write(1).expect("a write");
        lease.written(RequestId::new(12), first.epoch);
        let second = lease.write(1).expect("another");
        lease.written(RequestId::new(13), second.epoch);
        assert!(lease.answered(RequestId::new(12), refusal(ErrorCode::ResourceUnavailable)));
        assert_eq!(lease.owed(), Some(Owed::Release(InputLeaseEpoch::new(5))));
        assert!(
            !lease.answered(RequestId::new(13), refusal(ErrorCode::InvalidArgument)),
            "the epoch has already ended"
        );
        assert_eq!(lease.owed(), None);
    }

    #[test]
    fn an_answer_for_an_epoch_no_longer_held_changes_nothing() {
        let mut lease = holding();
        let old = lease.write(1).expect("a write");
        lease.written(RequestId::new(12), old.epoch);
        lease.request(2, false);
        lease.request(3, true);
        assert_eq!(lease.owed(), Some(Owed::Release(InputLeaseEpoch::new(5))));
        lease.sent(Owed::Release(InputLeaseEpoch::new(5)), RequestId::new(13));
        assert_eq!(lease.owed(), Some(Owed::Acquire));
        lease.sent(Owed::Acquire, RequestId::new(14));
        assert!(lease.answered(RequestId::new(14), acquired(7)));
        assert!(!lease.answered(RequestId::new(12), refusal(ErrorCode::LeaseLost)));
        assert_eq!(lease.control().state, ControlState::Controlling);
        assert!(!lease.answered(RequestId::new(13), written()));
        assert_eq!(lease.write(3).expect("the new take").epoch.get(), 7);
    }

    #[test]
    fn a_refused_take_says_why() {
        let mut lease = Lease::default();
        lease.request(1, true);
        lease.owed();
        lease.sent(Owed::Acquire, RequestId::new(10));
        assert!(lease.answered(RequestId::new(10), refusal(ErrorCode::InputIncompatible)));
        let control = lease.control();
        assert_eq!(control.state, ControlState::Watching);
        assert_eq!(
            control.ended.as_deref(),
            Some(
                "This view cannot take control: the program reads keys in a form the view \
                 does not send."
            )
        );
        assert_eq!(
            lease.owed(),
            None,
            "a refused take is not asked again by itself"
        );
        assert!(lease.request(2, true));
        assert_eq!(lease.control().ended, None);
        assert_eq!(lease.owed(), Some(Owed::Acquire));
    }
}
