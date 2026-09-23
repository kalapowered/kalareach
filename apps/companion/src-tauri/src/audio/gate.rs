//! Whether the microphone may carry the person's voice, decided in one place.
//!
//! Section 15 paragraphs 21 and 22 ask for two things at once: a call the person started keeps its
//! microphone, and nothing opens the microphone without a fresh permitted active-call context. This
//! module is the second half, and the phone applications keep the same rule in the same shape.
//! Capture is on only while every one of these holds, and each is kept apart from the others so
//! that none of them can stand in for another:
//!
//! - a permit: the host answered a start with a voice session and a deadline, and the call applied
//!   that answer. A permit belongs to one generation, and a revocation naming an older generation
//!   is refused, so one that arrives late cannot touch the call that replaced the one it was about;
//! - the deadline, on this process's monotonic clock, has not passed;
//! - the person has not muted the microphone;
//! - the system has not taken it: an interruption, or capture suspended;
//! - the audio route is settled on a device that has an input;
//! - the platform's recorder reports itself running. Until it starts, and after it stops or fails,
//!   nothing is being recorded, and the display says the microphone is unavailable rather than on;
//! - the call has not been stopped. A stopped gate never opens again.
//!
//! It also keeps the intervals in which capture was on, so a claim that something was said when
//! nothing could have been heard is refused from this device's own record. The record answers for
//! the past only: an instant later than the time it is asked at is not one anything was heard in.
//!
//! Every method takes the time from its caller, in milliseconds on the monotonic clock, so tests
//! drive time instead of waiting for it, and every method holds one lock.

use std::collections::VecDeque;
use std::ops::Range;
use std::sync::{Mutex, MutexGuard};

/// How many closed intervals a gate keeps by default.
pub const KEPT_INTERVALS: usize = 64;

/// One permitted call, as the host's answer to a start bound it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permit {
    /// Which permit this is. A later one always has a larger number.
    pub generation: u64,
    /// The voice session the host started.
    pub voice_session_id: String,
    /// When the call's own deadline falls, on the monotonic clock.
    pub deadline_ms: u64,
}

/// What the system has done to the microphone, apart from anything the person chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Taken {
    /// Nothing.
    None,
    /// Another call or application took the microphone.
    Interrupted,
    /// The system suspended capture.
    Suspended,
}

impl Taken {
    /// Every case, in declaration order.
    pub const ALL: [Self; 3] = [Self::None, Self::Interrupted, Self::Suspended];
}

/// The one owner of whether the microphone may carry speech.
#[derive(Debug)]
pub struct CaptureGate {
    inner: Mutex<Inner>,
    kept: usize,
}

#[derive(Debug)]
struct Inner {
    generation: u64,
    permit: Option<Permit>,
    muted_by_person: bool,
    taken: Taken,
    route_changing: bool,
    input_available: bool,
    recorder_running: bool,
    stopped: bool,
    opened_at: Option<u64>,
    opened_until: u64,
    heard: VecDeque<Range<u64>>,
}

impl Default for CaptureGate {
    fn default() -> Self {
        Self::with_kept_intervals(KEPT_INTERVALS)
    }
}

impl CaptureGate {
    /// A gate that keeps at most `kept` closed intervals.
    #[must_use]
    pub fn with_kept_intervals(kept: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                generation: 0,
                permit: None,
                muted_by_person: false,
                taken: Taken::None,
                route_changing: false,
                input_available: true,
                recorder_running: false,
                stopped: false,
                opened_at: None,
                opened_until: u64::MAX,
                heard: VecDeque::new(),
            }),
            kept,
        }
    }

    fn locked(&self) -> MutexGuard<'_, Inner> {
        // A poisoned lock means a panic mid-change; the state it guards is still the last one
        // written whole, and refusing every later question would leave a microphone nobody can mute.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Binds the gate to the host's answer, and returns the permit.
    ///
    /// `None` when the gate is stopped, when it already holds a permit, or when the deadline has
    /// already passed: a call is permitted once, by an answer that is still current.
    pub fn permit(&self, voice_session_id: &str, deadline_ms: u64, now_ms: u64) -> Option<Permit> {
        let mut inner = self.locked();
        if inner.stopped || inner.permit.is_some() || deadline_ms <= now_ms {
            return None;
        }
        inner.generation += 1;
        let made = Permit {
            generation: inner.generation,
            voice_session_id: voice_session_id.to_owned(),
            deadline_ms,
        };
        inner.permit = Some(made.clone());
        inner.settle(now_ms, self.kept);
        Some(made)
    }

    /// Withdraws the permit of one generation. False, and nothing changed, for any other.
    pub fn revoke(&self, generation: u64, now_ms: u64) -> bool {
        let mut inner = self.locked();
        if inner.permit.as_ref().map(|held| held.generation) != Some(generation) {
            return false;
        }
        inner.permit = None;
        inner.settle(now_ms, self.kept);
        true
    }

    /// The person's own mute. What the system does to the microphone never changes it.
    pub fn set_muted_by_person(&self, muted: bool, now_ms: u64) {
        let mut inner = self.locked();
        inner.muted_by_person = muted;
        inner.settle(now_ms, self.kept);
    }

    /// What the system has done to the microphone.
    pub fn taken(&self, by: Taken, now_ms: u64) {
        let mut inner = self.locked();
        inner.taken = by;
        inner.settle(now_ms, self.kept);
    }

    /// The audio route, as the platform reports it.
    pub fn route(&self, changing: bool, input_available: bool, now_ms: u64) {
        let mut inner = self.locked();
        inner.route_changing = changing;
        inner.input_available = input_available;
        inner.settle(now_ms, self.kept);
    }

    /// Whether the platform's recorder is running, as the platform reports it.
    ///
    /// Reported by the audio device itself: when it starts, when it stops and when it fails. A
    /// recorder that has not started heard nothing, whatever the call was permitted to do.
    pub fn recorder(&self, running: bool, now_ms: u64) {
        let mut inner = self.locked();
        inner.recorder_running = running;
        inner.settle(now_ms, self.kept);
    }

    /// Stops the gate for good.
    pub fn stop(&self, now_ms: u64) {
        let mut inner = self.locked();
        inner.stopped = true;
        inner.permit = None;
        inner.settle(now_ms, self.kept);
    }

    /// Whether the microphone may carry speech now.
    #[must_use]
    pub fn capture_enabled(&self, now_ms: u64) -> bool {
        let mut inner = self.locked();
        inner.settle(now_ms, self.kept);
        inner.enabled(now_ms)
    }

    /// What a person is told about the microphone now, in the words the surface draws.
    ///
    /// `capturing` exactly when [`Self::capture_enabled`] is true, so the display and the refusal
    /// of unheard speech can never disagree.
    #[must_use]
    pub fn displayed(&self, now_ms: u64) -> &'static str {
        let mut inner = self.locked();
        inner.settle(now_ms, self.kept);
        let live = inner
            .permit
            .as_ref()
            .is_some_and(|held| now_ms < held.deadline_ms);
        // What the system did is said first: it is why the recorder stopped, when it did.
        if inner.stopped || !live {
            return "idle";
        }
        match inner.taken {
            Taken::Interrupted => "interrupted",
            Taken::Suspended => "suspended_by_system",
            Taken::None if inner.route_changing => "route_changing",
            Taken::None if !inner.input_available || !inner.recorder_running => "unavailable",
            Taken::None if inner.muted_by_person => "muted_by_person",
            Taken::None => "capturing",
        }
    }

    /// Whether the microphone was carrying speech at `at_ms`, asked at `now_ms`.
    ///
    /// Answered from the intervals this gate kept. An instant later than `now_ms` answers false:
    /// a permit that is still running is permission to capture, not a record that anything was
    /// heard. An instant older than the oldest kept interval answers false too: a record that no
    /// longer reaches back that far cannot vouch for it.
    #[must_use]
    pub fn could_have_heard(&self, at_ms: u64, now_ms: u64) -> bool {
        let mut inner = self.locked();
        inner.settle(now_ms, self.kept);
        if at_ms > now_ms {
            return false;
        }
        if let Some(open) = inner.opened_at
            && at_ms >= open
            && at_ms < inner.opened_until
        {
            return true;
        }
        inner.heard.iter().any(|interval| interval.contains(&at_ms))
    }

    /// Whether a permit is running: given, not withdrawn, not stopped and not past its deadline.
    ///
    /// What the platform's audio device is allowed to run for. Whether the microphone carries
    /// speech is [`Self::capture_enabled`]'s, which asks everything else as well.
    #[must_use]
    pub fn live(&self, now_ms: u64) -> bool {
        let inner = self.locked();
        !inner.stopped
            && inner
                .permit
                .as_ref()
                .is_some_and(|held| now_ms < held.deadline_ms)
    }

    /// The permit capture runs under now.
    #[must_use]
    pub fn current(&self) -> Option<Permit> {
        self.locked().permit.clone()
    }

    /// Whether the person muted the microphone.
    #[must_use]
    pub fn is_muted_by_person(&self) -> bool {
        self.locked().muted_by_person
    }
}

impl Inner {
    fn enabled(&self, now_ms: u64) -> bool {
        self.permit.as_ref().is_some_and(|held| {
            !self.stopped
                && now_ms < held.deadline_ms
                && !self.muted_by_person
                && self.taken == Taken::None
                && !self.route_changing
                && self.input_available
                && self.recorder_running
        })
    }

    /// Opens or closes the interval capture is in, to match what is true now.
    fn settle(&mut self, now_ms: u64, kept: usize) {
        let on = self.enabled(now_ms);
        match (on, self.opened_at) {
            (true, None) => {
                self.opened_at = Some(now_ms);
                self.opened_until = self.permit.as_ref().map_or(now_ms, |held| held.deadline_ms);
            }
            (false, Some(open)) => {
                // Capture that ran out at the deadline ended there, not whenever somebody next asked.
                let end = now_ms.min(self.opened_until);
                if end > open {
                    self.heard.push_back(open..end);
                    while self.heard.len() > kept {
                        self.heard.pop_front();
                    }
                }
                self.opened_at = None;
                self.opened_until = u64::MAX;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A permitted gate whose recorder reported itself running at the same moment.
    fn permitted(now_ms: u64, deadline_ms: u64) -> (CaptureGate, Permit) {
        let gate = CaptureGate::default();
        let permit = gate
            .permit("voice-session-1", deadline_ms, now_ms)
            .expect("a current answer permits the call");
        gate.recorder(true, now_ms);
        (gate, permit)
    }

    /// KR-REQ-15.34: a call with no permit captures nothing, whatever else is true.
    #[test]
    fn nothing_is_captured_without_a_permit() {
        let gate = CaptureGate::default();
        assert!(!gate.capture_enabled(1_000));
        assert_eq!(gate.displayed(1_000), "idle");
        gate.set_muted_by_person(false, 1_100);
        gate.taken(Taken::None, 1_200);
        gate.route(false, true, 1_300);
        gate.recorder(true, 1_350);
        assert!(
            !gate.capture_enabled(1_400),
            "no event other than a permit opens the microphone"
        );
        assert!(!gate.live(1_400));
    }

    /// KR-REQ-15.36: a permitted call captures nothing until the recorder reports itself running,
    /// and says the microphone is unavailable until then and once it fails.
    #[test]
    fn capture_waits_for_the_recorder_and_ends_with_it() {
        let gate = CaptureGate::default();
        gate.permit("voice-session-1", 61_000, 1_000)
            .expect("a current answer permits the call");
        assert!(gate.live(1_000));
        assert!(!gate.capture_enabled(1_000), "the recorder has not started");
        assert_eq!(gate.displayed(1_000), "unavailable");
        gate.recorder(true, 1_200);
        assert!(gate.capture_enabled(1_200));
        assert_eq!(gate.displayed(1_200), "capturing");
        gate.recorder(false, 5_000);
        assert!(
            !gate.capture_enabled(5_000),
            "a recorder that failed hears nothing"
        );
        assert_eq!(gate.displayed(5_000), "unavailable");
        assert!(!gate.could_have_heard(1_100, 6_000));
        assert!(gate.could_have_heard(1_200, 6_000));
        assert!(!gate.could_have_heard(5_000, 6_000));
    }

    /// KR-REQ-15.34: a permit is given once, by an answer that is still current.
    #[test]
    fn a_permit_is_refused_when_stale_repeated_or_after_a_stop() {
        assert!(CaptureGate::default().permit("s", 1_000, 1_000).is_none());
        let (gate, _) = permitted(1_000, 61_000);
        assert!(gate.permit("s-2", 90_000, 2_000).is_none());
        gate.stop(3_000);
        assert!(gate.permit("s-3", 90_000, 4_000).is_none());
        assert!(!gate.capture_enabled(4_000));
    }

    /// KR-REQ-15.34: capture ends at the deadline with no event at all, and the record says so.
    #[test]
    fn capture_ends_at_the_deadline_by_itself() {
        let (gate, _) = permitted(1_000, 11_000);
        assert!(gate.capture_enabled(10_999));
        assert!(!gate.capture_enabled(11_000));
        assert!(!gate.live(11_000));
        assert_eq!(gate.displayed(15_000), "idle");
        assert!(gate.could_have_heard(10_999, 15_000));
        assert!(!gate.could_have_heard(12_000, 15_000));
    }

    /// KR-ACC-014: a running permit vouches for nothing that has not happened yet.
    #[test]
    fn a_future_instant_is_never_vouched_for() {
        let (gate, _) = permitted(1_000, 61_000);
        assert!(gate.capture_enabled(1_000));
        assert!(
            !gate.could_have_heard(50_000, 1_000),
            "permission to capture is not a record of speech"
        );
        assert!(gate.could_have_heard(1_000, 1_000));
        assert!(gate.could_have_heard(20_000, 30_000));
    }

    /// KR-REQ-15.35: the person's mute and the system are kept apart. Unmuting while the system
    /// holds the microphone opens nothing, and its return restores what the person chose.
    #[test]
    fn the_persons_mute_and_the_system_are_separate() {
        let (gate, _) = permitted(1_000, 61_000);
        gate.taken(Taken::Interrupted, 2_000);
        gate.set_muted_by_person(false, 2_100);
        assert!(!gate.capture_enabled(2_200));
        gate.set_muted_by_person(true, 2_300);
        gate.taken(Taken::None, 2_400);
        assert!(!gate.capture_enabled(2_500));
        assert_eq!(gate.displayed(2_500), "muted_by_person");
        gate.set_muted_by_person(false, 2_600);
        assert!(gate.capture_enabled(2_700));
    }

    /// KR-REQ-15.35 and 15.36: a route in change or without an input keeps capture off and says so.
    #[test]
    fn a_route_change_and_a_missing_input_keep_capture_off() {
        let (gate, _) = permitted(1_000, 61_000);
        gate.route(true, true, 2_000);
        assert_eq!(gate.displayed(2_000), "route_changing");
        gate.route(false, false, 3_000);
        assert_eq!(gate.displayed(3_000), "unavailable");
        assert!(!gate.capture_enabled(3_000));
        gate.route(false, true, 4_000);
        assert!(gate.capture_enabled(4_000));
    }

    /// KR-REQ-15.35: a revocation names its generation, and a late one for an older call is refused.
    #[test]
    fn only_the_current_generation_can_be_revoked() {
        let (gate, permit) = permitted(1_000, 61_000);
        assert!(!gate.revoke(permit.generation - 1, 2_000));
        assert!(gate.capture_enabled(2_000));
        assert!(gate.revoke(permit.generation, 3_000));
        assert!(!gate.capture_enabled(3_000));
        assert!(gate.current().is_none());
    }

    /// KR-ACC-014: what was said is checked against when the microphone was on, and nothing else.
    #[test]
    fn speech_is_vouched_for_only_inside_the_kept_intervals() {
        let (gate, _) = permitted(1_000, 100_000);
        gate.set_muted_by_person(true, 5_000);
        gate.set_muted_by_person(false, 9_000);
        assert!(gate.could_have_heard(4_999, 10_000));
        assert!(!gate.could_have_heard(5_000, 10_000));
        assert!(!gate.could_have_heard(8_999, 10_000));
        assert!(gate.could_have_heard(9_000, 10_000));
        assert!(!gate.could_have_heard(999, 10_000));

        let bounded = CaptureGate::with_kept_intervals(2);
        bounded.permit("s", 100_000, 0);
        bounded.recorder(true, 0);
        for start in [10_000, 20_000, 30_000] {
            bounded.set_muted_by_person(true, start);
            bounded.set_muted_by_person(false, start + 5_000);
        }
        assert!(!bounded.could_have_heard(1_000, 40_000));
        assert!(bounded.could_have_heard(26_000, 40_000));
    }

    /// KR-REQ-15.36: what the person is told and whether anything could be heard never disagree.
    #[test]
    fn the_display_and_the_microphone_agree_in_every_combination() {
        for muted in [false, true] {
            for taken in Taken::ALL {
                for changing in [false, true] {
                    for input in [false, true] {
                        for recording in [false, true] {
                            let (gate, _) = permitted(1_000, 61_000);
                            gate.set_muted_by_person(muted, 2_000);
                            gate.taken(taken, 2_000);
                            gate.route(changing, input, 2_000);
                            gate.recorder(recording, 2_000);
                            assert_eq!(
                                gate.capture_enabled(3_000),
                                gate.displayed(3_000) == "capturing",
                                "muted={muted} taken={taken:?} changing={changing} \
                                 input={input} recording={recording}"
                            );
                        }
                    }
                }
            }
        }
    }
}
