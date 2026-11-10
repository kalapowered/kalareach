//! What decides whether a spoken delegation may be handed to the host.
//!
//! Section 15 paragraph 22: if capture is muted or unavailable the device displays it and rejects
//! any claim that speech it did not receive authorised an action. The provider announces a
//! delegation on its data channel and says nothing of what was said; the device hands the host the
//! transcript fragments it vouches for. This module is the vouching, and it only ever refuses:
//!
//! * **Taint.** Anything that shows the device cannot know it read everything said since the call
//!   began (news that was lost, a required event it could not read, fragments that overlap or run
//!   backwards, a break in capture, a late fragment, the provider's own mute) ends the call's
//!   authority for good. A call that is tainted submits nothing.
//! * **The first fragment.** The device cannot hear what was said before capture first opened, and
//!   a person can say "do not" before it. A set that holds the first fragment the call delivered,
//!   or the first one that arrived after the opening, never authorises. The two are told apart by
//!   when they arrived against the opening; a fragment that arrives before the opening taints the
//!   call, since nothing is carried before it.
//! * **The set.** The fragments that start at or before the delegation's offset, no more than the
//!   look-back before it, that no earlier set used. Every other fragment is checked against the
//!   set's span: one that overlaps it taints the call, and one that ends within the exclusion gap
//!   before it refuses the set, since it may be the first half of one instruction.
//!
//! The look-back and the exclusion gap are the device's own measure of what one instruction is, and
//! the gap is a parameter of these cases, not a safety bound: no rule here decides what separates
//! two instructions exactly.
//!
//! The gate keeps no clock and asks no question of native code. The owner tells it what it heard,
//! and asks it to freeze a set once the barrier of a capture proof has been read.

use std::collections::VecDeque;

use kr_protocol::voice::{
    VOICE_FRAGMENT_BYTES_MAX, VOICE_FRAGMENTS_BYTES_MAX, VOICE_FRAGMENTS_MAX, VOICE_LOOK_BACK_MS,
};

use companion_platform::call::{CallId, CaptureProof, CaptureState};

use super::provider::{Fragment, Malformed, Provider};

/// How far before its first fragment's start another fragment may end and still be taken for the
/// first half of the same instruction. A test parameter, not a safety bound: the recorded session
/// has 400 ms silences inside one sentence, so nothing under 400 ms can stand.
pub(super) const EXCLUSION_GAP_MS: u64 = 2_000;

/// How far back, on the call's timeline, a fragment is kept for a set or for the exclusion check.
const KEEP_MS: u64 = 300_000;

/// The most fragments kept at once. A call that delivers more than this inside the time they are
/// kept for is one the gate cannot read.
const KEPT_MAX: usize = 4_096;

/// The most delegation identifiers a call can tell apart: it is tainted by one more.
const SEEN: usize = 256;

/// Why a call can no longer authorise anything, or why one set cannot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cause {
    // What taints the call, for good.
    /// News was lost: a skipped number, a full queue or text that was not news.
    LostNews,
    /// A message of a required kind that could not be read as it must be.
    UnreadableEvent,
    /// A fragment whose text is empty, over the bound or holds a control character.
    FragmentText,
    /// A moment that is not a whole number from 0 to a call's longest length.
    FragmentTime,
    /// A fragment that ends before it starts, or starts before the one before it.
    FragmentOrder,
    /// Two fragments whose intervals overlap.
    Overlap,
    /// A delegation whose offset is below an earlier one's, or an identifier announced twice at
    /// two offsets.
    DelegationOrder,
    /// A fragment that arrived after the set it belongs to was frozen.
    LateFragment,
    /// A fragment that arrived before capture first opened, or before it was known to have.
    BeforeOpening,
    /// More than one opening of capture, or none, by native code's own record.
    Openings,
    /// A break in capture, by native code's own record.
    CaptureBreak,
    /// The provider's answer turns discontinuous transmission on.
    Dtx,
    /// The provider says it muted what it hears, after capture opened.
    ProviderMuted,
    /// More fragments than the gate can keep.
    TooManyFragments,
    /// More delegations than the gate can tell apart: an identifier it no longer remembers could be
    /// announced again as another attempt.
    TooManyDelegations,
    // What refuses one set and leaves the call as it was.
    /// The set holds the first fragment of the call, or the first after the opening.
    FirstFragment,
    /// Nothing was said that this delegation answers.
    Empty,
    /// The set is over what the host takes.
    TooLarge,
    /// The voice service did not announce this delegation at this offset.
    BrokerDisagrees,
    /// Native code's news was not read up to the marker in time.
    NotDrained,
    /// A fragment outside the set ends within the exclusion gap before it.
    Excluded,
    /// The delegation is older than what is kept of what was said.
    TooOld,
    /// The proof taken before the send was too old by the moment the request could be written.
    StaleProof,
    /// Native code could not give a proof.
    NoProof,
    /// The request could not be built or recorded, so nothing was sent.
    NotComposed,
    /// The path to the host was lost before the request was written.
    HostLost,
}

impl Cause {
    /// The word the screen branches on.
    pub(super) const fn word(self) -> &'static str {
        match self {
            Self::LostNews => "lost_news",
            Self::UnreadableEvent => "unreadable_event",
            Self::FragmentText => "fragment_text",
            Self::FragmentTime => "fragment_time",
            Self::FragmentOrder => "fragment_order",
            Self::Overlap => "overlap",
            Self::DelegationOrder => "delegation_order",
            Self::LateFragment => "late_fragment",
            Self::BeforeOpening => "before_opening",
            Self::Openings => "openings",
            Self::CaptureBreak => "capture_break",
            Self::Dtx => "dtx",
            Self::ProviderMuted => "provider_muted",
            Self::TooManyFragments => "too_many_fragments",
            Self::TooManyDelegations => "too_many_delegations",
            Self::FirstFragment => "first_fragment",
            Self::Empty => "empty",
            Self::TooLarge => "too_large",
            Self::BrokerDisagrees => "broker_disagrees",
            Self::NotDrained => "not_drained",
            Self::Excluded => "excluded",
            Self::TooOld => "too_old",
            Self::StaleProof => "stale_proof",
            Self::NoProof => "no_proof",
            Self::NotComposed => "not_composed",
            Self::HostLost => "host_lost",
        }
    }

    /// Whether this ends the call's authority, and not only one set.
    pub(super) const fn taints(self) -> bool {
        matches!(
            self,
            Self::LostNews
                | Self::UnreadableEvent
                | Self::FragmentText
                | Self::FragmentTime
                | Self::FragmentOrder
                | Self::Overlap
                | Self::DelegationOrder
                | Self::LateFragment
                | Self::BeforeOpening
                | Self::Openings
                | Self::CaptureBreak
                | Self::Dtx
                | Self::ProviderMuted
                | Self::TooManyFragments
                | Self::TooManyDelegations
        )
    }
}

impl From<Malformed> for Cause {
    fn from(malformed: Malformed) -> Self {
        match malformed {
            Malformed::NotAnEvent | Malformed::Schema | Malformed::UnknownRequired => {
                Self::UnreadableEvent
            }
            Malformed::Text => Self::FragmentText,
            Malformed::Time => Self::FragmentTime,
            Malformed::Ends => Self::FragmentOrder,
        }
    }
}

/// What the gate tells its owner of one message.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Told {
    /// Nothing the owner acts on.
    Nothing,
    /// The model delegated work: a collection opens.
    Delegation { id: String, offset_ms: u64 },
    /// The call is tainted by this message, which is the first cause.
    Tainted(Cause),
    /// A fragment arrived after its set was frozen. The call is tainted by it.
    Late,
}

/// What native code's capture record showed, as the gate reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Record {
    pub openings: u64,
    pub breaks: u64,
    pub capturing: bool,
}

impl Record {
    /// What a capture proof's record shows.
    pub(super) fn of(proof: &CaptureProof) -> Self {
        Self {
            openings: proof.openings,
            breaks: proof.breaks,
            capturing: proof.state == CaptureState::Capturing,
        }
    }
}

/// What a frozen set came to.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Frozen {
    /// The fragments that may be handed to the host, in the order they were said.
    Set(Vec<Fragment>),
    /// Nothing is handed over, for this cause.
    Refused(Cause),
}

/// How a capture proof taken just before a send reads, when it may be used: how old, in
/// milliseconds, the freshest sign that the recorder delivers was when native code answered.
///
/// The proof must be of this call and show capture on, opened once and never broken. What shows
/// less taints the call, and a proof with no sign of the recorder's progress is one that cannot be
/// called young.
///
/// # Errors
///
/// Returns the cause that refuses the send, which taints the call when it is of its kind.
pub(super) fn usable(proof: &CaptureProof, call: &CallId) -> Result<u64, Cause> {
    if proof.call != *call {
        return Err(Cause::NoProof);
    }
    if proof.openings != 1 {
        return Err(Cause::Openings);
    }
    if proof.breaks != 0 || proof.state != CaptureState::Capturing {
        return Err(Cause::CaptureBreak);
    }
    proof.progress_age_ms.ok_or(Cause::StaleProof)
}

/// A fragment kept, with the order it arrived in.
struct Kept {
    ordinal: u64,
    fragment: Fragment,
    used: bool,
}

/// What the gate knows of one call's data channel.
pub(super) struct Gate {
    taint: Option<Cause>,
    /// Whether capture is known to have opened, from the news the owner read.
    opened: bool,
    kept: VecDeque<Kept>,
    /// How many fragments arrived.
    arrived: u64,
    /// The ordinal of the first fragment that arrived after the opening.
    first_after_opening: Option<u64>,
    previous_start: u64,
    furthest_end: u64,
    /// The latest end of a fragment no longer kept, when one was dropped.
    dropped_to: Option<u64>,
    seen: VecDeque<(String, u64)>,
    last_offset: Option<u64>,
    /// The largest offset of a set that was frozen.
    frozen_to: Option<u64>,
}

impl Gate {
    pub(super) const fn new() -> Self {
        Self {
            taint: None,
            opened: false,
            kept: VecDeque::new(),
            arrived: 0,
            first_after_opening: None,
            previous_start: 0,
            furthest_end: 0,
            dropped_to: None,
            seen: VecDeque::new(),
            last_offset: None,
            frozen_to: None,
        }
    }

    /// The first cause that tainted the call, when one did.
    pub(super) const fn taint(&self) -> Option<Cause> {
        self.taint
    }

    /// Taints the call, and says so only the first time.
    pub(super) fn taint_with(&mut self, cause: Cause) -> Told {
        if self.taint.is_some() {
            return Told::Nothing;
        }
        self.taint = Some(cause);
        // A call that can no longer act has no use for what it heard.
        self.kept.clear();
        Told::Tainted(cause)
    }

    /// What a capture proof for this call shows of capture, as the owner reads it. An opening that
    /// is not the only one, or a break, taints the call at once, so that nothing waiting to be
    /// written is written after it; the news read up to the proof's marker is still what a set is
    /// vouched for by, and this only ever stops one.
    pub(super) fn note_record(&mut self, record: Record) -> Told {
        if record.openings != 1 {
            self.taint_with(Cause::Openings)
        } else if record.breaks != 0 || !record.capturing {
            self.taint_with(Cause::CaptureBreak)
        } else {
            Told::Nothing
        }
    }

    /// The owner read news that capture is on.
    pub(super) fn capture_is_on(&mut self) {
        self.opened = true;
    }

    /// The owner read news that capture is off. After it first opened that is a break, and the call
    /// is tainted at once, so that nothing waiting to be written is written after it; the capture
    /// proof is still what a set is vouched for by, and this only ever stops one.
    pub(super) fn capture_is_off(&mut self) -> Told {
        if self.opened {
            self.taint_with(Cause::CaptureBreak)
        } else {
            Told::Nothing
        }
    }

    /// News was lost.
    pub(super) fn lost(&mut self) -> Told {
        self.taint_with(Cause::LostNews)
    }

    /// The provider's answer turns discontinuous transmission on.
    pub(super) fn dtx(&mut self) -> Told {
        self.taint_with(Cause::Dtx)
    }

    /// Takes what the provider's data channel said.
    pub(super) fn provider(&mut self, message: Provider) -> Told {
        match message {
            Provider::Other { .. } => Told::Nothing,
            Provider::Malformed(malformed) => self.taint_with(malformed.into()),
            Provider::InputMuted => {
                if self.opened {
                    self.taint_with(Cause::ProviderMuted)
                } else {
                    Told::Nothing
                }
            }
            Provider::Fragment(fragment) => self.fragment(fragment),
            Provider::Delegation { id, offset_ms } => self.delegation(id, offset_ms),
        }
    }

    fn fragment(&mut self, fragment: Fragment) -> Told {
        let before = self.taint;
        if !self.opened {
            self.taint_with(Cause::BeforeOpening);
        }
        if self.arrived > 0 && fragment.start_ms < self.previous_start {
            self.taint_with(Cause::FragmentOrder);
        } else if self.arrived > 0 && fragment.start_ms < self.furthest_end {
            self.taint_with(Cause::Overlap);
        }
        let late = self
            .frozen_to
            .is_some_and(|frozen| fragment.start_ms <= frozen);
        if late {
            self.taint_with(Cause::LateFragment);
        }
        let ordinal = self.arrived;
        self.arrived += 1;
        if self.opened && self.first_after_opening.is_none() {
            self.first_after_opening = Some(ordinal);
        }
        self.previous_start = self.previous_start.max(fragment.start_ms);
        self.furthest_end = self.furthest_end.max(fragment.end_ms);
        // A tainted call hands nothing over, so what it hears is not kept: the text of a call that
        // can no longer act is not held, and what is held is bounded by what can still be used.
        if self.taint.is_some() {
            self.kept.clear();
        } else {
            self.kept.push_back(Kept {
                ordinal,
                fragment,
                used: false,
            });
            self.prune();
            if self.kept.len() > KEPT_MAX {
                self.taint_with(Cause::TooManyFragments);
                self.kept.clear();
            }
        }
        match (before, self.taint) {
            (None, Some(_)) if late => Told::Late,
            (None, Some(cause)) => Told::Tainted(cause),
            _ => Told::Nothing,
        }
    }

    /// Forgets the fragments older than the gate keeps, and remembers what the latest of them
    /// ended at. What was forgotten is never read as nothing said: a delegation whose reach goes
    /// back to it is refused as too old, whatever offsets came before it.
    fn prune(&mut self) {
        let newest = self.previous_start;
        while let Some(front) = self.kept.front() {
            let end = front.fragment.end_ms;
            if end.saturating_add(KEEP_MS) >= newest {
                break;
            }
            self.dropped_to = Some(self.dropped_to.map_or(end, |dropped| dropped.max(end)));
            self.kept.pop_front();
        }
    }

    fn delegation(&mut self, id: String, offset_ms: u64) -> Told {
        if let Some((_, earlier)) = self.seen.iter().find(|(seen, _)| *seen == id) {
            // The same identifier again is the same delegation arriving twice, and is not another:
            // one at another offset names two moments and cannot be read.
            return if *earlier == offset_ms {
                Told::Nothing
            } else {
                self.taint_with(Cause::DelegationOrder)
            };
        }
        if self.last_offset.is_some_and(|last| offset_ms < last) {
            self.taint_with(Cause::DelegationOrder);
        }
        self.last_offset = Some(
            self.last_offset
                .map_or(offset_ms, |last| last.max(offset_ms)),
        );
        // An identifier is remembered for the life of the call: one forgotten could be announced
        // again at another offset as another attempt. A call with more delegations than can be
        // remembered can no longer act.
        if self.seen.len() >= SEEN {
            self.taint_with(Cause::TooManyDelegations);
        } else {
            self.seen.push_back((id.clone(), offset_ms));
        }
        Told::Delegation { id, offset_ms }
    }

    /// Freezes the set of the delegation at `offset_ms`, once native code's news has been read up to
    /// the marker of the proof whose record is `record`. `announced` is the offset the voice service
    /// announced for the same identifier, when it announced one.
    pub(super) fn freeze(
        &mut self,
        offset_ms: u64,
        record: Record,
        announced: Option<u64>,
    ) -> Frozen {
        // Whatever the set comes to, a fragment that starts at or before this offset and arrives
        // later is a late one.
        self.frozen_to = Some(
            self.frozen_to
                .map_or(offset_ms, |frozen| frozen.max(offset_ms)),
        );
        self.note_record(record);
        if let Some(cause) = self.taint {
            return Frozen::Refused(cause);
        }
        let chosen: Vec<usize> = self
            .kept
            .iter()
            .enumerate()
            .filter(|(_, kept)| {
                let start = kept.fragment.start_ms;
                !kept.used && start <= offset_ms && offset_ms - start <= VOICE_LOOK_BACK_MS
            })
            .map(|(index, _)| index)
            .collect();
        // Whatever becomes of the set, what it held is spent: a later delegation answers what was
        // said after it.
        for index in &chosen {
            self.kept[*index].used = true;
        }
        if announced != Some(offset_ms) {
            return Frozen::Refused(Cause::BrokerDisagrees);
        }
        // A fragment forgotten may be one that excludes this set: it did if it ended within the gap
        // before where the set can start, which is as far back as the look-back reaches.
        if self.dropped_to.is_some_and(|dropped| {
            dropped.saturating_add(VOICE_LOOK_BACK_MS + EXCLUSION_GAP_MS) >= offset_ms
        }) {
            return Frozen::Refused(Cause::TooOld);
        }
        let (Some(first), Some(last)) = (chosen.first(), chosen.last()) else {
            return Frozen::Refused(Cause::Empty);
        };
        let (span_start, span_end) = (
            self.kept[*first].fragment.start_ms,
            self.kept[*last]
                .fragment
                .end_ms
                .max(self.kept[*last].fragment.start_ms),
        );
        if chosen.len() > VOICE_FRAGMENTS_MAX
            || chosen
                .iter()
                .map(|index| self.kept[*index].fragment.text.len())
                .sum::<usize>()
                > VOICE_FRAGMENTS_BYTES_MAX
            || chosen
                .iter()
                .any(|index| self.kept[*index].fragment.text.len() > VOICE_FRAGMENT_BYTES_MAX)
        {
            return Frozen::Refused(Cause::TooLarge);
        }
        let holds_first = chosen.iter().any(|index| {
            let ordinal = self.kept[*index].ordinal;
            ordinal == 0 || Some(ordinal) == self.first_after_opening
        });
        if holds_first {
            return Frozen::Refused(Cause::FirstFragment);
        }
        for (index, kept) in self.kept.iter().enumerate() {
            if chosen.contains(&index) {
                continue;
            }
            let (start, end) = (kept.fragment.start_ms, kept.fragment.end_ms);
            if start < span_end && end > span_start {
                self.taint_with(Cause::Overlap);
                return Frozen::Refused(Cause::Overlap);
            }
            if end <= span_start && end.saturating_add(EXCLUSION_GAP_MS) >= span_start {
                return Frozen::Refused(Cause::Excluded);
            }
        }
        Frozen::Set(
            chosen
                .iter()
                .map(|index| self.kept[*index].fragment.clone())
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn said(start_ms: u64, end_ms: u64) -> Provider {
        Provider::Fragment(Fragment {
            start_ms,
            end_ms,
            text: " word".to_owned(),
        })
    }

    fn open() -> Gate {
        let mut gate = Gate::new();
        gate.capture_is_on();
        gate
    }

    const CLEAN: Record = Record {
        openings: 1,
        breaks: 0,
        capturing: true,
    };

    /// The provider announces the delegation `id` at `offset_ms`.
    fn delegating(gate: &mut Gate, id: &str, offset_ms: u64) {
        let told = gate.provider(Provider::Delegation {
            id: id.to_owned(),
            offset_ms,
        });
        assert_eq!(
            told,
            Told::Delegation {
                id: id.to_owned(),
                offset_ms
            }
        );
    }

    /// A throwaway sentence that the model delegated, which is refused as the first of the call and
    /// spent, then a command after a pause: the command is a set of its own, and the throwaway is
    /// neither in it nor within the gap before it.
    #[test]
    fn the_command_after_a_pause_is_the_set_and_the_first_utterance_is_not_in_it() {
        let mut gate = open();
        for start in [0, 200, 400] {
            assert_eq!(gate.provider(said(start, start + 200)), Told::Nothing);
        }
        delegating(&mut gate, "first", 400);
        assert_eq!(
            gate.freeze(400, CLEAN, Some(400)),
            Frozen::Refused(Cause::FirstFragment)
        );
        for start in [6_000, 6_200, 6_400] {
            assert_eq!(gate.provider(said(start, start + 200)), Told::Nothing);
        }
        delegating(&mut gate, "d", 6_400);
        let Frozen::Set(set) = gate.freeze(6_400, CLEAN, Some(6_400)) else {
            panic!("the command is a set");
        };
        assert_eq!(
            set.iter().map(|each| each.start_ms).collect::<Vec<_>>(),
            [6_000, 6_200, 6_400],
            "the throwaway sentence was spent, and ended long before the gap"
        );
    }

    /// The first fragment ever delivered is never in an authorising set, whatever came after it,
    /// and a fragment that arrives before capture opened taints the call.
    #[test]
    fn the_first_fragment_never_authorises_and_one_before_the_opening_taints() {
        let mut gate = open();
        gate.provider(said(1_000, 1_200));
        gate.provider(said(5_000, 5_200));
        delegating(&mut gate, "d", 5_000);
        assert_eq!(
            gate.freeze(5_000, CLEAN, Some(5_000)),
            Frozen::Refused(Cause::FirstFragment),
            "the first fragment is within the look-back and in the set"
        );
        assert_eq!(gate.taint(), None, "the call is as it was");

        let mut early = Gate::new();
        assert_eq!(
            early.provider(said(0, 200)),
            Told::Tainted(Cause::BeforeOpening)
        );
    }

    /// An instruction said soon after another is refused whole, since its first words may belong to
    /// the one before; the same words after a pause are a set. Fragments a set used are not used
    /// again.
    #[test]
    fn a_fragment_that_ends_within_the_gap_before_the_set_refuses_it() {
        let mut gate = open();
        gate.provider(said(0, 200));
        delegating(&mut gate, "first", 0);
        assert_eq!(
            gate.freeze(0, CLEAN, Some(0)),
            Frozen::Refused(Cause::FirstFragment)
        );
        gate.provider(said(3_000, 3_200));
        delegating(&mut gate, "a", 3_000);
        let Frozen::Set(first) = gate.freeze(3_000, CLEAN, Some(3_000)) else {
            panic!("the first command is a set");
        };
        assert_eq!(first.len(), 1);
        // The next begins 800 ms after the one before ended.
        gate.provider(said(4_000, 4_200));
        delegating(&mut gate, "b", 4_000);
        assert_eq!(
            gate.freeze(4_000, CLEAN, Some(4_000)),
            Frozen::Refused(Cause::Excluded)
        );
    }

    /// Overlap, order, offset, late and text rules taint the call, each by its own cause.
    #[test]
    fn what_shows_the_gate_cannot_read_the_stream_taints_the_call_by_its_cause() {
        let mut gate = open();
        gate.provider(said(1_000, 2_000));
        assert_eq!(
            gate.provider(said(1_500, 2_500)),
            Told::Tainted(Cause::Overlap)
        );
        let mut gate = open();
        gate.provider(said(1_000, 1_200));
        assert_eq!(
            gate.provider(said(500, 600)),
            Told::Tainted(Cause::FragmentOrder)
        );
        let mut gate = open();
        delegating(&mut gate, "a", 5_000);
        assert_eq!(
            gate.provider(Provider::Delegation {
                id: "b".to_owned(),
                offset_ms: 4_000,
            }),
            Told::Delegation {
                id: "b".to_owned(),
                offset_ms: 4_000
            }
        );
        assert_eq!(gate.taint(), Some(Cause::DelegationOrder));
        // A fragment that starts at or before the offset of a set that was frozen arrives late.
        let mut gate = open();
        gate.provider(said(0, 200));
        gate.provider(said(3_000, 3_200));
        delegating(&mut gate, "a", 3_200);
        let _ = gate.freeze(3_200, CLEAN, Some(3_200));
        assert_eq!(gate.provider(said(3_200, 3_400)), Told::Late);
        assert_eq!(gate.taint(), Some(Cause::LateFragment));
    }

    /// A record that shows more than one opening, or none, taints the call whatever its breaks say.
    #[test]
    fn an_opening_that_is_not_the_only_one_taints_the_call() {
        for openings in [0, 2] {
            let mut gate = open();
            gate.provider(said(0, 200));
            gate.provider(said(5_000, 5_200));
            delegating(&mut gate, "d", 5_000);
            assert_eq!(
                gate.freeze(5_000, Record { openings, ..CLEAN }, Some(5_000)),
                Frozen::Refused(Cause::Openings),
                "{openings} openings"
            );
        }
    }

    /// What the gate has forgotten is never read as nothing said: a delegation whose reach goes back
    /// to a fragment it forgot is refused as too old, whatever offsets were announced before it.
    #[test]
    fn what_the_gate_has_forgotten_is_never_read_as_nothing_said() {
        let mut gate = open();
        // An early delegation, then four hundred seconds of speech, a fragment a second: the first
        // of it is forgotten, and the early offset does not hold it.
        delegating(&mut gate, "early", 0);
        for second in 0..400_u64 {
            gate.provider(said(second * 1_000, second * 1_000 + 200));
        }
        assert!(gate.kept.len() <= 301, "{} kept", gate.kept.len());
        delegating(&mut gate, "old", 50_000);
        assert_eq!(
            gate.freeze(50_000, CLEAN, Some(50_000)),
            Frozen::Refused(Cause::TooOld)
        );
    }

    /// A fragment forgotten that ended exactly as far before a command as the exclusion gap reaches
    /// excludes it, so the command is refused as too old and not read as a set of its own; and one
    /// forgotten that ended at the start of the call counts as one forgotten.
    #[test]
    fn a_forgotten_fragment_at_the_edge_of_the_gap_still_refuses_the_command() {
        let mut gate = open();
        gate.provider(said(0, 100));
        gate.provider(said(2_100, 400_000));
        gate.provider(said(400_000, 400_001));
        delegating(&mut gate, "command", 32_100);
        assert_eq!(
            gate.freeze(32_100, CLEAN, Some(32_100)),
            Frozen::Refused(Cause::TooOld)
        );

        let mut gate = open();
        gate.provider(said(0, 0));
        gate.provider(said(400_000, 400_200));
        delegating(&mut gate, "command", 30_000);
        assert_eq!(
            gate.freeze(30_000, CLEAN, Some(30_000)),
            Frozen::Refused(Cause::TooOld)
        );
    }

    /// More fragments than the gate keeps taint the call, and a call that is tainted keeps none.
    #[test]
    fn a_flood_of_fragments_taints_the_call_and_is_not_kept() {
        let mut gate = open();
        let mut told = Told::Nothing;
        for index in 0..=KEPT_MAX as u64 {
            told = gate.provider(said(index * 10, index * 10 + 10));
        }
        assert_eq!(told, Told::Tainted(Cause::TooManyFragments));
        for index in 0..2 * KEPT_MAX as u64 {
            let start = (KEPT_MAX as u64 + 1 + index) * 10;
            gate.provider(said(start, start + 10));
        }
        assert!(gate.kept.is_empty(), "a tainted call keeps nothing");
    }

    /// A delegation's identifier is remembered for the life of the call: more delegations than the
    /// gate can tell apart taint it, and an identifier it first saw at one offset is never another
    /// attempt at a later one.
    #[test]
    fn a_delegation_identifier_is_remembered_for_the_life_of_the_call() {
        let mut gate = open();
        delegating(&mut gate, "a", 1_000);
        for index in 0..SEEN {
            gate.provider(Provider::Delegation {
                id: format!("x{index}"),
                offset_ms: 2_000,
            });
        }
        assert_eq!(gate.taint(), Some(Cause::TooManyDelegations));
        // The first identifier is announced again, at a later offset, with fresh words before it.
        gate.provider(said(0, 100));
        gate.provider(said(9_000, 9_200));
        gate.provider(Provider::Delegation {
            id: "a".to_owned(),
            offset_ms: 9_200,
        });
        assert_eq!(
            gate.freeze(9_200, CLEAN, Some(9_200)),
            Frozen::Refused(Cause::TooManyDelegations)
        );
    }

    /// A call that is tainted keeps nothing of what it heard, whether or not more is said.
    #[test]
    fn a_tainted_call_keeps_nothing_even_when_nothing_more_is_said() {
        let mut gate = open();
        for start in [0, 300, 600] {
            gate.provider(said(start, start + 200));
        }
        assert!(!gate.kept.is_empty());
        gate.lost();
        assert!(gate.kept.is_empty());
    }

    /// Capture going off after it first opened taints the call; before that it says nothing.
    #[test]
    fn capture_going_off_after_it_opened_taints_the_call() {
        let mut gate = Gate::new();
        assert_eq!(gate.capture_is_off(), Told::Nothing);
        gate.capture_is_on();
        assert_eq!(gate.capture_is_off(), Told::Tainted(Cause::CaptureBreak));
    }

    /// A set the voice service did not confirm, or that reaches back to what was forgotten, is
    /// refused and spent all the same: the words it held answer no later delegation.
    #[test]
    fn a_set_refused_for_the_service_or_for_age_is_spent() {
        let mut gate = open();
        gate.provider(said(0, 200));
        delegating(&mut gate, "first", 0);
        let _ = gate.freeze(0, CLEAN, Some(0));
        gate.provider(said(6_000, 6_200));
        delegating(&mut gate, "a", 6_000);
        assert_eq!(
            gate.freeze(6_000, CLEAN, Some(7_000)),
            Frozen::Refused(Cause::BrokerDisagrees)
        );
        delegating(&mut gate, "b", 6_100);
        assert_eq!(
            gate.freeze(6_100, CLEAN, Some(6_100)),
            Frozen::Refused(Cause::Empty),
            "what the refused set held is not read again"
        );
    }

    /// The provider's mute taints a call only after capture opened.
    #[test]
    fn the_providers_mute_taints_after_the_opening_only() {
        let mut gate = Gate::new();
        assert_eq!(gate.provider(Provider::InputMuted), Told::Nothing);
        gate.capture_is_on();
        assert_eq!(
            gate.provider(Provider::InputMuted),
            Told::Tainted(Cause::ProviderMuted)
        );
    }

    /// A record that shows a break, or an opening that is not the only one, taints the call at the
    /// freeze, and a set over what the host takes is refused and never cut.
    #[test]
    fn a_record_that_shows_a_break_taints_and_a_set_over_the_hosts_bound_is_refused() {
        let mut gate = open();
        gate.provider(said(0, 100));
        gate.provider(said(1_000, 1_100));
        assert_eq!(
            gate.freeze(1_000, Record { breaks: 1, ..CLEAN }, Some(1_000)),
            Frozen::Refused(Cause::CaptureBreak)
        );
        assert_eq!(gate.taint(), Some(Cause::CaptureBreak));

        let mut gate = open();
        gate.provider(said(0, 10));
        for index in 0..=VOICE_FRAGMENTS_MAX as u64 {
            let start = 5_000 + index * 10;
            gate.provider(said(start, start + 10));
        }
        let offset = 5_000 + (VOICE_FRAGMENTS_MAX as u64) * 10;
        assert_eq!(
            gate.freeze(offset, CLEAN, Some(offset)),
            Frozen::Refused(Cause::TooLarge)
        );
    }
}
