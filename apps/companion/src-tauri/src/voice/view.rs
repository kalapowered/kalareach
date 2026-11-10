//! What the screen is told of the call this application holds.

use kr_protocol::ids::{ActionId, DeviceId, EnvironmentId, VoiceSessionId};
use kr_protocol::voice::VoiceSessionDescriptor;
use serde::Serialize;

use super::host::CallHost;
use crate::commands::VoiceFence;
use crate::device::hosts::{UNNAMED_HOST, reference_of};

/// What the screen reads of the call, from this application's own record of it.
///
/// Every field is a fact the call's owner holds: the news native code told, the control's state,
/// what the host answered. It is read from here so that it stays true when nothing can be reached,
/// and so that a screen that was loaded again finds the call it left.
#[derive(Clone, Debug, Serialize)]
pub struct VoiceCallState {
    /// Whether this device is holding a call that runs.
    pub running: bool,
    /// Whether this device holds a call that does not run: one being set up, before the host has
    /// said whether it made it too, or one being ended. A screen that finds this finds a device
    /// that is busy and a call it cannot yet name; it can end a setup without naming it.
    pub setting_up: bool,
    /// Whether what the device holds is being ended: the end has begun, and nothing more can be
    /// asked of it. Only while `setting_up` is true.
    pub ending: bool,
    /// What the microphone is doing, in the vocabulary the surface draws.
    pub capture: String,
    /// Whether the model's voice is coming out of this device.
    pub playing: bool,
    /// The call's own control channel to the voice service: `none` when it holds none,
    /// `connecting` while it opens its first socket, `connected`, or `unreachable` once an attempt
    /// has failed and until a socket is held again.
    pub control: String,
    /// Whether the host this call belongs to is being reached: `none` with no call, `reachable`,
    /// or `lost`.
    pub host: String,
    /// Milliseconds from the start of the call to this device's receipt of the news that audio was
    /// played out of it for the first time. An estimate that is taken for the device runs and not
    /// drawn by the screen; absent until that news comes, and for a call that never plays any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_audio_ms: Option<u64>,
    /// The call, as the host described it with the provider's answer left out, while it runs.
    pub session: Option<VoiceSessionDescriptor>,
    /// How the last call ended, until another starts.
    pub ended: Option<EndedView>,
    /// The delegations the provider announced, and what this version did with each.
    pub delegations: Vec<DelegationRow>,
    /// What the call met that a person is told, each problem once, from the moment it was met until
    /// another call begins: on the running call, and after it for the person who starts the next.
    pub problems: Vec<CallProblem>,
    /// What this device could not finish and the host may still hold open, until the moment the
    /// call would have closed. It outlives the call that left it and the calls that follow.
    pub owed: Vec<OwedView>,
    /// Which call's owner last wrote this record, so that an owner that failed late does not
    /// overwrite the record of the call after it.
    #[serde(skip)]
    pub owner: u64,
    /// The owners that have ended a call and have still to say what the voice service did about
    /// it, whose call may by now be another's record. The screen is told only whether there are
    /// any: while there are, what the service did may still arrive as something owed, and the
    /// screen keeps reading. It lives in the record so that every copy of the record carries it,
    /// and is kept across a new call's start as what is owed is.
    #[serde(rename = "finalising", serialize_with = "any_owner")]
    pub finalising_owners: std::collections::BTreeSet<u64>,
}

/// Whether any owner is finalising, as the screen reads it.
fn any_owner<S: serde::Serializer>(
    owners: &std::collections::BTreeSet<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_bool(!owners.is_empty())
}

impl VoiceCallState {
    /// The state of a device holding no call.
    #[must_use]
    pub fn no_call() -> Self {
        Self {
            running: false,
            setting_up: false,
            ending: false,
            capture: "idle".to_owned(),
            playing: false,
            control: "none".to_owned(),
            host: "none".to_owned(),
            first_audio_ms: None,
            session: None,
            ended: None,
            delegations: Vec::new(),
            problems: Vec::new(),
            owed: Vec::new(),
            owner: 0,
            finalising_owners: std::collections::BTreeSet::new(),
        }
    }
}

impl VoiceCallState {
    /// Starts the record of a call the owner `owner` holds, keeping what is still owed from the
    /// calls before it.
    pub fn begin(&mut self, owner: u64) {
        let owed = std::mem::take(&mut self.owed);
        let finalising = std::mem::take(&mut self.finalising_owners);
        *self = Self::no_call();
        self.owed = owed;
        self.finalising_owners = finalising;
        self.owner = owner;
    }

    /// Says that the call the owner `owner` holds is being ended, unless a later owner has begun.
    pub fn begin_ending(&mut self, owner: u64) {
        if self.owner <= owner {
            self.ending = true;
        }
    }

    /// Notes a problem the call met. A problem of the same kind that still stands is the same
    /// problem, and says what is said of it now; one that is over, and every other kind, is kept
    /// beside it, and none is dropped for the sake of another: the record is the call's, and the
    /// owner's probe of a host path that was lost is paced, so it grows by at most one problem in
    /// each pause between probes.
    pub fn meet(&mut self, kind: ProblemKind, words: String) {
        if let Some(standing) = self
            .problems
            .iter_mut()
            .find(|each| each.kind == kind && !each.over)
        {
            standing.words = words;
            return;
        }
        self.problems.push(CallProblem {
            kind,
            words,
            over: false,
        });
    }

    /// Says that what a problem of this kind said no longer holds. It stays in the record: the
    /// call met it.
    pub fn pass(&mut self, kind: ProblemKind) {
        for each in self.problems.iter_mut().filter(|each| each.kind == kind) {
            each.over = true;
        }
    }

    /// Notes something owed until its `until_ms`, and forgets what has lapsed by `now_ms`.
    ///
    /// Nothing that has not lapsed is dropped to make room: a grant the host may still hold open is
    /// told to the person until it ends, however many there are. The list is bounded by time, as
    /// each entry ends by itself, and by the calls a device can make in that time.
    pub fn owe(&mut self, now_ms: u64, owed: OwedView) {
        self.owed.retain(|each| each.until_ms > now_ms);
        self.owed.push(owed);
    }
}

/// What kind of problem a call met.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemKind {
    /// The call was not given all of the host's context as its opening context: the host did not
    /// give it, the voice service took part of it, or the call ended before it was all given.
    OpeningContext,
    /// The host answered, but would not say that the call is still its own.
    HostPath,
    /// The last call found that the voice service has no such call for this account.
    NoSuchCall,
    /// The call can no longer hand a spoken request to the host: what was said may not all have
    /// been heard and read.
    SpokenRequests,
}

/// A problem a call met, in words for a person.
#[derive(Clone, Debug, Serialize)]
pub struct CallProblem {
    /// What kind of problem it is, which the screen branches on.
    pub kind: ProblemKind,
    /// What a person is told.
    pub words: String,
    /// Whether what it says no longer holds: the host that would not vouch for the call has
    /// answered since.
    pub over: bool,
}

/// Something this device could not finish, which the host may still hold open.
#[derive(Clone, Debug, Serialize)]
pub struct OwedView {
    /// `revocation` when a call's grant may still be live at the host, `start_unknown` when the
    /// host never said whether it made a call, `service_close` when the voice service has not
    /// confirmed that it closed a call.
    pub kind: String,
    /// What a person is told.
    pub words: String,
    /// The action a start was sent under, for `start_unknown`.
    pub action_id: Option<String>,
    /// The call whose grant may be live, for `revocation`.
    pub voice_session_id: Option<String>,
    /// The moment the grant ends by itself, in milliseconds since the epoch, with room for a clock
    /// that is not this device's own.
    pub until_ms: u64,
    /// What the page names the host this is owed to by: the reference its list of hosts uses.
    pub host_reference: String,
    /// The name the host gives people.
    pub host_name: String,
    /// The host's identity and environment, which this device asks again when it reaches the host.
    /// Kept with the entry from one launch to the next, and never sent to the page.
    #[serde(skip)]
    pub host: Option<(DeviceId, EnvironmentId)>,
}

impl HostEnd {
    /// What a revocation owed to the host is owed for, in words, when this end leaves one owed: the
    /// host was not told, did not answer, or refused (which does not say the grant is gone).
    #[must_use]
    pub fn owed_reason(&self) -> Option<String> {
        match self {
            Self::NotTold { words } => Some(words.clone()),
            Self::Refused { words } => Some(format!("The host refused the stop: {words}")),
            Self::Revoked { .. } | Self::NotHeld { .. } | Self::NotNeeded => None,
        }
    }

    /// Whether the host's answer settles a revocation owed to it: it revoked the grant, or it
    /// holds no call of this device by that name, so a stop from this device can end nothing more
    /// there. A refusal that says neither leaves the revocation owed.
    #[must_use]
    pub const fn settles(&self) -> bool {
        matches!(self, Self::Revoked { .. } | Self::NotHeld { .. })
    }
}

impl OwedView {
    /// A call's grant that `host` may still hold open until `until_ms`, for the reason `words`.
    #[must_use]
    pub fn revocation(
        words: String,
        voice_session_id: VoiceSessionId,
        until_ms: u64,
        host: &CallHost,
    ) -> Self {
        Self {
            kind: "revocation".to_owned(),
            words,
            action_id: None,
            voice_session_id: Some(voice_session_id.to_string()),
            until_ms,
            ..Self::of(host)
        }
    }

    /// A start `host` never said it answered, which may have made a call whose grant stands until
    /// `until_ms`.
    #[must_use]
    pub fn start_unknown(action_id: ActionId, until_ms: u64, host: &CallHost) -> Self {
        Self {
            kind: "start_unknown".to_owned(),
            words: "The host never said whether it created the call. If it did, its grant ends by \
                    itself when the call was to close."
                .to_owned(),
            action_id: Some(action_id.to_string()),
            voice_session_id: None,
            until_ms,
            ..Self::of(host)
        }
    }

    /// A service `host` made a call for, that the voice service has not said it closed, though this
    /// device asked: the call's own limit has not passed. The notice lapses with it, at `until_ms`,
    /// which is when the host's reading of the call's limit and the clock allowance are over. It
    /// does not say when the service closes the call; it may close it later than that.
    #[must_use]
    pub fn service_close(voice_session_id: VoiceSessionId, until_ms: u64, host: &CallHost) -> Self {
        let base = Self::of(host);
        Self {
            kind: "service_close".to_owned(),
            words: format!(
                "The voice service has not confirmed that it closed the call that {} started.",
                base.host_name
            ),
            action_id: None,
            voice_session_id: Some(voice_session_id.to_string()),
            until_ms,
            ..base
        }
    }

    /// The part of an entry that says which host it is owed to.
    fn of(host: &CallHost) -> Self {
        Self {
            kind: String::new(),
            words: String::new(),
            action_id: None,
            voice_session_id: None,
            until_ms: 0,
            host_reference: reference_of(&host.paired),
            host_name: host
                .paired
                .name
                .clone()
                .unwrap_or_else(|| UNNAMED_HOST.to_owned()),
            host: Some((host.paired.host_device_id, host.environment_id)),
        }
    }
}

/// What the host did about the end of a call, kept apart from what happened on this device.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostEnd {
    /// The host answered the stop: it revoked the call's grant.
    Revoked {
        /// The status of its fence, as the page reads it.
        fence: VoiceFence,
        /// Whether the host also told the voice service the call ended.
        broker_notified: bool,
    },
    /// The host answered the stop with a refusal that says it holds no call of this device by that
    /// name: it ended the call, it started again, or the call is another device's. A stop from
    /// this device can end nothing more there. It does not say a grant is gone, or that a fence the
    /// host owes its workers is done; the host keeps what it owes.
    NotHeld {
        /// What the host said.
        words: String,
    },
    /// The host answered the stop with a refusal that says nothing of whether it holds the call:
    /// it may not have looked at it, and a grant it holds ends at the moment the call was to
    /// close. The revocation is owed.
    Refused {
        /// What the host said.
        words: String,
    },
    /// The host was not told, or did not answer: the revocation is owed.
    NotTold {
        /// Why.
        words: String,
    },
    /// There was nothing to tell it: the host never created a call.
    NotNeeded,
}

/// How a call ended.
#[derive(Clone, Debug, Serialize)]
pub struct EndedView {
    /// Which call's owner wrote this, so that a later one is not overwritten by an earlier one.
    #[serde(skip)]
    pub owner: u64,
    /// Why, as a word the screen branches on.
    pub cause: String,
    /// Why, in words for a person.
    pub words: String,
    /// Whether the call's media was stopped on this device.
    pub closed_locally: bool,
    /// What the host did.
    pub host: HostEnd,
    /// What the voice service did: `pending` while its closure is awaited, then `closed` (by the
    /// control), `closed_by_service`, `closed_by_host`, `closed_over_http` or `not_confirmed`;
    /// `unknown` when the host never said whether it made a call, so the service may hold one this
    /// device cannot name; or `not_needed` when the host never created a call.
    pub broker: String,
}

/// A delegation the provider announced, and the answer this version gives it.
#[derive(Clone, Debug, Serialize)]
pub struct DelegationRow {
    /// The provider's identifier. Correlation data, never authority.
    pub delegation_id: String,
    /// Where in the call it happened, in milliseconds from its start, when the voice service said:
    /// a delegation listed when the control attached carries no offset.
    pub offset_ms: Option<u64>,
    /// What became of it. `not_done` for every delegation while this version acts on no spoken
    /// request. A call that hands spoken requests to the host, which only a case or the debug
    /// build's probe makes, also says `collecting` (the fragments said before it are still being
    /// read), `asking` (the host has the request and has not answered), `refused` (this device
    /// would not hand it over, for `cause`), `not_sent` (nothing was written to the host, for
    /// `cause`), `performed`, `admitted` (the host took it and what became of it is not
    /// established), `confirmation_required`, `cancelled` (a challenge the host awaited an answer
    /// to was dropped, for `cause`), `host_refused` (the host said no, for `cause`) and `unknown`
    /// (the request may have been written and no answer came).
    pub state: String,
    /// Whether the model was told what became of it.
    pub told: bool,
    /// Why, for the states that name a cause. Absent while this version acts on nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owed(until_ms: u64) -> OwedView {
        OwedView {
            kind: "revocation".to_owned(),
            words: String::new(),
            action_id: None,
            voice_session_id: None,
            until_ms,
            host_reference: "a-host".to_owned(),
            host_name: "A host".to_owned(),
            host: None,
        }
    }

    /// Each problem a call met is kept: a later one of another kind is beside the first and does not
    /// replace it, a refusal that is repeated is one problem, and one that has passed stays in the
    /// record, so a refusal after the host answered again is a problem of its own.
    #[test]
    fn each_problem_a_call_met_is_kept_and_none_replaces_another() {
        let mut state = VoiceCallState::no_call();
        state.meet(ProblemKind::OpeningContext, "no context".to_owned());
        state.meet(ProblemKind::HostPath, "would not vouch".to_owned());
        state.meet(ProblemKind::HostPath, "would not vouch, again".to_owned());
        let words = |state: &VoiceCallState| -> Vec<(ProblemKind, String, bool)> {
            state
                .problems
                .iter()
                .map(|each| (each.kind, each.words.clone(), each.over))
                .collect()
        };
        assert_eq!(
            words(&state),
            [
                (ProblemKind::OpeningContext, "no context".to_owned(), false),
                (
                    ProblemKind::HostPath,
                    "would not vouch, again".to_owned(),
                    false
                ),
            ]
        );

        state.pass(ProblemKind::HostPath);
        state.meet(ProblemKind::HostPath, "would not vouch later".to_owned());
        assert_eq!(
            words(&state),
            [
                (ProblemKind::OpeningContext, "no context".to_owned(), false),
                (
                    ProblemKind::HostPath,
                    "would not vouch, again".to_owned(),
                    true
                ),
                (
                    ProblemKind::HostPath,
                    "would not vouch later".to_owned(),
                    false
                ),
            ]
        );
    }

    /// A call keeps every problem it met, however many: a host that refuses to vouch for the call and
    /// answers again, over and over, leaves each refusal that passed in the record.
    #[test]
    fn a_call_keeps_every_problem_that_passed_however_many() {
        let mut state = VoiceCallState::no_call();
        for index in 0..40 {
            state.meet(ProblemKind::HostPath, format!("would not vouch, {index}"));
            state.pass(ProblemKind::HostPath);
        }

        assert_eq!(state.problems.len(), 40);
        assert!(state.problems.iter().all(|each| each.over));
        assert_eq!(state.problems[0].words, "would not vouch, 0");
    }

    /// A grant the host may still hold open is told to the person until it ends by itself, however
    /// many calls left one; only what has lapsed is forgotten.
    #[test]
    fn what_is_owed_is_forgotten_when_it_lapses_and_never_to_make_room() {
        let mut state = VoiceCallState::no_call();
        for index in 0..20 {
            state.owe(0, owed(1_000 + index));
        }
        assert_eq!(state.owed.len(), 20, "none was dropped for room");

        state.owe(1_010, owed(5_000));

        assert!(state.owed.iter().all(|each| each.until_ms > 1_010));
        assert_eq!(
            state.owed.len(),
            10,
            "nine that had not lapsed, and the new one"
        );
    }
}
