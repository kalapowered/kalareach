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
    /// `connected`, or `unreachable`.
    pub control: String,
    /// Whether the host this call belongs to is being reached: `none` with no call, `reachable`,
    /// or `lost`.
    pub host: String,
    /// The call, as the host described it with the provider's answer left out, while it runs.
    pub session: Option<VoiceSessionDescriptor>,
    /// How the last call ended, until another starts.
    pub ended: Option<EndedView>,
    /// The delegations the provider announced, and what this version did with each.
    pub delegations: Vec<DelegationRow>,
    /// What a person is told before starting, from what the last call showed.
    pub warning: Option<String>,
    /// What this device could not finish and the host may still hold open, until the moment the
    /// call would have closed. It outlives the call that left it and the calls that follow.
    pub owed: Vec<OwedView>,
    /// Which call's owner last wrote this record, so that an owner that failed late does not
    /// overwrite the record of the call after it.
    #[serde(skip)]
    pub owner: u64,
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
            session: None,
            ended: None,
            delegations: Vec::new(),
            warning: None,
            owed: Vec::new(),
            owner: 0,
        }
    }
}

impl VoiceCallState {
    /// Starts the record of a call the owner `owner` holds, keeping what is still owed from the
    /// calls before it.
    pub fn begin(&mut self, owner: u64) {
        let owed = std::mem::take(&mut self.owed);
        *self = Self::no_call();
        self.owed = owed;
        self.owner = owner;
    }

    /// Says that the call the owner `owner` holds is being ended, unless a later owner has begun.
    pub fn begin_ending(&mut self, owner: u64) {
        if self.owner <= owner {
            self.ending = true;
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

/// Something this device could not finish, which the host may still hold open.
#[derive(Clone, Debug, Serialize)]
pub struct OwedView {
    /// `revocation` when a call's grant may still be live at the host, `start_unknown` when the
    /// host never said whether it made a call.
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
    /// What became of it: always `not_done` in this version, which acts on no spoken request.
    pub state: String,
    /// Whether the model was told so.
    pub told: bool,
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
