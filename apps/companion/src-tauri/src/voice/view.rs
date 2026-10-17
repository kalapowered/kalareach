//! What the screen is told of the call this application holds.

use kr_protocol::voice::VoiceSessionDescriptor;
use serde::Serialize;

use crate::commands::VoiceFence;

/// What the screen reads of the call, from this application's own record of it.
///
/// Every field is a fact the call's owner holds: the news native code told, the control's state,
/// what the host answered. It is read from here so that it stays true when nothing can be reached,
/// and so that a screen that was loaded again finds the call it left.
#[derive(Clone, Debug, Serialize)]
pub struct VoiceCallState {
    /// Whether this device is holding a call at all.
    pub running: bool,
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

/// The most things a device keeps as owed at once.
const MOST_OWED: usize = 8;

impl VoiceCallState {
    /// Starts the record of a call the owner `owner` holds, keeping what is still owed from the
    /// calls before it.
    pub fn begin(&mut self, owner: u64) {
        let owed = std::mem::take(&mut self.owed);
        *self = Self::no_call();
        self.owed = owed;
        self.owner = owner;
    }

    /// Notes something owed until `until_ms`, and forgets what has lapsed by `now_ms`.
    pub fn owe(&mut self, now_ms: u64, owed: OwedView) {
        self.owed.retain(|each| each.until_ms > now_ms);
        self.owed.push(owed);
        if self.owed.len() > MOST_OWED {
            self.owed.remove(0);
        }
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
    /// The moment the grant ends by itself, in milliseconds since the epoch.
    pub until_ms: u64,
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
    /// The host answered the stop with a refusal. It no longer knows the call, or does not let
    /// this device stop it, and a grant it holds ends at the moment the call was to close.
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
    /// control), `closed_by_service`, `closed_by_host`, `closed_over_http` or `not_confirmed`; or
    /// `not_needed` when the host never created a call.
    pub broker: String,
}

/// A delegation the provider announced, and the answer this version gives it.
#[derive(Clone, Debug, Serialize)]
pub struct DelegationRow {
    /// The provider's identifier. Correlation data, never authority.
    pub delegation_id: String,
    /// Where in the call it happened, in milliseconds from its start.
    pub offset_ms: u64,
    /// What became of it: always `not_done` in this version, which acts on no spoken request.
    pub state: String,
    /// Whether the model was told so.
    pub told: bool,
}
