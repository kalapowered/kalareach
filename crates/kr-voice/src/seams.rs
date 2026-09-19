//! The three narrow seams the host implements.
//!
//! This crate never opens a store, never reaches a worker and never performs an effect. It reads
//! through [`ContextSource`], decides against what [`VoiceAuthority`] gives it, and proposes
//! through [`ActionSubmitter`]. Keeping them narrow is what makes the data-access boundary in the
//! crate documentation checkable rather than asserted: there is no other way in or out.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use kr_protocol::grant::Grant;
use kr_protocol::ids::{ActionId, ApprovalRequestId, DeviceId, GrantId, SessionId};
use kr_protocol::scalars::{CanonicalSet, Digest256};
use kr_protocol::voice::{VoiceAction, VoiceContextClass};

use crate::error::Result;

/// A boxed future, so every seam stays usable behind a trait object.
pub type VoiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/* -------------------------------------------------------------------------- */
/* Reading                                                                     */
/* -------------------------------------------------------------------------- */

/// One piece of content, with the moment it was produced.
///
/// The moment is not decoration. The coordinator applies the grant's history lower bound to every
/// item it is handed, so an item that cannot say when it was produced is an item that cannot be
/// admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextItem {
    /// The text.
    pub text: String,
    /// When it was produced, in UTC milliseconds.
    pub produced_at_ms: u64,
}

impl ContextItem {
    /// Builds an item.
    #[must_use]
    pub fn new(text: impl Into<String>, produced_at_ms: u64) -> Self {
        Self {
            text: text.into(),
            produced_at_ms,
        }
    }
}

/// One piece of content from a class the person selected on top of the default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedItem {
    /// Which class it belongs to.
    pub class: VoiceContextClass,
    /// The content.
    pub item: ContextItem,
}

/// A run of content the host's filter kept back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithheldRun {
    /// Why, in the filter's own words.
    pub reason: String,
    /// How many items.
    pub count: u64,
}

/// What the coordinator asks the host to gather.
///
/// The grant is the **requesting device's**. There is no owner variant and no flag that widens the
/// scope, because section 10 says voice selection intersects the requesting device's scope and
/// cannot use the host owner's broader history by default: a parameter that could express the
/// wider scope would be a parameter somebody could pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextRequest {
    /// The session the context is about.
    pub session_id: SessionId,
    /// The grant the host already checked, and the only scope the selection may use.
    pub grant: Grant,
    /// Content classes the person selected on top of the default.
    pub selected: CanonicalSet<VoiceContextClass>,
}

/// What the host gathered, already filtered.
///
/// Every field here has passed the shared host-side filter at `Surface::VoiceContext` under a
/// viewer scope built from [`ContextRequest::grant`]. The coordinator applies the grant's lower
/// bound again before it uses any of it, so this is a statement the host makes and the coordinator
/// checks rather than one it takes on trust.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GatheredContext {
    /// The session's description, when the host has one.
    pub session_description: Option<ContextItem>,
    /// The current working directory.
    pub working_directory: Option<ContextItem>,
    /// The active application.
    pub active_application: Option<ContextItem>,
    /// Summaries of the decisions waiting on a person, newest last.
    pub pending_decisions: Vec<ContextItem>,
    /// Semantic messages, oldest first. The coordinator keeps the last twenty.
    pub recent_messages: Vec<ContextItem>,
    /// Content from the classes the person selected.
    pub selected: Vec<SelectedItem>,
    /// The resources the gathering read, as the host names them.
    pub resources: Vec<String>,
    /// What the filter kept back, so a gap is visible rather than silent.
    pub withheld: Vec<WithheldRun>,
}

/// Where the coordinator reads a session's content.
pub trait ContextSource: Send + Sync + fmt::Debug {
    /// Gathers what this device may see of one session.
    ///
    /// The implementation passes every item through the shared host-side history filter at
    /// `Surface::VoiceContext`, under a viewer scope built from the request's grant and from
    /// nothing else, and reports what it kept back.
    ///
    /// # Errors
    ///
    /// Returns an error when the session cannot be read.
    fn gather<'a>(&'a self, request: &'a ContextRequest) -> VoiceFuture<'a, GatheredContext>;

    /// Reads the details of one approval request, as the host holds them.
    ///
    /// Section 15 ¶13: an approval decision requires the verified request's details. The
    /// coordinator compares the digest the device answered against this, so a model that invented
    /// the details is refused rather than believed.
    ///
    /// # Errors
    ///
    /// Returns an error when the approval cannot be read.
    fn approval_details<'a>(
        &'a self,
        session_id: SessionId,
        approval_request_id: &'a ApprovalRequestId,
    ) -> VoiceFuture<'a, Option<Digest256>>;
}

/* -------------------------------------------------------------------------- */
/* Deciding                                                                    */
/* -------------------------------------------------------------------------- */

/// Where the coordinator reads and writes grants.
///
/// The store is the host's one authority store. This crate reads through its public interface and
/// intersects at decision time; it keeps no authority of its own and holds no second store.
///
/// These calls are synchronous because the host's grant store is: a decision that took a future
/// would be a decision a subject could move underneath.
pub trait VoiceAuthority: Send + Sync + fmt::Debug {
    /// Returns the ordinary grant this device holds for `session_id`, when it holds one.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read.
    fn device_grant(
        &self,
        device_id: DeviceId,
        session_id: Option<SessionId>,
    ) -> Result<Option<Grant>>;

    /// Returns the live grant with this identity, when it is live.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read.
    fn grant(&self, grant_id: GrantId) -> Result<Option<Grant>>;

    /// Returns this device's standing voice grant, when it has one.
    ///
    /// The standing grant is what `voice.grant` wrote: the voice actions this person chose to
    /// permit. A call's own grant is delegated from it, so withdrawing this one ends the calls
    /// running under it.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read.
    fn standing_voice_grant(&self, device_id: DeviceId) -> Result<Option<Grant>>;

    /// Writes a grant the coordinator planned.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant cannot be written.
    fn issue(&self, plan: &crate::grant::VoiceGrantPlan) -> Result<Grant>;

    /// Revokes a grant and everything delegated from it, and reports when.
    ///
    /// # Errors
    ///
    /// Returns an error when the revocation cannot be written.
    fn revoke(&self, grant_id: GrantId, now_ms: u64) -> Result<u64>;

    /// The device identity key that signs this device's authority-bearing requests.
    ///
    /// Section 15 ¶8's confirmation is checked against this key and never against a session key.
    ///
    /// # Errors
    ///
    /// Returns an error when the device record cannot be read.
    fn device_identity_key(
        &self,
        device_id: DeviceId,
    ) -> Result<Option<kr_protocol::scalars::AuthorisationKey>>;
}

/* -------------------------------------------------------------------------- */
/* Proposing                                                                   */
/* -------------------------------------------------------------------------- */

/// What the host did about one proposal.
///
/// A receipt, because a receipt is what section 15 ¶10 makes authoritative. Nothing in this crate
/// reports an action as done from anything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostReceipt {
    /// The action the host performed.
    pub action_id: ActionId,
    /// Whether the effect happened. False means the host admitted the request and did not perform
    /// it, which is reported as admitted and never as done.
    pub performed: bool,
    /// One line about what happened, for the coordinator to speak.
    pub summary: String,
}

/// Where the coordinator proposes an effect.
///
/// The coordinator proposes and the host validates normally: nothing here bypasses a check because
/// the request arrived by speech.
pub trait ActionSubmitter: Send + Sync + fmt::Debug {
    /// Submits one proposal and returns the host's receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when the host refused the proposal or could not be reached.
    fn submit<'a>(
        &'a self,
        proposal: &'a crate::delegate::Proposal,
    ) -> VoiceFuture<'a, HostReceipt>;
}

/// The action a proposal carries, as the host reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalKind(pub VoiceAction);
