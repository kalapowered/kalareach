//! What a worker asks the control daemon about a draft, and what the daemon answers, on the
//! rendezvous endpoint.
//!
//! The control daemon owns the drafts and the transfers they hold. A worker whose agent is offered
//! an attachment reads the draft first, then claims the one binding it is about to offer, and
//! reports what became of the offer. Each request is one exchange on its own connection and is
//! answered only to the process the daemon recorded for the session it names, so a process that is
//! not that session's worker reads nothing and claims nothing. The worker names the actor the
//! action is for; the daemon looks for the draft among that actor's.
//!
//! The claim and the report name an owner, which is the action the offer was made for. A repeat of
//! a claim by its owner is answered with the same claim, so a reply that was lost does not leave a
//! binding that nothing owns; a report names the owner it was claimed by, so a worker that did not
//! claim a binding cannot settle it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::broker::ActionProvenance;
use crate::error::ProtocolError;
use crate::ids::{
    ActionId, ActorId, ApplicationInstanceId, DraftId, DraftRevision, SessionId, TransferId,
};
use crate::scalars::{Digest256, Nullable, U64};
use crate::transfer::{AttachmentReadGrant, DraftState, InsertionMethod, InsertionState};

/// The longest an upstream's evidence or an offer's failure detail is, in bytes.
///
/// Each is text a client shows and the draft keeps, and a draft's reply carries one per binding.
/// The daemon keeps the room for the longest one of every offer it has claimed, so a report can
/// always be recorded.
pub const MAX_INSERTION_REPORT_BYTES: usize = 512;

/// A worker's question about a draft, with the session and the actor it asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftWanted {
    /// The session whose worker asks. The daemon answers only the process it recorded for it.
    pub session_id: SessionId,
    /// The actor the action is for, as the daemon vouched for it to the worker.
    pub actor_id: ActorId,
    /// What is asked.
    pub step: DraftStep,
}

/// What a worker asks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum DraftStep {
    /// What the draft holds, without its text.
    Facts {
        /// The draft.
        draft_id: DraftId,
    },
    /// Claim one binding to be offered to the agent.
    Begin(InsertionBegin),
    /// Report what became of an offer.
    Report(InsertionReport),
}

/// A claim of one binding for one offer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsertionBegin {
    /// The action the offer is made for, which owns the claim.
    pub action_id: ActionId,
    /// The draft.
    pub draft_id: DraftId,
    /// The attachment.
    pub transfer_id: TransferId,
    /// The attempt the worker read: the binding's order in its draft. A binding bound again is a
    /// new attempt.
    pub attempt: U64,
    /// How many attachments the package's contribution lets a draft hold.
    pub max_count: U64,
    /// The latest moment the claim may be made, on the machine's boot clock in milliseconds. The
    /// daemon makes no claim after it, so a claim the worker gave up on cannot commit later.
    pub deadline_boot_ms: U64,
}

/// What an offer came to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsertionReport {
    /// The action the offer was made for.
    pub action_id: ActionId,
    /// The draft.
    pub draft_id: DraftId,
    /// The attachment.
    pub transfer_id: TransferId,
    /// The attempt that was claimed.
    pub attempt: U64,
    /// What it came to.
    pub outcome: ReportedOutcome,
}

/// What an offer came to, as the worker knows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, tag = "outcome", rename_all = "snake_case")]
pub enum ReportedOutcome {
    /// The upstream took it, and this is how the worker knows.
    AcceptedByAgent {
        /// How the worker knows. A write into the terminal is never evidence.
        provenance: ActionProvenance,
        /// The upstream's own evidence.
        evidence: String,
    },
    /// The offer was refused, or nothing was offered. The draft and the upload are retained.
    Failed {
        /// Why, for the person.
        detail: String,
    },
    /// The offer may have reached the upstream and nothing says whether it was taken.
    Unknown {
        /// What is known.
        detail: String,
    },
}

/// The daemon's answer to a [`DraftWanted`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum DraftAnswer {
    /// What the draft holds.
    Facts(DraftFacts),
    /// The claim.
    Claim(Box<InsertionClaim>),
    /// The report is recorded, and the binding is in this state.
    Reported(InsertionState),
    /// The daemon refused. The error's retry category says whether asking again can succeed.
    Refused(ProtocolError),
}

/// What a draft holds, without its text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftFacts {
    /// The draft.
    pub draft_id: DraftId,
    /// Its revision.
    pub revision: DraftRevision,
    /// Its state.
    pub state: DraftState,
    /// The session it targets.
    pub session_id: Nullable<SessionId>,
    /// The application instance it targets.
    pub application_instance_id: Nullable<ApplicationInstanceId>,
    /// Its bindings, in the order they were bound.
    pub bindings: Vec<BindingFacts>,
}

/// One binding of a draft, without the attachment's name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingFacts {
    /// The attachment.
    pub transfer_id: TransferId,
    /// The binding's attempt.
    pub attempt: U64,
    /// How it was offered to be inserted.
    pub insertion_method: InsertionMethod,
    /// What became of the offer.
    pub state: InsertionState,
    /// The media type the upload was declared with.
    pub media_type: String,
    /// The upload's size in bytes.
    pub byte_len: U64,
    /// The upload's whole-file digest.
    pub content_digest: Digest256,
    /// Where the bytes leave this environment for, when the binding recorded one.
    pub external_destination: Nullable<String>,
}

/// A claim the daemon made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsertionClaim {
    /// The draft as the claim left it.
    pub facts: DraftFacts,
    /// The narrow read grant over the one file. It is revoked when the offer is reported and when
    /// the session ends.
    pub grant: AttachmentReadGrant,
}
