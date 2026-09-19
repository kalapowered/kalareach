//! The authority vocabulary used by every method entry.
//!
//! Section 23 requires one exhaustive generated authority entry per method and per plugin effect,
//! covering the read or write effect class, permitted actor ingress, required rights, resource
//! selectors, history filter, capability revision, freshness and expiry, confirmation and
//! idempotency behaviour. Any effect that is not listed defaults to denied.
//!
//! The types here are that vocabulary. [`crate::method::REGISTRY`] is the table itself.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::actor::ActorIngress;
use crate::error::ErrorCode;
use crate::method::{Method, MethodGroup, MethodVersion};
use crate::rights::ActionRight;

/// Whether a method observes state or changes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    /// Observes state. A read never crosses an external-effect boundary and carries no receipt.
    Read,
    /// Changes state. A write carries an action identifier, a freshness context and a receipt.
    Write,
}

/// What a request must present besides a valid current grant.
///
/// An empty required-rights list is not "no check". It means scoped read authority and nothing
/// more: a valid, unexpired, unrevoked grant for this actor that covers the named environment and
/// the named resource. Only reads of host and environment configuration use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RequiredAuthority {
    /// One right from the section 10 action vocabulary.
    Right {
        /// The required right.
        right: ActionRight,
    },
    /// Ownership of the named resource by the verified actor: its own draft, its own attachment,
    /// its own question or its own undispatched action.
    ResourceOwner,
    /// A pairing transcript proof bound to the pinned endpoint identities.
    PairingTranscript,
    /// The invitation's issuing-owner context.
    IssuingOwnerContext,
    /// A separately created voice grant, intersected with the actor's ordinary grant.
    VoiceGrant,
    /// An installation or host service credential presented at a service endpoint.
    ServiceCredential,
    /// The registered plugin effect's own declared rights, intersected at dispatch.
    PluginEffectRights,
    /// The verified originating application or helper and its caller token on private IPC.
    LocalCallerToken,
    /// Current issuer or delegation authority over the named grant: the actor holds the parent
    /// grant it is delegating from, or issued the grant it is revoking. Holding a right that a
    /// grant happens to contain never implies authority over the grant itself.
    IssuerDelegation,
    /// Current read authority over the subject the host resolves from the named resource, rather
    /// than over a resource the request states. For a session subject that is `session.view` at
    /// the session's current scope; for a host or environment subject it is the actor's current
    /// read scope over that environment. It is a read requirement: permission to have performed
    /// the original effect is not required, and is not sufficient either. Holding a stale
    /// identifier is never enough.
    PresentViewAuthority,
}

/// When a required authority applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RightCondition {
    /// Always required.
    Always,
    /// Required only when the request claims or adds a geometry claim.
    GeometryClaim,
    /// Required only when the subject belongs to the verified actor itself.
    OwnSubject,
    /// Required only when the subject belongs to another actor.
    OtherActor,
    /// Required only when the caller is the pairing candidate rather than the issuing owner.
    CandidateEndpoint,
    /// Required only when the caller is the invitation's issuing owner rather than the candidate.
    IssuingOwner,
}

/// One entry in a method's required-authority list.
///
/// A composite action intersects every entry whose condition holds. A configuration or role label
/// never short-circuits one of these checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequiredRight {
    /// What must be presented.
    pub authority: RequiredAuthority,
    /// When it must be presented.
    pub when: RightCondition,
}

impl RequiredRight {
    /// An always-required right from the action vocabulary.
    #[must_use]
    pub const fn right(right: ActionRight) -> Self {
        Self {
            authority: RequiredAuthority::Right { right },
            when: RightCondition::Always,
        }
    }

    /// A right from the action vocabulary required only under `when`.
    #[must_use]
    pub const fn right_when(right: ActionRight, when: RightCondition) -> Self {
        Self {
            authority: RequiredAuthority::Right { right },
            when,
        }
    }

    /// An always-required authority that is not a right from the vocabulary.
    #[must_use]
    pub const fn basis(authority: RequiredAuthority) -> Self {
        Self {
            authority,
            when: RightCondition::Always,
        }
    }

    /// An authority that is not a right from the vocabulary, required only under `when`.
    #[must_use]
    pub const fn basis_when(authority: RequiredAuthority, when: RightCondition) -> Self {
        Self { authority, when }
    }
}

/// Which resource identities a request names and the host resolves before the authority check.
///
/// An attachment's identifier alone is not permission: it selects a resource, and the rights check
/// still runs against the resolved resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceSelectorKind {
    /// The host itself.
    Host,
    /// One execution environment.
    Environment,
    /// One session.
    Session,
    /// One attachment.
    Attachment,
    /// One foreground application instance.
    ApplicationInstance,
    /// One paired device.
    Device,
    /// One grant.
    Grant,
    /// One pairing invitation and candidate attempt.
    Invitation,
    /// One plugin catalogue.
    Catalogue,
    /// One plugin package.
    Plugin,
    /// One question.
    Question,
    /// One draft.
    Draft,
    /// One upload or download transfer.
    Transfer,
    /// One project repository.
    Project,
    /// One workspace.
    Workspace,
    /// One change set version.
    ChangeSet,
    /// One event stream and cursor range.
    EventStream,
    /// One action receipt.
    Action,
    /// One automation definition or run.
    Workflow,
    /// One native application installation.
    Installation,
    /// One managed voice session.
    VoiceSession,
    /// One encrypted mailbox.
    Mailbox,
    /// The target agent of a skill installation.
    AgentTarget,
}

/// How the shared host-side history filter applies to a method's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HistoryFilter {
    /// The method returns no retained history or derived content.
    NotApplicable,
    /// The grant's history lower bound applies to every returned event, snapshot, transcript,
    /// attachment reference, export and summary. Derived data identifies its source interval and
    /// is omitted or recomputed when that provenance crosses the viewer's scope.
    GrantLowerBound,
    /// Live view only: the currently visible screen. Inactive buffers, scrollback and the backing
    /// transcript stay excluded until actually displayed or separately granted.
    LiveViewOnly,
    /// Current questions or approval resources the grant names explicitly, even when they were
    /// created before the history lower bound. Without that scope the lower bound applies.
    NamedCurrentResources,
}

/// Which revision a capability check is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevisionBinding {
    /// The active agent binding revision.
    AgentBinding,
    /// The session epoch.
    SessionEpoch,
    /// The current input lease epoch.
    InputLeaseEpoch,
    /// The current geometry-owner epoch.
    GeometryEpoch,
    /// The exact question revision.
    QuestionRevision,
    /// The exact draft revision.
    DraftRevision,
    /// The exact change-set version.
    ChangeSetVersion,
    /// The exact version of the subject a review acknowledgement names.
    ///
    /// A review binds to a completed turn as well as to a captured change set, and a turn has no
    /// change-set version to be bound to. This is the version of whichever subject the
    /// acknowledgement names, which is what section 14 requires an acknowledgement to carry.
    ReviewSubjectVersion,
    /// The host authority revision.
    AuthorityRevision,
    /// The device's authorisation or preview key revision.
    DeviceKeyRevision,
    /// The verified plugin package hash.
    PackageHash,
    /// The catalogue repository generation.
    RepositoryGeneration,
    /// The automation definition version.
    WorkflowDefinitionVersion,
    /// The trusted root editor's fence state.
    RootEditorFence,
    /// The installation key revision at a push gateway.
    InstallationKeyRevision,
}

/// Which capability evidence a method requires, and at which revision.
///
/// Capabilities describe feasibility. They never create authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CapabilityRequirement {
    /// No capability evidence beyond the method being listed.
    None,
    /// The named capability must be currently evidenced at the bound revision.
    Required {
        /// The capability name.
        capability_id: &'static str,
        /// The revision the evidence is bound to.
        revision: RevisionBinding,
    },
}

/// Which freshness context a request must carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessRequirement {
    /// Current authority, expiry and revocation revision are revalidated when the request is
    /// served. A read carries no action window.
    CurrentAuthority,
    /// A host-issued action window plus the requested time to live. The host derives the accepted
    /// deadline as the earliest of window expiry, receipt time plus the requested time to live and
    /// any applicable authority or subject deadline. A local IPC caller receives the host-stamped
    /// equivalent context instead of a network window.
    ActionWindow,
    /// The current input lease epoch and connection stream identity. Raw input is an ordered
    /// stream, not an admitted action.
    InputLease,
    /// The invitation's deadline and its attempt budget.
    InvitationDeadline,
    /// A service credential's validity plus the host's current authority revision.
    ServiceCredential,
}

/// Whether a method needs a fresh owner confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationRequirement {
    /// No owner confirmation. Already-authorised restriction, revocation and emergency stop never
    /// need a new rights-enlarging confirmation.
    None,
    /// A fresh owner confirmation bound to the exact action digest, destination keys and rights,
    /// host, nonce and short expiry.
    Always,
    /// A fresh owner confirmation only when the request enlarges persistent authority: a new trust
    /// root, a wider capability ceiling or a persistent grant enlargement.
    WhenEnlargingAuthority,
}

/// How a repeated request is resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum IdempotencyBehaviour {
    /// An idempotent read. An automatic retry is permitted.
    IdempotentRead,
    /// Deduplicated by the verified actor and action identifier against the payload digest. A
    /// duplicate returns the retained receipt without dispatch; a reused identifier with a
    /// different payload is an `ID_CONFLICT`.
    ActionDeduplicated,
    /// Idempotent under a protocol key. A matching duplicate is acknowledged; a conflicting
    /// duplicate invalidates the operation.
    Keyed {
        /// The key the operation is idempotent under.
        key: &'static str,
    },
    /// An ordered stream. Positions are acknowledged per connection and never replayed;
    /// reconnecting creates a new stream identity.
    OrderedStream,
}

/// One exhaustive authority entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct MethodEntry {
    /// The method this entry governs.
    pub method: Method,
    /// The stable wire name.
    pub name: &'static str,
    /// The method group from section 23.
    pub group: MethodGroup,
    /// The method version this entry describes.
    pub version: MethodVersion,
    /// Read or write.
    pub effect: EffectClass,
    /// The only ingress classes that may reach this method.
    pub ingress: &'static [ActorIngress],
    /// Everything the actor must present, intersected.
    pub required_rights: &'static [RequiredRight],
    /// The resources the request names and the host resolves.
    pub resource_selectors: &'static [ResourceSelectorKind],
    /// How the history filter applies to the result.
    pub history_filter: HistoryFilter,
    /// Which capability evidence is required, and at which revision.
    pub capability: CapabilityRequirement,
    /// Which freshness context the request must carry.
    pub freshness: FreshnessRequirement,
    /// Whether a fresh owner confirmation is required.
    pub confirmation: ConfirmationRequirement,
    /// How a repeated request is resolved.
    pub idempotency: IdempotencyBehaviour,
    /// What the method does.
    pub summary: &'static str,
}

impl MethodEntry {
    /// Returns true when `ingress` may reach this method.
    #[must_use]
    pub fn permits_ingress(&self, ingress: ActorIngress) -> bool {
        self.ingress.contains(&ingress)
    }

    /// Returns the rights that always apply, ignoring conditional entries.
    pub fn unconditional_rights(&self) -> impl Iterator<Item = ActionRight> + '_ {
        self.required_rights.iter().filter_map(|required| {
            match (required.when, required.authority) {
                (RightCondition::Always, RequiredAuthority::Right { right }) => Some(right),
                _ => None,
            }
        })
    }
}

/// Why a request is refused before any parameter is parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenialReason {
    /// The method name is not in the registry. Anything unlisted is denied.
    UnlistedMethod,
    /// The method exists but not at the requested version.
    UnsupportedVersion {
        /// The version this build implements.
        supported: MethodVersion,
    },
    /// The ingress class may not reach this method.
    ForbiddenIngress {
        /// The ingress the request arrived on.
        ingress: ActorIngress,
    },
}

impl DenialReason {
    /// Returns the error code to return for this denial.
    #[must_use]
    pub const fn error_code(self) -> ErrorCode {
        match self {
            // An unlisted name and a forbidden ingress are both authority failures. Neither tells
            // the caller anything about what exists behind the boundary.
            Self::UnlistedMethod | Self::ForbiddenIngress { .. } => ErrorCode::PermissionDenied,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedSchema,
        }
    }
}

/// The result of looking a request up in the registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityDecision {
    /// The method is listed and its entry governs the request.
    Listed(&'static MethodEntry),
    /// The request is denied before any parameter is parsed.
    Denied(DenialReason),
}
