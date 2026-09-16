//! The method registry: one exhaustive authority entry per method.
//!
//! [`REGISTRY`] is the table section 23 requires. Every method in the method-groups table has
//! exactly one entry, and [`decide`] denies anything that is not listed. The table above the
//! registry is the minimum public surface, not permission to invent an unaudited effect under an
//! existing name.
//!
//! Reading an entry:
//!
//! * `effect` — read or write.
//! * `ingress` — the only ingress classes that may reach the method. An ingress class that is not
//!   listed is denied whatever rights the caller holds.
//! * `rights` — everything the actor must present, intersected. An empty list means scoped read
//!   authority and nothing more: a valid, unexpired, unrevoked grant covering the named
//!   environment and resource. Entries whose condition is not `always` apply only when that
//!   condition holds, which is how a pair of mutually exclusive conditions expresses a choice.
//! * `selectors` — the resources the request names and the host resolves before the check.
//! * `history` — how the shared host-side history filter applies to the result.
//! * `capability` — which capability evidence is required, and which revision it is bound to.
//! * `freshness` — which freshness context the request carries.
//! * `confirmation` — whether a fresh owner confirmation is required.
//! * `idempotency` — how a repeated request is resolved.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

use crate::actor::ActorIngress;
use crate::authority::RequiredAuthority::{self, *};
use crate::authority::RevisionBinding::{self, *};
use crate::authority::RightCondition::{self, *};
use crate::authority::{
    AuthorityDecision, CapabilityRequirement, ConfirmationRequirement, DenialReason, EffectClass,
    FreshnessRequirement, HistoryFilter, IdempotencyBehaviour, MethodEntry, RequiredRight,
    ResourceSelectorKind,
};
use crate::rights::ActionRight::{self, *};

/// The version of one method's schema.
///
/// Mutation schemas are closed for the negotiated version: an unknown field rejects rather than
/// being stripped. Read-only metadata may add explicitly optional ignored fields.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct MethodVersion(pub u16);

impl MethodVersion {
    /// Version 1, the only version this build implements.
    pub const V1: Self = Self(1);
}

impl fmt::Display for MethodVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Maximum length in bytes of a method name on the wire.
pub const MAX_METHOD_NAME_LEN: usize = 64;

/// A method name as it arrives on the wire.
///
/// The envelope accepts any well-formed name so the host can answer an unknown method with a
/// correlated error instead of failing to parse the request. [`MethodName::method`] resolves it
/// against the registry; an unresolved name is denied.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct MethodName(String);

/// A method name that is empty, too long or not in the permitted shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodNameError;

impl fmt::Display for MethodNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "a method name is 1 to 64 bytes of lower-case ASCII letters, digits, '_' and '.'",
        )
    }
}

impl std::error::Error for MethodNameError {}

impl MethodName {
    /// Validates and wraps a method name.
    ///
    /// # Errors
    ///
    /// Returns [`MethodNameError`] when the name is empty, longer than
    /// [`MAX_METHOD_NAME_LEN`] bytes, or contains a character outside `[a-z0-9_.]`.
    pub fn new(value: impl Into<String>) -> Result<Self, MethodNameError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_METHOD_NAME_LEN {
            return Err(MethodNameError);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        }) {
            return Err(MethodNameError);
        }
        if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
            return Err(MethodNameError);
        }
        Ok(Self(value))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Resolves the name against the registry.
    #[must_use]
    pub fn method(&self) -> Option<Method> {
        Method::from_wire(&self.0)
    }
}

impl From<Method> for MethodName {
    fn from(value: Method) -> Self {
        Self(value.as_str().to_owned())
    }
}

impl fmt::Display for MethodName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for MethodName {
    type Err = MethodNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for MethodName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for MethodName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "MethodName".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::MethodName".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_METHOD_NAME_LEN,
            "pattern": "^[a-z0-9_]+(\\.[a-z0-9_]+)*$",
            "description": "A method name. A name that is not in the registry is denied."
        })
    }
}

/// The method groups of section 23.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MethodGroup {
    /// Host and environment.
    HostAndEnvironment,
    /// Pairing.
    Pairing,
    /// Devices.
    Devices,
    /// Plugin catalogues.
    PluginCatalogues,
    /// Plugins.
    Plugins,
    /// Plugin actions.
    PluginActions,
    /// Question source, reachable only over private IPC.
    QuestionSource,
    /// Question user interface.
    QuestionUserInterface,
    /// Skill setup.
    SkillSetup,
    /// Sessions.
    Sessions,
    /// Attachments.
    Attachments,
    /// Input.
    Input,
    /// Root integration, reachable only over private IPC.
    RootIntegration,
    /// Shell launch.
    ShellLaunch,
    /// Agent state.
    AgentState,
    /// Agent mutations.
    AgentMutations,
    /// Drafts and media.
    DraftsAndMedia,
    /// Project repositories.
    ProjectRepositories,
    /// Workspaces.
    Workspaces,
    /// Changes and diffs.
    ChangesAndDiffs,
    /// Review and attention.
    ReviewAndAttention,
    /// Pending action control.
    PendingActionControl,
    /// Owner confirmation.
    OwnerConfirmation,
    /// State recovery.
    StateRecovery,
    /// Sharing.
    Sharing,
    /// Services.
    Services,
    /// Voice.
    Voice,
    /// Automation.
    Automation,
}

const fn req(right: ActionRight) -> RequiredRight {
    RequiredRight::right(right)
}

const fn req_when(right: ActionRight, when: RightCondition) -> RequiredRight {
    RequiredRight::right_when(right, when)
}

const fn basis(authority: RequiredAuthority) -> RequiredRight {
    RequiredRight::basis(authority)
}

const fn basis_when(authority: RequiredAuthority, when: RightCondition) -> RequiredRight {
    RequiredRight::basis_when(authority, when)
}

const fn cap(capability_id: &'static str, revision: RevisionBinding) -> CapabilityRequirement {
    CapabilityRequirement::Required {
        capability_id,
        revision,
    }
}

const fn keyed(key: &'static str) -> IdempotencyBehaviour {
    IdempotencyBehaviour::Keyed { key }
}

const NO_CAPABILITY: CapabilityRequirement = CapabilityRequirement::None;
const READ: IdempotencyBehaviour = IdempotencyBehaviour::IdempotentRead;
const ACTION: IdempotencyBehaviour = IdempotencyBehaviour::ActionDeduplicated;
const STREAM: IdempotencyBehaviour = IdempotencyBehaviour::OrderedStream;

macro_rules! methods {
    ($(
        $variant:ident = $name:literal, $group:ident,
        effect: $effect:ident,
        ingress: [$($ingress:ident),* $(,)?],
        rights: [$($right:expr),* $(,)?],
        selectors: [$($selector:ident),* $(,)?],
        history: $history:ident,
        capability: $capability:expr,
        freshness: $freshness:ident,
        confirmation: $confirmation:ident,
        idempotency: $idempotency:expr,
        doc: $doc:literal;
    )+) => {
        /// Every method in the section 23 method-groups table.
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
        )]
        pub enum Method {
            $(
                #[doc = $doc]
                #[serde(rename = $name)]
                $variant,
            )+
        }

        impl Method {
            /// Every method, in registry order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// Returns the stable wire name.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            /// Returns the method for a wire name.
            #[must_use]
            pub fn from_wire(value: &str) -> Option<Self> {
                match value {
                    $($name => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// Returns the group this method belongs to.
            #[must_use]
            pub const fn group(self) -> MethodGroup {
                match self {
                    $(Self::$variant => MethodGroup::$group,)+
                }
            }
        }

        /// One exhaustive authority entry per method.
        ///
        /// Entries are in the order of the section 23 method-groups table, and
        /// `REGISTRY[method as usize]` is that method's entry.
        pub static REGISTRY: &[MethodEntry] = &[
            $(MethodEntry {
                method: Method::$variant,
                name: $name,
                group: MethodGroup::$group,
                version: MethodVersion::V1,
                effect: EffectClass::$effect,
                ingress: &[$(ActorIngress::$ingress,)*],
                required_rights: &[$($right,)*],
                resource_selectors: &[$(ResourceSelectorKind::$selector,)*],
                history_filter: HistoryFilter::$history,
                capability: $capability,
                freshness: FreshnessRequirement::$freshness,
                confirmation: ConfirmationRequirement::$confirmation,
                idempotency: $idempotency,
                summary: $doc,
            },)+
        ];
    };
}

methods! {
    // ----- Host and environment -------------------------------------------------------------
    HostInfo = "host.info", HostAndEnvironment,
    effect: Read, ingress: [LocalIpc, PairedDevice], rights: [], selectors: [Host],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Host build identity, protocol limits and configured services.";

    EnvironmentList = "environment.list", HostAndEnvironment,
    effect: Read, ingress: [LocalIpc, PairedDevice], rights: [], selectors: [Host],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "The environments this actor's grant admits.";

    EnvironmentCapabilities = "environment.capabilities", HostAndEnvironment,
    effect: Read, ingress: [LocalIpc, PairedDevice], rights: [], selectors: [Environment],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "What one environment can currently do. Capability evidence, never authority.";

    HostDoctor = "host.doctor", HostAndEnvironment,
    effect: Read, ingress: [LocalIpc, PairedDevice], rights: [], selectors: [Host, Environment],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Host diagnostics with credentials redacted.";

    // ----- Pairing --------------------------------------------------------------------------
    PairInvite = "pair.invite", Pairing,
    effect: Write, ingress: [LocalIpc], rights: [req(HostManage)], selectors: [Host, Invitation],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: Always, idempotency: ACTION,
    doc: "Issue a five-minute single-use pairing invitation in code or direct mode.";

    PairRedeem = "pair.redeem", Pairing,
    effect: Write, ingress: [UnpairedPeer], rights: [basis(PairingTranscript)],
    selectors: [Invitation],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: InvitationDeadline,
    confirmation: None, idempotency: keyed("invitation_id + attempt_id"),
    doc: "Redeem an invitation from the bounded pre-authorisation surface.";

    PairFinish = "pair.finish", Pairing,
    effect: Write, ingress: [UnpairedPeer], rights: [basis(PairingTranscript)],
    selectors: [Invitation],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: InvitationDeadline,
    confirmation: None, idempotency: keyed("invitation_id + attempt_id"),
    doc: "Bind the pairing transcript to the live iroh endpoint identities.";

    PairConfirm = "pair.confirm", Pairing,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [basis(IssuingOwnerContext)],
    selectors: [Invitation, Device, Grant],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: InvitationDeadline,
    confirmation: Always, idempotency: keyed("invitation_id + client bundle hash"),
    doc: "Commit the device record and its grant after owner approval.";

    PairCancel = "pair.cancel", Pairing,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [basis(IssuingOwnerContext)],
    selectors: [Invitation],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: InvitationDeadline,
    confirmation: None, idempotency: keyed("invitation_id"),
    doc: "Consume an invitation without issuing a grant.";

    PairStatus = "pair.status", Pairing,
    effect: Read, ingress: [UnpairedPeer, LocalIpc, PairedDevice],
    rights: [
        basis_when(PairingTranscript, CandidateEndpoint),
        basis_when(IssuingOwnerContext, IssuingOwner),
    ],
    selectors: [Invitation],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: InvitationDeadline,
    confirmation: None, idempotency: READ,
    doc: "Report a pending or committed pairing result, never secret material.";

    // ----- Devices --------------------------------------------------------------------------
    DeviceList = "device.list", Devices,
    effect: Read, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)], selectors: [Device],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Paired devices, their key purposes and each host's last authority acknowledgement.";

    DeviceRevoke = "device.revoke", Devices,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Device, Grant],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Revoke a device. Completion requires the per-worker dispatch barrier, not a lease timer.";

    DevicePreviewKeyUpdate = "device.preview_key.update", Devices,
    effect: Write, ingress: [PairedDevice], rights: [basis(ResourceOwner)], selectors: [Device],
    history: NotApplicable, capability: cap("device.preview_key", DeviceKeyRevision),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Rotate this device's own notification-preview key through its paired proof.";

    // ----- Plugin catalogues ----------------------------------------------------------------
    CatalogueList = "catalogue.list", PluginCatalogues,
    effect: Read, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Catalogue],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Configured plugin catalogues, their roots, generations and budgets.";

    CatalogueAdd = "catalogue.add", PluginCatalogues,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Catalogue],
    history: NotApplicable, capability: cap("catalogue.root", RepositoryGeneration),
    freshness: ActionWindow, confirmation: Always, idempotency: ACTION,
    doc: "Trust a new catalogue root. A new root always requires fresh owner confirmation.";

    CatalogueSync = "catalogue.sync", PluginCatalogues,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Catalogue],
    history: NotApplicable, capability: cap("catalogue.root", RepositoryGeneration),
    freshness: ActionWindow, confirmation: WhenEnlargingAuthority, idempotency: ACTION,
    doc: "Synchronise a catalogue generation within its verified trust ceiling.";

    CataloguePin = "catalogue.pin", PluginCatalogues,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Catalogue],
    history: NotApplicable, capability: cap("catalogue.root", RepositoryGeneration),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Pin a catalogue to an exact generation.";

    CatalogueRemove = "catalogue.remove", PluginCatalogues,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Catalogue],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Remove a catalogue and stop trusting its root.";

    // ----- Plugins --------------------------------------------------------------------------
    PluginList = "plugin.list", Plugins,
    effect: Read, ingress: [LocalIpc, PairedDevice], rights: [], selectors: [Plugin, Environment],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Installed plugins, their pinned packages and their enabled state.";

    PluginInstall = "plugin.install", Plugins,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Plugin, Catalogue, Environment],
    history: NotApplicable, capability: cap("plugin.package", PackageHash),
    freshness: ActionWindow, confirmation: WhenEnlargingAuthority, idempotency: ACTION,
    doc: "Install a verified package inside the repository's trust ceiling.";

    PluginRemove = "plugin.remove", Plugins,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Plugin, Environment],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Remove an installed plugin from an environment.";

    PluginPin = "plugin.pin", Plugins,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Plugin, Environment],
    history: NotApplicable, capability: cap("plugin.package", PackageHash),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Pin a plugin to an exact package hash.";

    PluginEnable = "plugin.enable", Plugins,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Plugin, Environment],
    history: NotApplicable, capability: cap("plugin.package", PackageHash),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Enable an installed plugin in an environment.";

    PluginDisable = "plugin.disable", Plugins,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Plugin, Environment],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Disable an installed plugin without removing it.";

    PluginGrant = "plugin.grant", Plugins,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(HostManage)],
    selectors: [Plugin, Environment],
    history: NotApplicable, capability: cap("plugin.package", PackageHash),
    freshness: ActionWindow, confirmation: Always, idempotency: ACTION,
    doc: "Grant a plugin capability. Executable and native-bridge capabilities need confirmation.";

    PluginCapabilities = "plugin.capabilities", Plugins,
    effect: Read, ingress: [LocalIpc, PairedDevice], rights: [], selectors: [Plugin, Environment],
    history: NotApplicable, capability: cap("plugin.package", PackageHash),
    freshness: CurrentAuthority, confirmation: None, idempotency: READ,
    doc: "What one installed plugin can currently do under its verified package.";

    // ----- Plugin actions -------------------------------------------------------------------
    PluginActionInvoke = "plugin.action.invoke", PluginActions,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [basis(PluginEffectRights)],
    selectors: [Plugin, Session, ApplicationInstance, Draft],
    history: GrantLowerBound, capability: cap("plugin.action", PackageHash),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Invoke a registered plugin action. Its own entry adds the rights this call intersects.";

    // ----- Question source (private IPC only) -----------------------------------------------
    QuestionCreate = "question.create", QuestionSource,
    effect: Write, ingress: [LocalIpc], rights: [basis(LocalCallerToken)],
    selectors: [Session, Question],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Create a question from a verified originating application. Source ownership never \
          impersonates a human answer or chooses an ungranted destination.";

    QuestionReadOwn = "question.read_own", QuestionSource,
    effect: Read, ingress: [LocalIpc], rights: [basis(LocalCallerToken), basis(ResourceOwner)],
    selectors: [Session, Question],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read the questions this source created.";

    QuestionCancelOwn = "question.cancel_own", QuestionSource,
    effect: Write, ingress: [LocalIpc], rights: [basis(LocalCallerToken), basis(ResourceOwner)],
    selectors: [Session, Question],
    history: NotApplicable, capability: cap("question", QuestionRevision),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Cancel a question this source created.";

    AlertCreate = "alert.create", QuestionSource,
    effect: Write, ingress: [LocalIpc], rights: [basis(LocalCallerToken)], selectors: [Session],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Raise an alert from a verified originating application.";

    // ----- Question user interface ----------------------------------------------------------
    QuestionRead = "question.read", QuestionUserInterface,
    effect: Read, ingress: [LocalIpc, PairedDevice], rights: [req(SessionView)],
    selectors: [Session, Question],
    history: NamedCurrentResources, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read questions this actor may see, at their exact current revision.";

    QuestionAnswer = "question.answer", QuestionUserInterface,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(QuestionRespond)],
    selectors: [Session, Question],
    history: NotApplicable, capability: cap("question", QuestionRevision),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Answer the exact question revision shown, resolved atomically.";

    QuestionCancel = "question.cancel", QuestionUserInterface,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(QuestionRespond)],
    selectors: [Session, Question],
    history: NotApplicable, capability: cap("question", QuestionRevision),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Cancel the exact question revision shown, resolved atomically.";

    // ----- Skill setup ----------------------------------------------------------------------
    AgentToolsInstall = "agent_tools.install", SkillSetup,
    effect: Write, ingress: [LocalIpc], rights: [req(HostManage)], selectors: [Host, AgentTarget],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Install the contact skill for a target agent under an exact change manifest.";

    AgentToolsStatus = "agent_tools.status", SkillSetup,
    effect: Read, ingress: [LocalIpc], rights: [req(HostManage)], selectors: [Host, AgentTarget],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Report what is installed for a target agent, at which scope and version.";

    AgentToolsRemove = "agent_tools.remove", SkillSetup,
    effect: Write, ingress: [LocalIpc], rights: [req(HostManage)], selectors: [Host, AgentTarget],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Remove the contact skill from a target agent under an exact change manifest.";

    // ----- Sessions -------------------------------------------------------------------------
    SessionList = "session.list", Sessions,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Environment],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "List the sessions this actor may observe.";

    SessionCreate = "session.create", Sessions,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionCreate)],
    selectors: [Environment, Session],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Create a session. Deduplication happens in the controller before a worker exists.";

    SessionRead = "session.read", Sessions,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read one session's filtered metadata and current state.";

    SessionClose = "session.close", Sessions,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionClose)],
    selectors: [Session],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Close a session and hand its final metadata to the archive service.";

    SessionDescribe = "session.describe", Sessions,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "An authorised read of filtered session metadata, not arbitrary model control.";

    SessionRename = "session.rename", Sessions,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionRename)],
    selectors: [Session],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Set a session's pinned label.";

    // ----- Attachments ----------------------------------------------------------------------
    SessionAttach = "session.attach", Attachments,
    effect: Write, ingress: [LocalIpc, PairedDevice],
    rights: [req(SessionView), req_when(TerminalGeometry, GeometryClaim)],
    selectors: [Session, Attachment],
    history: LiveViewOnly, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Attach in semantic or terminal mode. A geometry claim needs terminal.geometry as well.";

    SessionDetach = "session.detach", Attachments,
    effect: Write, ingress: [LocalIpc, PairedDevice],
    rights: [req(SessionView), basis(ResourceOwner)], selectors: [Session, Attachment],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Detach this actor's own attachment and run geometry succession.";

    AttachmentConfigure = "attachment.configure", Attachments,
    effect: Write, ingress: [LocalIpc, PairedDevice],
    rights: [
        req(SessionView),
        basis(ResourceOwner),
        req_when(TerminalGeometry, GeometryClaim),
    ],
    selectors: [Session, Attachment],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Withdraw or add an authorised geometry claim without displacing the current owner.";

    AttachmentViewport = "attachment.viewport", Attachments,
    effect: Write, ingress: [LocalIpc, PairedDevice],
    rights: [req(SessionView), basis(ResourceOwner)], selectors: [Session, Attachment],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Report this attachment's physical dimensions. It never changes the pseudoterminal.";

    TerminalResize = "terminal.resize", Attachments,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(TerminalGeometry)],
    selectors: [Session, Attachment],
    history: NotApplicable, capability: cap("terminal.geometry", GeometryEpoch),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Resize the pseudoterminal. Only the current geometry owner at the current epoch may.";

    TerminalGeometryTransfer = "terminal.geometry.transfer", Attachments,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(TerminalGeometryTransfer)],
    selectors: [Session, Attachment],
    history: NotApplicable, capability: cap("terminal.geometry", GeometryEpoch),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Hand geometry ownership to another eligible attachment.";

    TerminalPaletteSet = "terminal.palette.set", Attachments,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(TerminalPalette)],
    selectors: [Session, Attachment],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Set the session palette.";

    // ----- Input ----------------------------------------------------------------------------
    InputAcquire = "input.acquire", Input,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(TerminalInput)],
    selectors: [Session, Attachment],
    history: NotApplicable, capability: cap("terminal.input", InputLeaseEpoch),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Acquire the input lease explicitly. There is no implicit remote acquisition.";

    InputRelease = "input.release", Input,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(TerminalInput)],
    selectors: [Session, Attachment],
    history: NotApplicable, capability: cap("terminal.input", InputLeaseEpoch),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Release the input lease this actor holds.";

    InputInterrupt = "input.interrupt", Input,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(TerminalInput)],
    selectors: [Session, Attachment],
    history: NotApplicable, capability: cap("terminal.input", InputLeaseEpoch),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Send an interrupt under the current lease.";

    InputWrite = "input.write", Input,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(TerminalInput)],
    selectors: [Session, Attachment],
    history: NotApplicable, capability: cap("terminal.input", InputLeaseEpoch),
    freshness: InputLease, confirmation: None, idempotency: STREAM,
    doc: "Write ordered raw input under the current lease epoch and input sequence. Unsent or \
          ambiguously delivered keystrokes are discarded, never replayed.";

    // ----- Root integration (private IPC only) ----------------------------------------------
    RootEditorEnter = "root.editor.enter", RootIntegration,
    effect: Write, ingress: [LocalIpc], rights: [basis(LocalCallerToken)], selectors: [Session],
    history: NotApplicable, capability: cap("shell.root_integration", RootEditorFence),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "The validated root process reports that its line editor is active.";

    RootEditorLeave = "root.editor.leave", RootIntegration,
    effect: Write, ingress: [LocalIpc], rights: [basis(LocalCallerToken)], selectors: [Session],
    history: NotApplicable, capability: cap("shell.root_integration", RootEditorFence),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "The validated root process reports that its line editor is no longer active.";

    RootEditorFence = "root.editor.fence", RootIntegration,
    effect: Write, ingress: [LocalIpc], rights: [basis(LocalCallerToken)], selectors: [Session],
    history: NotApplicable, capability: cap("shell.root_integration", RootEditorFence),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Advance the root editor fence so an intervening local edit is detected.";

    RootEofDetach = "root.eof.detach", RootIntegration,
    effect: Write, ingress: [LocalIpc], rights: [basis(LocalCallerToken)],
    selectors: [Session, Attachment],
    history: NotApplicable, capability: cap("shell.root_integration", RootEditorFence),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "The root shell reached end of file and the session detaches instead of exiting blindly.";

    RootCommandAccepted = "root.command.accepted", RootIntegration,
    effect: Write, ingress: [LocalIpc], rights: [basis(LocalCallerToken)], selectors: [Session],
    history: NotApplicable, capability: cap("shell.root_integration", RootEditorFence),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "The root integration confirms that the installed command was accepted by the editor.";

    // ----- Shell launch ---------------------------------------------------------------------
    ShellLaunch = "shell.launch", ShellLaunch,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(TerminalInput)],
    selectors: [Session],
    history: NotApplicable, capability: cap("shell.root_integration", RootEditorFence),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Install and submit an argument vector or correctly quoted command through the trusted \
          root editor. An intervening local edit returns DRAFT_CONFLICT.";

    // ----- Agent state ----------------------------------------------------------------------
    AgentCapabilities = "agent.capabilities", AgentState,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session, ApplicationInstance],
    history: GrantLowerBound, capability: cap("agent.binding", AgentBinding),
    freshness: CurrentAuthority, confirmation: None, idempotency: READ,
    doc: "What the bound agent can currently do, with its capability evidence.";

    AgentSnapshot = "agent.snapshot", AgentState,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session, ApplicationInstance],
    history: GrantLowerBound, capability: cap("agent.binding", AgentBinding),
    freshness: CurrentAuthority, confirmation: None, idempotency: READ,
    doc: "A filtered snapshot of the bound agent's shared state.";

    AgentCommands = "agent.commands", AgentState,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session, ApplicationInstance],
    history: GrantLowerBound, capability: cap("agent.binding", AgentBinding),
    freshness: CurrentAuthority, confirmation: None, idempotency: READ,
    doc: "The commands the bound agent advertises.";

    // ----- Agent mutations ------------------------------------------------------------------
    AgentPromptSubmit = "agent.prompt.submit", AgentMutations,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(AgentPrompt)],
    selectors: [Session, ApplicationInstance, Draft],
    history: NotApplicable, capability: cap("agent.prompt", AgentBinding),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Submit a prompt. Applied means upstream admission, not task completion.";

    AgentPromptQueue = "agent.prompt.queue", AgentMutations,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(AgentPrompt)],
    selectors: [Session, ApplicationInstance, Draft],
    history: NotApplicable, capability: cap("agent.prompt", AgentBinding),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Queue a prompt behind the current turn.";

    AgentTurnSteer = "agent.turn.steer", AgentMutations,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(AgentPrompt)],
    selectors: [Session, ApplicationInstance],
    history: NotApplicable, capability: cap("agent.steer", AgentBinding),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Steer the current turn where the upstream agent supports it.";

    AgentTurnCancel = "agent.turn.cancel", AgentMutations,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(AgentCancel)],
    selectors: [Session, ApplicationInstance],
    history: NotApplicable, capability: cap("agent.cancel", AgentBinding),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Cancel the current turn using its typed request and current turn identifier.";

    AgentApprovalRespond = "agent.approval.respond", AgentMutations,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(AgentApprovalRespond)],
    selectors: [Session, ApplicationInstance],
    history: NotApplicable, capability: cap("agent.approval", AgentBinding),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Answer an upstream approval request at its exact revision and pending state.";

    // ----- Drafts and media -----------------------------------------------------------------
    DraftCreate = "draft.create", DraftsAndMedia,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [basis(ResourceOwner)],
    selectors: [Environment, Draft],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Create a device-owned draft that survives attachment replacement.";

    DraftUpdate = "draft.update", DraftsAndMedia,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [basis(ResourceOwner)],
    selectors: [Draft],
    history: NotApplicable, capability: cap("draft", DraftRevision),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Update a draft at its exact revision. A draft is never submitted automatically.";

    AgentDraftAddAttachment = "agent.draft.add_attachment", DraftsAndMedia,
    effect: Write, ingress: [LocalIpc, PairedDevice],
    rights: [basis(ResourceOwner), req(FilesUpload), req(AgentPrompt)],
    selectors: [Draft, Transfer, Session, ApplicationInstance],
    history: NotApplicable, capability: cap("agent.attachment", AgentBinding),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Insert a completed attachment handle into a draft through the active adapter.";

    UploadBegin = "upload.begin", DraftsAndMedia,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesUpload)],
    selectors: [Environment, Transfer],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Reserve the declared size and return an upload identifier, chunk size and expiry.";

    UploadStatus = "upload.status", DraftsAndMedia,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesUpload)],
    selectors: [Transfer],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Report verified chunk status so an interrupted transfer resumes without republishing.";

    UploadChunk = "upload.chunk", DraftsAndMedia,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesUpload)],
    selectors: [Transfer],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: keyed("upload_id + chunk index + chunk digest"),
    doc: "Send one chunk with its index, exact length and digest. A matching duplicate is \
          acknowledged; a conflicting duplicate invalidates the upload.";

    UploadFinish = "upload.finish", DraftsAndMedia,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesUpload)],
    selectors: [Transfer],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: keyed("upload_id"),
    doc: "Verify the declared digest and size, then publish the attachment handle atomically.";

    UploadCancel = "upload.cancel", DraftsAndMedia,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow],
    rights: [req(FilesUpload), basis(ResourceOwner)], selectors: [Transfer],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: keyed("upload_id"),
    doc: "Cancel an unfinished upload and release its reservation.";

    DownloadBegin = "download.begin", DraftsAndMedia,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesRead)],
    selectors: [Environment, Transfer],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: keyed("transfer_id"),
    doc: "Open an immutable source revision or bounded staging snapshot and describe its chunks.";

    DownloadChunk = "download.chunk", DraftsAndMedia,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesRead)],
    selectors: [Transfer],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read one chunk of the same snapshot. Read authority is checked on every request.";

    // ----- Project repositories -------------------------------------------------------------
    ProjectList = "project.list", ProjectRepositories,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [],
    selectors: [Environment, Project],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "List environment-local repositories as scoped metadata.";

    ProjectRead = "project.read", ProjectRepositories,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [], selectors: [Project],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read one repository's scoped metadata.";

    ProjectInit = "project.init", ProjectRepositories,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(ProjectCreate)],
    selectors: [Environment, Project],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Initialise a repository at an authorised destination handle.";

    ProjectClone = "project.clone", ProjectRepositories,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(ProjectCreate)],
    selectors: [Environment, Project],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Clone into an authorised destination through the approved credential broker.";

    ProjectAdopt = "project.adopt", ProjectRepositories,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(ProjectCreate)],
    selectors: [Environment, Project],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Adopt an existing checkout through the explicit adoption flow.";

    ProjectOperationCancel = "project.operation.cancel", ProjectRepositories,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [basis(ResourceOwner)],
    selectors: [Project, Action],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Cancel owned repository work and report retained or removed staging paths.";

    // ----- Workspaces -----------------------------------------------------------------------
    WorkspaceList = "workspace.list", Workspaces,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [],
    selectors: [Environment, Workspace],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "List workspaces. A view never implies deletion.";

    WorkspaceCreate = "workspace.create", Workspaces,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(WorkspaceManage)],
    selectors: [Project, Workspace],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Create a shared or isolated workspace with explicit inclusion rules.";

    WorkspaceRead = "workspace.read", Workspaces,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [], selectors: [Workspace],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read one workspace's policy and bound sessions.";

    WorkspaceRemove = "workspace.remove", Workspaces,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(WorkspaceManage)],
    selectors: [Workspace],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Remove a workspace once its retention rules and pins permit it.";

    // ----- Changes and diffs ----------------------------------------------------------------
    DiffRead = "diff.read", ChangesAndDiffs,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesRead)],
    selectors: [Workspace, ChangeSet],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read a diff with repository identity, base, head and content revisions.";

    DiffApply = "diff.apply", ChangesAndDiffs,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesApplyDiff)],
    selectors: [Workspace, ChangeSet],
    history: NotApplicable, capability: cap("workspace.destination", ChangeSetVersion),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Apply a diff under the destination's concurrency contract. A preflight conflict returns \
          DRAFT_CONFLICT without any write.";

    DiffRevert = "diff.revert", ChangesAndDiffs,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesApplyDiff)],
    selectors: [Workspace, ChangeSet],
    history: NotApplicable, capability: cap("workspace.destination", ChangeSetVersion),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Revert a previously applied change under the same destination contract.";

    ChangesetCapture = "changeset.capture", ChangesAndDiffs,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(ChangesetCreate)],
    selectors: [Workspace, ChangeSet],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Capture an immutable change-set version with its policy and provenance.";

    ChangesetRead = "changeset.read", ChangesAndDiffs,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(FilesRead)],
    selectors: [ChangeSet],
    history: GrantLowerBound, capability: cap("changeset", ChangeSetVersion),
    freshness: CurrentAuthority, confirmation: None, idempotency: READ,
    doc: "Read one exact change-set version.";

    ChangesetMaterialize = "changeset.materialize", ChangesAndDiffs,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(WorkspaceManage)],
    selectors: [ChangeSet, Workspace],
    history: NotApplicable, capability: cap("changeset", ChangeSetVersion),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Materialise an exact change-set version into an independent workspace.";

    // ----- Review and attention -------------------------------------------------------------
    ReviewRead = "review.read", ReviewAndAttention,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session, ChangeSet],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read review state bound to exact change-set versions.";

    ReviewAcknowledge = "review.acknowledge", ReviewAndAttention,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session, ChangeSet],
    history: NotApplicable, capability: cap("changeset", ChangeSetVersion),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Acknowledge review of one version. It affects only this actor and mutates no code.";

    AttentionRead = "attention.read", ReviewAndAttention,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Environment, Session],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read the attention inbox for this actor's scope.";

    AttentionAcknowledge = "attention.acknowledge", ReviewAndAttention,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Environment, Session],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Acknowledge an attention item for this actor only.";

    VisitAcknowledge = "visit.acknowledge", ReviewAndAttention,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Record this actor's visit so changed-since-last-visit stays per actor.";

    // ----- Pending action control -----------------------------------------------------------
    ActionCancel = "action.cancel", PendingActionControl,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow],
    rights: [
        basis_when(ResourceOwner, OwnSubject),
        req_when(HostManage, OtherActor),
    ],
    selectors: [Action],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Cancel an undispatched intent atomically. After a dispatch marker, cancellation is a \
          separate upstream action with its own receipt.";

    // ----- Owner confirmation ---------------------------------------------------------------
    OwnerConfirmationRequest = "owner.confirmation.request", OwnerConfirmation,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [basis(IssuingOwnerContext)],
    selectors: [Host, Action],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Start a confirmation ceremony bound to one single-use action digest.";

    OwnerConfirmationComplete = "owner.confirmation.complete", OwnerConfirmation,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [basis(IssuingOwnerContext)],
    selectors: [Host, Action],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: Always, idempotency: keyed("single-use action digest"),
    doc: "Complete the ceremony with a protected user-verification context. A click that desktop \
          automation can synthesise is not that proof.";

    // ----- State recovery -------------------------------------------------------------------
    EventsSubscribe = "events.subscribe", StateRecovery,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session, EventStream],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Subscribe to an event stream from a cursor.";

    EventsSnapshot = "events.snapshot", StateRecovery,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session, EventStream],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Take a filtered snapshot and the cursor it was taken at, after RESYNC_REQUIRED.";

    HistoryPage = "history.page", StateRecovery,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(SessionView)],
    selectors: [Session, EventStream],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Page retained history. A history request never creates a worker.";

    ActionRead = "action.read", StateRecovery,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow],
    rights: [basis(ResourceOwner), basis(PresentViewAuthority)],
    selectors: [Action, Environment, Session],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read a retained receipt. Owning the identifier is not enough: present view authority \
          over the subject the receipt names is checked before it is returned, so a device that \
          lost its scope cannot retrieve protected information through an old action identifier. \
          A receipt for a host effect resolves against that host scope, not against a session.";

    // ----- Sharing --------------------------------------------------------------------------
    GrantCreate = "grant.create", Sharing,
    effect: Write, ingress: [LocalIpc, PairedDevice],
    rights: [req(SessionShare), basis(IssuerDelegation)],
    selectors: [Session, Grant, Device],
    history: NotApplicable, capability: cap("grant.parent", AuthorityRevision),
    freshness: ActionWindow, confirmation: WhenEnlargingAuthority, idempotency: ACTION,
    doc: "Delegate a narrower grant. Persistent enlargement requires owner confirmation.";

    GrantRevoke = "grant.revoke", Sharing,
    effect: Write, ingress: [LocalIpc, PairedDevice],
    rights: [req(SessionShare), basis(IssuerDelegation)],
    selectors: [Grant],
    history: NotApplicable, capability: cap("grant.parent", AuthorityRevision),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Revoke a grant and its descendants. Completion uses the per-worker dispatch barrier.";

    GrantList = "grant.list", Sharing,
    effect: Read, ingress: [LocalIpc, PairedDevice],
    rights: [req(SessionShare), basis(IssuerDelegation)],
    selectors: [Grant],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "List grants this issuer may see, with their revisions and expiry.";

    // ----- Services -------------------------------------------------------------------------
    PushInstallationRegister = "push.installation.register", Services,
    effect: Write, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Installation],
    history: NotApplicable, capability: cap("push.installation", InstallationKeyRevision),
    freshness: ServiceCredential, confirmation: None,
    idempotency: keyed("token hash + installation key"),
    doc: "Bind a push token to an installation identity after the token-receipt challenge.";

    PushSenderIssue = "push.sender.issue", Services,
    effect: Write, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Installation, Host],
    history: NotApplicable, capability: cap("push.installation", InstallationKeyRevision),
    freshness: ServiceCredential, confirmation: None, idempotency: keyed("sender record id"),
    doc: "Issue a host-scoped delivery credential for one installation.";

    PushSenderRenew = "push.sender.renew", Services,
    effect: Write, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Installation, Host],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ServiceCredential,
    confirmation: None, idempotency: keyed("sender record id"),
    doc: "Renew a delivery credential without changing destination, host key or rate policy.";

    PushSenderRevoke = "push.sender.revoke", Services,
    effect: Write, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Installation, Host],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ServiceCredential,
    confirmation: None, idempotency: keyed("sender record id"),
    doc: "Revoke a sender authorisation. A revoked record cannot renew.";

    MailboxRead = "mailbox.read", Services,
    effect: Read, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Mailbox],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ServiceCredential,
    confirmation: None, idempotency: READ,
    doc: "Read encrypted mailbox envelopes. The service never sees their plaintext.";

    MailboxDeliver = "mailbox.deliver", Services,
    effect: Write, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Mailbox],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ServiceCredential,
    confirmation: None, idempotency: keyed("envelope id"),
    doc: "Place one sealed envelope in a recipient's mailbox. The service stores the routing \
          record and the ciphertext and never a plaintext field.";

    MailboxAcknowledge = "mailbox.acknowledge", Services,
    effect: Write, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Mailbox],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ServiceCredential,
    confirmation: None, idempotency: keyed("acknowledged sequence"),
    doc: "Acknowledge mailbox items the recipient has stored durably, so the service may remove \
          them. The replay identifiers outlive the items.";

    AuthoritySync = "authority.sync", Services,
    effect: Write, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Host, Grant],
    history: NotApplicable, capability: cap("authority.feed", AuthorityRevision),
    freshness: ServiceCredential, confirmation: None,
    idempotency: keyed("authority revision + host acknowledgement"),
    doc: "Exchange signed revocation requests and host acknowledgements. Only the host issues its \
          own ordered revisions, and it rejects an older revision.";

    SyncCompareExchange = "sync.compare_exchange", Services,
    effect: Write, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Mailbox],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ServiceCredential,
    confirmation: None, idempotency: keyed("collection generation"),
    doc: "Publish encrypted settings or draft state under a compare-and-exchange generation.";

    BackupManifest = "backup.manifest", Services,
    effect: Write, ingress: [ServiceClient], rights: [basis(ServiceCredential)],
    selectors: [Mailbox],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ServiceCredential,
    confirmation: None, idempotency: keyed("backup generation"),
    doc: "Publish or fetch a backup generation manifest. Writer authority is verified.";

    // ----- Voice ----------------------------------------------------------------------------
    VoiceStart = "voice.start", Voice,
    effect: Write, ingress: [PairedDevice], rights: [basis(VoiceGrant)],
    selectors: [Session, VoiceSession],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Start a voice session. Budget and account checks happen at the managed broker.";

    VoiceStop = "voice.stop", Voice,
    effect: Write, ingress: [PairedDevice], rights: [basis(VoiceGrant)], selectors: [VoiceSession],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Stop a voice session. Ending it revokes its voice grant immediately.";

    VoiceGrant = "voice.grant", Voice,
    effect: Write, ingress: [LocalIpc, PairedDevice],
    rights: [
        basis_when(ResourceOwner, OwnSubject),
        req_when(HostManage, OtherActor),
    ],
    selectors: [Host, Device, Session],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: WhenEnlargingAuthority, idempotency: ACTION,
    doc: "Create or change a voice grant, stating exactly which actions it permits. A device may \
          broaden its own; changing another device's needs host-management authority.";

    VoiceDelegate = "voice.delegate", Voice,
    effect: Write, ingress: [PairedDevice], rights: [basis(VoiceGrant)],
    selectors: [Session, VoiceSession],
    history: NotApplicable, capability: NO_CAPABILITY, freshness: ActionWindow,
    confirmation: None, idempotency: ACTION,
    doc: "Submit a delegation from the paired device. A provider delegation identifier is \
          correlation data, never authority.";

    VoiceContext = "voice.context", Voice,
    effect: Read, ingress: [PairedDevice], rights: [basis(VoiceGrant), req(SessionView)],
    selectors: [Session, VoiceSession],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read the selected voice context. Selection intersects this device's scope and never \
          uses the host owner's broader history.";

    // ----- Automation -----------------------------------------------------------------------
    WorkflowInstall = "workflow.install", Automation,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(AutomationManage)],
    selectors: [Environment, Workflow],
    history: NotApplicable, capability: cap("workflow", WorkflowDefinitionVersion),
    freshness: ActionWindow, confirmation: WhenEnlargingAuthority, idempotency: ACTION,
    doc: "Install a versioned automation definition under an explicit workflow grant.";

    WorkflowEnable = "workflow.enable", Automation,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(AutomationManage)],
    selectors: [Workflow],
    history: NotApplicable, capability: cap("workflow", WorkflowDefinitionVersion),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Enable an installed definition at an exact revision.";

    WorkflowPause = "workflow.pause", Automation,
    effect: Write, ingress: [LocalIpc, PairedDevice], rights: [req(AutomationManage)],
    selectors: [Workflow],
    history: NotApplicable, capability: cap("workflow", WorkflowDefinitionVersion),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Pause a definition. Exceeding a concurrency or budget limit pauses it automatically.";

    WorkflowRun = "workflow.run", Automation,
    effect: Write, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(AutomationManage)],
    selectors: [Workflow],
    history: NotApplicable, capability: cap("workflow", WorkflowDefinitionVersion),
    freshness: ActionWindow, confirmation: None, idempotency: ACTION,
    doc: "Start a run, recording the trigger event, definition version and causal parent.";

    WorkflowRead = "workflow.read", Automation,
    effect: Read, ingress: [LocalIpc, PairedDevice, Workflow], rights: [req(AutomationManage)],
    selectors: [Workflow],
    history: GrantLowerBound, capability: NO_CAPABILITY, freshness: CurrentAuthority,
    confirmation: None, idempotency: READ,
    doc: "Read definitions, runs, node receipts and remaining causal budget.";
}

impl Method {
    /// Returns this method's authority entry.
    #[must_use]
    pub fn entry(self) -> &'static MethodEntry {
        let entry = &REGISTRY[self as usize];
        debug_assert!(
            entry.method == self,
            "registry order must match declaration order"
        );
        entry
    }
}

impl fmt::Display for Method {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Returns the authority entry for a method name, or `None` when it is not listed.
#[must_use]
pub fn lookup(name: &str) -> Option<&'static MethodEntry> {
    Method::from_wire(name).map(Method::entry)
}

/// Decides whether a request may proceed past the registry.
///
/// Anything unlisted is denied. A listed method at an unsupported version is a schema failure. An
/// ingress class the entry does not list is denied whatever rights the caller holds.
#[must_use]
pub fn decide(name: &str, version: MethodVersion, ingress: ActorIngress) -> AuthorityDecision {
    let Some(entry) = lookup(name) else {
        return AuthorityDecision::Denied(DenialReason::UnlistedMethod);
    };
    if entry.version != version {
        return AuthorityDecision::Denied(DenialReason::UnsupportedVersion {
            supported: entry.version,
        });
    }
    if !entry.permits_ingress(ingress) {
        return AuthorityDecision::Denied(DenialReason::ForbiddenIngress { ingress });
    }
    AuthorityDecision::Listed(entry)
}
