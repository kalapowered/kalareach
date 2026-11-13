//! The writes the local door serves, and the kind of route each takes.
//!
//! A mutation that arrives on a local connection is a local write when the registry lists it as a
//! write with the local ingress. Each one has exactly one route here, and the route's kind decides
//! what its answer is labelled: an answer of this request's own effect, a copy of what an earlier
//! request left in a record, or an answer that derives from older records. A write with no row
//! here is refused by name, and a test walks the method table to hold it so.

use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::EffectClass;
use kr_protocol::method::Method;

use super::net;

/// The route a local write takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LocalWrite {
    /// Pairing and owner confirmation, performed by the network module for the host's own account.
    Pairing,
    /// The drafts and uploads the transfer service keeps.
    Transfer,
    /// The voice grant.
    Voice,
    /// The catalogue and the plugins.
    Catalogue,
    /// The project and workspace mutations.
    Project,
    /// The workflows.
    Automation,
    /// The attention store's acknowledgements.
    Attention,
    /// The change-set mutations.
    ChangeSet,
    /// `session.create`: the daemon launches the session itself.
    SessionCreate,
    /// The grant, device, delivery and organisation changes, which claim their action.
    Authority,
    /// The machine group's steps.
    MachineGroup,
    /// The changes of this daemon's own that claim their action first and keep what it came to
    /// under the claim.
    Claimed,
    /// The installation of the agent tools, which keeps its own record of the action.
    Installation,
    /// The disclosed capability checks, whose answers are kept for 30 days.
    Checks,
    /// Setting backups up, which answers a repeat from the saved setup.
    Setup,
    /// The routes that go to the session's worker, which keeps its own receipts: the daemon cannot
    /// tell the worker's first answer from its copy, so the whole answer is a copy.
    Worker,
    /// A write whose first answer derives from records older than the request: the report of the
    /// copies privacy mode lists, the event the lease raises, the adapter list in force. The
    /// reason says what.
    Derived(&'static str),
    /// A write that keeps no record of its action and reads none. The reason says why.
    Unrecorded(&'static str),
    /// A local write the daemon does not serve, because the worker does, or because no request
    /// carries it: the envelope refuses it first, by name.
    NotServed,
}

impl LocalWrite {
    /// The route of `method`, or `None` when it is not a local write.
    pub(super) fn of(method: Method) -> Option<Self> {
        let entry = method.entry();
        if entry.effect != EffectClass::Write || !entry.ingress.contains(&ActorIngress::LocalIpc) {
            return None;
        }
        Some(match method {
            Method::SessionCreate => Self::SessionCreate,
            Method::SessionClose | Method::AgentPromptSubmit | Method::AgentPromptQueue => {
                Self::Worker
            }
            Method::AgentToolsInstall | Method::AgentToolsRemove => Self::Installation,
            Method::EnvironmentCapabilitiesCheck => Self::Checks,
            Method::BackupEnable => Self::Setup,
            Method::GrantCreate
            | Method::GrantRevoke
            | Method::GrantTransfer
            | Method::DeviceRevoke
            | Method::DeliveryDestinationConfigure
            | Method::DeliveryDestinationRemove
            | Method::DeliveryDestinationSecretSet
            | Method::OrganisationEnrol
            | Method::OrganisationExclusiveSet
            | Method::OrganisationWithdraw => Self::Authority,
            Method::MachineJoin | Method::MachineMerge | Method::MachineSplit => Self::MachineGroup,
            Method::EnvironmentEnrol
            | Method::EnvironmentForget
            | Method::EnvironmentRefresh
            | Method::PrivacySet
            | Method::SessionRename
            | Method::DescriptionConfigure
            | Method::DescriptionDownload
            | Method::AccountSignIn
            | Method::AccountSignOut
            | Method::AccountStorageSignIn
            | Method::AccountStorageSignOut
            | Method::HostUpdateHandover => Self::Claimed,
            Method::PrivacyRetainedDelete => Self::Derived(
                "the report lists the copies privacy mode holds, which earlier exports left",
            ),
            Method::MembershipPresent => Self::Derived(
                "the event derives from the exclusive-management event an earlier presentation \
                 left",
            ),
            Method::OrganisationPolicyApply => Self::Derived(
                "the adapter list is the one in force across the policies held, and its refusals \
                 come from policy state",
            ),
            Method::BackupBundleWrite => Self::Unrecorded(
                "a call carries a new identity each time, and the bundle write reads no record",
            ),
            Method::HostPolicyConfirm => Self::Unrecorded(
                "asked again it answers that it lifted nothing, and it reads no record of the \
                 action",
            ),
            _ if net::methods::serves(method) => Self::Pairing,
            _ if crate::transfer::TransferModule::serves(method) => Self::Transfer,
            _ if crate::voice::VoiceModule::serves(method) => Self::Voice,
            _ if crate::catalogue::CatalogueModule::serves(method) => Self::Catalogue,
            _ if crate::project::ProjectModule::serves(method) => Self::Project,
            _ if crate::automation::AutomationModule::serves(method) => Self::Automation,
            _ if crate::attention::AttentionModule::serves(method) => Self::Attention,
            _ if crate::changeset::ChangeSetModule::serves(method) => Self::ChangeSet,
            // Neither the daemon nor a worker's request table serves these: the palette is no
            // action of a request, raw input is an ordered stream with no action identity, and the
            // root editor's frames travel to the worker on its own stream.
            Method::TerminalPaletteSet
            | Method::InputWrite
            | Method::RootEditorEnter
            | Method::RootEditorLeave
            | Method::RootEditorFence
            | Method::RootEofDetach
            | Method::RootCommandAccepted => Self::NotServed,
            _ if kr_protocol::worker_surface::serves(method) => Self::NotServed,
            _ => return None,
        })
    }
}
