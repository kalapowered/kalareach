//! What a package is permitted, and who has to say so.
//!
//! Enrolling a repository sets a ceiling so that thousands of passive downloads do not become
//! thousands of permission prompts. The default permits metadata matching, declarative
//! presentation and already-authorised broker semantic events, and nothing else: every one of
//! those is something the host was already doing with data the actor may already see.
//!
//! Everything past the default is somebody's explicit decision, and the decisions are not
//! interchangeable.
//!
//! | What the package asks for | Who has to say so |
//! | --- | --- |
//! | The three default capabilities | Nobody; the enrolment already did |
//! | Transcript tails, process observation, upstream actions | An explicit package or repository grant |
//! | Raw terminal streams, terminal input, filesystem, network, decoding and answering approvals | An explicit installation grant |
//! | A native bridge, which runs under the application's own permissions | An installation grant with the owner's confirmation |
//! | Anything the previous installation did not have | An installation grant, because an increase is not the old decision |
//!
//! The last row is why this module compares two grants rather than answering about one
//! capability. An upgrade that quietly widens what a package may do is the thing the installation
//! grant exists to prevent, and a host that only checked the floor would miss it.

use std::collections::BTreeSet;

use kr_plugin_sdk::capability::{CapabilityRequest, PluginCapability};

use crate::catalogue::error::{CatalogueError, CatalogueResult};
use crate::catalogue::repository::CapabilityCeiling;

/// Who has to permit one capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantRequirement {
    /// The repository's ceiling already permits it.
    WithinCeiling,
    /// An explicit package or repository grant is needed.
    RepositoryGrant,
    /// An explicit installation grant is needed.
    InstallationGrant,
    /// An installation grant the owner confirms, because the code runs outside the sandbox.
    ConfirmedInstallationGrant,
}

impl GrantRequirement {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WithinCeiling => "within_ceiling",
            Self::RepositoryGrant => "repository_grant",
            Self::InstallationGrant => "installation_grant",
            Self::ConfirmedInstallationGrant => "confirmed_installation_grant",
        }
    }

    /// Returns what the person is being asked to accept.
    #[must_use]
    pub const fn statement(self) -> &'static str {
        match self {
            Self::WithinCeiling => "the repository's ceiling",
            Self::RepositoryGrant => "an explicit package or repository grant",
            Self::InstallationGrant => "an explicit installation grant",
            Self::ConfirmedInstallationGrant => {
                "an installation grant the owner confirms, because the files run under the \
                 application's own permissions and outside the component sandbox"
            }
        }
    }

    /// Returns true when the owner has to confirm this decision.
    #[must_use]
    pub const fn needs_confirmation(self) -> bool {
        matches!(self, Self::ConfirmedInstallationGrant)
    }
}

impl core::fmt::Display for GrantRequirement {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.statement())
    }
}

/// What one installation has been permitted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstallationGrant {
    granted: BTreeSet<PluginCapability>,
}

impl InstallationGrant {
    /// An installation that has been granted nothing beyond its repository's ceiling.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Builds a grant over an explicit set.
    #[must_use]
    pub fn with(capabilities: impl IntoIterator<Item = PluginCapability>) -> Self {
        Self {
            granted: capabilities.into_iter().collect(),
        }
    }

    /// Returns true when this grant covers the capability.
    #[must_use]
    pub fn holds(&self, capability: PluginCapability) -> bool {
        self.granted.contains(&capability)
    }

    /// Returns the granted capabilities in a stable order.
    #[must_use]
    pub fn capabilities(&self) -> Vec<PluginCapability> {
        self.granted.iter().copied().collect()
    }

    /// Adds one capability to the grant.
    pub fn add(&mut self, capability: PluginCapability) {
        self.granted.insert(capability);
    }

    /// Returns what `other` holds and this grant does not.
    #[must_use]
    pub fn increase_over(&self, other: &Self) -> Vec<PluginCapability> {
        other.granted.difference(&self.granted).copied().collect()
    }
}

/// What one requested capability needs, and whether it has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityDecision {
    /// The capability the package asked for.
    pub capability: PluginCapability,
    /// Who has to permit it.
    pub requirement: GrantRequirement,
    /// Whether it is permitted as things stand.
    pub permitted: bool,
}

/// Decides what one capability needs under a ceiling.
#[must_use]
pub fn requirement_for(
    capability: PluginCapability,
    ceiling: &CapabilityCeiling,
) -> GrantRequirement {
    // A native bridge installs files that run under the application's own permissions, outside
    // the component sandbox. No repository ceiling reaches it, whatever the enrolment says.
    if capability == PluginCapability::NativeBridgeInstall {
        return GrantRequirement::ConfirmedInstallationGrant;
    }
    if capability.requires_installation_grant() {
        return GrantRequirement::InstallationGrant;
    }
    if ceiling.permits(capability) {
        return GrantRequirement::WithinCeiling;
    }
    GrantRequirement::RepositoryGrant
}

/// Decides every requested capability against a ceiling and a grant.
#[must_use]
pub fn decide(
    requests: &[CapabilityRequest],
    ceiling: &CapabilityCeiling,
    grant: &InstallationGrant,
) -> Vec<CapabilityDecision> {
    let mut decisions: Vec<CapabilityDecision> = requests
        .iter()
        .map(|request| {
            let requirement = requirement_for(request.capability, ceiling);
            CapabilityDecision {
                capability: request.capability,
                requirement,
                permitted: match requirement {
                    GrantRequirement::WithinCeiling => true,
                    GrantRequirement::RepositoryGrant
                    | GrantRequirement::InstallationGrant
                    | GrantRequirement::ConfirmedInstallationGrant => {
                        grant.holds(request.capability)
                    }
                },
            }
        })
        .collect();
    decisions.sort_by_key(|decision| decision.capability);
    decisions.dedup_by_key(|decision| decision.capability);
    decisions
}

/// Returns the capabilities an installation may actually use.
#[must_use]
pub fn effective(
    requests: &[CapabilityRequest],
    ceiling: &CapabilityCeiling,
    grant: &InstallationGrant,
) -> BTreeSet<PluginCapability> {
    decide(requests, ceiling, grant)
        .into_iter()
        .filter(|decision| decision.permitted)
        .map(|decision| decision.capability)
        .collect()
}

/// Checks that an installation may proceed under this ceiling and this grant.
///
/// # Errors
///
/// Returns [`CatalogueError::GrantRequired`] naming the first capability that has no permission,
/// and what would give it one.
pub fn check_installable(
    requests: &[CapabilityRequest],
    ceiling: &CapabilityCeiling,
    grant: &InstallationGrant,
) -> CatalogueResult<()> {
    for decision in decide(requests, ceiling, grant) {
        if !decision.permitted {
            return Err(CatalogueError::GrantRequired {
                capability: decision.capability,
                requirement: decision.requirement.statement().to_owned(),
            });
        }
    }
    Ok(())
}

/// Checks an upgrade's grant against the one the installation already had.
///
/// An increase over the previous grant is a new decision, whatever the new package asks for and
/// whatever the ceiling permits. A host that only asked "is this inside the ceiling?" would let an
/// upgrade widen an installation silently, which is the one thing the installation grant is for.
///
/// # Errors
///
/// Returns [`CatalogueError::GrantRequired`] when the upgrade would hold more than the previous
/// installation and the owner has not confirmed it.
pub fn check_upgrade(
    previous: &InstallationGrant,
    proposed: &InstallationGrant,
    confirmed: bool,
) -> CatalogueResult<()> {
    if confirmed {
        return Ok(());
    }
    if let Some(added) = previous.increase_over(proposed).first().copied() {
        return Err(CatalogueError::GrantRequired {
            capability: added,
            requirement: format!(
                "an explicit installation grant: the installed package was not permitted {added}, \
                 and an upgrade does not widen what it may do"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_plugin_sdk::text::Summary;

    fn request(capability: PluginCapability) -> CapabilityRequest {
        CapabilityRequest {
            capability,
            reason: Summary::new("because the package says so").expect("a valid summary"),
        }
    }

    #[test]
    fn the_default_ceiling_permits_exactly_the_three_passive_capabilities() {
        let ceiling = CapabilityCeiling::default_ceiling();
        for capability in PluginCapability::ALL {
            let requirement = requirement_for(*capability, &ceiling);
            let within = requirement == GrantRequirement::WithinCeiling;
            assert_eq!(
                within,
                capability.within_default_ceiling(),
                "{capability} decided {requirement:?}"
            );
        }
    }

    #[test]
    fn a_native_bridge_always_needs_the_owners_confirmation() {
        // Even a repository the owner widened all the way cannot reach a native bridge.
        let wide = CapabilityCeiling::with(PluginCapability::ALL.iter().copied());
        assert_eq!(
            requirement_for(PluginCapability::NativeBridgeInstall, &wide),
            GrantRequirement::ConfirmedInstallationGrant
        );
        assert!(requirement_for(PluginCapability::NativeBridgeInstall, &wide).needs_confirmation());
    }

    #[test]
    fn a_repository_grant_covers_an_observation_and_never_an_installation_capability() {
        let ceiling = CapabilityCeiling::with([
            PluginCapability::TranscriptTail,
            PluginCapability::FilesystemRead,
        ]);
        assert_eq!(
            requirement_for(PluginCapability::TranscriptTail, &ceiling),
            GrantRequirement::WithinCeiling
        );
        assert_eq!(
            requirement_for(PluginCapability::FilesystemRead, &ceiling),
            GrantRequirement::InstallationGrant,
            "a repository ceiling cannot grant filesystem access"
        );
    }

    #[test]
    fn an_ungranted_capability_names_itself_and_what_would_permit_it() {
        let requests = vec![
            request(PluginCapability::MetadataMatch),
            request(PluginCapability::TerminalInput),
        ];
        let ceiling = CapabilityCeiling::default_ceiling();
        let refusal = check_installable(&requests, &ceiling, &InstallationGrant::none())
            .expect_err("no grant");
        let message = refusal.to_string();
        assert!(message.contains("terminal.input"), "{message}");
        assert!(message.contains("installation grant"), "{message}");

        let granted = InstallationGrant::with([PluginCapability::TerminalInput]);
        assert!(check_installable(&requests, &ceiling, &granted).is_ok());
        assert_eq!(
            effective(&requests, &ceiling, &granted),
            [
                PluginCapability::MetadataMatch,
                PluginCapability::TerminalInput
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn an_upgrade_does_not_widen_what_an_installation_may_do() {
        let previous = InstallationGrant::with([PluginCapability::TranscriptTail]);
        let same = InstallationGrant::with([PluginCapability::TranscriptTail]);
        assert!(check_upgrade(&previous, &same, false).is_ok());

        let narrower = InstallationGrant::none();
        assert!(check_upgrade(&previous, &narrower, false).is_ok());

        let wider = InstallationGrant::with([
            PluginCapability::TranscriptTail,
            PluginCapability::NetworkOutbound,
        ]);
        let refusal = check_upgrade(&previous, &wider, false).expect_err("an increase");
        assert!(refusal.to_string().contains("does not widen"), "{refusal}");
        assert!(check_upgrade(&previous, &wider, true).is_ok());
    }
}
