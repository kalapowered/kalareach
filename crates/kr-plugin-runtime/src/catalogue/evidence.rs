//! Capability evidence the catalogue contributes, and what a signed qualification may not do.
//!
//! A repository ships qualification data as signed, immutable catalogue artifacts, separately from
//! host binaries. That is worth having: a vendor can say "this release was qualified against
//! ExternalApp 1.4" without waiting for a core release. It is also the obvious way to smuggle authority
//! into a host, so section 11 draws four lines and this module is where a host holds them.
//!
//! * **A qualification cannot create a new primitive effect.** The capability it talks about has
//!   to be one the installed package already requests. A record about something the package never
//!   asked for is not evidence about that package.
//! * **A qualification cannot raise a grant.** Evidence is about feasibility. What the package may
//!   do is the ceiling and the installation grant, and it is decided without reading a word of
//!   qualification data.
//! * **A qualification cannot turn an old live binding into a different version.** Evidence names
//!   the exact package hash it is about, and a live binding stays on the hash it was made against,
//!   so a record published for another release is about another release.
//! * **A qualification cannot say it works here.** Only a host probe or a live binding can
//!   establish that. The SDK's own validator enforces that last one, and this module keeps to it
//!   by construction: everything built here is a version-level state.
//!
//! The shape is [`kr_plugin_sdk::capability::CapabilityEvidence`], not a fourth spelling of it.
//! The catalogue's evidence carries the same capability namespace, the same runtime state
//! vocabulary, the same evidence sources, the same identity fields and the same invalidation
//! triggers every other subsystem uses.

use std::collections::BTreeSet;

use kr_plugin_sdk::capability::{
    CapabilityEvidence, CapabilityState, EvidenceSource, EvidenceSubject, InvalidationTrigger,
    PluginCapability, SubjectIdentity,
};
use kr_plugin_sdk::catalogue::{IndexEntry, QualificationResult};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::text::DisabledReason;
use kr_protocol::ids::{CapabilityRevision, EnvironmentId};
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};

use crate::catalogue::error::{CatalogueError, CatalogueResult};
use crate::catalogue::install::Installation;

/// The capability namespace prefix a plugin capability lives under.
///
/// The namespace is shared and versioned, so a plugin capability is spelled the same way in a
/// record, in a grant prompt and in `kr doctor`.
pub const NAMESPACE: &str = "plugin";

/// The version of the plugin capability contract this build speaks.
pub const NAMESPACE_VERSION: u32 = 1;

/// Returns the shared capability identifier for one plugin capability.
///
/// # Errors
///
/// Returns [`CatalogueError::InvalidArgument`] when the identifier cannot be built, which cannot
/// happen for the closed vocabulary and is reported rather than unwrapped.
pub fn capability_id(
    capability: PluginCapability,
) -> CatalogueResult<kr_protocol::ids::CapabilityId> {
    kr_protocol::ids::CapabilityId::new(format!(
        "{NAMESPACE}.{}/{NAMESPACE_VERSION}",
        capability.as_str()
    ))
    .map_err(|source| CatalogueError::InvalidArgument {
        detail: format!("{capability} has no capability identifier: {source}"),
    })
}

/// Builds the evidence one catalogue qualification supports, for one installation.
///
/// The record is always a version-level state: a signed catalogue artifact describes a release,
/// and this host has not probed anything by reading it.
///
/// # Errors
///
/// Returns [`CatalogueError::UnsafePackage`] when the qualification talks about a capability the
/// package never requested, or claims a host outcome, or names a release other than the installed
/// one.
pub fn from_qualification(
    entry: &IndexEntry,
    installation: &Installation,
    qualification: &QualificationResult,
    revision: CapabilityRevision,
    observed_at: TimestampMs,
) -> CatalogueResult<CapabilityEvidence> {
    // The SDK's own rule: a catalogue result cannot claim a host outcome and comes from a signed
    // record. Checking it here means a repository cannot reach a host by publishing one that the
    // pipeline would have rejected.
    qualification
        .validate()
        .map_err(|source| CatalogueError::UnsafePackage {
            detail: format!(
                "{} published a qualification this host will not read: {source}",
                entry.plugin_id
            ),
        })?;

    let requested: BTreeSet<PluginCapability> = entry
        .capabilities
        .iter()
        .map(|request| request.capability)
        .collect();
    let named = requested
        .iter()
        .copied()
        .find(|capability| {
            capability_id(*capability)
                .map(|id| id == qualification.capability_id)
                .unwrap_or(false)
        })
        .ok_or_else(|| CatalogueError::UnsafePackage {
            detail: format!(
                "{} published a qualification for {}, which it does not request; qualification \
                 data cannot create a primitive effect a package never asked for",
                entry.plugin_id, qualification.capability_id
            ),
        })?;

    if entry.manifest_digest != installation.package_digest {
        return Err(CatalogueError::UnsafePackage {
            detail: format!(
                "{} is installed at {} and the qualification is about {}; updating qualification \
                 data does not turn a live binding into a different version",
                entry.plugin_id, installation.package_digest, entry.manifest_digest
            ),
        });
    }

    let evidence = CapabilityEvidence {
        capability_id: qualification.capability_id.clone(),
        capability_version: qualification.capability_version.clone(),
        subject: EvidenceSubject {
            environment_id: installation.environment_id,
            application: Nullable(Some(qualification.subject.clone())),
            terminal: Nullable(None),
            desktop_generation: Nullable(None),
        },
        identity: SubjectIdentity {
            binary_digest: Nullable(None),
            schema_version: Nullable(None),
            plugin_id: Nullable(Some(entry.plugin_id.clone())),
            package_digest: Nullable(Some(entry.manifest_digest)),
            publisher_id: Nullable(Some(entry.publisher_id.clone())),
            profile_digest: Nullable(Some(qualification.profile_digest)),
            binding_revision: Nullable(None),
        },
        // One revision per generation of the catalogue this came from: a record that changes when
        // the repository publishes again is a record every action can recheck.
        revision,
        state: qualification.state,
        source: EvidenceSource::SignedRecord,
        invalidated_by: [
            InvalidationTrigger::ProfileChanged,
            InvalidationTrigger::BindingChanged,
            InvalidationTrigger::SchemaChanged,
        ]
        .into_iter()
        .collect::<CanonicalSet<_>>(),
        disabled_reason: Nullable(if qualification.state.is_usable() {
            None
        } else {
            Some(disabled_reason(named, qualification)?)
        }),
        observed_at,
    };
    evidence
        .validate()
        .map_err(|source| CatalogueError::UnsafePackage {
            detail: format!("{} published invalid evidence: {source}", entry.plugin_id),
        })?;
    Ok(evidence)
}

/// Builds the evidence for a capability nothing has qualified.
///
/// A package that requests something and has no signed result for it is not silently available.
/// The record says so, in the vocabulary that tells a person which fix applies.
///
/// # Errors
///
/// Returns [`CatalogueError::InvalidArgument`] when the capability has no identifier, and
/// [`CatalogueError::UnsafePackage`] when the record this builds would be invalid.
pub fn untested(
    entry: &IndexEntry,
    installation: &Installation,
    capability: PluginCapability,
    revision: CapabilityRevision,
    observed_at: TimestampMs,
) -> CatalogueResult<CapabilityEvidence> {
    let evidence = CapabilityEvidence {
        capability_id: capability_id(capability)?,
        capability_version: entry.version.clone(),
        subject: EvidenceSubject {
            environment_id: installation.environment_id,
            application: Nullable(None),
            terminal: Nullable(None),
            desktop_generation: Nullable(None),
        },
        identity: SubjectIdentity {
            binary_digest: Nullable(None),
            schema_version: Nullable(None),
            plugin_id: Nullable(Some(entry.plugin_id.clone())),
            package_digest: Nullable(Some(installation.package_digest)),
            publisher_id: Nullable(Some(entry.publisher_id.clone())),
            profile_digest: Nullable(None),
            binding_revision: Nullable(None),
        },
        revision,
        state: CapabilityState::NotTested,
        source: EvidenceSource::PackageDeclaration,
        invalidated_by: [
            InvalidationTrigger::BindingChanged,
            InvalidationTrigger::SchemaChanged,
        ]
        .into_iter()
        .collect::<CanonicalSet<_>>(),
        disabled_reason: Nullable(Some(
            DisabledReason::new(format!(
                "{} has not been tested against this environment",
                capability.as_str()
            ))
            .map_err(|source| CatalogueError::InvalidArgument {
                detail: format!("the reason could not be written: {source}"),
            })?,
        )),
        observed_at,
    };
    evidence
        .validate()
        .map_err(|source| CatalogueError::UnsafePackage {
            detail: format!("{} produced invalid evidence: {source}", entry.plugin_id),
        })?;
    Ok(evidence)
}

/// Checks that a set of evidence records grants nothing.
///
/// Evidence describes feasibility. This is the host-side half of "updating the data cannot raise
/// grants": whatever the records say, the capabilities an installation may use are the ones the
/// ceiling and the installation grant already decided, and a record about anything else is
/// refused rather than quietly ignored.
///
/// # Errors
///
/// Returns [`CatalogueError::UnsafePackage`] when a record is about a capability outside the
/// effective set.
pub fn check_grants_nothing(
    records: &[CapabilityEvidence],
    effective: &BTreeSet<PluginCapability>,
    plugin: &str,
) -> CatalogueResult<()> {
    for record in records {
        let covered = effective.iter().copied().any(|capability| {
            capability_id(capability)
                .map(|id| id == record.capability_id)
                .unwrap_or(false)
        });
        if !covered && record.state.is_positive() {
            return Err(CatalogueError::UnsafePackage {
                detail: format!(
                    "{plugin} carries a positive record for {}, which it has no grant for; \
                     qualification data cannot raise a grant",
                    record.capability_id
                ),
            });
        }
    }
    Ok(())
}

/// Returns true when a record still describes the binding it is about.
///
/// An installed upgrade does not invalidate an old running process's correctly pinned identity, so
/// the comparison is against the hash the binding holds rather than against whatever is installed
/// now.
#[must_use]
pub fn applies_to_binding(record: &CapabilityEvidence, package_digest: PayloadDigest) -> bool {
    record.identity.package_digest.0 == Some(package_digest)
}

fn disabled_reason(
    capability: PluginCapability,
    qualification: &QualificationResult,
) -> CatalogueResult<DisabledReason> {
    let explanation = match qualification.state {
        CapabilityState::VersionQualified => {
            "this release was qualified against it, and this host has not been checked"
        }
        CapabilityState::MissingInstallation => "the application or bridge is not installed",
        CapabilityState::PermissionRequired => "a permission has not been granted",
        CapabilityState::Incompatible => "the installed version cannot support it",
        CapabilityState::TemporarilyUnavailable => "it is not working right now",
        CapabilityState::NotTested => "nothing has tested it",
        CapabilityState::QualifiedAvailable => "it works here",
    };
    DisabledReason::new(format!(
        "{}: {explanation}. {}",
        capability.as_str(),
        qualification.statement.as_str()
    ))
    .map_err(|source| CatalogueError::InvalidArgument {
        detail: format!("the reason could not be written: {source}"),
    })
}

/// Returns an evidence subject naming only an environment.
#[must_use]
pub fn environment_subject(environment_id: EnvironmentId) -> EvidenceSubject {
    EvidenceSubject {
        environment_id,
        application: Nullable(None),
        terminal: Nullable(None),
        desktop_generation: Nullable(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_plugin_sdk::example::example_manifest;
    use kr_plugin_sdk::text::{Label, Summary};
    use kr_plugin_sdk::version::PackageVersion;
    use kr_protocol::scalars::Uuid;

    use crate::catalogue::ceiling::InstallationGrant;
    use crate::catalogue::repository::RepositoryId;

    fn now() -> TimestampMs {
        TimestampMs::new(1_760_000_000_000)
    }

    fn entry() -> IndexEntry {
        IndexEntry::from_manifest(&example_manifest(), PayloadDigest::of(b"manifest"), 4_096)
    }

    fn installation(entry: &IndexEntry) -> Installation {
        Installation::from_entry(
            entry,
            RepositoryId::new("official").expect("a valid identifier"),
            EnvironmentId::new(Uuid::NIL),
            InstallationGrant::none(),
            crate::catalogue::repository::CapabilityCeiling::default_ceiling(),
        )
    }

    fn qualification(capability: PluginCapability, state: CapabilityState) -> QualificationResult {
        QualificationResult {
            capability_id: capability_id(capability).expect("a capability identifier"),
            capability_version: PackageVersion::parse("1.0.0").expect("a valid version"),
            subject: Label::new("ExternalApp 1.4").expect("a valid label"),
            state,
            source: EvidenceSource::SignedRecord,
            profile_digest: PayloadDigest::of(b"profile"),
            statement: Summary::new("Qualified against ExternalApp 1.4")
                .expect("a valid statement"),
        }
    }

    #[test]
    fn a_qualification_names_a_capability_the_package_requests() {
        let entry = entry();
        let installation = installation(&entry);
        let requested = entry.capabilities[0].capability;
        let record = from_qualification(
            &entry,
            &installation,
            &qualification(requested, CapabilityState::VersionQualified),
            CapabilityRevision::new(1),
            now(),
        )
        .expect("a readable qualification");
        assert_eq!(record.source, EvidenceSource::SignedRecord);
        assert_eq!(record.state, CapabilityState::VersionQualified);
        assert!(
            !record.state.is_usable(),
            "a catalogue record is not a host result"
        );

        let unrequested = PluginCapability::ALL
            .iter()
            .copied()
            .find(|capability| {
                !entry
                    .capabilities
                    .iter()
                    .any(|r| r.capability == *capability)
            })
            .expect("some capability the example does not request");
        let refusal = from_qualification(
            &entry,
            &installation,
            &qualification(unrequested, CapabilityState::VersionQualified),
            CapabilityRevision::new(1),
            now(),
        )
        .expect_err("a capability the package never asked for");
        assert!(
            refusal
                .to_string()
                .contains("cannot create a primitive effect"),
            "{refusal}"
        );
    }

    #[test]
    fn a_qualification_cannot_claim_the_capability_works_here() {
        let entry = entry();
        let installation = installation(&entry);
        let requested = entry.capabilities[0].capability;
        let refusal = from_qualification(
            &entry,
            &installation,
            &qualification(requested, CapabilityState::QualifiedAvailable),
            CapabilityRevision::new(1),
            now(),
        )
        .expect_err("a host claim");
        assert!(refusal.to_string().contains("will not read"), "{refusal}");
    }

    #[test]
    fn a_qualification_for_another_release_does_not_move_an_installation() {
        let entry = entry();
        let mut installation = installation(&entry);
        installation.package_digest = PayloadDigest::of(b"the hash this host installed");
        let requested = entry.capabilities[0].capability;
        let refusal = from_qualification(
            &entry,
            &installation,
            &qualification(requested, CapabilityState::VersionQualified),
            CapabilityRevision::new(1),
            now(),
        )
        .expect_err("another release");
        assert!(
            refusal
                .to_string()
                .contains("does not turn a live binding into a different version"),
            "{refusal}"
        );
    }

    #[test]
    fn evidence_never_widens_what_a_package_may_do() {
        let entry = entry();
        let installation = installation(&entry);
        let requested = entry.capabilities[0].capability;
        let record = from_qualification(
            &entry,
            &installation,
            &qualification(requested, CapabilityState::VersionQualified),
            CapabilityRevision::new(1),
            now(),
        )
        .expect("a readable qualification");

        let granted: BTreeSet<PluginCapability> = [requested].into_iter().collect();
        assert!(check_grants_nothing(std::slice::from_ref(&record), &granted, "acme/tool").is_ok());

        let nothing = BTreeSet::new();
        let refusal = check_grants_nothing(&[record], &nothing, "acme/tool")
            .expect_err("a record outside the grant");
        assert!(
            refusal.to_string().contains("cannot raise a grant"),
            "{refusal}"
        );
    }

    #[test]
    fn an_untested_capability_says_so_and_names_a_reason() {
        let entry = entry();
        let installation = installation(&entry);
        let record = untested(
            &entry,
            &installation,
            PluginCapability::TerminalStream,
            CapabilityRevision::new(1),
            now(),
        )
        .expect("a buildable record");
        assert_eq!(record.state, CapabilityState::NotTested);
        assert!(!record.state.is_positive());
        assert!(record.disabled_reason.0.is_some());
        assert!(applies_to_binding(&record, installation.package_digest));
        assert!(!applies_to_binding(&record, PayloadDigest::of(b"other")));
    }

    #[test]
    fn a_capability_identifier_is_in_the_shared_namespace() {
        for capability in PluginCapability::ALL {
            let id = capability_id(*capability).expect("an identifier");
            assert!(id.as_str().starts_with("plugin."), "{id}");
            assert!(id.as_str().ends_with("/1"), "{id}");
        }
    }
}
