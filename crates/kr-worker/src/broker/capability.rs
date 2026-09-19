//! The per-installation capability map, and the evidence contract behind it.
//!
//! Section 11 separates two things that share a word. A *requested capability* is what a package
//! asks to be permitted. *Capability evidence* is what the host currently knows about whether
//! something works here. This module is about the second, and about the rule that keeps it honest:
//! evidence is never authority. A record saying a prompt can be submitted does not permit
//! submitting one; it says that if the actor may, the attempt will reach something.
//!
//! Three obligations shape the code.
//!
//! * **The host owns the evidence, and probes are bounded and disclosed.** A [`Probe`] declares
//!   what it will do before it runs, and a probe with a destructive effect is refused unless it
//!   names an isolated test context. Nothing here mutates unrelated user data to find out whether
//!   a capability works.
//! * **Evidence is invalidated by the right change.** A record names the triggers that make it
//!   stale, so an installed upgrade invalidates a record about the binary and leaves a running
//!   binding's correctly pinned record exactly as it was.
//! * **Every action rechecks.** [`CapabilityOwner::recheck`] is called on the dispatch path with
//!   the revision the caller read, so acting on evidence that has since changed is refused rather
//!   than attempted.

use std::collections::BTreeMap;

use kr_protocol::broker::{
    CapabilityMap, InstanceCapabilityRecord, InstanceCapabilityState, InstanceInvalidation,
};
use kr_protocol::ids::{ApplicationInstanceId, CapabilityId, CapabilityRevision};
use kr_protocol::scalars::TimestampMs;

use crate::broker::error::{BrokerError, Result};

/// One bounded, disclosed probe of a capability.
///
/// The declaration is the disclosure. A probe that ran something other than what it declared would
/// make the record a claim about an operation nobody agreed to, so the plan is what is shown to a
/// person and what the runner is held to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    /// The capability the probe establishes.
    pub capability_id: CapabilityId,
    /// The operations it will perform, named for a person.
    pub declared_operations: Vec<String>,
    /// True when one of those operations changes state.
    pub destructive: bool,
    /// The isolated context a destructive probe runs in, where it has one.
    ///
    /// Section 11: "destructive probes need their own explicit isolated test context". A probe
    /// that declares a destructive effect and names no context is refused.
    pub isolated_context: Option<String>,
    /// How long the probe may take.
    pub budget_ms: u64,
}

/// The longest a capability probe may run.
///
/// A probe is a bounded question, not a test suite. Anything that needs longer is qualification
/// data, which ships as a signed catalogue artefact rather than running here.
pub const MAX_PROBE_BUDGET_MS: u64 = 2_000;

impl Probe {
    /// Checks that this probe is one the host will run.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the probe declares nothing, exceeds its
    /// budget, or is destructive without an isolated context.
    pub fn validate(&self) -> Result<()> {
        if self.declared_operations.is_empty() {
            return Err(BrokerError::invalid(
                "a capability probe must declare the operations it performs",
            ));
        }
        if self.budget_ms == 0 || self.budget_ms > MAX_PROBE_BUDGET_MS {
            return Err(BrokerError::invalid(format!(
                "a capability probe runs for 1 to {MAX_PROBE_BUDGET_MS} milliseconds"
            )));
        }
        if self.destructive && self.isolated_context.is_none() {
            return Err(BrokerError::invalid(
                "a destructive capability probe needs its own isolated test context",
            ));
        }
        Ok(())
    }
}

/// The capability maps this worker keeps for dispatch.
#[derive(Debug, Default)]
pub struct CapabilityOwner {
    maps: BTreeMap<ApplicationInstanceId, CapabilityMap>,
}

impl CapabilityOwner {
    /// An empty owner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns one installation's map, or an empty one.
    #[must_use]
    pub fn map(&self, application_instance_id: ApplicationInstanceId) -> CapabilityMap {
        self.maps
            .get(&application_instance_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Records one capability record.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Capability`] when the record breaks one of section 11's rules: a
    /// source that cannot establish a working capability claiming one, or an unusable state with
    /// no reason a person can read.
    pub fn record(&mut self, record: InstanceCapabilityRecord) -> Result<()> {
        self.maps
            .entry(record.application_instance_id)
            .or_default()
            .upsert(record)
            .map_err(BrokerError::from)
    }

    /// Records the result of a probe the host ran.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the probe was not one the host would run, and
    /// [`BrokerError::Capability`] when the record it produced breaks a rule.
    pub fn record_probe(&mut self, probe: &Probe, record: InstanceCapabilityRecord) -> Result<()> {
        probe.validate()?;
        if record.capability_id != probe.capability_id {
            return Err(BrokerError::invalid(
                "a probe's record must be about the capability the probe declared",
            ));
        }
        self.record(record)
    }

    /// Invalidates every record one change makes stale, across every installation.
    ///
    /// Returns how many records were affected. A record whose triggers do not name the change is
    /// untouched, which is what leaves an old running process's pinned evidence alone when the
    /// executable on disk is replaced.
    pub fn invalidate(
        &mut self,
        change: InstanceInvalidation,
        reason: &str,
        now: TimestampMs,
    ) -> usize {
        self.maps
            .values_mut()
            .map(|map| map.invalidate(change, reason, now))
            .sum()
    }

    /// Invalidates the records of one installation only.
    pub fn invalidate_instance(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        change: InstanceInvalidation,
        reason: &str,
        now: TimestampMs,
    ) -> usize {
        self.maps
            .get_mut(&application_instance_id)
            .map_or(0, |map| map.invalidate(change, reason, now))
    }

    /// Rechecks one capability before an action is dispatched.
    ///
    /// The caller passes the revision it read the evidence at, where it read one. A revision that
    /// has moved is refused rather than acted on: what a client saw and what the host knows are
    /// two different things, and the second one decides.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnsupportedCapability`] when nothing is recorded or the state is not
    /// usable, and [`BrokerError::StaleBinding`] when the caller's revision is not the one held.
    pub fn recheck(
        &self,
        application_instance_id: ApplicationInstanceId,
        capability_id: &CapabilityId,
        read_at: Option<CapabilityRevision>,
    ) -> Result<&InstanceCapabilityRecord> {
        let record = self
            .maps
            .get(&application_instance_id)
            .and_then(|map| map.record(capability_id))
            .ok_or_else(|| BrokerError::UnsupportedCapability {
                detail: format!("nothing is known about {capability_id} for this installation"),
            })?;
        if let Some(read_at) = read_at
            && read_at != record.revision
        {
            return Err(BrokerError::StaleBinding {
                detail: format!(
                    "{capability_id} was read at revision {read_at} and is at {}",
                    record.revision
                ),
            });
        }
        if !record.state.is_usable() {
            return Err(BrokerError::UnsupportedCapability {
                detail: record.disabled_reason.as_ref().map_or_else(
                    || format!("{capability_id} is {}", record.state),
                    |reason| format!("{capability_id} is {}: {reason}", record.state),
                ),
            });
        }
        Ok(record)
    }

    /// Returns true when one capability is usable now.
    #[must_use]
    pub fn is_usable(
        &self,
        application_instance_id: ApplicationInstanceId,
        capability_id: &CapabilityId,
    ) -> bool {
        self.maps
            .get(&application_instance_id)
            .and_then(|map| map.record(capability_id))
            .is_some_and(|record| record.state == InstanceCapabilityState::QualifiedAvailable)
    }

    /// Forgets one installation's map.
    pub fn forget(&mut self, application_instance_id: ApplicationInstanceId) {
        self.maps.remove(&application_instance_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::broker::{InstanceCapabilityIdentity, InstanceEvidenceSource};
    use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable, Uuid};

    fn instance() -> ApplicationInstanceId {
        ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
    }

    fn capability(name: &str) -> CapabilityId {
        CapabilityId::new(name).expect("valid")
    }

    fn record(
        name: &str,
        state: InstanceCapabilityState,
        trigger: InstanceInvalidation,
    ) -> InstanceCapabilityRecord {
        InstanceCapabilityRecord {
            capability_id: capability(name),
            capability_version: "1".to_owned(),
            application_instance_id: instance(),
            identity: InstanceCapabilityIdentity {
                binary_digest: Nullable::some(Digest256::from_bytes([3; 32])),
                ..InstanceCapabilityIdentity::default()
            },
            revision: CapabilityRevision::new(1),
            state,
            source: InstanceEvidenceSource::HostProbe,
            invalidated_by: [trigger].into_iter().collect(),
            disabled_reason: if state.is_usable() {
                Nullable::null()
            } else {
                Nullable::some("not qualified here".to_owned())
            },
            observed_at: TimestampMs::new(1),
        }
    }

    fn probe(name: &str) -> Probe {
        Probe {
            capability_id: capability(name),
            declared_operations: vec!["list the upstream's advertised commands".to_owned()],
            destructive: false,
            isolated_context: None,
            budget_ms: 500,
        }
    }

    #[test]
    fn a_destructive_probe_needs_its_own_context() {
        let mut destructive = probe("agent.prompt");
        destructive.destructive = true;
        assert!(destructive.validate().is_err());
        destructive.isolated_context = Some("a scratch conversation".to_owned());
        assert!(destructive.validate().is_ok());
    }

    #[test]
    fn a_probe_declares_what_it_does_and_how_long_it_may_take() {
        let mut silent = probe("agent.prompt");
        silent.declared_operations.clear();
        assert!(silent.validate().is_err());
        let mut unbounded = probe("agent.prompt");
        unbounded.budget_ms = MAX_PROBE_BUDGET_MS + 1;
        assert!(unbounded.validate().is_err());
    }

    #[test]
    fn a_probe_records_only_the_capability_it_declared() {
        let mut owner = CapabilityOwner::new();
        let result = owner.record_probe(
            &probe("agent.prompt"),
            record(
                "agent.cancel",
                InstanceCapabilityState::QualifiedAvailable,
                InstanceInvalidation::BinaryChanged,
            ),
        );
        assert!(result.is_err());
    }

    #[test]
    fn evidence_is_not_permission_and_a_signed_record_cannot_claim_it_works_here() {
        let mut owner = CapabilityOwner::new();
        let mut signed = record(
            "agent.prompt",
            InstanceCapabilityState::QualifiedAvailable,
            InstanceInvalidation::BinaryChanged,
        );
        signed.source = InstanceEvidenceSource::SignedRecord;
        assert!(owner.record(signed).is_err());
    }

    #[test]
    fn a_recheck_refuses_a_revision_that_has_moved_or_a_capability_nothing_is_known_about() {
        let mut owner = CapabilityOwner::new();
        owner
            .record(record(
                "agent.prompt",
                InstanceCapabilityState::QualifiedAvailable,
                InstanceInvalidation::BinaryChanged,
            ))
            .expect("recorded");
        owner
            .recheck(
                instance(),
                &capability("agent.prompt"),
                Some(CapabilityRevision::new(1)),
            )
            .expect("the revision the caller read is the one held");
        assert!(
            owner
                .recheck(
                    instance(),
                    &capability("agent.prompt"),
                    Some(CapabilityRevision::new(2))
                )
                .is_err()
        );
        assert!(
            owner
                .recheck(instance(), &capability("agent.commands"), None)
                .is_err(),
            "nothing is known about an unrecorded capability, and nothing is assumed"
        );
    }

    #[test]
    fn an_upgrade_invalidates_what_it_is_about_and_nothing_else() {
        let mut owner = CapabilityOwner::new();
        owner
            .record(record(
                "agent.prompt",
                InstanceCapabilityState::QualifiedAvailable,
                InstanceInvalidation::BinaryChanged,
            ))
            .expect("recorded");
        owner
            .record(record(
                "agent.approval",
                InstanceCapabilityState::QualifiedAvailable,
                InstanceInvalidation::BindingChanged,
            ))
            .expect("recorded");
        assert_eq!(
            owner.invalidate(
                InstanceInvalidation::BinaryChanged,
                "the executable was upgraded",
                TimestampMs::new(5)
            ),
            1
        );
        assert!(!owner.is_usable(instance(), &capability("agent.prompt")));
        assert!(
            owner.is_usable(instance(), &capability("agent.approval")),
            "a running binding's pinned evidence survives an installed upgrade"
        );
    }

    #[test]
    fn an_unusable_capability_refuses_with_the_reason_a_person_reads() {
        let mut owner = CapabilityOwner::new();
        owner
            .record(record(
                "agent.prompt",
                InstanceCapabilityState::PermissionRequired,
                InstanceInvalidation::OsPermissionChanged,
            ))
            .expect("recorded");
        let refusal = owner
            .recheck(instance(), &capability("agent.prompt"), None)
            .expect_err("an unusable capability refuses");
        assert!(refusal.to_string().contains("not qualified here"));
    }

    #[test]
    fn a_map_is_per_installation() {
        let mut owner = CapabilityOwner::new();
        owner
            .record(record(
                "agent.prompt",
                InstanceCapabilityState::QualifiedAvailable,
                InstanceInvalidation::BinaryChanged,
            ))
            .expect("recorded");
        let other = ApplicationInstanceId::new(Uuid::from_bytes([3; 16]));
        assert!(owner.map(other).records.is_empty());
        assert_eq!(owner.map(instance()).records.len(), 1);
        let _ = CanonicalSet::<InstanceInvalidation>::new();
    }
}
