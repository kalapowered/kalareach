//! Execution environments, and where a model may be mapped.
//!
//! Section 22 puts one shared inference process and model mapping in each execution environment,
//! never one per session, and it puts two environments outside that rule altogether. WSL reaches a
//! native host only after somebody has explicitly chosen to let local data cross, and mobile does
//! not run a model to label a host session at all.
//!
//! The rule is expressed as a placement rather than as a check somebody remembers to make: an
//! environment answers where its inference may run, and [`ModelMapping`] holds one record per
//! environment.
//!
//! [`ModelMapping`] is bookkeeping, and saying so matters. It holds no process, no weights and no
//! runtime handle, so it unloads nothing by itself: what it records is *which* profile an
//! environment has mapped, which is what decides whether a result is late. The weights belong to
//! [`crate::service::DescriptionService`], which owns exactly one mapping and one runtime and
//! calls `unload` on the runtime **before** it maps another. Two `ModelMapping` values would be
//! two records of one fact, which is why nothing but the service builds one.

use std::collections::BTreeMap;

use kr_protocol::ids::{ActorId, EnvironmentId};
use kr_protocol::scalars::TimestampMs;

use crate::error::{DescribeError, Result};
use crate::profile::catalogue::MetGates;
use crate::profile::{ModelProfile, ProfileRevision};

/// What kind of execution environment this is.
///
/// The distinction that matters here is not the operating system but whether a model may be
/// mapped in this environment at all, and, when it may not, whether something else can be asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvironmentKind {
    /// A native host: macOS, Linux or Windows. Inference runs here.
    Native,
    /// A WSL distribution. Inference runs in the native host it brokers to, and only after an
    /// explicit local data-access choice.
    Wsl,
    /// A mobile device. Section 22: mobile does not run a model merely to label a host session.
    Mobile,
}

impl EnvironmentKind {
    /// Returns the stable name this kind is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Wsl => "wsl",
            Self::Mobile => "mobile",
        }
    }
}

/// The explicit choice that lets a WSL distribution's local data reach a native-host broker.
///
/// It is a recorded act by a named actor at a named moment, not a configuration default. An
/// environment with no choice recorded is an environment where the answer is no.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataAccessChoice {
    /// The environment the choice was made for.
    pub environment_id: EnvironmentId,
    /// Who made it.
    pub chosen_by: ActorId,
    /// When it was made.
    pub chosen_at_ms: TimestampMs,
}

/// A logical grouping of machines a person sees as one.
///
/// It exists so a person can be shown their hosts together. It grants nothing: two environments in
/// one group have their own mapping, their own context and their own transcripts, and this type
/// says so in the only way that cannot be forgotten, by having no method that returns access.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MachineGroup(String);

impl MachineGroup {
    /// Names a group.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Returns the group's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }

    /// Returns whether membership of this group grants access to another environment's
    /// transcripts. It does not, on any host, under any configuration.
    #[must_use]
    pub const fn grants_transcript_access(&self) -> bool {
        false
    }
}

/// One execution environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionEnvironment {
    id: EnvironmentId,
    kind: EnvironmentKind,
    group: Option<MachineGroup>,
}

impl ExecutionEnvironment {
    /// Builds an environment.
    #[must_use]
    pub const fn new(id: EnvironmentId, kind: EnvironmentKind) -> Self {
        Self {
            id,
            kind,
            group: None,
        }
    }

    /// Puts this environment in a logical group, which grants it nothing.
    #[must_use]
    pub fn in_group(mut self, group: MachineGroup) -> Self {
        self.group = Some(group);
        self
    }

    /// Returns the environment's identifier.
    #[must_use]
    pub const fn id(&self) -> &EnvironmentId {
        &self.id
    }

    /// Returns the environment's kind.
    #[must_use]
    pub const fn kind(&self) -> EnvironmentKind {
        self.kind
    }

    /// Returns the logical group this environment is shown in, if any.
    #[must_use]
    pub const fn group(&self) -> Option<&MachineGroup> {
        self.group.as_ref()
    }

    /// Returns where this environment's inference may run.
    ///
    /// The choice is only consulted for WSL, and only a choice recorded for *this* environment
    /// counts: a choice made for one distribution says nothing about another.
    #[must_use]
    pub fn placement(&self, choice: Option<&DataAccessChoice>) -> Placement {
        match self.kind {
            EnvironmentKind::Native => Placement::Local,
            EnvironmentKind::Wsl => match choice {
                Some(choice) if choice.environment_id == self.id => Placement::NativeHostBroker,
                _ => Placement::Refused(PlacementRefusal::WslDataAccessNotChosen),
            },
            EnvironmentKind::Mobile => Placement::Refused(PlacementRefusal::MobileRunsNoModel),
        }
    }
}

/// Where an environment's inference runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// In this environment, in its own shared process.
    Local,
    /// In the native host this distribution brokers to.
    NativeHostBroker,
    /// Nowhere. Deterministic metadata titles are what this environment has, and they are enough
    /// to name and order every session.
    Refused(PlacementRefusal),
}

impl Placement {
    /// Returns whether a model may be mapped for this placement.
    #[must_use]
    pub const fn admits_a_model(self) -> bool {
        matches!(self, Self::Local | Self::NativeHostBroker)
    }
}

/// Why an environment runs no model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementRefusal {
    /// A WSL distribution with no explicit local data-access choice recorded.
    WslDataAccessNotChosen,
    /// A mobile device, which never runs a model to label a host session.
    MobileRunsNoModel,
}

impl PlacementRefusal {
    /// Returns the stable reason this refusal is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WslDataAccessNotChosen => "wsl_data_access_not_chosen",
            Self::MobileRunsNoModel => "mobile_runs_no_model",
        }
    }
}

/// The one model an environment has mapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedModel {
    /// The profile that is mapped.
    pub profile_id: String,
    /// The revision of that profile. A result produced under an older revision is late.
    pub revision: ProfileRevision,
    /// When it was mapped.
    pub mapped_at_ms: TimestampMs,
}

/// What replacing a mapping did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remapped {
    /// The mapping that was unloaded first, when there was one.
    pub unloaded: Option<MappedModel>,
    /// The mapping now in force.
    pub mapped: MappedModel,
}

/// The record of which model each environment has mapped.
///
/// Section 22's "one shared inference process and model mapping per execution environment" is this
/// map: one entry per environment, replaced rather than added to, and no session key anywhere, so
/// there is nowhere for a per-session model to be recorded.
///
/// It is a record, not an owner. Replacing an entry returns the entry it replaced so its owner can
/// release the weights, and [`crate::service::DescriptionService::ensure_mapped`] is the caller
/// that does: it unloads its runtime first and maps second.
#[derive(Debug, Default)]
pub struct ModelMapping {
    mapped: BTreeMap<EnvironmentId, MappedModel>,
    unloaded: Vec<MappedModel>,
}

impl ModelMapping {
    /// Builds an empty mapping.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns what is mapped in an environment, if anything.
    #[must_use]
    pub fn mapped(&self, environment_id: &EnvironmentId) -> Option<&MappedModel> {
        self.mapped.get(environment_id)
    }

    /// Returns how many environments have a model mapped.
    #[must_use]
    pub fn mapped_environments(&self) -> usize {
        self.mapped.len()
    }

    /// Records a profile as this environment's mapping, returning whatever it replaced.
    ///
    /// Three things are checked here because this is the boundary a profile crosses to become the
    /// thing a host runs: the environment may run a model at all, the profile lists this target,
    /// and every gate the profile declares has been met on this host. The last is what stops a
    /// caller that obtained a candidate profile some other way from running it without the
    /// platform, resource and quality gates section 22 requires.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::PlacementRefused`] when the environment runs no model,
    /// [`DescribeError::IncompatibleTarget`] when the profile does not list this target, and
    /// [`DescribeError::GatesOutstanding`] when a candidate's gates have not been met.
    pub fn map(
        &mut self,
        environment: &ExecutionEnvironment,
        choice: Option<&DataAccessChoice>,
        profile: &ModelProfile,
        met: &MetGates,
        target: &str,
        now_ms: TimestampMs,
    ) -> Result<Remapped> {
        match environment.placement(choice) {
            Placement::Refused(refusal) => {
                return Err(DescribeError::PlacementRefused {
                    environment: environment.kind().as_str(),
                    reason: refusal.as_str(),
                });
            }
            Placement::Local | Placement::NativeHostBroker => {}
        }
        if !profile.supports_target(target) {
            return Err(DescribeError::IncompatibleTarget {
                profile: profile.profile_id().to_owned(),
                target: target.to_owned(),
            });
        }
        let outstanding = met.outstanding(profile);
        if !outstanding.is_empty() {
            return Err(DescribeError::GatesOutstanding {
                profile: profile.profile_id().to_owned(),
                gates: outstanding
                    .iter()
                    .map(|gate| gate.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        // The previous record comes out before the new one goes in, and it is returned so its
        // owner releases the weights before it loads more. Section 22 states that order, and the
        // order is what keeps the process ceiling a ceiling: two sets of weights resident at once
        // would exceed it for as long as the changeover took.
        let unloaded = self.mapped.remove(environment.id());
        if let Some(previous) = unloaded.clone() {
            self.unloaded.push(previous);
        }
        let mapped = MappedModel {
            profile_id: profile.profile_id().to_owned(),
            revision: profile.revision(),
            mapped_at_ms: now_ms,
        };
        self.mapped.insert(*environment.id(), mapped.clone());
        Ok(Remapped { unloaded, mapped })
    }

    /// Unloads whatever an environment has mapped, and returns it.
    pub fn unload(&mut self, environment_id: &EnvironmentId) -> Option<MappedModel> {
        let unloaded = self.mapped.remove(environment_id);
        if let Some(previous) = unloaded.clone() {
            self.unloaded.push(previous);
        }
        unloaded
    }

    /// Returns whether a result produced under a profile revision may still be published.
    ///
    /// A result from a revision this environment no longer has mapped is late: the weights that
    /// produced it are gone, and publishing it would attribute text to a profile this host is not
    /// running.
    #[must_use]
    pub fn accepts_result(
        &self,
        environment_id: &EnvironmentId,
        profile_id: &str,
        revision: ProfileRevision,
    ) -> bool {
        self.mapped
            .get(environment_id)
            .is_some_and(|mapped| mapped.profile_id == profile_id && mapped.revision == revision)
    }

    /// Returns every mapping this environment set has unloaded, oldest first.
    #[must_use]
    pub fn unloaded(&self) -> &[MappedModel] {
        &self.unloaded
    }
}
