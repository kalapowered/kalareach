//! The binder: what the control daemon admitted, held in the broker, and the bindings made from it.
//!
//! Each snapshot of admissions this worker applies is installed here, under the broker's own lock,
//! with every package it admits as this worker read it. A binding is made only from that: the
//! caller names the package by its hash and the frame it decided at, and [`Broker::bind`] looks the
//! package up in what is held, refuses a hash the held snapshot does not admit and a frame that is
//! not the one held, and derives everything else itself: the grants from the installation's
//! effective capabilities, the decoding trust from the admitted connector, the actions from the
//! verified manifest's declarations. Nothing a caller describes is bound.
//!
//! Installing a snapshot also brings every live binding to the state of the release it holds:
//!
//! * **Grants.** A binding on the installed hash takes the installation's effective grants, which
//!   may narrow or widen it; a widening keeps its actions and its fault state. A binding on a
//!   release the snapshot does not admit (an upgrade, a move, a removal left it behind) takes its
//!   release's cap, and is only ever narrowed by it.
//! * **Revocation.** A binding on a release its repository revoked is recorded in the session's
//!   journal once, with the warning a person reads, and the administrator's policy the snapshot
//!   carries applies: warn only, and the binding keeps serving; refuse every rich admission through
//!   it, until the revocation no longer stands or the policy only warns; or end it. Once the
//!   session holds no binding on that package's revoked releases, that is recorded too.
//! * **Endings.** A binding whose package was disabled or removed, or whose revocation ends it,
//!   admits nothing more from that snapshot on and is reported ending. What it admitted before is
//!   carried out, and a request it interpreted is left to settle: the binding closes at the first
//!   snapshot that finds none of those open, and a member that reports an ending binding is asked
//!   again each cadence until it has closed.
//!
//! A running instance that has no binding, and whose program an admitted package now recognises,
//! is bound when the snapshot is installed: an enable after the launch.
//!
//! Forgetting a binding drops it from memory at once and removes its row. A row the store refuses
//! to remove is owed: it is removed with the next binding write that succeeds, or once the fault's
//! recovery finishes, and the next process's open removes any left. A row confers nothing
//! meanwhile: no decision reads a binding row back.

use std::collections::{BTreeMap, BTreeSet};

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::matching::{Candidate, Resolution};
use kr_protocol::admission::{
    AdmittedBuild, AdmittedPackage, FrameId, LiveRelease, ReleaseOrigin, ReleaseState,
    RevocationPolicy,
};
use kr_protocol::attention::AdapterTransition;
use kr_protocol::broker::{BrokerGrant, BrokerGrants, DecodingTrust};
use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId, PluginId};
use kr_protocol::scalars::{Digest256, TimestampMs};

use crate::broker::catalogue::{ReadPackage, capabilities};
use crate::broker::connectors::decoding_trust;
use crate::broker::error::{BrokerError, Result};
use crate::broker::ledger::{BindingRecord, BoundExecutable};
use crate::broker::methods::RegisteredAction;
use crate::broker::{Binding, Broker, BrokerState};

/// The key a release's state is found by: the package, its hash and where it came from.
type ReleaseKey = (PluginId, Digest256, ReleaseOrigin);

/// What one snapshot of admissions admits, held where a binding is made from it.
#[derive(Debug, Default)]
pub(super) struct Admitted {
    /// The frame of the snapshot installed, where one is.
    pub(super) frame: Option<FrameId>,
    /// The administrator's revocation policy the snapshot carries.
    pub(super) policy: Option<RevocationPolicy>,
    /// Every package the snapshot admits that this worker read, by its hash.
    pub(super) packages: BTreeMap<Digest256, (AdmittedPackage, ReadPackage)>,
    /// The state of every release the snapshot covers.
    pub(super) releases: BTreeMap<ReleaseKey, ReleaseState>,
}

impl Admitted {
    /// Returns the admitted package the software development kit's rule selects for a program at
    /// `path`, with no selection made: an exact rule wins over an inferred one, and a conflict
    /// selects nothing.
    fn selected_for(&self, path: &str) -> Option<Digest256> {
        let mut found: Vec<(Candidate, Digest256)> = Vec::new();
        for (digest, (_, read)) in &self.packages {
            let manifest = read.manifest();
            for rule in &manifest.match_rules {
                if rule.executable.matches_path(path) {
                    found.push((
                        Candidate {
                            plugin_id: manifest.plugin_id(),
                            rule_id: rule.id.to_string(),
                            confidence: rule.confidence,
                            distribution_matched: false,
                        },
                        *digest,
                    ));
                }
            }
        }
        let resolution = kr_plugin_sdk::matching::resolve(
            found
                .iter()
                .map(|(candidate, _)| candidate.clone())
                .collect(),
            None,
        );
        match resolution {
            Resolution::Selected(chosen) => found
                .iter()
                .find(|(candidate, _)| candidate.plugin_id == chosen.plugin_id)
                .map(|(_, digest)| *digest),
            Resolution::None | Resolution::Conflict(_) => None,
        }
    }
}

/// One transition of a package's revocation state that this session's journal records, with the
/// words a person reads about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterNotice {
    /// The package.
    pub plugin_id: PluginId,
    /// What changed.
    pub transition: AdapterTransition,
    /// What a person reads.
    pub text: String,
}

/// The program a binding is made for: where it is and the digest its bytes hashed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedExecutable {
    /// Its path, as it was matched.
    pub path: String,
    /// The digest of its bytes.
    pub digest: Digest256,
}

/// The admitted package a program at one path is recognised as, and the frame that says so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedMatch {
    /// The frame of the snapshot that admits it.
    pub frame: FrameId,
    /// The package's hash.
    pub package_digest: Digest256,
    /// The package.
    pub plugin_id: PluginId,
    /// The builds its signed records name for this host.
    pub builds: Vec<AdmittedBuild>,
}

impl AdmittedMatch {
    /// Returns the version the signed records name for an executable of `digest`, where one does.
    #[must_use]
    pub fn version_of(&self, digest: &Digest256) -> Option<&str> {
        self.builds
            .iter()
            .find(|build| &build.executable_digest == digest)
            .map(|build| build.version.as_str())
    }
}

/// The broker grants a set of effective capabilities gives a binding: observation from any
/// capability that observes, upstream action from `upstream.action`, and the approval interpreter
/// from `approval.decode`. `approval.respond` is the decoding trust's to carry, beside
/// `approval.decode` only.
#[must_use]
pub fn broker_grants(granted: &BTreeSet<PluginCapability>) -> BrokerGrants {
    let observes = [
        PluginCapability::BrokerSemanticEvents,
        PluginCapability::TerminalStream,
        PluginCapability::TranscriptTail,
        PluginCapability::ProcessObserve,
    ]
    .iter()
    .any(|capability| granted.contains(capability));
    let mut grants = Vec::new();
    if observes {
        grants.push(BrokerGrant::Observation);
    }
    if granted.contains(&PluginCapability::UpstreamAction) {
        grants.push(BrokerGrant::UpstreamAction);
    }
    if granted.contains(&PluginCapability::ApprovalDecode) {
        grants.push(BrokerGrant::ApprovalInterpreter);
    }
    BrokerGrants::granted(grants)
}

/// The grants and trust an admitted package gives a binding now.
fn derived(read: &ReadPackage, granted: &BTreeSet<PluginCapability>, now: TimestampMs) -> Derived {
    Derived {
        grants: broker_grants(granted),
        trust: match read {
            ReadPackage::Connector(connector) => decoding_trust(connector, now),
            ReadPackage::Declarative(_) => None,
        },
    }
}

/// A binding's grants and decoding trust.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Derived {
    grants: BrokerGrants,
    trust: Option<DecodingTrust>,
}

impl Binding {
    /// Returns this binding's record as the ledger holds it, with `bound_at` as the time.
    pub(super) fn record(&self, bound_at: TimestampMs) -> BindingRecord {
        BindingRecord {
            binding_id: self.binding_id,
            application_instance_id: self.application_instance_id,
            grants: self.grants.clone(),
            trust: self.trust.clone(),
            bound_at,
            release: self.release.clone(),
            frame: self.frame,
            executable: self.executable.clone(),
            connector_digest: self.connector_digest,
        }
    }
}

impl Broker {
    /// Installs one applied snapshot of admissions, and brings every live binding to the state of
    /// the release it holds.
    ///
    /// `packages` are the packages the snapshot admits as this worker read them. Called with every
    /// snapshot this worker applies, in the order it applies them, and never with an older one.
    pub fn install_admissions(
        &self,
        frame: FrameId,
        policy: RevocationPolicy,
        packages: Vec<(AdmittedPackage, ReadPackage)>,
        releases: Vec<ReleaseState>,
        now: TimestampMs,
    ) {
        {
            let mut state = self.state();
            state.admitted = Admitted {
                frame: Some(frame),
                policy: Some(policy),
                packages: packages
                    .into_iter()
                    .map(|(package, read)| (package.package_digest, (package, read)))
                    .collect(),
                releases: releases
                    .into_iter()
                    .map(|state| {
                        (
                            (
                                state.plugin_id.clone(),
                                state.package_digest,
                                state.origin.clone(),
                            ),
                            state,
                        )
                    })
                    .collect(),
            };
            state.reinstall(now);
        }
        self.notices_ready.notify_one();
    }

    /// Returns the frame of the admissions this worker holds, where it holds any.
    #[must_use]
    pub fn admissions_frame(&self) -> Option<FrameId> {
        self.state().admitted.frame
    }

    /// Returns true while the admissions held admit any package: what an adoption could bind.
    #[must_use]
    pub fn admits_any(&self) -> bool {
        !self.state().admitted.packages.is_empty()
    }

    /// Returns the admitted package the software development kit's rule selects for a program at
    /// `path`, and the frame that admits it: an exact rule beats an inferred one, and two packages
    /// that both recognise it exactly select none.
    #[must_use]
    pub fn admitted_match(&self, path: &str) -> Option<AdmittedMatch> {
        let state = self.state();
        let frame = state.admitted.frame?;
        let digest = state.admitted.selected_for(path)?;
        let (package, _) = state.admitted.packages.get(&digest)?;
        Some(AdmittedMatch {
            frame,
            package_digest: digest,
            plugin_id: package.plugin_id.clone(),
            builds: package.builds.clone(),
        })
    }

    /// Binds the admitted package of hash `package_digest` to one registered instance, for the
    /// program `executable`, at the frame the caller decided at.
    ///
    /// The package is the one the admissions this worker holds admit, read and checked by this
    /// worker, never a caller's description of it. The grants are the installation's effective
    /// capabilities as the plugin runtime maps them, the trust is the admitted connector's, and the
    /// actions are the verified manifest's declarations; the version is the one the signed record
    /// for the executable's digest names now, and stays the binding's whatever later records say.
    /// The record is written before the binding is live, so a write that fails leaves no binding.
    /// Returns the declarations that could not be registered, by name.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PreconditionFailed`] when the admissions held are not at `frame`,
    /// [`BrokerError::PermissionDenied`] when they do not admit `package_digest`,
    /// [`BrokerError::UnknownSubject`] when the instance is not registered,
    /// [`BrokerError::InvalidArgument`] when the identifier is bound to another package,
    /// [`BrokerError::StoreFault`] when the store fails under the record's write, and
    /// [`BrokerError::LedgerUnavailable`] while the journal is faulted.
    pub fn bind(
        &self,
        binding_id: BrokerBindingId,
        application_instance_id: ApplicationInstanceId,
        package_digest: Digest256,
        frame: FrameId,
        executable: MatchedExecutable,
        now: TimestampMs,
    ) -> Result<Vec<BrokerError>> {
        self.state().bind_admitted(
            binding_id,
            application_instance_id,
            package_digest,
            frame,
            executable,
            now,
        )
    }

    /// Derives one live binding again as [`Self::bind`] derives it, for an installation whose
    /// effective grants widened, keeping its actions, its fault state and the version it was bound
    /// with. Only a binding on the package the admissions held admit is widened; one on a release
    /// they do not admit is left as it is.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PreconditionFailed`] when the admissions held are not at `frame`,
    /// [`BrokerError::UnknownSubject`] when this broker holds no such binding,
    /// [`BrokerError::PermissionDenied`] when the release it holds is not admitted,
    /// [`BrokerError::StoreFault`] when the store fails under the record's write, and
    /// [`BrokerError::LedgerUnavailable`] while the journal is faulted.
    pub fn regrant(
        &self,
        binding_id: BrokerBindingId,
        frame: FrameId,
        now: TimestampMs,
    ) -> Result<()> {
        self.state().regrant_in(binding_id, frame, now)
    }

    /// Takes the adapter notices waiting to be written to the session's journal, oldest first.
    #[must_use]
    pub fn take_notices(&self) -> Vec<AdapterNotice> {
        std::mem::take(&mut self.state().notices)
    }

    /// Waits until an adapter notice may be waiting.
    pub async fn notices_waiting(&self) {
        self.notices_ready.notified().await;
    }

    /// Returns why each admitted package's declared actions could not be registered, by package
    /// hash, for the report the control daemon's doctor reads.
    #[must_use]
    pub fn action_refusals(&self) -> BTreeMap<Digest256, Vec<String>> {
        self.state().action_refusals.clone()
    }

    /// Returns the bindings whose rows this broker still owes the ledger, for this host's own
    /// tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn owed_rows(&self) -> BTreeSet<BrokerBindingId> {
        self.state().owed_rows.clone()
    }
}

impl BrokerState {
    /// Refuses a frame that is not the one the admissions held are at.
    fn check_frame(&self, frame: FrameId) -> Result<()> {
        match self.admitted.frame {
            Some(held) if held == frame => Ok(()),
            Some(held) => Err(BrokerError::PreconditionFailed {
                detail: format!(
                    "the admissions this worker holds are at round {} of revision {}, not the \
                     frame the binding was decided at",
                    held.round, held.revision
                ),
            }),
            None => Err(BrokerError::PreconditionFailed {
                detail: "this worker holds no admissions yet".to_owned(),
            }),
        }
    }

    /// Returns the admitted package a binding's release is, where the admissions held admit it:
    /// the installed hash from the same origin.
    fn admitted_for(&self, binding: &Binding) -> Option<(AdmittedPackage, ReadPackage)> {
        let release = binding.release.as_ref()?;
        let (package, read) = self.admitted.packages.get(&release.package_digest)?;
        (package.origin == release.origin && package.plugin_id == release.plugin_id)
            .then(|| (package.clone(), read.clone()))
    }

    /// Makes one binding from the admissions held, under this lock. See [`Broker::bind`].
    fn bind_admitted(
        &mut self,
        binding_id: BrokerBindingId,
        application_instance_id: ApplicationInstanceId,
        package_digest: Digest256,
        frame: FrameId,
        executable: MatchedExecutable,
        now: TimestampMs,
    ) -> Result<Vec<BrokerError>> {
        self.check_frame(frame)?;
        let (package, read) = self
            .admitted
            .packages
            .get(&package_digest)
            .cloned()
            .ok_or_else(|| {
                BrokerError::denied(format!(
                    "the admissions this worker holds do not admit the package {}",
                    kr_plugin_sdk::digest::PayloadDigest::from_bytes(*package_digest.as_bytes())
                ))
            })?;
        if !self.instances.contains_key(&application_instance_id) {
            return Err(BrokerError::unknown(format!(
                "{application_instance_id} is not a registered instance"
            )));
        }
        if let Some(bound) = self.bindings.get(&binding_id)
            && bound.package_digest != package_digest
        {
            return Err(BrokerError::invalid(format!(
                "binding {binding_id} runs another package, and an identifier names one package \
                 for as long as it is bound"
            )));
        }
        let granted = capabilities(&package.grants);
        let Derived { grants, trust } = derived(&read, &granted, now);
        if let Some(trust) = trust.as_ref() {
            trust.validate()?;
        }
        let manifest = read.manifest();
        let version = package
            .builds
            .iter()
            .find(|build| build.executable_digest == executable.digest)
            .map(|build| build.version.clone());
        let binding = Binding {
            binding_id,
            application_instance_id,
            plugin_id: package.plugin_id.clone(),
            publisher_id: package.publisher_id.clone(),
            package_digest,
            grants,
            trust,
            actions: BTreeMap::new(),
            rich_disabled: None,
            release: Some(LiveRelease {
                plugin_id: package.plugin_id.clone(),
                publisher_id: package.publisher_id.clone(),
                version: package.version.clone(),
                package_digest,
                origin: package.origin.clone(),
            }),
            ending: false,
            frame: Some(frame),
            executable: Some(BoundExecutable {
                path: executable.path,
                digest: executable.digest,
                version,
            }),
            connector_digest: manifest
                .payload(kr_plugin_sdk::plugin::PayloadRole::Connector)
                .map(|payload| Digest256::from_bytes(*payload.digest.as_bytes())),
            revocation_disabled: false,
        };
        let record = binding.record(now);
        self.stored(now, "binding a package", |ledger| {
            ledger.put_binding(&record)
        })?;
        let mut binding = binding;
        let mut refused = Vec::new();
        for declaration in &manifest.actions {
            match RegisteredAction::from_declaration(declaration) {
                Ok(action) => {
                    binding.actions.insert(action.name.clone(), action);
                }
                Err(refusal) => refused.push(refusal),
            }
        }
        self.action_refusals.insert(
            package_digest,
            refused.iter().map(ToString::to_string).collect(),
        );
        self.bindings.insert(binding_id, binding);
        self.settle_owed_rows(now);
        Ok(refused)
    }

    /// Derives one binding on the installed hash again from the admissions held, under this lock.
    /// See [`Broker::regrant`].
    fn regrant_in(
        &mut self,
        binding_id: BrokerBindingId,
        frame: FrameId,
        now: TimestampMs,
    ) -> Result<()> {
        self.check_frame(frame)?;
        let binding = self
            .bindings
            .get(&binding_id)
            .ok_or_else(|| BrokerError::unknown(format!("no binding {binding_id}")))?;
        let Some((package, read)) = self.admitted_for(binding) else {
            return Err(BrokerError::denied(format!(
                "binding {binding_id} holds a release the admissions do not admit, and such a \
                 binding is never widened"
            )));
        };
        let granted = capabilities(&package.grants);
        let target = kept_trust(binding, derived(&read, &granted, now));
        self.rederive(binding_id, &target, frame, now)
    }

    /// Brings one binding's grants and trust to `target`, keeping its actions, its fault state and
    /// its version. Nothing changes when they are the ones it holds.
    ///
    /// What the binding loses goes at once, whatever the store says: withdrawn authority does not
    /// wait for a record, and the record is owed until a write succeeds. What it gains is in force
    /// only once its record is written, so a write that fails leaves the binding holding what it
    /// kept, and the next installation of the admissions, or the end of the store's recovery,
    /// tries again.
    fn rederive(
        &mut self,
        binding_id: BrokerBindingId,
        target: &Derived,
        frame: FrameId,
        now: TimestampMs,
    ) -> Result<()> {
        let Some(binding) = self.bindings.get(&binding_id) else {
            return Err(BrokerError::unknown(format!("no binding {binding_id}")));
        };
        if binding.grants == target.grants
            && same_trust(binding.trust.as_ref(), target.trust.as_ref())
        {
            return Ok(());
        }
        if let Some(trust) = target.trust.as_ref() {
            trust.validate()?;
        }
        let kept = kept_within(binding, target);
        if binding.grants != kept.grants || !same_trust(binding.trust.as_ref(), kept.trust.as_ref())
        {
            if let Some(binding) = self.bindings.get_mut(&binding_id) {
                binding.grants = kept.grants;
                binding.trust = kept.trust;
                binding.frame = Some(frame);
            }
            self.owed_rows.insert(binding_id);
        }
        let Some(binding) = self.bindings.get(&binding_id) else {
            return Err(BrokerError::unknown(format!("no binding {binding_id}")));
        };
        let mut changed = binding.clone();
        changed.grants = target.grants.clone();
        changed.trust = target.trust.clone();
        changed.frame = Some(frame);
        let record = changed.record(TimestampMs::new(0));
        self.stored(now, "changing a binding's grants", |ledger| {
            ledger.put_binding(&record)
        })?;
        if let Some(binding) = self.bindings.get_mut(&binding_id) {
            binding.grants = changed.grants;
            binding.trust = changed.trust;
            binding.frame = changed.frame;
        }
        self.owed_rows.remove(&binding_id);
        self.settle_owed_rows(now);
        Ok(())
    }

    /// Brings every live binding to the admissions held, as installing them does: after a
    /// snapshot, and when the store's recovery finishes, since a change a write could not record
    /// is owed until then.
    pub(super) fn reinstall(&mut self, now: TimestampMs) {
        self.apply_release_states(now);
        self.close_ended(now);
        self.bind_the_unbound(now);
    }

    /// Brings every live binding made from admissions to the state of the release it holds.
    fn apply_release_states(&mut self, now: TimestampMs) {
        let Some(frame) = self.admitted.frame else {
            return;
        };
        let policy = self.admitted.policy.unwrap_or(RevocationPolicy::WarnOnly);
        let live: Vec<BrokerBindingId> = self
            .bindings
            .values()
            .filter(|binding| binding.release.is_some())
            .map(|binding| binding.binding_id)
            .collect();
        for binding_id in live {
            let Some(binding) = self.bindings.get(&binding_id) else {
                continue;
            };
            let Some(release) = binding.release.clone() else {
                continue;
            };
            let key = (
                release.plugin_id.clone(),
                release.package_digest,
                release.origin.clone(),
            );
            // A release the frame did not cover is left as it is: the next round covers it.
            let Some(state) = self.admitted.releases.get(&key).cloned() else {
                continue;
            };
            // The installed hash takes the installation's effective grants, narrowing or
            // widening; any other release takes its cap, and only narrows. A write that fails
            // raises the fence, which refuses the binding's rich work until the recovery; the
            // narrowing is in force meanwhile, and the recovery's end records it and tries the
            // widening again.
            let _ = match self.admitted_for(binding) {
                Some(_) => self.regrant_in(binding_id, frame, now),
                None => {
                    let target = narrowed(binding, &capabilities(&state.grant_cap));
                    self.rederive(binding_id, &target, frame, now)
                }
            };
            self.apply_revocation(binding_id, &state, policy);
            if state.ends_at_next_boundary {
                self.end_at_next_boundary(
                    binding_id,
                    "its package is no longer admitted to this environment: it was disabled or \
                     removed, or the organisation's allowlist no longer names it",
                );
            }
        }
    }

    /// Applies a release's revocation, or its absence, to one binding on it.
    fn apply_revocation(
        &mut self,
        binding_id: BrokerBindingId,
        state: &ReleaseState,
        policy: RevocationPolicy,
    ) {
        let Some(binding) = self.bindings.get(&binding_id) else {
            return;
        };
        let plugin_id = binding.plugin_id.clone();
        let version = binding
            .release
            .as_ref()
            .map_or_else(String::new, |release| release.version.clone());
        let Some(revocation) = state.revocation.0.as_ref() else {
            // A revocation that no longer stands lifts what it did, and nothing a fault did.
            self.lift_revocation(binding_id);
            self.revoked_settled(&plugin_id, binding_id);
            return;
        };
        let reason = format!(
            "{plugin_id} {version} was revoked by its repository ({}): {}",
            revocation.reason, revocation.statement
        );
        match policy {
            // Under the policy that only warns the binding keeps serving, whatever an earlier
            // policy did to it.
            RevocationPolicy::WarnOnly => self.lift_revocation(binding_id),
            RevocationPolicy::DisableAtNextAdmission => {
                if let Some(binding) = self.bindings.get_mut(&binding_id)
                    && binding.rich_disabled.is_none()
                {
                    binding.rich_disabled = Some(reason.clone());
                    binding.revocation_disabled = true;
                }
            }
            RevocationPolicy::DisableAtOnce => {
                self.end_at_next_boundary(binding_id, &reason);
            }
        }
        let noticed = self.revoked.entry(plugin_id.clone()).or_default();
        if noticed.insert(binding_id) {
            self.notices.push(AdapterNotice {
                plugin_id,
                transition: AdapterTransition::Revoked,
                text: reason,
            });
        }
    }

    /// Lifts what a revocation disabled on one binding, and nothing a fault did.
    fn lift_revocation(&mut self, binding_id: BrokerBindingId) {
        if let Some(binding) = self.bindings.get_mut(&binding_id)
            && binding.revocation_disabled
        {
            binding.revocation_disabled = false;
            binding.rich_disabled = None;
        }
    }

    /// Marks one binding to end at its next admission boundary: it admits nothing more from here,
    /// and it is reported ending until it closes.
    fn end_at_next_boundary(&mut self, binding_id: BrokerBindingId, why: &str) {
        if let Some(binding) = self.bindings.get_mut(&binding_id) {
            binding.ending = true;
            if binding.rich_disabled.is_none() || binding.revocation_disabled {
                binding.rich_disabled = Some(format!("this binding is ending: {why}"));
                binding.revocation_disabled = false;
            }
        }
    }

    /// Closes every binding due to end that has no request it admitted still open.
    fn close_ended(&mut self, now: TimestampMs) {
        let closing: Vec<BrokerBindingId> = self
            .bindings
            .values()
            .filter(|binding| binding.ending && !self.admitted_open(binding.binding_id))
            .map(|binding| binding.binding_id)
            .collect();
        self.forget(closing, now);
    }

    /// Returns true while a request one binding admitted is still open: a resource its decoder
    /// interpreted that is not settled.
    fn admitted_open(&self, binding_id: BrokerBindingId) -> bool {
        self.arbitration.iter().any(|pending| {
            pending.decoder == Some(binding_id) && !pending.resource.state.is_terminal()
        })
    }

    /// Binds each registered instance that has no binding to the admitted package that now
    /// recognises its program, where exactly one does.
    fn bind_the_unbound(&mut self, now: TimestampMs) {
        let Some(frame) = self.admitted.frame else {
            return;
        };
        let bound: BTreeSet<ApplicationInstanceId> = self
            .bindings
            .values()
            .map(|binding| binding.application_instance_id)
            .collect();
        let unbound: Vec<(ApplicationInstanceId, MatchedExecutable)> = self
            .instances
            .keys()
            // An instance a launch still holds is bound by that launch, at its admission.
            .filter(|id| !bound.contains(id) && !self.launches.contains_key(id))
            .filter_map(|id| {
                let profile = self.profiles.profile_of(*id)?;
                Some((
                    *id,
                    MatchedExecutable {
                        path: profile.binary.resolved_path.clone(),
                        digest: profile.binary.digest,
                    },
                ))
            })
            .collect();
        for (application_instance_id, executable) in unbound {
            let Some(digest) = self.admitted.selected_for(&executable.path) else {
                continue;
            };
            let binding_id = BrokerBindingId::new(kr_ipc::new_uuid());
            // A bind refused here is tried again with the next snapshot.
            let _ = self.bind_admitted(
                binding_id,
                application_instance_id,
                digest,
                frame,
                executable,
                now,
            );
        }
    }

    /// Forgets bindings: they go from memory at once, and their rows go now, or are owed.
    pub(super) fn forget(&mut self, bindings: Vec<BrokerBindingId>, now: TimestampMs) {
        for binding_id in bindings {
            if let Some(binding) = self.bindings.remove(&binding_id) {
                self.owed_rows.insert(binding_id);
                self.revoked_settled(&binding.plugin_id, binding_id);
            }
        }
        self.settle_owed_rows(now);
    }

    /// Forgets every binding of one instance.
    pub(super) fn forget_instance(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        now: TimestampMs,
    ) {
        let bindings: Vec<BrokerBindingId> = self
            .bindings
            .values()
            .filter(|binding| binding.application_instance_id == application_instance_id)
            .map(|binding| binding.binding_id)
            .collect();
        self.forget(bindings, now);
    }

    /// Writes the rows the store owes, while it takes writes: a live binding's record as it now
    /// stands, and the removal of a forgotten binding's.
    pub(super) fn settle_owed_rows(&mut self, now: TimestampMs) {
        if !self.volatile.writes_are_durable() {
            return;
        }
        let owed: Vec<BrokerBindingId> = self.owed_rows.iter().copied().collect();
        for binding_id in owed {
            let written = match self.bindings.get(&binding_id) {
                Some(binding) => {
                    let record = binding.record(TimestampMs::new(0));
                    self.stored(now, "writing a binding's record", |ledger| {
                        ledger.put_binding(&record)
                    })
                }
                None => self.stored(now, "removing a binding's record", |ledger| {
                    ledger.remove_binding(binding_id)
                }),
            };
            if written.is_err() {
                return;
            }
            self.owed_rows.remove(&binding_id);
        }
    }

    /// Records that one binding no longer holds a revoked release of `plugin_id`, and that the
    /// session holds none any more where it was the last.
    fn revoked_settled(&mut self, plugin_id: &PluginId, binding_id: BrokerBindingId) {
        let Some(noticed) = self.revoked.get_mut(plugin_id) else {
            return;
        };
        if !noticed.remove(&binding_id) || !noticed.is_empty() {
            return;
        }
        self.revoked.remove(plugin_id);
        self.notices.push(AdapterNotice {
            plugin_id: plugin_id.clone(),
            transition: AdapterTransition::Cleared,
            text: format!(
                "this session holds no binding on a revoked release of {plugin_id} any more"
            ),
        });
    }
}

/// The admitted grants and trust for a binding on the installed hash, keeping the trust record the
/// binding holds where only its answer right moved: a record is granted once, and its time with it.
fn kept_trust(binding: &Binding, admitted: Derived) -> Derived {
    let trust = match (binding.trust.as_ref(), admitted.trust) {
        (Some(held), Some(now)) => Some(DecodingTrust {
            may_encode_response: now.may_encode_response,
            ..held.clone()
        }),
        (_, now) => now,
    };
    Derived {
        grants: admitted.grants,
        trust,
    }
}

/// What a binding keeps of what it holds when its grants and trust become `target`: never more
/// than either.
fn kept_within(binding: &Binding, target: &Derived) -> Derived {
    let grants = BrokerGrants::granted(
        binding
            .grants
            .iter()
            .filter(|grant| target.grants.holds(*grant)),
    );
    let trust = match (binding.trust.as_ref(), target.trust.as_ref()) {
        (Some(held), Some(target)) if grants.holds(BrokerGrant::ApprovalInterpreter) => {
            Some(DecodingTrust {
                may_encode_response: held.may_encode_response && target.may_encode_response,
                ..held.clone()
            })
        }
        _ => None,
    };
    Derived { grants, trust }
}

/// A binding on a release the admissions do not admit, narrowed by that release's cap: never
/// widened.
fn narrowed(binding: &Binding, cap: &BTreeSet<PluginCapability>) -> Derived {
    let allowed = broker_grants(cap);
    let grants = BrokerGrants::granted(binding.grants.iter().filter(|grant| allowed.holds(*grant)));
    let trust = if cap.contains(&PluginCapability::ApprovalDecode)
        && grants.holds(BrokerGrant::ApprovalInterpreter)
    {
        binding.trust.clone().map(|trust| DecodingTrust {
            may_encode_response: trust.may_encode_response
                && cap.contains(&PluginCapability::ApprovalRespond),
            ..trust
        })
    } else {
        None
    };
    Derived { grants, trust }
}

/// Returns true when two trust records grant the same, whenever each was granted.
fn same_trust(held: Option<&DecodingTrust>, other: Option<&DecodingTrust>) -> bool {
    match (held, other) {
        (None, None) => true,
        (Some(held), Some(other)) => {
            DecodingTrust {
                granted_at: other.granted_at,
                ..held.clone()
            } == *other
        }
        _ => false,
    }
}
