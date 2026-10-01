//! What the workers hold live, as the catalogue's reclaim asks it: the production broker bridge.
//!
//! The catalogue asks this synchronously, inside its own transaction, which release each worker
//! reported holding and which workers have not yet said so at the admission revision it runs at.
//! The registry sits behind the daemon's asynchronous lock, so the bridge keeps a member set of its
//! own: every reservation whose claim was consumed and every registered worker, each with the
//! process identity the kernel can be asked about.
//!
//! A member is reconciled at a revision when its accepted report names a frame this daemon
//! generation sent it at that revision and lists no release the frame did not cover. Anything else
//! is pending, and pending is what protects: a reclaim that needs room waits while a member is
//! pending, because that member may hold a release nothing here describes. A member leaves only when
//! its worker is known to have ended, never on a timer.
//!
//! Answers are used in the order the worker made them. Each member keeps at most
//! [`KEPT_FRAMES`] records of the frames this generation sent it, and an answer is used only when
//! its report number is above the accepted report's and it names a kept frame, so a delayed answer
//! can neither restore a release that closed nor undo a reconciliation.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

use kr_plugin_catalogue::broker::{EvidenceRequest, ProxyAdmission, ProxyRequest};
use kr_plugin_catalogue::{BrokerBridge, CatalogueError, CatalogueResult, LivePackages};
use kr_plugin_sdk::capability::CapabilityEvidence;
use kr_protocol::admission::{FrameId, LiveBinding, LiveRelease, PackageRefusal, ReleaseOrigin};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ControllerGeneration, PluginId, SessionId};
use kr_protocol::scalars::{Digest256, U64};

/// How many records of the frames sent to one member the bridge keeps.
pub const KEPT_FRAMES: usize = 4;

/// The key a release's state is found by: the package, its hash and where it came from.
pub type ReleaseKey = (PluginId, Digest256, ReleaseOrigin);

/// Returns the key of a live release.
#[must_use]
pub fn key_of(release: &LiveRelease) -> ReleaseKey {
    (
        release.plugin_id.clone(),
        release.package_digest,
        release.origin.clone(),
    )
}

/// What `plugin.list` reads beside the catalogue's records: what the workers reported, as it
/// counts it, and the admissions in force.
#[derive(Clone, Debug, Default)]
pub struct LiveView {
    /// The admission revision the counts were read at; counts read at another revision than the
    /// one the answer renders are not given.
    pub revision: u64,
    /// Every release a worker's accepted report lists, with whether it is ending there.
    pub live: BTreeMap<ReleaseKey, (LiveRelease, bool)>,
    /// The counts from reports every worker made after the read began, where every worker did.
    pub counts: Option<BTreeMap<ReleaseKey, (LiveRelease, u64, bool)>>,
    /// The admissions in force, where they could be computed; an answer that renders another
    /// revision than theirs says nothing about any installation's admission.
    pub admissions: Option<super::admissions::Snapshot>,
}

/// Where a member stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Its reservation's claim was consumed, and its worker is not recorded yet.
    Claimed,
    /// Its worker is recorded, and is sent rounds.
    Recorded,
    /// The host stopped trusting it. It is never sent a round and stays pending until the kernel
    /// says its process ended.
    Fenced,
    /// Its session closed without a confirmed end of its worker. It stays pending until the
    /// kernel says the process ended.
    Closed,
}

/// One complete report of a worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The frame the worker holds.
    pub frame: FrameId,
    /// The report's number.
    pub report_seq: u64,
    /// Every live binding.
    pub bindings: Vec<LiveBinding>,
    /// Every package the worker would not read or bind, or would use only in part.
    pub refusals: Vec<PackageRefusal>,
}

impl Report {
    /// Returns every release the report lists live.
    #[must_use]
    pub fn releases(&self) -> BTreeSet<ReleaseKey> {
        self.bindings
            .iter()
            .map(|binding| key_of(&binding.release))
            .collect()
    }
}

/// What using an answer did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acceptance {
    /// Nothing: an older report, one naming a frame not kept, or a member not sent rounds.
    Ignored,
    /// Used, and the member is reconciled at the frame's revision.
    Reconciled,
    /// Used, and it lists a release the frame did not cover: the member is sent the next round.
    Discovered,
}

#[derive(Debug)]
struct SentFrame {
    frame: FrameId,
    covered: BTreeSet<ReleaseKey>,
}

#[derive(Debug)]
struct Accepted {
    report: Report,
    reconciled_at: Option<u64>,
    used: u64,
}

#[derive(Debug)]
struct Member {
    standing: Standing,
    process: Option<ProcessStartIdentity>,
    next_round: u64,
    sent: VecDeque<SentFrame>,
    accepted: Option<Accepted>,
    in_flight: bool,
}

impl Member {
    fn new(standing: Standing, process: Option<ProcessStartIdentity>) -> Self {
        Self {
            standing,
            process,
            next_round: 1,
            sent: VecDeque::new(),
            accepted: None,
            in_flight: false,
        }
    }

    fn reconciled(&self, revision: u64) -> bool {
        self.standing == Standing::Recorded
            && self
                .accepted
                .as_ref()
                .is_some_and(|accepted| accepted.reconciled_at == Some(revision))
    }
}

#[derive(Debug, Default)]
struct Members {
    members: BTreeMap<SessionId, Member>,
    uses: u64,
}

/// The production broker bridge.
#[derive(Debug)]
pub struct WorkerBridge {
    generation: ControllerGeneration,
    members: Mutex<Members>,
    /// How many times a pass of the admissions cadence was asked for ahead of its tick, for this
    /// host's own tests. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    passes_asked: std::sync::atomic::AtomicU64,
}

impl WorkerBridge {
    /// A bridge with no members, for the daemon generation `generation`.
    #[must_use]
    pub fn new(generation: ControllerGeneration) -> Self {
        Self {
            generation,
            members: Mutex::new(Members::default()),
            #[cfg(feature = "testing")]
            passes_asked: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Notes that a pass of the admissions cadence was asked for ahead of its tick.
    #[cfg(feature = "testing")]
    pub(crate) fn pass_asked(&self) {
        self.passes_asked
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Returns how many times a pass of the admissions cadence was asked for ahead of its tick,
    /// for this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn passes_asked(&self) -> u64 {
        self.passes_asked.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn members(&self) -> std::sync::MutexGuard<'_, Members> {
        self.members
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Adds a member whose reservation's claim was consumed, or leaves an existing one as it is.
    pub fn claimed(&self, session_id: SessionId, process: Option<ProcessStartIdentity>) {
        self.members()
            .members
            .entry(session_id)
            .or_insert_with(|| Member::new(Standing::Claimed, process));
    }

    /// Records that a member's worker is registered, adding it where it was not a member.
    ///
    /// A fenced or closed member stays as it is: the host stopped trusting that worker, or its
    /// session closed, and recording it again would restore rounds to it.
    pub fn recorded(&self, session_id: SessionId, process: ProcessStartIdentity) {
        let mut members = self.members();
        let member = members
            .members
            .entry(session_id)
            .or_insert_with(|| Member::new(Standing::Claimed, None));
        if member.standing == Standing::Claimed {
            member.standing = Standing::Recorded;
            member.process = Some(process);
        }
    }

    /// Records that the host stopped trusting a member: it is never sent another round, and stays
    /// pending until its process is known to have ended.
    pub fn fenced(&self, session_id: SessionId) {
        if let Some(member) = self.members().members.get_mut(&session_id) {
            member.standing = Standing::Fenced;
        }
    }

    /// Records a member's session closed: gone at once where the end of its worker is confirmed,
    /// and otherwise kept, pending, until its process is known to have ended.
    pub fn closed(&self, session_id: SessionId, confirmed_ended: bool) {
        let mut members = self.members();
        if confirmed_ended {
            members.members.remove(&session_id);
        } else if let Some(member) = members.members.get_mut(&session_id) {
            member.standing = Standing::Closed;
        }
    }

    /// Records that a member's worker ended, which takes it out of the set.
    pub fn ended(&self, session_id: SessionId) {
        self.members().members.remove(&session_id);
    }

    /// Returns every member the kernel has to be asked about: the fenced and the closed ones, each
    /// with the process identity it was known by.
    #[must_use]
    pub fn to_check(&self) -> Vec<(SessionId, Option<ProcessStartIdentity>)> {
        self.members()
            .members
            .iter()
            .filter(|(_, member)| matches!(member.standing, Standing::Fenced | Standing::Closed))
            .map(|(session_id, member)| (*session_id, member.process.clone()))
            .collect()
    }

    /// Returns every member that is sent rounds.
    #[must_use]
    pub fn recorded_members(&self) -> Vec<SessionId> {
        self.members()
            .members
            .iter()
            .filter(|(_, member)| member.standing == Standing::Recorded)
            .map(|(session_id, _)| *session_id)
            .collect()
    }

    /// Returns true when this is a member.
    #[must_use]
    pub fn holds(&self, session_id: SessionId) -> bool {
        self.members().members.contains_key(&session_id)
    }

    /// Takes the next frame for a recorded member at `revision`, keeping its record with the
    /// releases the frame covers, and marks a round in flight: the round that takes it owns it
    /// until its answer is used or it ends without one. `None` for a member not sent rounds, and
    /// for one with a round already in flight, so two rounds never retire each other's records.
    ///
    /// A fifth record retires the oldest, so a member that never answers costs a bounded record.
    pub fn next_frame(
        &self,
        session_id: SessionId,
        revision: u64,
        covered: BTreeSet<ReleaseKey>,
    ) -> Option<FrameId> {
        let mut members = self.members();
        let member = members.members.get_mut(&session_id)?;
        if member.standing != Standing::Recorded || member.in_flight {
            return None;
        }
        let frame = FrameId {
            generation: self.generation,
            revision: U64::new(revision),
            round: U64::new(member.next_round),
        };
        member.next_round = member.next_round.saturating_add(1);
        member.sent.push_back(SentFrame { frame, covered });
        while member.sent.len() > KEPT_FRAMES {
            member.sent.pop_front();
        }
        member.in_flight = true;
        Some(frame)
    }

    /// Takes the frame of a worker's first snapshot, which travels with its specification before
    /// the worker is recorded: the member is claimed, and nothing answers this frame.
    #[must_use]
    pub fn first_frame(
        &self,
        session_id: SessionId,
        revision: u64,
        covered: BTreeSet<ReleaseKey>,
    ) -> FrameId {
        let mut members = self.members();
        let member = members
            .members
            .entry(session_id)
            .or_insert_with(|| Member::new(Standing::Claimed, None));
        let frame = FrameId {
            generation: self.generation,
            revision: U64::new(revision),
            round: U64::new(member.next_round),
        };
        member.next_round = member.next_round.saturating_add(1);
        member.sent.push_back(SentFrame { frame, covered });
        while member.sent.len() > KEPT_FRAMES {
            member.sent.pop_front();
        }
        frame
    }

    /// Records that a member's round ended without an answer.
    pub fn unanswered(&self, session_id: SessionId) {
        if let Some(member) = self.members().members.get_mut(&session_id) {
            member.in_flight = false;
        }
    }

    /// Returns true while a round to this member is in flight.
    #[must_use]
    pub fn in_flight(&self, session_id: SessionId) -> bool {
        self.members()
            .members
            .get(&session_id)
            .is_some_and(|member| member.in_flight)
    }

    /// Uses a worker's complete report, where it is newer than the accepted one and names a frame
    /// this generation sent the member and still keeps a record of.
    pub fn accept(&self, session_id: SessionId, report: Report) -> Acceptance {
        let mut members = self.members();
        let uses = members.uses.saturating_add(1);
        let Some(member) = members.members.get_mut(&session_id) else {
            return Acceptance::Ignored;
        };
        member.in_flight = false;
        if member.standing != Standing::Recorded {
            return Acceptance::Ignored;
        }
        if member
            .accepted
            .as_ref()
            .is_some_and(|accepted| report.report_seq <= accepted.report.report_seq)
        {
            return Acceptance::Ignored;
        }
        let Some(sent) = member.sent.iter().find(|sent| sent.frame == report.frame) else {
            return Acceptance::Ignored;
        };
        let covered = report.releases().is_subset(&sent.covered);
        let reconciled_at = covered.then(|| sent.frame.revision.get());
        member.accepted = Some(Accepted {
            report,
            reconciled_at,
            used: uses,
        });
        members.uses = uses;
        if covered {
            Acceptance::Reconciled
        } else {
            Acceptance::Discovered
        }
    }

    /// Returns true when the member is reconciled at `revision`.
    #[must_use]
    pub fn reconciled(&self, session_id: SessionId, revision: u64) -> bool {
        self.members()
            .members
            .get(&session_id)
            .is_some_and(|member| member.reconciled(revision))
    }

    /// Returns true when a recorded member needs a round at `revision`: it is not reconciled there,
    /// or its accepted report lists a release `described` does not describe, or a binding due to
    /// end, which closes only at a snapshot that follows the settlement of its requests.
    #[must_use]
    pub fn needs_round(
        &self,
        session_id: SessionId,
        revision: u64,
        described: &dyn Fn(&ReleaseKey) -> bool,
    ) -> bool {
        let members = self.members();
        let Some(member) = members.members.get(&session_id) else {
            return false;
        };
        if member.standing != Standing::Recorded {
            return false;
        }
        if !member.reconciled(revision) {
            return true;
        }
        member.accepted.as_ref().is_some_and(|accepted| {
            accepted
                .report
                .bindings
                .iter()
                .any(|binding| binding.ending || !described(&key_of(&binding.release)))
        })
    }

    /// Returns the mark a read counts from: only reports used after it count.
    #[must_use]
    pub fn mark(&self) -> u64 {
        self.members().uses
    }

    /// Returns true when every recorded member's accepted report was used after `mark`.
    #[must_use]
    pub fn answered_since(&self, mark: u64) -> bool {
        self.members()
            .members
            .values()
            .filter(|member| member.standing == Standing::Recorded)
            .all(|member| {
                member
                    .accepted
                    .as_ref()
                    .is_some_and(|accepted| accepted.used > mark)
            })
    }

    /// Counts the live bindings of every release from reports used after `mark`, with whether any
    /// of them is ending; `None` when a member is pending at `revision` or has not reported since.
    #[must_use]
    pub fn counts_since(
        &self,
        mark: u64,
        revision: u64,
    ) -> Option<BTreeMap<ReleaseKey, (LiveRelease, u64, bool)>> {
        let members = self.members();
        let mut counts: BTreeMap<ReleaseKey, (LiveRelease, u64, bool)> = BTreeMap::new();
        for member in members.members.values() {
            if !member.reconciled(revision) {
                return None;
            }
            let accepted = member.accepted.as_ref()?;
            if accepted.used <= mark {
                return None;
            }
            for binding in &accepted.report.bindings {
                let entry = counts
                    .entry(key_of(&binding.release))
                    .or_insert_with(|| (binding.release.clone(), 0, false));
                entry.1 = entry.1.saturating_add(1);
                entry.2 |= binding.ending;
            }
        }
        Some(counts)
    }

    /// Returns every release a member's accepted report lists live, with whether it is ending
    /// there.
    #[must_use]
    pub fn live(&self) -> BTreeMap<ReleaseKey, (LiveRelease, bool)> {
        let mut live: BTreeMap<ReleaseKey, (LiveRelease, bool)> = BTreeMap::new();
        for member in self.members().members.values() {
            let Some(accepted) = member.accepted.as_ref() else {
                continue;
            };
            for binding in &accepted.report.bindings {
                let entry = live
                    .entry(key_of(&binding.release))
                    .or_insert_with(|| (binding.release.clone(), false));
                entry.1 |= binding.ending;
            }
        }
        live
    }

    /// Makes the accepted report of the member for `session_id` list `binding` too, and says
    /// whether the member had one. For this host's own tests, which stand in for a worker whose
    /// answer listed a binding due to end.
    #[cfg(feature = "testing")]
    pub fn list_in_accepted_report(&self, session_id: SessionId, binding: LiveBinding) -> bool {
        let mut members = self.members();
        let Some(accepted) = members
            .members
            .get_mut(&session_id)
            .and_then(|member| member.accepted.as_mut())
        else {
            return false;
        };
        accepted.report.bindings.push(binding);
        true
    }

    /// Returns every package a member's accepted report says it would not read or bind.
    #[must_use]
    pub fn refusals(&self) -> Vec<(SessionId, PackageRefusal)> {
        let mut refusals = Vec::new();
        for (session_id, member) in &self.members().members {
            if let Some(accepted) = member.accepted.as_ref() {
                refusals.extend(
                    accepted
                        .report
                        .refusals
                        .iter()
                        .map(|refusal| (*session_id, refusal.clone())),
                );
            }
        }
        refusals
    }
}

/// Reads a release a worker reported into the catalogue's words, where it can be read.
pub(crate) fn catalogue_release(release: &LiveRelease) -> Option<kr_plugin_catalogue::LiveRelease> {
    Some(kr_plugin_catalogue::LiveRelease {
        plugin_id: release.plugin_id.clone(),
        publisher_id: kr_plugin_sdk::ids::PublisherId::new(release.publisher_id.as_str()).ok()?,
        version: kr_plugin_sdk::version::PackageVersion::parse(&release.version).ok()?,
        package_digest: kr_plugin_sdk::digest::PayloadDigest::from_bytes(
            *release.package_digest.as_bytes(),
        ),
        origin: kr_plugin_catalogue::ReleaseOrigin {
            repository_id: kr_plugin_catalogue::RepositoryId::new(
                release.origin.repository_id.as_str(),
            )
            .ok()?,
            enrolment_key: kr_plugin_catalogue::EnrolmentKey::parse(&release.origin.enrolment_key)
                .ok()?,
        },
    })
}

impl BrokerBridge for WorkerBridge {
    fn live_evidence(&self, _request: &EvidenceRequest) -> Option<CapabilityEvidence> {
        None
    }

    fn admit_proxy(&self, request: &ProxyRequest) -> CatalogueResult<ProxyAdmission> {
        Err(CatalogueError::Disabled {
            detail: format!(
                "{}'s declarative proxy is admitted by the worker's gateway for the instance it \
                 binds, not through the catalogue",
                request.plugin_id
            ),
        })
    }

    fn live_packages(&self, revision: u64) -> LivePackages {
        let members = self.members();
        let mut releases: BTreeMap<ReleaseKey, kr_plugin_catalogue::LiveRelease> = BTreeMap::new();
        let mut pending = Vec::new();
        for (session_id, member) in &members.members {
            if !member.reconciled(revision) {
                pending.push(format!("session {session_id}"));
            }
            let Some(accepted) = member.accepted.as_ref() else {
                continue;
            };
            for binding in &accepted.report.bindings {
                match catalogue_release(&binding.release) {
                    Some(release) => {
                        releases.insert(key_of(&binding.release), release);
                    }
                    // A release this host cannot read back is one it cannot protect by name, so
                    // the member that reported it stays pending rather than being believed.
                    None => pending.push(format!(
                        "session {session_id}, which reported a release this host cannot read"
                    )),
                }
            }
        }
        pending.dedup();
        LivePackages {
            releases: releases.into_values().collect(),
            pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId, PublisherId};
    use kr_protocol::scalars::{Nullable, Uuid};

    fn session(n: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([n; 16]))
    }

    fn process(n: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(
            n,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            n,
        )
    }

    fn release(n: u8) -> LiveRelease {
        LiveRelease {
            plugin_id: PluginId::new("kalareach/example-declarative").expect("an identifier"),
            publisher_id: PublisherId::new("kalareach").expect("a publisher"),
            version: "0.1.0".to_owned(),
            package_digest: Digest256::from_bytes([n; 32]),
            origin: ReleaseOrigin {
                repository_id: "official".to_owned(),
                enrolment_key: "0123456789abcdef0123456789abcdef".to_owned(),
            },
        }
    }

    fn binding(release: LiveRelease, ending: bool) -> LiveBinding {
        LiveBinding {
            binding_id: BrokerBindingId::new(Uuid::NIL),
            application_instance_id: ApplicationInstanceId::new(Uuid::NIL),
            release,
            ending,
            component: Nullable::null(),
        }
    }

    /// A member added when its claim commits is found by a fence that lands before its first
    /// snapshot is made: the first frame leaves it fenced, the kernel is asked about it, it is
    /// never sent a round, and it leaves only when its process has ended.
    #[test]
    fn a_fence_before_the_first_snapshot_keeps_the_member_until_its_end() {
        let bridge = WorkerBridge::new(ControllerGeneration::new(1));
        let member = session(9);
        bridge.claimed(member, Some(process(9)));
        bridge.fenced(member);
        let _ = bridge.first_frame(member, 1, BTreeSet::new());
        bridge.recorded(member, process(9));
        assert!(bridge.holds(member));
        assert!(bridge.recorded_members().is_empty(), "never sent a round");
        assert_eq!(bridge.to_check(), vec![(member, Some(process(9)))]);
        assert!(bridge.next_frame(member, 1, BTreeSet::new()).is_none());
        bridge.ended(member);
        assert!(!bridge.holds(member));
    }

    fn report(frame: FrameId, report_seq: u64, bindings: Vec<LiveBinding>) -> Report {
        Report {
            frame,
            report_seq,
            bindings,
            refusals: Vec::new(),
        }
    }

    fn recorded(bridge: &WorkerBridge, n: u8) -> SessionId {
        let session_id = session(n);
        bridge.claimed(session_id, Some(process(u64::from(n))));
        bridge.recorded(session_id, process(u64::from(n)));
        session_id
    }

    #[test]
    fn a_member_is_pending_until_it_answers_a_frame_of_this_generation_at_the_revision() {
        let bridge = WorkerBridge::new(ControllerGeneration::new(3));
        let member = recorded(&bridge, 1);
        assert_eq!(bridge.live_packages(5).pending.len(), 1);
        let frame = bridge
            .next_frame(member, 5, BTreeSet::new())
            .expect("a recorded member is sent rounds");
        assert_eq!(
            bridge.accept(member, report(frame, 1, Vec::new())),
            Acceptance::Reconciled
        );
        assert!(bridge.live_packages(5).pending.is_empty());
        // A later revision makes it pending again until it answers there.
        assert_eq!(bridge.live_packages(6).pending.len(), 1);
    }

    #[test]
    fn an_older_answer_or_one_naming_a_frame_not_kept_changes_nothing() {
        let bridge = WorkerBridge::new(ControllerGeneration::new(3));
        let member = recorded(&bridge, 1);
        let first = bridge
            .next_frame(member, 5, BTreeSet::new())
            .expect("a frame");
        assert!(
            bridge.next_frame(member, 5, BTreeSet::new()).is_none(),
            "one round at a time: a second is not taken while the first is out"
        );
        bridge.unanswered(member);
        let second = bridge
            .next_frame(member, 5, BTreeSet::new())
            .expect("a frame");
        // The newer answer is used first; the older arrives late and is dropped.
        assert_eq!(
            bridge.accept(member, report(second, 2, Vec::new())),
            Acceptance::Reconciled
        );
        assert_eq!(
            bridge.accept(member, report(first, 1, vec![binding(release(1), false)])),
            Acceptance::Ignored
        );
        assert!(bridge.live().is_empty(), "a closed binding stays closed");
        // A frame of another generation was never sent here.
        let foreign = FrameId {
            generation: ControllerGeneration::new(2),
            ..second
        };
        assert_eq!(
            bridge.accept(member, report(foreign, 9, Vec::new())),
            Acceptance::Ignored
        );
    }

    #[test]
    fn a_member_that_never_answers_keeps_four_frame_records_and_a_late_answer_to_a_retired_one_is_dropped()
     {
        let bridge = WorkerBridge::new(ControllerGeneration::new(3));
        let member = recorded(&bridge, 1);
        let frames: Vec<FrameId> = (0..10)
            .map(|_| {
                let frame = bridge
                    .next_frame(member, 5, BTreeSet::new())
                    .expect("a frame");
                bridge.unanswered(member);
                frame
            })
            .collect();
        assert_eq!(
            bridge.members().members[&member].sent.len(),
            KEPT_FRAMES,
            "the records are bounded"
        );
        assert_eq!(
            bridge.accept(member, report(frames[0], 1, Vec::new())),
            Acceptance::Ignored
        );
        assert_eq!(bridge.live_packages(5).pending.len(), 1);
        assert_eq!(
            bridge.accept(member, report(frames[9], 2, Vec::new())),
            Acceptance::Reconciled
        );
        assert!(bridge.live_packages(5).pending.is_empty());
    }

    #[test]
    fn a_release_the_frame_did_not_cover_is_discovered_and_not_reconciled() {
        let bridge = WorkerBridge::new(ControllerGeneration::new(3));
        let member = recorded(&bridge, 1);
        let frame = bridge
            .next_frame(member, 5, BTreeSet::new())
            .expect("a frame");
        assert_eq!(
            bridge.accept(member, report(frame, 1, vec![binding(release(1), false)])),
            Acceptance::Discovered
        );
        assert_eq!(bridge.live_packages(5).pending.len(), 1);
        let covered: BTreeSet<ReleaseKey> = std::iter::once(key_of(&release(1))).collect();
        let next = bridge.next_frame(member, 5, covered).expect("a frame");
        assert_eq!(
            bridge.accept(member, report(next, 2, vec![binding(release(1), false)])),
            Acceptance::Reconciled
        );
        let live = bridge.live_packages(5);
        assert!(live.pending.is_empty());
        assert_eq!(live.releases.len(), 1);
    }

    #[test]
    fn a_fenced_or_closed_member_is_never_rounded_and_stays_pending_until_it_ends() {
        let bridge = WorkerBridge::new(ControllerGeneration::new(3));
        let fenced = recorded(&bridge, 1);
        let closed = recorded(&bridge, 2);
        bridge.fenced(fenced);
        bridge.closed(closed, false);
        assert!(bridge.next_frame(fenced, 5, BTreeSet::new()).is_none());
        assert!(bridge.next_frame(closed, 5, BTreeSet::new()).is_none());
        assert_eq!(bridge.to_check().len(), 2);
        assert_eq!(bridge.live_packages(5).pending.len(), 2);
        // Recording a fenced worker again restores nothing.
        bridge.recorded(fenced, process(1));
        assert!(bridge.next_frame(fenced, 5, BTreeSet::new()).is_none());
        bridge.ended(fenced);
        bridge.ended(closed);
        assert!(bridge.live_packages(5).pending.is_empty());
        // A closure over a confirmed end takes the member out at once.
        let normal = recorded(&bridge, 3);
        bridge.closed(normal, true);
        assert!(!bridge.holds(normal));
    }

    #[test]
    fn counts_come_only_from_reports_used_after_the_mark() {
        let bridge = WorkerBridge::new(ControllerGeneration::new(3));
        let member = recorded(&bridge, 1);
        let covered: BTreeSet<ReleaseKey> = std::iter::once(key_of(&release(1))).collect();
        let frame = bridge
            .next_frame(member, 5, covered.clone())
            .expect("a frame");
        bridge.accept(member, report(frame, 1, vec![binding(release(1), false)]));
        let mark = bridge.mark();
        assert!(
            bridge.counts_since(mark, 5).is_none(),
            "the report is older than the read"
        );
        let frame = bridge.next_frame(member, 5, covered).expect("a frame");
        bridge.accept(
            member,
            report(
                frame,
                2,
                vec![binding(release(1), false), binding(release(1), true)],
            ),
        );
        let counts = bridge
            .counts_since(mark, 5)
            .expect("every member answered since");
        let (_, count, ending) = &counts[&key_of(&release(1))];
        assert_eq!((*count, *ending), (2, true));
        // A member that has not reported makes every count unknown.
        let _other = recorded(&bridge, 2);
        assert!(bridge.counts_since(mark, 5).is_none());
    }

    /// A binding due to end closes at the first snapshot after its requests settle, so a member
    /// whose report lists one needs a round even where it is reconciled and every installation
    /// still describes the release, as a disabled one and a revoked one do; once a report omits
    /// the binding, it needs none.
    #[test]
    fn a_member_reporting_a_binding_due_to_end_needs_a_round_until_its_report_omits_it() {
        let bridge = WorkerBridge::new(ControllerGeneration::new(3));
        let member = recorded(&bridge, 1);
        let covered: BTreeSet<ReleaseKey> = std::iter::once(key_of(&release(1))).collect();
        let installed = |key: &ReleaseKey| *key == key_of(&release(1));

        let frame = bridge
            .next_frame(member, 5, covered.clone())
            .expect("a frame");
        bridge.accept(member, report(frame, 1, vec![binding(release(1), false)]));
        assert!(
            !bridge.needs_round(member, 5, &installed),
            "a binding that is not ending, on an installed release, needs nothing"
        );

        let frame = bridge
            .next_frame(member, 5, covered.clone())
            .expect("a frame");
        assert_eq!(
            bridge.accept(member, report(frame, 2, vec![binding(release(1), true)])),
            Acceptance::Reconciled
        );
        assert!(
            bridge.needs_round(member, 5, &installed),
            "a reconciled member whose report lists a binding due to end is asked again"
        );

        let frame = bridge.next_frame(member, 5, covered).expect("a frame");
        bridge.accept(member, report(frame, 3, Vec::new()));
        assert!(
            !bridge.needs_round(member, 5, &installed),
            "and once a report omits it, the member needs no round"
        );
    }
}
