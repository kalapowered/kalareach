//! The owner-approved enrolment record, and the cache of what was last observed.
//!
//! Section 3 is exact about what a listing may do. Stopped distributions come from an
//! owner-approved cached inventory carrying `last_observed_at`, the environment identity and an
//! explicit `stale` or `environment_stopped` status; a cached row is not evidence that a process
//! is currently live; **listing never starts an environment**; and refresh, create and attach may
//! start the selected one.
//!
//! So the two operations are separate types of work here, not one with a flag. [`Store::list`]
//! reads the record and the cache and touches no platform at all — it does not take an
//! [`Observer`], so it could not ask one. [`Store::refresh`] is the only thing that does, and
//! starting is a separate call on the observer that a refresh makes only when its caller asked
//! for it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use kr_protocol::identity::{
    EnvironmentAccess, EnvironmentEnrolment, EnvironmentInventoryRow, EnvironmentPresence,
    EnvironmentReadiness, ObservationSource,
};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::TimestampMs;

use crate::error::{ControllerError, Result};

/// How long an observation describes the present.
///
/// Past it the row is `stale`: what was seen is still reported, with the time it was seen, and the
/// status says the row no longer describes now.
pub const OBSERVATION_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// The largest enrolment file this host will read, in bytes.
const MAX_RECORD_LEN: u64 = 1024 * 1024;

/// What was last observed about one enrolment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Observation {
    /// What was seen.
    status: EnvironmentPresence,
    /// When it was seen.
    at_ms: u64,
}

/// Which approved record an environment identity names now.
///
/// One identity can be approved, forgotten and approved again, and each of those is a separate
/// record of the owner's even when every field of it reads the same. An answer that came back for
/// one says nothing about another, so every answer is recorded against the instance the bridge was
/// opened for. The number is this host's own and is handed out once per enrolment, starting at one,
/// so a record written by another build carries none of these and matches nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnrolmentInstance(u64);

/// What one opened bridge established about an environment's own local channel.
///
/// Section 18: an integration needs a helper and scoped credentials in the target environment, and
/// forwarding a socket installs neither. So this is evidence rather than a flag: it names the
/// destination, the user and the helper that answered, and the approved record it answered for. A
/// record replaced since is a different instance, and the evidence does not carry over to it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ScopedChannel {
    /// The approved record the bridge was opened for.
    #[serde(default)]
    instance: EnrolmentInstance,
    /// The platform identity the helper answered from.
    target: String,
    /// The operating-system user it ran as there.
    os_user: String,
    /// The helper that answered.
    helper_path: String,
    /// When it answered.
    at_ms: u64,
}

/// The file this host keeps its enrolments and observations in.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Record {
    /// The enrolments, in the order the owner approved them.
    enrolments: Vec<EnvironmentEnrolment>,
    /// The last observation of each, by environment identity.
    observations: BTreeMap<String, Observation>,
    /// What a bridge established about each environment's own scoped local channel.
    #[serde(default)]
    scoped_channels: BTreeMap<String, ScopedChannel>,
    /// Which approved record each environment identity names now.
    #[serde(default)]
    instances: BTreeMap<String, EnrolmentInstance>,
    /// The last instance number this host handed out.
    #[serde(default)]
    last_instance: u64,
}

/// Asks the platform about one environment, and starts it when told to.
///
/// A refresh takes one of these. A listing does not, which is what makes "listing never starts an
/// environment" a property of the types rather than of a flag somebody has to pass correctly.
pub trait Observer {
    /// Reports whether the environment the enrolment names is running.
    ///
    /// # Errors
    ///
    /// Returns a failure when the platform could not be asked. A platform that answers "no such
    /// environment" is not a failure: it is [`EnvironmentPresence::EnvironmentStopped`] for a
    /// distribution that is registered and stopped, and a failure for one that is gone.
    fn observe(&self, enrolment: &EnvironmentEnrolment) -> Result<EnvironmentPresence>;

    /// Starts the environment the enrolment names.
    ///
    /// # Errors
    ///
    /// Returns a failure when the environment could not be started.
    fn start(&self, enrolment: &EnvironmentEnrolment) -> Result<()>;
}

/// What one refresh saw, and which approved record it saw it for.
#[derive(Clone, Debug)]
pub struct Refreshed {
    /// The row, observed now rather than read from the cache.
    pub row: EnvironmentInventoryRow,
    /// Whether this refresh started the environment.
    pub started: bool,
    /// The record the row was read from, so a bridge opened for it is recorded against it.
    pub instance: EnrolmentInstance,
}

/// Whether the bridge a refresh opened answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeAnswer {
    /// The destination answered on its own local channel.
    Answered,
    /// Nothing answered, for whatever reason the refusal names.
    Refused,
}

/// What the record says once a bridge's result has been written to it.
#[derive(Clone, Debug)]
pub struct BridgeOutcome {
    /// Whether this host now records a scoped local channel established by that bridge.
    pub established: bool,
    /// What the environment still needs, or nothing when the record has gone.
    pub readiness: Option<EnvironmentReadiness>,
}

/// The enrolments this host has, and what it last saw of them.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    record: Record,
}

/// Serialises every read-modify-write of an enrolment record in this process.
///
/// The record is one small file that a listing, an enrolment and a refresh all touch. One
/// environment has one control daemon, so one lock is enough, and holding it for the length of a
/// file write costs nothing measurable.
static RECORD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl Store {
    /// Opens the store, runs one operation against it and closes it again, under the record lock.
    ///
    /// # Errors
    ///
    /// Returns whatever opening the store or the operation returned.
    pub fn with_locked<T>(
        state_dir: &std::path::Path,
        operation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let guard = RECORD_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut store = Self::open(state_dir)?;
        let outcome = operation(&mut store);
        drop(guard);
        outcome
    }

    /// Opens the store beside this environment's other state, creating an empty one.
    ///
    /// # Errors
    ///
    /// Returns a failure when the file exists but cannot be read, or is not a record this build
    /// understands.
    pub fn open(state_dir: &std::path::Path) -> Result<Self> {
        let path = state_dir.join("environments.json");
        let mut record: Record = match kr_ipc::paths::read_owner_only_file(&path, MAX_RECORD_LEN)
            .map_err(|error| ControllerError::supervision(error.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                ControllerError::supervision(format!(
                    "{} is not an environment record this build understands: {error}",
                    path.display()
                ))
            })?,
            None => Record::default(),
        };
        // An enrolment written by a build that did not number its records gets a number now, so
        // every approved record here can be named. The evidence beside it carries no number, which
        // is what it deserves: this host cannot tell which record answered for it.
        for index in 0..record.enrolments.len() {
            let key = record.enrolments[index].environment_id.to_string();
            if !record.instances.contains_key(&key) {
                record.last_instance = record.last_instance.saturating_add(1);
                record
                    .instances
                    .insert(key, EnrolmentInstance(record.last_instance));
            }
        }
        Ok(Self { path, record })
    }

    /// Records one owner-approved enrolment, replacing any record with the same identity.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument failure when the record is incomplete, and a supervision
    /// failure when it cannot be written.
    pub fn enrol(
        &mut self,
        mut enrolment: EnvironmentEnrolment,
        now_ms: u64,
    ) -> Result<EnvironmentInventoryRow> {
        enrolment
            .validate()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The approval is this host's own record of when the owner approved it, not a value the
        // caller supplies: a request that set it into the future would make a row look fresher
        // than anything this host has seen.
        enrolment.approved_at_ms = TimestampMs::new(now_ms);
        let key = enrolment.environment_id.to_string();
        self.record
            .enrolments
            .retain(|existing| existing.environment_id != enrolment.environment_id);
        self.record.enrolments.push(enrolment.clone());
        // Every approval is a record of its own. It starts with nothing established about it, and
        // an answer still on its way back for the record it replaces belongs to that one.
        self.record.last_instance = self.record.last_instance.saturating_add(1);
        self.record
            .instances
            .insert(key.clone(), EnrolmentInstance(self.record.last_instance));
        self.record.scoped_channels.remove(&key);
        self.write()?;
        Ok(self.row(&enrolment, now_ms))
    }

    /// Removes one enrolment and its cached observation.
    ///
    /// # Errors
    ///
    /// Returns a supervision failure when the record cannot be written.
    pub fn forget(&mut self, environment_id: EnvironmentId) -> Result<bool> {
        let before = self.record.enrolments.len();
        self.record
            .enrolments
            .retain(|existing| existing.environment_id != environment_id);
        self.record.observations.remove(&environment_id.to_string());
        // What a bridge established about an environment this host no longer records goes with it,
        // and so does the number of the record it was established for.
        self.record
            .scoped_channels
            .remove(&environment_id.to_string());
        self.record.instances.remove(&environment_id.to_string());
        let removed = self.record.enrolments.len() != before;
        if removed {
            self.write()?;
        }
        Ok(removed)
    }

    /// Returns the cached inventory.
    ///
    /// Nothing is contacted and nothing is started. Every row this returns is
    /// [`ObservationSource::Cache`], so no caller can mistake one for evidence that a process is
    /// live.
    #[must_use]
    pub fn list(
        &self,
        access: Option<EnvironmentAccess>,
        now_ms: u64,
    ) -> Vec<EnvironmentInventoryRow> {
        self.record
            .enrolments
            .iter()
            .filter(|enrolment| access.is_none_or(|wanted| enrolment.access == wanted))
            .map(|enrolment| self.row(enrolment, now_ms))
            .collect()
    }

    /// Returns one enrolment by identity.
    #[must_use]
    pub fn enrolment(&self, environment_id: EnvironmentId) -> Option<&EnvironmentEnrolment> {
        self.record
            .enrolments
            .iter()
            .find(|enrolment| enrolment.environment_id == environment_id)
    }

    /// Returns which approved record this identity names now.
    #[must_use]
    pub fn instance_of(&self, environment_id: EnvironmentId) -> Option<EnrolmentInstance> {
        self.record
            .instances
            .get(&environment_id.to_string())
            .copied()
    }

    /// Observes one environment now, starting it first when `start` is set.
    ///
    /// # Errors
    ///
    /// Returns a not-found failure when nothing is enrolled under that identity, and whatever the
    /// observer reported otherwise.
    pub fn refresh(
        &mut self,
        environment_id: EnvironmentId,
        start: bool,
        observer: &dyn Observer,
        now_ms: u64,
    ) -> Result<Refreshed> {
        let enrolment = self
            .enrolment(environment_id)
            .ok_or_else(|| {
                ControllerError::InvalidArgument(format!(
                    "this host has no enrolled environment {environment_id}"
                ))
            })?
            .clone();
        let instance = self.instance_of(environment_id).ok_or_else(|| {
            ControllerError::supervision(format!(
                "this host has no approved record for environment {environment_id}"
            ))
        })?;
        let mut started = false;
        if start && observer.observe(&enrolment)? != EnvironmentPresence::Running {
            observer.start(&enrolment)?;
            started = true;
        }
        let status = observer.observe(&enrolment)?;
        self.record.observations.insert(
            environment_id.to_string(),
            Observation {
                status,
                at_ms: now_ms,
            },
        );
        self.write()?;
        let mut row = self.row(&enrolment, now_ms);
        row.observation = ObservationSource::Refresh;
        row.status = status;
        row.last_observed_at_ms = TimestampMs::new(now_ms);
        Ok(Refreshed {
            row,
            started,
            instance,
        })
    }

    /// Records what one opened bridge did, and reports what the record says afterwards.
    ///
    /// This is the whole of the decision a refresh makes about the scoped local channel, so that a
    /// caller has none of its own to get wrong. A bridge that answered establishes the channel for
    /// the record it was opened for; one that was refused takes back what an earlier bridge
    /// established for that same record. Either way the readiness that comes back is read from the
    /// record after the result was written, so it can never describe a channel this host did not
    /// keep.
    ///
    /// # Errors
    ///
    /// Returns a supervision failure when the record cannot be written.
    pub fn record_bridge_outcome(
        &mut self,
        environment_id: EnvironmentId,
        opened_for: EnrolmentInstance,
        answer: BridgeAnswer,
        now_ms: u64,
    ) -> Result<BridgeOutcome> {
        let established = match answer {
            BridgeAnswer::Answered => self.scope_channel(environment_id, opened_for, now_ms)?,
            BridgeAnswer::Refused => {
                self.unscope_channel(environment_id, opened_for)?;
                false
            }
        };
        Ok(BridgeOutcome {
            established,
            readiness: self.row_of(environment_id, now_ms).map(|row| row.readiness),
        })
    }

    /// Records what an opened bridge established about one environment's scoped local channel.
    ///
    /// The evidence belongs to the approved record the bridge was opened for. A record changed
    /// since, forgotten since, or forgotten and approved again with every field the same, is
    /// another record, and this answer says nothing about it: the next bridge decides for it.
    fn scope_channel(
        &mut self,
        environment_id: EnvironmentId,
        opened_for: EnrolmentInstance,
        now_ms: u64,
    ) -> Result<bool> {
        if self.instance_of(environment_id) != Some(opened_for) {
            return Ok(false);
        }
        let Some(enrolment) = self.enrolment(environment_id) else {
            return Ok(false);
        };
        let established = ScopedChannel {
            instance: opened_for,
            target: enrolment.target.clone(),
            os_user: enrolment.os_user.clone(),
            helper_path: enrolment.helper_path.clone(),
            at_ms: now_ms,
        };
        if self
            .record
            .scoped_channels
            .insert(environment_id.to_string(), established.clone())
            .as_ref()
            != Some(&established)
        {
            self.write()?;
        }
        Ok(true)
    }

    /// Forgets what an earlier bridge established about one environment's scoped local channel.
    ///
    /// A bridge that could not be opened, or one that reached another installation, leaves this
    /// host with no current evidence for the record it was opened for. Keeping the old result would
    /// report an integration as ready on the strength of an answer that is no longer being given.
    /// A refusal that arrives after the owner has approved another record takes nothing back from
    /// that one: it was never about it.
    fn unscope_channel(
        &mut self,
        environment_id: EnvironmentId,
        opened_for: EnrolmentInstance,
    ) -> Result<bool> {
        if self.instance_of(environment_id) != Some(opened_for) {
            return Ok(false);
        }
        if self
            .record
            .scoped_channels
            .remove(&environment_id.to_string())
            .is_some()
        {
            self.write()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Returns the cached row for one enrolment, without asking any platform.
    #[must_use]
    pub fn row_of(
        &self,
        environment_id: EnvironmentId,
        now_ms: u64,
    ) -> Option<EnvironmentInventoryRow> {
        self.enrolment(environment_id)
            .map(|enrolment| self.row(enrolment, now_ms))
    }

    /// Builds one row from the record and the cache.
    fn row(&self, enrolment: &EnvironmentEnrolment, now_ms: u64) -> EnvironmentInventoryRow {
        let (status, last_observed_at_ms) = match self
            .record
            .observations
            .get(&enrolment.environment_id.to_string())
        {
            // What was seen is reported with the time it was seen. Past the lifetime the status
            // says the row no longer describes the present rather than the row being hidden.
            Some(observation)
                if now_ms.saturating_sub(observation.at_ms) <= OBSERVATION_LIFETIME_MS =>
            {
                (observation.status, observation.at_ms)
            }
            Some(observation) => (EnvironmentPresence::Stale, observation.at_ms),
            None => (EnvironmentPresence::Stale, enrolment.approved_at_ms.get()),
        };
        EnvironmentInventoryRow {
            enrolment: enrolment.clone(),
            last_observed_at_ms: TimestampMs::new(last_observed_at_ms),
            status,
            observation: ObservationSource::Cache,
            readiness: self.readiness(enrolment),
        }
    }

    /// Reports what one environment still needs.
    fn readiness(&self, enrolment: &EnvironmentEnrolment) -> EnvironmentReadiness {
        let helper_enrolled = enrolment.validate().is_ok();
        // The channel is scoped when a bridge established it *for the record that is approved
        // now*. An access class, a destination, a user or a helper that has changed since is a
        // different installation of the integration, and so is an identical record approved again
        // after a forgetting, so the evidence does not carry over to any of them.
        let current = self.instance_of(enrolment.environment_id);
        let channel_scoped = self
            .record
            .scoped_channels
            .get(&enrolment.environment_id.to_string())
            .is_some_and(|established| Some(established.instance) == current);
        let detail = match (helper_enrolled, channel_scoped) {
            (true, true) => "the helper and the scoped channel are both recorded".to_owned(),
            (false, _) => format!(
                "install the helper in {} and enrol its absolute path",
                enrolment.target
            ),
            // Section 18: socket forwarding alone does not install the integration. A channel this
            // environment has not been given is not supplied by forwarding one from elsewhere.
            (true, false) => format!(
                "give {} its own scoped local channel; forwarding a socket does not install one",
                enrolment.label
            ),
        };
        EnvironmentReadiness {
            helper_enrolled,
            channel_scoped,
            detail,
        }
    }

    /// Writes the record back, owner only.
    fn write(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.record)
            .map_err(|error| ControllerError::supervision(error.to_string()))?;
        kr_ipc::paths::write_owner_only_file(&self.path, &bytes)
            .map_err(|error| ControllerError::supervision(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::{Nullable, Uuid};
    use std::cell::RefCell;

    /// An observer that records every question it is asked and every start it is told to make.
    struct Recorder {
        observed: RefCell<Vec<String>>,
        started: RefCell<Vec<String>>,
        answer: RefCell<EnvironmentPresence>,
    }

    impl Recorder {
        fn answering(answer: EnvironmentPresence) -> Self {
            Self {
                observed: RefCell::new(Vec::new()),
                started: RefCell::new(Vec::new()),
                answer: RefCell::new(answer),
            }
        }
    }

    impl Observer for Recorder {
        fn observe(&self, enrolment: &EnvironmentEnrolment) -> Result<EnvironmentPresence> {
            self.observed.borrow_mut().push(enrolment.target.clone());
            Ok(*self.answer.borrow())
        }

        fn start(&self, enrolment: &EnvironmentEnrolment) -> Result<()> {
            self.started.borrow_mut().push(enrolment.target.clone());
            *self.answer.borrow_mut() = EnvironmentPresence::Running;
            Ok(())
        }
    }

    fn enrolment(byte: u8, label: &str) -> EnvironmentEnrolment {
        EnvironmentEnrolment {
            environment_id: EnvironmentId::new(Uuid::from_bytes([byte; 16])),
            access: EnvironmentAccess::WslDistribution,
            label: label.to_owned(),
            target: format!("{label}-distribution"),
            os_user: "kala".to_owned(),
            helper_path: "/usr/local/bin/kr".to_owned(),
            clipboard_destination: Nullable::null(),
            approved_at_ms: TimestampMs::new(0),
        }
    }

    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let store = Store::open(directory.path()).expect("an empty store");
        (directory, store)
    }

    #[test]
    fn an_enrolment_is_recorded_and_read_back() {
        let (directory, mut store) = store();
        store.enrol(enrolment(1, "ubuntu"), 100).expect("enrolled");
        let reopened = Store::open(directory.path()).expect("reopened");
        let rows = reopened.list(None, 100);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].enrolment.target, "ubuntu-distribution");
        assert_eq!(rows[0].enrolment.os_user, "kala");
        assert_eq!(rows[0].enrolment.helper_path, "/usr/local/bin/kr");
    }

    #[test]
    fn a_listing_reports_a_cached_row_and_starts_nothing() {
        let (_directory, mut store) = store();
        store.enrol(enrolment(1, "ubuntu"), 100).expect("enrolled");
        let rows = store.list(None, 100);
        assert_eq!(rows[0].observation, ObservationSource::Cache);
        assert!(!rows[0].is_evidence_of_a_live_process());
    }

    #[test]
    fn an_unobserved_row_is_stale_and_carries_the_time_it_names() {
        let (_directory, mut store) = store();
        store.enrol(enrolment(1, "ubuntu"), 100).expect("enrolled");
        let rows = store.list(None, 100);
        assert_eq!(rows[0].status, EnvironmentPresence::Stale);
        assert_eq!(rows[0].last_observed_at_ms, TimestampMs::new(100));
    }

    #[test]
    fn an_observation_goes_stale_rather_than_being_repeated_as_the_present() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        let observer = Recorder::answering(EnvironmentPresence::Running);
        store
            .refresh(record.environment_id, false, &observer, 200)
            .expect("refreshed");
        let fresh = store.list(None, 200);
        assert_eq!(fresh[0].status, EnvironmentPresence::Running);
        assert!(!fresh[0].is_evidence_of_a_live_process());

        let later = store.list(None, 200 + OBSERVATION_LIFETIME_MS + 1);
        assert_eq!(later[0].status, EnvironmentPresence::Stale);
        assert_eq!(later[0].last_observed_at_ms, TimestampMs::new(200));
    }

    #[test]
    fn a_refresh_that_was_not_asked_to_start_does_not_start() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        let observer = Recorder::answering(EnvironmentPresence::EnvironmentStopped);
        let refreshed = store
            .refresh(record.environment_id, false, &observer, 200)
            .expect("refreshed");
        let (row, started) = (refreshed.row, refreshed.started);
        assert!(!started);
        assert!(observer.started.borrow().is_empty());
        assert_eq!(row.status, EnvironmentPresence::EnvironmentStopped);
        assert_eq!(row.observation, ObservationSource::Refresh);
        assert!(!row.is_evidence_of_a_live_process());
    }

    #[test]
    fn a_refresh_that_was_asked_to_start_starts_the_one_it_selected() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        store.enrol(enrolment(2, "debian"), 100).expect("enrolled");
        let observer = Recorder::answering(EnvironmentPresence::EnvironmentStopped);
        let refreshed = store
            .refresh(record.environment_id, true, &observer, 200)
            .expect("refreshed");
        let (row, started) = (refreshed.row, refreshed.started);
        assert!(started);
        assert_eq!(*observer.started.borrow(), vec!["ubuntu-distribution"]);
        assert_eq!(row.status, EnvironmentPresence::Running);
        assert!(row.is_evidence_of_a_live_process());
    }

    #[test]
    fn a_refresh_of_a_running_environment_starts_nothing() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        let observer = Recorder::answering(EnvironmentPresence::Running);
        let started = store
            .refresh(record.environment_id, true, &observer, 200)
            .expect("refreshed")
            .started;
        assert!(!started);
        assert!(observer.started.borrow().is_empty());
    }

    /// Which record an identity names now, which is what a bridge is opened for.
    fn instance(store: &Store, record: &EnvironmentEnrolment) -> EnrolmentInstance {
        store
            .instance_of(record.environment_id)
            .expect("an approved record has a number")
    }

    /// What the dispatch does when a bridge answered.
    fn answered(store: &mut Store, record: &EnvironmentEnrolment, at_ms: u64) -> BridgeOutcome {
        let opened_for = instance(store, record);
        store
            .record_bridge_outcome(
                record.environment_id,
                opened_for,
                BridgeAnswer::Answered,
                at_ms,
            )
            .expect("the outcome is recorded")
    }

    #[test]
    fn readiness_reports_the_scoped_channel_separately_from_the_helper() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        let before = store.list(None, 100);
        assert!(before[0].readiness.helper_enrolled);
        assert!(!before[0].readiness.channel_scoped);
        assert!(!before[0].readiness.is_ready());
        assert!(before[0].readiness.detail.contains("forwarding a socket"));

        let outcome = answered(&mut store, &record, 100);
        assert!(outcome.established);
        assert!(
            outcome
                .readiness
                .expect("the record answers for itself")
                .is_ready()
        );
        let after = store.list(None, 100);
        assert!(after[0].readiness.is_ready());
    }

    #[test]
    fn a_destination_that_changed_does_not_keep_what_an_earlier_bridge_established() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        answered(&mut store, &record, 100);
        assert!(store.list(None, 100)[0].readiness.is_ready());

        // The same identity, a different helper. Nothing has answered from there yet.
        let mut moved = record.clone();
        moved.helper_path = "/opt/kalareach/kr".to_owned();
        store.enrol(moved, 200).expect("enrolled again");
        let rows = store.list(None, 200);
        assert!(!rows[0].readiness.channel_scoped);
        assert!(rows[0].readiness.detail.contains("forwarding a socket"));
    }

    #[test]
    fn an_access_class_that_changed_does_not_keep_what_an_earlier_bridge_established() {
        // Everything about where the helper lives is the same; the way this host reaches it is
        // not. A container is not the distribution that answered, so the answer does not carry.
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        answered(&mut store, &record, 100);
        assert!(store.list(None, 100)[0].readiness.channel_scoped);

        let mut reclassified = record.clone();
        reclassified.access = EnvironmentAccess::Container;
        reclassified.target = "03".repeat(32);
        store.enrol(reclassified, 200).expect("enrolled again");
        assert!(!store.list(None, 200)[0].readiness.channel_scoped);
    }

    #[test]
    fn forgetting_an_environment_forgets_what_a_bridge_established_about_it() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        answered(&mut store, &record, 100);
        assert!(store.forget(record.environment_id).expect("forgotten"));
        store.enrol(record.clone(), 300).expect("enrolled again");
        assert!(
            !store.list(None, 300)[0].readiness.channel_scoped,
            "a record enrolled again starts with nothing established"
        );
    }

    #[test]
    fn an_answer_from_a_destination_that_was_replaced_meanwhile_establishes_nothing() {
        // The bridge answers after the record it was opened for has been changed. The answer came
        // from the old destination, so it says nothing about the new one.
        let (_directory, mut store) = store();
        let opened_for = enrolment(1, "ubuntu");
        store.enrol(opened_for.clone(), 100).expect("enrolled");
        let first = instance(&store, &opened_for);
        let mut replaced = opened_for.clone();
        replaced.target = "Ubuntu-24.04-again".to_owned();
        store.enrol(replaced, 200).expect("enrolled again");

        let outcome = store
            .record_bridge_outcome(
                opened_for.environment_id,
                first,
                BridgeAnswer::Answered,
                300,
            )
            .expect("recorded");
        assert!(
            !outcome.established,
            "the answer belongs to the record that was approved when the bridge opened"
        );
        assert!(!store.list(None, 300)[0].readiness.channel_scoped);
    }

    #[test]
    fn an_answer_that_arrives_after_an_identical_record_was_approved_again_establishes_nothing() {
        // Forgotten and approved again with every field the same, at the same moment. Nothing
        // about the record tells the two apart, so the number this host gave each of them does.
        let (_directory, mut store) = store();
        let opened_for = enrolment(1, "ubuntu");
        store.enrol(opened_for.clone(), 100).expect("enrolled");
        let first = instance(&store, &opened_for);
        assert!(store.forget(opened_for.environment_id).expect("forgotten"));
        store
            .enrol(opened_for.clone(), 100)
            .expect("enrolled again");
        assert_ne!(
            instance(&store, &opened_for),
            first,
            "approving a record again makes another record"
        );

        let outcome = store
            .record_bridge_outcome(
                opened_for.environment_id,
                first,
                BridgeAnswer::Answered,
                100,
            )
            .expect("recorded");
        assert!(!outcome.established);
        assert!(!store.list(None, 100)[0].readiness.channel_scoped);
    }

    #[test]
    fn a_bridge_that_failed_takes_back_what_an_earlier_one_established() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        answered(&mut store, &record, 100);
        assert!(store.list(None, 100)[0].readiness.channel_scoped);

        let opened_for = instance(&store, &record);
        let outcome = store
            .record_bridge_outcome(
                record.environment_id,
                opened_for,
                BridgeAnswer::Refused,
                200,
            )
            .expect("recorded");
        assert!(!outcome.established);
        let readiness = outcome.readiness.expect("the record answers for itself");
        assert!(!readiness.channel_scoped);
        assert!(
            readiness.detail.contains("forwarding a socket"),
            "a refusal leaves no detail claiming a channel: {}",
            readiness.detail
        );
        assert!(!store.list(None, 200)[0].readiness.channel_scoped);
    }

    #[test]
    fn a_refusal_that_arrives_late_takes_nothing_back_from_the_record_approved_since() {
        // A bridge is opened, the owner approves a replacement while it is open, a later bridge
        // establishes the channel for that replacement, and only then does the first one report
        // that it was refused. It was never about the record that is approved now.
        let (_directory, mut store) = store();
        let opened_for = enrolment(1, "ubuntu");
        store.enrol(opened_for.clone(), 100).expect("enrolled");
        let first = instance(&store, &opened_for);

        let mut replacement = opened_for.clone();
        replacement.helper_path = "/opt/kalareach/kr".to_owned();
        store.enrol(replacement.clone(), 200).expect("approved");
        answered(&mut store, &replacement, 200);
        assert!(store.list(None, 200)[0].readiness.channel_scoped);

        let outcome = store
            .record_bridge_outcome(opened_for.environment_id, first, BridgeAnswer::Refused, 300)
            .expect("recorded");
        assert!(
            outcome
                .readiness
                .expect("the record answers for itself")
                .channel_scoped,
            "the refusal was about the record that was replaced, not this one"
        );
        assert!(store.list(None, 300)[0].readiness.channel_scoped);
    }

    #[test]
    fn forgetting_removes_the_record_and_its_observation() {
        let (directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        assert!(store.forget(record.environment_id).expect("forgotten"));
        assert!(!store.forget(record.environment_id).expect("already gone"));
        assert!(
            Store::open(directory.path())
                .expect("reopened")
                .list(None, 100)
                .is_empty()
        );
    }

    #[test]
    fn a_listing_can_be_narrowed_to_one_access_class() {
        let (_directory, mut store) = store();
        store.enrol(enrolment(1, "ubuntu"), 100).expect("enrolled");
        let mut container = enrolment(2, "build");
        container.access = EnvironmentAccess::Container;
        container.target = "02".repeat(32);
        store.enrol(container, 100).expect("enrolled");
        assert_eq!(store.list(Some(EnvironmentAccess::Container), 100).len(), 1);
        assert_eq!(
            store
                .list(Some(EnvironmentAccess::WslDistribution), 100)
                .len(),
            1
        );
        assert_eq!(store.list(None, 100).len(), 2);
    }
}
