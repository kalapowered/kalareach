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

/// What one opened bridge established about an environment's own local channel.
///
/// Section 18: an integration needs a helper and scoped credentials in the target environment, and
/// forwarding a socket installs neither. So this is evidence rather than a flag: it names the
/// destination, the user and the helper that answered, and a record whose destination has changed
/// since no longer matches it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ScopedChannel {
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
        let record = match kr_ipc::paths::read_owner_only_file(&path, MAX_RECORD_LEN)
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
        self.record
            .enrolments
            .retain(|existing| existing.environment_id != enrolment.environment_id);
        self.record.enrolments.push(enrolment.clone());
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
        // What a bridge established about an environment this host no longer records goes with it.
        self.record
            .scoped_channels
            .remove(&environment_id.to_string());
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
    ) -> Result<(EnvironmentInventoryRow, bool)> {
        let enrolment = self
            .enrolment(environment_id)
            .ok_or_else(|| {
                ControllerError::InvalidArgument(format!(
                    "this host has no enrolled environment {environment_id}"
                ))
            })?
            .clone();
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
        Ok((row, started))
    }

    /// Records what an opened bridge established about one environment's scoped local channel.
    ///
    /// The evidence is the destination that answered, so a record whose target, user or helper
    /// changes afterwards does not keep the result: the next bridge decides again.
    ///
    /// # Errors
    ///
    /// Returns a not-found failure when nothing is enrolled under that identity, and a supervision
    /// failure when the record cannot be written.
    pub fn scope_channel(&mut self, environment_id: EnvironmentId, now_ms: u64) -> Result<()> {
        let enrolment = self.enrolment(environment_id).ok_or_else(|| {
            ControllerError::InvalidArgument(format!(
                "this host has no enrolled environment {environment_id}"
            ))
        })?;
        let established = ScopedChannel {
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
        Ok(())
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
        // The channel is scoped when a bridge established it *for this record*. A destination, a
        // user or a helper that has changed since is a different installation of the integration,
        // and the evidence does not carry over to it.
        let channel_scoped = self
            .record
            .scoped_channels
            .get(&enrolment.environment_id.to_string())
            .is_some_and(|established| {
                established.target == enrolment.target
                    && established.os_user == enrolment.os_user
                    && established.helper_path == enrolment.helper_path
            });
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
        let (row, started) = store
            .refresh(record.environment_id, false, &observer, 200)
            .expect("refreshed");
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
        let (row, started) = store
            .refresh(record.environment_id, true, &observer, 200)
            .expect("refreshed");
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
        let (_, started) = store
            .refresh(record.environment_id, true, &observer, 200)
            .expect("refreshed");
        assert!(!started);
        assert!(observer.started.borrow().is_empty());
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

        store
            .scope_channel(record.environment_id, 100)
            .expect("scoped");
        let after = store.list(None, 100);
        assert!(after[0].readiness.is_ready());
    }

    #[test]
    fn a_destination_that_changed_does_not_keep_what_an_earlier_bridge_established() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        store
            .scope_channel(record.environment_id, 100)
            .expect("scoped");
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
    fn forgetting_an_environment_forgets_what_a_bridge_established_about_it() {
        let (_directory, mut store) = store();
        let record = enrolment(1, "ubuntu");
        store.enrol(record.clone(), 100).expect("enrolled");
        store
            .scope_channel(record.environment_id, 100)
            .expect("scoped");
        assert!(store.forget(record.environment_id).expect("forgotten"));
        store.enrol(record.clone(), 300).expect("enrolled again");
        assert!(
            !store.list(None, 300)[0].readiness.channel_scoped,
            "a record enrolled again starts with nothing established"
        );
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
