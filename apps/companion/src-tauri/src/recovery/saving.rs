//! Saving the device's settings with the recovery bundle: the step, and when it runs.
//!
//! The bundle may carry the owner device's settings as one sealed, bucket-padded member that only
//! the kit opens. Settings are what a person chose on this computer, not session content, so the
//! member follows the colour mode's rule: privacy mode does not stop it. This module is the
//! companion's half of that: it reads the settings file, compares it with the member the bundle
//! holds, and writes the bundle by its own compare-and-swap when they differ. The library's
//! `BundleStore` holds the rules of the write; what is here is the order of a step and the times
//! it may run.
//!
//! # The order of a step
//!
//! A step takes the recovery lock and then, in this order: ends any write of the bundle whose
//! answer never came back (a cover's too, and the first write of all, so a person is never asked
//! to settle what a step can end); ends if the writer's level is closed; ends if the person
//! turned saving off; ends if the one eligibility deadline has not passed; reads the settings file
//! now, never a value captured earlier; fetches the bundle, compares, and writes. A write of the
//! step's own that gets no answer is ended at once. The line the page shows says "saved" only
//! after a write the service confirmed or a read of the bundle that holds the same settings, and a
//! change to the settings file takes the line away until a step ends after it, even when the change
//! came while a step was running.
//!
//! # The writer's level
//!
//! Once any device writes the member, a build that cannot read it fails every read of the bundle:
//! a cover, a settle, a checkpoint. Devices of one account update on their own schedules, so no
//! step writes the member while the oldest level its release retains is below
//! [`SETTINGS_READ_FROM`], the first level whose builds read it. [`Recovery::save_settings_from`]
//! takes that level as an input, and while it is below, the first bundle carries no member, a step
//! writes nothing and the page is told nothing of saving. The gate binds the writing of the member
//! and nothing the person does: restoring a member that a later build wrote, listing the member
//! the bundle holds and removing it do not depend on it. Nor does it bind the end of a lost write,
//! which fences a request and reads a bundle and writes no member, so a step ends one whatever the
//! level. The gate opens by itself when a release retains a level that reads the member.
//!
//! # When a step runs
//!
//! Five things want a step: the application's start, a change to the settings file (after
//! [`SettingsTiming::quiet`] with no further change), a recovery step that reached the service,
//! the person turning saving on again, and the end of the window after a step that failed. None of
//! them waits inside the lock: each only records that a step is wanted. One loop runs the steps.
//!
//!
//! There is one eligibility deadline for the process. It is read and moved only while a step holds
//! the lock ([`Step`] is the proof), it is a monotonic instant, and it only moves forward. A step
//! that reaches the service for the settings and does not find them saved moves it to the end of
//! the next [`SettingsTiming::window`], so this process makes at most one such step per window. A
//! step that finds the deadline ahead asks the service nothing for the settings, though it may
//! have ended a lost write first, and tells the loop when to try again, so a change made during
//! the window is kept scheduled and not dropped. Two processes on one computer
//! take turns under the lock, so the stated limit is one write per process per window; the bundle's
//! compare-and-swap is the real guard.

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use kr_client::recovery::{LocalSettings, LostWrite, RecoveryError, SettingsSaved};
use kr_protocol::hello::PackageVersion;
use kr_protocol::retained::RETAINED_WORKER_LEVELS;
use kr_protocol::scalars::TimestampMs;
use kr_protocol::update::{CompatibilityLevel, THIS_LEVEL};
use serde::Serialize;
use tokio::sync::Notify;

use super::{Named, Recovery, RecoveryView, Step, blocker, now, refuse_if_blocked, said};
use crate::account::Account;
use crate::error::{CommandError, Result};
use crate::retained::NO_SAVED_SETTINGS;
use crate::settings::Told;

/// The first level whose builds read a settings member in a recovery bundle.
pub const SETTINGS_READ_FROM: CompatibilityLevel =
    CompatibilityLevel::of(PackageVersion::new(0, 79, 0));

/// The oldest level this release's control daemon still speaks to: the oldest build the settings
/// member has to be readable by.
#[must_use]
pub fn oldest_retained_level() -> CompatibilityLevel {
    RETAINED_WORKER_LEVELS
        .iter()
        .copied()
        .min()
        .unwrap_or(THIS_LEVEL)
}

/// Where a step reads what this computer has chosen.
pub trait SettingsSource: Send + Sync {
    /// What this computer has chosen now, or that its settings file cannot be read.
    fn chosen(&self) -> LocalSettings;
}

impl SettingsSource for crate::settings::Settings {
    fn chosen(&self) -> LocalSettings {
        self.local().for_backup()
    }
}

/// How long the saving of settings waits: for quiet after a change, and between steps that reach
/// the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettingsTiming {
    /// How long a change is left alone, so that a run of changes is one step.
    pub quiet: Duration,
    /// How long after a step that reached the service the next may.
    pub window: Duration,
}

impl SettingsTiming {
    /// What the application runs with: 30 seconds of quiet, one step in ten minutes.
    pub const PRODUCT: Self = Self {
        quiet: Duration::from_secs(30),
        window: Duration::from_secs(10 * 60),
    };
}

/// Where the settings stand in the bundle, as the page is told.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SettingsLine {
    /// No step has ended in this run, so nothing is known.
    Waiting,
    /// The bundle holds this computer's settings: a write the service confirmed, or a read of the
    /// bundle that shows the same settings.
    Saved,
    /// The bundle does not hold them yet.
    NotSaved {
        /// Why not.
        why: NotSavedWhy,
    },
    /// The person turned saving off, and nothing is written until they turn it on.
    Stopped,
}

/// Why the settings are not in the bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotSavedWhy {
    /// The sync service could not be reached, or refused.
    Service,
    /// The bundle changed during the save, three reads over; the next window tries again.
    Moved,
    /// The bundle has no room for the settings beside what a restore needs to trust.
    NoRoom,
    /// This computer's settings file cannot be read, so what the bundle holds is kept.
    SettingsFile,
    /// The recovery seed cannot be read from this device's secure storage.
    Seed,
    /// The bundle at the service does not open with this computer's seed.
    Bundle,
    /// This computer's recovery record, or the store's record of its last write, cannot be read,
    /// or the lock cannot be taken.
    Records,
}

/// What removing the saved settings from the bundle came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsRemoved {
    /// The service confirmed that the bundle holds no saved settings now.
    Removed,
    /// The removal was sent and the service did not answer. The write is outstanding, so the
    /// settings stay listed and the page shows the write as unsettled until a step or the person
    /// ends it.
    Unconfirmed,
}

/// What one step came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsStep {
    /// Nothing more to do, and no settings were asked of the service: saving has no source,
    /// recovery is not on, or the account cannot be used now; or a write whose answer was lost was
    /// ended and the writer's level is closed, or the first write of all did not land.
    Idle,
    /// The eligibility deadline is ahead, so the settings were not asked of the service (a lost
    /// write may have been ended before it was found). The step is wanted again at `until`.
    Deferred {
        /// When the deadline passes.
        until: Instant,
    },
    /// The step ran.
    Ended {
        /// What it left the line at.
        line: SettingsLine,
        /// When to try again, for a failure that a later try may mend.
        retry_at: Option<Instant>,
    },
}

/// What saving the settings keeps between steps. Everything but the line is about when.
pub(super) struct Saving {
    source: OnceLock<Saves>,
    timing: Mutex<SettingsTiming>,
    /// The earliest moment a step may reach the service for the settings again. Read and moved
    /// only through a [`Step`].
    eligible: Mutex<Option<Instant>>,
    line: Mutex<SettingsLine>,
    /// When a step is next wanted, if one is.
    wanted: Mutex<Option<Instant>>,
    wake: Notify,
    stopped: AtomicBool,
    /// How many changes to the settings file saving has been told of.
    changes: AtomicU64,
    /// What the page is told when a step that ran by itself ended.
    told: Told,
}

/// What saving is given: where the settings come from, and whether the writer's level lets it write.
struct Saves {
    source: Arc<dyn SettingsSource>,
    open: bool,
}

impl Saving {
    pub(super) fn new() -> Self {
        Self {
            source: OnceLock::new(),
            timing: Mutex::new(SettingsTiming::PRODUCT),
            eligible: Mutex::new(None),
            line: Mutex::new(SettingsLine::Waiting),
            wanted: Mutex::new(None),
            wake: Notify::new(),
            stopped: AtomicBool::new(false),
            changes: AtomicU64::new(0),
            told: Told::default(),
        }
    }

    fn timing(&self) -> SettingsTiming {
        *self.timing.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn line(&self) -> SettingsLine {
        *self.line.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn say(&self, line: SettingsLine) -> SettingsLine {
        *self.line.lock().unwrap_or_else(PoisonError::into_inner) = line;
        line
    }

    /// How many changes to the settings file saving has been told of: a step reads this before it
    /// reads the file.
    pub(super) fn changes(&self) -> u64 {
        self.changes.load(Ordering::SeqCst)
    }

    /// Notes a change to the settings file. What the bundle holds is not what the file holds now,
    /// so the line shows nothing until a step has ended after the change.
    fn changed(&self) {
        let mut line = self.line.lock().unwrap_or_else(PoisonError::into_inner);
        self.changes.fetch_add(1, Ordering::SeqCst);
        *line = SettingsLine::Waiting;
    }

    /// Says `line`, except that "saved" is not said when the settings file changed since `seen`: the
    /// change came while the step ran, and what the step saved does not hold it.
    fn say_after(&self, line: SettingsLine, seen: u64) -> SettingsLine {
        let mut held = self.line.lock().unwrap_or_else(PoisonError::into_inner);
        let said = if line == SettingsLine::Saved && self.changes.load(Ordering::SeqCst) != seen {
            SettingsLine::Waiting
        } else {
            line
        };
        *held = said;
        said
    }

    /// What this computer has chosen now, when saving has a source: the settings a first bundle
    /// carries.
    pub(super) fn chosen_now(&self) -> Option<LocalSettings> {
        self.writer().map(|source| source.chosen())
    }

    /// The source of what a step may write: none until saving has a source, and none while the
    /// writer's level is closed.
    fn writer(&self) -> Option<&Arc<dyn SettingsSource>> {
        self.source
            .get()
            .filter(|saves| saves.open)
            .map(|saves| &saves.source)
    }

    /// What saving is given, whether or not the writer's level is open.
    fn given(&self) -> Option<&Saves> {
        self.source.get()
    }

    /// Whether the writer's level lets saving write or remove the member.
    pub(super) fn is_open(&self) -> bool {
        self.writer().is_some()
    }

    /// The deadline, read while a step holds the lock.
    fn eligible_at(&self, _step: &Step<'_>) -> Option<Instant> {
        *self.eligible.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Moves the deadline to `until` while a step holds the lock. It never moves back.
    pub(super) fn moved_to(&self, _step: &Step<'_>, until: Instant) {
        let mut eligible = self.eligible.lock().unwrap_or_else(PoisonError::into_inner);
        *eligible = Some(eligible.map_or(until, |held| held.max(until)));
    }

    /// Notes that a write of the bundle carried the settings: they are saved, and the next step
    /// that reaches the service for them waits a window.
    pub(super) fn wrote_settings(&self, step: &Step<'_>, seen: u64) {
        self.window_from_now(step);
        self.say_after(SettingsLine::Saved, seen);
    }

    /// Moves the deadline one window on from now, and says when that is.
    pub(super) fn window_from_now(&self, step: &Step<'_>) -> Instant {
        let until = Instant::now() + self.timing().window;
        self.moved_to(step, until);
        until
    }

    /// Wants a step at `at`, or sooner if one is wanted sooner.
    pub(super) fn want_at(&self, at: Instant) {
        let mut wanted = self.wanted.lock().unwrap_or_else(PoisonError::into_inner);
        *wanted = Some(wanted.map_or(at, |held| held.min(at)));
        drop(wanted);
        self.wake.notify_one();
    }

    /// Wants a step now.
    pub(super) fn want_now(&self) {
        self.want_at(Instant::now());
    }

    /// Wants a step once the settings have been quiet for [`SettingsTiming::quiet`]: each change
    /// moves the moment out again.
    fn want_after_quiet(&self) {
        let at = Instant::now() + self.timing().quiet;
        *self.wanted.lock().unwrap_or_else(PoisonError::into_inner) = Some(at);
        self.wake.notify_one();
    }

    /// When a step is wanted, if one is.
    fn due(&self) -> Option<Instant> {
        *self.wanted.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the want, if it is due, so that a want made while the step runs is a want of its own.
    fn take_if_due(&self) -> bool {
        let mut wanted = self.wanted.lock().unwrap_or_else(PoisonError::into_inner);
        if wanted.is_some_and(|at| at <= Instant::now()) {
            *wanted = None;
            true
        } else {
            false
        }
    }
}

impl Recovery {
    /// Gives saving a source for what this computer has chosen, and the oldest level this release
    /// retains. Nothing is saved before it has a source, or while that level is below
    /// [`SETTINGS_READ_FROM`].
    pub fn save_settings_from(
        &self,
        source: Arc<dyn SettingsSource>,
        oldest_retained: CompatibilityLevel,
    ) {
        let _ = self.saving.source.set(Saves {
            source,
            open: oldest_retained >= SETTINGS_READ_FROM,
        });
    }

    /// When the bundle was last written, if it holds saved settings now: a read of the service.
    ///
    /// This is what is stored, not what a step may write, so it does not depend on the writer's
    /// level: a member that a later build wrote is listed. A computer with no kept record has
    /// nothing to ask and lists nothing. One that cannot use the account now was not asked, which
    /// is no answer, so it fails with why and never lists nothing.
    ///
    /// # Errors
    ///
    /// Refuses when the account cannot be used at the service the record names, and returns a
    /// failure to read the bundle.
    pub async fn saved_settings_listed(&self, account: &Account) -> Result<Option<TimestampMs>> {
        let _step = self.step().await?;
        let Some(record) = self.record()?.filter(|record| record.kept) else {
            return Ok(None);
        };
        refuse_if_blocked(account, &record.origin()?, Named::ByListing)?;
        let seed = self.seed(false)?;
        let mut store = self.store(&record, account)?;
        let bundle = store.fetch(&seed).await.map_err(said)?;
        Ok(bundle
            .device_settings
            .is_some()
            .then_some(bundle.written_at_ms))
    }

    /// Takes the saved settings out of the bundle, and turns saving them off first.
    ///
    /// The stop is kept before anything is sent, so a step that had already begun finds it under
    /// the lock and writes nothing back. The member alone leaves: the bundle, its keys and every
    /// other entry stay. A removal whose answer never came back is [`SettingsRemoved::Unconfirmed`]
    /// and is not reported as done; the next step ends the write.
    ///
    /// # Errors
    ///
    /// Refuses when the bundle holds no saved settings, and returns what the write fails with.
    pub async fn remove_saved_settings(&self, account: &Account) -> Result<SettingsRemoved> {
        let _step = self.step().await?;
        let Some(mut record) = self.record()?.filter(|record| record.kept) else {
            return Err(CommandError::invalid(NO_SAVED_SETTINGS));
        };
        refuse_if_blocked(account, &record.origin()?, Named::ByRemoval)?;
        let seed = self.seed(false)?;
        if !record.settings_stopped {
            record.settings_stopped = true;
            self.keep(&record)?;
        }
        let mut store = self.store(&record, account)?;
        match store.remove_settings(&seed, now()).await {
            Ok(_) => Ok(SettingsRemoved::Removed),
            Err(RecoveryError::BundleOutcomeUnknown { .. }) => Ok(SettingsRemoved::Unconfirmed),
            Err(other) => Err(said(other)),
        }
    }

    /// Turns the saving of the settings on again, after the person removed them. A step is wanted
    /// now, and the line shows nothing until it has ended.
    ///
    /// # Errors
    ///
    /// Returns a failure to read or keep this computer's recovery record.
    pub async fn resume_saving_settings(&self, account: &Account) -> Result<RecoveryView> {
        let _step = self.step().await?;
        if let Some(mut record) = self.record()?.filter(|record| record.settings_stopped) {
            record.settings_stopped = false;
            self.keep(&record)?;
        }
        self.saving.say(SettingsLine::Waiting);
        self.saving.want_now();
        self.view_of(account)
    }

    /// Tells saving the settings file changed. The line shows nothing until a step has ended after
    /// the change, the page is told so, and a step is wanted once the settings have been quiet.
    pub fn settings_changed(&self) {
        self.saving.changed();
        self.saving.want_after_quiet();
        self.saving.told.tell();
    }

    /// Wants a step now: the application started, or a recovery step has reached the service.
    pub fn settings_wanted(&self) {
        self.saving.want_now();
    }

    /// What telling the page does when a step that ran by itself ended: where recovery stands may
    /// have changed, and the page reads it again.
    #[must_use]
    pub fn told(&self) -> &Told {
        &self.saving.told
    }

    /// Sets the times saving waits, for a test that cannot wait out the application's.
    #[cfg(feature = "testing")]
    pub fn set_settings_timing(&self, timing: SettingsTiming) {
        *self
            .saving
            .timing
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = timing;
    }

    /// Ends the loop that runs the steps. A test that starts the application again ends the old
    /// one's loop first, so that two never share a directory.
    pub fn stop_saving_settings(&self) {
        self.saving.stopped.store(true, Ordering::SeqCst);
        self.saving.wake.notify_one();
    }

    /// Runs the steps that are wanted, each when it is due, until [`Self::stop_saving_settings`].
    /// `account` says which account a step uses; one that cannot be had now is a step not run.
    pub async fn keep_settings_saved<F, Fut>(&self, account: F)
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Arc<Account>>>,
    {
        loop {
            if self.saving.stopped.load(Ordering::SeqCst) {
                return;
            }
            let Some(at) = self.saving.due() else {
                self.saving.wake.notified().await;
                continue;
            };
            if at > Instant::now() {
                tokio::select! {
                    () = tokio::time::sleep_until(at.into()) => {}
                    () = self.saving.wake.notified() => continue,
                }
            }
            if !self.saving.take_if_due() {
                continue;
            }
            let Ok(account) = account().await else {
                continue;
            };
            match self.save_settings(&account).await {
                Ok(SettingsStep::Deferred { until }) => self.saving.want_at(until),
                Ok(SettingsStep::Ended {
                    retry_at: Some(at), ..
                }) => self.saving.want_at(at),
                Ok(_) | Err(_) => {}
            }
            // Whatever the step came to, it may have ended a write or moved the line, and nobody
            // asked for it: the page reads recovery again.
            self.saving.told.tell();
        }
    }

    /// One step of saving the settings: see the module's account of the order.
    ///
    /// # Errors
    ///
    /// Returns nothing a person has to act on: a failure is the line's, and the step says when to
    /// try again.
    pub async fn save_settings(&self, account: &Account) -> Result<SettingsStep> {
        let Ok(step) = self.step().await else {
            return Ok(self.failed(NotSavedWhy::Records, None));
        };
        match self.save_settings_under(&step, account).await {
            Ok(done) => Ok(done),
            // A step that failed before it asked the service for the settings does not move the
            // deadline: the failure is not a write, and a person's change should not wait out a
            // window for it.
            Err(why) => {
                let retry = Instant::now() + self.saving.timing().window;
                Ok(self.failed(why, Some(retry)))
            }
        }
    }

    fn failed(&self, why: NotSavedWhy, retry_at: Option<Instant>) -> SettingsStep {
        SettingsStep::Ended {
            line: self.saving.say(SettingsLine::NotSaved { why }),
            retry_at,
        }
    }

    async fn save_settings_under(
        &self,
        step: &Step<'_>,
        account: &Account,
    ) -> std::result::Result<SettingsStep, NotSavedWhy> {
        let Some(saves) = self.saving.given() else {
            return Ok(SettingsStep::Idle);
        };
        let mut record = match self.record() {
            Ok(Some(record)) => record,
            Ok(None) => return Ok(SettingsStep::Idle),
            Err(_) => return Err(NotSavedWhy::Records),
        };
        let origin = record.origin().map_err(|_| NotSavedWhy::Records)?;
        if blocker(account, &origin).is_some() {
            return Ok(SettingsStep::Idle);
        }
        let mut store = self
            .store(&record, account)
            .map_err(|_| NotSavedWhy::Records)?;
        // Any write whose answer never came back is ended first, whoever sent it and the first
        // write of all too: nothing else can be written until it is, and a step that can end it
        // should not leave it to a person. Ending it fences a request and reads a bundle and writes
        // no member, so the writer's level does not bind it, and the seed is read only when there
        // is a write to end or a member to write. A service that cannot be asked leaves it
        // outstanding, which the card says.
        let outstanding = matches!(store.lost_write(), Some(LostWrite::Unsettled { .. }));
        if !outstanding && !(saves.open && record.kept) {
            return Ok(SettingsStep::Idle);
        }
        let seed = self.seed(false).map_err(|_| NotSavedWhy::Seed)?;
        if outstanding {
            match store.end_lost_write(&seed).await {
                // The first write of all landed: recovery is on, as when the person settles it.
                Ok(Some(LostWrite::Applied)) if !record.kept => {
                    record.kept = true;
                    self.keep(&record).map_err(|_| NotSavedWhy::Records)?;
                }
                Ok(_) => {}
                Err(_) => return Err(NotSavedWhy::Service),
            }
        }
        // Only then the writer's level, and the first write of all that did not land: a step has
        // nothing to write for either.
        if !saves.open || !record.kept {
            return Ok(SettingsStep::Idle);
        }
        // Then: a person who turned saving off has the member taken out and nothing written back,
        // by a step of whichever trigger had already begun.
        if record.settings_stopped {
            return Ok(SettingsStep::Ended {
                line: self.saving.say(SettingsLine::Stopped),
                retry_at: None,
            });
        }
        if let Some(until) = self
            .saving
            .eligible_at(step)
            .filter(|until| *until > Instant::now())
        {
            return Ok(SettingsStep::Deferred { until });
        }
        let seen = self.saving.changes();
        let outcome = store
            .save_settings(&seed, saves.source.chosen(), now())
            .await;
        let (line, reached, retry) = match outcome {
            Ok(SettingsSaved::AlreadySaved) => (SettingsLine::Saved, false, false),
            Ok(SettingsSaved::Saved { .. }) => (SettingsLine::Saved, true, false),
            // The step's own write got no answer: it is ended now, and counts as saved only if the
            // service says it landed.
            Err(RecoveryError::BundleOutcomeUnknown { .. }) => {
                match store.end_lost_write(&seed).await {
                    Ok(Some(LostWrite::Applied)) => (SettingsLine::Saved, true, false),
                    _ => (not_saved(NotSavedWhy::Service), true, true),
                }
            }
            Err(RecoveryError::BundleConflict { .. }) => {
                (not_saved(NotSavedWhy::Moved), true, true)
            }
            Err(RecoveryError::SettingsDoNotFit { .. }) => {
                (not_saved(NotSavedWhy::NoRoom), true, false)
            }
            Err(RecoveryError::SettingsUnusable { .. }) => {
                (not_saved(NotSavedWhy::SettingsFile), false, false)
            }
            Err(RecoveryError::BundleNotAuthentic) => (not_saved(NotSavedWhy::Bundle), true, false),
            Err(RecoveryError::Service(_)) => (not_saved(NotSavedWhy::Service), true, true),
            Err(error) => {
                tracing::warn!(%error, "the settings were not saved with the recovery bundle");
                return Ok(SettingsStep::Ended {
                    line: self.saving.say(SettingsLine::Waiting),
                    retry_at: None,
                });
            }
        };
        let moved = reached.then(|| self.saving.window_from_now(step));
        Ok(SettingsStep::Ended {
            line: self.saving.say_after(line, seen),
            retry_at: if retry { moved } else { None },
        })
    }
}

const fn not_saved(why: NotSavedWhy) -> SettingsLine {
    SettingsLine::NotSaved { why }
}
