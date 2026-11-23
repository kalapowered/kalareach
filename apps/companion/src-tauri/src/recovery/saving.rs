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
//! answer never came back (a cover's too, so a person is never asked to settle what a step can
//! end); ends if the person turned saving off; ends if the one eligibility deadline has not
//! passed; reads the settings file now, never a value captured earlier; fetches the bundle,
//! compares, and writes. A write of the step's own that gets no answer is ended at once. The line
//! the page shows says "saved" only after a write the service confirmed or a read of the bundle
//! that holds the same settings.
//!
//! There is one eligibility deadline for the process. It is read and moved only while a step holds
//! the lock ([`Step`] is the proof), it is a monotonic instant, and it only moves forward. A step
//! that reaches the service for the settings and does not find them saved moves it to the end of
//! the next [`SettingsTiming::window`], so this process makes at most one such step per window. A
//! step that finds the deadline ahead makes no request and tells the loop when to try again, so a
//! change made during the window is kept scheduled and not dropped. Two processes on one computer
//! take turns under the lock, so the stated limit is one write per process per window; the bundle's
//! compare-and-swap is the real guard.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use kr_client::recovery::{LocalSettings, LostWrite, RecoveryError, SettingsSaved};
use serde::Serialize;

use super::{Recovery, Step, blocker, now};
use crate::account::Account;
use crate::error::Result;

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

/// What one step came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsStep {
    /// Nothing to do, and nothing was asked of the service: saving has no source, recovery is not
    /// on, or the account cannot be used now.
    Idle,
    /// The eligibility deadline is ahead, so nothing was asked of the service. The step is wanted
    /// again at `until`.
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
    source: OnceLock<Arc<dyn SettingsSource>>,
    timing: Mutex<SettingsTiming>,
    /// The earliest moment a step may reach the service for the settings again. Read and moved
    /// only through a [`Step`].
    eligible: Mutex<Option<Instant>>,
    line: Mutex<SettingsLine>,
}

impl Saving {
    pub(super) fn new() -> Self {
        Self {
            source: OnceLock::new(),
            timing: Mutex::new(SettingsTiming::PRODUCT),
            eligible: Mutex::new(None),
            line: Mutex::new(SettingsLine::Waiting),
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

    /// What this computer has chosen now, when saving has a source: the settings a first bundle
    /// carries.
    pub(super) fn chosen_now(&self) -> Option<LocalSettings> {
        self.source.get().map(|source| source.chosen())
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
    pub(super) fn wrote_settings(&self, step: &Step<'_>) {
        self.window_from_now(step);
        self.say(SettingsLine::Saved);
    }

    /// Moves the deadline one window on from now, and says when that is.
    pub(super) fn window_from_now(&self, step: &Step<'_>) -> Instant {
        let until = Instant::now() + self.timing().window;
        self.moved_to(step, until);
        until
    }
}

impl Recovery {
    /// Gives saving a source for what this computer has chosen. Nothing is saved before it has one.
    pub fn save_settings_from(&self, source: Arc<dyn SettingsSource>) {
        let _ = self.saving.source.set(source);
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
        let Some(source) = self.saving.source.get() else {
            return Ok(SettingsStep::Idle);
        };
        let record = match self.record() {
            Ok(Some(record)) if record.kept => record,
            Ok(_) => return Ok(SettingsStep::Idle),
            Err(_) => return Err(NotSavedWhy::Records),
        };
        let origin = record.origin().map_err(|_| NotSavedWhy::Records)?;
        if blocker(account, &origin).is_some() {
            return Ok(SettingsStep::Idle);
        }
        let seed = self.seed(false).map_err(|_| NotSavedWhy::Seed)?;
        let mut store = self
            .store(&record, account)
            .map_err(|_| NotSavedWhy::Records)?;
        // Any write whose answer never came back is ended first, whoever sent it: nothing else
        // can be written until it is, and a step that can end it should not leave it to a person.
        // A service that cannot be asked leaves it outstanding, which the card says.
        if matches!(store.lost_write(), Some(LostWrite::Unsettled { .. }))
            && store.end_lost_write(&seed).await.is_err()
        {
            return Err(NotSavedWhy::Service);
        }
        // Only then: a person who turned saving off has the member taken out and nothing written
        // back, by a step of whichever trigger had already begun.
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
        let outcome = store.save_settings(&seed, source.chosen(), now()).await;
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
            line: self.saving.say(line),
            retry_at: if retry { moved } else { None },
        })
    }
}

const fn not_saved(why: NotSavedWhy) -> SettingsLine {
    SettingsLine::NotSaved { why }
}
