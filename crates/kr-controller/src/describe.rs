//! Session names and descriptions, as this daemon answers them.
//!
//! Section 23 gives two methods: `session.describe`, *an authorised read of filtered metadata, not
//! an arbitrary model-control method*, and `session.rename`, the pinned name a person sets. Both
//! are answered here from the environment's session-metadata store, which section 24 names as the
//! owner of names, pins and generated-description provenance: `descriptions.sqlite3` in the
//! daemon's state directory. This daemon maps no model, so what it answers is a pin, the
//! deterministic title, or a generated description the store already holds.
//!
//! * **A pin wins, and generated text never replaces one.** The store refuses to record generated
//!   text for a pinned session, and the precedence is the store's: a pin, then generated text, then
//!   the deterministic title.
//! * **Generated text is filtered before it leaves.** It is answered only while privacy mode is
//!   off, only when it was produced under the generation in force, and only to a caller whose
//!   history reaches the whole session: a description can summarise anything the session did, so a
//!   grant that reaches back only part of the way is answered the pin or the deterministic title.
//! * **Privacy mode shows metadata titles from the moment it is published.** Each read decides
//!   under the environment's published state, held from the reading to the decision, so a change
//!   of privacy mode waits for a read in progress and no generated text is decided after it; while
//!   the state says private no generated text is read at all. The privacy hook then removes every
//!   generated description and keeps every pin.
//! * **A rename answers the pin, or the deterministic title after a clearing, never generated
//!   text.** Its answer is kept with the action's claim so a retry is answered from it, where
//!   privacy mode's removal does not reach, and a caller may rename a session it may not view;
//!   generated text is `session.describe`'s, under its own right and filter.
//! * **A pin outlives its session.** It is in the environment's store, not the session's journal,
//!   so a session's closure and a daemon's restart leave it where it is.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use kr_describe::budget::Budgets;
use kr_describe::metadata::{LabelSource, SessionFacts, Title, deterministic_title};
use kr_describe::store::{DescriptionStore, GeneratedRecord};
use kr_protocol::describe::{
    DescriptionFreshness, DescriptionPause, DescriptionProvenance, DescriptionState,
    MAX_SESSION_TITLE_CODEPOINTS, SessionDescribeResult, SessionRenameResult,
};
use kr_protocol::ids::SessionId;
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use kr_worker::privacy::{
    Cancelled, Fenced, KeptExplicitly, PrivacyGeneration, PrivacySubsystem, Removed, Unavailable,
};

use crate::error::{ControllerError, Result};
use crate::privacy::{Admitted, PrivacyState, Published};

pub(crate) mod assets;
#[cfg(feature = "testing")]
pub mod hooks;
pub(crate) mod host;
mod link;

#[cfg(feature = "testing")]
pub use host::Figures;

/// How far back a caller's authority reaches into one session's history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryReach {
    /// All of it: the local owner, or a grant that reaches back to the session's start.
    WholeSession,
    /// Less than all of it, or no history at all.
    Partial,
}

impl HistoryReach {
    /// Returns a paired device's reach under its grant.
    ///
    /// The whole session only when the grant's history lower bound is at or before a known session
    /// start. A grant with no lower bound retains no history, and a session whose start is not known
    /// cannot be shown to lie inside the grant, so neither reaches the whole session.
    #[must_use]
    pub fn of_grant(
        lower_bound_ms: Option<TimestampMs>,
        session_started_at_ms: Option<TimestampMs>,
    ) -> Self {
        match (lower_bound_ms, session_started_at_ms) {
            (Some(bound), Some(started)) if bound.get() <= started.get() => Self::WholeSession,
            _ => Self::Partial,
        }
    }
}

/// The session-metadata store, as this daemon serves it.
#[derive(Debug)]
pub struct DescribeModule {
    store: Mutex<DescriptionStore>,
    /// The thread that runs the description service, once the daemon has started it. Until then,
    /// and in a module opened on its own, nothing is generated and every session is shown as it was
    /// before: a pin, or its deterministic title.
    host: OnceLock<Arc<host::DescribeHost>>,
    /// The tasks that read each session's facts from its worker.
    links: link::Links,
    /// The fetch of the model's files, when one runs.
    fetches: assets::Fetches,
    /// Where this crate's own tests stop a read.
    #[cfg(test)]
    pub(crate) pauses: Pauses,
}

/// The places in a read, a rename or a setting that this crate's own tests stop it at.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct Pauses {
    /// A rename, about to take the store: everything it waits for is still ahead of it.
    pub(crate) before_store: crate::attention::Pause,
    /// With the store held, before the privacy state is read.
    pub(crate) before_reading: crate::attention::Pause,
    /// With the store and the privacy state held, before the answer is decided.
    pub(crate) before_decision: crate::attention::Pause,
    /// A configuration change, holding the edit lock with its edit ready, about to ask whether the
    /// admission still stands.
    pub(crate) before_configuration: crate::attention::Pause,
}

/// What one session is shown as.
struct Shown {
    title: Title,
    source: LabelSource,
    generated: Option<GeneratedRecord>,
}

impl DescribeModule {
    /// Opens the environment's session-metadata store in `state_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be opened.
    pub fn open(state_dir: &Path) -> Result<Self> {
        Ok(Self {
            store: Mutex::new(
                DescriptionStore::open(state_dir).map_err(ControllerError::registry)?,
            ),
            host: OnceLock::new(),
            links: link::Links::default(),
            fetches: assets::Fetches::default(),
            #[cfg(test)]
            pauses: Pauses::default(),
        })
    }

    /// Returns the host that runs the description service, once it has been started.
    pub(crate) fn host(&self) -> Option<&Arc<host::DescribeHost>> {
        self.host.get()
    }

    /// What the host has done, for this crate's own tests: none when no host runs.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn figures(&self) -> Option<host::Figures> {
        self.host().map(|host| host.snapshot().figures)
    }

    /// Applies the owner's settings, as the configuration document says them: the host takes them
    /// at its next turn, and turning descriptions off also stops a fetch of the model's files, as
    /// it stops every other piece of work in flight. Every acceptance of the document comes here,
    /// whether the daemon wrote it or the owner edited it by hand.
    pub(crate) fn apply_settings(&self, settings: kr_describe::resource::ResourceSettings) {
        if let Some(host) = self.host() {
            host.settings(Some(settings.enabled), Some(settings.on_battery));
        }
        if !settings.enabled {
            self.fetches.cancel();
        }
    }

    /// Wakes the host, for this crate's own tests that change what it reads.
    #[cfg(feature = "testing")]
    pub fn wake(&self) {
        self.wake_host();
    }

    /// What setup shows: the host's own account of it, or that this host generates nothing.
    pub(crate) fn setup(
        &self,
        settings: kr_describe::resource::ResourceSettings,
    ) -> kr_protocol::describe::DescriptionSetup {
        let on_battery = settings.on_battery;
        use kr_describe::service::DownloadProgress;
        use kr_protocol::describe::DescriptionDownload;

        let published = self
            .host()
            .filter(|host| host.runs())
            .map(|host| host.snapshot());
        let Some((snapshot, setup)) = published
            .as_ref()
            .and_then(|snapshot| snapshot.setup.as_ref().map(|setup| (snapshot, setup)))
        else {
            return kr_protocol::describe::DescriptionSetup {
                offered: false,
                enabled: false,
                on_battery,
                profile_id: Nullable::null(),
                asset_bytes: U64::new(0),
                sources: Vec::new(),
                download: DescriptionDownload::NotStarted,
                fetched_bytes: U64::new(0),
                failure: Nullable::null(),
                can_cancel: false,
                can_disable: true,
                needs_hosted_account: false,
                unavailable: Nullable::some(
                    "this host's daemon is not generating descriptions".to_owned(),
                ),
                state: DescriptionState::ResourcePaused,
                paused: Nullable::some(DescriptionPause::NoModelHere),
            };
        };
        let (download, fetched_bytes, failure) = match &setup.progress {
            DownloadProgress::NotStarted => (DescriptionDownload::NotStarted, 0, None),
            DownloadProgress::Running { fetched_bytes, .. } => {
                (DescriptionDownload::Running, *fetched_bytes, None)
            }
            DownloadProgress::Verified => (DescriptionDownload::Verified, setup.asset_bytes, None),
            DownloadProgress::Cancelled => (DescriptionDownload::Cancelled, 0, None),
            DownloadProgress::Failed { why } => (DescriptionDownload::Failed, 0, Some(why.clone())),
        };
        kr_protocol::describe::DescriptionSetup {
            offered: setup.offered,
            enabled: settings.enabled,
            on_battery,
            profile_id: Nullable(setup.profile_id.clone()),
            asset_bytes: U64::new(setup.asset_bytes),
            sources: setup.sources.clone(),
            download,
            fetched_bytes: U64::new(fetched_bytes),
            failure: Nullable(failure),
            can_cancel: setup.can_cancel,
            can_disable: setup.can_disable,
            needs_hosted_account: setup.needs_hosted_account,
            unavailable: Nullable(setup.unavailable.clone()),
            state: snapshot.state.unwrap_or(DescriptionState::ResourcePaused),
            paused: Nullable(snapshot.paused),
        }
    }

    /// What the diagnostics say of descriptions: whether this host generates them, and what it is
    /// waiting for when it is not.
    pub(crate) fn doctor_check(
        &self,
        settings: &kr_describe::resource::ResourceSettings,
    ) -> kr_protocol::hostinfo::DoctorCheck {
        use kr_protocol::hostinfo::export::Sentence;
        use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};

        let published = self
            .host()
            .filter(|host| host.runs())
            .map(|host| host.snapshot());
        let (status, detail, fix): (_, _, Option<&str>) = match published {
            None => (
                DoctorStatus::NotApplicable,
                Sentence::new().stated("this daemon is not generating session descriptions"),
                None,
            ),
            Some(_) if !settings.enabled => (
                DoctorStatus::NotApplicable,
                Sentence::new().stated("descriptions are off; every session shows its title from metadata"),
                Some("kr host descriptions --on turns them on."),
            ),
            Some(snapshot) => match snapshot.paused {
                Some(DescriptionPause::NotDownloaded) => (
                    DoctorStatus::Warning,
                    Sentence::new().stated("the model's files are not on this host, so titles come from metadata"),
                    Some("kr host descriptions --download fetches them; the size is shown first."),
                ),
                Some(DescriptionPause::InferenceFailed) => (
                    DoctorStatus::Warning,
                    Sentence::new().stated("the description process failed three times running and is left alone for a while"),
                    Some("Titles come from metadata meanwhile; the process is tried again by itself."),
                ),
                Some(pause) => (
                    DoctorStatus::Ok,
                    Sentence::new()
                        .stated("inference is paused for ")
                        .stated(pause_word(pause))
                        .stated(" and resumes by itself"),
                    None,
                ),
                None => (
                    DoctorStatus::Ok,
                    Sentence::new()
                        .stated("generating descriptions; ")
                        .number(snapshot.figures.jobs.published)
                        .stated(" published since this daemon started"),
                    None,
                ),
            },
        };
        DoctorCheck::new(
            "descriptions",
            "Session descriptions are generated on this host, or say why not",
            status,
            detail,
            fix,
        )
    }

    /// Records the host the daemon started, once. Says whether it was the first.
    pub(crate) fn set_host(&self, host: Arc<host::DescribeHost>) -> std::result::Result<(), ()> {
        self.host.set(host).map_err(drop)
    }

    /// Starts reading one session's facts at its worker, for the host given.
    pub(crate) fn watch_links(
        &self,
        controller: std::sync::Weak<crate::service::Controller>,
        host: &Arc<host::DescribeHost>,
        worker: crate::directory::KnownWorker,
    ) {
        self.links.watch(controller, host, worker);
    }

    /// Stops reading one session's facts.
    pub(crate) fn stop_links(&self, session_id: SessionId) {
        self.links.stop(session_id);
    }

    /// Wakes the host, when there is one: something it reads has changed.
    pub(crate) fn wake_host(&self) {
        if let Some(host) = self.host() {
            host.wake();
        }
    }

    /// The store, held: everything that reads or writes it on this module's connection takes this
    /// first.
    ///
    /// A rename writes to it under an admission while holding the connection table, so a write
    /// that waits on the file's own lock waits with every other admission behind it. The
    /// description host writes through a connection of its own to the same file, under privacy
    /// mode's admission at the generation of what it publishes, and the store's removals take the
    /// write lock before they read, so a writer waits on the file's lock rather than failing and
    /// what a removal read is what it removes.
    pub(crate) fn store(&self) -> MutexGuard<'_, DescriptionStore> {
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Answers `session.describe`: the title to show and where it came from, filtered.
    ///
    /// `facts` are the host's own metadata for the session, which the deterministic title is built
    /// from; `reach` is how far the caller's authority reaches into the session's history; and
    /// `privacy` is the environment's published state. It is read once the store is held and held
    /// until the answer is decided, so a change of privacy mode waits for this read: the answer is
    /// decided wholly before the change is published, or after it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read. A store that
    /// cannot be read is not answered as a session with no pin.
    pub fn describe(
        &self,
        session_id: SessionId,
        facts: &SessionFacts,
        reach: HistoryReach,
        privacy: &PrivacyState,
    ) -> Result<SessionDescribeResult> {
        let shown = {
            let store = self.store();
            #[cfg(test)]
            self.pauses.before_reading.wait();
            let reading = privacy.reading();
            #[cfg(test)]
            self.pauses.before_decision.wait();
            self.shown(&store, session_id, facts, reach, reading.published())?
        };
        let generated = shown.generated.as_ref();
        // What the host last published, when it runs. Without one this daemon tracks no context
        // revision and runs no model, so it cannot say that a description it holds is current: it
        // says the conservative thing rather than implying current text.
        let published = self
            .host()
            .filter(|host| host.runs())
            .map(|host| host.snapshot());
        let standing = published
            .as_ref()
            .and_then(|snapshot| snapshot.sessions.get(&session_id).copied());
        let (state, paused, cadence_ms) = match &published {
            Some(snapshot) => (
                snapshot.state.unwrap_or(DescriptionState::ResourcePaused),
                snapshot.paused,
                snapshot.cadence_ms,
            ),
            None => (
                DescriptionState::ResourcePaused,
                Some(DescriptionPause::NoModelHere),
                Budgets::DEFAULTS.session_cooldown_ms,
            ),
        };
        Ok(SessionDescribeResult {
            session_id,
            title: shown.title.as_str().to_owned(),
            source: protocol_source(shown.source),
            activity_text: Nullable(generated.map(|record| record.activity.as_str().to_owned())),
            // A row from before this host started is from an earlier daemon, whose context
            // revisions say nothing about this one's: it is shown as stale until a newer
            // description replaces it.
            freshness: match (generated, standing) {
                (Some(record), Some(standing)) => {
                    let earlier = published
                        .as_ref()
                        .is_some_and(|snapshot| record.produced_at_ms < snapshot.started_wall_ms);
                    if earlier {
                        DescriptionFreshness::Stale
                    } else {
                        standing.freshness
                    }
                }
                (Some(_), None) => DescriptionFreshness::Stale,
                (None, _) => DescriptionFreshness::None,
            },
            provenance: Nullable(generated.map(|record| DescriptionProvenance {
                profile_id: record.profile_id.clone(),
                profile_revision: U64::new(record.profile_revision.get()),
                context_revision: U64::new(record.revision.get()),
                source_cursor_from: U64::new(record.cursor.from),
                source_cursor_to: U64::new(record.cursor.to),
                produced_at_ms: TimestampMs::new(record.produced_at_ms),
            })),
            queued_age_ms: Nullable(
                standing
                    .and_then(|standing| standing.queued_age_ms)
                    .map(U64::new),
            ),
            last_success_ms: Nullable(
                generated.map(|record| TimestampMs::new(record.produced_at_ms)),
            ),
            cadence_ms: U64::new(cadence_ms),
            state,
            paused: Nullable(paused),
        })
    }

    /// Answers `session.rename`: pins `title`, or clears the pin when it is `None`, and says what
    /// the session is shown as afterwards: the pin, or the deterministic title.
    ///
    /// A title is checked before anything is written: at most
    /// [`MAX_SESSION_TITLE_CODEPOINTS`] codepoints as given, rather than cut short, and something
    /// to show once control characters and runs of spaces are removed. The store is written under
    /// `admitted` once it is held, so the admission is asked after every wait and stands until the
    /// write is done. A pin is kept while privacy mode is on: it is a name somebody chose, and it
    /// is theirs until they clear it.
    ///
    /// The answer never carries generated text. It is kept with the action's claim so that a
    /// retry is answered from it, where privacy mode's removal does not reach, and the right to
    /// rename a session is not the right to view it; generated text is read with
    /// [`Self::describe`], filtered for whoever asks.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] for a title that is too long or empty, the
    /// admission's refusal, and [`ControllerError::RegistryUnavailable`] when the store cannot be
    /// read or written.
    pub fn rename(
        &self,
        session_id: SessionId,
        title: Option<&str>,
        pinned_by: &str,
        facts: &SessionFacts,
        now_ms: TimestampMs,
        admitted: Admitted<'_>,
    ) -> Result<SessionRenameResult> {
        let pinned = match title {
            Some(text) => {
                let codepoints = text.chars().count();
                if codepoints > MAX_SESSION_TITLE_CODEPOINTS as usize {
                    return Err(ControllerError::InvalidArgument(format!(
                        "a session name is at most {MAX_SESSION_TITLE_CODEPOINTS} characters, and \
                         this one has {codepoints}"
                    )));
                }
                Some(Title::new(text).ok_or_else(|| {
                    ControllerError::InvalidArgument(
                        "a session name has something to show once control characters and extra \
                         spaces are removed"
                            .to_owned(),
                    )
                })?)
            }
            None => None,
        };
        #[cfg(test)]
        self.pauses.before_store.wait();
        let store = self.store();
        admitted(&mut || match &pinned {
            Some(title) => store
                .pin(&session_id, title, pinned_by, now_ms.get())
                .map_err(ControllerError::registry),
            None => store
                .clear_pin(&session_id)
                .map(|_| ())
                .map_err(ControllerError::registry),
        })?;
        let shown = match store
            .pinned(&session_id)
            .map_err(ControllerError::registry)?
        {
            Some(pin) => (pin.title, LabelSource::Pinned, true),
            None => (deterministic_title(facts), LabelSource::Metadata, false),
        };
        Ok(SessionRenameResult {
            session_id,
            title: shown.0.as_str().to_owned(),
            source: protocol_source(shown.1),
            pinned: shown.2,
        })
    }

    /// Decides what one session is shown as: its pin, else generated text the caller may see,
    /// else the deterministic title.
    fn shown(
        &self,
        store: &DescriptionStore,
        session_id: SessionId,
        facts: &SessionFacts,
        reach: HistoryReach,
        privacy: Published,
    ) -> Result<Shown> {
        if let Some(pin) = store
            .pinned(&session_id)
            .map_err(ControllerError::registry)?
        {
            return Ok(Shown {
                title: pin.title,
                source: LabelSource::Pinned,
                generated: None,
            });
        }
        // While private nothing generated is read at all, and a caller whose history does not
        // reach the whole session is not shown a summary of it.
        let generated = if !privacy.private && reach == HistoryReach::WholeSession {
            store
                .generated(&session_id)
                .map_err(ControllerError::registry)?
                .filter(|record| record.generation == privacy.generation)
        } else {
            None
        };
        Ok(match generated {
            Some(record) => Shown {
                title: record.title.clone(),
                source: LabelSource::Generated,
                generated: Some(record),
            },
            None => Shown {
                title: deterministic_title(facts),
                source: LabelSource::Metadata,
                generated: None,
            },
        })
    }

    /// Returns privacy mode's hook over this store.
    #[must_use]
    pub const fn privacy(&self) -> DescriptionsPrivacy<'_> {
        DescriptionsPrivacy { module: self }
    }
}

/// The metadata a session's deterministic title is built from, as this daemon holds it: the
/// session's display number and the directory its root shell started in.
///
/// This daemon knows neither the repository nor the foreground application's name, so neither is
/// given, and a title is never guessed from what it does not hold.
#[must_use]
pub fn facts_of(summary: &kr_protocol::session::SessionSummary) -> SessionFacts {
    SessionFacts {
        display_number: Some(summary.display_number),
        directory: Path::new(&summary.cwd)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned),
        repository: None,
        application: None,
    }
}

impl crate::service::Controller {
    /// The session names and descriptions module, for this crate's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn descriptions(&self) -> &Arc<DescribeModule> {
        &self.descriptions
    }

    /// Performs `description.configure` or `description.download` under the admission it carries,
    /// and answers what setup shows afterwards.
    ///
    /// # Errors
    ///
    /// Returns the configuration's refusal, [`ControllerError::WindowExpired`] for an action that
    /// carries no freshness, and [`ControllerError::InvalidArgument`] for what this daemon does not
    /// serve.
    pub(crate) async fn description_write(
        self: &std::sync::Arc<Self>,
        method: kr_protocol::method::Method,
        mutation: &kr_protocol::envelope::MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<kr_protocol::envelope::ParamsValue> {
        use kr_protocol::method::Method;

        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not change a description setting"
                    .to_owned(),
            });
        }
        match method {
            Method::DescriptionConfigure => {
                let params: kr_protocol::describe::DescriptionConfigureParams = mutation
                    .params
                    .to_typed()
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
                // Admitted when the action was accepted, and asked again at the write: the
                // configuration's own waits are behind it by then, and the registration is held
                // standing until the document is written.
                self.apply_configuration_standing(
                    &kr_protocol::hostinfo::configuration::Change::Descriptions {
                        enabled: params.enabled.0,
                        on_battery: params.on_battery.0,
                    },
                    &|write| {
                        #[cfg(test)]
                        self.descriptions.pauses.before_configuration.wait();
                        self.under_registration(&carried, write)?
                    },
                )
                .await?;
                self.description_setup()
            }
            Method::DescriptionDownload => {
                let params: kr_protocol::describe::DescriptionDownloadParams = mutation
                    .params
                    .to_typed()
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
                let host = self
                    .descriptions
                    .host()
                    .filter(|host| host.runs())
                    .cloned()
                    .ok_or_else(|| ControllerError::Refused {
                        code: kr_protocol::error::ErrorCode::ResourceUnavailable,
                        detail: "this daemon is not generating descriptions".to_owned(),
                    })?;
                match params.action {
                    kr_protocol::describe::DescriptionDownloadAction::Start => {
                        self.start_fetch(&host, &carried).await?;
                    }
                    kr_protocol::describe::DescriptionDownloadAction::Cancel => {
                        self.descriptions.fetches.cancel();
                    }
                }
                self.description_setup()
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a mutation this daemon serves",
                method.as_str()
            ))),
        }
    }

    /// Starts the fetch of the selected profile's files, unless they are held or a fetch runs. The
    /// fetch begins only while the admission it was accepted under still stands.
    async fn start_fetch(
        self: &std::sync::Arc<Self>,
        host: &std::sync::Arc<host::DescribeHost>,
        carried: &crate::authority::AdmittedMutation,
    ) -> Result<()> {
        let Some(profile) = host.profile().cloned() else {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::ResourceUnavailable,
                detail: "this host has no model to fetch".to_owned(),
            });
        };
        if host.snapshot().setup.is_some_and(|setup| !setup.offered) {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::ResourceUnavailable,
                detail: "this host offers no model to fetch".to_owned(),
            });
        }
        // Files the host holds are not fetched again. A process that finds a file wrong at a load
        // makes the host lower its own record, so the next fetch starts from nothing; a fetch asked
        // for while the files are held changes nothing, and the answer says they are.
        if host.snapshot().figures.assets_held {
            return Ok(());
        }
        let proxy = self.started_proxy()?;
        let client = assets::client(proxy.as_ref())?;
        let taken = self.under_registration(carried, || {
            self.descriptions
                .fetches
                .start(std::sync::Arc::clone(host), profile, client)
        })?;
        // Waited for, so the answer that follows shows the fetch as running.
        if let Some(taken) = taken {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), taken).await;
        }
        Ok(())
    }

    /// Answers `description.setup`: what descriptions offer on this host, and what it costs, from
    /// what the description host last published. A host that runs none says so.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the answer cannot be encoded.
    pub(crate) fn description_setup(&self) -> Result<kr_protocol::envelope::ParamsValue> {
        // The settings are the document's, which the answer to a change that was just made must
        // already show; everything else is what the host last published.
        let answer = self.descriptions.setup(self.description_settings());
        kr_protocol::envelope::ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `session.describe` for one session, from its summary, to a caller whose history
    /// reaches `reach` into it, under the environment's privacy state as it stands now.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub(crate) async fn session_describe(
        &self,
        summary: kr_protocol::session::SessionSummary,
        reach: HistoryReach,
    ) -> Result<kr_protocol::envelope::ParamsValue> {
        let descriptions = std::sync::Arc::clone(&self.descriptions);
        let privacy = self.privacy.state();
        let answer = tokio::task::spawn_blocking(move || {
            descriptions.describe(summary.session_id, &facts_of(&summary), reach, &privacy)
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the session's name could not be read".to_owned(),
        })??;
        kr_protocol::envelope::ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Performs `session.rename` for `actor_id` under the admission it carries: pins the title,
    /// or clears the pin, and answers what the session is shown as afterwards, the pin or the
    /// deterministic title ([`DescribeModule::rename`]).
    ///
    /// The store is written under the admission once it is held: the admission is asked after
    /// every wait and held standing until the write is done.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::WindowExpired`] for an action that carries no freshness,
    /// [`ControllerError::InvalidArgument`] for a request that names another session than its
    /// target or a title that is too long or empty, the admission's refusal, and
    /// [`ControllerError::RegistryUnavailable`] when the store cannot be read or written.
    pub(crate) async fn session_rename(
        self: &std::sync::Arc<Self>,
        actor_id: &kr_protocol::ids::ActorId,
        mutation: &kr_protocol::envelope::MutationRequest,
        summary: kr_protocol::session::SessionSummary,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<kr_protocol::envelope::ParamsValue> {
        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not rename a session"
                    .to_owned(),
            });
        }
        let params: kr_protocol::describe::SessionRenameParams = mutation
            .params
            .to_typed()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        if params.session_id != summary.session_id {
            return Err(ControllerError::InvalidArgument(
                "a rename names the session it acts on, and this one names another".to_owned(),
            ));
        }
        let controller = std::sync::Arc::clone(self);
        let pinned_by = actor_id.as_str().to_owned();
        let now_ms = kr_ipc::now_ms();
        let answer = tokio::task::spawn_blocking(move || {
            controller.descriptions.rename(
                params.session_id,
                params.title.0.as_deref(),
                &pinned_by,
                &facts_of(&summary),
                now_ms,
                &|write| controller.under_registration(&carried, write)?,
            )
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the rename stopped before it could say what it did".to_owned(),
        })??;
        kr_protocol::envelope::ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }
}

/// Whether this module answers a method: the owner's two writes for descriptions. `description.setup`
/// is a read, served with the daemon's other reads.
#[must_use]
pub const fn serves(method: kr_protocol::method::Method) -> bool {
    matches!(
        method,
        kr_protocol::method::Method::DescriptionConfigure
            | kr_protocol::method::Method::DescriptionDownload
    )
}

/// The word a pause is reported under.
const fn pause_word(pause: DescriptionPause) -> &'static str {
    match pause {
        DescriptionPause::MemoryReserve => "the memory reserve",
        DescriptionPause::MemoryPressure => "memory pressure",
        DescriptionPause::Thermal => "heat",
        DescriptionPause::Battery => "battery power",
        DescriptionPause::SignalUnqualified => "a reading this host cannot take",
        DescriptionPause::Disabled => "the owner's setting",
        DescriptionPause::NoModelHere => "this environment, which runs no model",
        DescriptionPause::NotDownloaded => "the model's files",
        DescriptionPause::InferenceFailed => "repeated failures",
    }
}

/// Where the description process is and what the host reads, as the daemon places them.
pub(crate) struct Placement {
    pub(crate) program: std::path::PathBuf,
    pub(crate) environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    pub(crate) catalogue: kr_describe::profile::catalogue::Catalogue,
    pub(crate) clock: host::Clock,
    pub(crate) conditions: Option<Arc<Mutex<kr_describe::resource::HostConditions>>>,
    pub(crate) abandon: bool,
    pub(crate) free_space: Option<Arc<Mutex<Option<u64>>>>,
    pub(crate) stall: Option<Arc<Mutex<Option<std::time::Duration>>>>,
}

/// Maps where a title came from onto the protocol's word for it.
const fn protocol_source(source: LabelSource) -> kr_protocol::describe::LabelSource {
    match source {
        LabelSource::Pinned => kr_protocol::describe::LabelSource::Pinned,
        LabelSource::Metadata => kr_protocol::describe::LabelSource::Metadata,
        LabelSource::Generated => kr_protocol::describe::LabelSource::Generated,
    }
}

/// The session-metadata store as privacy mode sees it.
///
/// This daemon runs no model, so there is no queue to fence, no job to take back and nothing in
/// flight; reads stop showing generated text from the moment privacy mode is published, because
/// each decides under the published state. What is left is the removal: every generated
/// description goes, and every pin stays.
#[derive(Debug)]
pub struct DescriptionsPrivacy<'a> {
    module: &'a DescribeModule,
}

impl PrivacySubsystem for DescriptionsPrivacy<'_> {
    fn name(&self) -> &'static str {
        "descriptions"
    }

    fn fence(&mut self, generation: PrivacyGeneration) -> std::result::Result<Fenced, Unavailable> {
        // Every tracked session is fenced at once, and the job running for each is cancelled; a
        // module with no host has nothing running to stop.
        let cancelled = self
            .module
            .host()
            .filter(|host| host.runs())
            .map_or(0, |host| host.fence(generation));
        Ok(Fenced {
            queues: u64::from(self.module.host().is_some()),
            items: cancelled,
        })
    }

    fn cancel_undispatched(
        &mut self,
        _generation: PrivacyGeneration,
    ) -> std::result::Result<Cancelled, Unavailable> {
        // The queue is the host's memory, forgotten with the rest of it in `remove_retained`.
        Ok(Cancelled::default())
    }

    fn remove_retained(
        &mut self,
        _generation: PrivacyGeneration,
    ) -> std::result::Result<Removed, Unavailable> {
        // The rows go at once, through the module's own store. What the host holds in memory, its
        // queue and its contexts, goes with a purge it is asked to make and has a bound to make
        // it in; a host that has not finished is not a removal that has, and the caller asks
        // again. The purge is asked for whatever the store says: a queue that stays while a row
        // cannot be removed would keep a load running for a session that is private, so the
        // memory is forgotten whatever the store says, and the refused removal stays owed for the
        // next try.
        let removed = self.module.store().remove_generated();
        let purged = self.module.host().map_or(Ok(()), |host| host.purge());
        let removed = removed.map_err(|error| {
            Unavailable::new(format!(
                "generated descriptions could not be removed: {error}"
            ))
        })?;
        purged?;
        Ok(Removed {
            bytes: removed.bytes,
            records: removed.records,
        })
    }

    fn outstanding(&self) -> std::result::Result<u64, Unavailable> {
        Ok(self.module.host().map_or(0, |host| host.outstanding()))
    }

    fn kept(&self) -> Vec<KeptExplicitly> {
        vec![KeptExplicitly {
            what: "session names people pinned",
            why: "a name somebody chose is theirs, and section 24 keeps it until they clear it; it \
                  is excluded from sync while privacy mode is on",
        }]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use kr_describe::context::{ContextBinding, ContextRevision, CursorInterval};
    use kr_describe::metadata::{ActivityText, RepositoryFacts};
    use kr_describe::output::{GeneratedDescription, ProducedUnder};
    use kr_describe::profile::ProfileRevision;
    use kr_describe::store::Published as Recorded;
    use kr_protocol::describe::LabelSource as Shown;
    use kr_protocol::ids::SessionEpoch;
    use kr_protocol::scalars::Uuid;

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    /// What the host knows of the session: the repository its directory is inside.
    fn facts() -> SessionFacts {
        SessionFacts {
            repository: Some(RepositoryFacts {
                name: "kalareach".to_owned(),
                branch: Some("main".to_owned()),
            }),
            ..SessionFacts::default()
        }
    }

    /// A generated description produced under `generation`.
    pub(crate) fn generated(title: &str, generation: PrivacyGeneration) -> GeneratedDescription {
        GeneratedDescription {
            title: Title::new(title).expect("a title"),
            activity: ActivityText::new("Checks the code-entry flow").expect("activity text"),
            cursor: CursorInterval::new(3, 11),
            revision: ContextRevision::new(2),
            produced_under: ProducedUnder {
                session_epoch: SessionEpoch::V1,
                binding: ContextBinding::new("desktop-1/terminal/epoch-1"),
                context_revision: ContextRevision::new(2),
                cursor: CursorInterval::new(3, 11),
                profile_id: "minicpm".to_owned(),
                profile_revision: ProfileRevision::new(4),
                generation,
            },
        }
    }

    fn off() -> PrivacyState {
        PrivacyState::at(Published::default())
    }

    fn private(generation: u64) -> PrivacyState {
        PrivacyState::at(Published {
            generation: PrivacyGeneration::new(generation),
            private: true,
        })
    }

    /// An admission that stands: the write runs.
    fn standing(write: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        write()
    }

    /// The module over a store on the internal disk, and a second handle on the same store that
    /// stands in for whatever records generated text in it.
    fn module() -> (tempfile::TempDir, DescribeModule, DescriptionStore) {
        let root = tempfile::tempdir().expect("a directory on the internal disk");
        let module = DescribeModule::open(root.path()).expect("the session-metadata store");
        let other = DescriptionStore::open(root.path()).expect("the same store");
        (root, module, other)
    }

    /// KR-REQ-24.14: a pin that rename wrote is the environment's, not the session's, so it
    /// survives the session's closure and the daemon's restart.
    #[test]
    fn a_pin_that_rename_wrote_survives_the_sessions_closure() {
        let (root, module, _other) = module();
        let renamed = module
            .rename(
                session(1),
                Some("KalaReach pairing"),
                "local:501",
                &facts(),
                TimestampMs::new(1_000),
                &standing,
            )
            .expect("the name is pinned");
        assert_eq!(renamed.title, "KalaReach pairing");
        assert_eq!(renamed.source, Shown::Pinned);
        assert!(renamed.pinned);

        // The session closes and the daemon starts again: nothing of the session is left but
        // what the environment's store holds, and the pin is there.
        drop(module);
        let module = DescribeModule::open(root.path()).expect("the store opens again");
        let described = module
            .describe(session(1), &facts(), HistoryReach::Partial, &off())
            .expect("a read");
        assert_eq!(described.title, "KalaReach pairing");
        assert_eq!(described.source, Shown::Pinned);
        assert!(root.path().join("descriptions.sqlite3").exists());
    }

    /// KR-REQ-22.19: generated text never replaces a pin: not one recorded before the pin, and
    /// not one offered after it. Clearing the pin is the only thing that shows it again, and it is
    /// shown by describe: the rename's own answer is the deterministic title, never generated text.
    #[test]
    fn generated_text_never_replaces_a_pin() {
        let (_root, module, other) = module();
        other
            .publish(
                &session(1),
                &generated("Pairing check", PrivacyGeneration::INITIAL),
                900,
            )
            .expect("an earlier description");
        module
            .rename(
                session(1),
                Some("Release prep"),
                "local:501",
                &facts(),
                TimestampMs::new(1_000),
                &standing,
            )
            .expect("the name is pinned");
        assert_eq!(
            other
                .publish(
                    &session(1),
                    &generated("Something else", PrivacyGeneration::INITIAL),
                    1_100,
                )
                .expect("the offer is answered"),
            Recorded::NamePinned
        );
        let described = module
            .describe(session(1), &facts(), HistoryReach::WholeSession, &off())
            .expect("a read");
        assert_eq!(described.title, "Release prep");
        assert_eq!(described.source, Shown::Pinned);
        assert!(described.activity_text.0.is_none());

        let cleared = module
            .rename(
                session(1),
                None,
                "local:501",
                &facts(),
                TimestampMs::new(1_200),
                &standing,
            )
            .expect("the pin is cleared");
        assert!(!cleared.pinned);
        assert_eq!(cleared.source, Shown::Metadata);
        assert_eq!(cleared.title, "kalareach (main)");
        let described = module
            .describe(session(1), &facts(), HistoryReach::WholeSession, &off())
            .expect("a read");
        assert_eq!(described.source, Shown::Generated);
        assert_eq!(described.title, "Pairing check");
    }

    /// KR-REQ-22.17: while privacy mode is on, describe answers the metadata title and no
    /// generated text at all, from the moment the state is published; a pin is still shown.
    #[test]
    fn while_private_describe_answers_the_metadata_title_and_no_generated_text() {
        let (_root, module, other) = module();
        other
            .publish(
                &session(1),
                &generated("Pairing check", PrivacyGeneration::INITIAL),
                900,
            )
            .expect("a description");
        let open = module
            .describe(session(1), &facts(), HistoryReach::WholeSession, &off())
            .expect("a read");
        assert_eq!(open.source, Shown::Generated);
        assert!(open.provenance.0.is_some());

        let described = module
            .describe(
                session(1),
                &facts(),
                HistoryReach::WholeSession,
                &private(1),
            )
            .expect("a read");
        assert_eq!(described.source, Shown::Metadata);
        assert_eq!(described.title, "kalareach (main)");
        assert!(described.activity_text.0.is_none());
        assert!(described.provenance.0.is_none());
        assert!(described.last_success_ms.0.is_none());
        assert_eq!(described.freshness, DescriptionFreshness::None);
        assert_eq!(
            described.paused,
            Nullable::some(DescriptionPause::NoModelHere)
        );

        // Nothing generated is read while private, even a record carrying the generation in force,
        // which nothing should have produced while inference was off.
        other
            .publish(
                &session(1),
                &generated("Pairing check", PrivacyGeneration::new(1)),
                950,
            )
            .expect("a description under the private generation");
        let described = module
            .describe(
                session(1),
                &facts(),
                HistoryReach::WholeSession,
                &private(1),
            )
            .expect("a read");
        assert_eq!(described.source, Shown::Metadata);
        assert!(described.activity_text.0.is_none());

        module
            .rename(
                session(1),
                Some("Release prep"),
                "local:501",
                &facts(),
                TimestampMs::new(1_000),
                &standing,
            )
            .expect("a name is pinned while private");
        let described = module
            .describe(
                session(1),
                &facts(),
                HistoryReach::WholeSession,
                &private(1),
            )
            .expect("a read");
        assert_eq!(described.source, Shown::Pinned);
        assert_eq!(described.title, "Release prep");
    }

    /// Generated text reaches only a caller whose history covers the whole session, and only when
    /// it was produced under the generation in force.
    #[test]
    fn generated_text_reaches_only_a_caller_whose_history_covers_the_whole_session() {
        let started = Some(TimestampMs::new(10_000));
        assert_eq!(
            HistoryReach::of_grant(Some(TimestampMs::new(9_000)), started),
            HistoryReach::WholeSession
        );
        assert_eq!(
            HistoryReach::of_grant(Some(TimestampMs::new(10_000)), started),
            HistoryReach::WholeSession
        );
        assert_eq!(
            HistoryReach::of_grant(Some(TimestampMs::new(10_001)), started),
            HistoryReach::Partial,
            "a grant that begins after the session did sees only part of it"
        );
        assert_eq!(
            HistoryReach::of_grant(None, started),
            HistoryReach::Partial,
            "a grant with no lower bound retains no history"
        );
        assert_eq!(
            HistoryReach::of_grant(Some(TimestampMs::new(9_000)), None),
            HistoryReach::Partial,
            "a session whose start is not known is not shown to lie inside the grant"
        );

        let (_root, module, other) = module();
        other
            .publish(
                &session(1),
                &generated("Pairing check", PrivacyGeneration::new(2)),
                900,
            )
            .expect("a description");
        let at = |generation: u64| {
            PrivacyState::at(Published {
                generation: PrivacyGeneration::new(generation),
                private: false,
            })
        };
        let partial = module
            .describe(session(1), &facts(), HistoryReach::Partial, &at(2))
            .expect("a read");
        assert_eq!(partial.source, Shown::Metadata);
        assert!(partial.activity_text.0.is_none());
        let whole = module
            .describe(session(1), &facts(), HistoryReach::WholeSession, &at(2))
            .expect("a read");
        assert_eq!(whole.source, Shown::Generated);
        assert_eq!(whole.title, "Pairing check");
        assert_eq!(whole.freshness, DescriptionFreshness::Stale);
        let later = module
            .describe(session(1), &facts(), HistoryReach::WholeSession, &at(3))
            .expect("a read");
        assert_eq!(
            later.source,
            Shown::Metadata,
            "a description from another generation is not this one's"
        );
    }

    /// A name longer than a title may be is refused rather than cut short, and so is one with
    /// nothing to show; neither changes what was pinned before.
    #[test]
    fn rename_refuses_a_name_too_long_or_empty_and_keeps_the_pin_it_had() {
        let (_root, module, _other) = module();
        let rename = |title: &str| {
            module.rename(
                session(1),
                Some(title),
                "local:501",
                &facts(),
                TimestampMs::new(1_000),
                &standing,
            )
        };
        rename("Release prep").expect("a name is pinned");
        let longest = "a".repeat(64);
        assert!(rename(&longest).is_ok(), "sixty-four characters is a name");
        rename("Release prep").expect("a name is pinned");
        let too_long = "é".repeat(65);
        assert!(matches!(
            rename(&too_long),
            Err(ControllerError::InvalidArgument(_))
        ));
        assert!(matches!(
            rename("\u{202e}\u{0007}   "),
            Err(ControllerError::InvalidArgument(_))
        ));
        let described = module
            .describe(session(1), &facts(), HistoryReach::WholeSession, &off())
            .expect("a read");
        assert_eq!(described.title, "Release prep");
    }

    /// Privacy mode's hook removes every generated description and keeps every pin.
    #[test]
    fn the_privacy_hook_removes_every_generated_description_and_keeps_every_pin() {
        let (_root, module, other) = module();
        for byte in 1..=3 {
            other
                .publish(
                    &session(byte),
                    &generated("Pairing check", PrivacyGeneration::INITIAL),
                    900,
                )
                .expect("a description");
        }
        module
            .rename(
                session(2),
                Some("Release prep"),
                "local:501",
                &facts(),
                TimestampMs::new(1_000),
                &standing,
            )
            .expect("a name is pinned");
        let removed = module
            .privacy()
            .remove_retained(PrivacyGeneration::new(1))
            .expect("the removal");
        assert_eq!(removed.records, 3);
        assert_eq!(other.generated_count().expect("a count"), 0);
        assert_eq!(other.pin_count().expect("a count"), 1);
        assert_eq!(module.privacy().outstanding(), Ok(0));
        assert!(!module.privacy().kept().is_empty());
    }

    /// The store is written under the admission once it is held: a rename whose admission lapses
    /// while it waits for the store writes nothing, and leaves the pin it found.
    #[test]
    fn a_rename_whose_admission_lapses_while_it_waits_for_the_store_writes_nothing() {
        let (_root, module, other) = module();
        module
            .rename(
                session(1),
                Some("Release prep"),
                "local:501",
                &facts(),
                TimestampMs::new(1_000),
                &standing,
            )
            .expect("a name is pinned");
        let lapsed = std::sync::atomic::AtomicBool::new(false);
        let admitted = |write: &mut dyn FnMut() -> Result<()>| {
            if lapsed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ControllerError::WindowExpired {
                    detail: "the action's deadline passed".to_owned(),
                });
            }
            write()
        };
        let (arrived, release) = module.pauses.before_store.arm();
        std::thread::scope(|scope| {
            let renaming = scope.spawn(|| {
                module.rename(
                    session(1),
                    None,
                    "device:phone",
                    &facts(),
                    TimestampMs::new(2_000),
                    &admitted,
                )
            });
            // The rename is running and about to take the store, which somebody else then holds:
            // the wait it goes on to is entered by a thread that has been seen to arrive.
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the rename arrives at the store");
            let held = module.store();
            release.send(()).expect("the rename goes on");
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(!renaming.is_finished(), "the rename waits for the store");
            lapsed.store(true, std::sync::atomic::Ordering::SeqCst);
            drop(held);
            let refused = renaming.join().expect("the rename ends");
            assert!(
                matches!(refused, Err(ControllerError::WindowExpired { .. })),
                "{refused:?}"
            );
        });
        assert_eq!(
            other
                .pinned(&session(1))
                .expect("a read")
                .map(|pin| pin.title.as_str().to_owned()),
            Some("Release prep".to_owned()),
            "the pin it found is still there"
        );
    }
}
