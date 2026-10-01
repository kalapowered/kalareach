//! Starting the daemon: the lock, the generation, the clocks and what a start sweeps.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::identity::BootIdentity;
use kr_protocol::ids::{BootEpoch, BuildId, CapabilityRevision, EnvironmentId, SessionId};
use kr_protocol::session::ClosureReason;
use kr_transport::window::ActionWindowIssuer;
use tokio::sync::Mutex;

use crate::desktop::power::Inhibitor;
use crate::directory::Directory;
use crate::error::{ControllerError, Result};
use crate::registry::{LaunchPhase, Registry};
use crate::singleton::SingletonLock;
use crate::supervision::{JobRetirement, WorkerSupervisor};

use super::barrier::{DEBT_PASS_INTERVAL, Debts, PassSchedule, Published, Reach};
use super::capabilities::{DesktopReading, capability_revision, resolved_desktop};
use super::inhibition::DemandScan;
use super::{Clocks, Controller, net};

#[cfg(any(feature = "testing", test))]
use super::ReadPause;

/// How long a daemon's start spends looking at the worker jobs its environment still has defined.
///
/// Each job takes launchd a few milliseconds to answer for, so this is room for hundreds of them. A
/// launchd that has stopped answering costs a start this long, and the bounded questions about the
/// job in hand when it runs out, rather than the start; the jobs not reached are looked at again by
/// the next one.
pub const JOB_SWEEP_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// How often privacy mode's record retries what it owes and tells each worker it owes a notice.
pub const PRIVACY_TICK: std::time::Duration = std::time::Duration::from_secs(1);

/// How long one worker is given to take a privacy generation and answer.
///
/// A generation that turns privacy mode on waits, in the worker, for the attention store to stop
/// releasing the session's text and for the text leases already out to end: two seconds and one
/// lease at most. The rest is the session's own cleanup.
const PRIVACY_EXCHANGE: std::time::Duration = std::time::Duration::from_secs(15);

/// The file this environment's current boot identity is recorded in.
///
/// It lives in the state directory rather than the runtime one because it has to outlive the boot
/// it names, and a runtime directory does not.
pub const BOOT_FILE: &str = "boot";

/// The longest boot record this host reads.
const BOOT_FILE_LIMIT: u64 = 1_024;

impl Controller {
    /// Starts the description host and the reading of every session's facts, once, at the daemon's
    /// start: the host takes the owner's settings from the configuration document, finds the
    /// description process beside the daemon, and tracks every session the directory holds.
    ///
    /// A host that cannot start leaves the daemon serving pins and deterministic titles, as one
    /// without descriptions does: descriptions are never what stops a daemon.
    pub(crate) async fn start_descriptions(self: &std::sync::Arc<Self>) {
        let settings = self.description_settings();
        let state_dir = self.paths.state_dir().to_path_buf();
        let placed = self.description_placement(&state_dir);
        let setup = crate::describe::host::Setup {
            environment_id: self.paths.environment_id(),
            launch: kr_describe::supervise::Launch {
                program: placed.program,
                arguments: vec![
                    "--runtime-dir".into(),
                    self.paths.runtime_dir().as_os_str().to_owned(),
                ],
                working_directory: state_dir.clone(),
                environment: placed.environment,
                models: crate::describe::host::models_dir(&state_dir),
            },
            state_dir,
            build: self.build_id.as_str().to_owned(),
            catalogue: placed.catalogue,
            settings,
            clock: placed.clock,
            privacy: self.privacy.state(),
            conditions: placed.conditions,
            abandon: placed.abandon,
        };
        let started =
            tokio::task::spawn_blocking(move || crate::describe::host::DescribeHost::start(setup))
                .await;
        let host = match started {
            Ok(Ok(host)) => host,
            Ok(Err(error)) => {
                eprintln!("kr-controller: descriptions are not generated on this host: {error}");
                return;
            }
            Err(_) => return,
        };
        if self.descriptions.set_host(host).is_err() {
            return;
        }
        let workers: Vec<crate::directory::KnownWorker> =
            self.directory.lock().await.iter().cloned().collect();
        for worker in workers {
            self.describe_worker(&worker);
        }
    }

    /// Starts tracking one session the directory holds, and reading its facts.
    pub(crate) fn describe_worker(&self, worker: &crate::directory::KnownWorker) {
        let Some(host) = self.descriptions.host().cloned() else {
            return;
        };
        let descriptor = &worker.descriptor;
        host.session_opened(
            descriptor.session_id,
            descriptor.session_epoch,
            kr_describe::context::ContextBinding::new(format!(
                "display-{}/epoch-{}",
                descriptor.display_number.get(),
                descriptor.session_epoch.get()
            )),
        );
        self.descriptions
            .watch_links(self.me.clone(), &host, worker.clone());
    }

    /// Tells the description host a session closed, and stops reading its facts.
    pub(crate) fn describe_session_closed(&self, session_id: SessionId) {
        self.descriptions.stop_links(session_id);
        if let Some(host) = self.descriptions.host() {
            host.session_closed(session_id);
        }
    }

    /// The owner's settings for descriptions, as the configuration document now says them: each
    /// is on, or off for battery, unless the document chooses otherwise.
    pub(crate) fn description_settings(&self) -> kr_describe::resource::ResourceSettings {
        let resolver = self.configuration();
        let loaded = resolver.loaded();
        let section = loaded
            .document
            .as_ref()
            .map(|document| &document.descriptions);
        kr_describe::resource::ResourceSettings {
            enabled: section
                .and_then(|section| section.enabled())
                .unwrap_or(true),
            on_battery: section
                .and_then(|section| section.on_battery())
                .unwrap_or(false),
            ..kr_describe::resource::ResourceSettings::default()
        }
    }

    /// Where the description process is, what it is told, which profiles it may choose from, and
    /// the clock and conditions the host reads: the shipped ones, unless a test placed others.
    fn description_placement(&self, state_dir: &std::path::Path) -> crate::describe::Placement {
        #[cfg(feature = "testing")]
        if let Some(hooked) = crate::describe::hooks::placement_for(state_dir) {
            return hooked;
        }
        let _ = state_dir;
        crate::describe::Placement {
            program: self.worker_program.parent().map_or_else(
                || std::path::PathBuf::from("kr-describe-inference"),
                |directory| directory.join("kr-describe-inference"),
            ),
            environment: Vec::new(),
            catalogue: kr_describe::profile::catalogue::Catalogue::builtin()
                .unwrap_or_else(|_| unreachable!("this build ships profiles it can run")),
            clock: crate::describe::host::Clock::default(),
            conditions: None,
            abandon: false,
        }
    }

    /// Starts the daemon: takes the lock, advances the generation and rebuilds the directory.
    ///
    /// # Errors
    ///
    /// Returns an error when another daemon owns the environment, the registry cannot be opened,
    /// or the controller identity is missing.
    pub async fn start(setup: ControllerSetup) -> Result<Arc<Self>> {
        Self::start_with(setup, Clocks::system()).await
    }

    /// Starts the daemon on the clocks a test gives it, by the same path [`Self::start`] takes on
    /// the machine's own.
    ///
    /// # Errors
    ///
    /// As [`Self::start`].
    #[cfg(feature = "testing")]
    pub async fn start_on_clocks(setup: ControllerSetup, clocks: Clocks) -> Result<Arc<Self>> {
        Self::start_with(setup, clocks).await
    }

    async fn start_with(setup: ControllerSetup, clocks: Clocks) -> Result<Arc<Self>> {
        Self::start_passing(setup, clocks, PassSchedule::every(DEBT_PASS_INTERVAL)).await
    }

    /// The one start, with the schedule its debt pass keeps.
    pub(super) async fn start_passing(
        setup: ControllerSetup,
        clocks: Clocks,
        passes: PassSchedule,
    ) -> Result<Arc<Self>> {
        let Clocks {
            continuous: clock,
            wall,
        } = clocks;
        setup.paths.create()?;
        // The lock comes before everything the environment owns: the registry's own creation and
        // migration, the persistent identity, the generation and the directory. Two daemons
        // starting together would otherwise both run the schema creation, and both find an empty
        // key store, and the loser would overwrite the key every live worker recorded at spawn.
        let mut lock = SingletonLock::acquire(&setup.paths.singleton_lock(), setup.environment_id)?;
        let mut registry = Registry::open(setup.paths.registry_database(), setup.environment_id)?;
        let generation = lock.advance(&mut registry)?;
        // The configured session number, intersected with what this machine's resources allow,
        // becomes the number admission enforces. Only when the document actually names one: a
        // document that says nothing, and one this build cannot read, must not lift a restriction
        // the owner accepted through some other path.
        let startup_configuration = crate::config::open(&setup.paths);
        // A document on disk is not evidence that this host ever acted on it. An edit is written
        // before its effects run, so a daemon that stopped in between leaves a file nothing has
        // been done about, and a file edited while no daemon was running is the same case. The
        // durable record is the only thing that says which document this environment accepted:
        // anything else is an edit this host has not seen yet, and it goes through acceptance
        // below rather than being taken for a fact.
        let durably_accepted = registry.accepted_configuration()?;
        let accepted_document = crate::config::from_record(durably_accepted.document.as_deref());
        let unaccepted = accepted_document != startup_configuration.loaded().document;
        // The document whose effects are in force, which is the one the record holds and not the
        // one on disk. What an edit owes is the difference between the two, so a daemon that seeded
        // itself from the file would derive nothing from a ceiling somebody removed while it was
        // not running, and would fence nothing.
        // The rights ceiling this environment accepted is in force from the first request, before
        // any acceptance below runs: it is what the fences recorded against it were raised for.
        let rights_ceiling = accepted_document
            .as_ref()
            .and_then(|document| crate::config::ceilings::configured_rights(&document.ceilings));
        // So are the enrolment budgets it accepted. A startup reading that loaded a document
        // replaces them below, by the session number's rule; one that decided nothing leaves them.
        let accepted_budgets = accepted_document
            .as_ref()
            .map(|document| crate::config::catalogue::budgets(&document.ceilings));
        let mut accepted_configuration = crate::config::AcceptedState {
            revision: durably_accepted.revision,
            document: accepted_document,
            sessions: registry.session_limit()?,
        };
        if let Some(limit) = crate::config::session_limit_in_force(
            &startup_configuration,
            crate::config::HardLimits {
                sessions_per_environment: None,
            },
        ) {
            registry.set_session_limit(limit)?;
            accepted_configuration.sessions = limit;
        }
        let sessions_in_force = accepted_configuration.sessions;
        let in_force = crate::config::InForce::of(&startup_configuration);
        let startup_budgets = crate::config::catalogue::budgets_in_force(&startup_configuration);
        // The network and the voice broker come from this same reading, and from nothing a
        // process inherited: section 26 keeps a provider origin out of reach of an environment
        // variable. They apply for as long as this daemon runs.
        let started = crate::config::Started::of(startup_configuration.loaded().document.as_ref());
        drop(startup_configuration);
        let identity = (setup.identity)()?;
        let boot_epoch = kr_ipc::identity::boot_epoch(&setup.boot_identity)?;
        let boot = setup.boot_identity.clone();
        let paths = setup.paths.clone();
        let recorded_revision = capability_revision(&paths);
        let started_at_ms = kr_ipc::now_ms();
        let authority_revision = registry.authority_revision()?;
        let transfer = Arc::new(crate::transfer::TransferModule::open(&setup.paths).await?);
        let project = Arc::new(crate::project::ProjectModule::open(&setup.paths).await?);
        // The catalogue fetches through the proxy this daemon started with, the endpoint's own,
        // and asks this generation's member set what the workers hold before it makes room.
        let plugin_bridge = Arc::new(crate::catalogue::bridge::WorkerBridge::new(generation));
        // The budgets in force from the start, so the limits they set hold every package from
        // the catalogue's first check on.
        let catalogue = Arc::new(crate::catalogue::CatalogueModule::open(
            &setup.paths,
            Self::proxy_of(&started)?.as_ref(),
            Arc::clone(&plugin_bridge) as Arc<dyn kr_plugin_catalogue::BrokerBridge>,
            startup_budgets.or(accepted_budgets).unwrap_or_default(),
        )?);
        // The change-set service reads every repository through the project service's own opened
        // handles and restricted execution profile, so it takes that service rather than opening
        // a second one.
        let changesets = Arc::new(
            crate::changeset::ChangeSetModule::open(&setup.paths, Arc::clone(project.service()))
                .await?,
        );
        // Opening the backup store migrates it and touches the disk, so it runs on a blocking
        // task rather than on the daemon's reactor, exactly as the two above do.
        let backup = {
            let paths = setup.paths.clone();
            Arc::new(
                tokio::task::spawn_blocking(move || {
                    crate::backup::BackupService::open(paths.state_dir())
                })
                .await
                .map_err(|_| ControllerError::RegistryUnavailable {
                    detail: "the backup service could not be opened".to_owned(),
                })??,
            )
        };
        // The executable the daemon was told to start, resolved here rather than at the launch: a
        // worker runs in a directory of its own, so a relative name would be looked for beneath
        // that instead of beneath the directory this daemon was started in. It is resolved before
        // the daemon is built, because what builds it cannot fail.
        let worker_program = kr_ipc::paths::resolve_here(setup.worker_program)?;
        // The grants and the invitations live in the daemon's own registry database, beside the
        // devices that hold them, so an authority object and the device it was issued to are in
        // one file and one backup.
        // This host's own device identity is derived from its environment, the same way the
        // network half derives it, so the feed speaks for the same host across restarts.
        let host_device_id = kr_protocol::ids::DeviceId::new(setup.environment_id.get());
        let sharing = Arc::new(crate::sharing::SharingService::new(
            crate::grants::GrantDirectory::open(setup.paths.registry_database())?,
            host_device_id,
        ));
        // The policy and the feed are read back from the store rather than rebuilt empty. A host
        // that came back unrestricted after every restart would be the same failure as one that
        // accepted a restored old policy, by a different route.
        let stored = match sharing.grants().stored_policy()? {
            Some(stored) => stored,
            None => crate::grants::HostPolicy::personal(authority_revision).snapshot(),
        };
        // The host's one reading of UTC in this boot, which every worker maps too. It is opened,
        // adopted or created here, before any worker is adopted or spawned, and it starts at least
        // where this host's record of it stands.
        let (floor_words, continuity_lost) = open_utc_floor(
            &mut registry,
            &setup.paths,
            setup.environment_id,
            boot_epoch,
            stored.utc_floor_ms.get(),
        )?;
        let utc_floor = Arc::new(crate::grants::policy::UtcFloor::on(
            floor_words,
            stored.utc_floor_ms.get(),
        ));
        if continuity_lost {
            utc_floor.lose_continuity();
        }
        let policy =
            crate::grants::HostPolicy::restore(&stored, authority_revision, Arc::clone(&utc_floor));
        // Written down again with the revision the registry reached. A start that cannot write it
        // still starts, with its floor owed its record: no decision that reads the clock is taken
        // until a write lands, and a personal grant that never expires is used as before. Stopping
        // instead would leave no daemon at all while the store is full.
        let snapshot = policy.snapshot();
        match sharing.grants().store_policy(&snapshot) {
            Ok(()) => utc_floor.wrote(snapshot.utc_floor_ms.get()),
            Err(error) => {
                eprintln!(
                    "kr-controller: could not write this host's policy at start, so no decision \
                     that reads the clock is taken until it can: {error}"
                );
                utc_floor.could_not_write();
            }
        }
        let policy = Arc::new(std::sync::Mutex::new(policy));
        let mut feed = match sharing.grants().stored_feed()? {
            Some(stored) => crate::grants::AuthorityFeed::restore(&stored),
            None => crate::grants::AuthorityFeed::new(host_device_id, authority_revision),
        };
        // The registry is the allocator. A feed restored below it would number its next entry with
        // a revision the registry has already used, and would report an old number as the one in
        // force.
        feed.note_revision(authority_revision);
        sharing.grants().store_feed(&feed.snapshot())?;
        let attention = Arc::new(crate::attention::AttentionModule::open(
            &setup.paths,
            setup.boot_identity.clone(),
        )?);
        let devices = Arc::new(net::devices::DeviceDirectory::open(
            setup.paths.registry_database(),
        )?);
        // The offline bound's time, taken as the policy holding it is restored and before anything
        // remote is decided under it: from what this boot recorded of it, advanced by the boot
        // clock, and never less than this host's reading of UTC says.
        let shared_clock: Arc<dyn kr_ipc::clock::SharedClock> =
            Arc::new(kr_ipc::clock::SystemSharedClock);
        // One record of every grant's lifetime, on this daemon's clocks. The network's connections
        // and the owner confirmations they spend ask it, and so does everything else here that
        // decides a grant's time, so no two parts of the host can disagree about one grant.
        let lifetimes = Arc::new(net::lifetimes::GrantLifetimes::new(
            Arc::clone(&devices),
            Arc::clone(&clock),
            Arc::clone(&shared_clock),
            setup.boot_identity.clone(),
            wall.clone(),
            Arc::clone(&utc_floor),
        ));
        // The store decides a grant's time bound at the moment of its effect, on this host's own
        // clocks, under the floor every other decision stands on and from the same anchors.
        sharing
            .grants()
            .bind_host_clock(crate::grants::store::HostClock {
                floor: Arc::clone(&utc_floor),
                wall: wall.clone(),
                lifetimes: Arc::clone(&lifetimes),
            });
        let offline_anchor = net::offline_anchor(
            policy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .offline_validity(),
            None,
            &lifetimes.anchor_sources(),
        )?;
        // A record for any other synchronisation is one a policy write never reached.
        if let Err(error) = devices
            .forget_offline_anchors_except(offline_anchor.map(|anchor| anchor.synchronised_at_ms()))
        {
            eprintln!("kr-controller: could not forget stale offline bound records: {error}");
        }
        // The offline bound's cell states both of its ends from here, before anything is decided
        // under it.
        {
            let policy = policy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            lifetimes.hold_offline_anchor(offline_anchor, &policy);
            net::publish_offline_bound(
                policy.offline_cell(),
                policy.offline_validity(),
                offline_anchor,
                clock.now(),
                utc_floor.get(),
            );
        }
        // The automation service carries out its change-set nodes through the change-set service,
        // so it takes that rather than opening anything of its own beside its journal. The grant
        // each definition names is read from the stores this daemon holds and decided under this
        // daemon's own model once the daemon exists, which is where it is bound below.
        let automation = Arc::new(
            crate::automation::AutomationModule::open(
                &setup.paths,
                setup.environment_id,
                Arc::clone(changesets.service()),
            )
            .await?,
        );
        let (initial_desktop, initial_evidence) = resolved_desktop(in_force.worker_profile, &boot);
        let opened_store = setup
            .secret_store
            .open(
                kr_ipc::verify::CONTROLLER_SECRET_SERVICE,
                &setup.paths.secrets_dir(),
            )
            .map_err(ControllerError::registry)?;
        let secret_store: Arc<dyn kr_crypto::store::SecretStore> = Arc::from(opened_store.store);
        let device_keys = net::host_device_keys(&*secret_store, setup.environment_id)?;
        // External destinations' credentials are kept in the same store as this host's own keys,
        // in a scope of their own, and never in the delivery journal.
        let delivery = Arc::new(crate::push::DeliveryModule::open(
            &setup.paths,
            device_keys.notification_preview,
            device_keys.stored_envelope,
            crate::push::secrets::DestinationSecrets::new(secret_store, setup.environment_id),
        )?);
        // The runtime is built here and started once the daemon exists. Its renewals are proven
        // with this host's own authorisation key, which the installation named when it authorised
        // the host, and an external message's authority is the grant its rule names.
        let delivery_runtime = crate::push::runtime::DeliveryRuntime::new(
            Arc::clone(&delivery),
            Arc::new(crate::push::credentials::HeldCredentials::new()),
            Arc::new(crate::push::authority::GrantedRecipients::new(
                Arc::clone(&sharing),
                Arc::clone(&policy),
                setup.environment_id,
                Arc::clone(&lifetimes),
            )),
            Arc::new(crate::push::sender::HostSigner::new(
                device_keys.authorisation,
            )),
            crate::push::runtime::Cadence::DEFAULT,
            tokio::runtime::Handle::current(),
        );
        // Privacy mode's record comes before anything the subsystems it drives do. It is read and
        // published into the delivery module's send gate here, and whatever it asks for is taken
        // through the backup service, the delivery journal and the descriptions again, before the
        // backup service reconciles, before the delivery runtime starts and before any route is
        // served. A record that cannot be read stops the start: a daemon that cannot say whether
        // privacy mode is on does not start as though it knew.
        let (privacy, descriptions) = {
            let state_dir = setup.paths.state_dir().to_path_buf();
            let backup = Arc::clone(&backup);
            let delivery = Arc::clone(&delivery);
            tokio::task::spawn_blocking(move || {
                let descriptions = Arc::new(crate::describe::DescribeModule::open(&state_dir)?);
                let privacy = crate::privacy::EnvironmentPrivacy::open(
                    &state_dir,
                    backup,
                    delivery,
                    Arc::clone(&descriptions),
                )?;
                // Whatever this reports is carried by the tick from here on.
                let _ = privacy.resume(kr_ipc::now_ms());
                Ok::<_, ControllerError>((Arc::new(privacy), descriptions))
            })
            .await
            .map_err(|_| ControllerError::RegistryUnavailable {
                detail: "the privacy record could not be opened".to_owned(),
            })??
        };
        let controller = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            registry: Mutex::new(registry),
            directory: Mutex::new(Directory::default()),
            connections: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(BTreeMap::new()),
            recovering: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            recovered: tokio::sync::Notify::new(),
            admitted: std::sync::Mutex::new(BTreeMap::new()),
            identity,
            secret_store: setup.secret_store,
            generation,
            paths: setup.paths,
            plugin_bridge,
            admissions_due: Arc::new(tokio::sync::Notify::new()),
            admission_notes: std::sync::Mutex::new(Vec::new()),
            integrations: Arc::new(crate::catalogue::integrations::Integrations::new()),
            accepted_configuration: Mutex::new(accepted_configuration),
            in_force: std::sync::Mutex::new(in_force),
            started,
            rights_ceiling: std::sync::Mutex::new(rights_ceiling),
            debts: Arc::new(std::sync::Mutex::new(Debts::default())),
            debt_pass: Arc::new(tokio::sync::Notify::new()),
            #[cfg(feature = "testing")]
            before_presentation_lock: crate::attention::Pause::default(),
            #[cfg(feature = "testing")]
            after_the_claim: ReadPause::default(),
            #[cfg(test)]
            before_the_record: ReadPause::default(),
            #[cfg(test)]
            before_the_pass_tells: ReadPause::default(),
            boot_identity: setup.boot_identity,
            boot_epoch,
            windows: ActionWindowIssuer::with_default_validity(Arc::clone(&clock) as Arc<_>),
            shared_clock,
            leases: crate::authority::AuthorityBarrier::new(generation, authority_revision),
            clock,
            wall,
            network: std::sync::OnceLock::new(),
            supervisor: setup.supervisor,
            backup,
            transfer,
            project,
            catalogue,
            sharing,
            voice: std::sync::OnceLock::new(),
            privacy,
            descriptions,
            delivery,
            delivery_runtime,
            devices,
            lifetimes,
            policy,
            authority_epoch: std::sync::atomic::AtomicU64::new(0),
            utc_floor,
            feed: std::sync::Mutex::new(feed),
            changesets,
            automation,
            sessions_in_force: std::sync::atomic::AtomicU64::new(sessions_in_force),
            attention,
            agent_tools: tokio::sync::Mutex::new(()),
            worker_program,
            build_id: setup.build_id,
            release: setup.release,
            started_at_ms,
            shell_packages: setup.shell_packages,
            terminal: Arc::from(setup.terminal),
            presentations: Mutex::new(std::collections::HashMap::new()),
            desktop: Mutex::new(DesktopReading {
                context: initial_desktop,
                evidence: initial_evidence,
                revision: recorded_revision.unwrap_or_else(|| CapabilityRevision::new(0)),
                durable_revision: recorded_revision.is_some(),
                records: Vec::new(),
                read_at: std::time::Instant::now(),
            }),
            inhibitor: Mutex::new(Inhibitor::new()),
            demand_scan: Mutex::new(DemandScan::default()),
            finalising: Mutex::new(()),
            handover: super::host::Handover::default(),
            _lock: lock,
        });
        // Bound before anything can reach the module: from here on a workflow's grant is decided
        // under this daemon's policy, its configured ceiling and its clock model, and a node's
        // change-set write is held under this daemon's registry.
        controller.automation.bind(Arc::downgrade(&controller));
        // Reconnecting is not only verifying. A replacement daemon has to present the generation it
        // advanced to, because that is what fences the daemon it replaced.
        let directory = {
            let registry = controller.registry.lock().await;
            Directory::rebuild(&controller.paths, &registry, &controller.reconnect()).await?
        };
        *controller.directory.lock().await = directory;
        // Every reservation whose claim was consumed and every recorded worker is a member of the
        // plugin admissions' set before anything is served, each pending until it reports.
        controller.seed_admission_members().await?;
        // A reboot ends every live execution, of either profile. Sessions published in an earlier
        // boot are closed with that as their reason before anything tries to recover them, so the
        // record says the host restarted rather than that a worker died for reasons unknown.
        controller.close_previous_boot().await?;
        controller.recover_reservations().await?;
        // Recovery has settled every reservation it can, so what is left under the workers
        // directory that no session claims is nothing's.
        controller.sweep_worker_dirs().await?;
        // Before this daemon serves anything, so no job a create of its own defines is looked at.
        controller.retire_ended_jobs().await;
        // The workers recovery reached are sent their admissions from here on, and every member
        // that is pending or not confirmed ended is asked about on a cadence.
        controller.start_admissions_cadence();
        // A fence this environment recorded and never saw answered is announced again, to the
        // workers this daemon has just reconnected to. The debt is durable, so a daemon that
        // stopped between raising a fence and hearing every answer comes back still owing it; the
        // announcement is how a worker that has since acknowledged, or since ended, settles it.
        if controller.registry.lock().await.fence_owed()?.is_some() {
            controller.announce_authority_revision().await?;
        }
        // Every fence debt on disk is owed a barrier: its restriction took effect before the stop,
        // or never will. They are published before anything is served, a barrier is raised for
        // them now, and the pass raises one again until it lands.
        {
            let owed = controller.sharing.grants().fence_owed()?;
            let mut debts = controller.debts();
            for debt in owed {
                debts.published.insert(
                    debt,
                    Published {
                        reach: Reach::Host,
                        covered: false,
                    },
                );
            }
        }
        if let Err(error) = controller.raise_owed_barrier().await {
            eprintln!(
                "kr-controller: the barrier this host owes from before it stopped could not be \
                 raised yet, so nothing is admitted or forwarded until it is: {error}"
            );
        }
        controller.start_debt_pass(passes);
        // A document this environment has not accepted is put through acceptance here rather than
        // left for whoever reads next. What it owes can include fencing dispatch, and work must not
        // be dispatched under an authority that a document already written on this disk withdrew.
        // Nothing here can fail the start: acceptance reports what it could not do in the value it
        // returns, the durable record is advanced only once every effect landed, and an acceptance
        // that got nowhere is attempted again by the next one.
        if unaccepted {
            let accepted = controller.accept_configuration().await;
            // A fence this document owes has to be up before anything can be dispatched under the
            // authority it withdrew, so a start that could not raise one does not go on to serve.
            // Failing to *record* an acceptance whose effects all landed is a different thing: the
            // effects are in force, and the next start derives them again.
            if !accepted.effects_applied {
                let problem = accepted
                    .not_in_force
                    .clone()
                    .unwrap_or_else(|| Sentence::new().stated("the reason was not recorded"));
                return Err(ControllerError::Configuration(format!(
                    "this environment's configuration document could not be put into force: \
                     {problem}"
                )));
            }
        }
        controller.start_voice();
        // Every session the attention store reads: the live ones over their workers, and the ones
        // whose closure an earlier daemon recorded and which the store has not finished yet.
        controller.start_attention().await;
        // And every session's facts for the descriptions, over the workers the directory holds.
        controller.start_descriptions().await;
        // Backup work an earlier daemon left unfinished is resolved before anything can add to it:
        // what is still authorised goes back in hand, what is not is cancelled, and a publication
        // that left this host and was never answered is recorded as unknown rather than guessed at.
        {
            let backup = Arc::clone(&controller.backup);
            let now_ms = kr_ipc::now_ms();
            tokio::task::spawn_blocking(move || backup.reconcile(now_ms))
                .await
                .map_err(|_| ControllerError::RegistryUnavailable {
                    detail: "the backup service could not be reconciled".to_owned(),
                })??;
        }
        // Delivery the same way: what an earlier daemon left on the wire becomes an outcome
        // nobody knows, and what is no longer authorised is taken back, before a pass can claim
        // anything. The loop then drives the outbox until the daemon goes.
        controller.delivery_runtime.start().await;
        // Privacy mode's tick from here on: what the record owes is retried, and each worker the
        // environment's generation has not reached yet is told it.
        controller.start_privacy_tick();
        // A key update that stopped between its two stores is finished here, from the one that
        // took it first. A daemon that cannot write its own device directory does not start as
        // though it had: the next start tries again, and nothing serves a device from a directory
        // behind the journal in the meantime.
        controller.recover_preview_keys()?;
        crate::transfer::serve(&controller)?;
        // The owner's setting is the owner's setting across a restart. A daemon that waited for a
        // client to ask before it looked would leave an enabled setting doing nothing until
        // somebody happened to run a command.
        let _ = controller.power_state().await;
        // The network comes up last. A paired device must not reach a daemon that has not yet
        // recovered its reservations and rebuilt its worker directory, because it would be told
        // that sessions this host is running do not exist. Registering it also lends the project
        // service this host's owner, its owner devices, for its location decisions.
        //
        // What it joins is the configuration document's network section, read when this daemon
        // started: a selection that cannot be used stops the start with its key named, rather than
        // leaving a host that looks up and cannot be reached.
        if let Some(setup) = net::NetworkSetup::from_configuration(
            &controller.started.network,
            &controller.paths,
            controller.secret_store(),
        )? {
            net::register(&controller, setup).await?;
        }
        // Unattended workflow execution starts last. The journal was recovered when the module
        // was opened, but nothing it holds runs until every gate above has passed, the
        // configuration put into force among them: a withdrawal it made may owe a fence that has
        // to be up before anything is dispatched, and a start that fails anywhere above executes
        // nothing at all.
        controller.automation.start();
        Ok(controller)
    }

    /// Starts privacy mode's tick, which runs until the daemon goes.
    ///
    /// The tick holds the daemon weakly, and holds it at all only while it reads the directory and
    /// the registry and while it reaches a worker's connection, which is bounded. The record's own
    /// work runs on a blocking task that holds only the record, and a worker is told over its
    /// connection alone, so a pass waiting for a blocking thread or for a worker's answer keeps
    /// nothing of the daemon, and nothing of its environment's lock.
    fn start_privacy_tick(self: &Arc<Self>) {
        let daemon = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(PRIVACY_TICK);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                if privacy_pass(&daemon).await.is_none() {
                    return;
                }
            }
        });
    }

    /// The proxy this host's outbound HTTPS goes through: the configuration document's
    /// `network.proxy_url` as this daemon read it when it started, or `None` when it named none.
    ///
    /// It is the reading the network endpoint was built from, so the endpoint, the rendezvous,
    /// delivery and the plugin catalogue never go through two different proxies, and an edit
    /// applies to all of them at the next start.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] naming `network.proxy_url` when the address it
    /// holds is not one this host can use as a proxy.
    pub fn started_proxy(&self) -> Result<Option<kr_transport::config::ProxyUrl>> {
        Self::proxy_of(&self.started)
    }

    /// The proxy `started` selects, read as the network endpoint reads it.
    fn proxy_of(
        started: &crate::config::Started,
    ) -> Result<Option<kr_transport::config::ProxyUrl>> {
        started
            .network
            .proxy_url()
            .map(|value| {
                value
                    .parse()
                    .map_err(|error: kr_transport::config::ProxyUrlError| {
                        ControllerError::InvalidArgument(format!(
                            "network.proxy_url in this host's configuration document ({}) is not \
                             usable: {error}",
                            kr_protocol::hostinfo::configuration::FILE_NAME
                        ))
                    })
            })
            .transpose()
    }

    /// Closes every session recorded in an earlier boot.
    ///
    /// A reboot ends the live executions of both profiles: a desktop-bound worker went with its
    /// login session and a headless one went with the machine. The record says the host restarted,
    /// which is what happened, rather than describing a worker that vanished.
    ///
    /// The boot this environment last ran in is kept in its own state directory, beside the
    /// registry, because that is the only place that survives what a reboot removes. A runtime
    /// directory does not: on most hosts it is cleared with the boot it belonged to, taking the
    /// published descriptors with it, so a daemon that compared descriptors would find nothing to
    /// compare after exactly the event it was looking for.
    async fn close_previous_boot(&self) -> Result<()> {
        let path = self.paths.state_dir().join(BOOT_FILE);
        let current = kr_cbor::to_canonical_vec(&self.boot_identity)
            .map_err(|error| ControllerError::registry(error.to_string()))?;
        let bytes = kr_ipc::paths::read_owner_only_file(&path, BOOT_FILE_LIMIT)?;
        // A host with no record has not run here before, so there is nothing of an earlier boot to
        // close. A record that is there and does not decode is a damaged file rather than a boot,
        // and closing live sessions on the strength of one would be closing them for no reason.
        // Either way the record is written again below.
        let recorded = bytes.as_deref().and_then(|bytes| {
            kr_cbor::from_canonical_slice::<kr_protocol::identity::BootIdentity>(
                bytes,
                &kr_cbor::Limits::DEFAULT,
            )
            .ok()
        });
        if recorded.is_some_and(|recorded| recorded != self.boot_identity) {
            let rows = {
                let registry = self.registry.lock().await;
                registry.workers()?
            };
            for row in rows {
                self.directory.lock().await.remove(row.session_id);
                // The worker went with the boot it was in: a boot that is not this one ended
                // every process in it, which is what the boot record establishes and what the
                // kernel may still decline to say about any one of them. So the closure is
                // recorded either way.
                //
                // The recovery pass is not. It opens the session's stores, so it runs only where
                // the kernel confirms the death, and where it does not the store is left exactly
                // as it is. Nothing reads it afterwards either: writing the closure removes the
                // worker row and retires the descriptor, so the closure carries the fact itself,
                // and a session whose closure names a worker this host never saw end is refused
                // every archive read rather than served an incomplete one.
                let archive = self.archive();
                let validated = if let Ok(ownership) = archive.take_ownership(
                    row.session_id,
                    row.display_number,
                    &row.process_identity,
                ) {
                    let _ = archive.recover_journal(&ownership);
                    true
                } else {
                    false
                };
                self.record_final(
                    row.session_id,
                    ClosureReason::HostShutdown,
                    &row.process_identity,
                    &crate::archive::ArchiveService::nothing_fenced(row.session_id),
                    validated,
                )
                .await?;
            }
        }
        if bytes.as_deref() != Some(current.as_slice()) {
            kr_ipc::paths::write_owner_only_file(&path, &current)?;
        }
        Ok(())
    }

    /// Removes the directories of workers this environment no longer runs.
    ///
    /// One directory per session, and the session is the only thing that can say whether it is
    /// still wanted. A launch that failed after its directory was made, a removal a platform
    /// refused while the worker was exiting, and a daemon that died between the two all leave one
    /// behind; this is where they go.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(super) async fn sweep_worker_dirs(&self) -> Result<()> {
        let live = {
            let registry = self.registry.lock().await;
            let mut live: std::collections::BTreeSet<SessionId> = registry
                .workers()?
                .into_iter()
                .map(|worker| worker.session_id)
                .collect();
            // Every phase in which something may still be running, or may still be resolved. A
            // reservation that has not been settled keeps its directory.
            for phase in [
                LaunchPhase::Reserved,
                LaunchPhase::Spawned,
                LaunchPhase::Claimed,
                LaunchPhase::Live,
                LaunchPhase::Fenced,
            ] {
                live.extend(
                    registry
                        .reservations_in(phase)?
                        .into_iter()
                        .map(|reservation| reservation.session_id),
                );
            }
            live
        };
        let Ok(entries) = std::fs::read_dir(self.paths.workers_dir()) else {
            return Ok(());
        };
        for entry in entries.flatten() {
            // The name is the session the directory belongs to. Anything else under here was not
            // put there by this daemon, and this daemon does not remove what it did not write.
            let Some(session_id) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<SessionId>().ok())
            else {
                continue;
            };
            if !live.contains(&session_id) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        Ok(())
    }

    /// Removes the job of every worker this environment defined one for that has ended.
    ///
    /// A daemon that was not running when a worker ended, or that stopped before that worker's job
    /// was removed, leaves the job loaded, and nothing else would ever remove it. So every job this
    /// environment still has defined is looked at when the daemon starts: one whose process has
    /// ended goes, and one whose process is still running is a live session's and is left exactly
    /// as it is. It is finished before the daemon serves anything, which is what keeps a job that
    /// a create of this daemon has defined and not yet started off the list. launchd is asked
    /// about each job in a few milliseconds. A look that reaches every job leaves defined only the
    /// jobs of workers that are still running and those whose removal launchd did not confirm; one
    /// that [`JOB_SWEEP_BOUND`] cuts short leaves the jobs it did not reach for the next start.
    async fn retire_ended_jobs(&self) {
        let jobs = self.paths.jobs_dir();
        let _ = tokio::task::spawn_blocking(move || {
            let deadline = std::time::Instant::now() + JOB_SWEEP_BOUND;
            let defined = crate::supervision::defined_worker_jobs(&jobs);
            for (looked, reservation_id) in defined.iter().enumerate() {
                if std::time::Instant::now() >= deadline {
                    eprintln!(
                        "kr-controller: {} of {} worker jobs were not looked at within \
                         {JOB_SWEEP_BOUND:?}; the next start looks at them again",
                        defined.len() - looked,
                        defined.len()
                    );
                    return;
                }
                if let JobRetirement::Unsettled(detail) =
                    crate::supervision::retire_worker_job(&jobs, *reservation_id)
                {
                    eprintln!(
                        "kr-controller: the job of the worker started for reservation \
                         {reservation_id} could not be removed: {detail}"
                    );
                }
            }
        })
        .await;
    }
}

/// One pass of privacy mode's tick, or `None` once the daemon has gone.
///
/// The record learns which workers are running and which have ended, retries what it owes, and
/// each worker whose session has not answered for the generation in force is told it, one after
/// another, and its answer recorded.
async fn privacy_pass(daemon: &std::sync::Weak<Controller>) -> Option<()> {
    let (live, recorded, privacy) = {
        let controller = daemon.upgrade()?;
        let live: Vec<SessionId> = controller
            .directory
            .lock()
            .await
            .iter()
            .map(|worker| worker.descriptor.session_id)
            .collect();
        // A registry that cannot be read says nothing about which workers have ended, so nothing
        // is taken for ended on this pass.
        let recorded: Option<Vec<SessionId>> =
            controller
                .registry
                .lock()
                .await
                .workers()
                .ok()
                .map(|workers| {
                    workers
                        .into_iter()
                        .map(|worker| worker.session_id)
                        .collect()
                });
        (live, recorded, Arc::clone(&controller.privacy))
    };
    let now_ms = kr_ipc::now_ms();
    // A session that is neither running nor recorded is not thereby one that has ended: its worker
    // may not have reported yet. The registry says whether its launch is over.
    let over = match &recorded {
        Some(recorded) => {
            let unreached = {
                let privacy = Arc::clone(&privacy);
                let (live, recorded) = (live.clone(), recorded.clone());
                tokio::task::spawn_blocking(move || privacy.unreached(&live, &recorded))
                    .await
                    .unwrap_or_default()
            };
            let controller = daemon.upgrade()?;
            launches_over(&controller, &unreached).await
        }
        None => Vec::new(),
    };
    let notices = {
        let privacy = Arc::clone(&privacy);
        tokio::task::spawn_blocking(move || {
            if let Some(recorded) = recorded {
                // An obligation that could not be written is held and written again by the tick.
                let _ = privacy.sessions_seen(&live, &recorded, &over, now_ms);
            }
            let _ = privacy.tick(now_ms);
            privacy.notices_due(now_ms)
        })
        .await
        .unwrap_or_default()
    };
    for notice in notices {
        let Some(ack) = tell_privacy(daemon, notice).await? else {
            continue;
        };
        let privacy = Arc::clone(&privacy);
        let _ = tokio::task::spawn_blocking(move || privacy.note_answer(&ack)).await;
    }
    Some(())
}

/// The sessions among `unreached` whose launch the registry shows to be over: it records no
/// reservation for them, or one whose launch produced no worker or whose session has closed.
///
/// A reservation in any phase before that, reserved, spawned, claimed, live or fenced, is a worker
/// that may be starting or running and that this host has not reached, so its session is not over.
/// A registry that cannot be read says nothing about any of them, and none is.
pub(super) async fn launches_over(
    controller: &Controller,
    unreached: &[SessionId],
) -> Vec<SessionId> {
    if unreached.is_empty() {
        return Vec::new();
    }
    let registry = controller.registry.lock().await;
    let mut over = Vec::new();
    for session_id in unreached {
        match registry.reservation_for_session(*session_id) {
            Ok(None) => over.push(*session_id),
            Ok(Some(reservation))
                if matches!(reservation.phase, LaunchPhase::Failed | LaunchPhase::Closed) =>
            {
                over.push(*session_id);
            }
            Ok(Some(_)) => {}
            Err(_) => return Vec::new(),
        }
    }
    over
}

/// Tells one worker the environment's privacy generation, and returns its answer; `None` once the
/// daemon has gone.
///
/// The daemon is held only while the worker's connection is reached, which is bounded, and the
/// exchange runs over that connection alone. A worker that cannot be reached, or does not answer in
/// time, answers nothing here and is told again on its schedule; its connection is retired when an
/// exchange on it failed part way, because nothing knows where its stream stands.
async fn tell_privacy(
    daemon: &std::sync::Weak<Controller>,
    notice: crate::privacy::Notice,
) -> Option<Option<kr_protocol::privacy::PrivacyGenerationAck>> {
    let session_id = notice.session_id;
    let (reached, environment_id) = {
        let controller = daemon.upgrade()?;
        let reached = tokio::time::timeout(
            super::WORKER_EXCHANGE,
            controller.worker_client_of(session_id),
        )
        .await;
        (reached, controller.paths.environment_id())
    };
    let Ok(Ok(mut held)) = reached else {
        return Some(None);
    };
    let Some(client) = held.as_mut() else {
        return Some(None);
    };
    let told = tokio::time::timeout(
        PRIVACY_EXCHANGE,
        client.announce_privacy(kr_protocol::privacy::PrivacyGenerationNotice {
            environment_id,
            generation: kr_protocol::scalars::U64::new(notice.generation.get()),
            enabled: notice.enabled,
        }),
    )
    .await;
    match told {
        // An answer is about the session it names, and this connection is that session's alone.
        Ok(Ok(ack)) => Some((ack.session_id == session_id).then_some(ack)),
        Ok(Err(_)) | Err(_) => {
            *held = None;
            drop(held);
            daemon.upgrade()?.lost_control_path(session_id);
            Some(None)
        }
    }
}

/// What a controller needs before it starts.
pub struct ControllerSetup {
    /// The environment's directories.
    pub paths: EnvironmentPaths,
    /// The environment identity.
    pub environment_id: EnvironmentId,
    /// Opens or creates the persistent identity this daemon signs generation tokens with.
    ///
    /// It is a closure because it must run **after** the singleton lock is held: creating the
    /// environment's key is a first-start step, and two daemons racing for it would leave one of
    /// them holding a key no live worker recognises.
    pub identity: Box<dyn FnOnce() -> Result<ControllerIdentity> + Send>,
    /// Which store this daemon keeps its keys in.
    ///
    /// The closure above opens it for the identity; this is the same choice, for everything else
    /// this daemon keeps a key in. The transport's device keys are the one that matters: they are
    /// opened only when the environment selects a network, which is after startup.
    pub secret_store: kr_crypto::store::StoreSelection,
    /// The boot this host is running.
    pub boot_identity: BootIdentity,
    /// How workers are started.
    pub supervisor: Box<dyn WorkerSupervisor>,
    /// The worker executable.
    pub worker_program: PathBuf,
    /// This daemon's build.
    pub build_id: BuildId,
    /// The release string sessions report as their terminal program version.
    pub release: String,
    /// Where the qualified shell packages are installed.
    ///
    /// `None` is the installation's own directory, or whatever
    /// [`PACKAGE_ROOT_VARIABLE`](kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE)
    /// names. A host that keeps its packages somewhere else is told, rather than being expected to
    /// arrange a variable for every process that needs to know.
    pub shell_packages: Option<PathBuf>,
    /// How a `terminal` presentation opens its window.
    ///
    /// This daemon is the only party on the host that can open one for a session created from
    /// somewhere else, so the presentation is its work. A host that opens nothing says so with
    /// [`NoTerminal`](crate::supervision::NoTerminal).
    pub terminal: Box<dyn crate::supervision::TerminalPresenter>,
}

/// Resolves the qualified package a create request selects, against one package root.
///
/// Section 7: an unqualified system shell may be a child application or an explicitly selected
/// `native_compat` top-level shell; it cannot claim the managed contract. The refusal names the
/// shell rather than substituting another, and at admission it happens before a reservation is
/// recorded, so an unsupported request costs the caller an error rather than a session that closes
/// itself.
///
/// Free of the controller on purpose: it reads the filesystem, so it runs on a thread that may
/// block rather than on the runtime this daemon serves its clients on.
///
/// # Errors
///
/// Returns [`ControllerError::ShellIntegrationUnsupported`] naming the shell, never a substitution.
/// Opens, adopts or creates this environment's clock floor for the boot, and says whether the
/// boot's clock continuity is lost.
///
/// Three cases, told apart by the file and by the registry's record of the floors created in
/// this boot:
///
/// 1. A file of this environment and boot that passes every check, whose identity is not recorded
///    as lost: opened as it stands, never truncated or replaced, so every worker that outlived a
///    daemon restart keeps mapping the same word. An identity the registry does not know (a start
///    that stopped between publishing the file and recording it) is recorded now.
/// 2. No usable file and no floor recorded for this boot: the boot's first start. A new floor is
///    created under a fresh identity and recorded as the boot's floor in force.
/// 3. No usable file and a floor recorded for this boot: the floor was lost, and a worker of this
///    boot may still map it. The boot's clock continuity is recorded as lost first, then a new
///    floor is created and recorded in force. A reading published only in the lost floor may have
///    passed a deadline nothing on record shows as passed, so until the owner establishes the
///    clock no bound that can pass is decided ([`crate::grants::policy::UtcFloor::bound`]).
///
/// A file of another boot, one that fails a check, and one whose identity is recorded as lost
/// count as no usable file and are replaced: a lost floor moved back into place is never adopted.
/// A new floor's first value is `durable_ms`, the floor this host last wrote down.
fn open_utc_floor(
    registry: &mut Registry,
    paths: &EnvironmentPaths,
    environment_id: EnvironmentId,
    boot_epoch: BootEpoch,
    durable_ms: u64,
) -> Result<(Arc<kr_ipc::floor::SharedFloor>, bool)> {
    use kr_ipc::floor::SharedFloor;

    registry.forget_other_boots(boot_epoch)?;
    let recorded = registry.floors_of_boot(boot_epoch)?;
    let path = paths.utc_floor_file();
    let adopted = SharedFloor::open(&path, environment_id, boot_epoch)
        .ok()
        .filter(|floor| {
            let identity = floor.identity();
            !recorded
                .iter()
                .any(|known| Some(known.identity) == identity && !known.in_force)
        });
    let floor = match adopted {
        Some(floor) => {
            if let Some(identity) = floor.identity()
                && !recorded.iter().any(|known| known.identity == identity)
            {
                registry.record_floor_in_force(boot_epoch, identity, kr_ipc::now_ms())?;
            }
            floor
        }
        None => {
            if !recorded.is_empty() {
                registry.lose_clock_continuity(boot_epoch, kr_ipc::now_ms())?;
            }
            let floor = SharedFloor::create(&path, environment_id, boot_epoch, durable_ms)?;
            let identity =
                floor
                    .identity()
                    .ok_or_else(|| ControllerError::RegistryUnavailable {
                        detail: "a clock floor created from a file has no identity".to_owned(),
                    })?;
            registry.record_floor_in_force(boot_epoch, identity, kr_ipc::now_ms())?;
            floor
        }
    };
    let lost = registry.clock_continuity_lost(boot_epoch)?;
    Ok((Arc::new(floor), lost))
}
