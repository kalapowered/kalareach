//! The host's own reads and records: host information, the environments, the doctor, agent tools,
//! and the handover by which this daemon makes way for another installed release.

use std::sync::Arc;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::hostinfo::{
    DoctorCheck, DoctorStatus, EnvironmentListResult, EnvironmentSummary, HostDoctorResult,
    HostInfoResult,
};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{ActorId, AuthorityRevision, ConnectionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::update::{
    HANDOVER_HOLD_MS, HANDOVER_SETTLE_MS, HandoverStep, HostUpdateHandoverParams,
    HostUpdateHandoverResult, ReleaseName,
};

use crate::error::{ControllerError, Result};

use super::{Controller, encode, parse, wall_clock_ms};

/// How long the doctor gives the reading of the installed packages and of the executables their
/// commands name: an agent's executable can be a large file.
const DOCTOR_READS: std::time::Duration = std::time::Duration::from_secs(30);

impl Controller {
    /// Reports what is installed for one agent.
    pub(super) fn agent_tools_status(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::skill::AgentToolsParams = parse(params)?;
        encode(&self.installer()?.status(&params)?)
    }

    /// Installs or removes the contact skill for one agent.
    ///
    /// An installation changes files, so it runs under section 9's receipt contract: the same
    /// action retried returns what it produced the first time rather than repeating the change,
    /// the same identifier with a different payload is `ID_CONFLICT`, and a marker written before
    /// the change with no outcome after it is `unknown` rather than something to do again. What
    /// can be refused without touching anything is refused before the marker.
    ///
    /// `carried` is the admission the change was accepted under, asked at the marker.
    pub(super) async fn agent_tools_change(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        let params: kr_protocol::skill::AgentToolsParams = parse(&mutation.params)?;
        let installer = self.installer()?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // From here to the recorded outcome is one sequence. Two callers cannot both find no
        // record and both change the same files.
        let _admission = self.agent_tools.lock().await;
        // Waiting for that lock takes time, and what happens next is either a read of somebody's
        // completed action or a change to their files. Both need current authority, so it is
        // checked here rather than before the wait.
        self.authorised(carried.connection_id)?;
        if let Some(retained) = installer.retained(actor_id, mutation.action_id, &digest)? {
            return Ok(retained);
        }
        // What either change can refuse without touching anything, refused here: the platform, the
        // scope, a file or entry this host did not write, a record it cannot read, a document whose
        // protection it cannot keep. A refusal after the marker below would be reported as a change
        // whose outcome nobody knows, for a change that never began.
        match method {
            Method::AgentToolsInstall => installer.check(&params)?,
            Method::AgentToolsRemove => installer.check_removal(&params)?,
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not an installation this daemon serves",
                    method.as_str()
                )));
            }
        }
        // A change carrying no freshness at all is refused. This path answers its own retained
        // actions above, so anything still travelling is a first admission, and a first admission
        // needs a deadline it was admitted under.
        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this installation carries no freshness, so it may be answered from what \
                         this host holds and may not change anything"
                    .to_owned(),
            });
        }
        // Everything above can wait: for this task to be scheduled, for the lock, for the checks
        // to read the agent's tree. The admission this change was accepted under is asked after
        // those waits, and the dispatch marker is written while this daemon's connection table is
        // held, so a revocation cannot complete between the answer and the marker: withdrawing a
        // registration takes the same lock. The answer is the check every service asks from
        // inside its work: a fence this host owes and could not raise, the connection's
        // registration under the revision it was admitted at, then the deadline.
        let registrations = self.admitted_table();
        self.check_registration_in(&registrations, &carried)?;
        installer.mark_dispatching(actor_id, mutation.action_id, &digest)?;
        drop(registrations);
        let result = match method {
            Method::AgentToolsInstall => encode(&installer.install(&params)?)?,
            Method::AgentToolsRemove => encode(&installer.remove(&params)?)?,
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not an installation this daemon serves",
                    method.as_str()
                )));
            }
        };
        installer.settle(actor_id, mutation.action_id, &digest, &result)?;
        Ok(result)
    }

    /// Returns the installer, which keeps this host's record of what it wrote.
    pub(super) fn installer(&self) -> Result<crate::agent_tools::Installer> {
        crate::agent_tools::Installer::discover(self.paths.state_dir())
    }

    pub(super) async fn host_info(self: &Arc<Self>) -> Result<HostInfoResult> {
        // Asking what this host is configured as is what puts its configuration into force, the
        // same way asking for its diagnostics is. Reading the numbers without accepting the
        // document first is how this answer comes to name a session ceiling or a sleep policy a
        // later reading has already replaced.
        drop(self.accept_configuration().await);
        let registry = self.registry.lock().await;
        let live = registry.occupancy()?;
        let limit = registry.session_limit()?;
        drop(registry);
        Ok(HostInfoResult {
            build_id: self.build_id.clone(),
            protocol_version: PROTOCOL_VERSION,
            environment_id: self.paths.environment_id(),
            generation: self.generation,
            boot_identity: self.boot_identity.clone(),
            started_at_ms: self.started_at_ms,
            live_sessions: U64::new(live),
            session_limit: U64::new(limit),
            default_worker_profile: self.default_profile().await,
            power: self.power_state().await,
            machine: self.machine_report(),
        })
    }

    pub(super) async fn environment_list(&self) -> Result<EnvironmentListResult> {
        let registry = self.registry.lock().await;
        let live = registry.occupancy()?;
        drop(registry);
        Ok(EnvironmentListResult {
            environments: vec![EnvironmentSummary {
                environment_id: self.paths.environment_id(),
                label: format!("{} on {}", whoami(), std::env::consts::OS),
                os: std::env::consts::OS.to_owned(),
                arch: std::env::consts::ARCH.to_owned(),
                os_user: whoami(),
                runtime_directory: self.paths.runtime_dir().display().to_string(),
                state_directory: self.paths.state_dir().display().to_string(),
                live_sessions: U64::new(live),
                machine: self.machine_report(),
            }],
        })
    }

    /// Answers `environment.inventory` from this host's cache.
    ///
    /// Section 3: a listing reports what was last observed and starts nothing. Nothing here takes
    /// an observer, so nothing here could ask the platform even by mistake.
    pub(super) async fn environment_inventory(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let params: kr_protocol::identity::EnvironmentInventoryParams = parse(params)?;
        let state_dir = self.paths.state_dir().to_path_buf();
        let now_ms = wall_clock_ms();
        let access = params.access.as_ref().copied();
        let rows = tokio::task::spawn_blocking(move || {
            crate::bridge::store::Store::with_locked(&state_dir, |store| {
                Ok(store.list(access, now_ms))
            })
        })
        .await
        .map_err(|error| ControllerError::supervision(error.to_string()))??;
        encode(&kr_protocol::identity::EnvironmentInventoryResult { rows })
    }

    /// Claims one action of this daemon's own, performs it, and keeps what it came to under the
    /// claim before answering, so that a retry is answered from that record.
    ///
    /// The action is the actor's and the identifier together, and the payload decides whether a
    /// second request is the same action or a reused identifier. Only the attempt that wrote the
    /// claim performs: another attempt is answered from what the claim holds, and one that meets a
    /// claim still running is told so.
    ///
    /// What an earlier attempt kept is given back only under authority that has not been
    /// withdrawn, as it is by the retained lookup before a first admission: a claim can be recorded
    /// between that lookup and this one. The answer is waited for first, and the shared check
    /// ([`Self::check_retained_answer`]) is asked with it in hand, so a fence this host owes, or a
    /// registration withdrawn while the answer was read, stops it.
    pub(super) async fn claimed_action(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        connection_id: ConnectionId,
        admitted: Option<AuthorityRevision>,
        perform: impl std::future::Future<Output = Result<ParamsValue>>,
    ) -> kr_protocol::envelope::ControlFrame {
        let claimed = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
            .and_then(|digest| {
                self.sharing.grants().claim_action(
                    actor_id,
                    mutation.action_id,
                    &digest,
                    kr_ipc::now_ms().get(),
                )
            });
        match claimed {
            Ok(crate::grants::ActionClaim::Claimed { hold }) => {
                let outcome = perform.await;
                // A receipt that cannot be kept does not change what the action did, and the caller
                // is told that, not that the registry failed: the claim stays unfinished, and a
                // retry is answered as an outcome this host does not know, never performed again.
                if let Err(unrecorded) = self.settle_claim(&hold, &outcome) {
                    eprintln!("kr-controller: an action's receipt could not be kept: {unrecorded}");
                }
                drop(hold);
                super::respond(mutation.request_id, outcome)
            }
            Ok(crate::grants::ActionClaim::Recorded(record)) => {
                let answered = self
                    .recorded_authority_change(actor_id, mutation, record)
                    .await;
                #[cfg(feature = "testing")]
                self.after_the_retained_lookup.wait().await;
                if let Err(error) = self.check_retained_answer(connection_id, admitted) {
                    return super::error_reply(
                        mutation.request_id,
                        error.code(),
                        error.to_string(),
                    );
                }
                super::respond(mutation.request_id, answered)
            }
            Err(error) => super::respond(mutation.request_id, Err(error)),
        }
    }

    /// Answers the three mutations that change this host's enrolled environments.
    ///
    /// Only a refresh reaches the platform, and only when the request asked it to start the
    /// environment it selected. Enrolling and forgetting change the record and nothing else.
    ///
    /// None of the three takes a deadline: the record changes nothing a window decides. Each asks
    /// the check every service asks, on the registration `carried` names, again after it has the
    /// record's lock and before the effect it guards, because waiting for that lock can outlast a
    /// fence this host owes or the registration the change was admitted under. Enrolling and
    /// forgetting write the record while the registration is held standing; a refresh runs a
    /// platform command that can take seconds, so it is asked before the command and again before
    /// it opens a bridge.
    pub(super) async fn environment_record(
        self: &Arc<Self>,
        actor: &kr_protocol::actor::ActorEnvelope,
        bridged: bool,
        mutation: &MutationRequest,
        method: Method,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<ParamsValue> {
        use kr_protocol::identity::{
            EnvironmentEnrolParams, EnvironmentEnrolResult, EnvironmentForgetParams,
            EnvironmentForgetResult, EnvironmentRefreshParams, EnvironmentRefreshResult,
        };

        let state_dir = self.paths.state_dir().to_path_buf();
        let now_ms = wall_clock_ms();
        let carried = crate::authority::AdmittedMutation {
            deadline: None,
            ..carried
        };
        let controller = Arc::clone(self);
        match method {
            Method::EnvironmentEnrol => {
                let params: EnvironmentEnrolParams = parse(&mutation.params)?;
                let row = tokio::task::spawn_blocking(move || {
                    crate::bridge::store::Store::with_locked(&state_dir, |store| {
                        #[cfg(feature = "testing")]
                        controller.after_the_environment_record_is_taken.wait();
                        controller.under_registration(&carried, || {
                            store.enrol(params.enrolment, now_ms)
                        })?
                    })
                })
                .await
                .map_err(|error| ControllerError::supervision(error.to_string()))??;
                encode(&EnvironmentEnrolResult { row })
            }
            Method::EnvironmentForget => {
                let params: EnvironmentForgetParams = parse(&mutation.params)?;
                let forgotten = tokio::task::spawn_blocking(move || {
                    crate::bridge::store::Store::with_locked(&state_dir, |store| {
                        #[cfg(feature = "testing")]
                        controller.after_the_environment_record_is_taken.wait();
                        controller
                            .under_registration(&carried, || store.forget(params.environment_id))?
                    })
                })
                .await
                .map_err(|error| ControllerError::supervision(error.to_string()))??;
                encode(&EnvironmentForgetResult { forgotten })
            }
            Method::EnvironmentRefresh => {
                // Before anything is asked of the platform, and before the record is touched: a
                // refresh may start the environment it selects, and a request that has crossed a
                // bridge is not one that may open another. Starting something and then refusing to
                // look at it would be the wrong way round.
                if bridged {
                    return Err(ControllerError::PermissionDenied {
                        detail: "a request crosses at most one process bridge, and this one has \
                                 already crossed one to reach this environment"
                            .to_owned(),
                    });
                }
                let params: EnvironmentRefreshParams = parse(&mutation.params)?;
                let environment_id = params.environment_id;

                // An access class that is not a process bridge is answered from the record alone.
                // Asking the platform first would fail for it, because there is no launcher to ask
                // with, and the answer a person needs is that this environment is reached another
                // way rather than that a command was missing.
                let reading = state_dir.clone();
                // The row and the approved record it belongs to are read under one lock, so what an
                // answer is later recorded against is the record the row describes.
                let (cached, approved) = tokio::task::spawn_blocking(move || {
                    crate::bridge::store::Store::with_locked(&reading, |store| {
                        store.approved(environment_id, now_ms).ok_or_else(|| {
                            ControllerError::InvalidArgument(format!(
                                "this host has no enrolled environment {environment_id}"
                            ))
                        })
                    })
                })
                .await
                .map_err(|error| ControllerError::supervision(error.to_string()))??;
                // An SSH host is not a process bridge, and no request crosses ssh. Its helper is asked
                // once who it is, which is how the host registers an identity and the channel the
                // helper holds there.
                if cached.enrolment.access == kr_protocol::identity::EnvironmentAccess::SshHost {
                    // The helper is run and waited for: a fence this host owes, or the registration
                    // this was admitted under withdrawn, while the record's lock was waited for
                    // stops it, as it stops the platform command and the bridge.
                    self.check_registration(&carried)?;
                    return self
                        .register_ssh(actor, bridged, cached, approved, carried, now_ms)
                        .await;
                }
                if !cached.enrolment.access.is_process_bridge() {
                    let connection = format!(
                        "{} is not reached by a process bridge, so none was opened",
                        cached.enrolment.access.as_str()
                    );
                    return encode(&EnvironmentRefreshResult {
                        row: cached,
                        started: false,
                        verification: Nullable::null(),
                        connection,
                    });
                }

                let observing = state_dir.clone();
                let asking = Arc::clone(&controller);
                // The platform command is a blocking one, and it is run on a blocking thread so a
                // distribution that takes seconds to start does not hold this runtime.
                let refreshed = tokio::task::spawn_blocking(move || {
                    crate::bridge::store::Store::with_locked(&observing, |store| {
                        #[cfg(feature = "testing")]
                        asking.after_the_environment_record_is_taken.wait();
                        asking.check_registration(&carried)?;
                        store.refresh(
                            params.environment_id,
                            params.start,
                            &crate::bridge::platform::PlatformObserver,
                            now_ms,
                        )
                    })
                })
                .await
                .map_err(|error| ControllerError::supervision(error.to_string()))??;
                let crate::bridge::store::Refreshed {
                    mut row,
                    started,
                    instance,
                } = refreshed;

                // Only a running environment is worth opening a bridge to, and only a process
                // bridge has one to open. Everything else says so rather than starting anything:
                // section 3 leaves starting to the caller that asked for it.
                let (verification, connection) = if row.status
                    != kr_protocol::identity::EnvironmentPresence::Running
                {
                    (
                        Nullable::null(),
                        "no bridge was opened, because this environment is not running; refresh \
                         with --start to start it"
                            .to_owned(),
                    )
                } else {
                    // Opening a bridge reaches into another environment, after waits of its own.
                    controller.check_registration(&carried)?;
                    let opened_for = row.enrolment.clone();
                    match crate::bridge::verify::through_bridge(
                        actor,
                        bridged,
                        &opened_for,
                        self.paths.environment_id(),
                        self.build_id.clone(),
                    )
                    .await
                    {
                        Ok(verification) => {
                            // The destination answered on its own local channel, inside its own
                            // environment. That is section 25's scoped channel, established rather
                            // than assumed, so the record keeps it — against the approved record
                            // the bridge was opened for, which another caller may have replaced
                            // since.
                            let outcome = self
                                .record_outcome(
                                    carried,
                                    environment_id,
                                    instance,
                                    crate::bridge::store::BridgeAnswer::Answered,
                                    now_ms,
                                )
                                .await?;
                            // The record decides, including when it has gone: the readiness that
                            // comes back is read from it after the result was written.
                            row.readiness = outcome.readiness;
                            let detail = if outcome.established {
                                format!(
                                    "environment {} answered as {} over its own local channel",
                                    verification.environment_id, verification.os_user
                                )
                            } else {
                                "this environment's record changed while the bridge was open, so \
                                 what answered says nothing about what is recorded now"
                                    .to_owned()
                            };
                            (Nullable::some(verification), detail)
                        }
                        Err(refusal) => {
                            // Nothing answered. What an earlier bridge established for this record
                            // is not evidence about it any more, so it is taken back rather than
                            // left standing beside a failure.
                            let outcome = self
                                .record_outcome(
                                    carried,
                                    environment_id,
                                    instance,
                                    crate::bridge::store::BridgeAnswer::Refused,
                                    now_ms,
                                )
                                .await?;
                            row.readiness = outcome.readiness;
                            (Nullable::null(), refusal.to_string())
                        }
                    }
                };
                encode(&EnvironmentRefreshResult {
                    row,
                    started,
                    verification,
                    connection,
                })
            }
            other => Err(ControllerError::InvalidArgument(format!(
                "{} is not an environment record this daemon changes",
                other.as_str()
            ))),
        }
    }

    /// Registers an SSH host's identity and scoped channel from its helper's own answer.
    ///
    /// The evidence belongs to the approved record that was read with `cached`, and a refusal takes
    /// back what an earlier answer established for that record, exactly as for a process bridge.
    async fn register_ssh(
        self: &Arc<Self>,
        actor: &kr_protocol::actor::ActorEnvelope,
        bridged: bool,
        cached: kr_protocol::identity::EnvironmentInventoryRow,
        instance: crate::bridge::store::EnrolmentInstance,
        carried: crate::authority::AdmittedMutation,
        now_ms: u64,
    ) -> Result<ParamsValue> {
        use kr_protocol::identity::EnvironmentRefreshResult;

        let environment_id = cached.enrolment.environment_id;
        let opened_for = cached.enrolment.clone();
        let mut row = cached;
        let (verification, connection) = match crate::bridge::verify::through_identity_probe(
            actor,
            bridged,
            &opened_for,
            &self.paths,
            self.build_id.clone(),
        )
        .await
        {
            Ok(verification) => {
                let outcome = self
                    .record_outcome(
                        carried,
                        environment_id,
                        instance,
                        crate::bridge::store::BridgeAnswer::Answered,
                        now_ms,
                    )
                    .await?;
                row.readiness = outcome.readiness;
                let detail = if outcome.established {
                    format!(
                        "environment {} answered as {} on the helper installed there, over ssh; \
                         no request crosses ssh",
                        verification.environment_id, verification.os_user
                    )
                } else {
                    "this environment's record changed while its helper was asked, so what \
                     answered says nothing about what is recorded now"
                        .to_owned()
                };
                (Nullable::some(verification), detail)
            }
            Err(refusal) => {
                let outcome = self
                    .record_outcome(
                        carried,
                        environment_id,
                        instance,
                        crate::bridge::store::BridgeAnswer::Refused,
                        now_ms,
                    )
                    .await?;
                row.readiness = outcome.readiness;
                (Nullable::null(), refusal.to_string())
            }
        };
        encode(&EnvironmentRefreshResult {
            row,
            started: false,
            verification,
            connection,
        })
    }

    pub(super) async fn host_doctor(self: &Arc<Self>) -> Result<HostDoctorResult> {
        let mut checks = Vec::new();
        checks.push(DoctorCheck::new(
            "runtime-directory",
            "The runtime directory is owner-only",
            DoctorStatus::Ok,
            Sentence::new()
                .stated("created with owner-only permissions and verified on every open: ")
                .withheld(
                    ContentClass::Path,
                    &self.paths.runtime_dir().display().to_string(),
                ),
            None,
        ));
        checks.push(self.machine_check());
        checks.push(DoctorCheck::new(
            "supervisor",
            "Workers outlive this daemon",
            DoctorStatus::Ok,
            Sentence::new().stated(self.supervisor.describe()),
            None,
        ));
        let directory = self.directory.lock().await;
        let quarantined = directory.quarantined.len();
        let verified = directory.verified.len();
        drop(directory);
        checks.push(DoctorCheck::new(
            "workers",
            "Every published descriptor answered its challenge",
            if quarantined == 0 {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Warning
            },
            Sentence::new()
                .number(verified as u64)
                .stated(" verified, ")
                .number(quarantined as u64)
                .stated(" quarantined"),
            (quarantined > 0).then_some(
                "A quarantined descriptor is never used. Remove it once its session is known to \
                 be gone.",
            ),
        ));
        // One acceptance, one reading, and every configuration line below comes from it. The
        // sleep policy asking the document a second time is how a check and the report it sits
        // beside come to disagree about the same file.
        let accepted = self.accept_configuration().await;
        let power = self.power_state().await;
        let resolved = accepted.resolver.sleep_inhibition(None);
        let enabled = accepted.resolver.command_integrations().value;
        checks.push(DoctorCheck::new(
            "sleep-setting",
            "This host's sleep policy is the owner's choice",
            DoctorStatus::Ok,
            Self::sleep_setting_detail(&power, &resolved),
            (power.setting == kr_protocol::desktop::SleepInhibitionSetting::Off).then_some(
                "kr host power --set mains_only keeps this host awake for work it has admitted, \
                 while it is on mains power.",
            ),
        ));
        for entry in crate::desktop::persistence(self.supervisor.describe()) {
            checks.push(DoctorCheck::new(
                match entry.profile {
                    WorkerProfile::DesktopBound => "logout-desktop_bound",
                    WorkerProfile::HeadlessUser => "logout-headless_user",
                },
                match entry.profile {
                    WorkerProfile::DesktopBound => "What a logout does to a desktop-bound session",
                    WorkerProfile::HeadlessUser => "What a logout does to a headless session",
                },
                DoctorStatus::Ok,
                Sentence::new()
                    .stated(entry.persistence.as_str())
                    .stated(" through ")
                    .stated_value(entry.mechanism())
                    .stated(": ")
                    .stated_value(entry.detail()),
                None,
            ));
        }
        let pending = self.revision_pending().await?;
        checks.push(DoctorCheck::new(
            "authority-revision",
            "Every worker holds this environment's authority revision",
            if pending.is_empty() {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Warning
            },
            Sentence::new()
                .number(pending.len() as u64)
                .stated(" of ")
                .number(verified as u64)
                .stated(" pending"),
            (!pending.is_empty()).then_some(
                "A revocation is complete for a worker once it acknowledges the revision or is \
                 confirmed ended.",
            ),
        ));
        checks.push(self.descriptions.doctor_check(&self.description_settings()));
        checks.extend(self.device_repository_checks().await);
        // The configuration, its precedence, its overrides and its ceilings. After the checks
        // above because those are about whether this host is working; these are about what it is
        // working from.
        // The budgets the catalogue acts on, which the acceptance above put in force.
        let budgets = accepted.budgets.value;
        let effective = self.report_configuration(&accepted).await;
        // What the running network and voice services are doing, read from them, against what
        // the same reading of the document selects, so an edit that applies at the next start
        // says so.
        let network = crate::config::network_check(
            &self.started,
            accepted.resolver.loaded().document.as_ref(),
            crate::config::Running {
                network: self.network_guard().map(|guard| {
                    crate::config::RunningNetwork::of(guard.endpoint(), guard.bound_sockets().len())
                }),
                names_a_broker: !self.voice().broker_origin().is_empty(),
            },
        );
        drop(accepted);
        checks.extend(crate::config::checks(&effective));
        checks.push(network);
        checks.push(DoctorCheck::new(
            "configuration-secrets",
            "Secrets are named references, never configuration exports",
            DoctorStatus::Ok,
            crate::config::secret_line(&effective),
            None,
        ));
        // The shared section 11 capability evidence the catalogue contributes, read now.
        // `NotApplicable` with the reason stated while nothing is enrolled, rather than a claim
        // about a catalogue this host does not have.
        let evidence = self.catalogue_evidence().await;
        checks.push(crate::config::catalogue::check(Some(&evidence), budgets));
        // Section 7: the resolved executable, flags, version and integration mode of each command
        // integration, from the admissions in force and the configuration this reading accepted.
        let (integrations_check, integrations) = self.command_integration_report(enabled).await;
        checks.push(integrations_check);
        checks.push(
            self.catalogue
                .native_bridges_check(tokio::time::Instant::now() + DOCTOR_READS)
                .await,
        );
        let launch_probes = self.launch_probe_report().await;
        Ok(HostDoctorResult::new(checks, effective)
            .with_command_integrations(integrations)
            .with_launch_probes(launch_probes))
    }

    /// The doctor's checks of what this host serves a paired device in repository operations:
    /// whether it qualifies, and what it shows of the mount residual that remains where it does.
    ///
    /// The proof is made again here and held in place of the last one, so the door and the report
    /// say the same thing.
    async fn device_repository_checks(&self) -> Vec<DoctorCheck> {
        use kr_project::service::Refusal;

        let proved = self.project.qualify().await;
        let before = self.qualification();
        self.hold_qualification(Arc::clone(&proved));
        let refusal = proved.refusal();
        // What stopped the proof is for this daemon's own log, as at its start, and only when the
        // answer changed: a device that asks the doctor again learns nothing new from the log.
        if before.refusal() != refusal
            && matches!(refusal, Some(Refusal::SupportSet | Refusal::Invocation))
        {
            eprintln!(
                "kr-controller: no repository operation is served to a paired device: {}",
                proved.detail()
            );
        }
        let mut checks = vec![DoctorCheck::new(
            "device-repositories",
            "A paired device is served repository operations",
            match refusal {
                None => DoctorStatus::Ok,
                Some(Refusal::Platform) => DoctorStatus::NotApplicable,
                Some(Refusal::SupportSet | Refusal::Invocation) => DoctorStatus::Warning,
            },
            match refusal {
                None => Sentence::new().stated(
                    "Git runs for a paired device inside a boundary that confines what it reads: \
                     the loaders and libraries it needs are named and one invocation under the \
                     boundary ran here",
                ),
                Some(refusal) => Sentence::new()
                    .stated(refusal.text())
                    .stated(", so a paired device is refused repository operations"),
            },
            matches!(refusal, Some(Refusal::SupportSet | Refusal::Invocation)).then_some(
                "This daemon's own log says what it could not do. A paired device is refused \
                 until a later check proves it.",
            ),
        )];
        if refusal == Some(Refusal::Platform) {
            return checks;
        }
        // What a host shows of how a filesystem could come to be mounted beneath a directory the
        // owner authorised. It narrows the residual and never closes it, and the sentence says so.
        let narrowing = proved.narrowing();
        let counted = |sentence: Sentence, found: Option<u64>, what: &'static str| match found {
            Some(count) => sentence.number(count).stated(" ").stated(what),
            None => sentence
                .stated("the number of ")
                .stated(what)
                .stated(" could not be read"),
        };
        let sentence = Sentence::new().stated(narrowing.user_namespaces.map_or(
            "whether unprivileged user namespaces are allowed could not be read",
            kr_project::service::UserNamespaces::text,
        ));
        let sentence = sentence.stated("; ").stated(narrowing.fusermount.map_or(
            "whether fusermount is installed could not be read",
            kr_project::service::Fusermount::text,
        ));
        let sentence = counted(sentence.stated("; "), narrowing.automounts, "automounts");
        let sentence = counted(
            sentence.stated("; "),
            narrowing.user_mount_units,
            "mount units configured for this account",
        );
        checks.push(DoctorCheck::new(
            "device-repository-mounts",
            "What a paired device's repository operations could reach through a mount",
            if narrowing.is_narrow() {
                DoctorStatus::Ok
            } else {
                DoctorStatus::Warning
            },
            sentence.stated(
                ". This narrows what a paired device's repository operations can reach and does \
                 not close it: a program running as this account, or this host's own mount \
                 arrangement, can still put a filesystem beneath a directory the owner \
                 authorised.",
            ),
            (!narrowing.is_narrow()).then_some(
                "Restrict unprivileged user namespaces, remove the setuid permission from \
                 fusermount, and keep automount and mount units away from the directories the \
                 owner authorises.",
            ),
        ));
        checks
    }

    /// What each admitted package's launch probe reads of its application, run by this daemon
    /// against the executable its own search path names.
    ///
    /// The probes run on a thread that may block, each under its own deadline, and not inside the
    /// integration reading's time: a slow application must not cost the doctor its other answers.
    /// Where the admissions cannot be computed, or the probes do not finish, there is nothing to
    /// report.
    async fn launch_probe_report(&self) -> Vec<kr_protocol::hostinfo::LaunchProbeReport> {
        let Some(snapshot) = self.current_snapshot(tokio::time::Instant::now()).await else {
            return Vec::new();
        };
        let integrations = Arc::clone(&self.integrations);
        let search_path: Vec<std::path::PathBuf> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        let directory = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        let probed = tokio::task::spawn_blocking(move || {
            let reading = integrations.read(&snapshot.packages);
            crate::catalogue::launch_probes::report(
                &reading,
                &search_path,
                &directory,
                kr_worker::broker::probe::DEADLINE,
            )
        });
        match tokio::time::timeout(DOCTOR_READS, probed).await {
            Ok(Ok(reports)) => reports,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Every command integration an admitted release declares, and every package the configuration
    /// names, with the doctor's check of them, read from the admissions in force by a worker's own
    /// rules.
    ///
    /// The executable is looked for on this daemon's own search path, the one the native bridge
    /// reads, and read to find the version a signed record names for it. Where the admissions
    /// cannot be computed or their packages read, each package the configuration names is reported
    /// unknown, and the check says why.
    async fn command_integration_report(
        &self,
        enabled: Vec<String>,
    ) -> (
        kr_protocol::hostinfo::DoctorCheck,
        Vec<kr_protocol::hostinfo::CommandIntegrationReport>,
    ) {
        let snapshot = self.current_snapshot(tokio::time::Instant::now()).await;
        let unread = snapshot.is_none();
        // The first answer starts a process of its own to find out, which a thread of the runtime
        // does not wait for.
        let backends_failure = tokio::task::spawn_blocking(
            kr_worker::broker::process::ManagedProcess::command_backends_failure,
        )
        .await
        .unwrap_or(Some("the check of them did not finish"));
        let host = crate::catalogue::integrations::Host {
            search_path: std::env::var_os("PATH")
                .map(|path| std::env::split_paths(&path).collect())
                .unwrap_or_default(),
            backends: backends_failure.is_none(),
            backends_failure,
            // A worker runs an integrated invocation through the launcher beside it, held to the
            // rule the worker holds it to.
            launcher: self.worker_program.parent().is_some_and(|directory| {
                kr_worker::broker::commands::runnable(&directory.join(if cfg!(windows) {
                    "kr-hook.exe"
                } else {
                    "kr-hook"
                }))
            }),
            forwarder: kr_ipc::install::registered_forwarder(),
        };
        let integrations = Arc::clone(&self.integrations);
        let reported = {
            let enabled = enabled.clone();
            tokio::task::spawn_blocking(move || {
                let reading = snapshot
                    .as_ref()
                    .map(|snapshot| integrations.read(&snapshot.packages));
                let left_out = snapshot
                    .as_ref()
                    .map_or(&[][..], |snapshot| snapshot.left_out.as_slice());
                crate::catalogue::integrations::report(reading.as_ref(), left_out, &enabled, &host)
            })
        };
        match tokio::time::timeout(DOCTOR_READS, reported).await {
            // Admissions that could not be computed say nothing of what is installed.
            Ok(Ok(reported)) if unread => (
                crate::catalogue::integrations::unread_check(),
                reported.reports,
            ),
            Ok(Ok(reported)) => (
                crate::catalogue::integrations::check(&reported, &enabled),
                reported.reports,
            ),
            // With nothing read there is nothing to resolve, so this does not block.
            Ok(Err(_)) | Err(_) => (
                crate::catalogue::integrations::unread_check(),
                crate::catalogue::integrations::report(
                    None,
                    &[],
                    &enabled,
                    &crate::catalogue::integrations::Host::default(),
                )
                .reports,
            ),
        }
    }
}

impl Controller {
    /// Writes what one opened bridge did to the enrolment record, and reads back what it says then.
    ///
    /// The record is a file under a lock, so this runs on a blocking thread. Both of a refresh's
    /// branches, and its ssh host's, come through here, which is why none of them has a readiness
    /// of its own to assemble: what comes back is the record's own answer, taken after the result
    /// was written.
    ///
    /// The write is made only here, and only under the registration the refresh was admitted
    /// under: the helper or the bridge answered after waits of its own, and a fence this host owes,
    /// or a registration withdrawn in that time, stops the write as it stops every other effect.
    async fn record_outcome(
        self: &Arc<Self>,
        carried: crate::authority::AdmittedMutation,
        environment_id: kr_protocol::ids::EnvironmentId,
        opened_for: crate::bridge::store::EnrolmentInstance,
        answer: crate::bridge::store::BridgeAnswer,
        now_ms: u64,
    ) -> Result<crate::bridge::store::BridgeOutcome> {
        let state_dir = self.paths.state_dir().to_path_buf();
        let controller = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            crate::bridge::store::Store::with_locked(&state_dir, |store| {
                #[cfg(feature = "testing")]
                controller.after_the_environment_record_is_taken.wait();
                controller.under_registration(&carried, || {
                    store.record_bridge_outcome(environment_id, opened_for, answer, now_ms)
                })?
            })
        })
        .await
        .map_err(|error| ControllerError::supervision(error.to_string()))?
    }
}

/// The account this daemon runs as: the name the system records for it, and not a variable of the
/// daemon's environment, which whoever started the daemon chose. Where the system's record has
/// none, as on Windows, the platform's own `USERNAME` stands in, and the user number where that is
/// not there either.
fn whoami() -> String {
    kr_ipc::paths::passwd_entry()
        .map(|entry| entry.name)
        .or_else(|| {
            cfg!(windows)
                .then(|| std::env::var("USERNAME").ok())
                .flatten()
        })
        .unwrap_or_else(|| format!("uid {}", kr_ipc::paths::current_uid()))
}

/// This daemon's side of an update of the host: its gate to new sessions, the creates under way,
/// and whether it has been told to stop.
///
/// A create passes the gate at its start and is counted until it has settled, and the gate is
/// closed under the same lock that counts: once a handover closes it, no create begins, and the
/// ones already under way are the ones a handover waits for. A create settles when its worker has
/// reported itself or is known not to, so every worker this daemon launched holds its own release
/// by the time the daemon answers that it has made way.
///
/// A closed gate is an attempt: it is closed for the attempt `prepare` began, and nothing but that
/// attempt can stop the daemon. An attempt ends at its first stop or resume, when its hold of
/// [`HANDOVER_HOLD_MS`] lapses (the gate then opens again by itself, so a daemon whose updater
/// gave up between asking it to prepare and telling it to stop goes on starting sessions), or
/// when a later `prepare` begins another. A stop names its attempt, and every decision is made
/// under the lock the gate is under, so a stop that arrives late, after its update gave up and
/// whatever came after, finds its attempt over and ends nothing; a daemon told to stop refuses to
/// resume or to prepare, and one that has resumed refuses a stop, so an updater that sees a
/// daemon resume knows no stop of any earlier attempt will end it.
#[derive(Debug)]
pub(super) struct Handover {
    gate: std::sync::Mutex<Gate>,
    /// Signalled whenever a create under way settles.
    settled: tokio::sync::Notify,
    /// Whether this daemon has been told to stop.
    stopping: tokio::sync::watch::Sender<bool>,
}

/// The gate itself.
#[derive(Debug, Default)]
struct Gate {
    /// The creates admitted and not yet settled.
    creates: usize,
    /// Why the gate is closed and until when, while it is.
    closed: Option<Closed>,
}

/// A closed gate, and the attempt it is closed for.
#[derive(Debug)]
struct Closed {
    /// The identity of the attempt, made when it began: what a stop must name.
    attempt: Uuid,
    /// The release the host is being updated to.
    target: ReleaseName,
    /// When the attempt's hold lapses and the gate opens again by itself.
    until: std::time::Instant,
}

/// What a daemon that has been told to stop says to a step that would keep it.
fn stopping() -> ControllerError {
    ControllerError::Refused {
        code: ErrorCode::EnvironmentUnavailable,
        detail: "this control daemon has been told to stop for an update of this host, and is \
                 stopping; the environment is served again once a daemon of the current release \
                 starts"
            .to_owned(),
    }
}

impl Default for Handover {
    fn default() -> Self {
        Self {
            gate: std::sync::Mutex::default(),
            settled: tokio::sync::Notify::new(),
            stopping: tokio::sync::watch::channel(false).0,
        }
    }
}

/// One create admitted through the gate, counted until it is dropped.
pub(super) struct UnderWay<'a> {
    handover: &'a Handover,
}

impl Drop for UnderWay<'_> {
    fn drop(&mut self) {
        {
            let mut gate = self.handover.lock();
            gate.creates = gate.creates.saturating_sub(1);
        }
        self.handover.settled.notify_waiters();
    }
}

impl Handover {
    fn lock(&self) -> std::sync::MutexGuard<'_, Gate> {
        self.gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Admits one create, counted until the returned value is dropped, or refuses it while the
    /// gate is closed.
    ///
    /// # Errors
    ///
    /// `RESOURCE_UNAVAILABLE`, naming the release the host is being updated to, while the gate is
    /// closed.
    pub(super) fn admit(&self) -> Result<UnderWay<'_>> {
        let mut gate = self.lock();
        if let Some(closed) = &gate.closed {
            if std::time::Instant::now() < closed.until {
                return Err(ControllerError::Refused {
                    code: ErrorCode::ResourceUnavailable,
                    detail: format!(
                        "this environment's control daemon is making way for release {} of this \
                         host, and starts no session meanwhile; create the session again once \
                         the update has finished",
                        closed.target
                    ),
                });
            }
            // The update that closed it did not come back within its hold: the gate is open.
            gate.closed = None;
        }
        gate.creates += 1;
        Ok(UnderWay { handover: self })
    }

    /// Begins an attempt: closes the gate for `hold` under a new identity, naming the release the
    /// host is being updated to, and returns the identity. An attempt already open is over.
    ///
    /// # Errors
    ///
    /// `ENVIRONMENT_UNAVAILABLE` once this daemon has been told to stop.
    pub(super) fn close(&self, target: &ReleaseName, hold: std::time::Duration) -> Result<Uuid> {
        let mut gate = self.lock();
        if *self.stopping.borrow() {
            return Err(stopping());
        }
        let attempt = kr_ipc::new_uuid();
        gate.closed = Some(Closed {
            attempt,
            target: target.clone(),
            until: std::time::Instant::now() + hold,
        });
        Ok(attempt)
    }

    /// Whether `attempt` is still the attempt the gate is closed for, within its hold: whether a
    /// step that acts for it may still be answered.
    pub(super) fn is_current(&self, attempt: Uuid) -> bool {
        self.lock().closed.as_ref().is_some_and(|closed| {
            closed.attempt == attempt && std::time::Instant::now() < closed.until
        })
    }

    /// Ends `attempt` and opens the gate, if it is still the attempt the gate is closed for.
    pub(super) fn end(&self, attempt: Uuid) {
        let mut gate = self.lock();
        if gate
            .closed
            .as_ref()
            .is_some_and(|closed| closed.attempt == attempt)
        {
            gate.closed = None;
        }
    }

    /// Ends the attempt named, or the open one when none is named, and opens the gate: the update
    /// is not going ahead. Returns the attempt it ended, none when the one named is already over
    /// or none was open.
    ///
    /// # Errors
    ///
    /// `ENVIRONMENT_UNAVAILABLE` once this daemon has been told to stop: it is going, and the
    /// environment is served again by the daemon that starts after it.
    pub(super) fn resume(&self, attempt: Option<Uuid>) -> Result<Option<Uuid>> {
        let mut gate = self.lock();
        if *self.stopping.borrow() {
            return Err(stopping());
        }
        match &gate.closed {
            Some(closed) if attempt.is_none_or(|named| named == closed.attempt) => {
                let ended = closed.attempt;
                gate.closed = None;
                Ok(Some(ended))
            }
            _ => Ok(None),
        }
    }

    /// Waits up to `within` for every create under way to settle, and says how many have not.
    pub(super) async fn settle(&self, within: std::time::Duration) -> usize {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            // Created before the count is read, so a create that settles between the two is not
            // missed: the notification reaches a waiter from the moment it is created.
            let settled = self.settled.notified();
            let creates = self.lock().creates;
            if creates == 0 {
                return 0;
            }
            if tokio::time::timeout_at(deadline, settled).await.is_err() {
                return self.lock().creates;
            }
        }
    }

    /// Tells this daemon to stop, under the attempt it was prepared for, while that attempt is
    /// the gate's and its hold has not lapsed. Asked again for the same attempt, it stops still.
    ///
    /// # Errors
    ///
    /// `INVALID_ARGUMENT` when no attempt is named, and `RESOURCE_UNAVAILABLE` when the attempt
    /// is not the one the gate is closed for: this daemon was not prepared, the preparation
    /// lapsed and it may have started sessions since, or another attempt began or this one
    /// ended.
    pub(super) fn stop(&self, attempt: Option<Uuid>) -> Result<Uuid> {
        let Some(attempt) = attempt else {
            return Err(ControllerError::InvalidArgument(
                "a stop names the attempt that prepare answered".to_owned(),
            ));
        };
        let gate = self.lock();
        match &gate.closed {
            Some(closed)
                if closed.attempt == attempt && std::time::Instant::now() < closed.until =>
            {
                self.stopping.send_replace(true);
                Ok(attempt)
            }
            _ => Err(ControllerError::Refused {
                code: ErrorCode::ResourceUnavailable,
                detail: "this control daemon was not prepared for this handover, or the \
                         preparation lapsed, or it is over; prepare it again"
                    .to_owned(),
            }),
        }
    }

    /// Waits until this daemon has been told to stop.
    pub(super) async fn stopped(&self) {
        let mut stopping = self.stopping.subscribe();
        let _ = stopping.wait_for(|stopping| *stopping).await;
    }
}

impl Controller {
    /// `host.update.handover`: makes way for another installed release, one step at a time.
    ///
    /// `prepare` begins an attempt: it closes the gate to new sessions, waits for the creates
    /// under way to settle and answers how this daemon was started and under which attempt;
    /// `stop` then tells the daemon to stop under that attempt, and `resume` ends it instead. A
    /// step for an attempt that is over changes nothing, so an updater that lost an answer asks
    /// again rather than guessing.
    ///
    /// # Errors
    ///
    /// `RESOURCE_UNAVAILABLE` when the creates under way do not settle within
    /// [`HANDOVER_SETTLE_MS`] (the attempt ends and the gate opens again), or when `stop` names an
    /// attempt that is not the gate's; `INVALID_ARGUMENT` when `stop` names none, and when a
    /// `prepare` finds that this daemon cannot say how it was started (nothing has changed then);
    /// `ENVIRONMENT_UNAVAILABLE` when `prepare` or `resume` comes after a `stop`.
    pub(super) async fn update_handover(&self, mutation: &MutationRequest) -> Result<ParamsValue> {
        let params: HostUpdateHandoverParams = parse(&mutation.params)?;
        // How this daemon was started is what the update starts a daemon of the new release like,
        // so a prepare that cannot say is refused before it changes the gate. A stop or a resume
        // is taken whatever this reads, and never answers an error for a step it has taken: what
        // it answers with is not what a daemon is started from.
        let started = match (&params.step, self.started()) {
            (_, Ok(started)) => started,
            (HandoverStep::Prepare, Err(error)) => return Err(error),
            (_, Err(_)) => (Vec::new(), String::new()),
        };
        let attempt = match params.step {
            HandoverStep::Prepare => {
                let attempt = self.handover.close(
                    &params.target,
                    std::time::Duration::from_millis(HANDOVER_HOLD_MS),
                )?;
                let unsettled = self
                    .handover
                    .settle(std::time::Duration::from_millis(HANDOVER_SETTLE_MS))
                    .await;
                if unsettled > 0 {
                    self.handover.end(attempt);
                    return Err(ControllerError::Refused {
                        code: ErrorCode::ResourceUnavailable,
                        detail: format!(
                            "{unsettled} sessions this control daemon is creating did not finish \
                             within {} seconds, so it does not make way for release {} now; its \
                             gate to new sessions is open again",
                            HANDOVER_SETTLE_MS / 1000,
                            params.target
                        ),
                    });
                }
                // An attempt that ended while the creates settled, resumed or superseded, is not
                // one this daemon answers as prepared: nothing acts on an attempt that is over.
                if !self.handover.is_current(attempt) {
                    return Err(ControllerError::Refused {
                        code: ErrorCode::ResourceUnavailable,
                        detail: "the attempt this control daemon was preparing under ended while \
                                 it waited for the sessions it was creating, so it does not make \
                                 way; prepare it again"
                            .to_owned(),
                    });
                }
                Some(attempt)
            }
            HandoverStep::Stop => Some(self.handover.stop(params.attempt.0)?),
            HandoverStep::Resume => self.handover.resume(params.attempt.0)?,
        };
        encode(&self.started_as(started, attempt))
    }

    /// Waits until a prepared handover has told this daemon to stop, which is when the process
    /// that serves it ends.
    pub async fn handed_over(&self) {
        self.handover.stopped().await;
    }

    /// How this daemon was started: its arguments, its program's own name left out, and its working
    /// directory. What a daemon of the release that replaces it is started with.
    fn started(&self) -> Result<(Vec<String>, String)> {
        let arguments = std::env::args_os()
            .skip(1)
            .map(std::ffi::OsString::into_string)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| {
                ControllerError::InvalidArgument(
                    "this daemon was started with an argument that is not text, so a daemon of \
                     another release cannot be started like it"
                        .to_owned(),
                )
            })?;
        let working_directory = std::env::current_dir()
            .map_err(|_| {
                ControllerError::InvalidArgument(
                    "this daemon's working directory no longer exists or cannot be read, so a \
                     daemon of another release cannot be started like it; stop this daemon, or \
                     start it again from a directory that exists, and run the update again"
                        .to_owned(),
                )
            })?
            .into_os_string()
            .into_string()
            .map_err(|_| {
                ControllerError::InvalidArgument(
                    "this daemon's working directory cannot be read as text, so a daemon of \
                     another release cannot be started like it"
                        .to_owned(),
                )
            })?;
        Ok((arguments, working_directory))
    }

    /// The answer to a step: how the daemon was started, and the attempt the answer is for.
    fn started_as(
        &self,
        (arguments, working_directory): (Vec<String>, String),
        attempt: Option<Uuid>,
    ) -> HostUpdateHandoverResult {
        HostUpdateHandoverResult {
            attempt: Nullable(attempt),
            release: Nullable(ReleaseName::new(self.release.clone()).ok()),
            pid: U64::new(u64::from(std::process::id())),
            arguments,
            working_directory,
        }
    }
}
