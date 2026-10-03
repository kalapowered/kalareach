//! The local door's routes: which handler answers each read and each mutation.

use std::sync::Arc;

use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, AuthorityRevision, ConnectionId, ControllerGeneration, GrantId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_transport::window::AcceptedDeadline;

use crate::error::{ControllerError, Result};

use super::{Controller, encode, error_reply, net, parse, respond};

impl Controller {
    /// Performs one project or workspace mutation under the admission its ingress recorded.
    ///
    /// Both doors reach the project service through here, so the checks the daemon owes such a
    /// mutation are made once rather than once per ingress: a local caller and a paired device get
    /// the same answer to the same request, and neither can drift away from the other.
    ///
    /// Everything between the envelope check and this point can wait: for this task to be
    /// scheduled and for the registry's lock. The admission is asked about here, with the registry
    /// lock held across the answer for the reason [`Self::check_admission`] states, and it travels
    /// into the service through [`Self::check_registration`], which the service asks twice more:
    /// immediately before it acts, and inside the transaction that begins the effect, so its own
    /// preparation is covered as well.
    ///
    /// `grant` is the grant a paired device holds, set by the network door, or none for a caller on
    /// this machine's own socket. It is how the service tells the two apart.
    ///
    /// # Errors
    ///
    /// Returns the refusal the admission or the project service decided.
    pub(crate) async fn project_mutation(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: crate::authority::AdmittedMutation,
        grant: Option<GrantId>,
    ) -> std::result::Result<ParamsValue, ProtocolError> {
        // A mutation carrying no freshness at all is a retry of an action this host may already
        // hold: section 9 keeps its record readable after the window that admitted it is gone, and
        // the project service's own retained record is where such a retry is answered from above.
        // What it may not do is perform the action again.
        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not be performed"
                    .to_owned(),
            }
            .to_protocol_error());
        }
        {
            let registry = self.registry.lock().await;
            self.check_admission(&registry, &carried)
                .map_err(|error| error.to_protocol_error())?;
        }
        // And again inside the service's own work. Between the answer above and the effect there
        // is a blocking task to be scheduled and a retained record to be looked for, and a clone
        // or a materialisation takes long enough that a grant can run out or a revocation can
        // complete inside one. The service asks this immediately after it has failed to find a
        // retained record and immediately before it performs the action, so a retry still gets its
        // own result while a first admission does not begin under authority that has gone, nor
        // while a fence this host owes stops dispatch.
        //
        // And once more inside the transaction that begins the effect: the one that writes the
        // operation row, the one that writes the workspace row and the one that reserves a
        // removal. Resolving a destination, opening and surveying a repository and taking the
        // journal's lock all happen before it, so a revocation or an expiry that completes during
        // that preparation, or a fence this host fails to raise in it, reaches an action that then
        // does not begin. That is section 9's revalidation immediately before the effect.
        let admission = self.admission_in_service(carried);
        self.project
            .write(actor_id, mutation, method, admission, grant)
            .await
    }

    /// Performs one automation mutation under the admission its ingress recorded.
    ///
    /// The admission is asked here, under the registry lock, for the reason
    /// [`Self::check_admission`] states, and then carried into the workflow journal, which asks it
    /// again inside the transaction that performs the action, immediately before the action's
    /// first write ([`Self::admission_in_service`]: a fence this host owes, the registration, the
    /// deadline). Nothing the service does before that write can wait long enough to outlast
    /// it: the answer and the write are under the journal's one lock, and the journal holds no
    /// record of an action it has not written. A retry is answered from its record before the
    /// admission is asked, so a caller whose window has since been replaced still gets its own
    /// result.
    ///
    /// # Errors
    ///
    /// Returns the refusal the admission or the automation service decided.
    pub(crate) async fn automation_mutation(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        carried: crate::authority::AdmittedMutation,
        caller_grant: Option<kr_protocol::ids::GrantId>,
    ) -> std::result::Result<ParamsValue, ProtocolError> {
        // A mutation carrying no freshness at all is a retry of an action this host may already
        // hold, and the journal's record is where such a retry is answered from. What it may not
        // do is perform the action.
        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not be performed"
                    .to_owned(),
            }
            .to_protocol_error());
        }
        {
            let registry = self.registry.lock().await;
            self.check_admission(&registry, &carried)
                .map_err(|error| error.to_protocol_error())?;
        }
        let admission: crate::automation::Admission = Arc::new(self.admission_in_service(carried));
        self.automation
            .write(actor_id, mutation, method, admission, caller_grant)
            .await
    }

    /// Reads one session's summary the way `session.read` answers it: from its worker while it
    /// runs, and from what this host recorded once it has closed. A session's name is built from
    /// it, at either door.
    pub(super) async fn session_summary(
        self: &Arc<Self>,
        session_id: kr_protocol::ids::SessionId,
    ) -> Result<kr_protocol::session::SessionSummary> {
        let read = self
            .session_read(&encode(&kr_protocol::session::SessionReadParams {
                session_id,
            })?)
            .await?;
        Ok(parse::<kr_protocol::session::SessionReadResult>(&read)?.session)
    }

    pub(super) async fn read_method(
        self: &Arc<Self>,
        actor_id: &ActorId,
        request: &Request,
    ) -> ControlFrame {
        let Some(method) = request.method.method() else {
            return error_reply(
                request.request_id,
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            );
        };
        if crate::transfer::TransferModule::serves(method) {
            return self.transfer.read_frame(actor_id, request).await;
        }
        if crate::project::ProjectModule::serves(method) {
            return self.project.read_frame(request).await;
        }
        if crate::voice::VoiceModule::serves(method) {
            // Voice is reachable from a paired device and nothing else, which is the registry's
            // own entry rather than a rule restated here. An actor that resolves to no live device
            // reaches none of it.
            let Some(device_id) = self.paired_device(actor_id) else {
                return error_reply(
                    request.request_id,
                    ErrorCode::PermissionDenied,
                    "voice is reachable from a paired device",
                );
            };
            return self.voice().read_frame(device_id, request).await;
        }
        if crate::catalogue::CatalogueModule::serves(method) {
            return self
                .catalogue_read_frame(kr_protocol::actor::ActorIngress::LocalIpc, request)
                .await;
        }
        if crate::changeset::ChangeSetModule::serves(method) {
            return self.changesets.read_frame(request).await;
        }
        if crate::automation::AutomationModule::serves(method) {
            return self.automation.read_frame(request, None).await;
        }
        if net::methods::serves(method) {
            let caller = net::owner::Caller::local(actor_id.clone());
            let outcome = self.pairing_read(caller, method, &request.params).await;
            return respond(request.request_id, outcome);
        }
        // The diagnostics are two answers, not one. The owner at their own machine is shown the
        // paths this host resolved and the names they chose, because that is a person asking their
        // own host where its files are; everything else that reaches a read arrived over the
        // network, and what leaves for somebody else to read carries each value on its class's
        // terms. The two are separated here rather than inside each answer, so a diagnostic added
        // later cannot forget which one it is.
        let owner = is_owners_own_socket(actor_id);
        let outcome = match method {
            Method::HostInfo => self
                .host_info()
                .await
                .and_then(|answer| host_read(answer, owner)),
            Method::EnvironmentCapabilities => self
                .environment_capabilities(&request.params)
                .await
                .and_then(|answer| host_read(answer, owner)),
            Method::EnvironmentList => self
                .environment_list()
                .await
                .and_then(|answer| host_read(answer, owner)),
            Method::EnvironmentInventory => self.environment_inventory(&request.params).await,
            Method::HostDoctor => self
                .host_doctor()
                .await
                .and_then(|answer| host_read(answer, owner)),
            Method::SessionList => self.session_list(&request.params).await,
            Method::SessionRead => self.session_read(&request.params).await,
            // A closed or crashed session's history and receipts are the archive's, and it serves
            // them with no worker. A live session's are its worker's, and this daemon says which
            // endpoint to ask rather than reading another process's journal behind its back.
            Method::HistoryPage => self.archive_history_page(&request.params).await,
            Method::ActionRead => {
                // A receipt of an action this host performed itself names no session and is kept
                // by the service that performed it. The catalogue's are answered from there, for
                // the actor that submitted the action; every other receipt is the archive's.
                if let Some(answer) = self.host_action_read(actor_id, request).await {
                    return answer;
                }
                self.archive_action_read(actor_id, &request.params, owner)
                    .await
            }
            Method::AgentToolsStatus => self.agent_tools_status(&request.params),
            Method::GrantList => self.grant_list(self.host_device_id(), &request.params),
            Method::DeviceList => self.device_list(&request.params).await,
            Method::PrivacyStatus => self.privacy_status().await,
            Method::DescriptionSetup => self.description_setup(),
            // A session's name is the environment's metadata, filtered for whoever asks. The owner
            // at this machine reaches the whole of every session's history.
            Method::SessionDescribe => {
                let summary = async {
                    let params: kr_protocol::describe::SessionDescribeParams =
                        parse(&request.params)?;
                    self.session_summary(params.session_id).await
                };
                match summary.await {
                    Ok(summary) => {
                        self.session_describe(summary, crate::describe::HistoryReach::WholeSession)
                            .await
                    }
                    Err(error) => Err(error),
                }
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a read this daemon serves",
                method.as_str()
            ))),
        };
        respond(request.request_id, outcome)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "a write is the actor, the request, the connection it arrived on and where that \
                  began, and the admission it carries"
    )]
    pub(super) async fn write_method(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        connection_id: ConnectionId,
        origin: Option<kr_protocol::local::BridgeOrigin>,
        accepted: Option<AcceptedDeadline>,
        admitted: Option<AuthorityRevision>,
    ) -> ControlFrame {
        if net::methods::serves(method) {
            // Pairing and owner confirmation are the network module's, and a local caller reaches
            // them as the host's own account: the issuing owner of what it invites.
            let caller = net::owner::Caller::local(actor_id.clone());
            let admission = self.pairing_admission(
                connection_id,
                admitted,
                accepted.map(|accepted| accepted.deadline),
            );
            let outcome = self
                .pairing_write(caller, method, mutation, admission)
                .await;
            return respond(mutation.request_id, outcome);
        }
        if crate::transfer::TransferModule::serves(method) {
            // The stored subject is read first, because reading it waits: for a blocking thread
            // and for the journal's lock. The admission is asked after it, inside the service's
            // own work, so that answer is the last thing between this mutation and its effect
            // rather than one more thing with waits after it.
            if let Err(error) = self
                .transfer
                .check_subject_of_record(actor_id, mutation, method)
                .await
            {
                return ControlFrame::Response(Response {
                    request_id: mutation.request_id,
                    outcome: Outcome::Error(error),
                });
            }
            // A mutation carrying no freshness at all is refused here. This service answers its
            // own retained actions before this point, so anything still travelling is a first
            // admission, and a first admission needs a deadline it was admitted under.
            let Some(accepted) = accepted else {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "this action carries no freshness, so it may be answered from \
                                 what this host holds and may not write"
                            .to_owned(),
                    }),
                );
            };
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            // The admission travels into the service's blocking work and is asked there, once no
            // retained record has answered and immediately before the action: this task, a
            // blocking thread and the journal are all waited for before it. It is the check every
            // service asks from inside its work, so a fence this host owes, a registration it has
            // withdrawn or replaced, and a deadline that has passed each stop the action.
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: Some(accepted.deadline),
            };
            return self
                .transfer
                .write_frame(
                    actor_id,
                    mutation,
                    method,
                    crate::transfer::TransferAdmission::new(Arc::clone(self), carried),
                )
                .await;
        }
        if crate::voice::VoiceModule::serves(method) {
            // Section 23 gives `voice.grant` both ingresses: a paired device changes its own voice
            // grant, and the person at this machine changes a device's. The other four are a
            // paired device's alone, which the registry refuses before this, and an actor on this
            // socket that resolves to no device reaches none of them.
            let actor = match self.paired_device(actor_id) {
                Some(device_id) => crate::voice::VoiceActor::Device(device_id),
                None if method == Method::VoiceGrant => crate::voice::VoiceActor::Owner,
                None => {
                    return error_reply(
                        mutation.request_id,
                        ErrorCode::PermissionDenied,
                        "voice is reachable from a paired device",
                    );
                }
            };
            // Everything between the envelope check and here can wait: for this task to be
            // scheduled, for a blocking thread, for the coordinator's own lock. An action whose
            // accepted deadline passed while it queued does not go on to write. A retry of a
            // completed voice change is answered from its record before this, so anything still
            // travelling is a first admission, and a first admission needs a deadline.
            let Some(accepted) = accepted.filter(|accepted| self.clock.now() < accepted.deadline)
            else {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "the deadline this action was admitted under passed before it \
                                 could run"
                            .to_owned(),
                    }),
                );
            };
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            // The admission travels with the change, as it does with a project or an automation
            // mutation, and the voice service asks it again where it writes.
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: Some(accepted.deadline),
            };
            // The revision this daemon is at, read now: a voice grant is written under the
            // authority in force at the moment of the write rather than the one a connection was
            // admitted under.
            let authority_revision = self.policy.lock().map_or_else(
                |_| AuthorityRevision::new(0),
                |policy| policy.authority_revision(),
            );
            return respond(
                mutation.request_id,
                self.voice_mutation(
                    actor_id,
                    actor,
                    mutation,
                    method,
                    authority_revision,
                    carried,
                )
                .await,
            );
        }
        if crate::catalogue::CatalogueModule::serves(method) {
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            // The admission travels into the catalogue and is asked again where the change
            // becomes durable, holding this daemon's connection table for that commit.
            let admission: Arc<dyn crate::catalogue::Admission> = Arc::new(
                crate::catalogue::DaemonAdmission::new(Arc::clone(self), carried),
            );
            // The owner's own ceremony, checked by this host's pairing service against its owner
            // devices. `None` is a host that is not on the network and so has no owner device, and
            // every method that needs the owner's confirmation (adopting a root, a grant, an
            // installation that widens what a package may do) is then refused rather than
            // performed under the identity of whoever asked.
            let pairing = self.network.get().map(|guard| Arc::clone(guard.pairing()));
            let confirmations = pairing
                .as_deref()
                .map(|host| host as &dyn crate::sharing::OwnerConfirmations);
            return crate::catalogue::frame(
                mutation.request_id,
                self.catalogue_write(actor_id, mutation, method, confirmations, admission)
                    .await,
            );
        }
        if crate::project::ProjectModule::serves(method) {
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            return crate::project::frame(
                mutation.request_id,
                // The machine's own socket: the caller holds no grant.
                self.project_mutation(actor_id, mutation, method, carried, None)
                    .await,
            );
        }
        if crate::automation::AutomationModule::serves(method) {
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            let answered = crate::automation::frame(
                mutation.request_id,
                self.automation_mutation(actor_id, mutation, method, carried, None)
                    .await,
            );
            // A run dispatches its nodes and waits for each of them, so the effect and its reply
            // are separated by however long that took, and a revocation can land in the interval.
            // What this host must not do is **disclose** an answer under authority that has since
            // been withdrawn, so the check is made again here, where the reply is about to go out.
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            return answered;
        }
        if crate::attention::AttentionModule::serves(method) {
            // The attention store's actions are the daemon's own, committed with their records
            // inside this daemon's guarded operation, so a revocation that begins while one is
            // committing finishes after it.
            if accepted.is_none_or(|accepted| self.clock.now() >= accepted.deadline) {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "the deadline this action was admitted under passed before it \
                                 could run"
                            .to_owned(),
                    }),
                );
            }
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            let answered = self
                .attention
                .write_frame(
                    self,
                    &crate::attention::Caller::Owner,
                    actor_id,
                    mutation,
                    method,
                    &carried,
                )
                .await;
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            return answered;
        }
        if crate::changeset::ChangeSetModule::serves(method) {
            // Everything between the envelope check and this point can wait: for this task to be
            // scheduled and for a blocking thread. An action whose accepted deadline passed while
            // it queued does not go on to write, and neither does one whose connection lost its
            // authority in the meantime.
            if accepted.is_none_or(|accepted| self.clock.now() >= accepted.deadline) {
                return respond(
                    mutation.request_id,
                    Err(ControllerError::WindowExpired {
                        detail: "the deadline this action was admitted under passed before it \
                                 could run"
                            .to_owned(),
                    }),
                );
            }
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            let Some(admitted_revision) = admitted else {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    "the authority this connection was admitted under has been withdrawn; open a \
                     new connection",
                );
            };
            // What the change-set service holds its effects under: the connection this mutation
            // arrived on, the authority revision it was admitted under, and the deadline this
            // daemon accepted. Between this point and the transaction that commits an effect lie
            // a blocking task, the journal's own lock and, for a capture, a whole working tree
            // being read, and authority can run out inside any of them. The service runs each of
            // those transactions inside this daemon's own guarded operation, so a revocation that
            // begins while one is committing finishes after it.
            let carried = crate::authority::AdmittedMutation {
                connection_id,
                admitted_revision,
                deadline: accepted.map(|accepted| accepted.deadline),
            };
            let controller = Arc::clone(self);
            let answered = self
                .changesets
                .write_frame(actor_id, mutation, method, carried, controller)
                .await;
            // The effect and its reply are separated by everything a blocking task waits for, and
            // a revocation can land in that interval. What this host must not do is **disclose**
            // an answer under authority that has since been withdrawn, so the check is made again
            // here, where the reply is about to go out.
            if let Err(error) = self.authorised(connection_id) {
                return error_reply(
                    mutation.request_id,
                    ErrorCode::PermissionDenied,
                    error.to_string(),
                );
            }
            return answered;
        }
        // The admission the mutation carries into its transaction: the deadline this daemon
        // accepted, the authority revision it was admitted under, and the connection it arrived
        // on. Every service re-checks all three inside its own transaction.
        //
        // The revision is the one `perform` read beside the registration check, before anything
        // waited, and never one read here. A revocation of another device stamps every surviving
        // registration with the revision it advanced to, so a change admitted before it and
        // checked against a revision read afterwards would be checked against the authority that
        // replaced the one it was admitted under.
        let Some(admitted_revision) = admitted else {
            return error_reply(
                mutation.request_id,
                ErrorCode::PermissionDenied,
                "the authority this connection was admitted under has been withdrawn; open a new \
                 connection",
            );
        };
        let carried = crate::authority::AdmittedMutation {
            connection_id,
            admitted_revision,
            deadline: accepted.map(|accepted| accepted.deadline),
        };
        // Four methods take no admission into a service: the environment record and the update
        // handover change nothing the revision or the deadline decides. They still do not run for a
        // connection whose registration was withdrawn while the call waited, and they do not run
        // while this host owes a fence it could not raise: whichever service performs an effect,
        // an owed fence stops it.
        if matches!(
            method,
            Method::EnvironmentEnrol
                | Method::EnvironmentForget
                | Method::EnvironmentRefresh
                | Method::HostUpdateHandover
        ) && let Err(error) = self
            .authorised(connection_id)
            .and_then(|_| self.check_fence())
        {
            return error_reply(mutation.request_id, error.code(), error.to_string());
        }
        let outcome = match method {
            // A create needs freshness of its own. An admission that carries none is a retry of an
            // action this host may already hold: section 9 keeps its record readable after the
            // window that admitted it is gone, and the reservation above is where such a retry is
            // answered from. What it may not do is start a session.
            Method::SessionCreate => match accepted {
                Some(_) => self.session_create(actor_id, mutation, carried).await,
                None => Err(ControllerError::WindowExpired {
                    detail: "this action carries no freshness, so it may be answered from what \
                             this host holds and may not start a session"
                        .to_owned(),
                }),
            },
            Method::SessionClose => {
                let actor = local_actor(actor_id.clone(), connection_id, self.generation);
                let closed = self
                    .session_close(mutation, &actor, accepted, carried)
                    .await;
                // A closure the host has accepted and not finished is a request outstanding, and
                // the setting decides whether that keeps the machine awake while it finishes. The
                // caller's answer does not wait for that decision.
                self.review_power_soon();
                closed
            }
            Method::AgentToolsInstall | Method::AgentToolsRemove => {
                self.agent_tools_change(actor_id, mutation, method, carried)
                    .await
            }
            Method::GrantCreate
            | Method::GrantRevoke
            | Method::DeviceRevoke
            | Method::DevicePreviewKeyUpdate
            | Method::DeliveryDestinationSecretSet => {
                self.authority_change(actor_id, mutation, method, carried)
                    .await
            }
            Method::EnvironmentEnrol | Method::EnvironmentForget | Method::EnvironmentRefresh => {
                // The envelope this host built for the connection, not anything the caller sent.
                // A refresh may open a bridge, and what may cross one is decided by this.
                let actor = local_actor(actor_id.clone(), connection_id, self.generation);
                // Each is performed once per actor's action: claimed first, and what it came to is
                // kept under the claim before it is answered, so a retry is answered from that
                // record rather than enrolling, forgetting or observing again. A retry that finds
                // the record is answered under the same check as any retained answer. A connection
                // that came over a process bridge has already crossed its one: the helper that made
                // it refuses to carry a request that would open another, and this is the rule kept
                // where only the destination can keep it.
                return self
                    .claimed_action(
                        actor_id,
                        mutation,
                        connection_id,
                        admitted,
                        self.environment_record(
                            &actor,
                            origin.is_some(),
                            mutation,
                            method,
                            carried,
                        ),
                    )
                    .await;
            }
            // Privacy mode and a session's pinned name are this daemon's own, each changed once per
            // actor's action: the action is claimed first, and what it came to is kept under the
            // claim before it is answered, so a retry is answered from that record.
            Method::PrivacySet
            | Method::SessionRename
            | Method::DescriptionConfigure
            | Method::DescriptionDownload => {
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
                        let outcome = if method == Method::PrivacySet {
                            let outcome = self.privacy_set(mutation, carried).await;
                            // The state is published: the description host looks again, with its
                            // fences following it.
                            self.descriptions.wake_host();
                            outcome
                        } else if crate::describe::serves(method) {
                            self.description_write(method, mutation, carried).await
                        } else {
                            let summary = match mutation.target.session_id.as_ref().copied() {
                                Some(session_id) => self.session_summary(session_id).await,
                                None => Err(ControllerError::InvalidArgument(
                                    "a rename names the session it renames".to_owned(),
                                )),
                            };
                            match summary {
                                Ok(summary) => {
                                    self.session_rename(actor_id, mutation, summary, carried)
                                        .await
                                }
                                Err(error) => Err(error),
                            }
                        };
                        let kept = self.settle_claim(&hold, &outcome);
                        drop(hold);
                        // The change happened, or was refused, and that is what the caller is
                        // told. A receipt that could not be kept leaves a claim with no answer,
                        // which a retry is told is unfinished and never performs again; it does not
                        // turn an applied change into a failed one.
                        if let Err(error) = kept {
                            eprintln!(
                                "kr-controller: could not keep what an action came to, so a retry \
                                 of it is answered as an unfinished one: {error}"
                            );
                        }
                        outcome
                    }
                    Ok(crate::grants::ActionClaim::Recorded(record)) => {
                        // A claim can be recorded between the retained lookup before a first
                        // admission and this one. What the action produced is given back only
                        // under authority that has not been withdrawn, and the answer is waited
                        // for first: it is the check made with the answer in hand that decides.
                        let answered = self
                            .recorded_authority_change(actor_id, mutation, record)
                            .await;
                        #[cfg(feature = "testing")]
                        self.after_the_retained_lookup.wait().await;
                        if let Err(error) = self.check_retained_answer(connection_id, admitted) {
                            return error_reply(
                                mutation.request_id,
                                error.code(),
                                error.to_string(),
                            );
                        }
                        return respond(mutation.request_id, answered);
                    }
                    Err(error) => Err(error),
                }
            }
            // A machine group step changes this environment's own record under the revision it was
            // admitted at, read before anything waited rather than again here: a revocation of
            // another device stamps every surviving connection with the revision it advanced to,
            // and a step checked against a revision read afterwards would be checked against the
            // authority that replaced the one it was admitted under.
            Method::MachineJoin | Method::MachineMerge | Method::MachineSplit => match admitted {
                Some(admitted_revision) => {
                    self.machine_step(
                        actor_id,
                        mutation,
                        method,
                        crate::authority::AdmittedMutation {
                            admitted_revision,
                            ..carried
                        },
                    )
                    .await
                }
                None => Err(ControllerError::PermissionDenied {
                    detail: "the authority this connection was admitted under has been \
                             withdrawn; open a new connection"
                        .to_owned(),
                }),
            },
            // Only the owner at this machine replaces what the host runs.
            Method::HostUpdateHandover => {
                if is_owners_own_socket(actor_id) {
                    self.update_handover(mutation).await
                } else {
                    Err(ControllerError::PermissionDenied {
                        detail: "only the owner at this machine hands its control daemon over to \
                                 an update"
                            .to_owned(),
                    })
                }
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a mutation this daemon serves",
                method.as_str()
            ))),
        };
        respond(mutation.request_id, outcome)
    }
}

/// Builds the actor envelope a local caller acts under.
///
/// Ingress is recorded as the local operating-system path, never as a paired device. A local
/// caller cannot relabel itself, because the host constructs this rather than accepting it.
#[must_use]
pub fn local_actor(
    actor_id: ActorId,
    connection_id: ConnectionId,
    generation: ControllerGeneration,
) -> kr_protocol::actor::ActorEnvelope {
    kr_protocol::actor::ActorEnvelope {
        actor_id,
        ingress: kr_protocol::actor::ActorIngress::LocalIpc,
        device_id: Nullable::null(),
        grant_id: Nullable::null(),
        grant_revision: Nullable::null(),
        controller_generation: generation,
        connection_id,
    }
}

/// Whether this caller is the owner, at this machine, over its own socket.
///
/// The local listener admits an operating-system peer and names it after that peer's user; a paired
/// device is named after its device identity by the transport. Anything this host cannot recognise
/// as the local peer is treated as somebody else, because that is the answer that withholds rather
/// than the one that publishes.
fn is_owners_own_socket(actor_id: &ActorId) -> bool {
    actor_id.as_str().starts_with(LOCAL_PRINCIPAL_PREFIX)
}

/// Encodes one host-and-environment read for whoever asked: the one function that decides what a
/// paired device reads of this host.
///
/// The owner at their own machine, on its owner-only socket, is answered with the display form:
/// the account the environments belong to, the directories this host resolved, what the platform
/// said. Everybody else - a paired device, and any caller that is not the owner's own socket - is
/// answered with the export form of the same answer,
/// [`kr_protocol::hostinfo::export::ForExport::for_export`], which carries each
/// account name, path and platform message as its class and its length and composes the rest
/// from this build's own words. The four answers are `host.info`, `environment.list`,
/// `environment.capabilities` and `host.doctor`; each has its one reduction beside its type, and
/// the protocol's tests walk every field of all four, so a field added to one is classed before it
/// can be sent.
fn host_read<T>(answer: T, owner: bool) -> Result<ParamsValue>
where
    T: kr_protocol::hostinfo::export::ForExport + serde::Serialize,
{
    if owner {
        encode(&answer)
    } else {
        encode(answer.for_export().get())
    }
}

/// How the local listener names the operating-system peer it admitted.
pub(super) const LOCAL_PRINCIPAL_PREFIX: &str = "local:";
