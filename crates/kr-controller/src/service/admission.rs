//! Admitting a local connection and the mutations it carries.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_ipc::peer::PeerIdentity;
use kr_protocol::envelope::MutationRequest;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::hello::ActionWindow;
use kr_protocol::ids::{ActorId, AuthorityRevision, ConnectionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::U64;
use kr_protocol::session::{SessionCloseParams, SessionCreateParams};
use kr_transport::clock::ContinuousClock;
use kr_transport::lease::LeaseRefusal;
use kr_transport::window::AcceptedDeadline;

use crate::error::{ControllerError, Result};
use crate::registry::Registry;

use super::authority_changes::{destination_identifier, secret_params};
use super::{Controller, net, parse};

impl Controller {
    /// Validates a local caller's record and registers its connection in one step.
    ///
    /// The two have to be one step. Validating first and registering afterwards leaves a gap in
    /// which authority can be withdrawn, and a connection registered in that gap would pass every
    /// later check. The registry lock is taken first and the connection table second, which is the
    /// order [`Self::revoke_authority`] uses, so neither can interleave with the other.
    pub(super) async fn admit_connection(
        &self,
        connection_id: ConnectionId,
        actor_id: &ActorId,
        peer: &PeerIdentity,
    ) -> Result<()> {
        let registry = self.registry.lock().await;
        let admitted_revision = registry.authority_revision()?;
        // A local caller's record is the operating-system identity the listener authenticated.
        // Re-checking it here, inside the same critical section as the registration, is the final
        // validation the transport's contract names: the listener's check happened when the
        // connection was accepted, and this one happens where the registration is written, so
        // nothing can be admitted between the two.
        peer.authorise(kr_ipc::paths::current_uid())?;
        let mut admitted = self.admitted_table();
        admitted.insert(
            connection_id,
            AdmittedConnection::new(actor_id.clone(), admitted_revision),
        );
        drop(admitted);
        drop(registry);
        Ok(())
    }

    /// Refuses a mutation whose admission no longer stands, inside the caller's transaction.
    ///
    /// The caller holds the store lock it is about to write under, and passes the registry guard
    /// it took next: that order is the one admission and revocation both take, so neither can
    /// interleave with this. Nothing is awaited between this answer and the write, which is what
    /// makes the answer still true when the write happens.
    ///
    /// Checking before the wait would prove the admission stood before the wait, which is not the
    /// question. `docs/host/README.md` states the rule for the services outside this crate.
    ///
    /// # Errors
    ///
    /// Returns the way the admission lapsed: its deadline passed, the authority it was admitted
    /// under was withdrawn, or its connection's registration was.
    pub fn check_admission(
        &self,
        registry: &Registry,
        admission: &crate::authority::AdmittedMutation,
    ) -> Result<()> {
        self.check_fence()?;
        let authority_revision = registry.authority_revision()?;
        let admitted = self.admitted_table();
        let registered = admitted
            .get(&admission.connection_id)
            .is_some_and(|connection| connection.admitted_revision >= authority_revision);
        drop(admitted);
        admission
            .check(crate::authority::AdmissionContext {
                now: self.clock.now(),
                authority_revision,
                registered,
            })
            .map_err(|lapse| match lapse {
                crate::authority::AdmissionLapse::Expired => ControllerError::WindowExpired {
                    detail: lapse.to_string(),
                },
                crate::authority::AdmissionLapse::Revoked
                | crate::authority::AdmissionLapse::Deregistered => {
                    ControllerError::PermissionDenied {
                        detail: lapse.to_string(),
                    }
                }
            })
    }

    /// The admission check a mutation's own effect repeats, when it is carrying an admission.
    ///
    /// A withdrawal is several writes and not all of them are in one store, and each waits for a
    /// lock of its own. The check is cheap and the guard is already held, so a caller repeats it
    /// before each write **that can still be refused**: once authority has actually been
    /// withdrawn, the rest of that withdrawal follows whatever the clock has done since, and its
    /// caller stops asking. `None` on either side is the local owner's own path, which carries no
    /// mutation window.
    pub(super) fn still_admitted(
        &self,
        registry: Option<&Registry>,
        carried: Option<&crate::authority::AdmittedMutation>,
    ) -> Result<()> {
        match (registry, carried) {
            (Some(registry), Some(carried)) => self.check_admission(registry, carried),
            _ => Ok(()),
        }
    }

    /// Returns the table of admitted connections.
    ///
    /// A synchronous lock, deliberately: nothing is awaited while it is held, and the registry
    /// guard often is. A connection table behind an asynchronous lock would make every reader of
    /// it require the registry to be shared across threads, which a SQLite connection is not.
    pub(super) fn admitted_table(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<ConnectionId, AdmittedConnection>> {
        self.admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Runs one service transaction under a carried admission.
    ///
    /// This is the guarded operation `docs/host/README.md` names for a service in another crate. A
    /// service holds its own store lock, calls this, and writes inside the closure: the registry
    /// lock is taken here and held across the check and the write, so a revocation cannot land
    /// between them. Nothing is awaited inside the closure, which is what makes the answer still
    /// true when the write happens.
    ///
    /// # Errors
    ///
    /// Returns the way the admission lapsed, or whatever the closure returns.
    pub async fn enter_admitted<T>(
        &self,
        admission: &crate::authority::AdmittedMutation,
        write: impl FnOnce(&mut Registry) -> Result<T>,
    ) -> Result<T> {
        // An admission with no deadline is a retry's admission: it may be *answered* from what
        // this host already holds, and it may not write. Section 9 keeps a receipt readable after
        // the freshness that admitted it is gone; what the freshness admitted was the action, and
        // nothing here can admit a new one without it.
        if admission.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not write"
                    .to_owned(),
            });
        }
        let mut registry = self.registry.lock().await;
        self.check_admission(&registry, admission)?;
        write(&mut registry)
    }

    /// Refuses a request on a connection whose registration has been withdrawn.
    pub(super) fn authorised(&self, connection_id: ConnectionId) -> Result<ActorId> {
        let admitted = self.admitted_table();
        match admitted.get(&connection_id) {
            Some(connection) => Ok(connection.actor_id.clone()),
            None => Err(ControllerError::PermissionDenied {
                detail: "the authority this connection was admitted under has been withdrawn; \
                         open a new connection"
                    .to_owned(),
            }),
        }
    }

    /// Refuses a retained answer that this host may not give back now: a fence this host owes, a
    /// registration that has been withdrawn or replaced since `admitted` was read.
    ///
    /// Finding a retained answer waits (for the registry, for a store's lock, for a blocking
    /// thread), and section 9 has the host check current authority before a retained receipt goes
    /// back, so a caller whose registration was withdrawn or replaced meanwhile cannot use an old
    /// action identifier to read what the action produced. It is the check every service asks from
    /// inside its work, asked without a deadline: a receipt stays readable after the window that
    /// admitted its action is gone. `admitted` is the revision read beside the first registration
    /// check, and none is read here; a caller that could read none has no registration to answer
    /// under.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::check_registration`] returns, and
    /// [`ControllerError::PermissionDenied`] when there is no revision to check against.
    pub(super) fn check_retained_answer(
        &self,
        connection_id: ConnectionId,
        admitted: Option<AuthorityRevision>,
    ) -> Result<()> {
        let admitted_revision = admitted.ok_or_else(|| ControllerError::PermissionDenied {
            detail: "the authority this connection was admitted under has been withdrawn; open a \
                     new connection"
                .to_owned(),
        })?;
        self.check_registration(&crate::authority::AdmittedMutation {
            connection_id,
            admitted_revision,
            deadline: None,
        })
    }

    /// The admission a service asks again from inside the work a mutation has begun.
    ///
    /// Every service that performs a mutation's effect after a wait is handed this one check, the
    /// project service, the transfer service and the workflow journal alike:
    /// [`Self::check_registration`], which asks the fence this host owes before the connection's
    /// registration and the accepted deadline.
    pub(crate) fn admission_in_service(
        self: &Arc<Self>,
        carried: crate::authority::AdmittedMutation,
    ) -> impl Fn() -> std::result::Result<(), ProtocolError> + Send + Sync + 'static {
        let controller = Arc::clone(self);
        move || {
            controller
                .check_registration(&carried)
                .map_err(|error| error.to_protocol_error())
        }
    }

    /// Refuses a mutation that a fence this host owes stops, or whose registration or accepted
    /// deadline has lapsed.
    ///
    /// These are the answers a caller can have without waiting for anything, so this can be asked
    /// from inside work that has already begun — a blocking task, a service's own call — where
    /// taking the registry's asynchronous lock is not possible.
    ///
    /// The fence comes first. A withdrawal whose fence could not be raised did not advance the
    /// revision, so every registration still stands under the revision it carries; without the
    /// fence this would let a mutation admitted just before that failure act after it.
    ///
    /// The registration carries the revision it stands under, and that is what makes the reading
    /// sufficient. Both revocations keep it true. [`Self::revoke_authority`] takes every
    /// connection out of the table before anything can observe the revision it installed, so a
    /// mutation whose connection is gone is refused. A revocation that withdraws one device leaves
    /// the rest registered and stamps them with the revision it advanced to, so a mutation
    /// admitted before that point finds its registration standing under a *later* revision than
    /// the one it carries, which is the authority it was admitted under having been replaced. The
    /// registration therefore has to stand under exactly the revision the mutation carries: a
    /// lower one is a registration this host has already replaced, and a higher one is a
    /// revocation this mutation predates.
    ///
    /// The order is the contract's: authority first, then freshness, so a caller that may act on a
    /// spent deadline cannot read past a withdrawal with it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] while a fence is owed and for a registration
    /// that has been withdrawn or replaced, and [`ControllerError::WindowExpired`] for a deadline
    /// that has passed.
    pub(crate) fn check_registration(
        &self,
        admission: &crate::authority::AdmittedMutation,
    ) -> Result<()> {
        self.check_registration_in(&self.admitted_table(), admission)
    }

    /// Runs `commit` while a mutation's registration is held standing, and refuses it where
    /// [`Self::check_registration`] would: a fence owed, the registration withdrawn or replaced,
    /// or the deadline passed.
    ///
    /// [`Self::check_registration`] answers for the moment it is asked. A change that becomes
    /// durable later asks here instead: the connection table stays held from the check to the end
    /// of `commit`, and revoking authority and withdrawing a connection both take that table, so
    /// a withdrawal is ordered wholly before the check or wholly after the commit. `commit` is
    /// synchronous and awaits nothing, because the table is a synchronous lock that every admission
    /// waits on. It may be a store transaction, including its sync to disk, and holds nothing else
    /// of this host's that a table holder takes.
    ///
    /// # Errors
    ///
    /// Returns what [`Self::check_registration`] returns, in which case `commit` did not run.
    pub(crate) fn under_registration<T>(
        &self,
        admission: &crate::authority::AdmittedMutation,
        commit: impl FnOnce() -> T,
    ) -> Result<T> {
        let admitted = self.admitted_table();
        self.check_registration_in(&admitted, admission)?;
        let committed = commit();
        drop(admitted);
        Ok(committed)
    }

    /// Returns the wall-clock deadline a mutation was accepted under, for the receipt it leaves.
    ///
    /// The deadline decides on the continuous clock. A receipt carries a wall-clock one, because
    /// that is what a person and the wire read, so what is left of it is measured on the clock
    /// that decides it and laid over the wall clock now.
    pub(crate) fn receipt_deadline_ms(
        &self,
        admission: &crate::authority::AdmittedMutation,
    ) -> Option<u64> {
        let deadline = admission.deadline?;
        let remaining = u64::try_from(
            deadline
                .saturating_duration_since(self.clock.now())
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        Some(kr_ipc::now_ms().get().saturating_add(remaining))
    }

    /// [`Self::check_registration`], for a caller that already holds the connection table.
    ///
    /// A caller that writes a marker under that table, so that a revocation cannot withdraw the
    /// registration between the answer and the marker, asks here rather than taking the table a
    /// second time.
    ///
    /// # Errors
    ///
    /// As [`Self::check_registration`].
    pub(super) fn check_registration_in(
        &self,
        admitted: &BTreeMap<ConnectionId, AdmittedConnection>,
        admission: &crate::authority::AdmittedMutation,
    ) -> Result<()> {
        self.check_fence()?;
        let standing = admitted
            .get(&admission.connection_id)
            .map(|connection| connection.admitted_revision);
        let Some(standing) = standing else {
            return Err(ControllerError::PermissionDenied {
                detail: crate::authority::AdmissionLapse::Deregistered.to_string(),
            });
        };
        if standing != admission.admitted_revision {
            return Err(ControllerError::PermissionDenied {
                detail: crate::authority::AdmissionLapse::Revoked.to_string(),
            });
        }
        if admission
            .deadline
            .is_some_and(|deadline| self.clock.now() >= deadline)
        {
            return Err(ControllerError::WindowExpired {
                detail: crate::authority::AdmissionLapse::Expired.to_string(),
            });
        }
        Ok(())
    }

    /// Returns the authority revision a connection was admitted under.
    pub(super) fn admitted_revision(
        &self,
        connection_id: ConnectionId,
    ) -> Result<AuthorityRevision> {
        let admitted = self.admitted_table();
        admitted.get(&connection_id).map_or_else(
            || {
                Err(ControllerError::PermissionDenied {
                    detail: "the authority this connection was admitted under has been withdrawn; \
                             open a new connection"
                        .to_owned(),
                })
            },
            |connection| Ok(connection.admitted_revision),
        )
    }

    /// Withdraws one connection's registration.
    pub(super) fn deregister(&self, connection_id: ConnectionId) {
        self.admitted_table().remove(&connection_id);
    }

    /// Ties the latch of a connection's write boundary to its registration, so that the
    /// registration going sets it ([`AdmittedConnection`]).
    ///
    /// Done once, when the boundary is built and before anything can be sent on it. A registration
    /// already gone sets the latch at once: the connection was withdrawn before its boundary
    /// existed. The table is held across the attachment, and a registration is removed under the
    /// same lock, so the latch is set either here or by the removal, never by neither.
    pub(crate) fn latch_registration(
        &self,
        connection_id: ConnectionId,
        latch: &Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut admitted = self.admitted_table();
        match admitted.get_mut(&connection_id) {
            Some(registration) => {
                debug_assert!(
                    registration.latch.is_none(),
                    "a registration holds the latch of one write boundary"
                );
                registration.latch = Some(Arc::clone(latch));
            }
            None => latch.store(true, std::sync::atomic::Ordering::Release),
        }
    }

    /// Takes the dispatch lease a remote-origin mutation needs, and returns its deadline.
    ///
    /// Section 9 requires a live worker-held authority lease from the current controller generation
    /// and revision for remote dispatch. A locally authenticated caller is not remote dispatch and
    /// needs none, which is why the ingress decides rather than the method.
    ///
    /// A fence this host owes refuses the lease. The fence is asked after the lease is taken, and
    /// not before: a debt is published without the revision moving, so the issuer still holds every
    /// worker's acknowledgement of the revision in force and renews on it, and only this keeps a
    /// lease from being handed out while the withdrawal is owed. It stays refused until the barrier
    /// that retires the debt has had the issuer adopt the revision it advanced to, which
    /// [`Self::withdraw`] orders before the debt is let go, and the worker has acknowledged that
    /// revision. Nothing here stops a lease taken just before the debt was published: it dispatches
    /// for what is left of its five seconds, which is the bound section 9 gives a lease, and its
    /// lapse completes nothing, since a barrier completes only by a worker's acknowledgement or a
    /// confirmed end. No renewal is stopped when a debt is published, because an acknowledgement of
    /// the revision still in force would lift the stop.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseDenied::NotAcknowledged`] when the worker has not acknowledged the revision in
    /// force, or the revision moved while the lease was taken, which an announcement to it can
    /// change, and [`LeaseDenied::Stopped`] for what one cannot: a generation this daemon no longer
    /// holds, or a fence it owes.
    pub(super) async fn dispatch_lease(
        &self,
        session_id: SessionId,
        actor: &kr_protocol::actor::ActorEnvelope,
    ) -> std::result::Result<Option<kr_transport::clock::ContinuousInstant>, LeaseDenied> {
        if actor.ingress != kr_protocol::actor::ActorIngress::PairedDevice {
            return Ok(None);
        }
        let not_acknowledged = || {
            LeaseDenied::NotAcknowledged(ControllerError::PermissionDenied {
                detail: "the worker has not acknowledged this environment's authority revision, \
                         so no remote action can be dispatched to it"
                    .to_owned(),
            })
        };
        let lease = match self
            .leases
            .renew(session_id, self.generation, &*self.clock)
            .map_err(|error| {
                LeaseDenied::Stopped(ControllerError::supervision(error.to_string()))
            })? {
            Ok(lease) => lease,
            Err(LeaseRefusal::GenerationReplaced) => {
                return Err(LeaseDenied::Stopped(ControllerError::PermissionDenied {
                    detail: "this daemon no longer holds the generation this lease was issued \
                             under"
                        .to_owned(),
                }));
            }
            Err(LeaseRefusal::RevisionNotAcknowledged | LeaseRefusal::NoLease) => {
                return Err(not_acknowledged());
            }
        };
        self.check_fence().map_err(LeaseDenied::Stopped)?;
        // A barrier that advanced the revision after this lease was taken has left it a lease for
        // the revision it replaced: no lease at all, which a worker's acknowledgement of the new
        // revision gives.
        if lease.authority_revision != self.leases.authority_revision() {
            return Err(not_acknowledged());
        }
        Ok(Some(lease.deadline))
    }

    /// Issues an action window for one authenticated connection.
    ///
    /// # Errors
    ///
    /// Returns an error when the random generator is unavailable.
    pub(super) fn issue_window(&self, connection_id: ConnectionId) -> Result<ActionWindow> {
        self.windows
            .issue(connection_id, self.boot_epoch)
            .map_err(|error| ControllerError::supervision(error.to_string()))
    }

    /// Checks the envelope of a mutation this daemon is asked to perform.
    ///
    /// The target says which environment the effect belongs to, and the window says whether this
    /// is a first admission the host will accept at all. Both are checked before the create token
    /// reaches the registry, so an expired window never reserves a session.
    pub(super) fn check_envelope(
        &self,
        connection_id: ConnectionId,
        mutation: &MutationRequest,
        method: Method,
        received_at: kr_transport::clock::ContinuousInstant,
    ) -> Result<AcceptedDeadline> {
        use kr_protocol::authority::AuthorityDecision;

        // The registry decides first: an unlisted name, a version this build does not implement
        // and an ingress that may not reach the method are all refused before a parameter is read.
        let entry = match kr_protocol::method::decide(
            mutation.method.as_str(),
            mutation.method_version,
            kr_protocol::actor::ActorIngress::LocalIpc,
        ) {
            AuthorityDecision::Listed(entry) => entry,
            AuthorityDecision::Denied(reason) => {
                return Err(match reason.error_code() {
                    ErrorCode::UnsupportedSchema => ControllerError::InvalidArgument(format!(
                        "{} is not implemented at version {}",
                        mutation.method.as_str(),
                        mutation.method_version
                    )),
                    _ => ControllerError::NotListed {
                        method: mutation.method.as_str().to_owned(),
                    },
                });
            }
        };
        mutation
            .target
            .validate()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        if mutation.target.environment_id != self.paths.environment_id() {
            return Err(ControllerError::InvalidArgument(format!(
                "this daemon owns environment {}",
                self.paths.environment_id()
            )));
        }
        // The target and the parameters have to name the same subject. A close that pointed at
        // one session and carried another in its parameters would close the one nobody addressed.
        // Creation is where the selector table and the envelope differ for a good reason:
        // `session.create` selects a session because it allocates one, and no request can name a
        // session that does not exist yet, so its subject is the environment.
        match method {
            Method::SessionClose => {
                let named = mutation
                    .target
                    .session_id
                    .as_ref()
                    .copied()
                    .ok_or_else(|| {
                        ControllerError::InvalidArgument(format!(
                            "{} names the session it acts on",
                            entry.name
                        ))
                    })?;
                let params: SessionCloseParams = parse(&mutation.params)?;
                if params.session_id != named {
                    return Err(ControllerError::InvalidArgument(
                        "the request's target and its parameters name different sessions"
                            .to_owned(),
                    ));
                }
            }
            Method::SessionCreate => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "a create allocates the session it is for, so it names none".to_owned(),
                    ));
                }
                let params: SessionCreateParams = parse(&mutation.params)?;
                if params.environment_id != mutation.target.environment_id {
                    return Err(ControllerError::InvalidArgument(
                        "the request's target and its parameters name different environments"
                            .to_owned(),
                    ));
                }
            }
            // A skill installation is the host's, not a session's, so its target names the
            // environment and nothing else. A request that named a session here would be asking
            // for an installation scoped to something installations do not have.
            Method::AgentToolsInstall | Method::AgentToolsRemove => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "an installation belongs to this host, not to a session".to_owned(),
                    ));
                }
                let _: kr_protocol::skill::AgentToolsParams = parse(&mutation.params)?;
            }
            // Sharing acts on a session, and the session it acts on is the one its target names.
            Method::GrantCreate => {
                let named = mutation
                    .target
                    .session_id
                    .as_ref()
                    .copied()
                    .ok_or_else(|| {
                        ControllerError::InvalidArgument(format!(
                            "{} names the session it shares",
                            entry.name
                        ))
                    })?;
                let params: kr_protocol::sharing::GrantCreateParams = parse(&mutation.params)?;
                if params.session_id != named {
                    return Err(ControllerError::InvalidArgument(
                        "the request's target and its parameters name different sessions"
                            .to_owned(),
                    ));
                }
            }
            // A revocation acts on a grant or a device, both of which belong to this host rather
            // than to one session: a grant can cover several sessions, and a device holds several
            // grants. A request that named a session here would be asking for a revocation scoped
            // to something revocations do not have.
            Method::GrantRevoke => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "a grant belongs to this host, not to one session".to_owned(),
                    ));
                }
                let _: kr_protocol::sharing::GrantRevokeParams = parse(&mutation.params)?;
            }
            Method::DeviceRevoke => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "a device belongs to this host, not to one session".to_owned(),
                    ));
                }
                let _: kr_protocol::sharing::DeviceRevokeParams = parse(&mutation.params)?;
            }
            // An enrolment, a removal and a refresh all act on this host's own record of the
            // environments it reaches, not on a session. A request that named a session here
            // would be asking for a record scoped to something the record does not have.
            Method::EnvironmentEnrol | Method::EnvironmentForget | Method::EnvironmentRefresh => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "an enrolled environment belongs to this host, not to one session"
                            .to_owned(),
                    ));
                }
            }
            // A handover acts on this daemon, which serves the whole environment, not on a session.
            Method::HostUpdateHandover => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "a handover belongs to this environment's daemon, not to one session"
                            .to_owned(),
                    ));
                }
                let _: kr_protocol::update::HostUpdateHandoverParams = parse(&mutation.params)?;
            }
            Method::DevicePreviewKeyUpdate => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "a device belongs to this host, not to one session".to_owned(),
                    ));
                }
                let _: kr_protocol::sharing::DevicePreviewKeyUpdateParams =
                    parse(&mutation.params)?;
            }
            // A notification destination belongs to this environment, not to a session. The
            // credential is checked here, before the action is claimed, so a credential of the
            // wrong shape is refused without holding its action identifier.
            Method::DeliveryDestinationSecretSet => {
                if mutation.target.session_id.as_ref().is_some()
                    || mutation.target.application_instance_id.is_present()
                {
                    return Err(ControllerError::InvalidArgument(
                        "a notification destination belongs to this environment, not to one \
                         session"
                            .to_owned(),
                    ));
                }
                let params = secret_params(&mutation.params)?;
                destination_identifier(&params.destination_id)?;
                crate::push::external::check_secret(&params.secret)
                    .map_err(ControllerError::InvalidArgument)?;
            }
            // Privacy mode belongs to the environment, not to a session.
            Method::PrivacySet => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(
                        "privacy mode belongs to this environment, not to one session".to_owned(),
                    ));
                }
                let _: kr_protocol::privacy::PrivacySetParams = parse(&mutation.params)?;
            }
            // The description settings and the fetch of the model's files belong to the
            // environment: the target names it and no session.
            _ if crate::describe::serves(method) => {
                if mutation.target.session_id.as_ref().is_some() {
                    return Err(ControllerError::InvalidArgument(format!(
                        "{} acts on this environment's descriptions, not on one session",
                        entry.name
                    )));
                }
                match method {
                    Method::DescriptionConfigure => {
                        let _: kr_protocol::describe::DescriptionConfigureParams =
                            parse(&mutation.params)?;
                    }
                    _ => {
                        let _: kr_protocol::describe::DescriptionDownloadParams =
                            parse(&mutation.params)?;
                    }
                }
            }
            // A rename acts on a session, and the session it acts on is the one its target names.
            Method::SessionRename => {
                let named = mutation
                    .target
                    .session_id
                    .as_ref()
                    .copied()
                    .ok_or_else(|| {
                        ControllerError::InvalidArgument(format!(
                            "{} names the session it renames",
                            entry.name
                        ))
                    })?;
                let params: kr_protocol::describe::SessionRenameParams = parse(&mutation.params)?;
                if params.session_id != named {
                    return Err(ControllerError::InvalidArgument(
                        "the request's target and its parameters name different sessions"
                            .to_owned(),
                    ));
                }
            }
            _ if crate::voice::VoiceModule::serves(method) => {
                crate::voice::VoiceModule::check_subject(method, mutation)?;
            }
            _ if crate::transfer::TransferModule::serves(method) => {
                crate::transfer::TransferModule::check_subject(method, mutation)?;
            }
            _ if crate::project::ProjectModule::serves(method) => {
                crate::project::ProjectModule::check_subject(method, mutation)?;
            }
            _ if crate::catalogue::CatalogueModule::serves(method) => {
                crate::catalogue::CatalogueModule::check_subject(method, mutation)?;
            }
            _ if crate::changeset::ChangeSetModule::serves(method) => {
                crate::changeset::ChangeSetModule::check_subject(method, mutation)?;
            }
            _ if crate::automation::AutomationModule::serves(method) => {
                crate::automation::AutomationModule::check_subject(method, mutation)?;
            }
            _ if crate::attention::AttentionModule::serves(method) => {
                crate::attention::AttentionModule::check_subject(method, mutation)?;
            }
            // Pairing and owner confirmation act on this host rather than on a session, so the
            // target names this environment and no session inside it.
            _ if net::methods::serves(method) => {
                if mutation.target.session_id.is_present() {
                    return Err(ControllerError::InvalidArgument(format!(
                        "{} acts on this host and names no session",
                        entry.name
                    )));
                }
            }
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not a mutation this daemon serves",
                    entry.name
                )));
            }
        }
        // A local caller's authority is the operating-system caller the listener authenticated.
        if mutation.grant_id.as_ref().is_some() {
            return Err(ControllerError::InvalidArgument(
                "a local caller acts under its authenticated operating-system identity, not a \
                 grant"
                    .to_owned(),
            ));
        }
        // The requested lifetime is the caller's request, not its decision. A lifetime beyond the
        // protocol maximum is a malformed envelope rather than a longer deadline.
        if mutation.requested_ttl_ms.get() > kr_protocol::limits::MAX_MUTATION_TTL.get() {
            return Err(ControllerError::InvalidArgument(format!(
                "a mutation lifetime is at most {} milliseconds",
                kr_protocol::limits::MAX_MUTATION_TTL.get()
            )));
        }
        // Preconditions belong to the subject, and the subject of a session mutation is the
        // worker. They are forwarded there unchanged; what this daemon checks is that the field is
        // a map at all, so a malformed envelope is refused before a reservation is written.
        if !matches!(
            mutation.expected.as_value(),
            kr_cbor::CanonicalValue::Map(_)
        ) {
            return Err(ControllerError::InvalidArgument(
                "the subject preconditions are a map of the facts the caller depends on".to_owned(),
            ));
        }
        // The accepted deadline is the earliest of what the window has left, receipt time plus the
        // requested lifetime, and any applicable authority deadline. The caller never supplies an
        // authoritative deadline, and nothing downstream lengthens this one.
        self.windows
            .accept_at(
                &mutation.action_window_id,
                connection_id,
                self.boot_epoch,
                received_at,
                mutation.requested_ttl_ms,
                None,
            )
            .map_err(|refusal| ControllerError::WindowExpired {
                detail: window_refusal_detail(refusal).to_owned(),
            })
    }
}

/// Why a dispatch lease was not taken ([`Controller::dispatch_lease`]).
#[derive(Debug)]
pub(crate) enum LeaseDenied {
    /// The worker has not acknowledged the authority revision in force. Asking it to is what
    /// changes this, and the first remote dispatch to a worker is the usual case.
    NotAcknowledged(ControllerError),
    /// Nothing an announcement to the worker could change.
    Stopped(ControllerError),
}

impl From<LeaseDenied> for ControllerError {
    fn from(denied: LeaseDenied) -> Self {
        match denied {
            LeaseDenied::NotAcknowledged(error) | LeaseDenied::Stopped(error) => error,
        }
    }
}

/// One connection this daemon has admitted, and the authority it was admitted under.
///
/// The transport's contract names this as the host's to keep: the final validation of the caller's
/// record and the registration of the connection are one step, and the registration stays
/// revocable for the life of the session. A read or a subscription on a connection that was
/// authorised a moment before authority was withdrawn is fenced here; section 9's dispatch barrier
/// covers a worker's dispatch and does not cover this.
///
/// A registration that goes, whichever way it goes, takes the write latch of the connection it
/// admitted with it ([`Controller::latch_registration`]): the latch is set by the registration
/// being dropped, in the critical section that removed it, so no frame begins on a connection
/// whose authority has gone, and no path that removes a registration can forget to say so.
#[derive(Debug)]
pub(super) struct AdmittedConnection {
    /// The principal the daemon assigned to the operating-system caller.
    pub(super) actor_id: ActorId,
    /// The authority revision in force when the connection was registered.
    pub(super) admitted_revision: kr_protocol::ids::AuthorityRevision,
    /// The latch of the write boundary this registration lets write, when it has one.
    latch: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl AdmittedConnection {
    /// A registration of `actor_id`, admitted under `admitted_revision`, with no write boundary
    /// tied to it yet.
    pub(super) const fn new(
        actor_id: ActorId,
        admitted_revision: kr_protocol::ids::AuthorityRevision,
    ) -> Self {
        Self {
            actor_id,
            admitted_revision,
            latch: None,
        }
    }
}

impl Drop for AdmittedConnection {
    fn drop(&mut self) {
        if let Some(latch) = &self.latch {
            latch.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

/// Returns the accepted deadline on the machine's own continuous clock, bounded by any lease.
///
/// The daemon decides deadlines on its own anchored clock, which nothing outside this process can
/// read. This converts one of those into the shared reading a worker can compare against. The
/// machine's clock is read **first** and the daemon's own clock second, so a pause between the two
/// readings shortens the answer rather than lengthening it: what is left is measured from the later
/// moment and anchored at the earlier one. `None` means the deadline has already passed, which is
/// never forwarded as though it had time left.
pub(super) fn remaining_deadline(
    shared: &dyn kr_ipc::clock::SharedClock,
    clock: &dyn ContinuousClock,
    accepted: kr_transport::clock::ContinuousInstant,
    lease: Option<kr_transport::clock::ContinuousInstant>,
) -> Option<U64> {
    // The machine's clock first, the daemon's own clock second.
    let shared_now = shared.boot_elapsed_ms();
    let now = clock.now();
    let deadline = lease.map_or(accepted, |lease| lease.min(accepted));
    let remaining = deadline.saturating_duration_since(now);
    kr_ipc::clock::transferred_deadline(shared_now, remaining).map(U64::new)
}

const fn window_refusal_detail(refusal: kr_transport::window::WindowRefusal) -> &'static str {
    use kr_transport::window::WindowRefusal;
    match refusal {
        WindowRefusal::Unknown => {
            "this action window is not the one this connection holds, so the request cannot be \
             admitted for the first time"
        }
        WindowRefusal::WrongConnection => {
            "this action window belongs to another connection, so it admits nothing here"
        }
        WindowRefusal::StaleBoot => {
            "this action window was issued in another boot of this host, so it admits nothing"
        }
        WindowRefusal::Expired => {
            "this action window has expired; the host has already replaced it, so submit a new \
             request rather than replaying this one"
        }
    }
}
