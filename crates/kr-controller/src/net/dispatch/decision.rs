//! Deciding a request: the registry's entry, the registration, the grant through the one
//! intersection.

use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::{HistoryFilter, MethodEntry, RequiredAuthority, ResourceSelectorKind};
use kr_protocol::envelope::{ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AuthorityRevision, RequestId, SessionId};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::CanonicalSet;
use kr_transport::window::AcceptedDeadline;

use crate::config::ceilings::CeilingRefusal;
use crate::grants::policy::HeldBound;
use crate::service::net::lifetimes::GrantStanding;

use super::output::{RELAY_DECISIONS, Written};
use super::{RemoteConnection, failure};

/// One request of this connection's as the host decided it: what was asked, and the decision,
/// which carries the time bounds the request stands on. What is cut from the decision ends by
/// them, and the answer is written under them.
#[derive(Clone, Debug)]
pub(super) struct Asked {
    session_id: Option<SessionId>,
    entry: &'static MethodEntry,
    claims_geometry: bool,
    pub(super) decision: super::super::DeviceDecision,
    /// The method whose answer the frame carries, which is what decides how the answer is shown.
    ///
    /// It is the entry's own method for a request answered by what it asks for. A retained answer
    /// is decided as a read of a receipt, under `action.read`'s entry, and is still the answer to
    /// the method it was kept for, so the two differ there.
    pub(super) shown_as: Method,
}

impl Asked {
    /// Returns the same decision, for an answer that is shown as `method`'s.
    pub(super) fn answering(self, method: Method) -> Self {
        Self {
            shown_as: method,
            ..self
        }
    }
}

/// The answer to one frame from the device, with the decision its request was taken under when the
/// request got that far ([`RemoteConnection::write_answer`]).
#[derive(Debug)]
pub struct Answered {
    pub(super) frame: ControlFrame,
    pub(super) asked: Option<Asked>,
}

impl Answered {
    /// The frame this answers with.
    #[must_use]
    pub const fn frame(&self) -> &ControlFrame {
        &self.frame
    }
}

impl RemoteConnection {
    /// Writes one answer under the time bounds its request was decided under, and returns whether
    /// the connection goes on.
    ///
    /// Each bound is read from its cell as it stands when the answer is written, so a renewal
    /// published while the answer waited lets it go. When one has ended before any of the answer
    /// went, a membership lease or an offline bound that ran out, the request is decided again as
    /// things stand and its refusal is the answer: once a lease has lapsed every
    /// organisation-mediated response is refused, while the transport stays connected. The
    /// refusal is the decision's own, so a lapse the clock decided is stated only once the floor
    /// it stood on is on record.
    pub async fn write_answer(&self, answered: Answered) -> bool {
        let Answered { frame, asked } = answered;
        let Some(mut asked) = asked else {
            return self.output.send(&frame).await;
        };
        let Some(request_id) = answered_request(&frame) else {
            return self.output.send(&frame).await;
        };
        for _ in 0..RELAY_DECISIONS {
            // What the answer shows is the decision's it is written under, as its bounds are.
            let shown = super::super::answer_shown(
                &frame,
                asked.shown_as,
                &asked.decision.decided.permitted.rights,
                &self.device.grant.history,
            );
            match self
                .output
                .write(&shown, &asked.decision.bounds(), None)
                .await
            {
                Written::Sent => return true,
                Written::Withdrawn => return false,
                Written::Undecided => {}
            }
            match self.ask(asked.session_id, asked.entry, asked.claims_geometry) {
                Ok(again) => asked = again.answering(asked.shown_as),
                Err(error) => return self.output.send(&failure(request_id, error)).await,
            }
        }
        self.output
            .send(&failure(request_id, authority_kept_moving()))
            .await
    }

    /// Decides this device's request through the one intersection ([`Self::check_grant`]), and
    /// keeps what was asked with the decision.
    pub(super) fn ask(
        &self,
        session_id: Option<SessionId>,
        entry: &'static MethodEntry,
        claims_geometry: bool,
    ) -> std::result::Result<Asked, ProtocolError> {
        let decision = self.check_grant(session_id, entry, claims_geometry)?;
        Ok(Asked {
            session_id,
            entry,
            claims_geometry,
            decision,
            shown_as: entry.method,
        })
    }

    /// When the authority `asked` was decided under runs out on the continuous clock: the earliest
    /// of the grant's anchored deadline, its expiry in UTC, and both deadlines of every bound the
    /// decision loaded, each UTC deadline converted at this host's reading of UTC through its
    /// floor, the reading raising it. A copy cut from the decision ends by this.
    ///
    /// # Errors
    ///
    /// When one of them has passed already, the request is decided again and this is that
    /// decision's refusal, so a lapse is stated only as a decision states it. A decision that
    /// holds again, because a renewal was published while this waited, is asked again.
    pub(super) fn authority_until(
        &self,
        asked: &Asked,
    ) -> std::result::Result<Option<kr_transport::clock::ContinuousInstant>, ProtocolError> {
        let now = self.controller.clock.now();
        let settled = self.controller.settled_utc_now();
        let bounds = asked.decision.bounds();
        let grant_expiry = match self.device.grant.expiry {
            kr_protocol::grant::GrantExpiry::At { expires_at_ms } => Some(expires_at_ms.get()),
            kr_protocol::grant::GrantExpiry::Never => None,
        };
        let mut until: Option<kr_transport::clock::ContinuousInstant> = None;
        let mut passed = false;
        let mut bound_by = |deadline: kr_transport::clock::ContinuousInstant| {
            passed |= now >= deadline;
            until = Some(until.map_or(deadline, |earliest| earliest.min(deadline)));
        };
        for deadline in self
            .authority
            .grant_deadline
            .into_iter()
            .chain(bounds.iter().filter_map(HeldBound::continuous_deadline))
        {
            bound_by(deadline);
        }
        for end in grant_expiry
            .into_iter()
            .chain(bounds.iter().filter_map(HeldBound::utc_deadline_ms))
        {
            // A deadline beyond what the continuous clock can represent bounds nothing it can
            // measure; one at or before the reading has passed.
            let left = end.saturating_sub(settled);
            match now.checked_add(std::time::Duration::from_millis(left)) {
                Some(deadline) => bound_by(deadline),
                None if left == 0 => bound_by(now),
                None => {}
            }
        }
        if !passed {
            return Ok(until);
        }
        match self.check_grant(asked.session_id, asked.entry, asked.claims_geometry) {
            Err(refusal) => Err(refusal),
            Ok(_) => Err(authority_kept_moving()),
        }
    }

    /// The deadline a read or raw input forwarded under `asked` carries to its worker, as a
    /// remaining duration: when the authority it was decided under runs out
    /// ([`Self::authority_until`]), or null for authority that does not expire.
    ///
    /// # Errors
    ///
    /// The refusal the request is decided again to, when that authority has run out.
    pub(super) fn authority_deadline(
        &self,
        asked: &Asked,
    ) -> std::result::Result<kr_protocol::scalars::Nullable<kr_protocol::scalars::U64>, ProtocolError>
    {
        let Some(deadline) = self.authority_until(asked)? else {
            return Ok(kr_protocol::scalars::Nullable::null());
        };
        // Null means "this authority does not expire", so a deadline that has already passed can
        // never be sent as null: that would forward expired authority as unlimited authority. One
        // that passed between the two readings is decided again, and refused as that decides.
        let remaining = crate::service::remaining_deadline(
            &*self.controller.shared_clock,
            &*self.controller.clock,
            deadline,
            None,
        )
        .ok_or_else(|| {
            self.authority_until(asked)
                .err()
                .unwrap_or_else(authority_kept_moving)
        })?;
        Ok(kr_protocol::scalars::Nullable(Some(remaining)))
    }

    /// Returns the authority revision this request is admitted at, or a refusal.
    ///
    /// The registration and the revision are read in one critical section, taking the registry
    /// lock and then the connection table — the order a revocation takes. So a request is never
    /// stamped with a revision that was installed *by* the revocation that withdrew its
    /// registration: either the registration is still there and the revision is the one it stands
    /// under, or the request is refused.
    pub(super) async fn admitted_at(
        &self,
    ) -> std::result::Result<AuthorityRevision, ProtocolError> {
        let registry = self.controller.registry.lock().await;
        let revision = registry
            .authority_revision()
            .map_err(|error| error.to_protocol_error())?;
        self.controller
            .authorised(self.connection_id)
            .map_err(|error| error.to_protocol_error())?;
        drop(registry);
        Ok(revision)
    }

    /// Asks, where a retained answer is about to go back, the admission this request arrived
    /// under.
    ///
    /// Finding the answer waited, for the registry, a blocking thread or a worker's journal, and
    /// section 23 has the host check current authority before a retained receipt goes back, so a
    /// device whose registration was withdrawn or replaced meanwhile cannot use an old action
    /// identifier to read protected information. It is the check every service asks from inside
    /// its work, asked without a deadline: section 9 keeps a receipt readable after the window that
    /// admitted it is gone.
    pub(super) fn admitted_to_answer(
        &self,
        validated: AuthorityRevision,
    ) -> std::result::Result<(), ProtocolError> {
        self.controller
            .check_registration(&crate::authority::AdmittedMutation {
                connection_id: self.connection_id,
                admitted_revision: validated,
                deadline: None,
            })
            .map_err(|error| error.to_protocol_error())
    }

    /// Resolves one method against the registry at this connection's ingress.
    pub(super) fn admit(
        &self,
        method: &str,
        version: kr_protocol::method::MethodVersion,
    ) -> std::result::Result<&'static MethodEntry, ProtocolError> {
        self.actor.admit(method, version)
    }

    /// Refuses a request on a connection whose registration has been withdrawn.
    pub(super) async fn authorised(&self) -> std::result::Result<(), ProtocolError> {
        self.controller
            .authorised(self.connection_id)
            .map(|_| ())
            .map_err(|error| error.to_protocol_error())
    }

    /// Checks the envelope of one mutation and returns the deadline the host accepted.
    ///
    /// The window is this connection's own, issued by the transport when the connection was
    /// authorised and replaced on the live connection at half its validity. A window from another
    /// connection, or from before a restart, first-admits nothing.
    pub(super) fn check_envelope(
        &self,
        mutation: &MutationRequest,
        entry: &'static MethodEntry,
        received_at: kr_transport::clock::ContinuousInstant,
        asked: &Asked,
    ) -> std::result::Result<AcceptedDeadline, ProtocolError> {
        mutation
            .target
            .validate()
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        if mutation.target.environment_id != self.controller.paths().environment_id() {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "this daemon owns environment {}",
                    self.controller.paths().environment_id()
                ),
            ));
        }
        // A project acts on a repository or a working copy. Its own subject check is the one the
        // local ingress makes: a target naming a session or an application is refused rather than
        // producing a receipt against something the effect never touched, and a destination
        // environment in the parameters has to be the one the target names.
        if crate::project::ProjectModule::serves(entry.method) {
            crate::project::ProjectModule::check_subject(entry.method, mutation)
                .map_err(|error| error.to_protocol_error())?;
        }
        if crate::changeset::ChangeSetModule::serves(entry.method) {
            crate::changeset::ChangeSetModule::check_subject(entry.method, mutation)
                .map_err(|error| error.to_protocol_error())?;
        }
        // A workflow belongs to this environment rather than to a session or an application, and
        // its own subject check is the one the local ingress makes.
        if crate::automation::AutomationModule::serves(entry.method) {
            crate::automation::AutomationModule::check_subject(entry.method, mutation)
                .map_err(|error| error.to_protocol_error())?;
        }
        // A catalogue mutation acts on a catalogue or on an installed package, both of which belong
        // to the environment. A target naming a session or an application is refused rather than
        // producing a receipt against something the effect never touched, and the environment in
        // the parameters has to be the one the target names. Its own subject check is the one the
        // local ingress makes.
        if crate::catalogue::CatalogueModule::serves(entry.method) {
            crate::catalogue::CatalogueModule::check_subject(entry.method, mutation)
                .map_err(|error| error.to_protocol_error())?;
        }
        // A voice mutation's subject is this host. A voice session is not a shell session, so the
        // target names none, and the session a delegation acts on travels in the parameters where
        // the coordinator checks it against what that voice session may reach. Its own subject
        // check is the one the local ingress makes.
        let voice = crate::voice::VoiceModule::serves(entry.method);
        if voice {
            crate::voice::VoiceModule::check_subject(entry.method, mutation)
                .map_err(|error| error.to_protocol_error())?;
        }
        // The target and the parameters have to name the same subject. One that pointed at a
        // session the grant admits and carried another in its parameters would act on the one
        // nobody addressed, and the grant check above would have looked at the wrong one.
        let names_session = !voice
            && entry
                .resource_selectors
                .contains(&ResourceSelectorKind::Session);
        match (
            mutation.target.session_id.as_ref().copied(),
            if voice {
                None
            } else {
                session_of(&mutation.params, entry).ok()
            },
        ) {
            (Some(named), Some(carried)) if named != carried => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "the request's target and its parameters name different sessions",
                ));
            }
            (None, Some(_)) => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} names the session it acts on in its target", entry.name),
                ));
            }
            (None, None) if names_session && entry.method != Method::SessionCreate => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} names the session it acts on", entry.name),
                ));
            }
            // A create allocates the session it is for, so it names none.
            (Some(_), None) if entry.method == Method::SessionCreate => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    "a create allocates the session it is for, so it names none",
                ));
            }
            // Pairing and owner confirmation act on this host rather than on a session, as they
            // do at the local door, so the target names none.
            (Some(_), None) if super::super::methods::serves(entry.method) => {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidArgument,
                    format!("{} acts on this host and names no session", entry.name),
                ));
            }
            _ => {}
        }
        // The caller states the grant it is acting under. It may only be the one this device holds:
        // a device cannot name another device's grant, and the host records the grant it checked
        // rather than the one the request claimed.
        if let Some(claimed) = mutation.grant_id.as_ref()
            && *claimed != self.device.grant.grant_id
        {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "that grant is not the one this device holds",
            ));
        }
        // The requested lifetime is the caller's request, not its decision.
        if mutation.requested_ttl_ms.get() > kr_protocol::limits::MAX_MUTATION_TTL.get() {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "a mutation lifetime is at most {} milliseconds",
                    kr_protocol::limits::MAX_MUTATION_TTL.get()
                ),
            ));
        }
        // Preconditions belong to the subject, and are forwarded unchanged. What is checked here is
        // that the field is a map at all, so a malformed envelope is refused before anything acts.
        if !matches!(
            mutation.expected.as_value(),
            kr_cbor::CanonicalValue::Map(_)
        ) {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "the subject preconditions are a map of the facts the caller depends on",
            ));
        }
        // The authority the request was decided under bounds the deadline it is accepted with, on
        // both of each bound's clocks.
        let authority = self.authority_until(asked)?;
        self.windows
            .accept_at(
                &mutation.action_window_id,
                self.connection_id,
                self.controller.boot_epoch,
                received_at,
                mutation.requested_ttl_ms,
                authority,
            )
            .map_err(|refusal| {
                ProtocolError::new(ErrorCode::PermissionDenied, window_refusal_detail(refusal))
            })
    }

    /// Decides this device's request through the one intersection, and returns the rights it was
    /// decided with.
    ///
    /// Checked here first is what only this connection knows: whether the grant's own deadline,
    /// anchored on the continuous clock when the connection was admitted, has passed. Everything a
    /// grant, this host's policy and this host's configuration decide is then
    /// [`Controller::decide_for_device`]'s, which is [`crate::config::ceilings::decide_with_ceiling`]:
    /// the method's reachability, the grant's standing and expiry, the policy's organisation
    /// leases and offline bound, the environment and session its selectors admit, and every right
    /// the method requires under the conditions this request meets, taken from the grant as the
    /// policy and the configured rights ceiling leave it. A right the configuration removed is
    /// refused by name, and a grant that decision finds expired ends this connection exactly as
    /// its own deadline passing would. Last comes the history scope. A requirement that depends on the resolved
    /// subject - resource ownership, a local caller's token - is the subject's to answer, and the
    /// worker answers it inside its own dispatch barrier where the subject cannot move.
    pub(super) fn check_grant(
        &self,
        session_id: Option<SessionId>,
        entry: &'static MethodEntry,
        claims_geometry: bool,
    ) -> std::result::Result<super::super::DeviceDecision, ProtocolError> {
        if !self.grant_is_current() {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this device's grant has expired",
            ));
        }
        let grant = self.decided_grant(entry)?;
        // The device's record is where its grant's standing is written: when it was committed,
        // which is when its invitation was redeemed, and when it was revoked.
        let record = crate::grants::GrantRecord {
            grant: grant.clone(),
            session_id: None,
            issued_at_ms: self.device.paired_at_ms.get(),
            activated_at_ms: Some(self.device.paired_at_ms.get()),
            revoked_at_ms: self.device.revoked_at_ms.map(|at| at.get()),
            revoked_by_parent: None,
        };
        let request = crate::grants::AccessRequest {
            method: entry.method,
            ingress: ActorIngress::PairedDevice,
            environment_id: self.controller.paths().environment_id(),
            session_id,
            claims_geometry,
            own_subject: None,
            now_ms: self.controller.wall_now_ms(),
            continuous_now: self.controller.clock.now(),
        };
        let decided = self
            .controller
            .decide_for_device(&grant, &record, request)
            .map_err(|refusal| match refusal {
                CeilingRefusal::Refused(crate::grants::Refusal::MissingRight {
                    right: ActionRight::VoiceUse,
                }) => ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this device holds no voice grant on this host",
                ),
                // The grant ran out by this host's wall clock, or by the floor under it, while
                // the deadline this connection anchored still has time on it: a clock stepped
                // forward, or a floor another decision raised. It is the same observation the
                // deadline makes, so it goes where that one goes: the latch stops every frame
                // this connection would write next, its subscription's output among them, and
                // the record keeps the device from coming back on another connection.
                expired @ CeilingRefusal::Refused(
                    crate::grants::Refusal::Expired { .. }
                    | crate::grants::Refusal::ExpiryUnrecorded { .. },
                ) => {
                    self.authority.expire();
                    expired.to_protocol_error()
                }
                other => other.to_protocol_error(),
            })?;
        self.check_history(entry)?;
        Ok(decided)
    }

    /// The grant this device's requests are decided against ([`decided_with_voice`]).
    ///
    /// # Errors
    ///
    /// Refuses a method that needs a voice grant while this host cannot say whether the device's
    /// voice grant has run out, because the clock floor an end of it was found on is not on
    /// record yet ([`Self::voice_standing`]).
    fn decided_grant(
        &self,
        entry: &'static MethodEntry,
    ) -> std::result::Result<kr_protocol::grant::Grant, ProtocolError> {
        decided_with_voice(&self.device.grant, entry, || self.voice_standing())
    }

    /// Whether this device holds a voice grant that stands now on this host.
    ///
    /// Read from the host's one authority store at the moment of the question, because a voice
    /// grant is written, replaced and withdrawn while a connection stands. Each live record is
    /// decided as every stored grant is: on both clocks, with the UTC one read through this host's
    /// floor, which the reading raises, so a wall clock wound back does not bring a lapsed grant
    /// back to life. A lapse the floor decided is stated only once the floor is on record, and
    /// until then the answer is neither ([`VoiceStanding::Unrecorded`]): a daemon started in a new
    /// boot could decide the other way. A record this host cannot read leaves the device without
    /// a voice grant.
    fn voice_standing(&self) -> VoiceStanding {
        let grants = self.controller.sharing().grants();
        let Ok(records) = grants.records_for_device(self.device.device_id) else {
            return VoiceStanding::Lacks;
        };
        let mut unrecorded = false;
        for record in records {
            if record.revoked_at_ms.is_some()
                || !record.is_active()
                || !record.grant.permits(ActionRight::VoiceUse)
            {
                continue;
            }
            match self.controller.lifetimes().stored_standing(grants, &record) {
                Ok(GrantStanding::InForce) => return VoiceStanding::Holds,
                Ok(GrantStanding::OutOfForce) | Err(_) => {}
                Ok(GrantStanding::Unrecorded) => unrecorded = true,
            }
        }
        if unrecorded {
            VoiceStanding::Unrecorded
        } else {
            VoiceStanding::Lacks
        }
    }

    /// Refuses a read whose content is outside the grant's history scope.
    fn check_history(&self, entry: &'static MethodEntry) -> std::result::Result<(), ProtocolError> {
        let scope = &self.device.grant.history;
        match entry.method {
            // The only method that returns *retained* history. Its scope is the grant's lower
            // bound, and nothing on this path can apply one: the bound is a moment in time and a
            // history page is a byte range. A host that cannot narrow content to a grant refuses
            // it rather than serving more than the grant allows.
            Method::HistoryPage => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this host does not serve retained history to a paired device",
            )),
            // These return the session's current screen and the stream that follows it, which is
            // the live view the scope either includes or does not.
            Method::EventsSubscribe | Method::EventsSnapshot | Method::SessionAttach
                if !scope.include_live_screen =>
            {
                Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this device's grant does not include the session's live screen",
                ))
            }
            // Everything else returns metadata or an effect rather than session content, or
            // content the session's worker holds to the scope this connection sends with the read:
            // an agent's snapshot and an approval's record. The registry's filter is recorded here
            // so a method added later is decided rather than admitted by omission.
            _ => match entry.history_filter {
                HistoryFilter::NotApplicable
                | HistoryFilter::GrantLowerBound
                | HistoryFilter::LiveViewOnly
                | HistoryFilter::NamedCurrentResources => Ok(()),
            },
        }
    }

    /// Refuses the five repository operations to a device on a host that cannot confine what the
    /// Git program reads, and says why in one sentence.
    ///
    /// Section 14 paragraph 5 puts filesystem authority in opened directory handles: a grant
    /// reaches the objects the owner authorised and nothing else. This host holds that rule over
    /// every name **it** resolves. It holds it over the Git program only where it has proved it
    /// can: on Linux, inside one boundary that confines what Git reads to the directories the
    /// owner authorised and a support set named for this host's Git, which the project service
    /// builds for a caller bounded by a grant and the daemon proves at its start and at each
    /// `host.doctor`. Anywhere else, and on a Linux host that could not prove it, an operation
    /// that runs Git for a device would give that device reach the owner never named, and this
    /// host does not start one.
    ///
    /// The local owner is unaffected: the owner's own authority runs the owner's own program,
    /// which is the posture this product has always had. The metadata methods are unaffected too:
    /// they answer from this host's own store and start nothing.
    pub(super) fn check_project_authority(
        &self,
        method: Method,
        _mutation: &MutationRequest,
    ) -> std::result::Result<(), ProtocolError> {
        if matches!(
            method,
            Method::ProjectInit
                | Method::ProjectClone
                | Method::ProjectAdopt
                | Method::WorkspaceCreate
                | Method::WorkspaceRemove
        ) && !self.controller.qualification().qualifies()
        {
            return Err(refuses_to_run_git());
        }
        Ok(())
    }
}

/// The one refusal every method that would start the Git program for a device is given where this
/// host cannot confine what that program reads.
///
/// It says no more than that: what stopped the host from proving it is in the doctor and in the
/// daemon's own log, and a caller is not told which of this host's libraries or mounts did.
pub(super) fn refuses_to_run_git() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::PermissionDenied,
        "this host cannot confine what the Git program reads to the directories the owner \
         authorised, so it does not run that program for a paired device",
    )
}

/// The refusal a device is given for a change-set method that reads or writes a working tree.
///
/// Capture, apply, revert and a diff of a working copy each run the Git program on a working tree,
/// and that program does not run inside the boundary that confines what Git reads for a device's
/// repository operations. So the method is not served, and the sentence says which part of what it
/// does is the reason.
pub(super) fn refuses_a_working_tree(method: Method) -> ProtocolError {
    let does = match method {
        Method::DiffApply | Method::DiffRevert => "checks and writes a working tree",
        _ => "reads a working tree",
    };
    ProtocolError::new(
        ErrorCode::PermissionDenied,
        format!(
            "{} is not served to a paired device: it {does} by running the Git program, outside \
             the boundary that confines what that program reads for a device's repository \
             operations",
            method.as_str()
        ),
    )
}

/// Returns whether one request claims or adds a geometry claim.
///
/// The condition on `terminal.geometry` is "when the request claims or adds a geometry claim", so
/// the request is what decides it: `claim_geometry` is the field that registers one, and
/// `session.attach` and `attachment.configure` both carry it.
///
/// A *requested capability* is not a claim. Section 8 makes an attachment's granted capabilities
/// the requested ones intersected with the actor's rights, so asking for `geometry` in a grant
/// that does not carry `terminal.geometry` yields an attachment without it rather than a refusal,
/// and the summary the caller is given says which it got. Refusing here instead would mean a
/// client that asks for everything it can use gets nothing, which is the opposite of what an
/// intersection is for. What it may still never do is register the claim: `claim_geometry` needs
/// the right here, and every later operation is checked against the capability the attachment was
/// actually granted.
pub(super) fn claims_geometry(mutation: &MutationRequest) -> bool {
    let kr_cbor::CanonicalValue::Map(map) = mutation.params.as_value() else {
        return false;
    };
    matches!(
        map.get("claim_geometry"),
        Some(kr_cbor::CanonicalValue::Bool(true))
    )
}

/// Returns the session a request names, from the encoded parameters.
///
/// It is read out of the encoded parameters rather than through a typed shape of its own, because
/// the typed shape belongs to the subject: the daemon needs one field to decide which worker a
/// request goes to and which session its grant is checked against, and parsing the whole thing
/// here would mean two places that have to agree on every parameter of every method.
///
/// A request names its session at the top of its parameters, except the agent-state reads, which
/// name the exact instance they are about as a subject that carries its session. That session is
/// the one the worker answers for, so it is the one the grant is checked against and the request
/// routed by; a read whose session was looked for anywhere else would be decided without one.
pub(super) fn session_of(
    params: &ParamsValue,
    entry: &'static MethodEntry,
) -> std::result::Result<SessionId, ProtocolError> {
    let named = || {
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("{} names the session it acts on", entry.name),
        )
    };
    let kr_cbor::CanonicalValue::Map(map) = params.as_value() else {
        return Err(named());
    };
    let carried = if entry.group == MethodGroup::AgentState {
        match map.get("subject") {
            Some(kr_cbor::CanonicalValue::Map(subject)) => subject.get("session_id"),
            _ => None,
        }
    } else {
        map.get("session_id")
    };
    let Some(kr_cbor::CanonicalValue::Bytes(bytes)) = carried else {
        return Err(named());
    };
    let bytes = <[u8; 16]>::try_from(bytes.as_slice()).map_err(|_| named())?;
    Ok(SessionId::new(kr_protocol::scalars::Uuid::from_bytes(
        bytes,
    )))
}

/// The request an answer answers, when it answers one.
const fn answered_request(frame: &ControlFrame) -> Option<RequestId> {
    match frame {
        ControlFrame::Response(response) => Some(response.request_id),
        ControlFrame::Receipt(receipt) => Some(receipt.request_id),
        _ => None,
    }
}

/// What a request is told when the time bounds it was decided under ran out and came back while it
/// waited, a renewal published after a lapse: nothing was done under them, and it is asked again.
fn authority_kept_moving() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::ResourceUnavailable,
        "the authority this request was decided under changed while it waited; ask again",
    )
}

/// Returns the sentence a caller is given when a window cannot first-admit a request.
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

/// The grant a paired device's request for `entry` is decided against: the one its pairing
/// committed (`paired`), with one right resolved elsewhere.
///
/// `voice.use` lives in the separate voice grant section 15 paragraph 7 intersects with this one,
/// not in the grant a connection was admitted under: a person holds their ordinary authority and
/// chooses separately how much of it voice may use. So it is taken out of the pairing grant and
/// put back only for a method that needs it, when the device holds a live voice grant carrying it
/// (`voice_standing`, asked only then). The policy and the configured ceiling then apply to it
/// like any other right, and the coordinator takes the intersection again at the moment of each
/// decision.
///
/// Every method that needs it is a voice method this daemon serves itself, so the rights a
/// forwarded mutation carries to a worker, which its decision cut from this grant, never include
/// it: a worker holds no work under a voice grant, and a voice grant's withdrawal owes no fence.
fn decided_with_voice(
    paired: &kr_protocol::grant::Grant,
    entry: &MethodEntry,
    voice_standing: impl FnOnce() -> VoiceStanding,
) -> std::result::Result<kr_protocol::grant::Grant, ProtocolError> {
    let needs_voice = entry.required_rights.iter().any(|required| {
        matches!(
            required.authority,
            RequiredAuthority::Right {
                right: ActionRight::VoiceUse
            }
        )
    });
    let mut actions: CanonicalSet<ActionRight> = paired
        .actions
        .iter()
        .copied()
        .filter(|right| *right != ActionRight::VoiceUse)
        .collect();
    if needs_voice {
        match voice_standing() {
            VoiceStanding::Holds => {
                actions.insert(ActionRight::VoiceUse);
            }
            VoiceStanding::Lacks => {}
            VoiceStanding::Unrecorded => {
                return Err(
                    CeilingRefusal::Refused(crate::grants::Refusal::FloorUnrecorded)
                        .to_protocol_error(),
                );
            }
        }
    }
    Ok(kr_protocol::grant::Grant {
        actions,
        ..paired.clone()
    })
}

/// Whether a device holds a voice grant that stands now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VoiceStanding {
    /// A live voice grant stands on both clocks.
    Holds,
    /// None does.
    Lacks,
    /// None stands, and the end that decides it is not written down yet.
    Unrecorded,
}
