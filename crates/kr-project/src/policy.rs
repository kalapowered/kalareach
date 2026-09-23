//! The owner's authorised locations: the directories repository work may happen in, and the open
//! handles that are that authority.
//!
//! Section 14 paragraph 5 wants filesystem authority to be an opened directory rather than a path
//! string. An **authorised location** is exactly that: a directory the owner named, opened by this
//! host, confined to the mount it was opened on, and kept open for as long as the authorisation
//! lives. Every name resolved through one descends from the held handle a component at a time and
//! never follows a link out of it. The recorded path is for a person to read and for a
//! reauthorisation to open again; it is never authority.
//!
//! What this module owns:
//!
//! * **The rows.** `authorised_locations` in the project store: one grant, one environment and one
//!   purpose per row. A directory wanted as both a destination and a source is authorised twice.
//! * **The held handles.** [`LocationPolicy`] maps each active location to the handle this process
//!   opened for it, shared by reference count, so an admission and the transaction that later
//!   relies on it can prove they hold the same object: the one the policy holds *now*, compared
//!   with [`Arc::ptr_eq`], never a descriptor number and never a path opened again.
//! * **Restart.** This host holds no descriptor across a restart, so an active row loads dormant. A
//!   dormant location admits nothing until the owner authorises it again, and a withdrawn one never
//!   becomes active by any route.
//! * **The owner's four methods.** `project.location.list`, `.authorise`, `.withdraw` and
//!   `.attach`. Authorising a location and binding a repository to one enlarge what this host will
//!   do, so each needs the owner's fresh confirmation, bound to the opened object.
//!
//! A location is the owner's. The rows have a grant column, and a location naming a grant admits
//! nothing on this host: no paired device reaches a repository operation here, and an owner's
//! confirmation of a device's location would have to be bound to that device's four public keys,
//! of which this host keeps only two. So such a location is not authorised in the first place.
//!
//! ## The confirmation, in two submissions of one action
//!
//! The first submission carries no proof. This host opens what it would authorise, keeps that
//! handle beside a challenge whose digest covers the request **and the identity read back through
//! the handle**, and answers with the challenge. Nothing durable is written and no outcome is
//! retained, so a repeat of the same request under the same action identifier is answered with the
//! same outstanding challenge. The challenge lives for as long as the daemon's own ledger holds it,
//! on the ledger's own clock: once the ledger lets it go, so does this module, with the handle.
//!
//! The second submission carries the proof, and everything it does happens inside one serial
//! transition for its actor and action identifier, taken before anything is looked up. Inside it:
//! a retained answer is returned when there is one; otherwise the outstanding challenge has to be
//! there and the proof has to answer it. Then, **before the challenge is spent, the action is
//! claimed in the journal**, and only then is the challenge consumed and the effect performed; the
//! effect and its answer commit in one transaction with the outbox row that announces it. A copy of
//! the same submission that arrives meanwhile waits for the transition and then finds the answer.
//! Because the claim is durable before the spend, no order of failures leaves a spent challenge
//! with nothing recorded against its action: a repeat finds the answer, or the open claim, and
//! never a challenge that is gone.
//!
//! ## Lock order
//!
//! The per-action transition, then the outstanding challenges, then the daemon's ledger; the
//! per-action transition, then the project journal, then this policy's own lock. A read admission
//! takes only the policy's lock. Nothing here is held across a subprocess.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, EnvironmentId, GrantId, ProjectLocationId, ProjectRepositoryId};
use kr_protocol::pairing::{OwnerConfirmationProof, OwnerConfirmationRequest};
use kr_protocol::project::{
    AuthorisedLocation, LocationAttachment, LocationAuthorisation, LocationPurpose, LocationState,
    ProjectLocationAttachParams, ProjectLocationAttachResult, ProjectLocationAuthoriseParams,
    ProjectLocationAuthoriseResult, ProjectLocationListParams, ProjectLocationListResult,
    ProjectLocationWithdrawParams, ProjectLocationWithdrawResult, SourceBinding,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable, TimestampMs, Uuid};
use kr_transfer::{AuthorisedDirectory, ObjectIdentity, RelativeName};
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::{ProjectError, Result};
use crate::service::ProjectService;
use crate::store::{Action, LocatedName, Performed, ProjectRow};

/// How many challenges this host keeps outstanding at once.
///
/// Each one holds an open directory until it is answered or the ledger lets it go, and an owner
/// who asks for challenges and never signs them would otherwise hold descriptors without bound. A
/// real owner confirms one decision at a time; this is far above that and far below what a process
/// may open. The bound is checked before a challenge is issued, so a refusal issues nothing.
pub const MAX_OUTSTANDING_CHALLENGES: usize = 32;

/// The rights a location carries: a destination enables creating a repository and a working copy
/// in it, and a source enables cloning one and taking a working copy of it. An owner location
/// carries both, and the owner is shown both.
const LOCATION_RIGHTS: [ActionRight; 2] =
    [ActionRight::ProjectCreate, ActionRight::WorkspaceManage];

/// What an owner is asked to confirm: exactly one enlargement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enlargement {
    /// The digest of the exact request and of the object this host opened for it.
    pub action_digest: Digest256,
    /// The rights the enlargement carries, which the owner is shown.
    pub rights: CanonicalSet<ActionRight>,
}

/// What the daemon lends this service for the owner's own decisions.
///
/// The service knows its locations and its repositories. It does not know this host's owner, its
/// enrolled signer, its identity or its clock, and it should not: those are the daemon's, and a
/// service that kept its own copy would be one more place for them to disagree. So the ceremony is
/// the daemon's, and so is the ledger that decides how long a challenge lives.
///
/// Verifying a proof and spending the challenge it answers are two calls, so that the service can
/// record the action durably in between: a spend with nothing recorded against it is the one state
/// a repeat of the action could not be answered from.
pub trait OwnerAuthority: Send + Sync {
    /// Issues a fresh challenge for one enlargement and records it as outstanding.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal.
    fn challenge(
        &self,
        enlargement: &Enlargement,
    ) -> std::result::Result<OwnerConfirmationRequest, ProtocolError>;

    /// Returns whether the ledger still holds exactly this challenge, inside its own deadline.
    fn outstanding(&self, request: &OwnerConfirmationRequest) -> bool;

    /// Verifies a proof against an outstanding challenge issued for exactly this enlargement,
    /// under the enrolled signer, without spending it.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal when the proof does not answer such a challenge.
    fn verify(
        &self,
        enlargement: &Enlargement,
        proof: &OwnerConfirmationProof,
    ) -> std::result::Result<(), ProtocolError>;

    /// Spends the challenge a verified proof answers. It succeeds once.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal when the challenge is no longer outstanding.
    fn consume(&self, proof: &OwnerConfirmationProof) -> std::result::Result<(), ProtocolError>;
}

/// One active location: the handle this process opened for it, and its row.
#[derive(Debug)]
pub struct HeldLocation {
    handle: AuthorisedDirectory,
    row: AuthorisedLocation,
}

impl HeldLocation {
    /// Returns the handle every name beneath this location descends from.
    #[must_use]
    pub const fn handle(&self) -> &AuthorisedDirectory {
        &self.handle
    }

    /// Returns the location as it was authorised.
    #[must_use]
    pub const fn row(&self) -> &AuthorisedLocation {
        &self.row
    }

    /// Returns its identity.
    #[must_use]
    pub const fn location_id(&self) -> ProjectLocationId {
        self.row.location_id
    }
}

/// Whose use a location is admitted for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admitting {
    /// The owner deciding something about the location itself.
    OwnerDecision,
    /// An operation performed for a caller, which the location has to admit exactly: the owner,
    /// who holds no grant and matches only a location that names none, or a caller bounded by one
    /// grant, which matches only a location naming that grant.
    Caller(Option<GrantId>),
}

/// What one read or effect through a location needs it to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocationUse {
    /// The purpose it has to have been authorised for.
    pub purpose: LocationPurpose,
    /// The environment the request is in.
    pub environment_id: EnvironmentId,
    /// Whose use it is.
    pub admitting: Admitting,
}

/// The active locations and the handles held for them.
///
/// One lock guards the map, and the same lock is what a withdrawal takes to take a location away:
/// an admission granted before a withdrawal committed keeps the handle it was given, and none is
/// granted after it.
#[derive(Debug, Default)]
pub struct LocationPolicy {
    /// Shared, so that the admission a request's reads carry asks this same map under this same
    /// lock however long after the request was resolved it is asked.
    held: Arc<Mutex<BTreeMap<ProjectLocationId, Arc<HeldLocation>>>>,
}

impl LocationPolicy {
    /// Takes the policy's lock.
    pub(crate) fn lock(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<ProjectLocationId, Arc<HeldLocation>>>> {
        self.held
            .lock()
            .map_err(|_| ProjectError::StoreUnavailable {
                detail: "the location policy was left poisoned by an earlier failure"
                    .to_owned()
                    .into(),
            })
    }

    /// Admits one read through a location, immediately before it starts.
    ///
    /// The location has to be active, of the purpose asked for, in the request's environment and,
    /// for an operation, the caller's own. What comes back is the policy's own reference: the
    /// caller keeps it for as long as the read lasts, and a later transaction can prove that the
    /// location it relies on is still this one.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::PermissionDenied`] when the location admits no such use now.
    pub fn admit(
        &self,
        location_id: ProjectLocationId,
        wanted: &LocationUse,
    ) -> Result<Arc<HeldLocation>> {
        let map = self.lock()?;
        let held = map
            .get(&location_id)
            .cloned()
            .ok_or_else(|| not_active(location_id))?;
        admits(&held, wanted)?;
        Ok(held)
    }

    /// Returns the admission every read of one request asks immediately before it starts, and
    /// the transaction that begins its effect asks again.
    ///
    /// Each location the request reached a name through has to be the object this policy holds
    /// now, compared by reference, and still admit that use. A request that reached no location
    /// asks nothing.
    #[must_use]
    pub fn read_admission(
        &self,
        reach: Vec<(Arc<HeldLocation>, LocationUse)>,
    ) -> Option<crate::git::ReadAdmission> {
        if reach.is_empty() {
            return None;
        }
        let held = Arc::clone(&self.held);
        Some(crate::git::ReadAdmission::new(move || {
            let map = held.lock().map_err(|_| ProjectError::StoreUnavailable {
                detail: "the location policy was left poisoned by an earlier failure"
                    .to_owned()
                    .into(),
            })?;
            for (location, wanted) in &reach {
                recheck(&map, location, wanted)?;
            }
            Ok(())
        }))
    }
}

/// Checks, under the policy's lock, that a location an earlier admission produced is still the one
/// the policy holds and still admits the use.
///
/// # Errors
///
/// Returns [`ProjectError::PermissionDenied`] when it was withdrawn, replaced or no longer admits
/// the use.
pub(crate) fn recheck(
    map: &BTreeMap<ProjectLocationId, Arc<HeldLocation>>,
    held: &Arc<HeldLocation>,
    wanted: &LocationUse,
) -> Result<()> {
    match map.get(&held.row.location_id) {
        Some(current) if Arc::ptr_eq(current, held) => admits(current, wanted),
        _ => Err(not_active(held.row.location_id)),
    }
}

/// Refuses a use a held location does not admit.
fn admits(held: &HeldLocation, wanted: &LocationUse) -> Result<()> {
    let row = &held.row;
    if let Some(grant) = row.grant_id.0 {
        // A grant's location admits nothing on this host, whoever asks: nothing here would bound
        // what the Git program reaches for the device that holds the grant.
        return Err(ProjectError::PermissionDenied {
            detail: format!(
                "location {} admits grant {grant}, and no location admits a grant on this host",
                row.location_id
            )
            .into(),
        });
    }
    if row.purpose != wanted.purpose {
        return Err(ProjectError::PermissionDenied {
            detail: format!(
                "location {} was authorised as a {}, not as a {}",
                row.location_id,
                purpose_text(row.purpose),
                purpose_text(wanted.purpose)
            )
            .into(),
        });
    }
    if row.environment_id != wanted.environment_id {
        return Err(ProjectError::PermissionDenied {
            detail: format!(
                "location {} belongs to environment {}, not {}",
                row.location_id, row.environment_id, wanted.environment_id
            )
            .into(),
        });
    }
    if let Admitting::Caller(Some(grant)) = wanted.admitting {
        return Err(ProjectError::PermissionDenied {
            detail: format!(
                "location {} admits the owner, and this request is grant {grant}'s",
                row.location_id
            )
            .into(),
        });
    }
    Ok(())
}

fn grant_text(grant: Option<GrantId>) -> String {
    grant.map_or_else(|| "the owner".to_owned(), |grant| format!("grant {grant}"))
}

fn not_active(location_id: ProjectLocationId) -> ProjectError {
    ProjectError::PermissionDenied {
        detail: format!(
            "location {location_id} is not active: it was withdrawn, or this host has not held it \
             since it last started and the owner has not authorised it again"
        )
        .into(),
    }
}

/// Turns the daemon's refusal into this service's, under the daemon's code.
fn declined(refusal: ProtocolError) -> ProjectError {
    ProjectError::Declined {
        code: refusal.code,
        detail: refusal.message.into(),
    }
}

fn no_owner() -> ProjectError {
    ProjectError::Declined {
        code: ErrorCode::HostNotConfigured,
        detail: "this environment has no enrolled owner to confirm the decision, so nothing is \
                 authorised"
            .to_owned()
            .into(),
    }
}

// ----- outstanding challenges ----------------------------------------------------------------

/// The key one submission's challenge is kept under: its actor and its action identifier.
type ChallengeKey = (String, Uuid);

fn challenge_key(actor: &ActorId, action: &Action) -> ChallengeKey {
    (actor.as_str().to_owned(), action.action_id)
}

/// What a challenge was issued for.
#[derive(Debug)]
enum Subject {
    /// A location: the directory this host opened, which the confirmation is bound to.
    Location { handle: AuthorisedDirectory },
    /// A binding: the location it resolved through, the working tree the descent produced and the
    /// name that produced it. All three are kept until the binding commits.
    Attachment {
        held: Arc<HeldLocation>,
        tree: AuthorisedDirectory,
        relative: RelativeName,
    },
}

/// One outstanding challenge and everything it was issued against.
#[derive(Debug)]
struct Pending {
    /// The digest of the request without its proof, which a repeat has to match.
    request_digest: Digest256,
    /// The challenge itself.
    request: OwnerConfirmationRequest,
    /// What the owner is asked to confirm.
    enlargement: Enlargement,
    /// What the challenge holds open.
    subject: Subject,
}

/// The challenges this host has issued for a location decision and not yet seen answered.
///
/// Nothing here is durable, and nothing here decides how long a challenge lives: the daemon's
/// ledger does, on its own clock, and an entry the ledger no longer holds is dropped with its
/// handle the next time anything here is asked, or when the daemon sweeps. A restart ends every
/// challenge together with the handle it held, and the owner starts again, which is right: a
/// confirmation is bound to an object this process opened, and the next process has not opened
/// it.
#[derive(Debug, Default)]
pub(crate) struct Challenges {
    state: Mutex<Outstanding>,
}

/// What the challenges hold: the ones waiting for a proof, and how many are being answered.
///
/// A challenge taken out to be answered keeps its place in the bound until it is spent or put
/// back, so a proof being verified cannot make room for a challenge the bound would refuse.
#[derive(Debug, Default)]
struct Outstanding {
    waiting: BTreeMap<ChallengeKey, Pending>,
    answering: usize,
}

impl Outstanding {
    fn held(&self) -> usize {
        self.waiting.len() + self.answering
    }
}

/// A challenge taken out to be answered, which keeps its place in the bound while it is held.
struct Answering<'a> {
    challenges: &'a Challenges,
    key: ChallengeKey,
    pending: Option<Pending>,
}

impl Answering<'_> {
    fn enlargement(&self) -> Option<&Enlargement> {
        self.pending.as_ref().map(|pending| &pending.enlargement)
    }

    /// Puts the challenge back for the owner's own proof, while the ledger still holds it.
    fn restore(mut self, owner: &dyn OwnerAuthority) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let mut state = self
            .challenges
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.answering = state.answering.saturating_sub(1);
        if owner.outstanding(&pending.request) {
            state.waiting.entry(self.key.clone()).or_insert(pending);
        }
    }

    /// Gives up the challenge's place once it is spent, and returns what it held.
    fn spent(mut self) -> Option<Pending> {
        let pending = self.pending.take();
        let mut state = self
            .challenges
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.answering = state.answering.saturating_sub(1);
        pending
    }
}

impl Drop for Answering<'_> {
    fn drop(&mut self) {
        if self.pending.take().is_some() {
            let mut state = self
                .challenges
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.answering = state.answering.saturating_sub(1);
        }
    }
}

impl Challenges {
    fn lock(&self) -> Result<MutexGuard<'_, Outstanding>> {
        self.state
            .lock()
            .map_err(|_| ProjectError::StoreUnavailable {
                detail: "the outstanding challenges were left poisoned by an earlier failure"
                    .to_owned()
                    .into(),
            })
    }

    /// Returns the challenge still outstanding for this same request, when there is one.
    ///
    /// One action identifier used for a different request is refused as the journal would refuse
    /// it.
    fn repeated(
        &self,
        key: &ChallengeKey,
        request_digest: Digest256,
        owner: &dyn OwnerAuthority,
    ) -> Result<Option<OwnerConfirmationRequest>> {
        let mut state = self.lock()?;
        let_go(&mut state.waiting, owner);
        match state.waiting.get(key) {
            None => Ok(None),
            Some(pending) if pending.request_digest == request_digest => {
                Ok(Some(pending.request.clone()))
            }
            Some(_) => Err(conflict(key)),
        }
    }

    /// Issues a challenge for one enlargement and keeps it with what it holds.
    ///
    /// The bound is checked and the challenge issued under one hold, so a request the bound
    /// refuses issues nothing, and two requests cannot both pass it.
    fn issue(
        &self,
        key: ChallengeKey,
        request_digest: Digest256,
        enlargement: Enlargement,
        subject: Subject,
        owner: &dyn OwnerAuthority,
    ) -> Result<OwnerConfirmationRequest> {
        let mut state = self.lock()?;
        let_go(&mut state.waiting, owner);
        if let Some(pending) = state.waiting.get(&key) {
            return if pending.request_digest == request_digest {
                Ok(pending.request.clone())
            } else {
                Err(conflict(&key))
            };
        }
        if state.held() >= MAX_OUTSTANDING_CHALLENGES {
            return Err(ProjectError::QuotaExceeded {
                detail: format!(
                    "this host already holds {MAX_OUTSTANDING_CHALLENGES} challenges nobody has \
                     answered; answer one or let them expire"
                )
                .into(),
            });
        }
        let request = owner.challenge(&enlargement).map_err(declined)?;
        state.waiting.insert(
            key,
            Pending {
                request_digest,
                request: request.clone(),
                enlargement,
                subject,
            },
        );
        Ok(request)
    }

    /// Takes out the outstanding challenge a proof answers, leaving it in place when it does not.
    fn take(
        &self,
        key: &ChallengeKey,
        request_digest: Digest256,
        presented: &OwnerConfirmationRequest,
        owner: &dyn OwnerAuthority,
    ) -> Result<Answering<'_>> {
        let mut state = self.lock()?;
        let_go(&mut state.waiting, owner);
        let Some(pending) = state.waiting.get(key) else {
            return Err(ProjectError::Unconfirmed {
                detail: "this host holds no outstanding challenge for this action; submit it \
                         without a proof to be given one"
                    .to_owned()
                    .into(),
            });
        };
        if pending.request_digest != request_digest {
            return Err(ProjectError::Unconfirmed {
                detail: "the challenge outstanding for this action was issued for a different \
                         request"
                    .to_owned()
                    .into(),
            });
        }
        if &pending.request != presented {
            return Err(ProjectError::Unconfirmed {
                detail: "this proof answers a different challenge from the one this host issued \
                         for this action"
                    .to_owned()
                    .into(),
            });
        }
        let pending = state.waiting.remove(key);
        if pending.is_some() {
            state.answering += 1;
        }
        Ok(Answering {
            challenges: self,
            key: key.clone(),
            pending,
        })
    }

    /// Drops every challenge the ledger no longer holds, with the handle each one held.
    fn expire(&self, owner: &dyn OwnerAuthority) -> Result<usize> {
        let mut state = self.lock()?;
        let before = state.waiting.len();
        let_go(&mut state.waiting, owner);
        Ok(before - state.waiting.len())
    }
}

/// Drops every waiting entry whose challenge the daemon's ledger has let go.
fn let_go(waiting: &mut BTreeMap<ChallengeKey, Pending>, owner: &dyn OwnerAuthority) {
    waiting.retain(|_, pending| owner.outstanding(&pending.request));
}

fn conflict(key: &ChallengeKey) -> ProjectError {
    ProjectError::IdConflict {
        action: key.1.to_string().into(),
        method: "a different request".to_owned().into(),
    }
}

// ----- the serial transition ------------------------------------------------------------------

/// One transition at a time for each actor and action identifier.
///
/// A second submission of the same action waits here for the first to finish, and then finds its
/// answer. Without it, two submissions could both find nothing retained, the first spend the
/// challenge and the second fail on a spent one before it ever looked for the answer.
#[derive(Debug, Default)]
pub(crate) struct Transitions {
    busy: Mutex<BTreeSet<ChallengeKey>>,
    finished: Condvar,
}

/// The transition one submission holds until it is dropped.
pub(crate) struct Transition<'a> {
    transitions: &'a Transitions,
    key: ChallengeKey,
}

impl Transitions {
    fn enter(&self, key: ChallengeKey) -> Result<Transition<'_>> {
        let poisoned = |_| ProjectError::StoreUnavailable {
            detail: "the action transitions were left poisoned by an earlier failure"
                .to_owned()
                .into(),
        };
        let mut busy = self.busy.lock().map_err(poisoned)?;
        while busy.contains(&key) {
            busy = self.finished.wait(busy).map_err(poisoned)?;
        }
        busy.insert(key.clone());
        Ok(Transition {
            transitions: self,
            key,
        })
    }
}

impl Drop for Transition<'_> {
    fn drop(&mut self) {
        let mut busy = self
            .transitions
            .busy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        busy.remove(&self.key);
        drop(busy);
        self.transitions.finished.notify_all();
    }
}

// ----- the rows ------------------------------------------------------------------------------

const LOCATION_COLUMNS: &str = "location_id, grant_id, environment_id, purpose, label, path, \
     state, authorised_at_ms, withdrawn_at_ms";

/// Returns the stored text of a purpose.
#[must_use]
pub const fn purpose_text(purpose: LocationPurpose) -> &'static str {
    match purpose {
        LocationPurpose::Destination => "destination",
        LocationPurpose::Source => "source",
    }
}

/// Returns the stored text of a state.
#[must_use]
pub const fn state_text(state: LocationState) -> &'static str {
    match state {
        LocationState::Active => "active",
        LocationState::Dormant => "dormant",
        LocationState::Withdrawn => "withdrawn",
    }
}

fn purpose_of(text: &str) -> rusqlite::Result<LocationPurpose> {
    match text {
        "destination" => Ok(LocationPurpose::Destination),
        "source" => Ok(LocationPurpose::Source),
        other => Err(unreadable(3, &format!("{other} is not a location purpose"))),
    }
}

fn state_of(text: &str) -> rusqlite::Result<LocationState> {
    match text {
        "active" => Ok(LocationState::Active),
        "dormant" => Ok(LocationState::Dormant),
        "withdrawn" => Ok(LocationState::Withdrawn),
        other => Err(unreadable(6, &format!("{other} is not a location state"))),
    }
}

/// A stored value this build cannot read, reported rather than guessed at.
///
/// A location is authority, so a row whose purpose or state this build does not know is not read
/// as the nearest thing it does: it is refused, and nothing is admitted through it.
fn unreadable(index: usize, detail: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            detail.to_owned(),
        )),
    )
}

fn uuid_column(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Uuid> {
    let bytes: Vec<u8> = row.get(index)?;
    <[u8; 16]>::try_from(bytes.as_slice())
        .map(Uuid::from_bytes)
        .map_err(|_| unreadable(index, "an identifier is sixteen bytes"))
}

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthorisedLocation> {
    let grant: Option<Vec<u8>> = row.get(1)?;
    let grant_id = match grant {
        None => None,
        Some(bytes) => Some(GrantId::new(
            <[u8; 16]>::try_from(bytes.as_slice())
                .map(Uuid::from_bytes)
                .map_err(|_| unreadable(1, "a grant identifier is sixteen bytes"))?,
        )),
    };
    Ok(AuthorisedLocation {
        location_id: ProjectLocationId::new(uuid_column(row, 0)?),
        grant_id: Nullable(grant_id),
        environment_id: EnvironmentId::new(uuid_column(row, 2)?),
        purpose: purpose_of(&row.get::<_, String>(3)?)?,
        label: row.get(4)?,
        path: row.get(5)?,
        state: state_of(&row.get::<_, String>(6)?)?,
        authorised_at_ms: TimestampMs::new(row.get::<_, i64>(7)?.cast_unsigned()),
        withdrawn_at_ms: Nullable(
            row.get::<_, Option<i64>>(8)?
                .map(|stamp| TimestampMs::new(stamp.cast_unsigned())),
        ),
    })
}

/// Returns one location's row.
///
/// # Errors
///
/// Returns [`ProjectError::StoreUnavailable`] when the row cannot be read.
pub(crate) fn read_location(
    connection: &Connection,
    location_id: ProjectLocationId,
) -> Result<Option<AuthorisedLocation>> {
    connection
        .query_row(
            &format!("SELECT {LOCATION_COLUMNS} FROM authorised_locations WHERE location_id = ?1"),
            params![location_id.get().as_bytes().to_vec()],
            read_row,
        )
        .optional()
        .map_err(ProjectError::store)
}

/// Returns an environment's locations, or one grant's among them, oldest first.
fn read_locations(
    connection: &Connection,
    environment_id: EnvironmentId,
    grant: Option<GrantId>,
) -> Result<Vec<AuthorisedLocation>> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {LOCATION_COLUMNS} FROM authorised_locations
              WHERE environment_id = ?1 AND (?2 IS NULL OR grant_id = ?2)
              ORDER BY authorised_at_ms, location_id"
        ))
        .map_err(ProjectError::store)?;
    let mapped = statement
        .query_map(
            params![
                environment_id.get().as_bytes().to_vec(),
                grant.map(|grant| grant.get().as_bytes().to_vec()),
            ],
            read_row,
        )
        .map_err(ProjectError::store)?;
    let mut rows = Vec::new();
    for row in mapped {
        rows.push(row.map_err(ProjectError::store)?);
    }
    Ok(rows)
}

fn write_location(connection: &Connection, row: &AuthorisedLocation) -> Result<()> {
    connection
        .execute(
            "INSERT INTO authorised_locations (location_id, grant_id, environment_id, purpose,
                                               label, path, state, authorised_at_ms,
                                               withdrawn_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (location_id) DO UPDATE SET
                 label = excluded.label,
                 path = excluded.path,
                 state = excluded.state,
                 authorised_at_ms = excluded.authorised_at_ms,
                 withdrawn_at_ms = excluded.withdrawn_at_ms",
            params![
                row.location_id.get().as_bytes().to_vec(),
                row.grant_id.0.map(|grant| grant.get().as_bytes().to_vec()),
                row.environment_id.get().as_bytes().to_vec(),
                purpose_text(row.purpose),
                row.label,
                row.path,
                state_text(row.state),
                row.authorised_at_ms.get().cast_signed(),
                row.withdrawn_at_ms.0.map(|stamp| stamp.get().cast_signed()),
            ],
        )
        .map_err(ProjectError::store)?;
    Ok(())
}

/// Moves every active location to dormant, because the process that held its handle is gone.
///
/// Each one is announced in the same transaction, so a consumer of the outbox sees the transition
/// this host made rather than a row that silently changed.
///
/// # Errors
///
/// Returns [`ProjectError::StoreUnavailable`] when the journal cannot be written.
pub(crate) fn load_dormant(store: &mut crate::store::Store, now_ms: TimestampMs) -> Result<u64> {
    let transaction = store.transaction()?;
    let active: Vec<Uuid> = {
        let mut statement = transaction
            .prepare("SELECT location_id FROM authorised_locations WHERE state = ?1")
            .map_err(ProjectError::store)?;
        let mapped = statement
            .query_map(params![state_text(LocationState::Active)], |row| {
                uuid_column(row, 0)
            })
            .map_err(ProjectError::store)?;
        let mut active = Vec::new();
        for id in mapped {
            active.push(id.map_err(ProjectError::store)?);
        }
        active
    };
    for id in &active {
        transaction
            .execute(
                "UPDATE authorised_locations SET state = ?2 WHERE location_id = ?1",
                params![id.as_bytes().to_vec(), state_text(LocationState::Dormant)],
            )
            .map_err(ProjectError::store)?;
        crate::store::announce(
            &transaction,
            "project.location.dormant",
            &ProjectLocationId::new(*id).to_string(),
            now_ms,
        )?;
    }
    transaction.commit().map_err(ProjectError::store)?;
    Ok(u64::try_from(active.len()).unwrap_or(u64::MAX))
}

// ----- the journal ---------------------------------------------------------------------------

/// Claims an action in a transaction of its own, before anything is spent for it.
fn claim(store: &mut crate::store::Store, action: &Action) -> Result<()> {
    let transaction = store.transaction()?;
    crate::store::claim_action(&transaction, action, None)?;
    transaction.commit().map_err(ProjectError::store)
}

/// Settles an action with its answer, inside the transaction of its effect.
///
/// An action a challenge was spent for is claimed already, and one that needed no confirmation is
/// claimed here; either way the effect, its outbox row and its answer commit together, so an
/// absent answer never conceals an effect that happened.
fn settle_answer<T: serde::Serialize>(
    transaction: &rusqlite::Transaction<'_>,
    action: &Action,
    subject: Uuid,
    answer: &T,
    claimed: bool,
) -> Result<()> {
    let encoded = kr_cbor::to_canonical_vec(answer).map_err(ProjectError::store)?;
    if !claimed {
        crate::store::claim_action(transaction, action, Some(subject))?;
    }
    if crate::store::settle_claim(transaction, action, Some(&encoded), None)? != 1 {
        return Err(ProjectError::StoreUnavailable {
            detail: format!(
                "action {} has no open claim for its answer to settle",
                action.action_id
            )
            .into(),
        });
    }
    Ok(())
}

// ----- the digests -----------------------------------------------------------------------------

fn digest_of<T: serde::Serialize>(value: &T) -> Result<Digest256> {
    let encoded = kr_cbor::to_canonical_vec(value).map_err(ProjectError::store)?;
    Ok(Digest256::from_bytes(kr_cbor::sha256(&encoded)))
}

/// The digest of an authorisation request without its proof, which a repeat has to match.
fn authorise_request_digest(params: &ProjectLocationAuthoriseParams) -> Result<Digest256> {
    let mut unproven = params.clone();
    unproven.owner_confirmation = Nullable(None);
    digest_of(&("kr-project-location-authorise-request/1", unproven))
}

/// The digest of an attachment request without its proof.
fn attach_request_digest(params: &ProjectLocationAttachParams) -> Result<Digest256> {
    let mut unproven = params.clone();
    unproven.owner_confirmation = Nullable(None);
    digest_of(&("kr-project-location-attach-request/1", unproven))
}

/// What an owner confirms when a location is authorised.
///
/// The exact request, and the identity of the directory this host opened for it, read back through
/// the handle that will be held. A proof for another path, another purpose or a directory that has
/// since replaced the one opened is a proof of something else.
fn authorisation_digest(
    params: &ProjectLocationAuthoriseParams,
    opened: ObjectIdentity,
) -> Result<Digest256> {
    digest_of(&(
        "kr-project-location-authorise/1",
        params.location_id,
        params.grant_id,
        params.environment_id,
        params.purpose,
        &params.label,
        &params.path,
        (opened.device, opened.file_id),
    ))
}

/// What an owner confirms when a repository is bound to a source location.
///
/// The repository, the location, the name the working tree was resolved by and the identity the
/// descent through the held handle produced.
fn attachment_digest(
    project_repository_id: ProjectRepositoryId,
    location_id: ProjectLocationId,
    relative: &RelativeName,
    resolved: ObjectIdentity,
) -> Result<Digest256> {
    digest_of(&(
        "kr-project-location-attach/1",
        project_repository_id,
        location_id,
        relative.as_str(),
        (resolved.device, resolved.file_id),
    ))
}

/// The rights an owner location carries, which the owner is shown unintersected.
fn location_rights() -> CanonicalSet<ActionRight> {
    LOCATION_RIGHTS.into_iter().collect()
}

/// Returns the name a recorded working tree has beneath a location's recorded path.
///
/// Both are the paths this host recorded, and the comparison is of their components, which is all
/// a name needs: the name is then resolved from the held handle, one component at a time, and the
/// object that descent produces is what decides. A working tree that is not beneath the location,
/// or that is the location itself, has no such name.
fn relative_beneath(location: &str, recorded: &str) -> Result<RelativeName> {
    let beneath = Path::new(recorded)
        .strip_prefix(Path::new(location))
        .map_err(|_| ProjectError::PermissionDenied {
            detail: format!(
                "the repository at {} is not beneath the location at {}",
                crate::git::redact(recorded),
                crate::git::redact(location)
            )
            .into(),
        })?;
    let mut components = Vec::new();
    for component in beneath.components() {
        match component {
            Component::Normal(name) => components.push(name.to_str().ok_or_else(|| {
                ProjectError::PermissionDenied {
                    detail: "the repository's recorded path is not text this host can name"
                        .to_owned()
                        .into(),
                }
            })?),
            _ => {
                return Err(ProjectError::PermissionDenied {
                    detail: format!(
                        "the repository at {} is not named beneath the location by ordinary \
                         names",
                        crate::git::redact(recorded)
                    )
                    .into(),
                });
            }
        }
    }
    if components.is_empty() {
        return Err(ProjectError::PermissionDenied {
            detail: "the location is the repository's own working tree; a source location is \
                     authorised over the directory the repository is in"
                .to_owned()
                .into(),
        });
    }
    Ok(RelativeName::parse(&components.join("/"))?)
}

/// Refuses an authorisation of a path that is not absolute.
fn absolute(path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(ProjectError::InvalidArgument(
            format!(
                "{} is not an absolute path; a location is named absolutely and opened once",
                crate::git::redact(&path.display().to_string())
            )
            .into(),
        ))
    }
}

/// Refuses a reauthorisation of anything but a dormant location of the same grant, environment and
/// purpose.
///
/// Naming the identifier is how the owner says two authorisations are one location; a matching
/// path never does. What the identifier cannot do is become a different kind of location: every
/// repository, working copy and operation that names it was recorded against the grant and the
/// purpose it had.
fn check_reauthorisable(
    row: &AuthorisedLocation,
    params: &ProjectLocationAuthoriseParams,
) -> Result<()> {
    match row.state {
        LocationState::Dormant => {}
        LocationState::Active => {
            return Err(ProjectError::InvalidArgument(
                format!(
                    "location {} is active; withdraw it before authorising another directory for \
                     it",
                    row.location_id
                )
                .into(),
            ));
        }
        LocationState::Withdrawn => {
            return Err(ProjectError::PermissionDenied {
                detail: format!(
                    "location {} was withdrawn, and a withdrawal is final",
                    row.location_id
                )
                .into(),
            });
        }
    }
    if row.grant_id != params.grant_id
        || row.environment_id != params.environment_id
        || row.purpose != params.purpose
    {
        return Err(ProjectError::InvalidArgument(
            format!(
                "location {} admits {} in environment {} as a {}; authorising it again keeps all \
                 three",
                row.location_id,
                grant_text(row.grant_id.0),
                row.environment_id,
                purpose_text(row.purpose)
            )
            .into(),
        ));
    }
    Ok(())
}

fn unanswerable(what: &str) -> ProjectError {
    ProjectError::InvalidArgument(
        format!("{what} is submitted under an action identifier, which it is answered by").into(),
    )
}

// ----- the four methods ----------------------------------------------------------------------

impl ProjectService {
    /// Returns the policy of active locations and the handles held for them.
    #[must_use]
    pub const fn locations(&self) -> &LocationPolicy {
        &self.policy
    }

    /// Drops every outstanding challenge the daemon's ledger has let go, with the handle each one
    /// held, and returns how many.
    ///
    /// Every location method does this as it starts. The daemon also does it on a timer, so a
    /// challenge nobody answers does not hold its directory open until somebody asks for another.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StoreUnavailable`] when the challenges were left poisoned.
    pub fn expire_challenges(&self, owner: &dyn OwnerAuthority) -> Result<usize> {
        self.challenges.expire(owner)
    }

    /// Serves `project.location.list`: the environment's locations, or one grant's.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::WrongEnvironment`] for another environment, or
    /// [`ProjectError::StoreUnavailable`] when the journal cannot be read.
    pub fn project_location_list(
        &self,
        params: &ProjectLocationListParams,
    ) -> Result<ProjectLocationListResult> {
        self.check_environment(params.environment_id)?;
        let store = self.locked()?;
        Ok(ProjectLocationListResult {
            locations: read_locations(store.connection(), self.environment_id, params.grant_id.0)?,
        })
    }

    /// Serves `project.location.authorise`, in either of its two submissions.
    ///
    /// # Errors
    ///
    /// Returns the refusal the request, the directory, the confirmation or the journal produced.
    pub fn project_location_authorise<'a>(
        &self,
        actor: &ActorId,
        params: &ProjectLocationAuthoriseParams,
        performed: impl Into<Performed<'a>>,
        owner: Option<&dyn OwnerAuthority>,
    ) -> Result<ProjectLocationAuthoriseResult> {
        let performed = performed.into();
        let action = performed
            .action()
            .ok_or_else(|| unanswerable("an authorisation"))?;
        self.check_environment(params.environment_id)?;
        crate::service::check_label(&params.label)?;
        let path = absolute(&params.path)?;
        let request_digest = authorise_request_digest(params)?;
        let key = challenge_key(actor, action);
        let _transition = self.transitions.enter(key.clone())?;
        // A retained answer is this action's answer, whichever submission asks. A submission with
        // no proof whose action already has one is a different request under the same identifier,
        // and the journal says so.
        if let Some(answered) =
            self.answer_from_record::<ProjectLocationAuthoriseResult>(Some(action))?
        {
            return Ok(answered);
        }
        let owner = owner.ok_or_else(no_owner)?;
        let Some(proof) = params.owner_confirmation.as_ref() else {
            let request =
                self.authorisation_challenge(key, params, &path, request_digest, owner)?;
            return Ok(ProjectLocationAuthoriseResult {
                outcome: LocationAuthorisation::ConfirmationRequired { request },
            });
        };
        let taken = self
            .challenges
            .take(&key, request_digest, &proof.request, owner)?;
        let subject = self.spend(taken, proof, action, owner)?;
        // The challenge is spent and the action is claimed. Whatever happens now is this action's
        // answer, and is kept.
        let outcome = match subject {
            Subject::Location { handle } => handle
                .revalidate()
                .map_err(ProjectError::from)
                .and_then(|()| self.commit_authorisation(action, params, handle, performed)),
            Subject::Attachment { .. } => Err(ProjectError::Unconfirmed {
                detail: "the challenge for this action was issued for a binding"
                    .to_owned()
                    .into(),
            }),
        };
        self.answered(action, outcome, true)
    }

    /// Opens what an authorisation names and answers with the challenge the owner signs.
    fn authorisation_challenge(
        &self,
        key: ChallengeKey,
        params: &ProjectLocationAuthoriseParams,
        path: &Path,
        request_digest: Digest256,
        owner: &dyn OwnerAuthority,
    ) -> Result<OwnerConfirmationRequest> {
        if let Some(request) = self.challenges.repeated(&key, request_digest, owner)? {
            return Ok(request);
        }
        if let Some(grant) = params.grant_id.0 {
            // The confirmation of a device's location has to name the four public keys of the
            // device that holds the grant, and this host keeps only two of them; a location that
            // named a grant would admit nothing here anyway.
            return Err(ProjectError::PermissionDenied {
                detail: format!(
                    "a location is authorised for the owner alone on this host: confirming one for \
                     grant {grant} would have to name the four public keys of the device that holds \
                     it, and this host keeps only two of them"
                )
                .into(),
            });
        }
        if let Some(location_id) = params.location_id.0 {
            let row =
                read_location(self.locked()?.connection(), location_id)?.ok_or_else(|| {
                    ProjectError::UnknownLocation {
                        location: location_id.to_string().into(),
                    }
                })?;
            check_reauthorisable(&row, params)?;
        }
        // Opened now, confined to the mount it is on, and kept: the confirmation is bound to this
        // object, and this object is what the location will hold. A platform that will not say
        // which mount a directory is on refuses the authorisation rather than approximating one.
        let handle =
            AuthorisedDirectory::open_root(self.environment_id, path)?.confined_to_one_mount()?;
        let enlargement = Enlargement {
            action_digest: authorisation_digest(params, handle.identity())?,
            rights: location_rights(),
        };
        self.challenges.issue(
            key,
            request_digest,
            enlargement,
            Subject::Location { handle },
            owner,
        )
    }

    /// Verifies a proof, claims the action, and spends the challenge, in that order.
    ///
    /// A proof that does not verify spends nothing and records nothing, and the challenge stays
    /// outstanding for the owner's own proof. A claim the journal refuses spends nothing either.
    /// Once the claim is written the challenge is spent, and from then on whatever happens is this
    /// action's answer: the claim is what a repeat finds if nothing else gets written.
    fn spend(
        &self,
        taken: Answering<'_>,
        proof: &OwnerConfirmationProof,
        action: &Action,
        owner: &dyn OwnerAuthority,
    ) -> Result<Subject> {
        let verified = match taken.enlargement() {
            Some(enlargement) => owner.verify(enlargement, proof).map_err(declined),
            None => Err(ProjectError::Unconfirmed {
                detail: "the challenge for this action is no longer outstanding"
                    .to_owned()
                    .into(),
            }),
        };
        if let Err(error) = verified {
            taken.restore(owner);
            return Err(error);
        }
        let claimed = self
            .writable()
            .and_then(|mut store| claim(&mut store, action));
        if let Err(error) = claimed {
            taken.restore(owner);
            return Err(error);
        }
        if let Err(refusal) = owner.consume(proof) {
            drop(taken);
            return self.answered(action, Err(declined(refusal)), true);
        }
        taken
            .spent()
            .map(|pending| pending.subject)
            .ok_or_else(|| ProjectError::Unconfirmed {
                detail: "the challenge for this action is no longer outstanding"
                    .to_owned()
                    .into(),
            })
            .or_else(|error| self.answered(action, Err(error), true))
    }

    /// Writes an authorised location, its outbox row and its answer in one transaction, and holds
    /// its handle.
    fn commit_authorisation(
        &self,
        action: &Action,
        params: &ProjectLocationAuthoriseParams,
        handle: AuthorisedDirectory,
        performed: Performed<'_>,
    ) -> Result<ProjectLocationAuthoriseResult> {
        let mut store = self.writable()?;
        let transaction = store.transaction()?;
        performed.admit()?;
        let mut held = self.policy.lock()?;
        let now = self.clock.now_ms();
        let row = match params.location_id.0 {
            None => AuthorisedLocation {
                location_id: ProjectLocationId::new(crate::service::new_uuid()),
                grant_id: params.grant_id,
                environment_id: params.environment_id,
                purpose: params.purpose,
                label: params.label.clone(),
                path: params.path.clone(),
                state: LocationState::Active,
                authorised_at_ms: now,
                withdrawn_at_ms: Nullable(None),
            },
            Some(location_id) => {
                // Asked again inside the transaction: a withdrawal between the challenge and this
                // commit is final, and the challenge the owner signed does not undo it.
                let current = read_location(&transaction, location_id)?.ok_or_else(|| {
                    ProjectError::UnknownLocation {
                        location: location_id.to_string().into(),
                    }
                })?;
                check_reauthorisable(&current, params)?;
                AuthorisedLocation {
                    label: params.label.clone(),
                    path: params.path.clone(),
                    state: LocationState::Active,
                    authorised_at_ms: now,
                    withdrawn_at_ms: Nullable(None),
                    ..current
                }
            }
        };
        write_location(&transaction, &row)?;
        crate::store::announce(
            &transaction,
            "project.location.authorised",
            &row.location_id.to_string(),
            now,
        )?;
        let answer = ProjectLocationAuthoriseResult {
            outcome: LocationAuthorisation::Authorised {
                location: row.clone(),
            },
        };
        settle_answer(&transaction, action, row.location_id.get(), &answer, true)?;
        transaction.commit().map_err(ProjectError::store)?;
        held.insert(row.location_id, Arc::new(HeldLocation { handle, row }));
        Ok(answer)
    }

    /// Serves `project.location.withdraw`.
    ///
    /// The row moves to withdrawn and stays, so an old authorisation's retry still finds its
    /// answer, and the policy lets go of the handle in the same critical section: an admission
    /// already granted keeps the handle it holds, and none is granted after the commit.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::UnknownLocation`] for a location this environment never had, or
    /// the journal's failure.
    pub fn project_location_withdraw<'a>(
        &self,
        params: &ProjectLocationWithdrawParams,
        performed: impl Into<Performed<'a>>,
    ) -> Result<ProjectLocationWithdrawResult> {
        let performed = performed.into();
        if let Some(answered) =
            self.answer_from_record::<ProjectLocationWithdrawResult>(performed.action())?
        {
            return Ok(answered);
        }
        let mut store = self.writable()?;
        let transaction = store.transaction()?;
        performed.admit()?;
        let mut held = self.policy.lock()?;
        let current = read_location(&transaction, params.location_id)?.ok_or_else(|| {
            ProjectError::UnknownLocation {
                location: params.location_id.to_string().into(),
            }
        })?;
        let now = self.clock.now_ms();
        let row = if matches!(current.state, LocationState::Withdrawn) {
            // Withdrawn already. Nothing changes, so nothing is announced; the answer is the row.
            current
        } else {
            let row = AuthorisedLocation {
                state: LocationState::Withdrawn,
                withdrawn_at_ms: Nullable(Some(now)),
                ..current
            };
            write_location(&transaction, &row)?;
            crate::store::announce(
                &transaction,
                "project.location.withdrawn",
                &row.location_id.to_string(),
                now,
            )?;
            row
        };
        let answer = ProjectLocationWithdrawResult {
            location: row.clone(),
        };
        if let Some(action) = performed.action() {
            settle_answer(&transaction, action, row.location_id.get(), &answer, false)?;
        }
        transaction.commit().map_err(ProjectError::store)?;
        held.remove(&row.location_id);
        Ok(answer)
    }

    /// Serves `project.location.attach`, in either of its two submissions, and its clearing.
    ///
    /// # Errors
    ///
    /// Returns the refusal the request, the descent, the confirmation or the journal produced.
    pub fn project_location_attach<'a>(
        &self,
        actor: &ActorId,
        params: &ProjectLocationAttachParams,
        performed: impl Into<Performed<'a>>,
        owner: Option<&dyn OwnerAuthority>,
    ) -> Result<ProjectLocationAttachResult> {
        let performed = performed.into();
        let action = performed
            .action()
            .ok_or_else(|| unanswerable("a binding"))?;
        let request_digest = attach_request_digest(params)?;
        let key = challenge_key(actor, action);
        let _transition = self.transitions.enter(key.clone())?;
        if let Some(answered) =
            self.answer_from_record::<ProjectLocationAttachResult>(Some(action))?
        {
            return Ok(answered);
        }
        let Some(location_id) = params.location_id.0 else {
            // Clearing a binding only reduces what the location reaches, so it needs no
            // confirmation and is an action like any other: its answer is kept whichever way it
            // goes.
            let outcome = if params.owner_confirmation.is_present() {
                Err(ProjectError::InvalidArgument(
                    "clearing a binding reduces reach and carries no confirmation"
                        .to_owned()
                        .into(),
                ))
            } else {
                self.commit_binding(action, params.project_repository_id, None, performed, false)
            };
            return self.answered(action, outcome, false);
        };
        let owner = owner.ok_or_else(no_owner)?;
        let Some(proof) = params.owner_confirmation.as_ref() else {
            let request =
                self.attachment_challenge(key, params, location_id, request_digest, owner)?;
            return Ok(ProjectLocationAttachResult {
                outcome: LocationAttachment::ConfirmationRequired { request },
            });
        };
        let taken = self
            .challenges
            .take(&key, request_digest, &proof.request, owner)?;
        let subject = self.spend(taken, proof, action, owner)?;
        let outcome = match subject {
            Subject::Attachment {
                held,
                tree,
                relative,
            } => self.commit_binding(
                action,
                params.project_repository_id,
                Some(Resolved {
                    held: &held,
                    tree: &tree,
                    relative: &relative,
                }),
                performed,
                true,
            ),
            Subject::Location { .. } => Err(ProjectError::Unconfirmed {
                detail: "the challenge for this action was issued for a location"
                    .to_owned()
                    .into(),
            }),
        };
        self.answered(action, outcome, true)
    }

    /// Proves a binding and answers with the challenge the owner signs.
    ///
    /// Nothing is opened here: the location's own held handle is the start, the repository's
    /// recorded working tree has to resolve downward from it by a name, and the object the descent
    /// produces has to be the one the repository's record names. That read is admitted like every
    /// other read through a location.
    fn attachment_challenge(
        &self,
        key: ChallengeKey,
        params: &ProjectLocationAttachParams,
        location_id: ProjectLocationId,
        request_digest: Digest256,
        owner: &dyn OwnerAuthority,
    ) -> Result<OwnerConfirmationRequest> {
        if let Some(request) = self.challenges.repeated(&key, request_digest, owner)? {
            return Ok(request);
        }
        let (project, location) = {
            let store = self.locked()?;
            let project = store
                .project(params.project_repository_id)?
                .ok_or_else(|| ProjectError::UnknownProject {
                    project: params.project_repository_id.to_string().into(),
                })?;
            let location = read_location(store.connection(), location_id)?.ok_or_else(|| {
                ProjectError::UnknownLocation {
                    location: location_id.to_string().into(),
                }
            })?;
            (project, location)
        };
        if matches!(location.state, LocationState::Withdrawn) {
            return Err(ProjectError::PermissionDenied {
                detail: format!("location {location_id} was withdrawn, and a withdrawal is final")
                    .into(),
            });
        }
        let held = self.policy.admit(
            location_id,
            &LocationUse {
                purpose: LocationPurpose::Source,
                environment_id: project.environment_id,
                admitting: Admitting::OwnerDecision,
            },
        )?;
        let relative = relative_beneath(&held.row.path, &project.display_path)?;
        let tree = held.handle.subdirectory(&relative)?;
        if tree.identity() != project.identity.work_tree {
            return Err(ProjectError::IdentityChanged {
                detail: format!(
                    "the repository's record names the working tree {} and {} beneath location \
                     {location_id} is {}; a binding is proved through the location, and this one \
                     is not",
                    project.identity.work_tree,
                    crate::git::redact(relative.as_str()),
                    tree.identity()
                )
                .into(),
            });
        }
        let enlargement = Enlargement {
            action_digest: attachment_digest(
                project.project_repository_id,
                location_id,
                &relative,
                tree.identity(),
            )?,
            rights: location_rights(),
        };
        self.challenges.issue(
            key,
            request_digest,
            enlargement,
            Subject::Attachment {
                held,
                tree,
                relative,
            },
            owner,
        )
    }

    /// Writes a repository's source binding, its outbox row and its answer in one transaction.
    ///
    /// A binding is checked once more under the policy's lock, immediately before the commit: the
    /// location has to be the one the descent went through, still held and still a source. The
    /// handle and the name the descent produced are held by the caller until this returns.
    fn commit_binding(
        &self,
        action: &Action,
        project_repository_id: ProjectRepositoryId,
        resolved: Option<Resolved<'_>>,
        performed: Performed<'_>,
        claimed: bool,
    ) -> Result<ProjectLocationAttachResult> {
        let mut store = self.writable()?;
        let transaction = store.transaction()?;
        performed.admit()?;
        let held = self.policy.lock()?;
        let project =
            crate::store::project_in(&transaction, project_repository_id)?.ok_or_else(|| {
                ProjectError::UnknownProject {
                    project: project_repository_id.to_string().into(),
                }
            })?;
        let source = match resolved {
            None => None,
            Some(resolved) => {
                recheck(
                    &held,
                    resolved.held,
                    &LocationUse {
                        purpose: LocationPurpose::Source,
                        environment_id: project.environment_id,
                        admitting: Admitting::OwnerDecision,
                    },
                )?;
                if resolved.tree.identity() != project.identity.work_tree {
                    return Err(ProjectError::IdentityChanged {
                        detail: "the working tree the binding was proved against is no longer the \
                                 one the repository's record names"
                            .to_owned()
                            .into(),
                    });
                }
                Some(LocatedName {
                    location_id: resolved.held.location_id(),
                    relative_path: resolved.relative.as_str().to_owned(),
                })
            }
        };
        crate::store::set_project_source(&transaction, project_repository_id, source.as_ref())?;
        let now = self.clock.now_ms();
        crate::store::announce(
            &transaction,
            "project.location.attached",
            &project_repository_id.to_string(),
            now,
        )?;
        let workspaces = crate::store::workspace_count_in(
            &transaction,
            project.environment_id,
            project_repository_id,
        )?;
        let answer = ProjectLocationAttachResult {
            outcome: LocationAttachment::Bound {
                project: self.summarise(
                    &ProjectRow {
                        source: source.clone(),
                        ..project
                    },
                    workspaces,
                ),
                source: Nullable(source.map(|named| SourceBinding {
                    location_id: named.location_id,
                    relative_path: named.relative_path,
                })),
            },
        };
        settle_answer(
            &transaction,
            action,
            project_repository_id.get(),
            &answer,
            claimed,
        )?;
        transaction.commit().map_err(ProjectError::store)?;
        drop(held);
        Ok(answer)
    }

    /// Keeps a failure as this action's answer, and returns the outcome it was given.
    ///
    /// A confirmed decision's failure after its challenge is spent is owed to a repeat, because
    /// the confirmation cannot be answered twice; an ordinary action's failure is owed to a repeat
    /// because it is an action. The claim a spent challenge left is settled; an action with none
    /// is claimed and settled in one transaction. A journal that refuses even that leaves the
    /// claim open, which a repeat is told about and a restart settles, and never a spent challenge
    /// with nothing recorded.
    fn answered<T>(&self, action: &Action, outcome: Result<T>, claimed: bool) -> Result<T> {
        let Err(error) = outcome else {
            return outcome;
        };
        let detail = error.to_string();
        if let Ok(mut store) = self.writable()
            && let Ok(transaction) = store.transaction()
            && (claimed || crate::store::claim_action(&transaction, action, None).is_ok())
            && matches!(
                crate::store::settle_claim(
                    &transaction,
                    action,
                    None,
                    Some((error.code(), &detail))
                ),
                Ok(1)
            )
        {
            let _ = transaction.commit();
        }
        Err(error)
    }
}

/// What a binding resolved through, held until it commits.
#[derive(Clone, Copy)]
struct Resolved<'a> {
    held: &'a Arc<HeldLocation>,
    tree: &'a AuthorisedDirectory,
    relative: &'a RelativeName,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(grant: Option<GrantId>, purpose: LocationPurpose) -> HeldLocation {
        let directory = tempfile::tempdir().expect("a directory");
        let environment_id = EnvironmentId::new(Uuid::from_bytes([3; 16]));
        HeldLocation {
            handle: AuthorisedDirectory::open_root(environment_id, directory.path())
                .expect("the directory opens"),
            row: AuthorisedLocation {
                location_id: ProjectLocationId::new(Uuid::from_bytes([4; 16])),
                grant_id: Nullable(grant),
                environment_id,
                purpose,
                label: "a location".to_owned(),
                path: directory.path().display().to_string(),
                state: LocationState::Active,
                authorised_at_ms: TimestampMs::new(1),
                withdrawn_at_ms: Nullable(None),
            },
        }
    }

    #[test]
    fn a_working_tree_is_named_beneath_a_location_by_its_components_alone() {
        let name = relative_beneath("/srv/projects", "/srv/projects/team/repo").expect("beneath");
        assert_eq!(name.as_str(), "team/repo");
        let name = relative_beneath("/srv/projects/", "/srv/projects/repo").expect("beneath");
        assert_eq!(name.as_str(), "repo");
        for (location, recorded) in [
            ("/srv/projects", "/srv/other/repo"),
            ("/srv/projects", "/srv/projects-old/repo"),
            ("/srv/projects", "/srv/projects"),
            ("/srv/projects", "/srv/projects/../elsewhere"),
            ("/srv/projects", "relative/repo"),
        ] {
            assert!(
                relative_beneath(location, recorded).is_err(),
                "{recorded} is not named beneath {location}"
            );
        }
    }

    #[test]
    fn an_owner_location_admits_the_owner_and_a_grant_location_admits_nobody() {
        let environment_id = EnvironmentId::new(Uuid::from_bytes([3; 16]));
        let grant = GrantId::new(Uuid::from_bytes([5; 16]));
        let owners = held(None, LocationPurpose::Source);
        let wanted = |admitting| LocationUse {
            purpose: LocationPurpose::Source,
            environment_id,
            admitting,
        };
        admits(&owners, &wanted(Admitting::Caller(None))).expect("the owner's own use");
        admits(&owners, &wanted(Admitting::OwnerDecision)).expect("the owner's decision");
        admits(&owners, &wanted(Admitting::Caller(Some(grant))))
            .expect_err("a caller bounded by a grant is not the owner");
        let grants = held(Some(grant), LocationPurpose::Source);
        for admitting in [
            Admitting::Caller(Some(grant)),
            Admitting::Caller(None),
            Admitting::OwnerDecision,
        ] {
            let refusal = admits(&grants, &wanted(admitting))
                .expect_err("a grant's location admits nothing on this host");
            assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
        }
    }

    #[test]
    fn an_owner_location_carries_both_rights() {
        assert_eq!(
            location_rights(),
            [ActionRight::ProjectCreate, ActionRight::WorkspaceManage]
                .into_iter()
                .collect()
        );
    }

    #[test]
    fn a_proof_is_not_part_of_the_request_a_repeat_has_to_match() {
        let params = ProjectLocationAuthoriseParams {
            location_id: Nullable(None),
            environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
            grant_id: Nullable(None),
            purpose: LocationPurpose::Destination,
            label: "work".to_owned(),
            path: "/srv/work".to_owned(),
            owner_confirmation: Nullable(None),
        };
        let other = ProjectLocationAuthoriseParams {
            path: "/srv/elsewhere".to_owned(),
            ..params.clone()
        };
        assert_ne!(
            authorise_request_digest(&params).expect("a digest"),
            authorise_request_digest(&other).expect("a digest")
        );
    }
}
