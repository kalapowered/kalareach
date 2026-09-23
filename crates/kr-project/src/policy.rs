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
//! ## The confirmation, in two submissions of one action
//!
//! The first submission carries no proof. This host opens what it would authorise, keeps that
//! handle beside a challenge whose digest covers the request **and the identity read back through
//! the handle**, and answers with the challenge. Nothing durable is written and no outcome is
//! retained, so a repeat of the same request under the same action identifier is answered with the
//! same outstanding challenge, and the challenge's own expiry ends it with the handle.
//!
//! The second submission carries the proof, and everything it does happens inside one serial
//! transition for its actor and action identifier, taken before anything is looked up. Inside it:
//! a retained answer is returned when there is one; otherwise the outstanding challenge has to be
//! there, the proof has to answer it, and the challenge is consumed; then the effect and its
//! answer commit in one transaction with the outbox row that announces it. A copy of the same
//! submission that arrives meanwhile waits for the transition and then finds the answer, rather
//! than meeting a spent challenge. Once the challenge is spent, a failure is this action's answer
//! too and is retained, so a spent confirmation never needs a second ceremony to learn what
//! happened.
//!
//! ## Lock order
//!
//! The per-action transition, then the project journal, then this policy's own lock. A read
//! admission takes only the last. Nothing here is held across a subprocess.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ActorId, DeviceId, EnvironmentId, GrantId, ProjectLocationId, ProjectRepositoryId,
};
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
/// Each one holds an open directory until it is answered or expires, and an owner who asks for
/// challenges and never signs them would otherwise hold descriptors without bound. A real owner
/// confirms one decision at a time; this is far above that and far below what a process may open.
pub const MAX_OUTSTANDING_CHALLENGES: usize = 32;

/// The rights a location can carry: a destination enables creating a repository and a working
/// copy in it, and a source enables cloning one and taking a working copy of it.
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

/// What one grant reaches, as the daemon holds it now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantReach {
    /// The device the grant was issued to.
    pub recipient_device_id: DeviceId,
    /// The actions it carries.
    pub actions: CanonicalSet<ActionRight>,
}

/// What the daemon lends this service for the owner's own decisions.
///
/// The service knows its locations and its repositories. It does not know this host's owner, its
/// enrolled signer or its grants, and it should not: those are the daemon's, and a service that
/// kept its own copy would be one more place for them to disagree. So the ceremony and the question
/// about a grant are asked of the daemon, which answers under its own codes.
pub trait OwnerAuthority: Send + Sync {
    /// Issues a fresh challenge for one enlargement and records it as outstanding.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal, for example on a host with no enrolled owner.
    fn challenge(
        &self,
        enlargement: &Enlargement,
    ) -> std::result::Result<OwnerConfirmationRequest, ProtocolError>;

    /// Verifies a proof against the challenge this host issued for exactly this enlargement, and
    /// consumes the challenge.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal when the proof does not answer an outstanding challenge for
    /// this enlargement under the enrolled signer.
    fn accept(
        &self,
        enlargement: &Enlargement,
        proof: &OwnerConfirmationProof,
    ) -> std::result::Result<(), ProtocolError>;

    /// Returns what a grant reaches, while its registration stands and it has not expired.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal for a grant that is unknown, revoked or expired.
    fn grant(&self, grant_id: GrantId) -> std::result::Result<GrantReach, ProtocolError>;
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
    /// The owner deciding something about the location itself, whichever grant it admits.
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
    held: Mutex<BTreeMap<ProjectLocationId, Arc<HeldLocation>>>,
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
    /// for an operation, the caller's own. Where it names a grant, that grant's registration and
    /// expiry are asked about as well; an owner location names none, and that absence is the
    /// owner's own case rather than a failure. What comes back is the policy's own reference: the
    /// caller keeps it for as long as the read lasts, and a later transaction can prove that the
    /// location it relies on is still this one.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::PermissionDenied`] when the location admits no such use now, or the
    /// daemon's refusal of its grant.
    pub fn admit(
        &self,
        location_id: ProjectLocationId,
        wanted: &LocationUse,
        owner: Option<&dyn OwnerAuthority>,
    ) -> Result<Arc<HeldLocation>> {
        let held = {
            let map = self.lock()?;
            let held = map
                .get(&location_id)
                .cloned()
                .ok_or_else(|| not_active(location_id))?;
            admits(&held, wanted)?;
            held
        };
        if let Some(grant_id) = held.row.grant_id.0 {
            let owner = owner.ok_or_else(|| ProjectError::PermissionDenied {
                detail: format!(
                    "location {location_id} admits grant {grant_id}, and this host cannot ask \
                     whether that grant stands"
                )
                .into(),
            })?;
            owner.grant(grant_id).map_err(declined)?;
        }
        // The answer is the one under the lock. A withdrawal that committed while the grant was
        // being asked about took the location away, and this is where that is seen.
        let map = self.lock()?;
        match map.get(&location_id) {
            Some(current) if Arc::ptr_eq(current, &held) => Ok(held),
            _ => Err(not_active(location_id)),
        }
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
    if let Admitting::Caller(grant) = wanted.admitting
        && row.grant_id.0 != grant
    {
        return Err(ProjectError::PermissionDenied {
            detail: format!(
                "location {} admits {}, and this request is {}",
                row.location_id,
                grant_text(row.grant_id.0),
                grant_text(grant)
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

// ----- outstanding challenges ---------------------------------------------------------------------

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
/// Nothing here is durable. A restart ends every challenge together with the handle it held, and
/// the owner starts again, which is right: a confirmation is bound to an object this process
/// opened, and the next process has not opened it.
#[derive(Debug, Default)]
pub(crate) struct Challenges {
    outstanding: Mutex<BTreeMap<ChallengeKey, Pending>>,
}

impl Challenges {
    fn lock(&self) -> Result<MutexGuard<'_, BTreeMap<ChallengeKey, Pending>>> {
        self.outstanding
            .lock()
            .map_err(|_| ProjectError::StoreUnavailable {
                detail: "the outstanding challenges were left poisoned by an earlier failure"
                    .to_owned()
                    .into(),
            })
    }

    /// Returns the challenge still outstanding for this same request, when there is one.
    ///
    /// A challenge that has run out is dropped here with its handle. One action identifier used
    /// for a different request is refused as the journal would refuse it.
    fn outstanding(
        &self,
        key: &ChallengeKey,
        request_digest: Digest256,
        now_ms: TimestampMs,
    ) -> Result<Option<OwnerConfirmationRequest>> {
        let mut outstanding = self.lock()?;
        sweep(&mut outstanding, now_ms);
        match outstanding.get(key) {
            None => Ok(None),
            Some(pending) if pending.request_digest == request_digest => {
                Ok(Some(pending.request.clone()))
            }
            Some(_) => Err(ProjectError::IdConflict {
                action: key.1.to_string().into(),
                method: "a different request".to_owned().into(),
            }),
        }
    }

    /// Keeps a challenge this host has just issued.
    fn hold(&self, key: ChallengeKey, pending: Pending, now_ms: TimestampMs) -> Result<()> {
        let mut outstanding = self.lock()?;
        sweep(&mut outstanding, now_ms);
        if outstanding.len() >= MAX_OUTSTANDING_CHALLENGES {
            return Err(ProjectError::QuotaExceeded {
                detail: format!(
                    "this host already holds {MAX_OUTSTANDING_CHALLENGES} challenges nobody has \
                     answered; answer one or let them expire"
                )
                .into(),
            });
        }
        outstanding.insert(key, pending);
        Ok(())
    }

    /// Takes the outstanding challenge a proof answers, leaving it in place when it does not.
    fn take(
        &self,
        key: &ChallengeKey,
        request_digest: Digest256,
        presented: &OwnerConfirmationRequest,
        now_ms: TimestampMs,
    ) -> Result<Pending> {
        let mut outstanding = self.lock()?;
        sweep(&mut outstanding, now_ms);
        let Some(pending) = outstanding.get(key) else {
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
        outstanding
            .remove(key)
            .ok_or_else(|| ProjectError::Unconfirmed {
                detail: "the challenge for this action is no longer outstanding"
                    .to_owned()
                    .into(),
            })
    }

    /// Puts back a challenge whose proof the daemon did not accept, while it is still current.
    fn restore(&self, key: ChallengeKey, pending: Pending, now_ms: TimestampMs) {
        if pending.request.expires_at_ms.get() <= now_ms.get() {
            return;
        }
        if let Ok(mut outstanding) = self.lock() {
            outstanding.entry(key).or_insert(pending);
        }
    }
}

/// Drops every challenge that has run out, and the handle each one held.
fn sweep(outstanding: &mut BTreeMap<ChallengeKey, Pending>, now_ms: TimestampMs) {
    outstanding.retain(|_, pending| pending.request.expires_at_ms.get() > now_ms.get());
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

/// Claims an action and settles it with its answer, inside the transaction of its effect.
fn retain_answer<T: serde::Serialize>(
    connection: &rusqlite::Transaction<'_>,
    action: &Action,
    subject: Uuid,
    answer: &T,
) -> Result<()> {
    let encoded = kr_cbor::to_canonical_vec(answer).map_err(ProjectError::store)?;
    crate::store::claim_action(connection, action, Some(subject))?;
    crate::store::settle_claim(connection, action, Some(&encoded), None)?;
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
/// the handle that will be held. A proof for another path, another purpose, another grant or a
/// directory that has since replaced the one opened is a proof of something else. A location that
/// admits a grant also names the device that grant was issued to.
fn authorisation_digest(
    params: &ProjectLocationAuthoriseParams,
    opened: ObjectIdentity,
    reach: Option<&GrantReach>,
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
        reach.map(|reach| reach.recipient_device_id),
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
    reach: Option<&GrantReach>,
) -> Result<Digest256> {
    digest_of(&(
        "kr-project-location-attach/1",
        project_repository_id,
        location_id,
        relative.as_str(),
        (resolved.device, resolved.file_id),
        reach.map(|reach| reach.recipient_device_id),
    ))
}

/// The rights a location carries for its grant: both of them for an owner location, and those of
/// the two the grant holds for a grant's.
fn location_rights(reach: Option<&GrantReach>) -> CanonicalSet<ActionRight> {
    LOCATION_RIGHTS
        .into_iter()
        .filter(|right| reach.is_none_or(|reach| reach.actions.contains(right)))
        .collect()
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
        let Some(proof) = params.owner_confirmation.as_ref() else {
            let request =
                self.authorisation_challenge(key, params, &path, request_digest, owner)?;
            return Ok(ProjectLocationAuthoriseResult {
                outcome: LocationAuthorisation::ConfirmationRequired { request },
            });
        };
        let owner = owner.ok_or_else(no_owner)?;
        let pending =
            self.challenges
                .take(&key, request_digest, &proof.request, self.clock.now_ms())?;
        if let Err(refusal) = owner.accept(&pending.enlargement, proof) {
            self.challenges.restore(key, pending, self.clock.now_ms());
            return Err(declined(refusal));
        }
        // The challenge is spent. Whatever happens now is this action's answer, and is kept.
        let outcome = match pending.subject {
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
        self.kept(action, outcome)
    }

    /// Opens what an authorisation names and answers with the challenge the owner signs.
    fn authorisation_challenge(
        &self,
        key: ChallengeKey,
        params: &ProjectLocationAuthoriseParams,
        path: &Path,
        request_digest: Digest256,
        owner: Option<&dyn OwnerAuthority>,
    ) -> Result<OwnerConfirmationRequest> {
        let now = self.clock.now_ms();
        if let Some(request) = self.challenges.outstanding(&key, request_digest, now)? {
            return Ok(request);
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
        let owner = owner.ok_or_else(no_owner)?;
        let reach = params
            .grant_id
            .0
            .map(|grant| owner.grant(grant).map_err(declined))
            .transpose()?;
        // Opened now, confined to the mount it is on, and kept: the confirmation is bound to this
        // object, and this object is what the location will hold. A platform that will not say
        // which mount a directory is on refuses the authorisation rather than approximating one.
        let handle =
            AuthorisedDirectory::open_root(self.environment_id, path)?.confined_to_one_mount()?;
        let enlargement = Enlargement {
            action_digest: authorisation_digest(params, handle.identity(), reach.as_ref())?,
            rights: location_rights(reach.as_ref()),
        };
        let request = owner.challenge(&enlargement).map_err(declined)?;
        self.challenges.hold(
            key,
            Pending {
                request_digest,
                request: request.clone(),
                enlargement,
                subject: Subject::Location { handle },
            },
            now,
        )?;
        Ok(request)
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
        retain_answer(&transaction, action, row.location_id.get(), &answer)?;
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
            retain_answer(&transaction, action, row.location_id.get(), &answer)?;
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
            // Clearing a binding only reduces what the location's grant reaches.
            if params.owner_confirmation.is_present() {
                return Err(ProjectError::InvalidArgument(
                    "clearing a binding reduces reach and carries no confirmation"
                        .to_owned()
                        .into(),
                ));
            }
            return self.commit_binding(action, params.project_repository_id, None, performed);
        };
        let Some(proof) = params.owner_confirmation.as_ref() else {
            let request =
                self.attachment_challenge(key, params, location_id, request_digest, owner)?;
            return Ok(ProjectLocationAttachResult {
                outcome: LocationAttachment::ConfirmationRequired { request },
            });
        };
        let owner = owner.ok_or_else(no_owner)?;
        let pending =
            self.challenges
                .take(&key, request_digest, &proof.request, self.clock.now_ms())?;
        if let Err(refusal) = owner.accept(&pending.enlargement, proof) {
            self.challenges.restore(key, pending, self.clock.now_ms());
            return Err(declined(refusal));
        }
        let outcome = match pending.subject {
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
            ),
            Subject::Location { .. } => Err(ProjectError::Unconfirmed {
                detail: "the challenge for this action was issued for a location"
                    .to_owned()
                    .into(),
            }),
        };
        self.kept(action, outcome)
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
        owner: Option<&dyn OwnerAuthority>,
    ) -> Result<OwnerConfirmationRequest> {
        let now = self.clock.now_ms();
        if let Some(request) = self.challenges.outstanding(&key, request_digest, now)? {
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
        let owner = owner.ok_or_else(no_owner)?;
        let held = self.policy.admit(
            location_id,
            &LocationUse {
                purpose: LocationPurpose::Source,
                environment_id: project.environment_id,
                admitting: Admitting::OwnerDecision,
            },
            Some(owner),
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
        let reach = held
            .row
            .grant_id
            .0
            .map(|grant| owner.grant(grant).map_err(declined))
            .transpose()?;
        let enlargement = Enlargement {
            action_digest: attachment_digest(
                project.project_repository_id,
                location_id,
                &relative,
                tree.identity(),
                reach.as_ref(),
            )?,
            rights: location_rights(reach.as_ref()),
        };
        let request = owner.challenge(&enlargement).map_err(declined)?;
        self.challenges.hold(
            key,
            Pending {
                request_digest,
                request: request.clone(),
                enlargement,
                subject: Subject::Attachment {
                    held,
                    tree,
                    relative,
                },
            },
            now,
        )?;
        Ok(request)
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
        retain_answer(&transaction, action, project_repository_id.get(), &answer)?;
        transaction.commit().map_err(ProjectError::store)?;
        drop(held);
        Ok(answer)
    }

    /// Keeps a failure that happened after a challenge was spent, as this action's answer.
    ///
    /// The confirmation cannot be answered twice, so what became of the submission that spent it
    /// has to be readable by a repeat of the action. A journal that refuses even that leaves the
    /// failure unrecorded, and the caller is still told it.
    fn kept<T>(&self, action: &Action, outcome: Result<T>) -> Result<T> {
        let Err(error) = outcome else {
            return outcome;
        };
        let detail = error.to_string();
        if let Ok(mut store) = self.writable()
            && let Ok(transaction) = store.transaction()
            && crate::store::claim_action(&transaction, action, None).is_ok()
            && crate::store::settle_claim(&transaction, action, None, Some((error.code(), &detail)))
                .is_ok()
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
    fn a_location_carries_both_rights_for_the_owner_and_those_a_grant_holds() {
        let both: CanonicalSet<ActionRight> = LOCATION_RIGHTS.into_iter().collect();
        assert_eq!(location_rights(None), both);
        let reach = GrantReach {
            recipient_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
            actions: [ActionRight::WorkspaceManage, ActionRight::SessionView]
                .into_iter()
                .collect(),
        };
        assert_eq!(
            location_rights(Some(&reach)),
            [ActionRight::WorkspaceManage].into_iter().collect()
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
