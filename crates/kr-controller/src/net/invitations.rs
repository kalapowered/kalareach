//! The host's durable pairing records.
//!
//! Five tables in the daemon's registry database, beside the device directory and written through
//! its connection, so one transaction can hold a device row and the records of how it was admitted:
//!
//! | Table | What it holds |
//! | --- | --- |
//! | `pairing_invitations` | Every invitation this host issued: kr-pairing's record, its mode and origin, the proposed grant, and who issued it under which action |
//! | `pairing_commitments` | What each completed pairing committed, the owner's proof included |
//! | `pairing_events` | The retained security outbox: one immutable row per completed pairing |
//! | `host_owner` | Whether, and how, this host has an owner |
//! | `owner_confirmations` | The acceptance record: each owner confirmation answered, and the effect that consumed it |
//!
//! Section 10 is why the invitation records are durable even though a candidate's attempt is not.
//! A host restart cancels every unfinished invitation, because nothing can resume an attempt that
//! lived only in memory; the consumed state and the failed-confirmation count survive it, so a
//! restart can neither hand a spent guess back nor reopen an invitation somebody already consumed.
//!
//! # The security outbox
//!
//! Every completed pairing writes one row to `pairing_events` in the transaction that commits the
//! device, so no device exists without its event. The sequence is the outbox's stable cursor and a
//! row never changes after its transaction commits. A consumer reads forward from a cursor with
//! [`InvitationRows::events_after`]. The contract is the one every retained outbox of this host
//! keeps: a row is removed only after every registered consumer has passed it, and none is removed
//! while no consumer is registered, which is the case today. Delivering the event to the owner's
//! devices is the environment attention store's work; this is the source it reads.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kr_pairing::platform::{
    BootIdentity, InvitationRecord, InvitationState, InvitationStore, PairingCommitment,
    TransitionOutcome,
};
use kr_protocol::actor::ActorIngress;
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::Grant;
use kr_protocol::ids::{
    ActionId, ActorId, AttemptId, ConfirmationId, DeviceId, InvitationId, PairingEventSequence,
};
use kr_protocol::invitation::{InviteGrantKind, InviteModeKind, PairingSecurityEvent};
use kr_protocol::pairing::{
    ClientBundle, ConfirmationChannel, DevicePublicKeys, KeyPurpose, Locator,
    OwnerConfirmationProof, OwnerConfirmationRequest, PairingConsumedReason, ProposedGrant,
    RendezvousOrigin,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use rusqlite::{Connection, OptionalExtension as _, params};
use serde::{Deserialize, Serialize};

use super::devices::{DeviceDirectory, DeviceRecord, insert_record};
use super::lifetimes::GrantLifetimes;
use crate::error::{ControllerError, Result};

/// Creates the pairing tables, and records an owner a host upgraded in place already had.
///
/// The owner record is written by the pairing that establishes a host's first owner. A host that
/// paired owner devices before that record existed has an owner all the same, so the migration
/// that creates the table looks once: a device row holding `host.manage`, live or revoked, means
/// this host already has an owner and never reopens the initial bootstrap. A row this host cannot
/// read counts as such a device, because an unreadable record is not evidence that there never was
/// one. It runs only when it creates the table; on every later start the table's own row answers.
///
/// # Errors
///
/// Returns a registry error when the tables cannot be created.
pub fn prepare(directory: &DeviceDirectory) -> Result<()> {
    directory.transaction(|transaction| {
        let had_owner_table = transaction
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'host_owner'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(ControllerError::registry)?
            > 0;
        transaction
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS pairing_invitations (
                     invitation_id BLOB PRIMARY KEY NOT NULL,
                     mode TEXT NOT NULL,
                     locator TEXT,
                     rendezvous_origin TEXT,
                     state TEXT NOT NULL,
                     locked_attempt BLOB,
                     consumed_reason TEXT,
                     failed_confirmations INTEGER NOT NULL,
                     deadline_monotonic_ms INTEGER NOT NULL,
                     boot_identity BLOB NOT NULL,
                     grant_kind TEXT NOT NULL,
                     proposed_grant BLOB NOT NULL,
                     issuing_actor TEXT NOT NULL,
                     issuing_ingress TEXT NOT NULL,
                     issuing_action_id BLOB,
                     mutation_digest BLOB,
                     issued_at_ms INTEGER NOT NULL,
                     confirmation_id BLOB NOT NULL
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS pairing_invitations_action
                     ON pairing_invitations (issuing_actor, issuing_action_id)
                     WHERE issuing_action_id IS NOT NULL;
                 CREATE TABLE IF NOT EXISTS pairing_commitments (
                     invitation_id BLOB PRIMARY KEY NOT NULL,
                     commitment BLOB NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS pairing_events (
                     sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                     invitation_id BLOB NOT NULL UNIQUE,
                     event BLOB NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS host_owner (
                     id INTEGER PRIMARY KEY NOT NULL CHECK (id = 0),
                     how TEXT NOT NULL,
                     device_id BLOB,
                     invitation_id BLOB,
                     established_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS owner_confirmation_requests (
                     actor TEXT NOT NULL,
                     action_id BLOB NOT NULL,
                     mutation_digest BLOB NOT NULL,
                     request BLOB NOT NULL,
                     PRIMARY KEY (actor, action_id)
                 );
                 CREATE TABLE IF NOT EXISTS owner_confirmations (
                     confirmation_id BLOB PRIMARY KEY NOT NULL,
                     action TEXT NOT NULL,
                     action_digest BLOB NOT NULL,
                     request BLOB NOT NULL,
                     channel TEXT NOT NULL,
                     signer_key_id BLOB NOT NULL,
                     answered_at_ms INTEGER NOT NULL,
                     answered_by TEXT NOT NULL,
                     proof BLOB NOT NULL,
                     consumed_at_ms INTEGER,
                     consumed_by TEXT
                 );",
            )
            .map_err(ControllerError::registry)?;
        if !had_owner_table && holds_owner_device(transaction)? {
            transaction
                .execute(
                    "INSERT INTO host_owner (id, how, device_id, invitation_id, established_at_ms)
                     VALUES (0, 'migrated', NULL, NULL, ?1)",
                    params![to_sql(kr_ipc::now_ms().get())],
                )
                .map_err(ControllerError::registry)?;
        }
        Ok(())
    })
}

/// Returns true when the device table holds a device with an owner grant, live or revoked.
fn holds_owner_device(connection: &Connection) -> Result<bool> {
    let mut statement = connection
        .prepare("SELECT grant FROM network_devices")
        .map_err(ControllerError::registry)?;
    let grants = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(ControllerError::registry)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(ControllerError::registry)?;
    Ok(grants.iter().any(|bytes| {
        kr_cbor::from_canonical_slice::<Grant>(bytes, &kr_cbor::Limits::DEFAULT)
            .map_or(true, |grant| grant.permits(ActionRight::HostManage))
    }))
}

/// How this host has an owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOwner {
    /// Its first owner was paired through the local bootstrap.
    FirstOwner {
        /// The owner device.
        device_id: DeviceId,
        /// The invitation it paired through.
        invitation_id: InvitationId,
    },
    /// It already had an owner device when this record was introduced.
    Migrated,
}

/// One owner confirmation as the acceptance record holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acceptance {
    /// When the host accepted the proof.
    pub answered_at_ms: TimestampMs,
    /// When an effect consumed it, once one has.
    pub consumed_at_ms: Option<TimestampMs>,
    /// The channel it arrived through, by its protocol name.
    pub channel: String,
    /// The key identifier of the signer that answered it.
    pub signer_key_id: kr_protocol::scalars::KeyId,
    /// The challenge it answered.
    pub request: OwnerConfirmationRequest,
    /// The caller that completed it, when a caller did. An effect that consumed a proof nobody
    /// completed through this host records none.
    pub answered_by: Option<ActorId>,
    /// The proof itself, exactly as it was accepted.
    pub proof: OwnerConfirmationProof,
}

/// What an invitation was issued as, which the store writes beside kr-pairing's record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssueTerms {
    /// How the invitation is offered.
    pub mode: InviteModeKind,
    /// The rendezvous origin, for a code invitation.
    pub rendezvous_origin: Option<RendezvousOrigin>,
    /// Which rules the proposed grant was checked against.
    pub grant_kind: InviteGrantKind,
    /// The exact rights proposed.
    pub proposed_grant: ProposedGrant,
    /// The owner that issued it.
    pub issuing_actor: ActorId,
    /// How that owner reached the host.
    pub issuing_ingress: ActorIngress,
    /// The action that issued it and the digest of that whole mutation, so a retry is recognised
    /// after a restart without anything secret having been written.
    pub action: Option<(ActionId, Digest256)>,
    /// When it was issued, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
}

/// The check an owner mutation makes immediately before its effect: its connection's registration
/// under the revision it was admitted at, and the deadline it was accepted with.
pub type Admission = Arc<dyn Fn() -> Result<()> + Send + Sync>;

/// The admission of the owner mutation an invitation's next write is made for.
///
/// Set for the length of one call into kr-pairing and asked inside the transaction that call's
/// write takes, after every lock and every wait before it: the owner's own confirmation, the
/// invitation's lock and the database's. A candidate's steps and the restart sweep write with it
/// empty, because no owner mutation is waiting on them.
#[derive(Clone, Default)]
pub struct WriteAdmission(Arc<Mutex<Option<Admission>>>);

impl std::fmt::Debug for WriteAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("WriteAdmission")
            .field(&self.held().is_some())
            .finish()
    }
}

impl WriteAdmission {
    /// Runs `call` with `admission` asked inside every write it makes, and clears it afterwards,
    /// however `call` ends.
    pub fn during<T>(&self, admission: &Admission, call: impl FnOnce() -> T) -> T {
        struct Clear<'a>(&'a WriteAdmission);
        impl Drop for Clear<'_> {
            fn drop(&mut self) {
                *self.0.held() = None;
            }
        }
        *self.held() = Some(Arc::clone(admission));
        let _clear = Clear(self);
        call()
    }

    /// Asks the admission a write is being made under, when one is.
    fn check(&self) -> Result<()> {
        let admission = self.held().clone();
        admission.map_or(Ok(()), |admission| admission())
    }

    fn held(&self) -> MutexGuard<'_, Option<Admission>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One invitation as this host recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationRow {
    /// kr-pairing's record: state, lock, failure count and deadline.
    pub record: InvitationRecord,
    /// What it was issued as.
    pub terms: IssueTerms,
    /// The owner confirmation it was issued under.
    pub confirmation_id: ConfirmationId,
}

/// kr-pairing's commitment as this host stores it.
///
/// Every member is a protocol type already, so the stored form is the canonical encoding of the
/// commitment itself and nothing is reinterpreted on the way back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredCommitment {
    invitation_id: InvitationId,
    attempt_id: AttemptId,
    device_id: DeviceId,
    grant: Grant,
    client_keys: DevicePublicKeys,
    client_bundle: Nullable<ClientBundle>,
    proposed_grant: ProposedGrant,
    verification_value: String,
    owner_confirmation: OwnerConfirmationProof,
    committed_at_ms: TimestampMs,
}

impl StoredCommitment {
    fn of(commitment: &PairingCommitment) -> Self {
        Self {
            invitation_id: commitment.invitation_id,
            attempt_id: commitment.attempt_id,
            device_id: commitment.device_id,
            grant: commitment.grant.clone(),
            client_keys: commitment.client_keys,
            client_bundle: commitment
                .client_bundle
                .clone()
                .map_or_else(Nullable::null, Nullable::some),
            proposed_grant: commitment.proposed_grant.clone(),
            verification_value: commitment.verification_value.clone(),
            owner_confirmation: commitment.owner_confirmation.clone(),
            committed_at_ms: commitment.committed_at_ms,
        }
    }

    fn into_commitment(self) -> PairingCommitment {
        PairingCommitment {
            invitation_id: self.invitation_id,
            attempt_id: self.attempt_id,
            device_id: self.device_id,
            grant: self.grant,
            client_keys: self.client_keys,
            client_bundle: self.client_bundle.0,
            proposed_grant: self.proposed_grant,
            verification_value: self.verification_value,
            owner_confirmation: self.owner_confirmation,
            committed_at_ms: self.committed_at_ms,
        }
    }
}

/// The pairing records, as kr-pairing's [`InvitationStore`].
///
/// A handle carries the terms of the invitation it is about to issue, when it is about to issue
/// one: kr-pairing's `create` hands over its own record and the proof, and the host's own terms
/// travel here so the row is written complete in one statement.
///
/// A handle that issues an invitation also carries that invitation's [`WriteAdmission`]: the
/// admission of the owner mutation its next write is made for, asked inside that write's
/// transaction.
#[derive(Clone, Debug)]
pub struct InvitationRows {
    directory: Arc<DeviceDirectory>,
    lifetimes: Arc<GrantLifetimes>,
    issue: Option<Arc<IssueTerms>>,
    admission: WriteAdmission,
}

impl InvitationRows {
    /// Opens the records in `directory`'s database, whose devices' grants run out as `lifetimes`
    /// decides. [`prepare`] must have run.
    #[must_use]
    pub fn new(directory: Arc<DeviceDirectory>, lifetimes: Arc<GrantLifetimes>) -> Self {
        Self {
            directory,
            lifetimes,
            issue: None,
            admission: WriteAdmission::default(),
        }
    }

    /// Returns a handle that issues one invitation under these terms, with an admission slot of
    /// its own.
    #[must_use]
    pub fn issuing(&self, terms: IssueTerms) -> Self {
        Self {
            directory: Arc::clone(&self.directory),
            lifetimes: Arc::clone(&self.lifetimes),
            issue: Some(Arc::new(terms)),
            admission: WriteAdmission::default(),
        }
    }

    /// Returns the device directory these records commit into.
    #[must_use]
    pub const fn directory(&self) -> &Arc<DeviceDirectory> {
        &self.directory
    }

    /// Returns the grant lifetimes the owner devices behind these records are checked against.
    #[must_use]
    pub const fn lifetimes(&self) -> &Arc<GrantLifetimes> {
        &self.lifetimes
    }

    /// Returns the admission slot of the invitation this handle issues.
    #[must_use]
    pub const fn write_admission(&self) -> &WriteAdmission {
        &self.admission
    }

    /// Returns how this host has an owner, when it has one.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the row cannot be read.
    pub fn host_owner(&self) -> Result<Option<HostOwner>> {
        self.directory
            .with(|connection| {
                connection
                    .query_row(
                        "SELECT how, device_id, invitation_id FROM host_owner WHERE id = 0",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, Option<Vec<u8>>>(1)?,
                                row.get::<_, Option<Vec<u8>>>(2)?,
                            ))
                        },
                    )
                    .optional()
            })?
            .map(|(how, device, invitation)| match how.as_str() {
                "migrated" => Ok(HostOwner::Migrated),
                "first_owner" => Ok(HostOwner::FirstOwner {
                    device_id: DeviceId::new(uuid(device.as_deref())?),
                    invitation_id: InvitationId::new(uuid(invitation.as_deref())?),
                }),
                other => Err(ControllerError::registry(format!(
                    "the host owner record names an unknown kind {other:?}"
                ))),
            })
            .transpose()
    }

    /// Returns one invitation as this host recorded it.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the row cannot be read.
    pub fn row(&self, invitation_id: InvitationId) -> Result<Option<InvitationRow>> {
        self.directory
            .with(|connection| read_row(connection, invitation_id))?
            .map(decode_row)
            .transpose()
    }

    /// Returns the invitation one owner issued under one action, when there is one.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the row cannot be read.
    pub fn row_for_action(
        &self,
        actor: &ActorId,
        action_id: ActionId,
    ) -> Result<Option<InvitationRow>> {
        let invitation = self.directory.with(|connection| {
            connection
                .query_row(
                    "SELECT invitation_id FROM pairing_invitations
                     WHERE issuing_actor = ?1 AND issuing_action_id = ?2",
                    params![actor.as_str(), action_id.get().as_bytes().as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
        })?;
        match invitation {
            Some(bytes) => self.row(InvitationId::new(uuid(Some(&bytes))?)),
            None => Ok(None),
        }
    }

    /// Returns the security event one completed pairing wrote.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the row cannot be read or decoded.
    pub fn event_for(&self, invitation_id: InvitationId) -> Result<Option<PairingSecurityEvent>> {
        self.directory
            .with(|connection| {
                connection
                    .query_row(
                        "SELECT event FROM pairing_events WHERE invitation_id = ?1",
                        params![invitation_id.get().as_bytes().as_slice()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
            })?
            .map(|bytes| decode::<PairingSecurityEvent>(&bytes))
            .transpose()
    }

    /// Returns up to `limit` security events after `cursor`, in order.
    ///
    /// This is the outbox's read for a consumer. It removes nothing.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the rows cannot be read or decoded.
    pub fn events_after(
        &self,
        cursor: Option<PairingEventSequence>,
        limit: usize,
    ) -> Result<Vec<PairingSecurityEvent>> {
        let after = cursor.map_or(0, |cursor| to_sql(cursor.get()));
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = self.directory.with(|connection| {
            let mut statement = connection.prepare(
                "SELECT event FROM pairing_events WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
            )?;
            statement
                .query_map(params![after, limit], |row| row.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        rows.iter().map(|bytes| decode(bytes)).collect()
    }

    /// Returns the challenge one caller's action already asked for, and the digest of that
    /// mutation.
    ///
    /// `owner.confirmation.request` is answered once per action: a retry of the same mutation gets
    /// the challenge it was given, whether or not it is still outstanding, and the same action with
    /// another payload is refused. This is the record that makes that hold across a restart.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the row cannot be read or decoded.
    pub fn requested(
        &self,
        actor: &ActorId,
        action_id: ActionId,
    ) -> Result<Option<(Digest256, OwnerConfirmationRequest)>> {
        self.directory
            .with(|connection| {
                connection
                    .query_row(
                        "SELECT mutation_digest, request FROM owner_confirmation_requests
                         WHERE actor = ?1 AND action_id = ?2",
                        params![actor.as_str(), action_id.get().as_bytes().as_slice()],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
                    )
                    .optional()
            })?
            .map(|(digest, request)| {
                Ok((
                    Digest256::from_bytes(
                        <[u8; 32]>::try_from(digest.as_slice()).map_err(|_| {
                            ControllerError::registry("a mutation digest is 32 bytes")
                        })?,
                    ),
                    decode::<OwnerConfirmationRequest>(&request)?,
                ))
            })
            .transpose()
    }

    /// Records the challenge one caller's action asked for, under that action's admission.
    ///
    /// # Errors
    ///
    /// Returns the admission's refusal, and a registry error when the row cannot be written,
    /// including when the action already has one.
    pub fn record_requested(
        &self,
        actor: &ActorId,
        action_id: ActionId,
        digest: Digest256,
        request: &OwnerConfirmationRequest,
        admission: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let request = encode(request)?;
        self.directory.transaction(|transaction| {
            admission()?;
            transaction
                .execute(
                    "INSERT INTO owner_confirmation_requests
                         (actor, action_id, mutation_digest, request)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        actor.as_str(),
                        action_id.get().as_bytes().as_slice(),
                        digest.as_bytes().as_slice(),
                        request,
                    ],
                )
                .map_err(ControllerError::registry)?;
            Ok(())
        })
    }

    /// Records that an owner confirmation was answered, before anything spends it, under the
    /// admission of the completion that answered it.
    ///
    /// Section 10 makes user-presence verification part of the host's acceptance record, so the
    /// answer is on record from the moment the host accepts the proof, whatever happens next. The
    /// caller that completed it and the proof itself are kept, so a repeat of that completion is
    /// recognised as the same caller's same proof and nothing else.
    ///
    /// # Errors
    ///
    /// Returns the admission's refusal, and a registry error when the row cannot be written.
    pub fn record_answered(
        &self,
        proof: &OwnerConfirmationProof,
        answered_by: &ActorId,
        now: TimestampMs,
        admission: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let request = encode(&proof.request)?;
        let action = text_of(&proof.request.action)?;
        let channel = proof.channel.as_str();
        let stored_proof = encode(proof)?;
        self.directory.transaction(|transaction| {
            admission()?;
            transaction
                .execute(
                    "INSERT INTO owner_confirmations (
                         confirmation_id, action, action_digest, request, channel, signer_key_id,
                         answered_at_ms, answered_by, proof, consumed_at_ms, consumed_by
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL)
                     ON CONFLICT (confirmation_id) DO NOTHING",
                    params![
                        proof.request.confirmation_id.get().as_bytes().as_slice(),
                        action,
                        proof.request.action_digest.as_bytes().as_slice(),
                        request,
                        channel,
                        proof.signer_key_id.as_bytes().as_slice(),
                        to_sql(now.get()),
                        answered_by.as_str(),
                        stored_proof,
                    ],
                )
                .map_err(ControllerError::registry)?;
            Ok(())
        })
    }

    /// Records that an owner confirmation was consumed by `effect`, immediately before the effect.
    ///
    /// For an effect outside these tables. A crash between this and the effect wastes the
    /// confirmation and never leaves an effect without its record.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the row cannot be written, and refuses a confirmation that an
    /// effect already consumed.
    pub fn record_consumed(
        &self,
        proof: &OwnerConfirmationProof,
        effect: &str,
        now: TimestampMs,
    ) -> Result<()> {
        let consumed = self
            .directory
            .transaction(|transaction| consume(transaction, &self.lifetimes, proof, effect, now));
        self.lifetimes.settle();
        consumed
    }

    /// Returns when a confirmation was answered and when it was consumed, as recorded.
    ///
    /// # Errors
    ///
    /// Returns a registry error when the row cannot be read.
    pub fn acceptance(&self, confirmation_id: ConfirmationId) -> Result<Option<Acceptance>> {
        let row = self.directory.with(|connection| {
            connection
                .query_row(
                    "SELECT answered_at_ms, consumed_at_ms, channel, signer_key_id, request,
                            answered_by, proof
                     FROM owner_confirmations WHERE confirmation_id = ?1",
                    params![confirmation_id.get().as_bytes().as_slice()],
                    |row| {
                        Ok((
                            TimestampMs::new(from_sql(row.get::<_, i64>(0)?)),
                            row.get::<_, Option<i64>>(1)?
                                .map(|at| TimestampMs::new(from_sql(at))),
                            row.get::<_, String>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                        ))
                    },
                )
                .optional()
        })?;
        row.map(
            |(answered_at_ms, consumed_at_ms, channel, signer, request, answered_by, proof)| {
                Ok(Acceptance {
                    answered_at_ms,
                    consumed_at_ms,
                    channel,
                    signer_key_id: kr_protocol::scalars::KeyId::from_bytes(
                        <[u8; 32]>::try_from(signer.as_slice()).map_err(|_| {
                            ControllerError::registry("a key identifier is 32 bytes")
                        })?,
                    ),
                    request: decode(&request)?,
                    answered_by: if answered_by.is_empty() {
                        None
                    } else {
                        Some(ActorId::new(answered_by).map_err(ControllerError::registry)?)
                    },
                    proof: decode(&proof)?,
                })
            },
        )
        .transpose()
    }
}

impl InvitationStore for InvitationRows {
    fn create(
        &self,
        record: &InvitationRecord,
        issued_under: &OwnerConfirmationProof,
    ) -> kr_pairing::Result<()> {
        let terms = self
            .issue
            .as_deref()
            .ok_or_else(|| kr_pairing::PairingError::Store {
                reason: "an invitation is issued through a handle that carries its terms"
                    .to_owned(),
            })?;
        let effect = format!("pair.invite {}", record.invitation_id);
        let created = self.directory.transaction(|transaction| {
            self.admission.check()?;
            insert_invitation(transaction, record, terms, issued_under)?;
            consume(
                transaction,
                &self.lifetimes,
                issued_under,
                &effect,
                terms.issued_at_ms,
            )
        });
        self.lifetimes.settle();
        created.map_err(store_error)
    }

    fn load(&self, invitation_id: InvitationId) -> kr_pairing::Result<Option<InvitationRecord>> {
        self.row(invitation_id)
            .map(|row| row.map(|row| row.record))
            .map_err(store_error)
    }

    fn transition(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
    ) -> kr_pairing::Result<TransitionOutcome> {
        self.directory
            .transaction(|transaction| {
                self.admission.check()?;
                let current = read_record(transaction, expected.invitation_id)?
                    .ok_or_else(|| ControllerError::registry("that invitation has no record"))?;
                if &current != expected {
                    return Ok(TransitionOutcome::Stale(current));
                }
                write_record(transaction, next)?;
                Ok(TransitionOutcome::Written)
            })
            .or_else(unwritten)
    }

    fn commit(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
        commitment: &PairingCommitment,
    ) -> kr_pairing::Result<TransitionOutcome> {
        let committed = self.directory.transaction(|transaction| {
            self.admission.check()?;
            commit_pairing(transaction, &self.lifetimes, expected, next, commitment)
        });
        self.lifetimes.settle();
        committed.or_else(unwritten)
    }

    fn commitment(
        &self,
        invitation_id: InvitationId,
    ) -> kr_pairing::Result<Option<PairingCommitment>> {
        self.directory
            .with(|connection| {
                connection
                    .query_row(
                        "SELECT commitment FROM pairing_commitments WHERE invitation_id = ?1",
                        params![invitation_id.get().as_bytes().as_slice()],
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .optional()
            })
            .and_then(|bytes| {
                bytes
                    .map(|bytes| {
                        decode::<StoredCommitment>(&bytes).map(StoredCommitment::into_commitment)
                    })
                    .transpose()
            })
            .map_err(store_error)
    }

    fn unfinished(&self) -> kr_pairing::Result<Vec<InvitationRecord>> {
        let ids = self
            .directory
            .with(|connection| {
                let mut statement = connection.prepare(
                    "SELECT invitation_id FROM pairing_invitations
                     WHERE state IN ('open', 'locked') ORDER BY issued_at_ms",
                )?;
                statement
                    .query_map([], |row| row.get::<_, Vec<u8>>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .map_err(store_error)?;
        let mut records = Vec::with_capacity(ids.len());
        for bytes in ids {
            let invitation_id = InvitationId::new(uuid(Some(&bytes)).map_err(store_error)?);
            if let Some(record) = self.load(invitation_id)? {
                records.push(record);
            }
        }
        Ok(records)
    }
}

/// Commits one pairing: everything section 10 writes together, or nothing.
fn commit_pairing(
    transaction: &Connection,
    lifetimes: &GrantLifetimes,
    expected: &InvitationRecord,
    next: &InvitationRecord,
    commitment: &PairingCommitment,
) -> Result<TransitionOutcome> {
    let current = read_record(transaction, expected.invitation_id)?
        .ok_or_else(|| ControllerError::registry("that invitation has no record"))?;
    if &current != expected {
        return Ok(TransitionOutcome::Stale(current));
    }
    let row = read_row(transaction, expected.invitation_id)
        .map_err(ControllerError::registry)?
        .map(decode_row)
        .transpose()?
        .ok_or_else(|| ControllerError::registry("that invitation has no record"))?;
    // A host with no owner commits exactly one kind of pairing: the one that establishes its first
    // owner, a device holding host management. That is what the initial bootstrap is for and all
    // it is for, and the owner record is written with the device, so the host is never paired to
    // its first owner device without the record that ends the bootstrap.
    let first_owner = transaction
        .query_row("SELECT COUNT(*) FROM host_owner WHERE id = 0", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(ControllerError::registry)?
        == 0;
    if first_owner && !commitment.grant.permits(ActionRight::HostManage) {
        return Err(ControllerError::PermissionDenied {
            detail:
                "a host with no owner commits only the pairing that establishes its first owner"
                    .to_owned(),
        });
    }

    // The confirmation is spent, and its signer's authority read, before the candidate's own row
    // exists: a candidate presenting the signer's key must not be what makes that signer look like
    // an owner device.
    consume(
        transaction,
        lifetimes,
        &commitment.owner_confirmation,
        &format!("pair.confirm {}", commitment.invitation_id),
        commitment.committed_at_ms,
    )?;
    let record = device_record(commitment).map_err(ControllerError::registry)?;
    insert_record(transaction, &record)?;
    transaction
        .execute(
            "INSERT INTO pairing_commitments (invitation_id, commitment) VALUES (?1, ?2)",
            params![
                commitment.invitation_id.get().as_bytes().as_slice(),
                encode(&StoredCommitment::of(commitment))?,
            ],
        )
        .map_err(ControllerError::registry)?;
    if first_owner {
        transaction
            .execute(
                "INSERT INTO host_owner (id, how, device_id, invitation_id, established_at_ms)
                 VALUES (0, 'first_owner', ?1, ?2, ?3)",
                params![
                    commitment.device_id.get().as_bytes().as_slice(),
                    commitment.invitation_id.get().as_bytes().as_slice(),
                    to_sql(commitment.committed_at_ms.get()),
                ],
            )
            .map_err(ControllerError::registry)?;
    }

    // The event row takes its sequence from the table, and the event carries it, so the row is
    // inserted and then completed inside this same transaction. Nothing reads it before the
    // transaction commits, and nothing changes it afterwards.
    transaction
        .execute(
            "INSERT INTO pairing_events (invitation_id, event, recorded_at_ms) VALUES (?1, x'', ?2)",
            params![
                commitment.invitation_id.get().as_bytes().as_slice(),
                to_sql(commitment.committed_at_ms.get()),
            ],
        )
        .map_err(ControllerError::registry)?;
    let sequence = PairingEventSequence::new(from_sql(transaction.last_insert_rowid()));
    let bundle = commitment.client_bundle.as_ref().ok_or_else(|| {
        ControllerError::registry("a committed pairing carries the candidate's declaration")
    })?;
    let event = PairingSecurityEvent {
        sequence,
        invitation_id: commitment.invitation_id,
        mode: row.terms.mode,
        device_id: commitment.device_id,
        grant_id: commitment.grant.grant_id,
        grant_kind: row.terms.grant_kind,
        device_name: bundle.device_name.clone(),
        platform: bundle.platform,
        verification_value: commitment.verification_value.clone(),
        confirmation_id: commitment.owner_confirmation.request.confirmation_id,
        channel: commitment.owner_confirmation.channel,
        signer_key_id: commitment.owner_confirmation.signer_key_id,
        first_owner,
        committed_at_ms: commitment.committed_at_ms,
    };
    transaction
        .execute(
            "UPDATE pairing_events SET event = ?1 WHERE sequence = ?2",
            params![encode(&event)?, to_sql(sequence.get())],
        )
        .map_err(ControllerError::registry)?;
    write_record(transaction, next)?;
    Ok(TransitionOutcome::Written)
}

/// Records a confirmation's consumption inside the caller's transaction.
///
/// The row is written whole when `complete` never recorded the answer, so the acceptance record
/// holds every confirmation an effect consumed. A confirmation some effect already consumed is
/// refused: one ceremony authorises one action.
fn consume(
    transaction: &Connection,
    lifetimes: &GrantLifetimes,
    proof: &OwnerConfirmationProof,
    effect: &str,
    now: TimestampMs,
) -> Result<()> {
    signer_still_authorised(transaction, lifetimes, proof)?;
    let request = encode(&proof.request)?;
    let action = text_of(&proof.request.action)?;
    let changed = transaction
        .execute(
            "INSERT INTO owner_confirmations (
                 confirmation_id, action, action_digest, request, channel, signer_key_id,
                 answered_at_ms, answered_by, proof, consumed_at_ms, consumed_by
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', ?8, ?7, ?9)
             ON CONFLICT (confirmation_id) DO UPDATE
                 SET consumed_at_ms = excluded.consumed_at_ms,
                     consumed_by = excluded.consumed_by
                 WHERE consumed_at_ms IS NULL",
            params![
                proof.request.confirmation_id.get().as_bytes().as_slice(),
                action,
                proof.request.action_digest.as_bytes().as_slice(),
                request,
                proof.channel.as_str(),
                proof.signer_key_id.as_bytes().as_slice(),
                to_sql(now.get()),
                encode(proof)?,
                effect,
            ],
        )
        .map_err(ControllerError::registry)?;
    if changed == 0 {
        return Err(ControllerError::PermissionDenied {
            detail: "that owner confirmation has already been spent".to_owned(),
        });
    }
    Ok(())
}

/// Checks, inside the consuming transaction, that the confirmation's signer still has the authority
/// it answered with.
///
/// An answer is accepted when it arrives and spent later, and authority can change in between: the
/// owner device that answered can be revoked, or its grant can run out, and the first owner can be
/// established by another pairing. Revocation, expiry tombstones and the owner record are written
/// to this same database, so reading them here, in the transaction that records the effect, is the
/// boundary they share: an effect commits only under the authority standing at that moment. A grant
/// that expires is judged by the deadline the host time contract anchored for it, against the
/// continuous clock read now, after every wait before this transaction.
fn signer_still_authorised(
    transaction: &Connection,
    lifetimes: &GrantLifetimes,
    proof: &OwnerConfirmationProof,
) -> Result<()> {
    let lapsed = |detail: &str| ControllerError::Refused {
        code: ErrorCode::OwnerConfirmationRequired,
        detail: detail.to_owned(),
    };
    match proof.channel {
        ConfirmationChannel::LocalBootstrapTerminal => {
            let owned = transaction
                .query_row("SELECT COUNT(*) FROM host_owner WHERE id = 0", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(ControllerError::registry)?
                > 0;
            if owned {
                return Err(lapsed(
                    "this host has an owner, so the terminal bootstrap no longer confirms anything",
                ));
            }
            Ok(())
        }
        ConfirmationChannel::OwnerDevicePresence | ConfirmationChannel::PairedOwnerDevice => {
            let mut statement = transaction
                .prepare(
                    "SELECT device_id, authorisation_key, grant FROM network_devices
                     WHERE revoked_at_ms IS NULL AND expired_at_ms IS NULL",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(ControllerError::registry)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(ControllerError::registry)?;
            let standing = rows.iter().any(|(device_id, key, grant)| {
                let signed = <[u8; 32]>::try_from(key.as_slice()).is_ok_and(|key| {
                    kr_crypto::keys::key_id(KeyPurpose::Authorisation, &key) == proof.signer_key_id
                });
                signed
                    && uuid(Some(device_id)).is_ok_and(|device_id| {
                        decode::<Grant>(grant).is_ok_and(|grant| {
                            grant.permits(ActionRight::HostManage)
                                && lifetimes.in_force_now(DeviceId::new(device_id), grant.expiry)
                        })
                    })
            });
            if !standing {
                return Err(lapsed(
                    "the device that answered this confirmation is no longer an owner device of \
                     this host",
                ));
            }
            Ok(())
        }
        ConfirmationChannel::EnrolledPresenceSigner
        | ConfirmationChannel::Session
        | ConfirmationChannel::Plugin
        | ConfirmationChannel::ContactTool => Err(lapsed(
            "that channel carries no owner confirmation on this host",
        )),
    }
}

/// Returns the device record one completed pairing writes.
///
/// Every field comes from the commitment: the endpoint identity the candidate proved, the four keys
/// its transcript bound, the grant the host issued and the display members it declared. Nothing
/// here is taken from what the candidate asked for.
///
/// # Errors
///
/// Returns a reason when the commitment carries no candidate declaration.
pub fn device_record(commitment: &PairingCommitment) -> std::result::Result<DeviceRecord, String> {
    let bundle = commitment
        .client_bundle
        .as_ref()
        .ok_or_else(|| "a committed pairing carries the candidate's declaration".to_owned())?;
    Ok(DeviceRecord {
        device_id: commitment.device_id,
        endpoint_id: commitment.client_keys.transport,
        device_key_revision: bundle.device_key_revision,
        authorisation: commitment.client_keys.authorisation,
        // All four keys the owner-approved exchange bound, so another device can seal to this one
        // through this host's report of it rather than through anything the device says later.
        stored_envelope: Some(commitment.client_keys.stored_envelope),
        notification_preview: Some(commitment.client_keys.notification_preview),
        device_name: bundle.device_name.clone(),
        platform: bundle.platform,
        grant: commitment.grant.clone(),
        paired_at_ms: commitment.committed_at_ms,
        revoked_at_ms: None,
        expired_at_ms: None,
        committed_invitation_id: Some(commitment.invitation_id),
    })
}

/// The raw row, as the columns hold it.
struct RawRow {
    invitation_id: Vec<u8>,
    mode: String,
    locator: Option<String>,
    rendezvous_origin: Option<String>,
    state: String,
    locked_attempt: Option<Vec<u8>>,
    consumed_reason: Option<String>,
    failed_confirmations: i64,
    deadline_monotonic_ms: i64,
    boot_identity: Vec<u8>,
    grant_kind: String,
    proposed_grant: Vec<u8>,
    issuing_actor: String,
    issuing_ingress: String,
    issuing_action_id: Option<Vec<u8>>,
    mutation_digest: Option<Vec<u8>>,
    issued_at_ms: i64,
    confirmation_id: Vec<u8>,
}

fn read_row(
    connection: &Connection,
    invitation_id: InvitationId,
) -> rusqlite::Result<Option<RawRow>> {
    connection
        .query_row(
            "SELECT invitation_id, mode, locator, rendezvous_origin, state, locked_attempt,
                    consumed_reason, failed_confirmations, deadline_monotonic_ms, boot_identity,
                    grant_kind, proposed_grant, issuing_actor, issuing_ingress, issuing_action_id,
                    mutation_digest, issued_at_ms, confirmation_id
             FROM pairing_invitations WHERE invitation_id = ?1",
            params![invitation_id.get().as_bytes().as_slice()],
            |row| {
                Ok(RawRow {
                    invitation_id: row.get(0)?,
                    mode: row.get(1)?,
                    locator: row.get(2)?,
                    rendezvous_origin: row.get(3)?,
                    state: row.get(4)?,
                    locked_attempt: row.get(5)?,
                    consumed_reason: row.get(6)?,
                    failed_confirmations: row.get(7)?,
                    deadline_monotonic_ms: row.get(8)?,
                    boot_identity: row.get(9)?,
                    grant_kind: row.get(10)?,
                    proposed_grant: row.get(11)?,
                    issuing_actor: row.get(12)?,
                    issuing_ingress: row.get(13)?,
                    issuing_action_id: row.get(14)?,
                    mutation_digest: row.get(15)?,
                    issued_at_ms: row.get(16)?,
                    confirmation_id: row.get(17)?,
                })
            },
        )
        .optional()
}

fn read_record(
    connection: &Connection,
    invitation_id: InvitationId,
) -> Result<Option<InvitationRecord>> {
    read_row(connection, invitation_id)
        .map_err(ControllerError::registry)?
        .map(|raw| decode_record(&raw))
        .transpose()
}

fn decode_record(raw: &RawRow) -> Result<InvitationRecord> {
    let state = match raw.state.as_str() {
        "open" => InvitationState::Open,
        "locked" => InvitationState::Locked {
            attempt_id: AttemptId::new(uuid(raw.locked_attempt.as_deref())?),
        },
        "committed" => InvitationState::Committed,
        "consumed" => InvitationState::Consumed {
            reason: reason_from(raw.consumed_reason.as_deref())?,
        },
        other => {
            return Err(ControllerError::registry(format!(
                "an invitation record names an unknown state {other:?}"
            )));
        }
    };
    Ok(InvitationRecord {
        invitation_id: InvitationId::new(uuid(Some(&raw.invitation_id))?),
        locator: raw
            .locator
            .as_deref()
            .map(Locator::new)
            .transpose()
            .map_err(ControllerError::registry)?,
        state,
        failed_confirmations: u32::try_from(raw.failed_confirmations)
            .map_err(ControllerError::registry)?,
        deadline_monotonic_ms: from_sql(raw.deadline_monotonic_ms),
        boot_identity: BootIdentity(
            <[u8; 32]>::try_from(raw.boot_identity.as_slice())
                .map_err(|_| ControllerError::registry("a boot identity is 32 bytes"))?,
        ),
    })
}

fn decode_row(raw: RawRow) -> Result<InvitationRow> {
    let record = decode_record(&raw)?;
    let action = match (
        raw.issuing_action_id.as_deref(),
        raw.mutation_digest.as_deref(),
    ) {
        (Some(action), Some(digest)) => Some((
            ActionId::new(uuid(Some(action))?),
            Digest256::from_bytes(
                <[u8; 32]>::try_from(digest)
                    .map_err(|_| ControllerError::registry("a parameter digest is 32 bytes"))?,
            ),
        )),
        _ => None,
    };
    Ok(InvitationRow {
        record,
        terms: IssueTerms {
            mode: from_text(&raw.mode)?,
            rendezvous_origin: raw
                .rendezvous_origin
                .as_deref()
                .map(RendezvousOrigin::new)
                .transpose()
                .map_err(ControllerError::registry)?,
            grant_kind: from_text(&raw.grant_kind)?,
            proposed_grant: decode(&raw.proposed_grant)?,
            issuing_actor: ActorId::new(raw.issuing_actor).map_err(ControllerError::registry)?,
            issuing_ingress: from_text(&raw.issuing_ingress)?,
            action,
            issued_at_ms: TimestampMs::new(from_sql(raw.issued_at_ms)),
        },
        confirmation_id: ConfirmationId::new(uuid(Some(&raw.confirmation_id))?),
    })
}

fn insert_invitation(
    connection: &Connection,
    record: &InvitationRecord,
    terms: &IssueTerms,
    issued_under: &OwnerConfirmationProof,
) -> Result<()> {
    let StateColumns {
        state,
        locked,
        reason,
    } = state_columns(record.state)?;
    connection
        .execute(
            "INSERT INTO pairing_invitations (
                 invitation_id, mode, locator, rendezvous_origin, state, locked_attempt,
                 consumed_reason, failed_confirmations, deadline_monotonic_ms, boot_identity,
                 grant_kind, proposed_grant, issuing_actor, issuing_ingress, issuing_action_id,
                 mutation_digest, issued_at_ms, confirmation_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                       ?18)",
            params![
                record.invitation_id.get().as_bytes().as_slice(),
                text_of(&terms.mode)?,
                record.locator.as_ref().map(Locator::as_str),
                terms
                    .rendezvous_origin
                    .as_ref()
                    .map(RendezvousOrigin::as_str),
                state,
                locked,
                reason,
                i64::from(record.failed_confirmations),
                to_sql(record.deadline_monotonic_ms),
                record.boot_identity.0.as_slice(),
                text_of(&terms.grant_kind)?,
                encode(&terms.proposed_grant)?,
                terms.issuing_actor.as_str(),
                text_of(&terms.issuing_ingress)?,
                terms
                    .action
                    .map(|(action, _)| action.get().as_bytes().to_vec()),
                terms.action.map(|(_, digest)| digest.as_bytes().to_vec()),
                to_sql(terms.issued_at_ms.get()),
                issued_under
                    .request
                    .confirmation_id
                    .get()
                    .as_bytes()
                    .as_slice(),
            ],
        )
        .map(|_| ())
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                ControllerError::registry(
                    "that invitation, or an invitation for that action, already exists",
                )
            }
            other => ControllerError::registry(other),
        })
}

fn write_record(connection: &Connection, record: &InvitationRecord) -> Result<()> {
    let StateColumns {
        state,
        locked,
        reason,
    } = state_columns(record.state)?;
    let changed = connection
        .execute(
            "UPDATE pairing_invitations
             SET locator = ?2, state = ?3, locked_attempt = ?4, consumed_reason = ?5,
                 failed_confirmations = ?6, deadline_monotonic_ms = ?7, boot_identity = ?8
             WHERE invitation_id = ?1",
            params![
                record.invitation_id.get().as_bytes().as_slice(),
                record.locator.as_ref().map(Locator::as_str),
                state,
                locked,
                reason,
                i64::from(record.failed_confirmations),
                to_sql(record.deadline_monotonic_ms),
                record.boot_identity.0.as_slice(),
            ],
        )
        .map_err(ControllerError::registry)?;
    if changed != 1 {
        return Err(ControllerError::registry("that invitation has no record"));
    }
    Ok(())
}

/// An invitation state as its three columns hold it.
struct StateColumns {
    state: &'static str,
    locked: Option<Vec<u8>>,
    reason: Option<String>,
}

fn state_columns(state: InvitationState) -> Result<StateColumns> {
    let (state, locked, reason) = match state {
        InvitationState::Open => ("open", None, None),
        InvitationState::Locked { attempt_id } => {
            ("locked", Some(attempt_id.get().as_bytes().to_vec()), None)
        }
        InvitationState::Committed => ("committed", None, None),
        InvitationState::Consumed { reason } => ("consumed", None, Some(text_of(&reason)?)),
    };
    Ok(StateColumns {
        state,
        locked,
        reason,
    })
}

fn reason_from(text: Option<&str>) -> Result<PairingConsumedReason> {
    let text =
        text.ok_or_else(|| ControllerError::registry("a consumed invitation has a reason"))?;
    from_text(text)
}

/// Returns the snake-case name serde gives a unit variant, which is how the enums are stored.
fn text_of<T: Serialize>(value: &T) -> Result<String> {
    match serde_json::to_value(value).map_err(ControllerError::registry)? {
        serde_json::Value::String(text) => Ok(text),
        other => Err(ControllerError::registry(format!(
            "{other} is not stored as a name"
        ))),
    }
}

fn from_text<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|_| ControllerError::registry(format!("{text:?} is not a name this host stores")))
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    kr_cbor::to_canonical_vec(value).map_err(ControllerError::registry)
}

fn decode<T: Serialize + serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    kr_cbor::from_canonical_slice(bytes, &kr_cbor::Limits::DEFAULT)
        .map_err(ControllerError::registry)
}

fn uuid(bytes: Option<&[u8]>) -> Result<Uuid> {
    let bytes = bytes.ok_or_else(|| ControllerError::registry("an identifier is missing"))?;
    Ok(Uuid::from_bytes(<[u8; 16]>::try_from(bytes).map_err(
        |_| ControllerError::registry("an identifier is 16 bytes"),
    )?))
}

/// SQLite integers are signed. Every value stored here is a millisecond count or a counter well
/// below `i64::MAX`, and saturating keeps an impossible one impossible rather than negative.
fn to_sql(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn from_sql(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// Returns true when a store error is the store's own decision not to write, rather than a
/// failure.
///
/// Every error raised inside a transaction rolls it back, so nothing was written either way. What
/// differs is what kr-pairing may conclude: a refusal (the mutation's admission lapsed, the
/// confirmation's signer is no longer an owner device, a host with no owner refusing anything but
/// its first owner, a confirmation already spent) is a decision, and the invitation serves its
/// next step; a failure is a write whose outcome nobody knows, and kr-pairing fences the invitation
/// for it.
const fn is_refusal(error: &ControllerError) -> bool {
    matches!(
        error,
        ControllerError::PermissionDenied { .. }
            | ControllerError::WindowExpired { .. }
            | ControllerError::Refused { .. }
    )
}

/// Returns kr-pairing's view of a store error, under the code the host reports it with.
///
/// A confirmation whose authority lapsed before its effect committed is refused as what it is,
/// so the caller is told to confirm again rather than that storage failed.
fn store_error(error: ControllerError) -> kr_pairing::PairingError {
    if !is_refusal(&error) {
        return kr_pairing::PairingError::Store {
            reason: error.to_string(),
        };
    }
    if error.code() == ErrorCode::OwnerConfirmationRequired {
        return kr_pairing::PairingError::OwnerConfirmationRequired;
    }
    kr_pairing::PairingError::Refused {
        code: error.code(),
        reason: error.to_string(),
    }
}

/// Returns what a conditional write that wrote nothing reports: a refusal, or a failure.
fn unwritten(error: ControllerError) -> kr_pairing::Result<TransitionOutcome> {
    if is_refusal(&error) {
        Ok(TransitionOutcome::Refused(store_error(error)))
    } else {
        Err(store_error(error))
    }
}

/// Converts kr-pairing's own store failure back into the daemon's.
#[must_use]
pub fn from_store_failure(error: &kr_pairing::PairingError) -> ControllerError {
    ControllerError::registry(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_consumed_reason_is_stored_under_its_protocol_name() {
        assert_eq!(
            text_of(&PairingConsumedReason::HostRestarted).expect("a name"),
            "host_restarted"
        );
        assert_eq!(
            from_text::<PairingConsumedReason>("attempts_exhausted").expect("a reason"),
            PairingConsumedReason::AttemptsExhausted
        );
        assert!(from_text::<PairingConsumedReason>("forgotten").is_err());
        assert_eq!(
            text_of(&ActorIngress::LocalIpc).expect("a name"),
            "local_ipc"
        );
        assert_eq!(text_of(&InviteModeKind::Code).expect("a name"), "code");
        assert_eq!(
            text_of(&ConfirmationChannel::LocalBootstrapTerminal).expect("a name"),
            ConfirmationChannel::LocalBootstrapTerminal.as_str()
        );
    }
}
