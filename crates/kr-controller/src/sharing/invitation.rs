//! Single-use expiring invitations, and the preview their issuer accepted.
//!
//! Section 25: "Invitations are single-use, expire, and cannot grant rights beyond their issuer. A
//! shared live screen can contain text printed before the invitation; the preview must show what
//! is being shared. New grant recipients do not receive all historical attachment keys
//! automatically."
//!
//! Four properties, and each one is a column rather than a convention:
//!
//! * **Single use.** [`InvitationLedger::redeem`] moves the row from `open` to `redeemed` in one
//!   statement and records which device did it. A second redemption finds the row redeemed,
//!   whichever device asks, so two devices racing the same invitation produce one grant.
//! * **Expiring.** A redemption after the deadline is refused and the row becomes `expired`. The
//!   deadline is the invitation's own, not the grant's; a grant whose invitation was never
//!   redeemed belongs to nobody.
//! * **Never beyond the issuer.** The grant the invitation carries was already checked against the
//!   issuer's own grant in [`super::roles::check_delegation`]. What this ledger adds is that the
//!   *preview* the issuer accepted is kept, so what a recipient receives can be compared with what
//!   the issuer was shown.
//! * **No historical attachment keys.** [`InvitationPreview::historical_attachment_keys`] is
//!   written `false` and checked on the way out. A recipient that needs an old attachment asks for
//!   it under its own file grant, and the wrap is made then.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use kr_protocol::ids::{DeviceId, InvitationId};
use kr_protocol::sharing::{InvitationPreview, InvitationState};

use crate::error::{ControllerError, Result};

/// One invitation as the ledger holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationRecord {
    /// What the issuer was shown and accepted.
    pub preview: InvitationPreview,
    /// The device that issued it.
    pub issuer_device_id: DeviceId,
    /// Where it is in its life.
    pub state: InvitationState,
    /// The device that redeemed it, when one has.
    pub redeemed_by: Option<DeviceId>,
    /// When it was issued, in UTC milliseconds.
    pub issued_at_ms: u64,
}

impl InvitationRecord {
    /// Where this invitation stands at `now_ms`, taking the deadline into account.
    #[must_use]
    pub fn state_at(&self, now_ms: u64) -> InvitationState {
        match self.state {
            InvitationState::Open if now_ms >= self.preview.expires_at_ms.get() => {
                InvitationState::Expired
            }
            other => other,
        }
    }
}

/// The host's invitations.
#[derive(Debug)]
pub struct InvitationLedger {
    connection: std::sync::Mutex<Connection>,
}

impl InvitationLedger {
    /// Opens the ledger in the daemon's registry database, creating its table.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be opened or migrated.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).map_err(ControllerError::registry)?;
        Self::prepare(connection)
    }

    /// Opens an in-memory ledger, which is what a test uses.
    ///
    /// # Errors
    ///
    /// Returns an error when the table cannot be created.
    pub fn in_memory() -> Result<Self> {
        Self::prepare(Connection::open_in_memory().map_err(ControllerError::registry)?)
    }

    fn prepare(connection: Connection) -> Result<Self> {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ControllerError::registry)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ControllerError::registry)?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS session_invitations (
                     invitation_id    BLOB PRIMARY KEY NOT NULL,
                     issuer_device_id BLOB NOT NULL,
                     preview          BLOB NOT NULL,
                     state            TEXT NOT NULL,
                     redeemed_by      BLOB,
                     issued_at_ms     INTEGER NOT NULL,
                     expires_at_ms    INTEGER NOT NULL
                 );",
            )
            .map_err(ControllerError::registry)?;
        Ok(Self {
            connection: std::sync::Mutex::new(connection),
        })
    }

    fn with<T>(&self, body: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        body(&connection).map_err(ControllerError::registry)
    }

    /// Records an invitation and the preview its issuer accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the preview promises historical
    /// attachment keys or is not single use, and when the identity is already in use.
    pub fn issue(
        &self,
        preview: &InvitationPreview,
        issuer_device_id: DeviceId,
        now_ms: u64,
    ) -> Result<()> {
        if preview.historical_attachment_keys {
            return Err(ControllerError::InvalidArgument(
                "a new recipient does not receive historical attachment keys".to_owned(),
            ));
        }
        if !preview.single_use {
            return Err(ControllerError::InvalidArgument(
                "a session invitation is redeemed once".to_owned(),
            ));
        }
        if preview.expires_at_ms.get() <= now_ms {
            return Err(ControllerError::InvalidArgument(
                "a session invitation expires in the future".to_owned(),
            ));
        }
        let encoded = kr_cbor::to_canonical_vec(preview)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let written = self.with(|connection| {
            connection.execute(
                "INSERT OR IGNORE INTO session_invitations (
                     invitation_id, issuer_device_id, preview, state, redeemed_by,
                     issued_at_ms, expires_at_ms
                 ) VALUES (?1, ?2, ?3, 'open', NULL, ?4, ?5)",
                params![
                    preview.invitation_id.get().as_bytes().as_slice(),
                    issuer_device_id.get().as_bytes().as_slice(),
                    encoded,
                    i64::try_from(now_ms).unwrap_or(i64::MAX),
                    i64::try_from(preview.expires_at_ms.get()).unwrap_or(i64::MAX),
                ],
            )
        })?;
        if written == 0 {
            return Err(ControllerError::InvalidArgument(
                "that invitation identity is already in use".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns one invitation's record.
    ///
    /// # Errors
    ///
    /// Returns an error when the row cannot be read.
    pub fn record(&self, invitation_id: InvitationId) -> Result<Option<InvitationRecord>> {
        let key = invitation_id.get().as_bytes().to_vec();
        let row: Option<Result<InvitationRecord>> = self.with(|connection| {
            connection
                .query_row(
                    "SELECT preview, issuer_device_id, state, redeemed_by, issued_at_ms
                     FROM session_invitations WHERE invitation_id = ?1",
                    params![key],
                    |row| Ok(read_row(row)),
                )
                .optional()
        })?;
        row.transpose()
    }

    /// Redeems an invitation, once.
    ///
    /// The state change and the redeeming device are written in one statement whose `WHERE` clause
    /// carries the whole precondition, so a second redemption changes no row and is told so. Two
    /// devices arriving at the same moment therefore produce one grant and one refusal, rather
    /// than two grants from one invitation.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when there is no such invitation, and
    /// [`ControllerError::PermissionDenied`] when it has expired, been cancelled, or already been
    /// redeemed.
    pub fn redeem(
        &self,
        invitation_id: InvitationId,
        device_id: DeviceId,
        now_ms: u64,
    ) -> Result<InvitationRecord> {
        let Some(record) = self.record(invitation_id)? else {
            return Err(ControllerError::InvalidArgument(
                "this host holds no such invitation".to_owned(),
            ));
        };
        match record.state_at(now_ms) {
            InvitationState::Open => {}
            InvitationState::Redeemed => {
                return Err(ControllerError::PermissionDenied {
                    detail: "this invitation has already been redeemed".to_owned(),
                });
            }
            InvitationState::Cancelled => {
                return Err(ControllerError::PermissionDenied {
                    detail: "this invitation was withdrawn".to_owned(),
                });
            }
            InvitationState::Expired => {
                self.settle(invitation_id, InvitationState::Expired)?;
                return Err(ControllerError::PermissionDenied {
                    detail: "this invitation has expired".to_owned(),
                });
            }
        }
        let changed = self.with(|connection| {
            connection.execute(
                "UPDATE session_invitations
                    SET state = 'redeemed', redeemed_by = ?2
                  WHERE invitation_id = ?1 AND state = 'open' AND expires_at_ms > ?3",
                params![
                    invitation_id.get().as_bytes().as_slice(),
                    device_id.get().as_bytes().as_slice(),
                    i64::try_from(now_ms).unwrap_or(i64::MAX),
                ],
            )
        })?;
        if changed == 0 {
            return Err(ControllerError::PermissionDenied {
                detail: "this invitation has already been redeemed".to_owned(),
            });
        }
        self.record(invitation_id)?.ok_or_else(|| {
            ControllerError::InvalidArgument("this host holds no such invitation".to_owned())
        })
    }

    /// Withdraws an invitation before anybody redeems it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when it has already been redeemed.
    pub fn cancel(&self, invitation_id: InvitationId) -> Result<()> {
        let changed = self.with(|connection| {
            connection.execute(
                "UPDATE session_invitations SET state = 'cancelled'
                  WHERE invitation_id = ?1 AND state = 'open'",
                params![invitation_id.get().as_bytes().as_slice()],
            )
        })?;
        if changed == 0 {
            return Err(ControllerError::PermissionDenied {
                detail: "this invitation is no longer open".to_owned(),
            });
        }
        Ok(())
    }

    fn settle(&self, invitation_id: InvitationId, state: InvitationState) -> Result<()> {
        self.with(|connection| {
            connection
                .execute(
                    "UPDATE session_invitations SET state = ?2
                      WHERE invitation_id = ?1 AND state = 'open'",
                    params![invitation_id.get().as_bytes().as_slice(), state.as_str()],
                )
                .map(|_| ())
        })
    }
}

fn read_row(row: &rusqlite::Row<'_>) -> Result<InvitationRecord> {
    let encoded: Vec<u8> = row.get(0).map_err(ControllerError::registry)?;
    let preview: InvitationPreview =
        kr_cbor::from_canonical_slice(&encoded, &kr_cbor::Limits::DEFAULT)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    let issuer: Vec<u8> = row.get(1).map_err(ControllerError::registry)?;
    let state: String = row.get(2).map_err(ControllerError::registry)?;
    let redeemed: Option<Vec<u8>> = row.get(3).map_err(ControllerError::registry)?;
    let issued: i64 = row.get(4).map_err(ControllerError::registry)?;
    Ok(InvitationRecord {
        preview,
        issuer_device_id: DeviceId::new(uuid_of(&issuer).ok_or_else(|| {
            ControllerError::InvalidArgument("a stored issuer identity is malformed".to_owned())
        })?),
        state: state_of(&state).ok_or_else(|| {
            ControllerError::InvalidArgument("a stored invitation state is malformed".to_owned())
        })?,
        redeemed_by: redeemed.as_deref().and_then(uuid_of).map(DeviceId::new),
        issued_at_ms: u64::try_from(issued).unwrap_or_default(),
    })
}

fn state_of(value: &str) -> Option<InvitationState> {
    match value {
        "open" => Some(InvitationState::Open),
        "redeemed" => Some(InvitationState::Redeemed),
        "cancelled" => Some(InvitationState::Cancelled),
        "expired" => Some(InvitationState::Expired),
        _ => None,
    }
}

fn uuid_of(bytes: &[u8]) -> Option<kr_protocol::scalars::Uuid> {
    <[u8; 16]>::try_from(bytes)
        .ok()
        .map(kr_protocol::scalars::Uuid::from_bytes)
}
