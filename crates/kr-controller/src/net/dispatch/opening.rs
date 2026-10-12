//! What a paired connection is opened for.
//!
//! A paired connection starts unscoped and behaves as it always did. `session.open` scopes it
//! once: to the host alone, or to one session under one grant. After that the connection serves
//! exactly that and refuses everything else, before the request is decided, so a connection can
//! neither be tied to a share by a read nor carry a share's end to the requests of another
//! session.
//!
//! * A **session scope** serves one session under one grant. A request that names another
//!   session is refused, and so is one that names the session under another grant.
//! * A **host scope** serves the host's own reads, decided under the pairing grant. It refuses
//!   every decision under a share and every route that reaches a worker, so no worker link, and
//!   no share, can end it. It ends with the pairing.
//!
//! The device's pairing grant decides what a scoped connection may do with the session, as it does
//! for any request, and `session.open` returns what that decision allows.

use std::sync::PoisonError;

use kr_protocol::authority::MethodEntry;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{GrantId, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::session::{SessionOpenParams, SessionOpenResult, ShareEnd};

use super::acting::{Acting, Held};
use super::decision::Asked;
use super::{RemoteConnection, failure};
use crate::service::net::lifetimes::GrantEnd;

/// What a connection is scoped to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scope {
    /// Nothing has opened it: it serves what an unscoped paired connection serves.
    Open,
    /// The host alone.
    Host,
    /// One session, under one grant.
    Session {
        session_id: SessionId,
        grant_id: GrantId,
    },
}

/// What a connection that serves one session is told about a request for another.
fn another_session() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::InvalidArgument,
        "this connection serves another session; open the session on its own connection",
    )
}

/// What a connection that serves the host alone is told about a request for a session's worker
/// or a decision under a share.
pub(super) fn serves_no_session() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::InvalidArgument,
        "this connection serves no session; open the session on its own connection",
    )
}

/// What a connection that serves a session is told about a request under another grant.
fn another_grant() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::PermissionDenied,
        "this connection acts under another grant; open another connection to act under the one \
         named",
    )
}

impl RemoteConnection {
    /// What this connection is scoped to.
    pub(super) fn scope(&self) -> Scope {
        *self.scope.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Refuses a request that names a session this connection is not scoped to, before anything
    /// is decided for it.
    ///
    /// Only a session scope refuses: a host scope serves the host's own reads of any session the
    /// pairing grant admits, and refuses what reaches a worker or a share elsewhere.
    pub(super) fn check_session_scope(
        &self,
        session_id: Option<SessionId>,
    ) -> std::result::Result<(), ProtocolError> {
        match (self.scope(), session_id) {
            (
                Scope::Session {
                    session_id: scoped, ..
                },
                Some(named),
            ) if named != scoped => Err(another_session()),
            _ => Ok(()),
        }
    }

    /// Refuses a request decided under `acting` on a connection scoped otherwise.
    ///
    /// It refuses and never substitutes: the decision keeps its own grant for the envelope it
    /// forwards and the history it shows. A request that names no session is decided under the
    /// pairing grant and records nothing, except `grant.revoke`, which acts under the share it
    /// delegated from and is served only on the connection scoped to that share.
    pub(super) fn check_scope(
        &self,
        session_id: Option<SessionId>,
        acting: &Acting,
    ) -> std::result::Result<(), ProtocolError> {
        match self.scope() {
            Scope::Open => Ok(()),
            Scope::Host => {
                if acting.held == Held::Share {
                    Err(serves_no_session())
                } else {
                    Ok(())
                }
            }
            Scope::Session {
                session_id: scoped,
                grant_id,
            } => {
                if session_id.is_some_and(|named| named != scoped) {
                    return Err(another_session());
                }
                let names_scoped = session_id == Some(scoped);
                if (names_scoped || acting.held == Held::Share) && acting.grant.grant_id != grant_id
                {
                    return Err(another_grant());
                }
                Ok(())
            }
        }
    }

    /// Refuses a route to a worker on a connection that serves the host alone.
    ///
    /// Every route that reaches a worker passes through this: the worker link a read or a
    /// mutation opens, the link a close opens for itself, and a receipt read that resolves to a
    /// session. The refusal is `INVALID_ARGUMENT`, so a caller can tell it from a missing right.
    pub(super) fn check_worker_route(&self) -> std::result::Result<(), ProtocolError> {
        if self.scope() == Scope::Host {
            Err(serves_no_session())
        } else {
            Ok(())
        }
    }

    /// Serves `session.open`: scopes the connection and says under what.
    pub(super) async fn session_open(
        &self,
        request: &Request,
        entry: &'static MethodEntry,
        asked: &mut Option<Asked>,
    ) -> ControlFrame {
        let opened = self.open(request, entry, asked).await;
        let value = opened.and_then(|opened| {
            ParamsValue::from_typed(&opened).map_err(|error| {
                ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())
            })
        });
        match value {
            Ok(value) => {
                // Checked again now the answer is made, as every read is.
                if let Err(error) = self.authorised().await {
                    return failure(request.request_id, error);
                }
                ControlFrame::Response(Response {
                    request_id: request.request_id,
                    outcome: Outcome::Ok(value),
                })
            }
            Err(error) => failure(request.request_id, error),
        }
    }

    async fn open(
        &self,
        request: &Request,
        entry: &'static MethodEntry,
        asked: &mut Option<Asked>,
    ) -> std::result::Result<SessionOpenResult, ProtocolError> {
        let params: SessionOpenParams = request
            .params
            .to_typed()
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let session_id = params.session_id.0;
        let named = params.grant_id.0;
        if session_id.is_none() && named.is_some() {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "a grant is named with the session it is for",
            ));
        }
        if !self.grant_is_current() {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this device's grant has expired",
            ));
        }
        let pairing_id = self.device.grant.grant_id;
        let wanted = match session_id {
            Some(session_id) => Scope::Session {
                session_id,
                grant_id: named.unwrap_or(pairing_id),
            },
            None => Scope::Host,
        };
        self.may_open(wanted)?;

        let (acting, share) = match session_id {
            Some(session_id) => self.acting_to_open(session_id, named)?,
            None => (self.acting_for(None, None)?, None),
        };
        // A share is over only on proof. The standing is read before the decision, which would
        // refuse an ended share in words and note it on the registration.
        if let Some(record) = &share
            && let Some(end) = self
                .controller
                .lifetimes()
                .stored_end(self.controller.sharing().grants(), record)
                .map_err(|error| error.to_protocol_error())?
        {
            return Ok(SessionOpenResult::Ended {
                reason: match end {
                    GrantEnd::Revoked => ShareEnd::Revoked,
                    GrantEnd::Expired => ShareEnd::Expired,
                },
            });
        }
        let decided = self.ask_under(acting.clone(), session_id, entry, false)?;
        let summary = match session_id {
            Some(session_id) => Some(
                self.controller
                    .session_summary(session_id)
                    .await
                    .map_err(|error| error.to_protocol_error())?,
            ),
            None => None,
        };
        if let Some(session_id) = session_id {
            self.fix(session_id, &acting)?;
        }
        self.scope_to(wanted)?;
        let actions = decided.decision.decided.permitted.rights.clone();
        *asked = Some(decided);

        let history = &acting.grant.history;
        let ends_at_ms = match &share {
            Some(record) => crate::service::net::lifetimes::GrantLifetimes::effective_end_ms(
                record,
                &self.device.grant,
            ),
            None => match self.device.grant.expiry {
                kr_protocol::grant::GrantExpiry::At { expires_at_ms } => Some(expires_at_ms.get()),
                kr_protocol::grant::GrantExpiry::Never => None,
            },
        };
        Ok(SessionOpenResult::InForce {
            session: Nullable(summary),
            environment_id: self.controller.paths().environment_id(),
            grant_id: acting.grant.grant_id,
            via: match acting.held {
                Held::Pairing => kr_protocol::session::OpenedVia::Pairing,
                Held::Share => kr_protocol::session::OpenedVia::Share,
            },
            actions,
            includes_live_screen: history.include_live_screen,
            history_from_ms: history.lower_bound_ms,
            ends_at_ms: Nullable(ends_at_ms.map(TimestampMs::new)),
        })
    }

    /// Whether this connection may be opened for `wanted`: a fresh one may, and one already
    /// scoped to exactly that may be opened again.
    ///
    /// A connection that is fixed to another session or grant, scoped otherwise, or that has
    /// decided a request under another share is meant for what it already does, and the open is
    /// refused rather than adding a second standing to it.
    fn may_open(&self, wanted: Scope) -> std::result::Result<(), ProtocolError> {
        let scope = self.scope();
        if scope != Scope::Open && scope != wanted {
            return Err(match (scope, wanted) {
                (Scope::Host, _) => serves_no_session(),
                (Scope::Session { .. }, Scope::Host) => another_session(),
                (
                    Scope::Session {
                        session_id: scoped, ..
                    },
                    Scope::Session { session_id, .. },
                ) if scoped != session_id => another_session(),
                _ => another_grant(),
            });
        }
        let fixed = *self.fixed.lock().unwrap_or_else(PoisonError::into_inner);
        let fixed_elsewhere = match (fixed, wanted) {
            (None, _) => false,
            (Some(_), Scope::Host | Scope::Open) => true,
            (
                Some((session_id, grant_id)),
                Scope::Session {
                    session_id: wanted_session,
                    grant_id: wanted_grant,
                },
            ) => session_id != wanted_session || grant_id != wanted_grant,
        };
        let wanted_grant = match wanted {
            Scope::Session { grant_id, .. } => Some(grant_id),
            Scope::Host | Scope::Open => None,
        };
        let noted = self.controller.noted_grants(self.connection_id);
        let other_share = noted
            .iter()
            .any(|noted| Some(*noted) != wanted_grant && *noted != self.device.grant.grant_id);
        if fixed_elsewhere || other_share {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "this connection already acts for something else; open a new connection",
            ));
        }
        Ok(())
    }

    /// Scopes the connection, once.
    fn scope_to(&self, wanted: Scope) -> std::result::Result<(), ProtocolError> {
        let mut scope = self.scope.lock().unwrap_or_else(PoisonError::into_inner);
        if *scope != Scope::Open && *scope != wanted {
            return Err(another_session());
        }
        *scope = wanted;
        Ok(())
    }
}
