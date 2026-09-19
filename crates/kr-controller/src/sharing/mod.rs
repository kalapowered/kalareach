//! Sharing: roles compiled to grants, single-use invitations, and transfer of control.
//!
//! [`crate::grants`] answers "may this request happen?". This module answers "what does the person
//! who is sharing actually get to choose, and what are they shown before they choose it?".
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`roles`] | Compiling a role selection into explicit actions and history, the delegation rule, and what an actor may reach through a plugin, an attachment action or a workflow |
//! | [`invitation`] | Single-use expiring invitations and the preview their issuer accepted |
//! | [`transfer`] | Handing control of a session to another device |
//!
//! [`SharingService`] is the three of them together, because the sharing method group acts on all
//! three in one transition: a `grant.create` writes a grant, records the invitation and keeps the
//! preview, and any one of those failing has to leave none of them behind.
//!
//! # Owner confirmation
//!
//! Section 23 puts owner confirmation on "persistent enlargement". [`requires_owner_confirmation`]
//! is that phrase as code: a grant that never expires **and** carries a right the recipient does
//! not already hold. Both halves matter. A one-hour invitation is not persistent however wide it
//! is, and re-issuing what a device already holds enlarges nothing. Transfer of control is
//! separate and always confirmed, because it changes who the owner is.

pub mod invitation;
pub mod roles;
pub mod transfer;

use kr_protocol::grant::{Grant, GrantExpiry};
use kr_protocol::ids::{
    AuthorityRevision, DeviceId, EnvironmentId, GrantId, InvitationId, SessionId,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateResult, GrantListResult, InvitationPreview, LiveScreenPreview,
    NamedApprovalPreview, NamedQuestionPreview, RoleSelection,
};

use crate::error::{ControllerError, Result};
use crate::grants::{GrantDirectory, GrantRecord, GrantRevocation};

pub use invitation::{InvitationLedger, InvitationRecord};
pub use roles::{Intermediary, effective_rights};
pub use transfer::{ControlTransfer, TransferPlan};

/// What the issuer supplies when it shares a session.
#[derive(Clone, Debug)]
pub struct ShareRequest {
    /// The invitation's identity, allocated by the host.
    pub invitation_id: InvitationId,
    /// The grant's identity, allocated by the host.
    pub grant_id: GrantId,
    /// The environment the session lives in.
    pub environment_id: EnvironmentId,
    /// The session being shared.
    pub session_id: SessionId,
    /// The device issuing the invitation.
    pub issuer_device_id: DeviceId,
    /// The device it is issued to.
    pub recipient_device_id: DeviceId,
    /// The grant the issuer is delegating from, when it is delegating.
    pub parent_grant_id: Option<GrantId>,
    /// The role and the explicit choices on top of it.
    pub selection: RoleSelection,
    /// The invitation's lifetime. `None` takes section 10's one-hour default.
    pub lifetime_ms: Option<u64>,
    /// The notices the issuer states it was shown and accepted.
    ///
    /// Checked against what the grant actually carries. Section 25 makes a controller's terminal
    /// input conditional on the issuer accepting its account-level implications, and this is where
    /// that acceptance is a fact rather than a hope about the user interface.
    pub accepted_notices: CanonicalSet<AuthorityNotice>,
    /// The live screen as it stands, when the issuer included it.
    pub live_screen: Option<LiveScreenPreview>,
    /// The current questions the invitation names.
    pub named_questions: Vec<NamedQuestionPreview>,
    /// The current approval requests it names.
    pub named_approvals: Vec<NamedApprovalPreview>,
    /// The authority revision the host is issuing under.
    pub authority_revision: AuthorityRevision,
    /// Whether an owner confirmation has been completed for this exact request.
    pub owner_confirmed: bool,
    /// The host's current time, in UTC milliseconds.
    pub now_ms: u64,
}

/// The sharing service: grants, invitations and transfers in one place.
#[derive(Debug)]
pub struct SharingService {
    grants: GrantDirectory,
    invitations: InvitationLedger,
    /// This host's own device identity.
    ///
    /// The one issuer that may write a grant without delegating from one. Everything else has to
    /// name a parent it holds, which is what stops a device issuing authority out of nothing.
    host_device_id: DeviceId,
}

impl SharingService {
    /// Builds a service over an open grant directory and invitation ledger.
    #[must_use]
    pub const fn new(
        grants: GrantDirectory,
        invitations: InvitationLedger,
        host_device_id: DeviceId,
    ) -> Self {
        Self {
            grants,
            invitations,
            host_device_id,
        }
    }

    /// Opens both stores in memory, which is what a test uses.
    ///
    /// # Errors
    ///
    /// Returns an error when either store cannot be created.
    pub fn in_memory(host_device_id: DeviceId) -> Result<Self> {
        Ok(Self::new(
            GrantDirectory::in_memory()?,
            InvitationLedger::in_memory()?,
            host_device_id,
        ))
    }

    /// This host's own device identity.
    #[must_use]
    pub const fn host_device_id(&self) -> DeviceId {
        self.host_device_id
    }

    /// The grant directory.
    #[must_use]
    pub const fn grants(&self) -> &GrantDirectory {
        &self.grants
    }

    /// The invitation ledger.
    #[must_use]
    pub const fn invitations(&self) -> &InvitationLedger {
        &self.invitations
    }

    /// Builds the preview an issuer sees before anything is written.
    ///
    /// Nothing durable happens here. Section 25 requires the issuer to be shown what is being
    /// shared, and a preview computed by the same code that will write the grant is the only kind
    /// worth showing: a preview built separately would describe an intention rather than the
    /// effect.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the lifetime is outside its bound.
    pub fn preview(&self, request: &ShareRequest) -> Result<InvitationPreview> {
        let proposed = roles::compile(
            &request.selection,
            request.session_id,
            request.lifetime_ms,
            request.now_ms,
        )?;
        let expires_at_ms = match proposed.expiry {
            GrantExpiry::At { expires_at_ms } => expires_at_ms,
            GrantExpiry::Never => {
                return Err(ControllerError::InvalidArgument(
                    "a session invitation expires; persistent access needs owner pairing"
                        .to_owned(),
                ));
            }
        };
        let live_screen = if request.selection.include_live_screen {
            Nullable(request.live_screen.clone())
        } else {
            Nullable::null()
        };
        Ok(InvitationPreview {
            invitation_id: request.invitation_id,
            session_id: request.session_id,
            environment_id: request.environment_id,
            role: request.selection.role,
            actions: proposed.actions.clone(),
            history: proposed.history.clone(),
            expires_at_ms,
            live_screen,
            named_questions: request.named_questions.clone(),
            named_approvals: request.named_approvals.clone(),
            notices: AuthorityNotice::for_actions(&proposed.actions),
            // Section 25: new recipients do not receive historical attachment keys automatically.
            // The field is here so the issuer is told, rather than left to assume either way.
            historical_attachment_keys: false,
            single_use: true,
        })
    }

    /// Shares a session: writes the grant, records the invitation, keeps the preview.
    ///
    /// The order is the order the checks have to happen in. The preview is computed first, because
    /// everything after it is decided against what the issuer was shown. The issuer's acceptance
    /// is checked next, so a surface that showed a softer set of notices than the grant carries
    /// cannot get the grant written. Then the delegation rule, then owner confirmation, then the
    /// two writes.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when the issuer accepted a different set of
    /// notices, when the delegation would exceed its parent, or when a persistent enlargement
    /// arrives without owner confirmation.
    pub fn share(&self, request: &ShareRequest) -> Result<GrantCreateResult> {
        let preview = self.preview(request)?;

        if request.accepted_notices != preview.notices {
            return Err(ControllerError::PermissionDenied {
                detail: "the issuer accepted a different set of consequences from the ones this \
                         grant carries"
                    .to_owned(),
            });
        }

        let mut grant = Grant {
            grant_id: request.grant_id,
            parent_grant_id: Nullable(request.parent_grant_id),
            issuer_device_id: request.issuer_device_id,
            recipient_device_id: request.recipient_device_id,
            authority_revision: request.authority_revision,
            environment_selector: kr_protocol::grant::EnvironmentSelector::These {
                environment_ids: [request.environment_id].into_iter().collect(),
            },
            session_selector: kr_protocol::grant::SessionSelector::These {
                session_ids: [request.session_id].into_iter().collect(),
            },
            actions: preview.actions.clone(),
            history: preview.history.clone(),
            expiry: GrantExpiry::At {
                expires_at_ms: preview.expires_at_ms,
            },
            organisation: Nullable::null(),
        };

        match request.parent_grant_id {
            Some(parent_grant_id) => {
                let parent = self.grants.record(parent_grant_id)?.ok_or_else(|| {
                    ControllerError::PermissionDenied {
                        detail: "this host holds no such parent grant".to_owned(),
                    }
                })?;
                // The issuer has to *hold* the parent. Naming one is not holding one: without this
                // check any device that learned a grant identifier could delegate from somebody
                // else's authority, and the structural narrowing check below would happily agree.
                if parent.grant.recipient_device_id != request.issuer_device_id {
                    return Err(ControllerError::PermissionDenied {
                        detail: "that grant belongs to another device, so this one cannot \
                                 delegate from it"
                            .to_owned(),
                    });
                }
                if parent.revoked_at_ms.is_some() {
                    return Err(ControllerError::PermissionDenied {
                        detail: "the grant this one delegates from has been revoked".to_owned(),
                    });
                }
                if !parent.grant.expiry.is_valid_at(request.now_ms) {
                    return Err(ControllerError::PermissionDenied {
                        detail: "the grant this one delegates from has expired".to_owned(),
                    });
                }
                // Sharing is its own right. Holding the rights a grant contains is not authority
                // to hand them on, which is what section 23 means by "current issuer/delegation
                // authority" being separate from the grant's contents.
                if !parent.grant.permits(ActionRight::SessionShare) {
                    return Err(ControllerError::PermissionDenied {
                        detail: "delegating a grant needs session.share".to_owned(),
                    });
                }
                // A delegation inherits its parent's organisation requirement. Dropping it would
                // be a way to turn an organisation-scoped grant into a personal one.
                grant.organisation = parent.grant.organisation;
                roles::check_delegation(&grant, &parent.grant)?;
            }
            // No parent. Only this host's own device issues from its own authority; anything else
            // would be a device writing a grant nothing authorised.
            None => {
                if request.issuer_device_id != self.host_device_id {
                    return Err(ControllerError::PermissionDenied {
                        detail: "only this host issues a grant that delegates from nothing"
                            .to_owned(),
                    });
                }
            }
        }

        let held = self.grants_held_by(request.recipient_device_id, request.now_ms)?;
        if requires_owner_confirmation(&grant, &held) && !request.owner_confirmed {
            return Err(ControllerError::PermissionDenied {
                detail: "a persistent enlargement of a device's authority needs the owner's \
                         confirmation"
                    .to_owned(),
            });
        }

        // A retry that reaches here before its receipt was recorded finds the grant it already
        // wrote, rather than writing a second one or being refused. That only works because the
        // caller derives the identities from the action, which is why the daemon does.
        if let Some(existing) = self.grants.record(grant.grant_id)?
            && existing.grant == grant
        {
            let kept = self
                .invitations
                .record(preview.invitation_id)?
                .map(|record| record.preview);
            return Ok(GrantCreateResult {
                preview: kept.unwrap_or(preview),
                grant,
                authority_revision: request.authority_revision,
            });
        }
        self.grants.issue(&GrantRecord {
            grant: grant.clone(),
            session_id: Some(request.session_id),
            issued_at_ms: request.now_ms,
            revoked_at_ms: None,
            revoked_by_parent: None,
        })?;
        // The invitation is recorded after the grant, and its failure takes the grant with it: an
        // invitation nobody can redeem is recoverable, a grant nobody previewed is not.
        if let Err(error) =
            self.invitations
                .issue(&preview, request.issuer_device_id, request.now_ms)
        {
            self.grants.revoke(grant.grant_id, request.now_ms)?;
            return Err(error);
        }

        Ok(GrantCreateResult {
            grant,
            preview,
            authority_revision: request.authority_revision,
        })
    }

    /// Revokes a grant and its descendants.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read or written.
    pub fn revoke(&self, grant_id: GrantId, now_ms: u64) -> Result<GrantRevocation> {
        self.grants.revoke(grant_id, now_ms)
    }

    /// Lists the grants one issuer may see.
    ///
    /// An issuer sees the grants it issued and their descendants, which is exactly the set its own
    /// delegation authority reaches. Holding a right that a grant happens to contain is not
    /// authority over the grant, so it does not widen this list.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read.
    pub fn list_for_issuer(
        &self,
        issuer_device_id: DeviceId,
        session_id: Option<SessionId>,
        include_resolved: bool,
        now_ms: u64,
    ) -> Result<GrantListResult> {
        let all = self.grants.records()?;
        let mut visible: Vec<GrantId> = all
            .iter()
            .filter(|record| record.grant.issuer_device_id == issuer_device_id)
            .map(|record| record.grant.grant_id)
            .collect();
        // Descendants of what this issuer issued, however deep.
        let mut grew = true;
        while grew {
            grew = false;
            for record in &all {
                if let Some(parent) = record.grant.parent_grant_id.as_ref()
                    && visible.contains(parent)
                    && !visible.contains(&record.grant.grant_id)
                {
                    visible.push(record.grant.grant_id);
                    grew = true;
                }
            }
        }
        let grants = all
            .into_iter()
            .filter(|record| visible.contains(&record.grant.grant_id))
            .filter(|record| session_id.is_none_or(|named| record.session_id == Some(named)))
            .filter(|record| {
                include_resolved || record.state(now_ms) == kr_protocol::sharing::GrantState::Active
            })
            .map(|record| record.summary(now_ms))
            .collect();
        Ok(GrantListResult { grants })
    }

    /// Every live grant one device currently holds.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read.
    pub fn grants_held_by(&self, device_id: DeviceId, now_ms: u64) -> Result<Vec<Grant>> {
        Ok(self
            .grants
            .records_for_device(device_id)?
            .into_iter()
            .filter(|record| {
                record.revoked_at_ms.is_none() && record.grant.expiry.is_valid_at(now_ms)
            })
            .map(|record| record.grant)
            .collect())
    }

    /// Every right one device currently holds, across its live grants.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be read.
    pub fn rights_held_by(
        &self,
        device_id: DeviceId,
        now_ms: u64,
    ) -> Result<CanonicalSet<ActionRight>> {
        let mut held: CanonicalSet<ActionRight> = CanonicalSet::from_iter([]);
        for grant in self.grants_held_by(device_id, now_ms)? {
            for right in &grant.actions {
                held.insert(*right);
            }
        }
        Ok(held)
    }
}

/// Whether this grant is a persistent enlargement, and so needs the owner's confirmation.
///
/// Both halves of section 23's phrase, in order:
///
/// * **Persistent.** It never expires. A bounded invitation, however wide, ends on its own.
/// * **Enlargement.** No live grant the recipient already holds covers it. "Covers" is the
///   delegation rule read the other way round: an existing grant covers the new one when the new
///   one would be a valid narrowing of it. Comparing action *names* alone would miss the case that
///   matters most, where a device with a one-hour view of one session is handed a permanent view of
///   every session and nothing asks the owner.
#[must_use]
pub fn requires_owner_confirmation(grant: &Grant, already_held: &[Grant]) -> bool {
    if grant.expiry != GrantExpiry::Never {
        return false;
    }
    !already_held.iter().any(|held| covers(held, grant))
}

/// Whether `held` already reaches everything `proposed` would, so issuing it enlarges nothing.
///
/// [`Grant::narrows`] answers this for a real parent-child pair, and it also checks the parent
/// link, which is not the question here: two grants issued side by side can still make one
/// redundant. So the comparison is the rest of that rule, applied between the two.
fn covers(held: &Grant, proposed: &Grant) -> bool {
    held.recipient_device_id == proposed.recipient_device_id
        && proposed.actions.is_subset(&held.actions)
        && proposed
            .environment_selector
            .narrows(&held.environment_selector)
        && proposed.session_selector.narrows(&held.session_selector)
        && proposed.history.narrows(&held.history)
        && proposed.expiry.narrows(held.expiry)
        && (held.organisation.0.is_none() || proposed.organisation == held.organisation)
}
