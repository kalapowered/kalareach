//! Fixtures the automation suites share.
//!
//! A definition names a grant, and the host reads that grant from its own store rather than from
//! the request. These suites therefore need two things: grants to put into a store, and a store
//! to put them in. Both are here, so a suite that is about budgets or deadlines says nothing
//! about authority beyond naming the grant its definitions use.

#![allow(dead_code)]

use std::sync::Arc;

use kr_automation::{GrantStanding, GrantTable};
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

/// A grant of `rights` over every environment and session.
#[must_use]
pub fn grant_of(grant_id: GrantId, rights: &[ActionRight]) -> Grant {
    Grant {
        grant_id,
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
        recipient_device_id: DeviceId::new(Uuid::from_bytes([0xf1; 16])),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: rights.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    }
}

/// An authority holding one active grant of every right under each identifier.
#[must_use]
pub fn every_right(grant_ids: &[GrantId]) -> Arc<GrantTable> {
    let table = GrantTable::new();
    for grant_id in grant_ids {
        table.insert(grant_of(*grant_id, ActionRight::ALL));
    }
    Arc::new(table)
}

/// An authority holding one active grant carrying exactly `rights`.
#[must_use]
pub fn holding(grant_id: GrantId, rights: &[ActionRight]) -> Arc<GrantTable> {
    let table = GrantTable::new();
    table.insert(grant_of(grant_id, rights));
    Arc::new(table)
}

/// An authority holding one grant of every right, in a standing the caller chose.
#[must_use]
pub fn standing(grant_id: GrantId, standing: GrantStanding) -> Arc<GrantTable> {
    let table = GrantTable::new();
    table.set(grant_of(grant_id, ActionRight::ALL), standing);
    Arc::new(table)
}
