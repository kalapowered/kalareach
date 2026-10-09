//! What one caller may see of the environment's attention.
//!
//! The store is one across every session the environment runs, so every answer it gives is cut to
//! the caller that asked. Section 23 makes the review and attention group a read of the caller's
//! current scoped view, and section 10 intersects a paired device's grant with current policy on
//! every request; this module is the part of that decision the store makes, from what the host
//! has already worked out about the grant.
//!
//! | What an item is about | The owner at this machine | A paired device |
//! | --- | --- | --- |
//! | a session, or raised from a session's records | sees it | when its grant admits the session and carries `session.view` |
//! | a workflow or a causal chain | sees it | when its grant carries `automation.manage` and the workflow or chain acts under that same grant |
//! | the environment itself | sees it | when its grant carries `host.manage` |
//!
//! The automation rule is the workflow journal's own rule for `workflow.read`: a device is shown the
//! workflows that act under its own grant and the chains whose root run does, and nothing of
//! another grant's.
//!
//! Earlier history is opt-in. Beside what its grant admits, a device is shown an item only when the
//! condition it stands for was first seen at or after the moment its grant's history reaches back
//! to ([`Viewer::reaches`]): its history cursor, or its own start when it has none.

use kr_protocol::attention::{AttentionGap, AttentionSource};
use kr_protocol::ids::{GrantId, SessionId};
use kr_protocol::scalars::TimestampMs;

use crate::engine::Item;

/// What a paired device's grant lets it see, as the host worked it out for this request.
pub struct DeviceScope<'a> {
    /// The grant the device holds.
    pub grant_id: GrantId,
    /// Whether the grant carries `session.view`.
    pub session_view: bool,
    /// Whether the grant carries `automation.manage`.
    pub automation_manage: bool,
    /// Whether the grant carries `host.manage`.
    pub host_manage: bool,
    /// Whether the grant's environment and session selectors admit one session.
    pub admits_session: &'a dyn Fn(SessionId) -> bool,
    /// The earliest moment, in UTC milliseconds, of what the grant's history reaches: a condition
    /// first seen before it is not the device's to be told of. A grant whose history reaches back
    /// to no moment at all sets the latest one there is.
    pub history_from_ms: u64,
}

impl core::fmt::Debug for DeviceScope<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DeviceScope")
            .field("grant_id", &self.grant_id)
            .field("session_view", &self.session_view)
            .field("automation_manage", &self.automation_manage)
            .field("host_manage", &self.host_manage)
            .field("history_from_ms", &self.history_from_ms)
            .finish_non_exhaustive()
    }
}

/// Who is asking.
#[derive(Debug)]
pub enum Viewer<'a> {
    /// The host's owner at this machine, who sees everything the store holds.
    Owner,
    /// A paired device, which sees what its grant admits.
    Device(DeviceScope<'a>),
}

impl Viewer<'_> {
    /// Whether this caller may see one session's items and review state.
    #[must_use]
    pub fn sees_session(&self, session_id: SessionId) -> bool {
        match self {
            Self::Owner => true,
            Self::Device(scope) => scope.session_view && (scope.admits_session)(session_id),
        }
    }

    /// Whether this caller may see one item.
    #[must_use]
    pub fn sees(&self, item: &Item) -> bool {
        match self {
            Self::Owner => true,
            Self::Device(scope) => {
                // An item raised from a session's records has its text read from that session, so
                // a caller sees it only when it may see that session as well as any the item names.
                let sessions = [item.origin.session(), item.session_id];
                if sessions.iter().any(Option::is_some) {
                    return sessions
                        .into_iter()
                        .flatten()
                        .all(|session_id| self.sees_session(session_id));
                }
                if item.automation.is_some() {
                    // An automation item whose grant the journal could not name is the owner's
                    // alone: there is no grant a device could be holding that it belongs to.
                    return scope.automation_manage && item.grant == Some(scope.grant_id);
                }
                scope.host_manage
            }
        }
    }

    /// Whether this caller's history reaches back to the moment a condition was first seen.
    ///
    /// The owner's reaches back to every moment. A device's reaches back to the moment its grant's
    /// cursor, or its own start, names, and an item that has no date to check is not one it can be
    /// shown.
    #[must_use]
    pub fn reaches(&self, first_seen: Option<TimestampMs>) -> bool {
        match self {
            Self::Owner => true,
            Self::Device(scope) => {
                first_seen.is_some_and(|first_seen| first_seen.get() >= scope.history_from_ms)
            }
        }
    }

    /// Whether this caller may be told about one gap.
    ///
    /// A gap names a session and a range of its records, which is itself something about that
    /// session, so it is shown to whoever may see the session. A gap in the environment's own
    /// workflow journal is shown to whoever may manage automation here; any other environment gap
    /// is the host's own, and needs `host.manage`.
    #[must_use]
    pub fn sees_gap(&self, gap: &AttentionGap) -> bool {
        match self {
            Self::Owner => true,
            Self::Device(scope) => match gap.session_id.0 {
                Some(session_id) => self.sees_session(session_id),
                None if gap.source == AttentionSource::Automation => scope.automation_manage,
                None => scope.host_manage,
            },
        }
    }
}
