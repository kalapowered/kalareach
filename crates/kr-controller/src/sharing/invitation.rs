//! Single-use expiring invitations, and the preview their issuer accepted.
//!
//! Section 25: "Invitations are single-use, expire, and cannot grant rights beyond their issuer. A
//! shared live screen can contain text printed before the invitation; the preview must show what
//! is being shared. New grant recipients do not receive all historical attachment keys
//! automatically."
//!
//! Four properties, and each one is a column rather than a convention:
//!
//! * **Single use.** Redemption moves the row from `open` to `redeemed` and activates the grant it
//!   carries, in one transaction. A second redemption finds the row redeemed, whichever device
//!   asks, so two devices racing the same invitation produce one grant.
//! * **Expiring.** A redemption after the deadline is refused and the row becomes `expired`. The
//!   deadline is the invitation's own, and a grant whose invitation was never redeemed authorises
//!   nothing at all.
//! * **Never beyond the issuer.** The grant an invitation carries was already checked against the
//!   issuer's own grant when it was written. What the ledger adds is that the *preview* the issuer
//!   accepted is kept, so what a recipient receives can be compared with what the issuer was shown.
//! * **No historical attachment keys.** [`InvitationPreview::historical_attachment_keys`] is
//!   written `false` and checked on the way in. A recipient that needs an old attachment asks for
//!   it under its own file grant, and the wrap is made then.
//!
//! The rows live in the grant store's own database and are written through its transactions, so an
//! invitation and the grant it carries move together. Two stores would mean two commits, and a
//! crash between them would leave either a grant nobody previewed or an invitation nobody can
//! redeem.

use kr_protocol::ids::{DeviceId, GrantId};
use kr_protocol::sharing::{InvitationPreview, InvitationState};

/// One invitation as the store holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationRecord {
    /// What the issuer was shown and accepted.
    pub preview: InvitationPreview,
    /// The device that issued it.
    pub issuer_device_id: DeviceId,
    /// The grant this invitation carries, which redemption activates.
    pub grant_id: GrantId,
    /// The device it was issued to. Only that device can redeem it.
    pub recipient_device_id: DeviceId,
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

/// Returns the state a stored wire string names.
#[must_use]
pub fn state_of(value: &str) -> Option<InvitationState> {
    match value {
        "open" => Some(InvitationState::Open),
        "redeemed" => Some(InvitationState::Redeemed),
        "cancelled" => Some(InvitationState::Cancelled),
        "expired" => Some(InvitationState::Expired),
        _ => None,
    }
}
