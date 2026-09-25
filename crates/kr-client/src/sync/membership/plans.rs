//! The plans an owner confirms: one exact operation, a digest over it and a short expiry.
//!
//! An addition to a collection and a join into one each enlarge who reads a person's settings, so
//! each needs the owner's presence (section 10). This library plans the exact operation, the
//! companion's native command runs the presence ceremony with the plan's summary as its reason,
//! and on success hands the plan back, which is consumed here once. The WebView only chooses: a
//! plan it swapped, one that expired, one that was cancelled and one already used are all refused.
//! A removal needs no plan, because taking away rights needs no new rights-enlarging confirmation.

use std::collections::BTreeMap;

use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use serde::{Deserialize, Serialize};

use super::{CollectionRef, Device};

/// How long a plan waits for the owner's confirmation.
pub const PLAN_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// The domain a plan's digest is computed under.
const PLAN_DOMAIN: &str = "kr-sync-membership-plan/1";

/// The operation one plan asks the owner to confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PlannedOperation {
    /// Share this device's settings collection with another device: "share settings with *name*".
    Share {
        /// The collection.
        collection: CollectionRef,
        /// The epoch of the key the device would receive.
        epoch: u64,
        /// The device, with both keys as its hosts reported them.
        device: Device,
    },
    /// Join a collection another device shares: "join settings shared by *name*".
    Join {
        /// The collection.
        collection: CollectionRef,
    },
}

/// One planned operation, as the owner is asked to confirm it and as it is handed back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// Which plan this is.
    pub id: Uuid,
    /// What it does.
    pub operation: PlannedOperation,
    /// When it stops being accepted, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
    /// The SHA-256 of the canonical encoding of the three fields above under the plan domain.
    pub digest: Digest256,
}

/// Why a plan handed back was not consumed.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlanRefusal {
    /// No plan with this identity is waiting: it was never made here, was cancelled, or was
    /// already consumed.
    #[error("no plan with this identity is waiting to be confirmed")]
    Unknown,
    /// The plan handed back is not the plan that was made.
    #[error("the plan handed back is not the one that was made")]
    Substituted,
    /// The plan expired before it was handed back.
    #[error("the plan expired before the owner confirmed it")]
    Expired,
    /// The collection moved on since the plan was made, so the operation is not the one confirmed.
    #[error("the collection changed after the plan was made; plan it again")]
    Stale,
}

crate::debug_as_display!(PlanRefusal);

/// The plans waiting for the owner, for the life of this process.
#[derive(Debug, Default)]
pub(crate) struct Plans {
    waiting: BTreeMap<[u8; 16], Plan>,
}

impl Plans {
    /// Makes a plan for one operation.
    pub(crate) fn make(
        &mut self,
        id: Uuid,
        operation: PlannedOperation,
        now: TimestampMs,
    ) -> Result<Plan, kr_cbor::CborError> {
        let expires_at_ms = TimestampMs::new(now.get().saturating_add(PLAN_LIFETIME_MS));
        let digest = digest(id, &operation, expires_at_ms)?;
        let plan = Plan {
            id,
            operation,
            expires_at_ms,
            digest,
        };
        self.waiting.insert(*id.as_bytes(), plan);
        Ok(plan)
    }

    /// Consumes a plan handed back, once.
    ///
    /// A plan that expired is consumed too, so it cannot be tried again.
    pub(crate) fn consume(&mut self, handed: &Plan, now: TimestampMs) -> Result<Plan, PlanRefusal> {
        let waiting = self
            .waiting
            .get(handed.id.as_bytes())
            .ok_or(PlanRefusal::Unknown)?;
        let recomputed = digest(handed.id, &handed.operation, handed.expires_at_ms)
            .map_err(|_| PlanRefusal::Substituted)?;
        if waiting != handed || recomputed != handed.digest {
            return Err(PlanRefusal::Substituted);
        }
        let plan = self
            .waiting
            .remove(handed.id.as_bytes())
            .ok_or(PlanRefusal::Unknown)?;
        if now.get() >= plan.expires_at_ms.get() {
            return Err(PlanRefusal::Expired);
        }
        Ok(plan)
    }

    /// Cancels a plan. Cancelling one that is not waiting does nothing.
    pub(crate) fn cancel(&mut self, id: Uuid) {
        self.waiting.remove(id.as_bytes());
    }
}

/// The digest a plan carries.
fn digest(
    id: Uuid,
    operation: &PlannedOperation,
    expires_at_ms: TimestampMs,
) -> Result<Digest256, kr_cbor::CborError> {
    let bytes = kr_cbor::to_canonical_vec(&(PLAN_DOMAIN, id, operation, expires_at_ms))?;
    Ok(Digest256::from_bytes(kr_cbor::sha256(&bytes)))
}
