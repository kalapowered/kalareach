//! The fence that holds publication while a device is taken out.
//!
//! A revocation this computer sent is known here before the membership has recorded it, and a step
//! may be in hand, waiting on the network, when it is. The membership cannot record it then: the
//! step holds the membership for as long as it waits. From the moment the revocation is known,
//! nothing more may be sent that the device could read, so the fence is raised first, before
//! anything that can wait or fail, and lifted once the membership has recorded the revocation.
//!
//! The fence is held where it cannot be missed. Every send of content, settings and drafts alike,
//! goes through [`Fenced`], which refuses it while the fence is raised, at the moment it would
//! leave. A check made earlier in a step cannot stand for that: the content a step sends is read
//! and sealed after awaits of its own, and the revocation can arrive in any of them.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use kr_client::services::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence,
    SyncRequestStatus,
};
use kr_client::{ClientError, Shown};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::SyncConflictId;
use kr_protocol::scalars::{AuthorisationKey, Uuid};

/// The devices whose revocation this computer sent and the membership has not recorded yet.
#[derive(Debug, Default)]
pub struct Fence {
    raised: Mutex<BTreeSet<AuthorisationKey>>,
}

impl Fence {
    /// Holds publication until `devices` are recorded as revoked.
    pub(super) fn raise(&self, devices: &[AuthorisationKey]) {
        self.raised
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(devices.iter().copied());
    }

    /// Lets go of `devices`, whose revocation the membership recorded.
    pub(super) fn lift(&self, devices: &[AuthorisationKey]) {
        let mut raised = self.raised.lock().unwrap_or_else(PoisonError::into_inner);
        for device in devices {
            raised.remove(device);
        }
    }

    /// Whether publication is held.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        !self
            .raised
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }
}

/// A service whose writes of content wait while a [`Fence`] is raised.
///
/// A write refused here never leaves this computer. It ends the way any write that got no answer
/// ends: the next step asks the service about it, learns that it never ran, and sends the content
/// again once the device is out.
pub struct Fenced {
    inner: Arc<dyn SyncBackupService>,
    fence: Arc<Fence>,
}

impl Fenced {
    /// `inner`, held by `fence`.
    #[must_use]
    pub fn new(inner: Arc<dyn SyncBackupService>, fence: Arc<Fence>) -> Self {
        Self { inner, fence }
    }
}

impl std::fmt::Debug for Fenced {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Fenced").finish_non_exhaustive()
    }
}

/// What a write is refused with while a device is being taken out.
fn withheld() -> ClientError {
    ClientError::refusal(
        ErrorCode::ResourceUnavailable,
        Shown::said(
            "a device is being taken out of the shared settings, so nothing is sent until it is",
        ),
    )
}

impl SyncBackupService for Fenced {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            if self.fence.is_raised() {
                return Err(withheld());
            }
            self.inner
                .compare_exchange(collection, request_id, signed_at_ms, expected, ciphertext)
                .await
        })
    }

    // A removal carries no content, and a draft thrown away leaves when the person asks.
    fn compare_remove<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
    ) -> ServiceFuture<'a, SyncExchanged> {
        self.inner
            .compare_remove(collection, request_id, signed_at_ms, expected)
    }

    fn request_status<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        self.inner.request_status(collection, request_id)
    }

    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        self.inner.fence_request(
            collection,
            request_id,
            first_signed_at_ms,
            last_signed_at_ms,
        )
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, SyncFetched> {
        self.inner.fetch(collection)
    }

    fn resolve<'a>(
        &'a self,
        collection: &'a str,
        retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        self.inner.resolve(collection, retained)
    }
}
