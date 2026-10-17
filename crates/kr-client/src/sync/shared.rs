//! A settings collection two or more devices share, reached as the service the settings and the
//! draft clients write through.
//!
//! [`SyncClient`](super::SyncClient) and [`DraftSync`](crate::drafts::DraftSync) are written
//! against [`SyncBackupService`]: one object, named by its kind and identity, in a collection
//! nobody has claimed. Once a key record has claimed a collection, every request about it names
//! the home it lives in and every write names the epoch its object is sealed under, so the plain
//! service no longer reaches it. [`SharedCollectionService`] is the one that does: it holds the
//! collection and the epoch, and asks the `_shared` calls of [`ManagedSyncService`] for what the
//! clients ask.
//!
//! # One epoch per value
//!
//! The epoch is part of what a write asks, and the sealer that made the write's ciphertext belongs
//! to one epoch too. So a value of this type and the [`CollectionSealer`]
//! beside it are built together for the epoch the installed key record carries, and a client built
//! over them writes under that epoch and no other. When the collection moves to a newer epoch,
//! both are built again from the installed record; this type never takes the epoch it writes
//! under from the service, because a ciphertext sealed under one key must not travel under the name
//! of another.
//!
//! # The three answers that are not data
//!
//! A shared collection can answer a request with three things the single-object interface has no
//! word for, and each is said in the words it has:
//!
//! * **A write under an epoch the collection has retired** stored nothing and held nothing, and is
//!   that request's receipt. The write is refused as [`ErrorCode::ResyncRequired`], the code the
//!   service's refusal carries everywhere else, so the client leaves the work outstanding and asks
//!   about it; a status query or a fence that meets the receipt answers that the request was
//!   fenced and never ran, which is what a request that stored nothing and never will is.
//! * **A collection that does not list this installation** is answered as one that does not exist.
//!   It is refused as [`ErrorCode::UnknownSession`], as the same answer is everywhere else.
//! * **An object sealed under another epoch than the one this reads** is not opened with the key of
//!   this one. It is refused as [`ErrorCode::ResyncRequired`] naming both epochs, where the sealer
//!   would say only that it did not authenticate and the answer would read as tampering.

use std::sync::Arc;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{SyncConflictId, SyncObjectId};
use kr_protocol::scalars::Uuid;

use super::membership::CollectionRef;
use super::{CollectionKeys, CollectionSealer};
use crate::error::{ClientError, Result};
use crate::services::{
    Keyed, ManagedSyncService, ServiceFuture, SyncBackupService, SyncExchanged, SyncFetched,
    SyncRequestFence, SyncRequestStatus,
};
use crate::shown::Shown;

/// A collection two or more devices share, as the single-object service the clients write
/// through, at one epoch.
pub struct SharedCollectionService {
    service: Arc<ManagedSyncService>,
    collection: CollectionRef,
    epoch: u64,
}

impl std::fmt::Debug for SharedCollectionService {
    /// Which collection and which epoch. The service it asks is not rendered.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedCollectionService")
            .field("collection", &self.collection)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl SharedCollectionService {
    /// The shared `collection`, written under `epoch`, over a service client that signs as this
    /// installation.
    #[must_use]
    pub const fn new(
        service: Arc<ManagedSyncService>,
        collection: CollectionRef,
        epoch: u64,
    ) -> Self {
        Self {
            service,
            collection,
            epoch,
        }
    }

    /// The collection this reaches.
    #[must_use]
    pub const fn collection(&self) -> &CollectionRef {
        &self.collection
    }

    /// The epoch it writes under.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The sealer for this collection at this epoch, so that what a client seals and what it asks
    /// the service to write are for one epoch by construction.
    #[must_use]
    pub fn sealer(&self, keys: Arc<dyn CollectionKeys>) -> CollectionSealer {
        CollectionSealer::new(keys, &self.collection.collection_id.to_string(), self.epoch)
    }
}

/// The error a write under a retired epoch is: the collection has a newer key to be read first.
fn retired() -> ClientError {
    ClientError::refusal(
        ErrorCode::ResyncRequired,
        Shown::said(
            "the settings collection moved to a newer key, so the write was not kept: read its \
             key records and write again",
        ),
    )
}

/// The error an object sealed under another epoch than the one this reads is: the key it was
/// sealed under is not the key this opens it with, so it is not opened and not taken for a forgery.
fn sealed_under_another_epoch(sealed: Option<u64>, reads: u64) -> ClientError {
    let text = match sealed {
        Some(sealed) => crate::shown!(
            "that object is sealed under key epoch {}, and this reads key epoch {}",
            sealed,
            reads
        ),
        None => crate::shown!(
            "that object names no key epoch, and this reads key epoch {}",
            reads
        ),
    };
    ClientError::refusal(ErrorCode::ResyncRequired, text)
}

/// The error a collection that does not list this installation is.
fn absent() -> ClientError {
    ClientError::refusal(
        ErrorCode::UnknownSession,
        Shown::said("this device is not a member of that collection"),
    )
}

/// The identity of the object a per-object name (`settings/<uuid>`) names.
fn object_of(name: &str) -> Result<SyncObjectId> {
    name.split_once('/')
        .and_then(|(_, identity)| identity.parse::<Uuid>().ok())
        .map(SyncObjectId::new)
        .ok_or_else(|| {
            ClientError::refusal(
                ErrorCode::InvalidArgument,
                Shown::said("that is not the name of a synchronised object"),
            )
        })
}

impl SyncBackupService for SharedCollectionService {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<crate::services::SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            match self
                .service
                .exchange_shared(
                    &self.collection,
                    collection,
                    self.epoch,
                    request_id,
                    signed_at_ms,
                    expected,
                    ciphertext,
                )
                .await?
            {
                Keyed::Answered { answer, .. } => Ok(answer),
                Keyed::Retired { .. } => Err(retired()),
                Keyed::Absent => Err(absent()),
            }
        })
    }

    fn request_status<'a>(
        &'a self,
        _collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async move {
            match self
                .service
                .status_shared(&self.collection, request_id)
                .await?
            {
                Keyed::Answered { answer, .. } => Ok(answer),
                Keyed::Retired { head } => Ok(SyncRequestStatus::Fenced {
                    never_ran: true,
                    recovery: head.recovery,
                }),
                Keyed::Absent => Err(absent()),
            }
        })
    }

    fn fence_request<'a>(
        &'a self,
        _collection: &'a str,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async move {
            match self
                .service
                .fence_shared(
                    &self.collection,
                    request_id,
                    first_signed_at_ms,
                    last_signed_at_ms,
                )
                .await?
            {
                Keyed::Answered { answer, .. } => Ok(answer),
                Keyed::Retired { head } => Ok(SyncRequestFence::Fenced {
                    never_ran: true,
                    recovery: head.recovery,
                }),
                Keyed::Absent => Err(absent()),
            }
        })
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(async move {
            let wanted = object_of(collection)?;
            let Some(found) = self
                .service
                .compare_shared(&self.collection, &[], false, None)
                .await?
            else {
                return Err(absent());
            };
            let Some(held) = found
                .objects
                .into_iter()
                .find(|held| held.object_id == wanted)
            else {
                return Ok(SyncFetched::Absent {
                    recovery: found.recovery,
                });
            };
            // The sealer this is read with has one epoch's key. An object sealed under another
            // is refused here by name, where the sealer would say only that it did not
            // authenticate.
            if held.epoch != Some(self.epoch) {
                return Err(sealed_under_another_epoch(held.epoch, self.epoch));
            }
            Ok(SyncFetched::Held {
                position: held.position,
                ciphertext: held.ciphertext,
            })
        })
    }

    fn resolve<'a>(
        &'a self,
        _collection: &'a str,
        retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        Box::pin(async move {
            self.service
                .resolve_shared(&self.collection, retained)
                .await?
                .ok_or_else(absent)
        })
    }
}
