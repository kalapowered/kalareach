//! Encrypted settings sync: the compare-and-swap client, its conflicts and its privacy hook.
//!
//! The service in this suite is a real compare-and-exchange store over opaque bytes, and the
//! sealing is real: the objects it holds are sealed with `kr-crypto` under a key it never sees, so
//! what the tests read out of it is what a service would hold.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_client::ClientError;
use kr_client::drafts::{
    Draft, DraftSealer, DraftStore, DraftSync, DraftTarget, NotSubmittable,
    Published as DraftPublished, SyncCheckpoint as DraftCheckpoint, draft_collection,
};
use kr_client::services::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncPosition, SyncRequestFence,
    SyncRequestStatus, SyncRevision,
};
use kr_client::sync::{
    Claimed, ClientSelection, ConflictCopy, Dispatch, Outcome, PrivacyRecord, Publication,
    Published, Reconciled, RequestRecord, RequestRevision, RequestState, Resolutions, Restored,
    SettingValue, Settlement, StorageFeature, SyncBody, SyncCheckpoint, SyncClient, SyncError,
    SyncObject, SyncSettings, SyncStore, fresh_object_id, fresh_revision, sync_collection,
};
use kr_crypto::envelope::{open_sync_object, seal_sync_object};
use kr_crypto::secret::{Secret, SymmetricKey};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, DeviceId, DraftRevision, SessionId,
    SyncConflictId, SyncObjectId,
};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};
use kr_protocol::sync::{MAX_SYNC_CONFLICT_COPIES, SyncObjectKind};
use tokio::sync::Mutex;

const NOW: u64 = 1_764_000_000_000;

/// The position a service reports for the nth write of a collection.
///
/// The deployed service names each write with an opaque identifier of its own; this suite derives
/// one from the write sequence so a test can say where it expects a write to land. Only writes of
/// one collection are ever compared, which is what makes deriving it safe here.
fn at(write_sequence: u64) -> SyncPosition {
    SyncPosition::at(
        write_sequence,
        SyncRevision::new(Uuid::from_bytes([write_sequence as u8; 16])),
    )
}

/// Somewhere a test can hold one call at the wire while it changes something else.
///
/// Section 24 asks for privacy mode to be enabled while work is in flight. Without somewhere to
/// hold a call, a test could only change the generation before or after one, which is the case
/// that needs no rule.
#[derive(Debug)]
struct Gate {
    armed: Mutex<bool>,
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            armed: Mutex::new(false),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        }
    }
}

impl Gate {
    /// Holds the next call that passes through this gate.
    async fn hold_the_next_call(&self) {
        *self.armed.lock().await = true;
    }

    /// Waits here when this gate is armed, announcing that a call has arrived.
    async fn pass(&self) {
        if !std::mem::take(&mut *self.armed.lock().await) {
            return;
        }
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("the gate is open")
            .forget();
    }

    /// Waits until a call is waiting at this gate.
    async fn wait_for_a_call(&self) {
        self.entered
            .acquire()
            .await
            .expect("the gate is open")
            .forget();
    }

    /// Lets the waiting call finish.
    fn let_it_go(&self) {
        self.release.add_permits(1);
    }
}

/// How far a signature may be from the service's own clock, either side, before it is refused.
///
/// The service contract's own window. It is what makes a signing time worth recording: a request
/// runs within this of the instant it was signed at, or it does not run at all.
const SERVICE_REQUEST_FRESHNESS_MS: u64 = 5 * 60 * 1000;

/// The service's own clock, which reads the same instant the devices do until a test moves it.
#[derive(Debug)]
struct ServiceClock(u64);

impl Default for ServiceClock {
    fn default() -> Self {
        Self(NOW)
    }
}

/// The object a comparison names, which is the only part of a position the wire carries.
///
/// A position whose revision is null is the removal of the object, and so is no position at all
/// from the comparison's point of view: both name no object. The write sequence beside it orders
/// the answers and is never compared.
fn expected_object(expected: Option<SyncPosition>) -> Option<SyncRevision> {
    expected.and_then(|position| position.revision.0)
}

/// What one request was answered with, kept under the identity that request presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recorded {
    /// The write was applied, leaving the object at this position.
    Applied(SyncPosition),
    /// The comparison was refused, and the service kept the rejected write as this copy of its own.
    Refused(SyncConflictId),
    /// The request was fenced before anything ran under it, so nothing ever will.
    ///
    /// It carries what the service established about the past when it fenced: whether a receipt of
    /// any attempt under the identity would still have been there for the fence to find. The
    /// receipt records that statement, and every later answer about the identity repeats it.
    Fenced {
        /// Whether the service established that nothing ever ran under the identity.
        never_ran: bool,
    },
}

/// The receipt one request left behind.
#[derive(Clone, Debug)]
struct Receipt {
    /// The request this receipt answered, as the wire carried it: the revision the comparison
    /// named and the bytes. The deployed service records a digest of those fields, and its order is
    /// not one of them. A fence receipt answers no request, so it has nothing to hold: there is no
    /// payload for a request that never ran.
    request: Option<(Option<SyncRevision>, Vec<u8>)>,
    /// The reply that was given.
    recorded: Recorded,
    /// The service clock reading this receipt was written under.
    ///
    /// It is the same reading that passed the freshness check, so a receipt always bears an instant
    /// no earlier than its request's signing time less the window. That is what makes the sweep
    /// mark below mean something: an instant the mark has passed is an instant no receipt survives.
    recorded_at_ms: u64,
}

impl Receipt {
    const fn recorded(&self) -> &Recorded {
        &self.recorded
    }
}

/// One exchange as this device sent it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Exchange {
    collection: String,
    request_id: Uuid,
    signed_at_ms: u64,
    expected: Option<SyncPosition>,
    ciphertext: Vec<u8>,
}

/// One fence as this device asked for it.
///
/// The two signing times are the whole reason the service can answer about the past, so what the
/// device sent is recorded rather than only that it asked.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fence {
    collection: String,
    request_id: Uuid,
    first_signed_at_ms: u64,
    last_signed_at_ms: u64,
}

/// What becomes of the next exchange, so a test can lose an answer the way a network does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Interruption {
    /// The service applies the request and the answer never reaches the device.
    AfterTheWrite,
    /// The request never reaches the service, so no receipt is ever written for it.
    BeforeItArrives,
    /// The identity the request presents already answered a different request.
    ///
    /// The receipt under it accounts for that other request, and the object is left alone: what
    /// section 9 refuses is the second request wearing the first one's name.
    IdentityTaken,
}

/// A compare-and-exchange store over opaque bytes, and the request receipts beside it.
///
/// It is the service's half of section 20's compare and swap and of section 9's receipt: it holds
/// one position and one object per collection, records the reply it gave each request identity,
/// replays that reply for an exact retry, refuses a reused identity carrying different content,
/// and answers about an identity it has no receipt for by saying it holds none.
#[derive(Debug, Default)]
struct Service {
    /// The service's own clock, which stamps the receipts it writes.
    ///
    /// It is the service's and not the device's: what a fence records is the service's reading of
    /// when it fenced, and a device that read its own clock instead would be measuring against
    /// something the answer never said.
    clock: Mutex<ServiceClock>,
    objects: Mutex<BTreeMap<String, (SyncPosition, Vec<u8>)>>,
    /// Where the removal of each removed collection's object fell in that collection's order.
    ///
    /// A removal takes a place in the order and leaves nothing behind, so the next write of the
    /// object carries on from it rather than starting again. The deployed service keeps the same
    /// two columns for the same reason.
    removals: Mutex<BTreeMap<String, u64>>,
    receipts: Mutex<BTreeMap<(String, Uuid), Receipt>>,
    /// The highest instant any receipt this service has ever removed was recorded at.
    ///
    /// It only rises, and it is what lets a fence say whether a receipt of a run could have gone:
    /// below it the service has swept and cannot tell a request it ran from one it never saw, above
    /// it every receipt it ever wrote is still here.
    swept_through_ms: Mutex<u64>,
    sent: Mutex<Vec<Exchange>>,
    asked: Mutex<Vec<(String, Uuid)>>,
    fences: Mutex<Vec<Fence>>,
    fence_unreachable: Mutex<bool>,
    /// Whether the next fence records its receipt and then loses the answer on the way back.
    fence_answer_lost: Mutex<bool>,
    /// Where the next applied write is put, for a service whose own order is not what it seems.
    applies_the_next_write_at: Mutex<Option<SyncPosition>>,
    /// Where a test can hold one status query, so something can change while the answer is out.
    status_gate: Gate,
    /// Where a test can hold one fence, for the same reason.
    fence_gate: Gate,
    /// Whether the next status query answers before the request it asks about has committed.
    status_misses_the_receipt: Mutex<bool>,
    interruption: Mutex<Option<Interruption>>,
    status_unreachable: Mutex<bool>,
    /// Whether the service can be asked for what it holds.
    fetch_unreachable: Mutex<bool>,
    /// The collection each request was sent to, so a forgotten receipt can be found again.
    receipt_of: Mutex<BTreeMap<Uuid, String>>,
    /// The copies it kept of refused writes, by the collection each was kept in, until the person
    /// chooses about them.
    copies: Mutex<BTreeMap<SyncConflictId, String>>,
    /// Whether the service can be told about a person's choice.
    resolve_unreachable: Mutex<bool>,
}

impl Service {
    /// Forgets everything, which is what a reset or a replaced service looks like to a device.
    async fn reset(&self) {
        self.objects.lock().await.clear();
        self.removals.lock().await.clear();
        self.receipts.lock().await.clear();
    }

    /// Moves the service's own clock to this instant, which every receipt it writes then records.
    async fn its_clock_reads(&self, at_ms: u64) {
        self.clock.lock().await.0 = at_ms;
    }

    /// Returns what the service's own clock reads.
    async fn service_now(&self) -> u64 {
        self.clock.lock().await.0
    }

    /// Removes what a collection holds, at the next place in that collection's order.
    ///
    /// What another device removing the object looks like from here: the object is gone, and the
    /// place its removal took is kept so the order carries on rather than starting again.
    async fn remove(&self, collection: &str) -> SyncPosition {
        let mut objects = self.objects.lock().await;
        let next = objects
            .remove(collection)
            .map_or(1, |(position, _)| position.write_sequence + 1);
        self.removals
            .lock()
            .await
            .insert(collection.to_owned(), next);
        SyncPosition::removed_at(next)
    }

    /// Puts one object in a collection at a position of the caller's choosing.
    ///
    /// What a service restored from somewhere else looks like: the order is continued from a
    /// history this device never saw.
    async fn hold(&self, collection: &str, position: SyncPosition, ciphertext: Vec<u8>) {
        self.objects
            .lock()
            .await
            .insert(collection.to_owned(), (position, ciphertext));
    }

    async fn stored(&self, collection: &str) -> Option<(SyncPosition, Vec<u8>)> {
        self.objects.lock().await.get(collection).cloned()
    }

    async fn collections(&self) -> Vec<String> {
        self.objects.lock().await.keys().cloned().collect()
    }

    /// Applies the next exchange and loses its answer on the way back.
    async fn lose_the_next_answer(&self) {
        *self.interruption.lock().await = Some(Interruption::AfterTheWrite);
    }

    /// Stops the next exchange before the service sees it, so it leaves no receipt.
    async fn drop_the_next_request(&self) {
        *self.interruption.lock().await = Some(Interruption::BeforeItArrives);
    }

    /// Answers the next exchange as an identity a different request already wore.
    async fn give_the_next_identity_to_another_request(&self) {
        *self.interruption.lock().await = Some(Interruption::IdentityTaken);
    }

    /// Makes every status query fail, which is a service this device cannot ask.
    async fn stop_answering_about_requests(&self) {
        *self.status_unreachable.lock().await = true;
    }

    /// Makes every fetch fail, which is a service this device cannot bring content down from.
    async fn stop_serving_what_it_holds(&self) {
        *self.fetch_unreachable.lock().await = true;
    }

    /// Serves what it holds again.
    async fn serve_what_it_holds_again(&self) {
        *self.fetch_unreachable.lock().await = false;
    }

    /// Sweeps one receipt, which is section 9's thirty-day retention passing.
    ///
    /// The receipt is gone, not hidden: an exchange under that identity would be executed again and
    /// a status query holds nothing to answer from. The sweep mark rises to what the receipt was
    /// recorded at, in the same step that removes it, because that is the fact a later fence needs:
    /// from here on the service cannot tell a request it ran at that instant from one it never saw.
    async fn sweep_the_receipt(&self, request_id: Uuid) {
        let collection = self.receipt_of.lock().await.remove(&request_id);
        let Some(collection) = collection else {
            return;
        };
        // Removing the receipt and raising the mark are one step, under the lock a fence decides
        // beneath, exactly as the deployed service writes them in one transaction. A fence that
        // saw the receipt already gone and the mark not yet raised would say nothing ever ran
        // about a request this service had just forgotten.
        let mut receipts = self.receipts.lock().await;
        if let Some(receipt) = receipts.remove(&(collection, request_id)) {
            let mut mark = self.swept_through_ms.lock().await;
            *mark = (*mark).max(receipt.recorded_at_ms);
        }
    }

    /// Returns how far the service has swept its receipts.
    async fn swept_through(&self) -> u64 {
        *self.swept_through_ms.lock().await
    }

    /// Every exchange this device sent, whether or not the service acted on it.
    async fn exchanges(&self) -> Vec<Exchange> {
        self.sent.lock().await.clone()
    }

    /// Every request identity this device asked the status of.
    async fn status_queries(&self) -> Vec<(String, Uuid)> {
        self.asked.lock().await.clone()
    }

    /// Every fence this device asked for, as it asked for it.
    async fn fence_requests(&self) -> Vec<Fence> {
        self.fences.lock().await.clone()
    }

    /// Every copy the service keeps of a refused write in one collection.
    async fn copies_in(&self, collection: &str) -> Vec<SyncConflictId> {
        self.copies
            .lock()
            .await
            .iter()
            .filter(|(_, kept_in)| kept_in.as_str() == collection)
            .map(|(copy, _)| *copy)
            .collect()
    }

    /// Makes every resolution fail, which is a service this device cannot tell about a choice.
    async fn stop_dropping_copies(&self) {
        *self.resolve_unreachable.lock().await = true;
    }

    /// Lets the service be told about choices again.
    async fn drop_copies_again(&self) {
        *self.resolve_unreachable.lock().await = false;
    }

    /// Makes every fence fail, which is a service this device cannot ask to end a request.
    async fn stop_fencing_requests(&self) {
        *self.fence_unreachable.lock().await = true;
    }

    /// Lets the service answer fences again.
    async fn answer_fences_again(&self) {
        *self.fence_unreachable.lock().await = false;
    }

    /// Puts the next applied write at this place rather than at the next one in the order.
    ///
    /// A service whose history forked looks like this: it accepts a write and puts it at a place
    /// its own order has already used, which is not a later state of what this device saw.
    async fn applies_the_next_write_at(&self, position: SyncPosition) {
        *self.applies_the_next_write_at.lock().await = Some(position);
    }

    /// Records the next fence and loses its answer, which is a fence the device never learns of.
    ///
    /// The identity is fenced at the service from then on, and the only thing the device can do
    /// about it is ask again.
    async fn lose_the_next_fence_answer(&self) {
        *self.fence_answer_lost.lock().await = true;
    }

    /// Answers the next status query before the request it asks about has committed.
    ///
    /// The request is on its way and the service has written no receipt for it yet, which is the
    /// case a status query cannot tell from one that never arrived.
    async fn let_the_next_status_miss_the_receipt(&self) {
        *self.status_misses_the_receipt.lock().await = true;
    }

    /// Answers one exchange, from the receipt when this identity has one.
    ///
    /// The signing time is checked first, as the deployed service checks it where the request acts:
    /// a request whose signature is further from the service's own clock than the freshness window
    /// is refused before anything runs, which is what bounds when a request under one identity can
    /// have executed.
    async fn exchange(
        &self,
        collection: &str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &[u8],
    ) -> kr_client::Result<SyncExchanged> {
        let now = self.service_now().await;
        if now.abs_diff(signed_at_ms) > SERVICE_REQUEST_FRESHNESS_MS {
            return Err(ClientError::Host(ProtocolError::new(
                ErrorCode::ClockUntrusted,
                "that request was not signed within the freshness window",
            )));
        }
        let key = (collection.to_owned(), request_id);
        let request = (expected_object(expected), ciphertext.to_vec());
        let mut receipts = self.receipts.lock().await;
        if let Some(receipt) = receipts.get(&key) {
            // An identity that was fenced runs nothing afterwards, whatever it carries.
            if matches!(receipt.recorded, Recorded::Fenced { .. }) {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "that request was fenced",
                )));
            }
            // An exact retry is answered from the receipt and applied no second time. The same
            // identity carrying different content is a second request wearing the first one's
            // name, which section 9 refuses rather than answers.
            if receipt.request != Some(request) {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::IdConflict,
                    "that identity already answered a different request",
                )));
            }
            return Ok(answer(receipt.recorded));
        }
        let mut objects = self.objects.lock().await;
        let mut removals = self.removals.lock().await;
        // Where the collection stands: the live object, else the removal that took its place, else
        // nothing at all. Only the last of the three is an object that was never there.
        let current = objects
            .get(collection)
            .map(|(position, _)| *position)
            .or_else(|| {
                removals
                    .get(collection)
                    .map(|sequence| SyncPosition::removed_at(*sequence))
            });
        // The comparison is against the object the caller named, which is the only part of a
        // position the exchange carries. The order beside it is the service's own answer.
        let recorded = if current.and_then(|position| position.revision.0)
            == expected_object(expected)
        {
            // The service's own order: the next write of this object takes the next place in it,
            // and the first write of all takes place one. A removal took a place of its own, so a
            // write after one carries on from there rather than beginning again.
            let next = self
                .applies_the_next_write_at
                .lock()
                .await
                .take()
                .unwrap_or_else(|| at(current.map_or(1, |position| position.write_sequence + 1)));
            removals.remove(collection);
            objects.insert(collection.to_owned(), (next, ciphertext.to_vec()));
            Recorded::Applied(next)
        } else {
            // The service keeps the rejected write as a copy of its own, and the receipt names it.
            // A refusal is therefore an answer about the comparison and never a claim that the
            // service stored nothing.
            let kept = SyncConflictId::new(fresh_request_id());
            self.copies.lock().await.insert(kept, collection.to_owned());
            Recorded::Refused(kept)
        };
        receipts.insert(
            key.clone(),
            Receipt {
                request: Some(request),
                recorded,
                // The reading that passed the freshness check above is the one the receipt keeps,
                // so the receipt cannot claim an instant the request was never admitted at.
                recorded_at_ms: now,
            },
        );
        self.receipt_of.lock().await.insert(request_id, key.0);
        Ok(answer(recorded))
    }
}

/// The reply a receipt records, as the exchange itself would have answered.
fn answer(recorded: Recorded) -> SyncExchanged {
    match recorded {
        Recorded::Applied(position) => SyncExchanged::Applied { position },
        Recorded::Refused(conflict_id) => SyncExchanged::Refused {
            retained: Some(conflict_id),
        },
        Recorded::Fenced { .. } => unreachable!("a fenced identity never answers an exchange"),
    }
}

/// An answer that never came back, which is the one refusal that establishes nothing.
fn lost(what: &'static str) -> ClientError {
    ClientError::Host(ProtocolError::new(ErrorCode::UpstreamUnavailable, what))
}

impl SyncBackupService for Service {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            self.sent.lock().await.push(Exchange {
                collection: collection.to_owned(),
                request_id,
                signed_at_ms,
                expected,
                ciphertext: ciphertext.to_vec(),
            });
            let interruption = self.interruption.lock().await.take();
            if interruption == Some(Interruption::BeforeItArrives) {
                return Err(lost("the request never reached the service"));
            }
            if interruption == Some(Interruption::IdentityTaken) {
                // The receipt under this identity answers a request that carried other content,
                // and it says that request was applied. The object is untouched.
                let current = self
                    .objects
                    .lock()
                    .await
                    .get(collection)
                    .map_or(0, |(position, _)| position.write_sequence);
                self.receipts.lock().await.insert(
                    (collection.to_owned(), request_id),
                    Receipt {
                        request: Some((expected_object(expected), b"a different payload".to_vec())),
                        recorded: Recorded::Applied(at(current + 1)),
                        recorded_at_ms: self.service_now().await,
                    },
                );
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::IdConflict,
                    "that identity already answered a different request",
                )));
            }
            let answered = self
                .exchange(collection, request_id, signed_at_ms, expected, ciphertext)
                .await;
            if interruption == Some(Interruption::AfterTheWrite) {
                return Err(lost("the answer never came back"));
            }
            answered
        })
    }

    fn request_status<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async move {
            self.asked
                .lock()
                .await
                .push((collection.to_owned(), request_id));
            self.status_gate.pass().await;
            if *self.status_unreachable.lock().await {
                return Err(lost("the service could not be asked"));
            }
            if std::mem::take(&mut *self.status_misses_the_receipt.lock().await) {
                return Ok(SyncRequestStatus::Unknown);
            }
            Ok(
                match self
                    .receipts
                    .lock()
                    .await
                    .get(&(collection.to_owned(), request_id))
                    .map(|receipt| receipt.recorded)
                {
                    Some(Recorded::Applied(position)) => SyncRequestStatus::Applied { position },
                    Some(Recorded::Refused(conflict_id)) => SyncRequestStatus::Refused {
                        retained: Some(conflict_id),
                    },
                    Some(Recorded::Fenced { never_ran }) => SyncRequestStatus::Fenced { never_ran },
                    None => SyncRequestStatus::Unknown,
                },
            )
        })
    }

    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async move {
            self.fences.lock().await.push(Fence {
                collection: collection.to_owned(),
                request_id,
                first_signed_at_ms,
                last_signed_at_ms,
            });
            self.fence_gate.pass().await;
            if *self.fence_unreachable.lock().await {
                return Err(lost("the service could not be asked to fence"));
            }
            let key = (collection.to_owned(), request_id);
            let now = self.service_now().await;
            // The receipts and the mark are read under one hold, in the order a sweep takes them,
            // so this decision sees a sweep whole or not at all.
            let mut receipts = self.receipts.lock().await;
            let swept_through = *self.swept_through_ms.lock().await;
            // Whether anything ever ran under the identity, decided from the service's own
            // records. A receipt of any attempt would bear an instant no earlier than the first
            // signing time less the freshness window, because that is the reading that admitted it.
            // So if the service has never swept that far, every receipt it ever wrote for this
            // identity is still here, and it holds none.
            let never_ran = !receipts.contains_key(&key)
                && swept_through < first_signed_at_ms.saturating_sub(SERVICE_REQUEST_FRESHNESS_MS);
            // A request the service has already decided keeps its outcome; one it has not is
            // fenced, and the receipt that records the fence is what refuses an exchange
            // afterwards. A fence never answers that it does not know. The receipt records the
            // statement about the past, so a second fence answers what the first one concluded.
            let recorded = *receipts
                .entry(key)
                .or_insert(Receipt {
                    request: None,
                    recorded: Recorded::Fenced { never_ran },
                    recorded_at_ms: now,
                })
                .recorded();
            // A fence receipt is a receipt, so the suite can sweep it the same way. The deployed
            // service keeps it until no attempt the caller named can still become fresh, which is
            // what the newest signing time recorded above is for.
            self.receipt_of
                .lock()
                .await
                .insert(request_id, collection.to_owned());
            drop(receipts);
            if std::mem::take(&mut *self.fence_answer_lost.lock().await) {
                return Err(lost("the fence landed and its answer never came back"));
            }
            Ok(match recorded {
                Recorded::Applied(position) => SyncRequestFence::Applied { position },
                Recorded::Refused(conflict_id) => SyncRequestFence::Refused {
                    retained: Some(conflict_id),
                },
                Recorded::Fenced { never_ran } => SyncRequestFence::Fenced { never_ran },
            })
        })
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (SyncPosition, Vec<u8>)> {
        Box::pin(async move {
            if *self.fetch_unreachable.lock().await {
                return Err(lost("what the service holds could not be fetched"));
            }
            self.objects
                .lock()
                .await
                .get(collection)
                .cloned()
                .ok_or_else(|| {
                    ClientError::Host(ProtocolError::new(
                        ErrorCode::UnknownSession,
                        "no such object",
                    ))
                })
        })
    }

    fn resolve<'a>(
        &'a self,
        collection: &'a str,
        retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        Box::pin(async move {
            if *self.resolve_unreachable.lock().await {
                return Err(lost("the service could not be told about the choice"));
            }
            // A copy is dropped from the collection it was kept in, and from no other.
            let mut copies = self.copies.lock().await;
            if copies.get(&retained).map(String::as_str) == Some(collection) {
                copies.remove(&retained);
                return Ok(true);
            }
            Ok(false)
        })
    }
}

/// A service that holds a publication at the wire until a test lets it go.
///
/// Section 24 asks for privacy mode to be enabled while upload work is in flight. Without somewhere
/// to hold the call, a test could only enable it before or after, which is the case that needs no
/// rule.
#[derive(Debug)]
struct GatedService {
    inner: Service,
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    /// Whether the reply is held rather than the request.
    afterwards: Mutex<bool>,
    /// Whether the next fetch is held at the wire instead of a publication.
    hold_a_fetch: Mutex<bool>,
}

impl GatedService {
    fn new() -> Self {
        Self {
            inner: Service::default(),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
            afterwards: Mutex::new(false),
            hold_a_fetch: Mutex::new(false),
        }
    }

    /// Holds the next fetch at the wire, so a test can change what this device holds while the
    /// answer to a fetch is still out.
    async fn hold_the_next_fetch(&self) {
        *self.hold_a_fetch.lock().await = true;
    }

    /// Holds the reply instead of the request, so the write is committed and its receipt written
    /// before the device making the call learns anything.
    async fn hold_the_answer_instead(&self) {
        *self.afterwards.lock().await = true;
    }

    /// Waits until a publication has reached the service and is waiting there.
    async fn wait_for_a_publication(&self) {
        self.entered
            .acquire()
            .await
            .expect("the gate is open")
            .forget();
    }

    /// Lets the waiting publication finish.
    fn let_it_go(&self) {
        self.release.add_permits(1);
    }

    /// Announces that a publication has reached the gate, and waits there.
    async fn wait_at_the_gate(&self) {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("the gate is open")
            .forget();
    }
}

impl SyncBackupService for GatedService {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            let afterwards = *self.afterwards.lock().await;
            if !afterwards {
                self.wait_at_the_gate().await;
            }
            let answered = self
                .inner
                .compare_exchange(collection, request_id, signed_at_ms, expected, ciphertext)
                .await;
            if afterwards {
                self.wait_at_the_gate().await;
            }
            answered
        })
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

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (SyncPosition, Vec<u8>)> {
        Box::pin(async move {
            let answered = self.inner.fetch(collection).await;
            if std::mem::take(&mut *self.hold_a_fetch.lock().await) {
                self.wait_at_the_gate().await;
            }
            answered
        })
    }

    fn resolve<'a>(
        &'a self,
        collection: &'a str,
        retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        self.inner.resolve(collection, retained)
    }
}

/// This device's sealing: a real synchronised object under a key the service never sees.
#[derive(Debug)]
struct DeviceSealer {
    key: SymmetricKey,
}

impl DeviceSealer {
    fn new(byte: u8) -> Self {
        Self {
            key: Secret::from_bytes([byte; 32]),
        }
    }
}

impl DraftSealer for DeviceSealer {
    fn seal(&self, plaintext: &[u8]) -> kr_client::Result<Vec<u8>> {
        let object = seal_sync_object(&self.key, plaintext).map_err(refused)?;
        Ok(kr_cbor::to_canonical_vec(&object)?)
    }

    fn open(&self, ciphertext: &[u8]) -> kr_client::Result<Vec<u8>> {
        let object: kr_protocol::sync::SealedSyncObject =
            kr_cbor::from_canonical_slice(ciphertext, &kr_cbor::Limits::DEFAULT)?;
        let opened = open_sync_object(&self.key, &object).map_err(refused)?;
        Ok(opened.expose().to_vec())
    }
}

/// Reports a sealing failure the way a client reports one it cannot classify further.
fn refused(error: kr_crypto::CryptoError) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::InvalidArgument,
        error.to_string(),
    ))
}

fn device(byte: u8) -> DeviceId {
    DeviceId::new(Uuid::from_bytes([byte; 16]))
}

/// One identity for a request a test sends itself, rather than through a client.
fn fresh_request_id() -> Uuid {
    kr_transport::random::fresh_uuid_v4().expect("an identity")
}

fn settings(pairs: &[(&str, &str)], pinned: &[&str]) -> SyncSettings {
    SyncSettings {
        values: pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), SettingValue::Text((*value).to_owned())))
            .collect(),
        pinned_labels: pinned.iter().map(|label| (*label).to_owned()).collect(),
    }
}

fn object(object_id: SyncObjectId, device_byte: u8, body: SyncBody, at_ms: u64) -> SyncObject {
    SyncObject {
        object_id,
        revision: fresh_revision().expect("a revision"),
        device_id: device(device_byte),
        updated_at_ms: TimestampMs::new(at_ms),
        body,
    }
}

/// One conflict copy of `other`, recorded at `at_ms`.
fn conflict(object_id: SyncObjectId, other: &SyncObject, at_ms: u64) -> ConflictCopy {
    ConflictCopy {
        conflict_id: SyncConflictId::new(
            kr_transport::random::fresh_uuid_v4().expect("an identity"),
        ),
        object_id,
        offered_revision: fresh_revision().expect("a revision"),
        retained: Nullable::null(),
        expected: Nullable::null(),
        current: at(1),
        other: other.clone(),
        recorded_at_ms: TimestampMs::new(at_ms),
    }
}

/// Claims one request's dispatch, which is what a settlement is decided under.
fn claim(store: &SyncStore, work_id: Uuid) -> Dispatch {
    match store.claim_dispatched(work_id).expect("a claim") {
        Claimed::Taken(dispatch, _) => dispatch,
        other => panic!("that request is not claimable: {other:?}"),
    }
}

/// Claims one request whose staged record has already gone, for a late answer about it.
fn claim_after_discard(store: &SyncStore, work_id: Uuid) -> Dispatch {
    store
        .claim_request(work_id)
        .expect("a claim")
        .expect("nobody is waiting on it")
}

/// One device: its own store and its own client over the shared service.
fn device_client(
    directory: &std::path::Path,
    name: &str,
    service: &Arc<Service>,
) -> (SyncClient, SyncObjectId) {
    let store = SyncStore::open(directory.join(name)).expect("a store");
    let client = SyncClient::new(
        Arc::clone(service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        store,
    );
    (client, fresh_object_id().expect("an identity"))
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13: per-object revisions and compare-and-swap writes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_settings_object_is_published_under_compare_and_swap_against_the_generation_it_last_saw()
{
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);

    let first = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&first).expect("stored");

    // Nothing is there yet, so the first comparison is against generation nought.
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW))
            .await
            .expect("published"),
        Published::Accepted { position: at(1) }
    );
    let note = client
        .store()
        .checkpoint(object_id)
        .expect("a note")
        .expect("one was written");
    assert_eq!(note.position, at(1));
    assert_eq!(note.published_revision, Nullable::some(first.revision));

    // A second write compares against what the note now says, and the revision is a fresh value
    // rather than the next number: an object removed and written again never repeats one.
    let mut second = first.clone();
    second.revision = fresh_revision().expect("a revision");
    second.body = SyncBody::Settings(settings(&[("theme", "light")], &[]));
    client.store().put_object(&second).expect("stored");
    assert_ne!(second.revision, first.revision);
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW + 1))
            .await
            .expect("published"),
        Published::Accepted { position: at(2) }
    );
    assert_eq!(
        service
            .collections()
            .await
            .first()
            .expect("one collection")
            .as_str(),
        sync_collection(SyncObjectKind::Settings, object_id)
    );
}

#[tokio::test]
async fn a_write_that_loses_the_comparison_keeps_the_other_copy_beside_it_rather_than_a_clock() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let two = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );

    // The first device publishes. The second holds its own edit and has never seen the object, so
    // it compares against nothing and loses.
    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW + 5_000,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // Deliberately the *later* clock, so a wall-clock rule would take this one.
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 10_000,
    );
    two.store().put_object(&mine).expect("stored");
    let outcome = two
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect("answered");
    let Published::Conflicted {
        copy,
        other_revision,
        position,
    } = outcome
    else {
        panic!("the second device lost the comparison: {outcome:?}")
    };
    assert_eq!(other_revision, theirs.revision);
    assert_eq!(position, at(1));

    // This device's own content is exactly as it was, and the other device's is beside it.
    let held = two
        .store()
        .object(object_id)
        .expect("an object")
        .expect("one is held");
    assert_eq!(held, mine, "a lost comparison never replaces local content");
    let copies = two.store().conflicts(object_id).expect("the copies").items;
    assert_eq!(copies.len(), 1);
    assert_eq!(copies[0].conflict_id, copy);
    assert_eq!(copies[0].other, theirs);
    assert_eq!(copies[0].offered_revision, mine.revision);

    // Nothing was chosen. The person chooses, and this is what that looks like: take the copy out
    // and publish what was chosen against the generation that won.
    let copies = two.store().conflicts(object_id).expect("the copies").items;
    let chosen = copies.first().expect("the copy is there").clone();
    let mut merged = mine.clone();
    merged.revision = fresh_revision().expect("a revision");
    merged.body = chosen.other.body.clone();
    // The choice is stored before its copy is taken away, so a stop between the two leaves the
    // person with a copy rather than with neither.
    two.store().put_object(&merged).expect("stored");
    assert_eq!(
        two.resolve(copy)
            .await
            .expect("resolved")
            .expect("the copy was still there")
            .copy
            .conflict_id,
        copy
    );
    assert!(
        service
            .copies_in(&sync_collection(SyncObjectKind::Settings, object_id))
            .await
            .is_empty(),
        "the copy the service kept of the refused write went with the choice"
    );
    assert_eq!(
        two.publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("published"),
        Published::Accepted { position: at(2) }
    );
    assert!(two.store().conflicts(object_id).expect("none").is_empty());
}

/// Two devices and one object, where the second device's write has lost to the first's.
///
/// It returns the second device's client and the copy it kept of the first device's content.
async fn a_lost_comparison(
    directory: &std::path::Path,
    service: &Arc<Service>,
) -> (SyncClient, SyncObjectId, SyncConflictId) {
    let (one, object_id) = device_client(directory, "one", service);
    let two = SyncClient::new(
        Arc::clone(service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.join("two")).expect("a store"),
    );
    one.store()
        .put_object(&object(
            object_id,
            1,
            SyncBody::Settings(settings(&[("theme", "dark")], &[])),
            NOW,
        ))
        .expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    two.store()
        .put_object(&object(
            object_id,
            2,
            SyncBody::Settings(settings(&[("theme", "light")], &[])),
            NOW,
        ))
        .expect("stored");
    let Published::Conflicted { copy, .. } = two
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect("answered")
    else {
        panic!("the second device lost the comparison")
    };
    (two, object_id, copy)
}

/// Whether any account of what left names a copy the service keeps.
fn names_a_kept_copy(client: &SyncClient) -> bool {
    client
        .exported()
        .expect("exported")
        .iter()
        .any(|entry| entry.kind.contains("kept as a copy by the service"))
}

#[tokio::test]
async fn a_resolved_conflict_leaves_no_copy_on_either_side() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (two, object_id, first) = a_lost_comparison(directory.path(), &service).await;
    let collection = sync_collection(SyncObjectKind::Settings, object_id);
    let first_kept = service.copies_in(&collection).await;
    assert_eq!(first_kept.len(), 1);

    // The device edits its own content and writes again from a note it has forgotten, so a second
    // and different version of its content is refused as well. The service keeps a copy of each
    // refused write, and this device keeps the other device's content beside its own each time.
    let mut edited = two.store().object(object_id).expect("read").expect("held");
    edited.revision = fresh_revision().expect("a revision");
    edited.body = SyncBody::Settings(settings(&[("theme", "sepia")], &[]));
    two.store().put_object(&edited).expect("stored");
    two.store().forget_checkpoint(object_id).expect("forgotten");
    let Published::Conflicted { copy: second, .. } = two
        .publish(object_id, TimestampMs::new(NOW + 2))
        .await
        .expect("answered")
    else {
        panic!("the note was behind again")
    };
    let both_kept = service.copies_in(&collection).await;
    assert_eq!(both_kept.len(), 2);
    let second_kept = both_kept
        .into_iter()
        .find(|kept| *kept != first_kept[0])
        .expect("the second refused version");
    assert_eq!(two.store().conflicts(object_id).expect("copies").len(), 2);

    // The person chooses about the first. Its copy leaves this device, and the one copy the service
    // kept of the refused write it answers leaves the service. The second refused version is one
    // the person has not decided about, and it stays exactly where it is: the service may be the
    // only place that still holds it.
    let resolved = two
        .resolve(first)
        .await
        .expect("resolved")
        .expect("the copy was there");
    assert_eq!(resolved.copy.conflict_id, first);
    assert_eq!(resolved.copy.retained, Nullable::some(first_kept[0]));
    assert_eq!(
        resolved.service,
        Resolutions {
            dropped: 1,
            pending: 0
        }
    );
    assert_eq!(
        service.copies_in(&collection).await,
        vec![second_kept],
        "only the copy the choice was about went"
    );
    let waiting = two.store().conflicts(object_id).expect("copies").items;
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].conflict_id, second);
    assert_eq!(waiting[0].retained, Nullable::some(second_kept));
    assert!(names_a_kept_copy(&two), "the second is still accounted for");

    // The second choice takes the second refused version with it, and nothing is left on either
    // side.
    let resolved = two
        .resolve(second)
        .await
        .expect("resolved")
        .expect("the copy was there");
    assert_eq!(
        resolved.service,
        Resolutions {
            dropped: 1,
            pending: 0
        }
    );
    assert!(
        service.copies_in(&collection).await.is_empty(),
        "no copy stays on the service"
    );
    assert!(
        two.store().conflicts(object_id).expect("copies").is_empty(),
        "nor on this device"
    );
    assert!(
        !names_a_kept_copy(&two),
        "and nothing still says the service keeps one"
    );
    assert!(
        two.resolve(first).await.expect("asked").is_none(),
        "a copy that is gone has nothing left to choose about"
    );

    // What was chosen is published through the ordinary path.
    assert!(matches!(
        two.publish(object_id, TimestampMs::new(NOW + 3))
            .await
            .expect("published"),
        Published::Accepted { .. }
    ));
}

#[tokio::test]
async fn a_copy_the_service_kept_with_nothing_here_to_choose_about_is_dropped_on_request() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let two = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );
    let collection = sync_collection(SyncObjectKind::Settings, object_id);
    one.store()
        .put_object(&object(
            object_id,
            1,
            SyncBody::Settings(settings(&[("theme", "dark")], &[])),
            NOW,
        ))
        .expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    two.store()
        .put_object(&object(
            object_id,
            2,
            SyncBody::Settings(settings(&[("theme", "light")], &[])),
            NOW,
        ))
        .expect("stored");

    // The refusal is settled, and the other device's content cannot be brought down, so this
    // device has no copy to choose about. The service still keeps what this device sent.
    service.stop_serving_what_it_holds().await;
    two.publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect_err("the other content could not be brought down");
    assert!(two.store().conflicts(object_id).expect("copies").is_empty());
    let kept = service.copies_in(&collection).await;
    assert_eq!(kept.len(), 1);

    // What has left names that copy by the identity the service gave it, as one this device can
    // ask to have dropped.
    let exported = two.exported().expect("exported");
    let entry = exported
        .iter()
        .find(|entry| entry.kind.contains("kept as a copy by the service"))
        .expect("the copy the service keeps is named");
    assert!(entry.deletable);
    assert!(entry.reference.contains(&kept[0].to_string()));

    // Nothing is dropped that the person did not name.
    assert!(
        two.drop_kept_copy(SyncConflictId::new(fresh_request_id()))
            .await
            .expect("asked")
            .is_none()
    );
    assert_eq!(service.copies_in(&collection).await.len(), 1);

    // Asked for by name, it goes, and nothing says the service keeps it any more.
    assert_eq!(
        two.drop_kept_copy(kept[0]).await.expect("asked"),
        Some(Resolutions {
            dropped: 1,
            pending: 0
        })
    );
    assert!(service.copies_in(&collection).await.is_empty());
    assert!(!names_a_kept_copy(&two));
    assert!(
        two.drop_kept_copy(kept[0]).await.expect("asked").is_none(),
        "a copy already gone is not asked about again"
    );
}

#[tokio::test]
async fn a_choice_the_service_cannot_be_told_about_stays_recorded_and_is_told_again() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (two, object_id, copy) = a_lost_comparison(directory.path(), &service).await;
    let collection = sync_collection(SyncObjectKind::Settings, object_id);
    assert_eq!(service.copies_in(&collection).await.len(), 1);

    // The service cannot be told. The choice is recorded all the same: the copy is gone from this
    // device, and what the service kept is counted as still to go rather than forgotten.
    service.stop_dropping_copies().await;
    let resolved = two
        .resolve(copy)
        .await
        .expect("the choice is recorded")
        .expect("the copy was there");
    assert_eq!(
        resolved.service,
        Resolutions {
            dropped: 0,
            pending: 1
        }
    );
    assert!(two.store().conflicts(object_id).expect("copies").is_empty());
    assert_eq!(service.copies_in(&collection).await.len(), 1);
    assert_eq!(two.store().resolutions().expect("pending").len(), 1);
    assert!(
        names_a_kept_copy(&two),
        "until the service drops it, the copy is still on the service and still accounted for"
    );

    // The choice is on this device's disk, so a device that stops and starts again still has it.
    drop(two);
    let reopened = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("the same store"),
    );
    assert_eq!(
        reopened.finish_resolutions().await.expect("asked again"),
        Resolutions {
            dropped: 0,
            pending: 1
        },
        "a service that still cannot be told leaves it recorded again"
    );

    // Once the service can be told, it is.
    service.drop_copies_again().await;
    assert_eq!(
        reopened.finish_resolutions().await.expect("asked again"),
        Resolutions {
            dropped: 1,
            pending: 0
        }
    );
    assert!(service.copies_in(&collection).await.is_empty());
    assert!(reopened.store().resolutions().expect("none").is_empty());
    assert!(!names_a_kept_copy(&reopened));
    assert_eq!(
        reopened.finish_resolutions().await.expect("nothing to ask"),
        Resolutions::default()
    );
}

#[tokio::test]
async fn copies_are_bounded_and_the_newest_refusal_is_the_one_that_is_kept() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let two = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );

    let mut theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    two.store().put_object(&mine).expect("stored");

    let mut newest = theirs.revision;
    for round in 0..(MAX_SYNC_CONFLICT_COPIES + 3) {
        theirs.revision = fresh_revision().expect("a revision");
        newest = theirs.revision;
        one.store().put_object(&theirs).expect("stored");
        one.publish(object_id, TimestampMs::new(NOW + round))
            .await
            .expect("published");
        // The second device's note is now behind again, so its next write loses again.
        two.store().forget_checkpoint(object_id).expect("forgotten");
        let outcome = two
            .publish(object_id, TimestampMs::new(NOW + round))
            .await
            .expect("answered");
        assert!(matches!(outcome, Published::Conflicted { .. }));
    }

    let copies = two.store().conflicts(object_id).expect("the copies").items;
    assert_eq!(copies.len() as u64, MAX_SYNC_CONFLICT_COPIES);
    assert_eq!(
        copies.last().expect("the newest").other.revision,
        newest,
        "the newest refusal is always the one that is kept"
    );
}

#[tokio::test]
async fn a_fetch_keeps_what_the_service_holds_beside_this_devices_own_content() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let two = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );

    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // A device with nothing of its own is seeing the object for the first time: there is nothing
    // to conflict with, and nothing is applied either.
    let restored = two
        .fetch(SyncObjectKind::Settings, object_id, TimestampMs::new(NOW))
        .await
        .expect("fetched");
    assert!(matches!(restored, Restored::Settings { .. }));
    assert_eq!(restored.copy(), None);
    assert_eq!(restored.object(), &theirs);
    assert!(
        two.store().object(object_id).expect("read").is_none(),
        "a fetch applies nothing"
    );

    // Once it holds a revision of its own, the same fetch keeps the other content beside it.
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    two.store().put_object(&mine).expect("stored");
    let restored = two
        .fetch(SyncObjectKind::Settings, object_id, TimestampMs::new(NOW))
        .await
        .expect("fetched");
    assert!(restored.copy().is_some());
    assert_eq!(
        two.store().object(object_id).expect("read").expect("held"),
        mine
    );
}

#[tokio::test]
async fn an_object_that_is_not_the_one_the_collection_was_asked_for_is_refused() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let elsewhere = fresh_object_id().expect("an identity");

    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // The service serves this object under another object's collection. Sealing says the bytes came
    // from a device holding the key; it says nothing about where they belong.
    let (position, ciphertext) = service
        .stored(&sync_collection(SyncObjectKind::Settings, object_id))
        .await
        .expect("it is stored");
    service
        .compare_exchange(
            &sync_collection(SyncObjectKind::Settings, elsewhere),
            fresh_request_id(),
            NOW,
            None,
            &ciphertext,
        )
        .await
        .expect("stored elsewhere");
    assert_eq!(position, at(1));

    assert!(matches!(
        one.fetch(SyncObjectKind::Settings, elsewhere, TimestampMs::new(NOW))
            .await,
        Err(SyncError::NotThatObject { .. })
    ));
}

#[tokio::test]
async fn a_copy_that_arrives_out_of_order_is_kept_rather_than_pruning_itself() {
    let directory = tempfile::tempdir().expect("a directory");
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let object_id = fresh_object_id().expect("an identity");
    let other = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );

    // Eight copies, all at one instant, which is what two answers finishing out of order or a
    // clock that stepped back produce.
    let mut kept = Vec::new();
    for _ in 0..MAX_SYNC_CONFLICT_COPIES {
        let copy = conflict(object_id, &other, NOW);
        kept.push(copy.conflict_id);
        store.keep_conflict(&copy).expect("kept");
    }
    assert_eq!(
        store.conflicts(object_id).expect("copies").len() as u64,
        MAX_SYNC_CONFLICT_COPIES
    );

    // A ninth at an *earlier* instant. It is the one just admitted, so it is never the one pruned:
    // a caller holding its identity must find it stored.
    let newest = conflict(object_id, &other, NOW - 1);
    store.keep_conflict(&newest).expect("kept");
    let copies = store.conflicts(object_id).expect("copies");
    assert_eq!(copies.len() as u64, MAX_SYNC_CONFLICT_COPIES);
    assert!(
        copies
            .items
            .iter()
            .any(|copy| copy.conflict_id == newest.conflict_id),
        "the copy just admitted is never the one pruned"
    );
    assert!(
        store
            .resolve_conflict(newest.conflict_id)
            .expect("resolved")
            .is_some()
    );
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13: one host authority, and drafts that stay drafts
// ---------------------------------------------------------------------------

#[test]
fn host_grants_and_revocation_state_are_not_things_a_restore_can_reach() {
    // Section 20 gives host grants and revocation state one host authority, and the closed kind set
    // is how it says so: there is no kind for them, so a synchronised object cannot be one.
    assert_eq!(
        SyncObjectKind::ALL.map(SyncObjectKind::as_str),
        ["settings", "draft", "client_selection"]
    );

    // A settings value is text, a number or a switch. Nothing in that shape carries a key, a
    // signature or a grant, so there is no settings object that could smuggle authority in.
    let with_authority = serde_json::json!({
        "collection_id": Uuid::from_bytes([1; 16]).to_string(),
        "object_id": Uuid::from_bytes([2; 16]).to_string(),
        "revision": Uuid::from_bytes([3; 16]).to_string(),
        "device_id": Uuid::from_bytes([4; 16]).to_string(),
        "updated_at_ms": NOW,
        "body": {
            "settings": {
                "values": { "theme": { "grant": { "grant_id": Uuid::from_bytes([5; 16]).to_string() } } },
                "pinned_labels": [],
            }
        }
    });
    assert!(
        serde_json::from_value::<SyncObject>(with_authority).is_err(),
        "a grant is not a setting this build reads"
    );

    // A whole extra field is refused too, so a newer writer cannot add one and have an older
    // reader accept it as settings.
    let with_extra = serde_json::json!({
        "collection_id": Uuid::from_bytes([1; 16]).to_string(),
        "object_id": Uuid::from_bytes([2; 16]).to_string(),
        "revision": Uuid::from_bytes([3; 16]).to_string(),
        "device_id": Uuid::from_bytes([4; 16]).to_string(),
        "updated_at_ms": NOW,
        "authority_revision": 4,
        "body": { "settings": { "values": {}, "pinned_labels": [] } }
    });
    assert!(serde_json::from_value::<SyncObject>(with_extra).is_err());
}

#[tokio::test]
async fn a_draft_is_synchronised_as_a_draft_and_never_as_an_execution_request() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let sealer: Arc<dyn DraftSealer> = Arc::new(DeviceSealer::new(0x5a));

    // The draft store publishes its own records through its own synchronised half, which is the one
    // way a draft reaches a service.
    let theirs = DraftStore::open(directory.path().join("theirs"), device(1)).expect("a store");
    let target = DraftTarget::session(SessionId::new(Uuid::from_bytes([3; 16]))).in_application(
        ApplicationInstanceId::new(Uuid::from_bytes([4; 16])),
        AgentBindingRevision::new(1),
    );
    let draft = theirs
        .create(
            target,
            "a prompt nobody asked to run".to_owned(),
            TimestampMs::new(NOW),
        )
        .expect("a draft");
    let drafts = DraftSync::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::clone(&sealer),
        SyncStore::open(directory.path().join("sync")).expect("a store"),
    );
    assert!(matches!(
        drafts
            .publish(
                &theirs,
                draft.draft_id,
                draft.revision,
                TimestampMs::new(NOW)
            )
            .await
            .expect("published"),
        DraftPublished::Accepted { .. }
    ));

    // On the other device it arrives as a draft, beside whatever that device holds, and the only
    // path towards a submission answers a question and performs nothing.
    let mine = DraftStore::open(directory.path().join("mine"), device(2)).expect("a store");
    let fetched = drafts
        .fetch_beside(&mine, draft.draft_id, TimestampMs::new(NOW + 1))
        .await
        .expect("fetched");
    assert_eq!(fetched.remote.text, draft.text);
    // What arrived is a draft on this device, under its own identity, saying which draft it sits
    // beside. Nothing submitted it, and the one path towards a submission is a question rather than
    // an action: it answers with the target a caller *would* send against, and sending is that
    // caller's own separate step.
    let copy: Draft = fetched.copy;
    assert_eq!(copy.conflict_of, Nullable::some(draft.draft_id));
    assert_eq!(copy.device_id, device(2));
    assert_eq!(copy.submission().expect("it answers"), &copy.target);

    // A copy whose application or binding has moved on is not submittable at all until a person
    // retargets it, which is the same rule reaching the same answer.
    let mut moved = copy.clone();
    moved.rebind(Some(&DraftTarget::session(SessionId::new(
        Uuid::from_bytes([3; 16]),
    ))));
    assert_eq!(
        moved.submission().expect_err("it is conflicted"),
        NotSubmittable::Conflicted
    );

    // The settings client refuses a draft before it asks the service, rather than growing a second
    // way to apply one.
    let object_id = SyncObjectId::new(draft.draft_id.get());
    let store = SyncStore::open(directory.path().join("settings")).expect("a store");
    let client = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        sealer,
        store,
    );
    assert!(matches!(
        client
            .fetch(SyncObjectKind::Draft, object_id, TimestampMs::new(NOW))
            .await,
        Err(SyncError::DraftElsewhere { .. })
    ));

    // And a settings collection that happens to hold a draft's bytes decodes as nothing this
    // module reads, so the refusal does not depend on the collection being honestly named.
    let (_, draft_bytes) = service
        .stored(&kr_client::drafts::draft_collection(draft.draft_id))
        .await
        .expect("the draft is stored");
    service
        .compare_exchange(
            &sync_collection(SyncObjectKind::Settings, object_id),
            fresh_request_id(),
            NOW,
            None,
            &draft_bytes,
        )
        .await
        .expect("stored under a settings name");
    assert!(matches!(
        client
            .fetch(SyncObjectKind::Settings, object_id, TimestampMs::new(NOW))
            .await,
        Err(SyncError::Encoding(_))
    ));
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13 and KR-REQ-24.28: one account per draft publication
// ---------------------------------------------------------------------------

/// What a draft in these tests is written for.
fn draft_target() -> DraftTarget {
    DraftTarget::session(SessionId::new(Uuid::from_bytes([3; 16]))).in_application(
        ApplicationInstanceId::new(Uuid::from_bytes([4; 16])),
        AgentBindingRevision::new(1),
    )
}

/// One device's drafts, over one directory: its draft store, its draft half over the device's
/// synchronisation store, and the settings client over that same store, which is the client
/// privacy mode drives.
///
/// Opening them again over the same directory is what a restart looks like: everything a process
/// held is gone and what is on disk is all there is.
fn draft_device(
    directory: &std::path::Path,
    service: Arc<dyn SyncBackupService>,
) -> (DraftStore, DraftSync, SyncClient) {
    let sealer: Arc<dyn DraftSealer> = Arc::new(DeviceSealer::new(0x5a));
    let drafts = DraftStore::open(directory.join("drafts"), device(2)).expect("a draft store");
    let sync = DraftSync::new(
        Arc::clone(&service),
        Arc::clone(&sealer),
        SyncStore::open(directory.join("sync")).expect("the device's sync store"),
    );
    let client = SyncClient::new(
        service,
        sealer,
        SyncStore::open(directory.join("sync")).expect("the same store"),
    );
    (drafts, sync, client)
}

/// The one record the device's store holds.
fn the_only_record(client: &SyncClient) -> RequestRecord {
    let requests = client.store().requests().expect("requests");
    assert!(requests.unreadable.is_empty());
    assert_eq!(
        requests.items.len(),
        1,
        "one publication, one record: {:?}",
        requests.items
    );
    requests.items[0].clone()
}

/// How many accounts of what left the device's store holds, of either kind.
fn accounts(client: &SyncClient) -> usize {
    let left = client.store().what_left().expect("what left");
    left.requests.len() + left.publications.len()
}

/// Another device's write of the same draft, sealed under the key every device of this suite shares.
fn their_write_of(draft: &Draft) -> (Draft, Vec<u8>) {
    let theirs = Draft {
        device_id: device(9),
        revision: DraftRevision::new(3),
        text: "what the other device had".to_owned(),
        ..draft.clone()
    };
    let sealed = DeviceSealer::new(0x5a)
        .seal(&DraftStore::encode_payload(&theirs).expect("canonical bytes"))
        .expect("sealed");
    (theirs, sealed)
}

#[tokio::test]
async fn a_draft_publication_keeps_one_account_in_the_store_settings_keep_theirs_in() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(
            draft_target(),
            "a prompt I have not sent".to_owned(),
            TimestampMs::new(NOW),
        )
        .expect("a draft");

    // The service applies the write and the answer never comes back.
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");

    // One record, in the store the settings client counts from, written before the call left and
    // naming exactly what the call carried.
    let record = the_only_record(&client);
    assert_eq!(record.kind, SyncObjectKind::Draft);
    assert_eq!(record.object_id, SyncObjectId::new(draft.draft_id.get()));
    assert_eq!(record.revision, RequestRevision::Draft(draft.revision));
    assert_eq!(record.collection(), draft_collection(draft.draft_id));
    assert!(record.dispatched());
    assert_eq!(
        record.signing_times(),
        Some((TimestampMs::new(NOW), TimestampMs::new(NOW)))
    );
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].request_id, record.work_id);
    assert_eq!(sent[0].collection, record.collection());
    assert_eq!(sent[0].signed_at_ms, NOW);
    assert_eq!(record.ciphertext(), Some(sent[0].ciphertext.as_slice()));

    // The barrier privacy mode measures counts it, and what left names it.
    assert_eq!(client.outstanding().expect("a count"), 1);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(
        exported[0]
            .kind
            .contains("synchronised draft, sent without an answer"),
        "{exported:?}"
    );
    assert!(
        exported[0]
            .reference
            .contains(&draft_collection(draft.draft_id))
    );
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));

    // And the draft is exactly as the person left it.
    assert_eq!(drafts.load(draft.draft_id).expect("the draft"), draft);
}

#[tokio::test]
async fn a_later_attempt_at_a_draft_publication_presents_its_identity_and_its_bytes() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");

    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");

    // The person asks again. It is the same publication, so it is the same request: the identity,
    // the bytes and the comparison are the first attempt's, and only the signing time is its own.
    let published = sync
        .publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW + 30),
        )
        .await
        .expect("answered");
    assert_eq!(published, DraftPublished::Accepted { position: at(1) });
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].request_id, sent[0].request_id);
    assert_eq!(sent[1].ciphertext, sent[0].ciphertext);
    assert_eq!(sent[1].expected, sent[0].expected);
    assert_eq!(sent[1].collection, sent[0].collection);
    assert_eq!(
        (sent[0].signed_at_ms, sent[1].signed_at_ms),
        (NOW, NOW + 30)
    );

    // The service answered from its receipt: the one write the first attempt made.
    assert_eq!(
        service.stored(&sent[0].collection).await.expect("stored").0,
        at(1)
    );
    assert_eq!(
        drafts.checkpoint(draft.draft_id).expect("a note"),
        Some(DraftCheckpoint {
            position: at(1),
            published_revision: Nullable::some(draft.revision),
        })
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let left = client.store().what_left().expect("what left");
    assert!(left.requests.is_empty());
    assert_eq!(left.publications.len(), 1, "one publication, one account");
    assert_eq!(left.publications.items[0].kind, SyncObjectKind::Draft);
    assert_eq!(
        left.publications.items[0].published_at_ms,
        TimestampMs::new(NOW),
        "the account says when the content first left"
    );

    // Edited since, it is other content and so another publication, under an identity of its own.
    let edited = drafts
        .update(
            &Draft {
                text: "a prompt, edited".to_owned(),
                ..draft.clone()
            },
            TimestampMs::new(NOW + 40),
        )
        .expect("an edit");
    assert_eq!(
        sync.publish(
            &drafts,
            edited.draft_id,
            edited.revision,
            TimestampMs::new(NOW + 50),
        )
        .await
        .expect("answered"),
        DraftPublished::Accepted { position: at(2) }
    );
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 3);
    assert_ne!(sent[2].request_id, sent[0].request_id);
    assert_eq!(sent[2].expected, Some(at(1)));
}

#[tokio::test]
async fn every_attempt_at_a_draft_publication_lies_between_the_two_instants_its_fence_carries() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");

    // Two attempts, neither of which arrives, the second signed on a clock that was put back.
    service.drop_the_next_request().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW + 10),
    )
    .await
    .expect_err("it never arrived");
    service.drop_the_next_request().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW + 5),
    )
    .await
    .expect_err("it never arrived");
    let record = the_only_record(&client);
    assert_eq!(
        record.signing_times(),
        Some((TimestampMs::new(NOW + 5), TimestampMs::new(NOW + 10))),
        "the earliest and the latest, not the first and the last"
    );
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].request_id, sent[1].request_id);
    assert_eq!(sent[0].ciphertext, sent[1].ciphertext);

    // Privacy mode moves past the generation that admitted it. The service holds no receipt, so the
    // cleanup fences the request, carrying both instants, and every attempt made lies between them.
    client.fence(1).expect("fenced");
    let cancelled = client
        .cancel_undispatched(1, TimestampMs::new(NOW + 20))
        .await
        .expect("cancelled");
    assert_eq!(
        service.fence_requests().await,
        vec![Fence {
            collection: draft_collection(draft.draft_id),
            request_id: record.work_id,
            first_signed_at_ms: NOW + 5,
            last_signed_at_ms: NOW + 10,
        }]
    );
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(
        cancelled.reconciled.accounts_kept, 0,
        "the service says nothing ran under it"
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(client.exported().expect("exported"), Vec::new());
}

#[tokio::test]
async fn a_stop_between_any_two_writes_of_a_draft_publication_leaves_one_account() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    assert_eq!(accounts(&client), 0, "nothing has been written yet");

    // Stopped after the record that says the content was sent, and before an answer. The content
    // may have left, so it is counted, and it is one account.
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");
    let dispatched = the_only_record(&client);
    let path = directory
        .path()
        .join("sync")
        .join(format!("{}.request", dispatched.work_id));
    assert_eq!(client.outstanding().expect("a count"), 1);
    assert_eq!(accounts(&client), 1);
    assert_eq!(client.exported().expect("exported").len(), 1);

    // Stopped after the note the answer moved, which the draft store holds, and before the answer
    // reached the record. The record is what counts, so the request is still waiting: one account.
    drafts
        .record_checkpoint(
            draft.draft_id,
            DraftCheckpoint {
                position: at(1),
                published_revision: Nullable::some(draft.revision),
            },
        )
        .expect("a note");
    assert_eq!(client.outstanding().expect("a count"), 1);
    assert_eq!(accounts(&client), 1);

    // Stopped after the answer reached the record and before the account it owes was written. The
    // request is over, so nothing counts it, and the next read writes the account: one entry.
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Applied { position: at(1) },
            ..dispatched.clone()
        },
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert_eq!(
        exported.len(),
        1,
        "one publication is one entry: {exported:?}"
    );
    assert!(exported[0].reference.contains("write 1"));
    assert!(
        exported[0]
            .reference
            .contains(&draft_collection(draft.draft_id))
    );
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
    assert!(!path.exists(), "the record goes once its account stands");

    // Stopped after the account was written and before the record went. Still one account.
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Applied { position: at(1) },
            ..dispatched.clone()
        },
    );
    assert_eq!(accounts(&client), 1);
    assert_eq!(client.exported().expect("exported").len(), 1);
    assert!(!path.exists());

    // The draft store has one draft and the note, and nothing of the publication beyond them.
    assert_eq!(
        drafts.list().expect("a listing").drafts,
        vec![draft.clone()]
    );
    assert_eq!(
        drafts
            .checkpoint(draft.draft_id)
            .expect("a note")
            .map(|note| note.position),
        Some(at(1))
    );
}

#[tokio::test]
async fn a_draft_publication_under_an_identity_another_request_wore_leaves_no_account() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");

    // The service compared these bytes with the receipt the identity already has and declined to
    // run them, so nothing of this publication is on the service and nothing will be.
    service.give_the_next_identity_to_another_request().await;
    let error = sync
        .publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW),
        )
        .await
        .expect_err("one identity, two requests");
    assert_eq!(error.code(), ErrorCode::IdConflict);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(accounts(&client), 0);
    assert_eq!(drafts.checkpoint(draft.draft_id).expect("a note"), None);
    assert_eq!(drafts.load(draft.draft_id).expect("the draft"), draft);
}

#[tokio::test]
async fn a_second_call_for_a_draft_publication_that_is_out_is_refused_rather_than_sent_beside_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let sync = Arc::new(sync);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");

    let first = tokio::spawn({
        let (sync, drafts) = (Arc::clone(&sync), drafts.clone());
        async move {
            sync.publish(
                &drafts,
                draft.draft_id,
                draft.revision,
                TimestampMs::new(NOW),
            )
            .await
        }
    });
    service.wait_for_a_publication().await;
    let record = the_only_record(&client);

    // The same publication, asked for again while its call is out. Sending it beside the first
    // would be one request twice with nobody able to say which answer came back.
    let error = sync
        .publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW + 1),
        )
        .await
        .expect_err("a call is out");
    assert!(
        matches!(error, SyncError::InFlight { work_id } if work_id == record.work_id),
        "{error:?}"
    );
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(
        the_only_record(&client),
        record,
        "nothing was written for it"
    );

    service.let_it_go();
    assert_eq!(
        first.await.expect("the task finished").expect("answered"),
        DraftPublished::Accepted { position: at(1) }
    );
    assert_eq!(service.inner.exchanges().await.len(), 1);
    assert_eq!(client.outstanding().expect("a count"), 0);
}

/// How far apart the attempts under one identity may be signed: one freshness window, so that a
/// receipt any of them left is certain to be at the service when another arrives.
const REPLAY_SPAN_MS: u64 = SERVICE_REQUEST_FRESHNESS_MS;

/// Sixty days, which is further ahead than any receipt is kept.
const TWO_MONTHS_MS: u64 = 60 * 24 * 60 * 60 * 1_000;

#[tokio::test]
async fn a_later_attempt_inside_the_span_presents_the_same_identity_and_is_answered_from_the_receipt()
 {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");
    let first = the_only_record(&client);

    // At the edge of the span the service still keeps the receipt, so an attempt under the same
    // identity is answered from it and nothing runs twice.
    let edge = NOW + REPLAY_SPAN_MS;
    service.its_clock_reads(edge).await;
    assert_eq!(
        sync.publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(edge),
        )
        .await
        .expect("answered from the receipt"),
        DraftPublished::Accepted { position: at(1) }
    );
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].request_id, first.work_id);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(accounts(&client), 1);
}

#[tokio::test]
async fn past_the_span_publishing_again_is_new_work_and_the_first_keeps_its_account() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    let collection = draft_collection(draft.draft_id);

    // The write lands and its answer is lost. What follows is what the identity would meet if it
    // were presented again after its receipt had gone: the receipt swept, and the object removed by
    // another device, so a comparison against nothing would hold again.
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");
    let first = the_only_record(&client);
    service.sweep_the_receipt(first.work_id).await;
    assert_eq!(
        service.remove(&collection).await,
        SyncPosition::removed_at(2)
    );

    // One instant past the span, the identity is not presented again: under it the same bytes could
    // run a second time, and the first attempt's account would become this one's. What is sent is
    // a new publication of the same content, under an identity of its own.
    let after = NOW + REPLAY_SPAN_MS + 1;
    service.its_clock_reads(after).await;
    assert_eq!(
        sync.publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(after),
        )
        .await
        .expect("answered"),
        DraftPublished::Accepted { position: at(3) }
    );
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 2);
    assert_ne!(
        sent[1].request_id, first.work_id,
        "the first identity is never presented again"
    );
    assert_ne!(
        sent[1].ciphertext, sent[0].ciphertext,
        "sealed again, as new work is"
    );

    // Both left this device and both are accounted for: the first as work nothing has yet
    // established the outcome of, the second as the publication it became.
    assert_eq!(client.outstanding().expect("a count"), 1);
    let requests = client.store().requests().expect("requests");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests.items[0], first, "the first account is untouched");
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 2, "{exported:?}");
    assert!(
        exported
            .iter()
            .any(|entry| entry.kind.contains("sent without an answer"))
    );
    assert!(
        exported
            .iter()
            .any(|entry| entry.kind == "synchronised draft" && entry.reference.contains("write 3"))
    );
}

#[tokio::test]
async fn an_attempt_signed_ahead_of_the_rest_keeps_its_identity_from_being_presented_again() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    let collection = draft_collection(draft.draft_id);

    // The first attempt is signed on a clock two months fast. The service refuses it as outside its
    // window, and nothing says where the envelope itself has got to.
    let ahead = NOW + TWO_MONTHS_MS;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(ahead),
    )
    .await
    .expect_err("outside the service's window");
    let first = the_only_record(&client);
    assert_eq!(
        first.signing_times(),
        Some((TimestampMs::new(ahead), TimestampMs::new(ahead)))
    );

    // The clock is corrected and the person asks again. The two attempts would be signed two months
    // apart, so a receipt of the second could be gone by the time the first becomes fresh: this is
    // new work under an identity of its own.
    assert_eq!(
        sync.publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW)
        )
        .await
        .expect("answered"),
        DraftPublished::Accepted { position: at(1) }
    );
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 2);
    assert_ne!(sent[1].request_id, first.work_id);

    // Two months on, the service has swept every receipt older than its retention, and the first
    // envelope arrives, fresh at last. It is its own request: it is compared against where the
    // object stands, refused, and kept by the service as a copy.
    service.sweep_the_receipt(sent[1].request_id).await;
    service.its_clock_reads(ahead).await;
    assert!(matches!(
        service
            .compare_exchange(
                &sent[0].collection,
                sent[0].request_id,
                sent[0].signed_at_ms,
                sent[0].expected,
                &sent[0].ciphertext,
            )
            .await
            .expect("answered"),
        SyncExchanged::Refused { .. }
    ));

    // Its own record settles it, so both envelopes are accounted for and neither ran twice.
    let reconciled = sync
        .reconcile_unsettled(&drafts, TimestampMs::new(ahead))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 2, "{exported:?}");
    assert!(
        exported
            .iter()
            .any(|entry| entry.kind == "synchronised draft")
    );
    assert!(
        exported
            .iter()
            .any(|entry| entry.kind.contains("kept as a copy by the service"))
    );
    assert_eq!(
        service.stored(&collection).await.expect("stored").0,
        at(1),
        "one write landed"
    );
}

/// Makes a directory readable and not writable, or writable again.
#[cfg(unix)]
fn writable(directory: &std::path::Path, writable: bool) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(
        directory,
        std::fs::Permissions::from_mode(if writable { 0o700 } else { 0o500 }),
    )
    .expect("the directory's mode");
}

#[cfg(unix)]
#[tokio::test]
async fn a_note_the_draft_store_cannot_write_leaves_the_draft_publication_counted_across_a_restart()
{
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");

    // The draft store can be read and not written, so the settlement reads the note and then fails
    // to write it. The note is written before the record that ends the request, so the request is
    // left waiting rather than ended without its note.
    let drafts_directory = directory.path().join("drafts");
    writable(&drafts_directory, false);
    let failed = sync
        .reconcile_unsettled(&drafts, TimestampMs::new(NOW + 1))
        .await;
    writable(&drafts_directory, true);
    failed.expect_err("the note could not be written");
    assert!(the_only_record(&client).dispatched());
    assert_eq!(client.outstanding().expect("a count"), 1);
    assert!(
        client.store().publications().expect("records").is_empty(),
        "nothing was ended without its note"
    );
    assert_eq!(drafts.checkpoint(draft.draft_id).expect("a note"), None);

    // A process that starts again finds the request still waiting, and settles it once.
    drop((drafts, sync, client));
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let reconciled = sync
        .reconcile_unsettled(&drafts, TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(accounts(&client), 1);
    assert_eq!(
        drafts.checkpoint(draft.draft_id).expect("a note"),
        Some(DraftCheckpoint {
            position: at(1),
            published_revision: Nullable::some(draft.revision),
        })
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_draft_publication_stopped_between_its_note_and_its_end_is_settled_once_after_a_restart()
{
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");

    // The sync store can be read and not written, so the note is written in the draft store and
    // then the record that ends the request cannot be. That leaves the note ahead of a request that
    // is still counted, which is the one arrangement a stop between the two writes can leave.
    let sync_directory = directory.path().join("sync");
    writable(&sync_directory, false);
    let failed = sync
        .reconcile_unsettled(&drafts, TimestampMs::new(NOW + 1))
        .await;
    writable(&sync_directory, true);
    failed.expect_err("the end of the request could not be recorded");
    assert!(the_only_record(&client).dispatched());
    assert_eq!(client.outstanding().expect("a count"), 1);
    let note = DraftCheckpoint {
        position: at(1),
        published_revision: Nullable::some(draft.revision),
    };
    assert_eq!(
        drafts.checkpoint(draft.draft_id).expect("a note"),
        Some(note)
    );

    // After a restart the next pass settles it once, and the note it meets is the same write.
    drop((drafts, sync, client));
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let reconciled = sync
        .reconcile_unsettled(&drafts, TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.diverged, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(accounts(&client), 1);
    assert_eq!(
        drafts.checkpoint(draft.draft_id).expect("a note"),
        Some(note)
    );
}

#[tokio::test]
async fn a_later_attempt_presents_its_own_comparison_after_the_note_has_moved() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "mine".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");

    // The first attempt never arrives. Another device then writes, and a fetch moves the note.
    service.drop_the_next_request().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("it never arrived");
    let (theirs, sealed) = their_write_of(&draft);
    service
        .compare_exchange(
            &draft_collection(draft.draft_id),
            fresh_request_id(),
            NOW,
            None,
            &sealed,
        )
        .await
        .expect("the other device's write");
    sync.fetch_beside(&drafts, draft.draft_id, TimestampMs::new(NOW + 1))
        .await
        .expect("fetched");

    // The later attempt is the same request, comparison included, because a service compares a
    // retry against its receipt by all of it. Against where the object now stands that comparison
    // is refused, and the refusal settles the publication and brings the other content down.
    let published = sync
        .publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW + 2),
        )
        .await
        .expect("answered");
    let sent = service.exchanges().await;
    let mine: Vec<&Exchange> = sent
        .iter()
        .filter(|exchange| exchange.request_id == the_first_identity(&sent))
        .collect();
    assert_eq!(mine.len(), 2, "both attempts, one identity");
    assert_eq!(
        mine[1].expected, None,
        "the comparison it was admitted with"
    );
    assert_eq!(mine[1].ciphertext, mine[0].ciphertext);
    assert!(
        matches!(published, DraftPublished::Conflicted { position, remote_revision, .. }
            if position == at(1) && remote_revision == theirs.revision),
        "{published:?}"
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(drafts.load(draft.draft_id).expect("the draft"), draft);
}

/// The identity this device's first exchange presented.
fn the_first_identity(sent: &[Exchange]) -> Uuid {
    sent.first().expect("an exchange").request_id
}

#[tokio::test]
async fn a_later_attempt_after_the_caller_dropped_the_first_call_presents_the_same_request() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let sync = Arc::new(sync);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");

    // The first call is held at the wire and its caller walks away. Dropping the call releases the
    // dispatch; it says nothing about the request, which stays counted.
    let first = tokio::spawn({
        let (sync, drafts) = (Arc::clone(&sync), drafts.clone());
        async move {
            sync.publish(
                &drafts,
                draft.draft_id,
                draft.revision,
                TimestampMs::new(NOW),
            )
            .await
        }
    });
    service.wait_for_a_publication().await;
    let record = the_only_record(&client);
    first.abort();
    assert!(
        first.await.expect_err("dropped").is_cancelled(),
        "the call was dropped"
    );
    assert_eq!(client.outstanding().expect("a count"), 1);

    // Asking again is a later attempt at the same publication, which nothing now holds.
    let second = tokio::spawn({
        let (sync, drafts) = (Arc::clone(&sync), drafts.clone());
        async move {
            sync.publish(
                &drafts,
                draft.draft_id,
                draft.revision,
                TimestampMs::new(NOW + 1),
            )
            .await
        }
    });
    service.wait_for_a_publication().await;
    service.let_it_go();
    assert_eq!(
        second.await.expect("the task finished").expect("answered"),
        DraftPublished::Accepted { position: at(1) }
    );
    let sent = service.inner.exchanges().await;
    assert_eq!(sent.len(), 1, "the dropped call never reached the service");
    assert_eq!(sent[0].request_id, record.work_id);
    assert_eq!(sent[0].signed_at_ms, NOW + 1);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(accounts(&client), 1);
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13 and KR-REQ-24.28: a draft publication whose answer was lost
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_restart_between_the_dispatch_and_the_answer_settles_the_draft_by_asking_about_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let draft = {
        let (drafts, sync, _) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
        let draft = drafts
            .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
            .expect("a draft");
        service.lose_the_next_answer().await;
        sync.publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW),
        )
        .await
        .expect_err("the answer never came back");
        draft
    };

    // The process ends and a new one opens the same stores. What is on disk is all it has.
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    assert_eq!(client.outstanding().expect("a count"), 1);
    let record = the_only_record(&client);

    let reconciled = sync
        .reconcile_unsettled(&drafts, TimestampMs::new(NOW + 60))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.unresolved, 0);
    assert_eq!(reconciled.unsettled, 0);
    // It asked about the request's own identity, and sent nothing again.
    assert_eq!(
        service.status_queries().await,
        vec![(draft_collection(draft.draft_id), record.work_id)]
    );
    assert_eq!(service.exchanges().await.len(), 1);

    // The note moved to where the receipt says this write left the draft, naming this revision.
    assert_eq!(
        drafts.checkpoint(draft.draft_id).expect("a note"),
        Some(DraftCheckpoint {
            position: at(1),
            published_revision: Nullable::some(draft.revision),
        })
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].kind, "synchronised draft");
    assert!(exported[0].reference.contains("write 1"));

    // A settled draft is still a draft nobody sent. The text is the person's, and the one path
    // towards a submission answers a question and performs nothing.
    let held = drafts.load(draft.draft_id).expect("the draft");
    assert_eq!(held, draft);
    assert_eq!(held.submission(), Ok(&draft.target));
}

#[tokio::test]
async fn a_lost_answer_to_a_draft_the_service_refused_brings_the_other_content_down_beside_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "mine".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    let (theirs, sealed) = their_write_of(&draft);
    service
        .compare_exchange(
            &draft_collection(draft.draft_id),
            fresh_request_id(),
            NOW,
            None,
            &sealed,
        )
        .await
        .expect("the other device's write");

    // This device's comparison is refused, and the answer is lost on its way back.
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");
    assert_eq!(client.outstanding().expect("a count"), 1);

    let reconciled = sync
        .reconcile_unsettled(&drafts, TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.copies_not_taken, 0);
    assert_eq!(reconciled.unsettled, 0);

    // The local draft is exactly as it was, and the other device's content is beside it.
    assert_eq!(drafts.load(draft.draft_id).expect("the draft"), draft);
    let listing = drafts.list().expect("a listing");
    assert_eq!(listing.drafts.len(), 2);
    let copy = listing
        .drafts
        .iter()
        .find(|held| held.draft_id != draft.draft_id)
        .expect("the copy");
    assert_eq!(copy.conflict_of, Nullable::some(draft.draft_id));
    assert_eq!(copy.text, theirs.text);
    assert_eq!(
        copy.retained.as_ref().copied(),
        service
            .copies_in(&draft_collection(draft.draft_id))
            .await
            .first()
            .copied(),
        "the copy names what the service kept of the write it beat"
    );
    assert_eq!(
        drafts.checkpoint(draft.draft_id).expect("a note"),
        Some(DraftCheckpoint {
            position: at(1),
            published_revision: Nullable::null(),
        }),
        "the note names where the other device's write stands, and no revision of this device's"
    );

    // The service kept the refused write, so the account of it stays and says it can be dropped.
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].kind.contains("kept as a copy by the service"));
    assert!(exported[0].deletable);
}

#[tokio::test]
async fn a_draft_publication_the_service_holds_no_receipt_for_stays_counted_under_its_generation() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    service.drop_the_next_request().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("it never arrived");

    // Each pass asks, and while the generation that admitted it is in force nothing ends it.
    for pass in 1..=2 {
        let reconciled = sync
            .reconcile_unsettled(&drafts, TimestampMs::new(NOW + pass))
            .await
            .expect("reconciled");
        assert_eq!(reconciled.unresolved, 1);
        assert_eq!(reconciled.settled + reconciled.fenced, 0);
        assert_eq!(reconciled.unsettled, 1);
    }
    assert_eq!(service.status_queries().await.len(), 2);
    assert!(service.fence_requests().await.is_empty());

    // The settings client leaves a draft under its generation to the draft half: it asks nothing,
    // and it counts the draft as the barrier still waiting.
    let by_settings = client
        .reconcile_unsettled(TimestampMs::new(NOW + 3))
        .await
        .expect("reconciled");
    assert_eq!(by_settings.unresolved, 1);
    assert_eq!(by_settings.unsettled, 1);
    assert_eq!(service.status_queries().await.len(), 2);
    assert_eq!(client.outstanding().expect("a count"), 1);
    assert_eq!(drafts.checkpoint(draft.draft_id).expect("a note"), None);
}

#[tokio::test]
async fn a_draft_publication_privacy_mode_has_moved_past_is_ended_by_the_settings_clients_cleanup()
{
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);

    // One publication applied with its answer lost, and one that never arrived.
    let landed = drafts
        .create(draft_target(), "landed".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        landed.draft_id,
        landed.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");
    let lost = drafts
        .create(draft_target(), "lost".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    service.drop_the_next_request().await;
    sync.publish(&drafts, lost.draft_id, lost.revision, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");
    assert_eq!(client.outstanding().expect("a count"), 2);

    // A service that cannot be asked to end a request leaves the barrier where it was.
    client.fence(3).expect("fenced");
    service.stop_fencing_requests().await;
    let unreachable = client
        .cancel_undispatched(3, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(unreachable.reconciled.settled, 1, "the receipt answered");
    assert_eq!(unreachable.reconciled.unresolved, 1);
    assert_eq!(unreachable.in_flight, 1);

    // Once it can be, the cleanup ends it: the status query finds no receipt, and the fence in the
    // same pass says nothing ran, so nothing of it is anywhere.
    service.answer_fences_again().await;
    let cancelled = client
        .cancel_undispatched(3, TimestampMs::new(NOW + 2))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(cancelled.reconciled.accounts_kept, 0);
    assert_eq!(cancelled.in_flight, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);

    // The one that landed is the account of what left, and neither answer moved a note: both
    // belong to a generation privacy mode has closed.
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1, "{exported:?}");
    assert!(
        exported[0]
            .reference
            .contains(&draft_collection(landed.draft_id))
    );
    assert_eq!(drafts.checkpoint(landed.draft_id).expect("a note"), None);
    assert_eq!(drafts.checkpoint(lost.draft_id).expect("a note"), None);
}

#[tokio::test]
async fn a_draft_publication_fenced_after_its_receipt_was_swept_keeps_the_account_of_what_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");
    service
        .sweep_the_receipt(the_only_record(&client).work_id)
        .await;

    // Long enough later that nothing depends on how soon the fence follows. The service swept a
    // receipt an attempt under this identity could have borne, so it cannot say nothing ran: the
    // fence still ends the request, and the account stays.
    let after = NOW + A_LONG_TIME_MS;
    service.its_clock_reads(after).await;
    client.fence(2).expect("fenced");
    let cancelled = client
        .cancel_undispatched(2, TimestampMs::new(after))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(cancelled.reconciled.accounts_kept, 1);
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].kind.contains("never accounted for"));
    assert!(
        exported[0]
            .reference
            .contains(&draft_collection(draft.draft_id))
    );
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
}

#[tokio::test]
async fn an_answer_about_a_draft_that_is_older_news_never_moves_its_note_back() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "mine".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");

    // This device's write lands at the first place and its answer is lost. Another device then
    // writes over it, and a fetch brings that down, so the note names the second place.
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");
    let (_, sealed) = their_write_of(&draft);
    service
        .compare_exchange(
            &draft_collection(draft.draft_id),
            fresh_request_id(),
            NOW,
            Some(at(1)),
            &sealed,
        )
        .await
        .expect("the other device's write");
    sync.fetch_beside(&drafts, draft.draft_id, TimestampMs::new(NOW + 1))
        .await
        .expect("fetched");
    let learnt = DraftCheckpoint {
        position: at(2),
        published_revision: Nullable::null(),
    };
    assert_eq!(
        drafts.checkpoint(draft.draft_id).expect("a note"),
        Some(learnt)
    );

    // The lost answer is settled now, and it is about the write before the one the note names. It
    // is recorded as what left, and the note stays where the later answer put it.
    let reconciled = sync
        .reconcile_unsettled(&drafts, TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.diverged, 0, "older news is not another history");
    assert_eq!(
        drafts.checkpoint(draft.draft_id).expect("a note"),
        Some(learnt)
    );
    let published = client.store().publications().expect("records");
    assert_eq!(published.len(), 1);
    assert_eq!(published.items[0].position, at(1));
}

#[tokio::test]
async fn an_accepted_draft_answered_at_the_place_it_replaced_is_never_recorded_as_applied() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "one".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    assert_eq!(
        sync.publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW)
        )
        .await
        .expect("published"),
        DraftPublished::Accepted { position: at(1) }
    );
    let note = drafts
        .checkpoint(draft.draft_id)
        .expect("a note")
        .expect("one was written");

    // The next write is accepted at the very place it replaced, under another name: a service
    // whose history forked. It is not a later state of the draft this device published.
    let edited = drafts
        .update(
            &Draft {
                text: "two".to_owned(),
                ..draft.clone()
            },
            TimestampMs::new(NOW + 1),
        )
        .expect("an edit");
    let forked_at = SyncPosition::at(1, SyncRevision::new(Uuid::from_bytes([0xee; 16])));
    service.applies_the_next_write_at(forked_at).await;
    let error = sync
        .publish(
            &drafts,
            edited.draft_id,
            edited.revision,
            TimestampMs::new(NOW + 1),
        )
        .await
        .expect_err("another history");
    assert!(
        matches!(error, SyncError::ForkedHistory { found, .. } if found == forked_at),
        "{error:?}"
    );

    // The request's own record keeps the account of what left, the note stays where this device's
    // own write left it, and nothing is counted as waiting.
    assert_eq!(
        the_only_record(&client).state,
        RequestState::Diverged {
            position: forked_at
        }
    );
    assert_eq!(
        drafts.checkpoint(draft.draft_id).expect("a note"),
        Some(note)
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert!(
        client
            .exported()
            .expect("exported")
            .iter()
            .any(|entry| entry.kind.contains("under another history"))
    );
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13: the copy the service kept of a refused draft
// ---------------------------------------------------------------------------

/// A draft this device publishes after another device has written the same draft, so the
/// comparison is refused and the service keeps this device's write as a copy of its own.
async fn a_refused_draft(
    directory: &std::path::Path,
    service: &Arc<Service>,
) -> (DraftStore, DraftSync, SyncClient, Draft, Draft) {
    let (drafts, sync, client) = draft_device(directory, Arc::clone(service) as Arc<_>);
    let draft = drafts
        .create(draft_target(), "mine".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    let (theirs, sealed) = their_write_of(&draft);
    service
        .compare_exchange(
            &draft_collection(draft.draft_id),
            fresh_request_id(),
            NOW,
            None,
            &sealed,
        )
        .await
        .expect("the other device's write");
    (drafts, sync, client, draft, theirs)
}

#[tokio::test]
async fn a_refused_draft_names_the_copy_the_service_kept_on_the_copy_kept_beside_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client, draft, theirs) = a_refused_draft(directory.path(), &service).await;
    let collection = draft_collection(draft.draft_id);

    let published = sync
        .publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW),
        )
        .await
        .expect("answered");
    let DraftPublished::Conflicted {
        copy,
        remote_revision,
        position,
    } = published
    else {
        panic!("another device wrote first: {published:?}");
    };
    assert_eq!(position, at(1));
    assert_eq!(remote_revision, theirs.revision);

    // The service kept this device's refused write, and the copy that beat it names that copy: the
    // two sides of one choice.
    let kept = service.copies_in(&collection).await;
    assert_eq!(kept.len(), 1);
    let copy = drafts.load(copy).expect("the copy");
    assert_eq!(copy.conflict_of, Nullable::some(draft.draft_id));
    assert_eq!(copy.retained, Nullable::some(kept[0]));
    assert_eq!(copy.text, theirs.text);

    // The refusal's own record is the account of what the service still holds, and it can be
    // dropped; the person's draft is exactly as it was.
    let record = the_only_record(&client);
    assert_eq!(
        record.state,
        RequestState::Refused {
            retained: Nullable::some(kept[0]),
        }
    );
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains(&kept[0].to_string()));
    assert!(exported[0].reference.contains(&collection));
    assert!(exported[0].deletable);
    assert_eq!(drafts.load(draft.draft_id).expect("the draft"), draft);
}

#[tokio::test]
async fn the_persons_choice_about_a_draft_copy_leaves_no_copy_on_either_side() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client, draft, _) = a_refused_draft(directory.path(), &service).await;
    let collection = draft_collection(draft.draft_id);
    let DraftPublished::Conflicted { copy, .. } = sync
        .publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW),
        )
        .await
        .expect("answered")
    else {
        panic!("another device wrote first");
    };

    // The person keeps their own draft. The copy goes from this device, and the copy the service
    // kept of the write it beat goes from the service.
    let resolved = sync
        .resolve(&drafts, copy)
        .await
        .expect("resolved")
        .expect("there was such a copy");
    assert_eq!(resolved.copy.draft_id, copy);
    assert_eq!(
        resolved.service,
        Resolutions {
            dropped: 1,
            pending: 0,
        }
    );
    assert!(service.copies_in(&collection).await.is_empty());
    assert_eq!(
        drafts.list().expect("a listing").drafts,
        vec![draft.clone()],
        "the person's draft, and nothing beside it"
    );
    assert!(client.store().requests().expect("requests").is_empty());
    assert_eq!(client.exported().expect("exported"), Vec::new());
    assert_eq!(client.outstanding().expect("a count"), 0);

    // Choosing about a copy that is already gone, or about a draft that is no copy, is nothing.
    assert!(
        sync.resolve(&drafts, copy)
            .await
            .expect("answered")
            .is_none()
    );
    assert!(
        sync.resolve(&drafts, draft.draft_id)
            .await
            .expect("answered")
            .is_none()
    );
    assert_eq!(drafts.load(draft.draft_id).expect("the draft"), draft);
}

#[tokio::test]
async fn a_choice_about_a_draft_copy_the_service_cannot_hear_yet_stays_recorded() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client, draft, _) = a_refused_draft(directory.path(), &service).await;
    let collection = draft_collection(draft.draft_id);
    let DraftPublished::Conflicted { copy, .. } = sync
        .publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW),
        )
        .await
        .expect("answered")
    else {
        panic!("another device wrote first");
    };

    // The choice is recorded before the service is asked, so a service that cannot be told leaves
    // the choice made: the copy is gone here, and the service's copy is still named as to go.
    service.stop_dropping_copies().await;
    let resolved = sync
        .resolve(&drafts, copy)
        .await
        .expect("resolved")
        .expect("there was such a copy");
    assert_eq!(
        resolved.service,
        Resolutions {
            dropped: 0,
            pending: 1,
        }
    );
    assert_eq!(drafts.list().expect("a listing").drafts.len(), 1);
    assert_eq!(service.copies_in(&collection).await.len(), 1);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].deletable);

    // The settings client asks again for every choice recorded in the store it shares, and asks
    // about the draft's copy in the draft's own collection.
    service.drop_copies_again().await;
    assert_eq!(
        client.finish_resolutions().await.expect("asked"),
        Resolutions {
            dropped: 1,
            pending: 0,
        }
    );
    assert!(service.copies_in(&collection).await.is_empty());
    assert_eq!(client.exported().expect("exported"), Vec::new());
}

#[tokio::test]
async fn a_stop_anywhere_after_a_draft_is_refused_leaves_one_account_of_the_copy_the_service_kept()
{
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client, draft, theirs) = a_refused_draft(directory.path(), &service).await;
    let collection = draft_collection(draft.draft_id);

    // The comparison is refused and the answer is lost, so the record says only that it was sent.
    service.lose_the_next_answer().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the answer never came back");
    let dispatched = the_only_record(&client);
    let kept = service.copies_in(&collection).await;
    assert_eq!(kept.len(), 1);
    let path = directory
        .path()
        .join("sync")
        .join(format!("{}.request", dispatched.work_id));

    // Stopped after the refusal reached the record and before anything came down. The record is
    // the account of the copy the service holds: nothing is waiting, and it can be dropped.
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Refused {
                retained: Nullable::some(kept[0]),
            },
            ..dispatched.clone()
        },
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(accounts(&client), 1);
    assert_eq!(drafts.list().expect("a listing").drafts.len(), 1);

    // Stopped after the copy was kept beside the draft and before the note. The copy names the
    // service's copy, and the account is still the one record.
    let copy = drafts
        .keep_copy(
            draft.draft_id,
            &theirs,
            Some(kept[0]),
            TimestampMs::new(NOW),
        )
        .expect("a copy");
    assert_eq!(accounts(&client), 1);
    assert_eq!(client.exported().expect("exported").len(), 1);

    // And after the note: still one account, until the person chooses.
    drafts
        .record_checkpoint(
            draft.draft_id,
            DraftCheckpoint {
                position: at(1),
                published_revision: Nullable::null(),
            },
        )
        .expect("a note");
    assert_eq!(accounts(&client), 1);
    sync.resolve(&drafts, copy.draft_id)
        .await
        .expect("resolved")
        .expect("there was such a copy");
    assert_eq!(accounts(&client), 0);
    assert!(service.copies_in(&collection).await.is_empty());
}

#[tokio::test]
async fn a_refusal_whose_other_content_never_came_down_is_still_dropped_on_request() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (drafts, sync, client, draft, _) = a_refused_draft(directory.path(), &service).await;
    let collection = draft_collection(draft.draft_id);

    // The refusal is settled but the other content cannot be brought down, so no copy sits beside
    // the draft to choose about. The account of the service's copy stands on its own.
    service.stop_serving_what_it_holds().await;
    sync.publish(
        &drafts,
        draft.draft_id,
        draft.revision,
        TimestampMs::new(NOW),
    )
    .await
    .expect_err("the copy could not be brought down");
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(drafts.list().expect("a listing").drafts.len(), 1);
    let kept = service.copies_in(&collection).await;
    assert_eq!(kept.len(), 1);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].deletable);

    // Asking for exactly that copy to go is the explicit deletion section 24 offers.
    assert_eq!(
        client
            .drop_kept_copy(kept[0])
            .await
            .expect("asked")
            .expect("this device holds that refusal"),
        Resolutions {
            dropped: 1,
            pending: 0,
        }
    );
    assert!(service.copies_in(&collection).await.is_empty());
    assert_eq!(client.exported().expect("exported"), Vec::new());
    assert_eq!(drafts.load(draft.draft_id).expect("the draft"), draft);
}

// ---------------------------------------------------------------------------
// KR-REQ-24.28: privacy mode reaches draft publications
// ---------------------------------------------------------------------------

#[tokio::test]
async fn privacy_enabled_while_a_draft_publication_is_in_flight_publishes_no_late_result() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let sync = Arc::new(sync);
    let draft = drafts
        .create(draft_target(), "a prompt".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");

    // The publication leaves and waits at the service.
    let publishing = tokio::spawn({
        let (sync, drafts) = (Arc::clone(&sync), drafts.clone());
        async move {
            sync.publish(
                &drafts,
                draft.draft_id,
                draft.revision,
                TimestampMs::new(NOW),
            )
            .await
        }
    });
    service.wait_for_a_publication().await;
    assert_eq!(client.outstanding().expect("a count"), 1, "it has left");

    // Privacy mode is enabled while it is in flight, through the client the host drives. Nothing of
    // a draft waits between admission and dispatch for a cancellation to take back, and the one in
    // flight is counted rather than hidden: only the device making the call can tell it from one
    // that never arrived.
    client.fence(5).expect("fenced");
    let cancelled = client
        .cancel_undispatched(5, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.undispatched, 0);
    assert_eq!(cancelled.in_flight, 1);
    assert_eq!(cancelled.reconciled.unresolved, 1);

    // The answer comes back for a publication admitted under the generation before. It is not
    // published, and the note beside the draft does not move.
    service.let_it_go();
    assert_eq!(
        publishing
            .await
            .expect("the task finished")
            .expect("answered"),
        DraftPublished::Discarded {
            produced_under: 0,
            current: 5,
        }
    );
    assert_eq!(drafts.checkpoint(draft.draft_id).expect("a note"), None);

    // The upload happened, and the device says so rather than pretending it did not. Cleanup is
    // complete once nothing is outstanding, and removing retained content leaves this account.
    assert_eq!(client.outstanding().expect("a count"), 0);
    let removed = client
        .remove_retained(5, TimestampMs::new(NOW + 2))
        .await
        .expect("removed");
    assert_eq!(removed.records, 0);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].kind, "synchronised draft");
    assert!(exported[0].reference.contains("write 1"));
    assert!(!exported[0].deletable);

    // While privacy mode is on, no draft is published and none is fetched, and nothing is sent.
    let sent = service.inner.exchanges().await.len();
    assert!(matches!(
        sync.publish(
            &drafts,
            draft.draft_id,
            draft.revision,
            TimestampMs::new(NOW + 3),
        )
        .await,
        Err(SyncError::Fenced { generation: 5 })
    ));
    assert!(matches!(
        sync.fetch_beside(&drafts, draft.draft_id, TimestampMs::new(NOW + 3))
            .await,
        Err(SyncError::Fenced { generation: 5 })
    ));
    assert_eq!(service.inner.exchanges().await.len(), sent);
    assert_eq!(client.outstanding().expect("a count"), 0);

    // The draft is the person's, exactly as they left it, and nothing on this path submitted it.
    let held = drafts.load(draft.draft_id).expect("the draft");
    assert_eq!(held, draft);
    assert_eq!(held.submission(), Ok(&draft.target));
}

#[tokio::test]
async fn a_fetch_whose_answer_arrives_after_privacy_is_enabled_keeps_nothing() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let (drafts, sync, client) = draft_device(directory.path(), Arc::clone(&service) as Arc<_>);
    let sync = Arc::new(sync);
    let draft = drafts
        .create(draft_target(), "mine".to_owned(), TimestampMs::new(NOW))
        .expect("a draft");
    let (_, sealed) = their_write_of(&draft);
    service
        .inner
        .compare_exchange(
            &draft_collection(draft.draft_id),
            fresh_request_id(),
            NOW,
            None,
            &sealed,
        )
        .await
        .expect("the other device's write");

    // The service answers the fetch, and the answer is held on its way back.
    service.hold_the_next_fetch().await;
    let fetching = tokio::spawn({
        let (sync, drafts) = (Arc::clone(&sync), drafts.clone());
        async move {
            sync.fetch_beside(&drafts, draft.draft_id, TimestampMs::new(NOW + 1))
                .await
        }
    });
    service.wait_for_a_publication().await;

    // Privacy mode is enabled before the answer lands, so what it brought is not kept: no copy
    // beside the draft and no note, both of which would be content the cleanup had just removed.
    client.fence(2).expect("fenced");
    service.let_it_go();
    assert!(matches!(
        fetching.await.expect("the task finished"),
        Err(SyncError::LateResult {
            produced_under: 0,
            current: 2,
        })
    ));
    assert_eq!(
        drafts.list().expect("a listing").drafts,
        vec![draft.clone()]
    );
    assert_eq!(drafts.checkpoint(draft.draft_id).expect("a note"), None);
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13: a checkpoint the service no longer holds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_service_that_was_reset_leaves_a_checkpoint_only_an_explicit_step_clears() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);

    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // The service is reset or replaced. The note names a write nothing holds, the comparison
    // is refused, and the fetch that would have brought the other content down finds nothing. This
    // device cannot tell an absent object from a service it could not reach, so the refusal is the
    // service's own rather than a diagnosis it has not earned.
    service.reset().await;
    let refused = client
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect_err("the comparison is lost and the fetch finds nothing");
    assert!(
        matches!(refused, SyncError::Client(_)),
        "an unreachable object is reported as it came: {refused}"
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_some(),
        "nothing clears the note automatically"
    );

    // Forgetting it is the explicit recovery, and it costs a comparison rather than a setting.
    client
        .store()
        .forget_checkpoint(object_id)
        .expect("forgotten");
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("published"),
        Published::Accepted { position: at(1) }
    );
}

#[test]
fn a_note_is_never_replaced_by_an_answer_that_does_not_follow_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let object_id = fresh_object_id().expect("an identity");
    let forked = SyncPosition::at(5, SyncRevision::new(Uuid::from_bytes([0xf0; 16])));

    let note = |position| SyncCheckpoint {
        position,
        published_revision: Nullable::null(),
    };
    assert!(
        store
            .record_checkpoint(object_id, note(at(5)))
            .expect("a note")
    );

    // One write sequence names one write for the life of a collection, so an answer naming the
    // same place under another name comes from a second history rather than from a later write.
    // The note this device established stands, and so does the account of what it published.
    assert!(
        !store
            .record_checkpoint(object_id, note(forked))
            .expect("a note")
    );
    assert!(
        !store
            .record_checkpoint(object_id, note(at(4)))
            .expect("a note")
    );
    assert_eq!(
        store
            .checkpoint(object_id)
            .expect("a note")
            .expect("one stands")
            .position,
        at(5)
    );

    let published = |position| Publication {
        object_id,
        kind: SyncObjectKind::Settings,
        position,
        published_at_ms: TimestampMs::new(NOW),
    };
    assert!(
        store
            .record_publication(&published(at(5)))
            .expect("a record")
    );
    assert!(
        !store
            .record_publication(&published(forked))
            .expect("a record")
    );
    assert_eq!(
        store.publications().expect("records").items[0].position,
        at(5)
    );

    // A later write still lands, on both.
    assert!(
        store
            .record_checkpoint(object_id, note(at(6)))
            .expect("a note")
    );
    assert!(
        store
            .record_publication(&published(at(6)))
            .expect("a record")
    );
}

#[tokio::test]
async fn a_service_holding_another_write_in_the_same_place_says_the_history_forked() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    let collection = sync_collection(SyncObjectKind::Settings, object_id);

    // The collection is rebuilt somewhere else and reaches the same place in the order under
    // another name. One write sequence names one write for the life of a collection, so this is
    // two histories rather than one, and the note beside this object belongs to the other.
    let (position, ciphertext) = service.stored(&collection).await.expect("it is stored");
    service
        .hold(
            &collection,
            SyncPosition::at(
                position.write_sequence,
                SyncRevision::new(Uuid::from_bytes([0xf0; 16])),
            ),
            ciphertext,
        )
        .await;

    let refused = client
        .fetch(
            SyncObjectKind::Settings,
            object_id,
            TimestampMs::new(NOW + 1),
        )
        .await
        .expect_err("the service holds another write in the same place");
    assert!(
        matches!(
            refused,
            SyncError::ForkedHistory {
                expected: SyncPosition {
                    write_sequence: 1,
                    ..
                },
                ..
            }
        ),
        "the refusal says which of the two things went wrong: {refused}"
    );
    assert_eq!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("the write left one")
            .position,
        at(1),
        "nothing writes a note from a history this device cannot follow"
    );

    // Forgetting the note is the explicit recovery here as well, and the fetch then succeeds.
    client
        .store()
        .forget_checkpoint(object_id)
        .expect("forgotten");
    client
        .fetch(
            SyncObjectKind::Settings,
            object_id,
            TimestampMs::new(NOW + 2),
        )
        .await
        .expect("fetched");
}

#[tokio::test]
async fn a_removal_keeps_its_place_in_the_order_and_the_write_after_it_names_no_object() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mut mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    let collection = sync_collection(SyncObjectKind::Settings, object_id);

    // Another device removes the object. The removal takes the next place in the collection's
    // order, and this device's note records that place: an object that is not there is not the
    // same thing as an object that has never been there, and the difference is the order.
    let removed = service.remove(&collection).await;
    assert_eq!(removed, SyncPosition::removed_at(2));
    let note = |position| SyncCheckpoint {
        position,
        published_revision: Nullable::null(),
    };
    assert!(
        client
            .store()
            .record_checkpoint(object_id, note(removed))
            .expect("a note")
    );
    assert!(
        client
            .store()
            .record_checkpoint(object_id, note(removed))
            .expect("a note"),
        "one removal said twice is the same answer, not a second history"
    );

    // A write claiming the removal's own place is two histories, exactly as two writes claiming one
    // place are, and a write behind it is a service that has gone back.
    assert!(
        !client
            .store()
            .record_checkpoint(
                object_id,
                note(SyncPosition::at(
                    2,
                    SyncRevision::new(Uuid::from_bytes([0xf0; 16])),
                )),
            )
            .expect("a note")
    );
    let (_, ciphertext) = service
        .stored(&sync_collection(SyncObjectKind::Settings, object_id))
        .await
        .unwrap_or((at(1), Vec::new()));
    service.hold(&collection, at(1), ciphertext).await;
    let refused = client
        .fetch(
            SyncObjectKind::Settings,
            object_id,
            TimestampMs::new(NOW + 1),
        )
        .await
        .expect_err("the service is behind the removal this device recorded");
    assert!(
        matches!(refused, SyncError::StaleCheckpoint { expected: 2, .. }),
        "the removal's place in the order is what the answer is measured against: {refused}"
    );

    // The next publication compares against the removal, which names **no object**: the service's
    // order carries on from the removal, so the write lands at the place after it.
    service.remove(&collection).await;
    mine.revision = fresh_revision().expect("a revision");
    client.store().put_object(&mine).expect("stored");
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("published"),
        Published::Accepted { position: at(3) }
    );
    let sent = service.exchanges().await;
    let last = sent.last().expect("an exchange");
    assert_eq!(
        last.expected,
        Some(SyncPosition::removed_at(2)),
        "the comparison names the removal, and the wire reads it as no object"
    );
    assert_eq!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("the write left one")
            .position,
        at(3)
    );
}

#[tokio::test]
async fn an_accepted_write_that_claims_the_notes_place_under_another_name_is_reported() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // This device's note names write five, and the service applies its write at write five under
    // another name. The note cannot move: one write sequence names one write for the life of a
    // collection, so the two answers come from two histories.
    client
        .store()
        .record_checkpoint(
            object_id,
            SyncCheckpoint {
                position: at(5),
                published_revision: Nullable::null(),
            },
        )
        .expect("a note");
    let collection = sync_collection(SyncObjectKind::Settings, object_id);
    service
        .hold(&collection, at(5), b"what the service holds".to_vec())
        .await;
    service
        .applies_the_next_write_at(SyncPosition::at(
            5,
            SyncRevision::new(Uuid::from_bytes([0xbb; 16])),
        ))
        .await;

    // The publication compares against write five, the service applies it as write five under its
    // own name, and this device is told rather than left to meet the disagreement at some later
    // comparison that may never come: the service can reach write six, which follows from either
    // history.
    let refused = client
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect_err("two histories claim write five");
    assert!(
        matches!(refused, SyncError::ForkedHistory { .. }),
        "the answer claims a place the note already gives to another write: {refused}"
    );
    assert_eq!(refused.code(), ErrorCode::DraftConflict);

    // The settlement is durable all the same, and the account of what left under that write is the
    // request's own record.
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("one stands")
            .position,
        at(5),
        "nothing writes a note from a history this device cannot follow"
    );
    assert_eq!(client.exported().expect("exported").len(), 1);
}

#[tokio::test]
async fn a_position_no_write_of_the_object_can_be_at_is_declined_rather_than_read() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    let collection = sync_collection(SyncObjectKind::Settings, object_id);

    // A fetch answers with content at the place a removal took. A removal produced no object, so
    // this is an answer this device declines: writing that note would leave the next publication
    // comparing against no object while one was there.
    let theirs = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    let sealed = DeviceSealer::new(0x5a)
        .seal(&kr_cbor::to_canonical_vec(&theirs).expect("canonical bytes"))
        .expect("sealed");
    service
        .hold(&collection, SyncPosition::removed_at(5), sealed.clone())
        .await;
    let refused = client
        .fetch(
            SyncObjectKind::Settings,
            object_id,
            TimestampMs::new(NOW + 1),
        )
        .await
        .expect_err("a removal produced no object");
    assert!(matches!(refused, SyncError::NotAWrite { .. }), "{refused}");
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none(),
        "nothing is written from an answer this device cannot read"
    );

    // And a place in the order counts from one. Nought is what a service says of an object it has
    // never held, and this contract says that by carrying no position at all.
    service.hold(&collection, at(0), sealed).await;
    assert!(matches!(
        client
            .fetch(
                SyncObjectKind::Settings,
                object_id,
                TimestampMs::new(NOW + 2),
            )
            .await
            .expect_err("nought is not a place"),
        SyncError::NotAWrite { .. }
    ));

    // An accepted write answered at either is declined too, and the work stays counted: a request
    // this device cannot settle is one it keeps asking about rather than one it invents an answer
    // for.
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    drop(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW + 3))
            .expect("dispatched"),
    );
    for impossible in [SyncPosition::removed_at(6), at(0)] {
        assert!(
            matches!(
                client
                    .store()
                    .settle(
                        &claim(client.store(), staged.work_id),
                        &staged,
                        Outcome::Accepted {
                            position: impossible
                        },
                    )
                    .expect_err("no write of this object landed there"),
                SyncError::NotAWrite { .. }
            ),
            "a write this device sent cannot have produced {impossible}"
        );
    }
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "the request is still one nothing has accounted for"
    );
}

#[tokio::test]
async fn a_service_that_has_gone_back_behind_the_note_says_so() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mut mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    mine.revision = fresh_revision().expect("a revision");
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect("published");

    // The service is replaced and another device writes once, so it answers with a write sequence
    // below the one this device's note names. A write sequence only goes forward, so that is
    // provable rather than guessed, and it is the case the explicit recovery exists for.
    service.reset().await;
    let elsewhere = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );
    let theirs = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    elsewhere.store().put_object(&theirs).expect("stored");
    elsewhere
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    mine.revision = fresh_revision().expect("a revision");
    client.store().put_object(&mine).expect("stored");
    let refused = client
        .publish(object_id, TimestampMs::new(NOW + 2))
        .await
        .expect_err("the note names a write the service is behind");
    assert!(
        matches!(
            refused,
            SyncError::StaleCheckpoint {
                expected: 2,
                found: 1,
                ..
            }
        ),
        "the refusal names what is wrong and what to do: {refused}"
    );

    client
        .store()
        .forget_checkpoint(object_id)
        .expect("forgotten");
    assert!(matches!(
        client
            .publish(object_id, TimestampMs::new(NOW + 3))
            .await
            .expect("answered"),
        Published::Conflicted { .. }
    ));
}

#[tokio::test]
async fn an_accepted_write_answered_at_or_behind_the_place_it_replaced_is_never_applied() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let collection = sync_collection(SyncObjectKind::Settings, object_id);
    let mut mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The note names write five, which is where the service holds the object. A write takes the
    // next place after the one it replaced, so a write sent against write five can only have landed
    // at write six or later, whatever the note says by the time the answer arrives.
    client
        .store()
        .record_checkpoint(
            object_id,
            SyncCheckpoint {
                position: at(5),
                published_revision: Nullable::null(),
            },
        )
        .expect("a note");
    let expected_diverged = |client: &SyncClient, found: SyncPosition| {
        let left = client.store().what_left().expect("what left");
        assert!(
            left.requests
                .items
                .iter()
                .any(|record| record.state == RequestState::Diverged { position: found }),
            "the request's own record is the account of what left under {found}"
        );
        assert_eq!(
            client
                .store()
                .checkpoint(object_id)
                .expect("a note")
                .expect("one stands")
                .position,
            at(5),
            "nothing writes a note from an answer that does not follow it"
        );
        assert!(
            left.publications.is_empty(),
            "no publication record claims a write that did not advance the object"
        );
    };

    // An answer behind the place the write replaced is a service that went back.
    service
        .hold(&collection, at(5), b"what the service holds".to_vec())
        .await;
    service.applies_the_next_write_at(at(3)).await;
    let refused = client
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect_err("write three is behind the write five this replaced");
    assert!(
        matches!(
            refused,
            SyncError::StaleCheckpoint {
                expected: 5,
                found: 3,
                ..
            }
        ),
        "{refused}"
    );
    expected_diverged(&client, at(3));

    // An answer at the very place the write replaced is two histories claiming one place: a write
    // never takes the place of the write it replaced.
    mine.revision = fresh_revision().expect("a revision");
    client.store().put_object(&mine).expect("stored");
    service
        .hold(&collection, at(5), b"what the service holds".to_vec())
        .await;
    service.applies_the_next_write_at(at(5)).await;
    let refused = client
        .publish(object_id, TimestampMs::new(NOW + 2))
        .await
        .expect_err("write five is the place this write replaced");
    assert!(
        matches!(refused, SyncError::ForkedHistory { .. }),
        "{refused}"
    );
    expected_diverged(&client, at(5));

    // A reconciliation that learns of such a write from its receipt settles it the same way: the
    // barrier releases and the account stays, and nothing is recorded as applied.
    mine.revision = fresh_revision().expect("a revision");
    client.store().put_object(&mine).expect("stored");
    service
        .hold(&collection, at(5), b"what the service holds".to_vec())
        .await;
    service.applies_the_next_write_at(at(4)).await;
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW + 3))
        .await
        .expect_err("the answer never came back");
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 4))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.diverged, 1, "counted rather than refused");
    assert_eq!(reconciled.unsettled, 0);
    expected_diverged(&client, at(4));
    assert_eq!(client.outstanding().expect("a count"), 0);
}

// ---------------------------------------------------------------------------
// KR-REQ-18.05: encrypted settings sync, named beside the rest of the feature
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_service_holds_ciphertext_in_a_declared_bucket_and_never_a_setting() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);

    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(
            &[("theme", "a-distinctive-setting-value")],
            &["a pinned label"],
        )),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    let (_, stored) = service
        .stored(&sync_collection(SyncObjectKind::Settings, object_id))
        .await
        .expect("it is stored");
    let haystack = String::from_utf8_lossy(&stored);
    assert!(!haystack.contains("a-distinctive-setting-value"));
    assert!(!haystack.contains("a pinned label"));
    assert!(!haystack.contains("theme"));

    // What it holds is a sealed object with a declared bucket, which is the one length rule a
    // service can check without a key.
    let object: kr_protocol::sync::SealedSyncObject =
        kr_cbor::from_canonical_slice(&stored, &kr_cbor::Limits::DEFAULT).expect("a sealed object");
    assert_eq!(object.check_structure(), Ok(()));
    assert_eq!(object.size_bucket_bytes.get(), 1024);

    // A device holding another key does not read it, which is the whole of what "encrypted" buys
    // against a service that stores the bytes.
    assert!(DeviceSealer::new(0x5b).open(&stored).is_err());
    assert_eq!(
        DeviceSealer::new(0x5a)
            .open(&stored)
            .expect("the device's own key reads it"),
        kr_cbor::to_canonical_vec(&mine).expect("canonical bytes")
    );
}

#[test]
fn the_feature_names_its_three_parts_and_which_of_them_is_optional() {
    assert_eq!(
        StorageFeature::ALL.map(StorageFeature::as_str),
        [
            "encrypted settings sync",
            "history backups",
            "recovery material"
        ]
    );
    assert!(!StorageFeature::SettingsSync.is_optional());
    assert!(StorageFeature::HistoryBackups.is_optional());
    assert!(StorageFeature::RecoveryMaterial.is_optional());
    for part in StorageFeature::ALL {
        assert!(!part.alternative().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Section 24: the privacy hook
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enabling_privacy_fences_production_and_removes_what_it_says_it_removed() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let two = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("two")).expect("a store"),
    );

    // Give the second device something of each kind to clean up: a checkpoint, a conflict copy and
    // a publication record.
    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    two.store().put_object(&mine).expect("stored");
    two.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("answered");
    two.store()
        .pin_label("a label", TimestampMs::new(NOW))
        .expect("pinned");
    assert_eq!(two.store().conflicts(object_id).expect("copies").len(), 1);

    let fenced = two.fence(7).expect("fenced");
    assert_eq!(fenced.queues, 1);
    assert!(two.is_fenced().expect("a record"));
    assert_eq!(two.generation().expect("a record"), 7);
    assert!(matches!(
        two.publish(object_id, TimestampMs::new(NOW + 1)).await,
        Err(SyncError::Fenced { generation: 7 })
    ));

    let cancelled = two
        .cancel_undispatched(7, TimestampMs::new(NOW + 2))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.in_flight, 0);
    // Nothing is waiting for an answer. What stays is the account of the write the service refused
    // and kept a copy of, which is a record of what left rather than work still to do.
    let waiting = |client: &SyncClient| {
        client
            .store()
            .requests()
            .expect("requests")
            .items
            .iter()
            .filter(|record| !record.ended())
            .count()
    };
    assert_eq!(waiting(&two), 0);

    let removed = two
        .remove_retained(7, TimestampMs::new(NOW + 2))
        .await
        .expect("removed");
    assert!(removed.records > 0);
    assert!(removed.bytes > 0);
    // What it reported removed is gone, which is what makes the figures worth reading.
    assert!(two.store().conflicts(object_id).expect("copies").is_empty());
    assert!(two.store().checkpoint(object_id).expect("a note").is_none());
    assert_eq!(waiting(&two), 0);

    // What stays is named rather than left out.
    let kept = two.kept().expect("kept");
    assert!(kept.iter().any(|item| item.what.contains("pinned")));
    assert!(kept.iter().any(|item| item.what.contains("settings")));
    assert_eq!(two.store().pinned_labels().expect("labels").len(), 1);
    assert!(two.store().object(object_id).expect("held").is_some());
}

#[tokio::test]
async fn pinned_labels_stay_on_the_device_and_are_left_out_of_what_is_published_while_private() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, _) = device_client(directory.path(), "one", &service);
    let mine = settings(&[("theme", "dark")], &["one", "two"]);

    // Not private: the labels travel with the settings.
    let publishable = client.settings_to_publish(&mine).expect("a filter");
    assert_eq!(publishable.pinned_labels.len(), 2);

    // Private: they are left out of what is published, and the device still holds them.
    client.fence(3).expect("fenced");
    let publishable = client.settings_to_publish(&mine).expect("a filter");
    assert!(publishable.pinned_labels.is_empty());
    assert_eq!(publishable.values, mine.values);
    assert_eq!(mine.pinned_labels.len(), 2);

    client
        .store()
        .pin_label("one", TimestampMs::new(NOW))
        .expect("pinned");
    client
        .remove_retained(3, TimestampMs::new(NOW))
        .await
        .expect("removed");
    assert_eq!(
        client.store().pinned_labels().expect("labels").len(),
        1,
        "privacy mode does not clear a pinned label"
    );

    // Clearing one is explicit, and it is the only thing that removes one.
    assert!(client.store().clear_pinned_label("one").expect("cleared"));
    assert!(!client.store().clear_pinned_label("one").expect("again"));
    assert!(client.store().pinned_labels().expect("labels").is_empty());

    // Turning privacy mode off starts a generation of its own and reconstructs nothing.
    let resumed = client.resume(4).expect("resumed");
    assert_eq!(resumed.generation, 4);
    assert!(!client.is_fenced().expect("a record"));
    assert!(!client.accepts_result(3).expect("a record"));
    assert!(client.accepts_result(4).expect("a record"));
}

#[tokio::test]
async fn a_result_produced_under_an_earlier_generation_is_not_published() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let client = Arc::new(SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        store,
    ));
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The publication leaves and waits at the service.
    let publishing = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "it is dispatched and unsettled"
    );

    // Privacy mode is enabled while it is in flight, which is the case section 24 names.
    client.fence(5).expect("fenced");
    let cancelled = client
        .cancel_undispatched(5, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(
        cancelled.undispatched, 0,
        "work that has left cannot be taken back"
    );
    // The cleanup reconciles first, and the service holds no receipt for a request it has not
    // committed yet. This device is the only thing that can tell that from a request that never
    // arrived, because the call is its own, so the work is counted rather than discarded.
    assert_eq!(cancelled.in_flight, 1, "it is counted rather than hidden");

    // The answer comes back for work admitted under the generation before this one. It is not
    // published, and nothing about where the object stands moves.
    service.let_it_go();
    let outcome = publishing
        .await
        .expect("the task finished")
        .expect("answered");
    assert_eq!(
        outcome,
        Published::Discarded {
            produced_under: 0,
            current: 5
        }
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none(),
        "no checkpoint moves for a result privacy mode refused"
    );

    // The upload itself happened, and this device says so. Suppressing the result does not undo
    // what left, and section 24 shows what left rather than pretending it did not.
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains("write 1"));
    assert!(!exported[0].deletable);
    assert_eq!(
        client.outstanding().expect("a count"),
        0,
        "it has now been reconciled"
    );
}

#[tokio::test]
async fn a_publication_whose_caller_walked_away_stays_work_this_device_cannot_account_for() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let client = Arc::new(SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        store,
    ));
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    let publishing = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    assert_eq!(client.outstanding().expect("a count"), 1);

    // The caller abandons the call at the await. Nothing about that establishes that the write did
    // not land, so the work stays outstanding: a count that followed the future rather than the
    // work would report a cleanup complete while the object may have been on its way.
    publishing.abort();
    let _ = publishing.await;
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "an abandoned call settles nothing"
    );
    let staged = client.store().requests().expect("requests");
    assert_eq!(staged.len(), 1);
    assert!(staged.items[0].dispatched());
    assert_eq!(
        client
            .cancel_undispatched(0, TimestampMs::new(NOW + 1))
            .await
            .expect("cancelled")
            .undispatched,
        0,
        "work that has left cannot be taken back"
    );

    // A client built over the same store counts it too, because a restart does not make an
    // uncertain outcome certain.
    let reopened = SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.path().join("one")).expect("a store"),
    );
    assert_eq!(reopened.outstanding().expect("a count"), 1);

    // Nothing here settles it, and this client does not pretend otherwise. A later answer about
    // the object says what the service holds; it does not say what became of this request, and one
    // whose answer was lost can still be accepted afterwards. What settles it is the request's own
    // identity, which is a separate question put to the service and never an inference from what
    // the object holds now.
    service.let_it_go();
    reopened.store().put_object(&mine).expect("stored");
    assert!(matches!(
        reopened
            .publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("answered"),
        Published::Accepted { .. } | Published::Conflicted { .. }
    ));
    assert_eq!(
        reopened.outstanding().expect("a count"),
        1,
        "an answer about the object settles that request and not another one"
    );

    // What it may have sent is named, because it left this device and nothing here can say whether
    // the service stored it.
    let exported = reopened.exported().expect("exported");
    assert!(
        exported
            .iter()
            .any(|entry| entry.kind.contains("sent without an answer")),
        "what may have left is named rather than dropped: {exported:?}"
    );
    assert!(exported.iter().all(|entry| !entry.deletable));
}

#[tokio::test]
async fn a_cleanup_keeps_the_record_of_work_that_had_already_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let client = Arc::new(SyncClient::new(
        Arc::clone(&service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        store,
    ));
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    let publishing = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    assert_eq!(client.outstanding().expect("a count"), 1);

    // The whole cleanup, in the order section 24 states it. It must not make this device say
    // nothing is outstanding while a write it sent has no answer.
    client.fence(4).expect("fenced");
    assert_eq!(
        client
            .cancel_undispatched(4, TimestampMs::new(NOW + 1))
            .await
            .expect("cancelled")
            .in_flight,
        1
    );
    client
        .remove_retained(4, TimestampMs::new(NOW + 1))
        .await
        .expect("removed");
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "a cleanup does not settle a write that has left"
    );
    let staged = client.store().requests().expect("requests");
    assert_eq!(staged.len(), 1);
    assert!(staged.items[0].dispatched());

    service.let_it_go();
    let _ = publishing.await.expect("the task finished");
}

#[tokio::test]
async fn a_fence_between_admission_and_dispatch_takes_the_work_back() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // Admitted under generation nought, and a fence lands before it is sent. The record is taken
    // back rather than dispatched, which is what the cancellation would have done to it.
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    client.fence(9).expect("fenced");
    assert!(matches!(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW)),
        Err(SyncError::Fenced { generation: 9 })
    ));
    assert!(client.store().requests().expect("requests").is_empty());
    assert_eq!(client.outstanding().expect("a count"), 0);

    // And a publication started after the fence never reaches the service at all.
    assert!(matches!(
        client.publish(object_id, TimestampMs::new(NOW)).await,
        Err(SyncError::Fenced { generation: 9 })
    ));
    assert!(service.collections().await.is_empty());
}

#[tokio::test]
async fn outstanding_reaches_nought_only_once_a_dispatched_publication_has_settled() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    assert_eq!(client.outstanding().expect("a count"), 0);
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    assert_eq!(
        client.outstanding().expect("a count"),
        0,
        "a settled publication is no longer in flight"
    );
    // A cancellation reports what is still out, which is nothing once it has settled.
    assert_eq!(
        client
            .cancel_undispatched(1, TimestampMs::new(NOW))
            .await
            .expect("cancelled")
            .in_flight,
        0
    );
}

#[tokio::test]
async fn what_has_already_left_is_shown_rather_than_claimed_to_be_erased() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    client.fence(2).expect("fenced");
    client
        .remove_retained(2, TimestampMs::new(NOW))
        .await
        .expect("removed");

    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
    assert!(exported[0].reference.contains("write 1"));
    assert!(
        !exported[0].deletable,
        "this client has no way to ask a compare-and-exchange store to delete an object"
    );
    // The record survives the cleanup, because it is the only account of what left.
    assert_eq!(client.store().publications().expect("records").len(), 1);
}

#[tokio::test]
async fn a_client_selection_is_a_position_rather_than_a_row() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);

    let mut selection = ClientSelection::nothing_selected();
    selection.session_id = Nullable::some(SessionId::new(Uuid::from_bytes([3; 16])));
    selection.rows_from_newest = U64::new(12);
    let mine = object(
        object_id,
        1,
        SyncBody::ClientSelection(selection.clone()),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    assert!(
        service
            .collections()
            .await
            .iter()
            .any(|name| name.starts_with("client_selection/"))
    );
    let restored = client
        .fetch(
            SyncObjectKind::ClientSelection,
            object_id,
            TimestampMs::new(NOW),
        )
        .await
        .expect("fetched");
    assert_eq!(restored.object().body, SyncBody::ClientSelection(selection));
}

#[tokio::test]
async fn a_cleanup_that_a_later_generation_overtook_is_refused() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // Privacy mode is enabled and then turned off again. A cleanup step of the older generation
    // arriving now is refused rather than carried out: the generation in force has already decided
    // what is retained, and the older step would delete what it admitted.
    client.fence(5).expect("fenced");
    client.resume(6).expect("resumed");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    assert!(matches!(
        client.cancel_undispatched(5, TimestampMs::new(NOW)).await,
        Err(SyncError::LateResult {
            produced_under: 5,
            current: 6
        })
    ));
    assert!(matches!(
        client.remove_retained(5, TimestampMs::new(NOW)).await,
        Err(SyncError::LateResult {
            produced_under: 5,
            current: 6
        })
    ));
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_some(),
        "an overtaken cleanup reaches nothing the generation in force admitted"
    );
    assert_eq!(client.generation().expect("a record"), 6);
}

// ---------------------------------------------------------------------------
// KR-REQ-20.13 and section 24: settling a dispatch whose answer was lost
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_lost_answer_to_a_write_the_service_applied_is_settled_by_asking_about_the_request() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The service applies the write and the answer never comes back.
    service.lose_the_next_answer().await;
    let error = client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");
    assert_eq!(error.code(), ErrorCode::UpstreamUnavailable);
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "nothing about a lost answer establishes that the write did not land"
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none(),
        "no checkpoint moves on an answer this device never received"
    );

    // The receipt the service kept under the identity the request carried is what settles it.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(
        reconciled,
        Reconciled {
            settled: 1,
            diverged: 0,
            fenced: 0,
            accounts_kept: 0,
            unresolved: 0,
            copies_not_taken: 0,
            unsettled: 0,
        }
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("the write left one")
            .position,
        at(1)
    );
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains("write 1"));

    // It asked about the request it had sent, under that request's own identity.
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 1);
    assert_eq!(
        service.status_queries().await,
        vec![(sent[0].collection.clone(), sent[0].request_id)]
    );

    // And the next publication compares against the generation the settlement recorded, so a
    // device that lost an answer is not left publishing against a comparison it must lose.
    let next = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 2,
    );
    client.store().put_object(&next).expect("stored");
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("published"),
        Published::Accepted { position: at(2) }
    );
}

#[tokio::test]
async fn a_lost_answer_to_a_write_the_service_refused_is_settled_as_a_copy_beside_this_device() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let (two, _) = device_client(directory.path(), "two", &service);

    // The other device writes first, so this device's comparison is the one that loses.
    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    two.store().put_object(&mine).expect("stored");
    service.lose_the_next_answer().await;
    two.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the refusal never came back");
    assert_eq!(two.outstanding().expect("a count"), 1);
    assert!(two.store().conflicts(object_id).expect("copies").is_empty());

    let reconciled = two
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.copies_not_taken, 0);
    assert_eq!(reconciled.unsettled, 0);
    assert_eq!(two.outstanding().expect("a count"), 0);

    // Section 20 keeps what the service held, beside this device's own content, which is where it
    // was. A refusal settled late is still a refusal that nothing of this device's replaced.
    let copies = two.store().conflicts(object_id).expect("copies");
    assert_eq!(copies.len(), 1);
    assert_eq!(copies.items[0].other.revision, theirs.revision);
    assert_eq!(copies.items[0].expected, Nullable::null());
    assert_eq!(
        two.store()
            .object(object_id)
            .expect("held")
            .expect("this device's own")
            .revision,
        mine.revision
    );
    // A refusal establishes that the comparison did not replace the object, and nothing more. The
    // service kept the rejected write as a copy of its own, so the account of what left names it.
    let exported = two.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(
        exported
            .iter()
            .all(|entry| !entry.kind.contains("sent without an answer")),
        "the service accounted for this request, so nothing is left unanswered"
    );
    assert!(exported[0].kind.contains("kept as a copy by the service"));
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
}

#[tokio::test]
async fn a_request_the_service_has_no_receipt_for_is_fenced_once_privacy_mode_has_moved_past_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The request never reaches the service, so no receipt is ever written for it.
    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");
    assert_eq!(client.outstanding().expect("a count"), 1);
    assert!(service.collections().await.is_empty());

    // The whole cleanup, in the order section 24 states it. Each step reconciles, so the count it
    // reports is what the service could not account for rather than every answer that went astray.
    client.fence(3).expect("fenced");
    let cancelled = client
        .cancel_undispatched(3, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.undispatched, 0);
    assert_eq!(
        cancelled.reconciled.fenced, 1,
        "the service is asked to end the request, and answers that it never ran it"
    );
    assert_eq!(
        cancelled.in_flight, 0,
        "a request the service will never execute is not one the barrier waits for"
    );
    assert_eq!(
        service.fence_requests().await.len(),
        1,
        "the fence names the identity this device sent"
    );
    client
        .remove_retained(3, TimestampMs::new(NOW + 1))
        .await
        .expect("removed");
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert!(client.store().requests().expect("requests").is_empty());

    // Nothing resurfaces: no checkpoint, no copy, and the object this device holds is its own.
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none()
    );
    assert!(
        client
            .store()
            .conflicts(object_id)
            .expect("copies")
            .is_empty()
    );
    assert_eq!(
        client
            .store()
            .object(object_id)
            .expect("held")
            .expect("this device's own")
            .revision,
        mine.revision
    );

    // Nothing is shown as having left, because nothing of it is anywhere: the service answered
    // that it executed nothing under that identity and will refuse anything that arrives under it.
    assert_eq!(client.exported().expect("exported"), Vec::new());

    // A second pass finds nothing left to do, and nothing is asked again about work that is gone.
    let again = client
        .reconcile_unsettled(TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(again, Reconciled::default());
    assert_eq!(
        service.status_queries().await.len(),
        1,
        "the request was asked about once, and nothing asks again about work that is gone"
    );
}

#[tokio::test]
async fn a_request_the_service_has_no_receipt_for_stays_counted_while_its_generation_is_in_force() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");

    // No fence has been recorded, so an answer to this work could still be published and the work
    // stays where it is: a receipt may yet be found, and section 23 makes an unknown outcome one
    // nothing retries by itself.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(
        reconciled,
        Reconciled {
            settled: 0,
            diverged: 0,
            fenced: 0,
            accounts_kept: 0,
            unresolved: 1,
            copies_not_taken: 0,
            unsettled: 1,
        }
    );
    assert_eq!(client.outstanding().expect("a count"), 1);
    assert_eq!(service.exchanges().await.len(), 1, "nothing was sent again");
    assert!(
        client
            .exported()
            .expect("exported")
            .iter()
            .any(|entry| entry.kind.contains("sent without an answer"))
    );

    // A service this device cannot ask at all leaves it counted too, rather than failing the pass:
    // a cleanup that could not report what is outstanding would be worse than one that reports it.
    service.stop_answering_about_requests().await;
    let unreachable = client
        .reconcile_unsettled(TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(unreachable.unresolved, 1);
    assert_eq!(unreachable.unsettled, 1);
    assert_eq!(client.outstanding().expect("a count"), 1);
}

#[tokio::test]
async fn a_retry_presents_the_identity_the_first_attempt_did_and_is_answered_from_the_receipt() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // What one exchange carries: the collection, the request's own identity, the comparison and
    // the sealed object. The identity is the staged work's, so the record on disk holds it and a
    // restart presents the same one.
    let sent = service.exchanges().await;
    assert_eq!(sent.len(), 1);
    let first = sent[0].clone();
    assert_eq!(
        first.collection,
        sync_collection(SyncObjectKind::Settings, object_id)
    );
    assert_eq!(first.expected, None);
    let staged = client.store().requests().expect("requests");
    assert_eq!(staged.items[0].work_id, first.request_id);
    assert_eq!(
        staged.items[0]
            .ciphertext()
            .expect("it is still to be answered"),
        first.ciphertext
    );
    assert_ne!(
        first.request_id,
        object_id.get(),
        "a request is not the object it is about"
    );

    // Presenting it again, byte for byte, is answered from the receipt: nothing is applied a
    // second time and the object stays where the first attempt left it.
    assert_eq!(
        service
            .compare_exchange(
                &first.collection,
                first.request_id,
                first.signed_at_ms,
                first.expected.as_ref().copied(),
                &first.ciphertext,
            )
            .await
            .expect("answered from the receipt"),
        SyncExchanged::Applied { position: at(1) }
    );
    assert_eq!(
        service
            .stored(&first.collection)
            .await
            .expect("it is stored")
            .0,
        at(1)
    );

    // The same identity carrying different content is a second request wearing the first one's
    // name, which is refused rather than answered.
    assert_eq!(
        service
            .compare_exchange(
                &first.collection,
                first.request_id,
                first.signed_at_ms,
                first.expected.as_ref().copied(),
                b"content the first attempt never carried",
            )
            .await
            .expect_err("one identity, two requests")
            .code(),
        ErrorCode::IdConflict
    );

    // And the settlement asks about that identity rather than about the object.
    client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(
        service.status_queries().await,
        vec![(first.collection, first.request_id)]
    );
}

#[tokio::test]
async fn a_request_the_service_will_never_run_leaves_the_store_with_nothing_to_account_for() {
    let directory = tempfile::tempdir().expect("a directory");
    let store = SyncStore::open(directory.path().join("one")).expect("a store");
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    store.put_object(&mine).expect("stored");
    let staged = store
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    drop(
        store
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW))
            .expect("dispatched"),
    );

    // Under the generation that admitted it, the work is still wanted, so nothing fences it: the
    // store says so, and a reconciliation reads that before it asks the service to end anything.
    assert!(
        !store
            .beyond_its_generation(&staged)
            .expect("the generation in force")
    );
    assert_eq!(store.unsettled().expect("a count"), 1);

    // Work that was never sent is never one of these: nothing left the device under it, so there
    // is no departure to account for and no dispatch of it to decide anything under.
    let never_sent = store
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    assert!(matches!(
        store.claim_dispatched(never_sent.work_id).expect("a claim"),
        Claimed::Gone
    ));

    // Once privacy mode has moved past that generation, the request can be ended at the service,
    // and a request the service executed nothing under leaves nothing behind: no ciphertext, and
    // no account, because there is nothing of it anywhere to account for.
    store
        .record_privacy(PrivacyRecord {
            generation: U64::new(4),
            fenced: true,
        })
        .expect("fenced");
    assert!(
        store
            .beyond_its_generation(&staged)
            .expect("the generation in force")
    );
    assert!(
        store
            .close_unexecuted(&claim(&store, staged.work_id), staged.work_id)
            .expect("closed")
    );
    assert_eq!(store.unsettled().expect("a count"), 0);
    let left = store.what_left().expect("what left");
    assert!(left.publications.is_empty());
    assert_eq!(left.requests.len(), 1, "only the work that never went");
    assert!(left.requests.items[0].admitted());

    // Closing it twice is closing nothing, whoever asks.
    assert!(
        !store
            .close_unexecuted(&claim_after_discard(&store, staged.work_id), staged.work_id)
            .expect("nothing to close")
    );

    // An answer that arrives afterwards changes nothing and publishes nothing. It is refused by
    // the generation rule rather than reported as settled, so a caller cannot report a late
    // old-generation result as an accepted publication.
    assert_eq!(
        store
            .settle(
                &claim_after_discard(&store, staged.work_id),
                &staged,
                Outcome::Accepted { position: at(7) },
            )
            .expect("settled")
            .settlement,
        Settlement::Discarded {
            produced_under: 0,
            current: 4
        }
    );
    assert!(
        store.checkpoint(object_id).expect("a note").is_none(),
        "no checkpoint moves for a result privacy mode refused"
    );
    assert!(store.publications().expect("records").is_empty());
}

/// One device over a gated service, so a test can hold a publication at the wire.
fn gated_client(
    directory: &std::path::Path,
    name: &str,
    service: &Arc<GatedService>,
) -> Arc<SyncClient> {
    Arc::new(SyncClient::new(
        Arc::clone(service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.join(name)).expect("a store"),
    ))
}

#[tokio::test]
async fn one_window_never_decides_what_became_of_another_windows_live_dispatch() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    // Two clients over one store, which is two windows of the same application.
    let one = gated_client(directory.path(), "shared", &service);
    let two = gated_client(directory.path(), "shared", &service);
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&mine).expect("stored");

    let publishing = tokio::spawn({
        let one = Arc::clone(&one);
        async move { one.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;

    // The other window cannot claim the request, because the first window has a call out for it.
    // A service writes its receipt when it commits the write, so asking about a request still on
    // the wire would be answered "no receipt" exactly as a request that never arrived is.
    let work_id = two.store().requests().expect("requests").items[0].work_id;
    assert!(matches!(
        two.store().claim_dispatched(work_id).expect("a claim"),
        Claimed::InHand
    ));

    // So a whole privacy cleanup driven from the other window leaves it outstanding rather than
    // discarding live work and reporting complete.
    two.fence(5).expect("fenced");
    let cancelled = two
        .cancel_undispatched(5, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.in_flight, 1, "it is counted rather than hidden");
    assert_eq!(
        cancelled.reconciled.unresolved, 1,
        "the cleanup reports what its reconciliation could establish, not only a total"
    );
    let reconciled = two
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(
        reconciled,
        Reconciled {
            settled: 0,
            diverged: 0,
            fenced: 0,
            accounts_kept: 0,
            unresolved: 1,
            copies_not_taken: 0,
            unsettled: 1,
        }
    );
    assert_eq!(two.outstanding().expect("a count"), 1);
    assert!(
        service.inner.status_queries().await.is_empty(),
        "nothing is asked about a request somebody is still waiting on"
    );

    // The first window's answer comes back. It is refused by the generation rule, the upload is
    // recorded as what left, and the request is no longer outstanding in either window.
    service.let_it_go();
    assert_eq!(
        publishing
            .await
            .expect("the task finished")
            .expect("answered"),
        Published::Discarded {
            produced_under: 0,
            current: 5
        }
    );
    assert_eq!(two.outstanding().expect("a count"), 0);
    assert_eq!(one.outstanding().expect("a count"), 0);
    assert!(
        two.store().checkpoint(object_id).expect("a note").is_none(),
        "no checkpoint moves for a result privacy mode refused"
    );
    let exported = two.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains("write 1"));
}

#[tokio::test]
async fn an_answer_to_a_request_something_else_settled_is_still_checked_against_the_generation() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let one = gated_client(directory.path(), "shared", &service);
    let two = gated_client(directory.path(), "shared", &service);
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&mine).expect("stored");

    // The service commits the write, its reply is held on the way back, and the window that sent
    // it stops waiting. The request is claimable again, and the write happened all the same.
    service.hold_the_answer_instead().await;
    let publishing = tokio::spawn({
        let one = Arc::clone(&one);
        async move { one.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    let staged = two.store().requests().expect("requests").items[0].clone();
    publishing.abort();
    assert!(publishing.await.expect_err("abandoned").is_cancelled());

    // The other window claims what nobody is holding and settles it from the receipt.
    let reconciled = two
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(two.outstanding().expect("a count"), 0);

    // Privacy mode then moves past the generation that admitted the work, and the answer to that
    // request arrives late, to a store holding no record of it at all. It is refused by the
    // generation rule: saying "already settled" here would report a publication under a generation
    // privacy mode had closed.
    two.fence(3).expect("fenced");
    assert_eq!(
        two.store()
            .settle(
                &claim_after_discard(two.store(), staged.work_id),
                &staged,
                Outcome::Accepted { position: at(1) },
            )
            .expect("settled")
            .settlement,
        Settlement::Discarded {
            produced_under: 0,
            current: 3
        }
    );
    assert_eq!(
        two.store().publications().expect("records").len(),
        1,
        "the settlement recorded the upload once"
    );
}

#[tokio::test]
async fn a_request_the_service_ran_after_the_caller_walked_away_is_settled_from_its_receipt() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let client = gated_client(directory.path(), "one", &service);
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The service commits the write; the caller abandons the call before the reply reaches it.
    // Dropping a future proves that this device stopped waiting, never that the request stopped.
    service.hold_the_answer_instead().await;
    let publishing = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    publishing.abort();
    assert!(publishing.await.expect_err("abandoned").is_cancelled());

    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "the record says the content left, and nothing has established what became of it"
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none()
    );
    // The call is over, so the request is claimable again: a released dispatch is a request this
    // device may ask about, which is exactly what it does next.
    let work_id = client.store().requests().expect("requests").items[0].work_id;
    assert!(matches!(
        client.store().claim_dispatched(work_id).expect("a claim"),
        Claimed::Taken(_, _)
    ));

    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.unsettled, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("the write left one")
            .position,
        at(1),
        "the write the service ran is what the note now names"
    );
}

#[tokio::test]
async fn a_device_that_stopped_part_way_through_a_transition_counts_the_request_once() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // Stopped after the staged record and before the dispatch: nothing left, so a cleanup takes it
    // back and nothing is counted.
    let never_sent = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(client.store().take_back_undispatched(0).expect("taken"), 1);
    assert!(client.store().requests().expect("requests").is_empty());
    assert!(
        matches!(
            client
                .store()
                .claim_dispatched(never_sent.work_id)
                .expect("a claim"),
            Claimed::Gone
        ),
        "work that never left has no dispatch to decide anything under"
    );

    // Stopped after the dispatch record and before the call: the content may have left, so it is
    // counted, and the next reconciliation asks about it.
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    drop(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW))
            .expect("dispatched"),
    );
    assert_eq!(client.outstanding().expect("a count"), 1);

    // A dispatch names one request in one store. Another store's claim on the same identity
    // decides nothing here, and work that has left does not leave a second time under one account.
    let elsewhere = SyncStore::open(directory.path().join("two")).expect("a store");
    assert_eq!(
        client
            .store()
            .close_unexecuted(
                &elsewhere
                    .claim_request(staged.work_id)
                    .expect("a claim")
                    .expect("nobody is waiting on it"),
                staged.work_id,
            )
            .expect_err("that claim is another store's")
            .code(),
        ErrorCode::InvalidArgument
    );
    assert!(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW + 1))
            .is_err(),
        "one piece of work leaves this device once"
    );

    // Stopped after the request was ended at the service and before the record went. The record
    // is what counts, so the work is outstanding again and the next pass asks about it.
    let request_path = directory
        .path()
        .join("one")
        .join(format!("{}.request", staged.work_id));
    let dispatched = std::fs::read(&request_path).expect("the request's record");
    client.fence(1).expect("fenced");
    client.store().advance_privacy(1).expect("moved on");
    assert!(
        client
            .store()
            .close_unexecuted(&claim(client.store(), staged.work_id), staged.work_id)
            .expect("closed")
    );
    std::fs::write(&request_path, &dispatched)
        .expect("a device that stopped between the two writes");

    // One request is one entry, in the count and in the account of what left.
    assert_eq!(client.outstanding().expect("a count"), 1);
    let left = client.store().what_left().expect("what left");
    assert_eq!(left.requests.len(), 1);
    assert_eq!(client.exported().expect("exported").len(), 1);

    // And the first settlement of that request leaves one account of it and no second.
    assert_eq!(
        client
            .store()
            .settle(
                &claim(client.store(), staged.work_id),
                &staged,
                Outcome::Accepted { position: at(4) },
            )
            .expect("settled")
            .settlement,
        Settlement::Discarded {
            produced_under: 0,
            current: 1
        }
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let left = client.store().what_left().expect("what left");
    assert!(left.requests.is_empty());
    assert_eq!(left.publications.len(), 1);
    // The account says when the content left this device, not when something got round to asking.
    assert_eq!(
        left.publications.items[0].published_at_ms,
        TimestampMs::new(NOW),
    );
}

/// Puts one request's record on disk exactly as a device that stopped part way would have left it.
///
/// Every write the store makes is a whole file renamed into place, so what a stop leaves behind is
/// one of these and never half of one.
fn leave_record_as_it_was(path: &std::path::Path, record: &RequestRecord) {
    std::fs::write(
        path,
        kr_cbor::to_canonical_vec(record).expect("canonical bytes"),
    )
    .expect("a record");
}

#[tokio::test]
async fn a_stop_anywhere_in_a_settlement_leaves_one_account_of_the_request() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // A write the service applied, whose answer was lost, and the record exactly as the store
    // wrote it before the call left.
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");
    let dispatched = client.store().requests().expect("requests").items[0].clone();
    let path = directory
        .path()
        .join("one")
        .join(format!("{}.request", dispatched.work_id));

    // Stopped after the note the answer moved and before the answer reached the record. The record
    // is what counts, so the request is still waiting: one entry, and the next pass asks again.
    client
        .store()
        .record_checkpoint(
            object_id,
            SyncCheckpoint {
                position: at(1),
                published_revision: Nullable::some(mine.revision),
            },
        )
        .expect("a note");
    assert_eq!(client.outstanding().expect("a count"), 1);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].kind.contains("sent without an answer"));

    // Stopped after the answer reached the record and before the account it owes was written. The
    // request is over, so nothing counts it, and the next read writes the account: one entry.
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Applied { position: at(1) },
            ..dispatched.clone()
        },
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1, "one request is one entry: {exported:?}");
    assert!(exported[0].reference.contains("write 1"));
    assert_eq!(
        exported[0].left_at_ms,
        TimestampMs::new(NOW),
        "the account says when the content left, not when something finished the step"
    );
    assert_eq!(client.store().publications().expect("records").len(), 1);

    // Stopped after the account was written and before the record went. This is the arrangement
    // that used to be two accounts of one request, and it is one.
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Applied { position: at(1) },
            ..dispatched.clone()
        },
    );
    let exported = client.exported().expect("exported");
    assert_eq!(
        exported.len(),
        1,
        "one request is one entry, whatever the stop interrupted: {exported:?}"
    );
    assert!(
        !path.exists(),
        "and the record goes once its account stands"
    );

    // A refusal the service kept nothing of ends the request and owes no account, so the next read
    // removes the record and names nothing of it.
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Refused {
                retained: Nullable::null(),
            },
            ..dispatched.clone()
        },
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(
        client.exported().expect("exported").len(),
        1,
        "the publication, and nothing of a refusal the service kept nothing of"
    );
    assert!(!path.exists());

    // A refusal the service kept a copy of **is** its own account, so its record stays and names
    // the copy the service holds.
    let conflict_id = SyncConflictId::new(fresh_request_id());
    leave_record_as_it_was(
        &path,
        &RequestRecord {
            state: RequestState::Refused {
                retained: Nullable::some(conflict_id),
            },
            ..dispatched
        },
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 2);
    assert!(
        exported
            .iter()
            .any(|entry| entry.reference.contains(&conflict_id.to_string()))
    );
    assert!(path.exists(), "the account of what left is not swept away");
}

#[tokio::test]
async fn a_service_that_cannot_end_a_request_leaves_the_barrier_where_it_was() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");
    assert_eq!(client.outstanding().expect("a count"), 1);

    // Privacy mode moves past the generation that admitted the work, so the request should be
    // ended at the service. The service cannot be asked, and a request nothing has established an
    // end for stays counted: a cleanup reports what is outstanding rather than assuming.
    client.fence(3).expect("fenced");
    service.stop_fencing_requests().await;
    let cancelled = client
        .cancel_undispatched(3, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 0);
    assert_eq!(cancelled.reconciled.unresolved, 1);
    assert_eq!(cancelled.in_flight, 1);
    assert_eq!(client.outstanding().expect("a count"), 1);
    let removed = client
        .remove_retained(3, TimestampMs::new(NOW + 1))
        .await
        .expect("removed");
    assert_eq!(
        removed.records, 0,
        "a dispatched record is not local content a cleanup may remove"
    );
    assert_eq!(
        client.outstanding().expect("a count"),
        1,
        "nothing reaches nought while a request has no end"
    );

    // When the service can be asked again, the same identity is what it is asked about, and the
    // barrier lifts.
    service.answer_fences_again().await;
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.fenced, 1);
    assert_eq!(reconciled.unsettled, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);
    let sent = service.exchanges().await;
    let asked = service.fence_requests().await;
    assert!(
        asked
            .iter()
            .all(|fence| fence.collection == sent[0].collection
                && fence.request_id == sent[0].request_id),
        "every attempt asks about the identity this device sent: {asked:?}"
    );
}

#[tokio::test]
async fn a_request_that_lands_between_the_two_calls_is_settled_by_the_fence() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The write is applied and the answer is lost on the way back.
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // The status query answers before the receipt is there, which is what a request still on its
    // way looks like. The fence that follows finds the receipt, so the request is settled by what
    // the service recorded rather than ended as one that never ran.
    client.fence(2).expect("fenced");
    client.store().advance_privacy(2).expect("moved on");
    service.let_the_next_status_miss_the_receipt().await;
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.fenced, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);

    // The content left and the service holds it, so the account of what left says so, and no note
    // moves, because the generation that admitted the work has been fenced.
    let published = client.store().publications().expect("records");
    assert_eq!(published.len(), 1);
    assert_eq!(published.items[0].position, at(1));
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none()
    );
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains("write 1"));
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
}

/// A device whose write was applied, whose answer was lost, and whose receipt the service no
/// longer keeps.
///
/// From here that is exactly what a request which never arrived looks like, which is the whole
/// difficulty: neither says the write did not land.
async fn a_write_whose_receipt_is_gone(
    directory: &std::path::Path,
    service: &Arc<Service>,
) -> (SyncClient, SyncObjectId) {
    let (client, object_id) = device_client(directory, "one", service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");
    let request_id = service.exchanges().await[0].request_id;
    assert!(
        service
            .stored(&sync_collection(SyncObjectKind::Settings, object_id))
            .await
            .is_some(),
        "the write landed, whatever this device can establish about it"
    );
    service.sweep_the_receipt(request_id).await;
    (client, object_id)
}

/// About a month, which is the order of how long a service keeps a receipt.
///
/// Nothing in this client measures against it. It is here so a test can say that a long time
/// passed, because what decides a fence is the service's own record of what it has swept and not
/// any interval this device could measure.
const A_LONG_TIME_MS: u64 = 30 * 24 * 60 * 60 * 1_000;

#[tokio::test]
async fn a_fence_the_service_says_nothing_ran_under_leaves_nothing_behind() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The request never reaches the service, so nothing ran under it and no receipt was ever
    // written. From this device that looks exactly like a receipt that has been swept, and the
    // service is what can tell the two apart.
    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");
    assert!(
        service.collections().await.is_empty(),
        "nothing of this request is on the service"
    );
    assert_eq!(
        service.swept_through().await,
        0,
        "the service has removed no receipt, so it still holds every one it ever wrote"
    );

    // A long time later, so that nothing here depends on how soon the fence follows the dispatch.
    // The fence finds no receipt for the identity and has swept none that could have been one, so
    // it says the request never ran and nothing of it is anywhere.
    service.its_clock_reads(NOW + A_LONG_TIME_MS).await;
    client.fence(2).expect("fenced");
    let cancelled = client
        .cancel_undispatched(2, TimestampMs::new(NOW + A_LONG_TIME_MS))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(cancelled.reconciled.accounts_kept, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert!(client.store().requests().expect("requests").is_empty());
    assert_eq!(
        client.exported().expect("exported"),
        Vec::new(),
        "a request the service says never ran leaves nothing of itself anywhere"
    );
}

#[tokio::test]
async fn a_fence_the_service_cannot_vouch_for_keeps_the_account_of_what_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = a_write_whose_receipt_is_gone(directory.path(), &service).await;

    // While the generation that admitted it is in force, nothing ends it: the work stays counted
    // and the next pass asks again.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.unresolved, 1);
    assert_eq!(reconciled.fenced, 0);
    assert_eq!(client.outstanding().expect("a count"), 1);

    // The service swept a receipt recorded inside the window this identity's attempts could bear,
    // so it can no longer tell a request it ran from one it never saw. The fence still ends the
    // request, because nothing executes under a fenced identity, so the barrier releases. What the
    // service cannot say is whether the write had already run.
    assert!(
        service.swept_through().await >= NOW,
        "the sweep passed the instant a receipt for this identity would bear"
    );
    let after = NOW + A_LONG_TIME_MS;
    service.its_clock_reads(after).await;
    client.fence(2).expect("fenced");
    let cancelled = client
        .cancel_undispatched(2, TimestampMs::new(after))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(
        cancelled.reconciled.accounts_kept, 1,
        "the fence ended it, and the service could not say it never ran"
    );
    assert_eq!(
        client.outstanding().expect("a count"),
        0,
        "nothing more can happen to it, so the barrier is not waiting for it"
    );

    // The ciphertext left this device and the service may be holding it, so the account says so.
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].kind.contains("never accounted for"));
    assert!(
        exported[0]
            .reference
            .contains(&sync_collection(SyncObjectKind::Settings, object_id))
    );
    assert_eq!(
        exported[0].left_at_ms,
        TimestampMs::new(NOW),
        "when the content left, not when something got round to ending the request"
    );
    assert!(!exported[0].deletable);
    assert!(
        client
            .kept()
            .expect("kept")
            .iter()
            .any(|entry| entry.what.contains("too late to say whether it ran"))
    );

    // It is an account and not content: a cleanup removes what this device holds and leaves it,
    // and the record carries no ciphertext to remove.
    let removed = client
        .remove_retained(2, TimestampMs::new(after))
        .await
        .expect("removed");
    assert_eq!(
        removed.records, 0,
        "the request was ended at the service, not removed as local content"
    );
    assert_eq!(client.exported().expect("exported").len(), 1);
    let held = client.store().requests().expect("requests");
    assert_eq!(held.len(), 1);
    assert!(held.items[0].ended());
    assert_eq!(
        held.items[0].ciphertext(),
        None,
        "an account carries no content"
    );
}

#[tokio::test]
async fn an_attempt_is_signed_with_the_instant_the_store_recorded_and_a_second_never_moves_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The answer is lost, so the record stays where this device can read it.
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // What went on the wire is what the record says, because the store is what the caller read it
    // out of. A fence is decided against that recorded instant afterwards, so an attempt signed
    // with an instant of its own would be an attempt nothing wrote down.
    let held = client.store().requests().expect("requests");
    assert_eq!(held.len(), 1);
    assert_eq!(
        held.items[0].signing_times(),
        Some((TimestampMs::new(NOW), TimestampMs::new(NOW))),
        "one attempt, so the first and the newest instant are that attempt's"
    );
    assert_eq!(service.exchanges().await[0].signed_at_ms, NOW);

    // A further attempt keeps the earliest instant any attempt was signed at and moves the latest.
    // The earliest bounds how far back a receipt of a run could go, so a later attempt may not
    // move it forward; the latest bounds how long an attempt can still become fresh, so it moves
    // to whichever attempt was signed last.
    let again = held.items[0]
        .clone()
        .attempted_at(TimestampMs::new(NOW + 60_000));
    assert_eq!(
        again.signing_times(),
        Some((TimestampMs::new(NOW), TimestampMs::new(NOW + 60_000)))
    );

    // A clock corrected backwards between two attempts does not put the two instants the wrong way
    // round: an attempt signed before the one this device made first is the earliest there has
    // been, and the latest stays where the attempt signed last put it.
    let corrected = again.attempted_at(TimestampMs::new(NOW - 60_000));
    assert_eq!(
        corrected.signing_times(),
        Some((
            TimestampMs::new(NOW - 60_000),
            TimestampMs::new(NOW + 60_000)
        ))
    );

    // One piece of work leaves this device once, so a second dispatch is refused and the record
    // keeps both instants where they were.
    assert!(
        client
            .store()
            .begin_dispatch(
                held.items[0].work_id,
                object_id,
                TimestampMs::new(NOW + 60_000),
            )
            .is_err(),
        "one piece of work leaves this device once"
    );
    let held = client.store().requests().expect("requests");
    assert_eq!(
        held.items[0].signing_times(),
        Some((TimestampMs::new(NOW), TimestampMs::new(NOW)))
    );
}

#[tokio::test]
async fn a_request_signed_outside_the_freshness_window_never_runs_and_leaves_no_account() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // This device's clock is a day out when it signs, so the service refuses the request before
    // anything runs under it. That is the other half of what makes a signing time worth recording:
    // a request that runs, runs within the window of the instant it was signed at.
    let wrong = NOW + 24 * 60 * 60 * 1000;
    let refused = client
        .publish(object_id, TimestampMs::new(wrong))
        .await
        .expect_err("it was not signed within the window");
    assert_eq!(refused.code(), ErrorCode::ClockUntrusted);
    assert!(
        service.collections().await.is_empty(),
        "nothing ran, so nothing of it is on the service"
    );

    // The device cannot tell a refusal it never saw from an answer that was lost, so the work
    // stays counted until something ends it. The service can: it wrote no receipt for the identity
    // and has swept none, so the fence says nothing ever ran and there is no account to keep.
    assert_eq!(client.outstanding().expect("a count"), 1);
    client.fence(2).expect("fenced");
    let cancelled = client
        .cancel_undispatched(2, TimestampMs::new(wrong))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(cancelled.reconciled.accounts_kept, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(client.exported().expect("exported"), Vec::new());
}

/// A device whose request never reached the service, so nothing ran under its identity.
async fn a_request_that_never_arrived(
    directory: &std::path::Path,
    service: &Arc<Service>,
) -> (SyncClient, SyncObjectId) {
    let (client, object_id) = device_client(directory, "one", service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");
    assert!(
        service.collections().await.is_empty(),
        "nothing of this request is on the service"
    );
    (client, object_id)
}

#[tokio::test]
async fn a_status_answer_on_a_fenced_request_repeats_what_the_fence_said_about_the_past() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, _) = a_request_that_never_arrived(directory.path(), &service).await;

    // The fence lands and its answer is lost on the way back. The identity is fenced at the
    // service from now on, and its receipt holds what that fence established about the past.
    service.lose_the_next_fence_answer().await;
    client.fence(2).expect("fenced");
    let cancelled = client
        .cancel_undispatched(2, TimestampMs::new(NOW))
        .await
        .expect("cancelled");
    assert_eq!(
        cancelled.reconciled.unresolved, 1,
        "a fence whose answer was lost has established nothing here yet"
    );
    assert_eq!(client.outstanding().expect("a count"), 1);

    // A long time later the status query finds that fence receipt. A receipt is history: it
    // repeats what the fence concluded rather than being decided again now, so asking again
    // concludes exactly what the lost answer would have.
    let later = NOW + A_LONG_TIME_MS;
    service.its_clock_reads(later).await;
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(later))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.fenced, 1);
    assert_eq!(
        reconciled.accounts_kept, 0,
        "the fence that ran is the one that decides, and it found nothing had ever run"
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert!(client.store().requests().expect("requests").is_empty());
    assert_eq!(client.exported().expect("exported"), Vec::new());
}

#[tokio::test]
async fn a_status_answer_on_a_request_the_fence_could_not_vouch_for_keeps_the_account() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, _) = a_write_whose_receipt_is_gone(directory.path(), &service).await;

    // The service has swept a receipt this identity's attempts could have borne, so the fence it
    // records says only that nothing more will run. Its answer is lost on the way back.
    service.lose_the_next_fence_answer().await;
    client.fence(2).expect("fenced");
    client
        .cancel_undispatched(2, TimestampMs::new(NOW))
        .await
        .expect("cancelled");
    assert_eq!(client.outstanding().expect("a count"), 1);

    // The status query finds that fence receipt and repeats what it holds. The barrier releases
    // and the account of what left this device stays.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.fenced, 1);
    assert_eq!(reconciled.accounts_kept, 1);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(client.exported().expect("exported").len(), 1);
}

#[tokio::test]
async fn a_fence_whose_own_receipt_was_swept_is_asked_again_and_keeps_the_account() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, _) = a_request_that_never_arrived(directory.path(), &service).await;

    // The first fence lands while the service still holds every receipt it wrote, and its answer
    // is lost, so this device learns nothing from it.
    let fenced_at = NOW + A_LONG_TIME_MS;
    service.its_clock_reads(fenced_at).await;
    service.lose_the_next_fence_answer().await;
    client.fence(2).expect("fenced");
    client
        .cancel_undispatched(2, TimestampMs::new(fenced_at))
        .await
        .expect("cancelled");
    assert_eq!(client.outstanding().expect("a count"), 1);

    // That fence receipt reaches its own retention and is swept, which carries the service's mark
    // past the window this identity's attempts fall in. The next pass fences again, and the second
    // fence can no longer say that no receipt of a run was ever removed.
    let request_id = service.exchanges().await[0].request_id;
    service.sweep_the_receipt(request_id).await;
    assert_eq!(service.swept_through().await, fenced_at);
    service.its_clock_reads(fenced_at + A_LONG_TIME_MS).await;
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(fenced_at + A_LONG_TIME_MS))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.fenced, 1);
    assert_eq!(
        reconciled.accounts_kept, 1,
        "the fence this device got an answer from could vouch for nothing"
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(client.exported().expect("exported").len(), 1);
}

#[tokio::test]
async fn a_device_clock_stepped_between_the_dispatch_and_the_fence_changes_nothing() {
    // The answer is the service's, taken from records this device cannot move: it reads no clock
    // to reach it and compares no instants. So stepping this device's clock either way between the
    // dispatch and the fence decides nothing.
    for step in [
        0_i64,
        -3 * 24 * 60 * 60 * 1000,
        3 * 24 * 60 * 60 * 1000,
        -(A_LONG_TIME_MS as i64),
    ] {
        let directory = tempfile::tempdir().expect("a directory");
        let service = Arc::new(Service::default());
        let (client, _) = a_write_whose_receipt_is_gone(directory.path(), &service).await;

        // The service swept a receipt this identity's attempts could have borne, so the account of
        // what left has to be kept.
        let fence_at = NOW + A_LONG_TIME_MS;
        service.its_clock_reads(fence_at).await;
        client.fence(2).expect("fenced");
        // Whatever this device's clock has been set to since it dispatched the request.
        let device_now = u64::try_from(i64::try_from(fence_at).expect("a signed instant") + step)
            .expect("an instant");
        let cancelled = client
            .cancel_undispatched(2, TimestampMs::new(device_now))
            .await
            .expect("cancelled");
        assert_eq!(cancelled.reconciled.fenced, 1);
        assert_eq!(
            cancelled.reconciled.accounts_kept, 1,
            "a device clock stepped by {step} ms cannot delete the account of an upload"
        );
        assert_eq!(client.outstanding().expect("a count"), 0);
        assert_eq!(client.exported().expect("exported").len(), 1);
    }
}

#[tokio::test]
async fn a_fence_carries_the_signing_times_the_request_record_holds() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, _) = a_request_that_never_arrived(directory.path(), &service).await;

    // What the fence carries is what the record says, because the service decides from those two
    // instants: the first bounds how far back a receipt of a run could go, and the newest bounds
    // how long an attempt can still become fresh. An instant this device read while asking would
    // be an instant nothing wrote down.
    let held = client.store().requests().expect("requests");
    let (first, last) = held.items[0].signing_times().expect("a dispatched request");
    client.fence(2).expect("fenced");
    client
        .cancel_undispatched(2, TimestampMs::new(NOW + A_LONG_TIME_MS))
        .await
        .expect("cancelled");
    let asked = service.fence_requests().await;
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].first_signed_at_ms, first.get());
    assert_eq!(asked[0].last_signed_at_ms, last.get());
    assert_eq!(asked[0].request_id, service.exchanges().await[0].request_id);
}

/// A client over one store, shared so a test can reconcile in a task of its own.
fn shared_client(
    directory: &std::path::Path,
    name: &str,
    service: &Arc<Service>,
) -> Arc<SyncClient> {
    Arc::new(SyncClient::new(
        Arc::clone(service) as Arc<dyn SyncBackupService>,
        Arc::new(DeviceSealer::new(0x5a)) as Arc<dyn DraftSealer>,
        SyncStore::open(directory.join(name)).expect("a store"),
    ))
}

#[tokio::test]
async fn privacy_moving_while_a_status_query_is_out_publishes_no_late_result() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let client = shared_client(directory.path(), "one", &service);
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // The pass asks about the request, and privacy mode moves past the generation that admitted the
    // work while that answer is out. What comes back is an accepted write of a generation that is
    // no longer in force.
    service.status_gate.hold_the_next_call().await;
    let reconciling = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.reconcile_unsettled(TimestampMs::new(NOW + 1)).await }
    });
    service.status_gate.wait_for_a_call().await;
    client.fence(2).expect("fenced");
    client.store().advance_privacy(2).expect("moved on");
    service.status_gate.let_it_go();

    let reconciled = reconciling
        .await
        .expect("the task finished")
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(client.outstanding().expect("a count"), 0);

    // Nothing of that generation is published: the note does not move and no copy is written. The
    // account of what left is kept all the same, because the content did leave this device.
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none(),
        "a note written now would be production state the cleanup had already removed"
    );
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains("write 1"));
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
}

#[tokio::test]
async fn privacy_moving_while_a_fence_is_out_still_ends_the_request() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let client = shared_client(directory.path(), "one", &service);
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it never arrived");
    client.fence(2).expect("fenced");
    client.store().advance_privacy(2).expect("moved on");

    // The fence is out when privacy mode moves on again. A fence ends a request whatever generation
    // is in force by the time its answer lands: the barrier is about what the service may still do,
    // and a generation cannot make an ended request run.
    service.fence_gate.hold_the_next_call().await;
    let reconciling = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.reconcile_unsettled(TimestampMs::new(NOW + 1)).await }
    });
    service.fence_gate.wait_for_a_call().await;
    client.fence(3).expect("fenced");
    client.store().advance_privacy(3).expect("moved on");
    service.fence_gate.let_it_go();

    let reconciled = reconciling
        .await
        .expect("the task finished")
        .expect("reconciled");
    assert_eq!(reconciled.fenced, 1);
    assert_eq!(
        reconciled.accounts_kept, 0,
        "the fence landed while a receipt of a run would still have been there to find"
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert!(client.store().requests().expect("requests").is_empty());
    assert_eq!(client.exported().expect("exported"), Vec::new());
}

#[tokio::test]
async fn a_fence_that_finds_a_refusal_settles_it_and_keeps_the_copy_the_service_named() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let collection = sync_collection(SyncObjectKind::Settings, object_id);

    // Another device's content is on the service, at a place this device does not expect.
    let theirs = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    let sealed = DeviceSealer::new(0x5a)
        .seal(&kr_cbor::to_canonical_vec(&theirs).expect("canonical bytes"))
        .expect("sealed");
    service.hold(&collection, at(1), sealed).await;

    // This device's write is refused, the service keeps a copy of it, and the answer is lost.
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // The status query misses the receipt, so the pass fences instead, and the fence finds the
    // refusal the service had already recorded. A fence answers with what the receipt holds, so the
    // copy it names is settled exactly as the exchange's own answer would have been.
    client.fence(2).expect("fenced");
    client.store().advance_privacy(2).expect("moved on");
    service.let_the_next_status_miss_the_receipt().await;
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.fenced, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);

    // The refusal is an account of ciphertext that left: the service kept a copy of the write it
    // declined, and that copy is what the record names.
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(
        exported[0].kind.contains("kept as a copy by the service"),
        "what left is a refused write the service kept: {:?}",
        exported[0]
    );
    assert!(
        exported[0]
            .reference
            .contains("which the service holds as copy"),
        "the record names the copy the fence's answer named: {:?}",
        exported[0]
    );
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
    assert!(
        exported[0].deletable,
        "a copy the service kept is one this device can ask to have dropped"
    );
}

#[tokio::test]
async fn an_exchange_that_arrives_after_a_fence_executes_nothing() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The request is still on its way when this device gives up on it, so the service has no
    // receipt for it and the pass fences the identity.
    service.drop_the_next_request().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("it has not arrived");
    client.fence(2).expect("fenced");
    let cancelled = client
        .cancel_undispatched(2, TimestampMs::new(NOW + 1))
        .await
        .expect("cancelled");
    assert_eq!(cancelled.reconciled.fenced, 1);
    assert_eq!(cancelled.reconciled.accounts_kept, 0);
    assert!(client.store().requests().expect("requests").is_empty());

    // The delayed request finally reaches the service. Nothing executes under a fenced identity, so
    // the refusal is the answer and the collection is untouched, which is what makes the conclusion
    // this device already drew stay true.
    let sent = service.exchanges().await;
    let delayed = sent.last().expect("an exchange");
    let refused = service
        .compare_exchange(
            &delayed.collection,
            delayed.request_id,
            delayed.signed_at_ms,
            delayed.expected.as_ref().copied(),
            &delayed.ciphertext,
        )
        .await
        .expect_err("that identity was fenced");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
    assert!(
        service.collections().await.is_empty(),
        "a fenced identity writes nothing, whatever arrives under it"
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(client.exported().expect("exported"), Vec::new());
}

/// The store a child process is told to claim a request in.
const CHILD_STORE: &str = "KR_SYNC_LOCK_STORE";
/// The request a child process is told to claim.
const CHILD_REQUEST: &str = "KR_SYNC_LOCK_REQUEST";

/// Claims one request in this process and says what the store answered.
///
/// It runs in the child, so what it prints is the only thing the parent reads: a claim is an
/// operating-system lock and two processes are the only way to show that it is.
fn report_a_claim_from_this_process(directory: &str, work_id: &str) {
    let store = SyncStore::open(directory).expect("a store");
    let work_id = work_id.parse::<Uuid>().expect("a request identity");
    let answer = match store.claim_dispatched(work_id).expect("a claim") {
        Claimed::Taken(_, _) => "taken",
        Claimed::InHand => "in-hand",
        Claimed::Gone => "gone",
    };
    println!("claim: {answer}");
}

/// Runs this test binary again, in a child process, to claim one request.
///
/// The binary is copied to the temporary directory first, under the removable-volume rule: a
/// process this test starts opens nothing in the workspace, including the executable it runs.
fn claim_in_another_process(
    binary: &std::path::Path,
    directory: &std::path::Path,
    work_id: Uuid,
) -> String {
    let output = std::process::Command::new(binary)
        .arg("a_request_one_process_is_holding_cannot_be_claimed_by_another")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_STORE, directory)
        .env(CHILD_REQUEST, work_id.to_string())
        .output()
        .expect("the child ran");
    let printed = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "the child failed: {printed}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    printed
}

/// Copies this test binary somewhere a started process may open it.
fn binary_on_the_internal_disk(into: &std::path::Path) -> std::path::PathBuf {
    let copy = into.join(if cfg!(windows) {
        "claimant.exe"
    } else {
        "claimant"
    });
    kr_ipc::testing::place_program(&std::env::current_exe().expect("this binary"), &copy);
    copy
}

#[test]
fn a_request_one_process_is_holding_cannot_be_claimed_by_another() {
    // The child half. It is this same test, started again by the parent below with the store and
    // the request in its environment, because a claim is a lock the operating system keeps and
    // another value in this process would not meet it.
    if let (Ok(directory), Ok(work_id)) = (std::env::var(CHILD_STORE), std::env::var(CHILD_REQUEST))
    {
        report_a_claim_from_this_process(&directory, &work_id);
        return;
    }

    let workspace = tempfile::tempdir().expect("a directory");
    let store = SyncStore::open(workspace.path().join("one")).expect("a store");
    let binary = binary_on_the_internal_disk(workspace.path());
    let object_id = fresh_object_id().expect("an identity");
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    store.put_object(&mine).expect("stored");
    let staged = store
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    let dispatch = store
        .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW))
        .expect("dispatched");

    // While this process has the call out, another process is told so rather than being allowed to
    // conclude anything: a service writes its receipt when it commits the write, so a request still
    // on the wire has none either, and only the process making the call can tell the two apart.
    let printed = claim_in_another_process(&binary, store.directory(), staged.work_id);
    assert!(
        printed.contains("claim: in-hand"),
        "another process claimed a request this one is holding: {printed}"
    );

    // The call ends, and the request is claimable again, in the other process as much as in this
    // one. What that permits is asking the service, never concluding.
    drop(dispatch);
    let printed = claim_in_another_process(&binary, store.directory(), staged.work_id);
    assert!(
        printed.contains("claim: taken"),
        "a released request is one another process may ask about: {printed}"
    );
}

#[tokio::test]
async fn a_refusal_is_settled_even_when_the_copy_it_names_cannot_be_brought_down() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let (two, _) = device_client(directory.path(), "two", &service);

    // The other device writes first, so this device's comparison is the one that loses, and the
    // refusal never comes back.
    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW,
    );
    two.store().put_object(&mine).expect("stored");
    service.lose_the_next_answer().await;
    two.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the refusal never came back");

    // The service can be asked what became of the request and cannot be asked for what it holds.
    // The refusal is settled all the same: the service answered the comparison, and a fetch this
    // device cannot make costs the copy rather than the knowledge that the write did not land.
    service.stop_serving_what_it_holds().await;
    let reconciled = two
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(
        reconciled.copies_not_taken, 1,
        "the refusal is settled and the copy is what went missing"
    );
    assert_eq!(reconciled.unresolved, 0);
    assert_eq!(reconciled.unsettled, 0);
    assert_eq!(two.outstanding().expect("a count"), 0);
    assert!(
        two.store().conflicts(object_id).expect("copies").is_empty(),
        "there was no fetch to keep a copy from"
    );

    // This device's own content is where it was, the account of what left names the copy the
    // service kept, and the note has not moved on a fetch that never happened.
    assert_eq!(
        two.store()
            .object(object_id)
            .expect("held")
            .expect("this device's own")
            .revision,
        mine.revision
    );
    let exported = two.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].kind.contains("kept as a copy by the service"));
    assert!(two.store().checkpoint(object_id).expect("a note").is_none());

    // A later fetch is what brings the other device's content down, once the service can serve it.
    service.serve_what_it_holds_again().await;
    two.fetch(
        SyncObjectKind::Settings,
        object_id,
        TimestampMs::new(NOW + 2),
    )
    .await
    .expect("fetched");
    let copies = two.store().conflicts(object_id).expect("copies");
    assert_eq!(copies.len(), 1);
    assert_eq!(copies.items[0].other.revision, theirs.revision);
}

#[tokio::test]
async fn an_answer_naming_an_earlier_generation_never_moves_the_note_backwards() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let (two, _) = device_client(directory.path(), "two", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&mine).expect("stored");

    // This device's write is applied at generation 1 and its answer is lost.
    service.lose_the_next_answer().await;
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // Another device writes over it, and this device fetches what is there now.
    let theirs = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 1,
    );
    two.store().put_object(&theirs).expect("stored");
    two.store()
        .record_checkpoint(
            object_id,
            SyncCheckpoint {
                position: at(1),
                published_revision: Nullable::null(),
            },
        )
        .expect("a note");
    assert_eq!(
        two.publish(object_id, TimestampMs::new(NOW + 1))
            .await
            .expect("published"),
        Published::Accepted { position: at(2) }
    );
    one.fetch(
        SyncObjectKind::Settings,
        object_id,
        TimestampMs::new(NOW + 2),
    )
    .await
    .expect("fetched");
    assert_eq!(
        one.store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("the fetch left one")
            .position,
        at(2)
    );

    // The older receipt is settled last. It names write 1, which is where that write left the
    // object, and the note stays where the later answer put it.
    let reconciled = one
        .reconcile_unsettled(TimestampMs::new(NOW + 3))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(one.outstanding().expect("a count"), 0);
    assert_eq!(
        one.store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("a note")
            .position,
        at(2),
        "an answer about an older state does not make it the current one"
    );
}

#[tokio::test]
async fn a_write_under_a_place_another_history_holds_keeps_its_own_account() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW))
            .await
            .expect("published"),
        Published::Accepted { position: at(1) }
    );

    // A second request of the same object is answered with write one under another name. One write
    // sequence names one write for the life of a collection, so this is a second history rather
    // than a later state of the first, and the object's record can hold only one of them.
    let forked = SyncPosition::at(1, SyncRevision::new(Uuid::from_bytes([0xbb; 16])));
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    drop(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW + 1))
            .expect("dispatched"),
    );
    assert_eq!(
        client
            .store()
            .settle(
                &claim(client.store(), staged.work_id),
                &staged,
                Outcome::Accepted { position: forked },
            )
            .expect("settled")
            .settlement,
        Settlement::Published
    );

    // The record on disk already says `Diverged`, before anything has read the store and repaired
    // it. That is what makes a stop here harmless: a record left saying `Applied` would be
    // re-decided against whatever the object's record named by then, and a later publication would
    // make this write look like ordinary older news and drop the account of what left under it.
    let on_disk: RequestRecord = kr_cbor::from_canonical_slice(
        &std::fs::read(
            directory
                .path()
                .join("one")
                .join(format!("{}.request", staged.work_id)),
        )
        .expect("the request's record"),
        &kr_cbor::Limits::DEFAULT,
    )
    .expect("a record");
    assert_eq!(on_disk.state, RequestState::Diverged { position: forked });

    // The object's record still names the write this device established, and the ciphertext that
    // left under the other one is accounted for by the request's own record rather than dropped.
    let published = client.store().publications().expect("records");
    assert_eq!(published.len(), 1);
    assert_eq!(published.items[0].position, at(1));
    let held = client.store().requests().expect("requests");
    assert_eq!(held.len(), 1);
    assert!(held.items[0].ended());
    assert_eq!(
        held.items[0].state,
        RequestState::Diverged { position: forked },
        "the record says once and for all that the object's record went to another history"
    );
    assert_eq!(
        client.outstanding().expect("a count"),
        0,
        "the request is over, whatever the object's record names"
    );

    // A later publication of the object moves its record on. That is ordinary news about this
    // device's own history and says nothing about the other one, so the account stays.
    let later = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 2,
    );
    client.store().put_object(&later).expect("stored");
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("published"),
        Published::Accepted { position: at(2) }
    );
    let held = client.store().requests().expect("requests");
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(
        held.items[0].state,
        RequestState::Diverged { position: forked }
    );

    // Both are named among what left, and reading it again does not lose either of them.
    for _ in 0..2 {
        let exported = client.exported().expect("exported");
        assert_eq!(exported.len(), 2, "{exported:?}");
        assert!(
            exported
                .iter()
                .any(|entry| entry.reference.contains(&format!("{}", at(2))))
        );
        assert!(
            exported
                .iter()
                .any(|entry| entry.reference.contains(&format!("{forked}")))
        );
    }
}

#[tokio::test]
async fn a_stop_after_the_fork_is_recorded_keeps_the_account_when_the_object_moves_on() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // A second request of the same object goes out and is answered at write one under another
    // name. The device stops with the settlement's **first** replacement on disk and nothing after
    // it: the record says which history took the write, and the object's own record still names
    // the other one. That is the state this store must come back to and finish from.
    let forked = SyncPosition::at(1, SyncRevision::new(Uuid::from_bytes([0xbb; 16])));
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    drop(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW + 1))
            .expect("dispatched"),
    );
    let dispatched = client
        .store()
        .requests()
        .expect("requests")
        .items
        .into_iter()
        .find(|item| item.work_id == staged.work_id)
        .expect("the dispatched record");
    let path = directory
        .path()
        .join("one")
        .join(format!("{}.request", staged.work_id));
    std::fs::write(
        &path,
        kr_cbor::to_canonical_vec(&RequestRecord {
            state: RequestState::Diverged { position: forked },
            ..dispatched
        })
        .expect("canonical bytes"),
    )
    .expect("the record a stop would have left");

    // Before anything reads the store again, a later publication of the object moves the object's
    // own record on. Under a record that said only that the write was applied, the repair would
    // now read it against write two, call it ordinary older news and remove it, and the ciphertext
    // that left under the other history would be accounted for by nothing.
    let later = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 2,
    );
    client.store().put_object(&later).expect("stored");
    assert_eq!(
        client
            .publish(object_id, TimestampMs::new(NOW + 2))
            .await
            .expect("published"),
        Published::Accepted { position: at(2) }
    );

    // The first read to report runs the repair. The account is still there and still says which
    // history took the write.
    let held = client.store().requests().expect("requests");
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(
        held.items[0].state,
        RequestState::Diverged { position: forked }
    );
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert!(
        exported
            .iter()
            .any(|entry| entry.reference.contains(&format!("{forked}"))),
        "the ciphertext that left under the other history is still accounted for: {exported:?}"
    );
}

#[tokio::test]
async fn a_publication_record_two_histories_claim_is_reported_even_when_the_note_has_moved_on() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // A second request, from a device that has forgotten where the object stands, so it names no
    // position and no place in the order is behind it. While it is out, the note beside the object
    // is moved past write one, which is what a fetch of a later state does. The request is then
    // answered at write one under another name: the note reads that as ordinary older news, and
    // the object's publication record is the one that still holds the place another write took.
    client
        .store()
        .forget_checkpoint(object_id)
        .expect("forgotten");
    let forked = SyncPosition::at(1, SyncRevision::new(Uuid::from_bytes([0xbb; 16])));
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    assert_eq!(staged.expected, Nullable::null());
    drop(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW + 1))
            .expect("dispatched"),
    );
    client
        .store()
        .record_checkpoint(
            object_id,
            SyncCheckpoint {
                position: at(2),
                published_revision: Nullable::null(),
            },
        )
        .expect("a note");
    let settled = client
        .store()
        .settle(
            &claim(client.store(), staged.work_id),
            &staged,
            Outcome::Accepted { position: forked },
        )
        .expect("settled");
    assert_eq!(
        settled.diverged,
        Some(at(1)),
        "the caller is owed the fork whichever of this device's records found it"
    );
    assert_eq!(
        client
            .store()
            .requests()
            .expect("requests")
            .items
            .into_iter()
            .find(|item| item.work_id == staged.work_id)
            .expect("a record")
            .state,
        RequestState::Diverged { position: forked },
        "and the account of what left under the other history is kept"
    );
}

#[tokio::test]
async fn a_reconciliation_counts_a_place_two_histories_claim_rather_than_refusing() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // A second write goes out and its answer is lost. The service put it at a place its own order
    // had already used, which is a second history rather than a later state of this one.
    let forked = SyncPosition::at(1, SyncRevision::new(Uuid::from_bytes([0xbb; 16])));
    service.applies_the_next_write_at(forked).await;
    service.lose_the_next_answer().await;
    let later = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 1,
    );
    client.store().put_object(&later).expect("stored");
    client
        .publish(object_id, TimestampMs::new(NOW + 1))
        .await
        .expect_err("the answer never came back");

    // The pass that learns of it is ending a barrier rather than answering one caller, so it
    // settles the request and counts what it found instead of refusing.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 2))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(reconciled.diverged, 1);
    assert_eq!(reconciled.unresolved, 0);
    assert_eq!(client.outstanding().expect("a count"), 0);
    let exported = client.exported().expect("exported");
    assert!(
        exported
            .iter()
            .any(|entry| entry.reference.contains(&format!("{forked}"))),
        "{exported:?}"
    );
}

#[tokio::test]
async fn a_note_two_histories_claim_is_reported_rather_than_left_to_a_later_comparison() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let client = gated_client(directory.path(), "one", &service);
    let object_id = fresh_object_id().expect("an identity");
    let theirs = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    let sealed = DeviceSealer::new(0x5a)
        .seal(&kr_cbor::to_canonical_vec(&theirs).expect("canonical bytes"))
        .expect("sealed");
    let collection = sync_collection(SyncObjectKind::Settings, object_id);
    service.inner.hold(&collection, at(5), sealed).await;
    client
        .store()
        .record_checkpoint(
            object_id,
            SyncCheckpoint {
                position: at(4),
                published_revision: Nullable::null(),
            },
        )
        .expect("a note");

    // The fetch leaves against write four, which the answer follows from. While it is out, another
    // observation records write five under a different name, so by the time the answer is applied
    // the note and the answer claim one place in the order under two names.
    service.hold_the_next_fetch().await;
    let fetching = tokio::spawn({
        let client = Arc::clone(&client);
        async move {
            client
                .fetch(
                    SyncObjectKind::Settings,
                    object_id,
                    TimestampMs::new(NOW + 1),
                )
                .await
        }
    });
    service.wait_for_a_publication().await;
    let other_history = SyncPosition::at(5, SyncRevision::new(Uuid::from_bytes([0xaa; 16])));
    client
        .store()
        .record_checkpoint(
            object_id,
            SyncCheckpoint {
                position: other_history,
                published_revision: Nullable::null(),
            },
        )
        .expect("a note");
    service.let_it_go();

    // The diagnosis before the call could not see it, and the next comparison may never meet it:
    // the service can reach write six, which follows from either history. So it is reported here.
    let error = fetching
        .await
        .expect("the task finished")
        .expect_err("two histories claim write five");
    assert!(
        matches!(
            error,
            SyncError::ForkedHistory {
                expected: SyncPosition {
                    write_sequence: 5,
                    ..
                },
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.code(), ErrorCode::DraftConflict);
    assert_eq!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .expect("a note")
            .position,
        other_history,
        "the note this device established is not replaced by the other history"
    );
}

#[tokio::test]
async fn a_fetch_keeps_a_copy_beside_what_this_device_holds_when_the_answer_comes_back() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(GatedService::new());
    let one = gated_client(directory.path(), "one", &service);
    let two = gated_client(directory.path(), "two", &service);
    let object_id = fresh_object_id().expect("an identity");
    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    // The gate holds every publication, so the other device's write goes through it first.
    let publishing = tokio::spawn({
        let one = Arc::clone(&one);
        async move { one.publish(object_id, TimestampMs::new(NOW)).await }
    });
    service.wait_for_a_publication().await;
    service.let_it_go();
    publishing
        .await
        .expect("the task finished")
        .expect("published");

    // This device holds nothing for the object when the fetch leaves, and stores its own content
    // while the answer is still out. Whether there is a choice to keep is a question about the
    // object as it is when the answer is applied, not as it was when the call left.
    service.hold_the_next_fetch().await;
    let fetching = tokio::spawn({
        let two = Arc::clone(&two);
        async move {
            two.fetch(
                SyncObjectKind::Settings,
                object_id,
                TimestampMs::new(NOW + 1),
            )
            .await
        }
    });
    service.wait_for_a_publication().await;
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 1,
    );
    two.store().put_object(&mine).expect("stored");
    service.let_it_go();

    let restored = fetching.await.expect("the task finished").expect("fetched");
    assert!(
        restored.copy().is_some(),
        "the content that came down is a choice beside what this device holds, not a replacement"
    );
    assert_eq!(
        two.store()
            .object(object_id)
            .expect("held")
            .expect("this device's own")
            .revision,
        mine.revision,
        "a fetch applies nothing"
    );
    let copies = two.store().conflicts(object_id).expect("copies");
    assert_eq!(copies.len(), 1);
    assert_eq!(copies.items[0].other.revision, theirs.revision);
    assert_eq!(copies.items[0].offered_revision, mine.revision);
}

#[tokio::test]
async fn a_staged_payload_past_the_readers_collection_bound_is_read_back() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    // Well past the four thousand members a collection may hold, which is what a sealed object
    // written as a list of numbers would have been bounded by.
    let long = "s".repeat(8 * 1024);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", long.as_str())], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    service.lose_the_next_answer().await;
    client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("the answer never came back");

    // The record is readable, which is what makes the work settleable at all.
    let staged = client.store().requests().expect("requests");
    assert!(
        staged.unreadable.is_empty(),
        "a staged record this device cannot open is work it can never settle"
    );
    assert_eq!(staged.len(), 1);
    assert!(
        staged.items[0]
            .ciphertext()
            .expect("it is still to be answered")
            .len()
            > 4_096
    );
    assert_eq!(client.outstanding().expect("a count"), 1);

    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled.settled, 1);
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert_eq!(
        service
            .stored(&sync_collection(SyncObjectKind::Settings, object_id))
            .await
            .expect("it is stored")
            .1,
        service.exchanges().await[0].ciphertext,
        "what the service holds is the sealed object this device staged"
    );
}

#[tokio::test]
async fn a_refused_write_the_service_kept_a_copy_of_is_named_among_what_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (one, object_id) = device_client(directory.path(), "one", &service);
    let (two, _) = device_client(directory.path(), "two", &service);

    let theirs = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    one.store().put_object(&theirs).expect("stored");
    one.publish(object_id, TimestampMs::new(NOW))
        .await
        .expect("published");

    // This device's comparison is the one that loses. The service keeps the rejected write as a
    // copy of its own, so the ciphertext is on the service whatever the comparison decided.
    let mine = object(
        object_id,
        2,
        SyncBody::Settings(settings(&[("theme", "light")], &[])),
        NOW + 1,
    );
    two.store().put_object(&mine).expect("stored");
    assert!(matches!(
        two.publish(object_id, TimestampMs::new(NOW + 1))
            .await
            .expect("answered"),
        Published::Conflicted { .. }
    ));

    let exported = two.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].kind.contains("kept as a copy by the service"));
    assert!(exported[0].reference.contains("holds as copy"));
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW + 1));
    assert!(
        exported[0].deletable,
        "a copy the service kept is one this device can ask to have dropped"
    );
    assert!(
        two.kept()
            .expect("kept")
            .iter()
            .any(|entry| entry.what.contains("kept a copy of"))
    );

    // It is an account and not content: a cleanup removes what this device holds and leaves it.
    two.fence(1).expect("fenced");
    two.remove_retained(1, TimestampMs::new(NOW + 2))
        .await
        .expect("removed");
    assert_eq!(two.exported().expect("exported").len(), 1);
}

#[tokio::test]
async fn an_identity_another_request_has_worn_never_settles_this_payload() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The service says the identity this request presented already answered a different one.
    service.give_the_next_identity_to_another_request().await;
    let error = client
        .publish(object_id, TimestampMs::new(NOW))
        .await
        .expect_err("that identity is taken");
    assert_eq!(error.code(), ErrorCode::IdConflict);

    // The service compared this content against the receipt it holds and declined to run it, so
    // this payload did not execute and never will under that identity. That ends the request: the
    // work goes, and nothing of it is on the service to account for.
    assert_eq!(client.outstanding().expect("a count"), 0);
    assert!(client.store().requests().expect("requests").is_empty());
    assert_eq!(client.exported().expect("exported"), Vec::new());

    // The receipt under that identity says applied. It is never asked for, because it accounts for
    // the other request: settling this payload from it would put the note at a revision this
    // content never produced.
    let reconciled = client
        .reconcile_unsettled(TimestampMs::new(NOW + 1))
        .await
        .expect("reconciled");
    assert_eq!(reconciled, Reconciled::default());
    assert!(
        service.status_queries().await.is_empty(),
        "an identity another request wore is not one to ask about"
    );
    assert!(
        service.fence_requests().await.is_empty(),
        "nor one to ask the service to end, because it is already over"
    );
    assert!(
        client
            .store()
            .checkpoint(object_id)
            .expect("a note")
            .is_none()
    );
}

#[tokio::test]
async fn a_late_refusal_names_the_copy_the_service_kept_and_when_the_content_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let service = Arc::new(Service::default());
    let (client, object_id) = device_client(directory.path(), "one", &service);
    let mine = object(
        object_id,
        1,
        SyncBody::Settings(settings(&[("theme", "dark")], &[])),
        NOW,
    );
    client.store().put_object(&mine).expect("stored");

    // The copy the caller holds is the one admission returned, which names no departure: the
    // instant is written when the work is dispatched, and the store is what remembers it.
    let staged = client
        .store()
        .admit(object_id, |object| {
            Ok(kr_cbor::to_canonical_vec(object).expect("canonical bytes"))
        })
        .expect("admitted");
    assert_eq!(staged.signing_times(), None);
    drop(
        client
            .store()
            .begin_dispatch(staged.work_id, object_id, TimestampMs::new(NOW))
            .expect("dispatched"),
    );

    // Privacy mode moves past the generation that admitted the work, and the refusal arrives
    // afterwards: nothing may be published from it, and what it says about content that left is
    // recorded all the same.
    client.fence(2).expect("fenced");
    client.store().advance_privacy(2).expect("moved on");
    let conflict_id = SyncConflictId::new(fresh_request_id());
    assert_eq!(
        client
            .store()
            .settle(
                &claim(client.store(), staged.work_id),
                &staged,
                Outcome::Refused {
                    retained: Some(conflict_id)
                },
            )
            .expect("settled")
            .settlement,
        Settlement::Discarded {
            produced_under: 0,
            current: 2
        }
    );

    // What left is named once, with the instant the content left rather than the instant something
    // got round to asking about it.
    let exported = client.exported().expect("exported");
    assert_eq!(exported.len(), 1);
    assert!(exported[0].reference.contains(&conflict_id.to_string()));
    assert_eq!(exported[0].left_at_ms, TimestampMs::new(NOW));
}
