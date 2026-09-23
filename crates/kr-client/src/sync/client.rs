//! The compare-and-swap client, and the privacy operations a host drives it through.
//!
//! # How a write is decided
//!
//! Section 20: *sync uses per-object revision IDs and compare-and-swap writes*. A publication sends
//! the object this device holds against the position this device last saw, which is the
//! [`SyncCheckpoint`] beside the object and never the object's own revision. The service answers
//! with the position it put the write at, or it refuses because another device wrote first.
//!
//! A position is the service's own: the name it gave one write, and where that write falls in the
//! collection's order. The order is what this device compares two answers by, and it is the
//! service's to state, because a device that numbered answers as they arrived would put a delayed
//! reply after the write that superseded it. A service that answers with an earlier write than the
//! note names has gone back behind what this device already saw, and one that answers with another
//! name for the same place in the order has forked; this client says which, and writes neither.
//!
//! A refusal is not a failure. It is the answer that somebody else's content is there, and section
//! 20 keeps that content for the person to choose from instead of taking whichever clock was
//! further ahead. So the refusal brings the other content down **beside** this device's own, as a
//! [`ConflictCopy`], and this device's settings are exactly as they were. Nothing here chooses.
//!
//! The service keeps a copy of the refused write as well, for the same reason, and once one object
//! holds as many unresolved copies as the service keeps, a write of it that loses its comparison is
//! refused outright rather than kept for anybody to choose from. So the person's choice goes to
//! both places: [`SyncClient::resolve`] takes the copy out of this device's store and drops the
//! one copy the service kept of the refused write it answers, and a choice the service could not be
//! told about is recorded and told again. A copy the service kept with nothing here to choose about
//! is dropped when the person asks for exactly that, through [`SyncClient::drop_kept_copy`].
//!
//! # What a restore can never reach
//!
//! Host grants and revocation state have one host authority. This client holds no handle to any
//! authority store, and [`super::SyncBody`] has no variant that could carry one: a restored object
//! is settings or a client's position, and that is all it can be. A draft is refused and named for
//! the draft store, so there is one way to write a draft on this device.
//!
//! # Privacy mode
//!
//! Section 24 disables sync production prospectively at a recorded privacy generation, fences what
//! is content-bearing, cancels what was admitted and never dispatched, removes retained local
//! content, reconciles in-flight work before reporting complete and publishes no late
//! old-generation result. The methods below are those operations, in the host's own vocabulary and
//! taking the host's generation as a plain number, because a client never depends on a host crate.
//! The two cleanup steps reconcile before they measure, so what they report as still in flight is
//! what the service could not account for rather than everything whose answer went missing. Their
//! semantics are the host's contract exactly:
//!
//! | This client | The host's subsystem contract |
//! | --- | --- |
//! | [`SyncClient::fence`] | stop every content-bearing queue, at once |
//! | [`SyncClient::cancel_undispatched`] | take back what was admitted and never dispatched |
//! | [`SyncClient::remove_retained`] | remove the retained local content |
//! | [`SyncClient::reconcile_unsettled`] | reconcile the work that was dispatched, before reporting |
//! | [`SyncClient::outstanding`] | how much dispatched work has no settled outcome |
//! | [`SyncClient::kept`] | what is kept, explicitly |
//! | [`SyncClient::exported`] | what already left, which is shown rather than erased |
//! | [`SyncClient::accepts_result`] | a result is published only under the generation in force |
//!
//! [`SyncClient::resume`] is the other half of the same contract: turning privacy mode off is a
//! boundary as much as turning it on, so it takes the new generation and lets production start
//! again. It reconstructs nothing that was omitted while privacy mode was on.

use std::sync::Arc;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{SyncConflictId, SyncObjectId, SyncRevisionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};
use kr_protocol::sync::SyncObjectKind;

use super::store::{
    Claimed, ConflictCopy, End, Outcome, PrivacyRecord, RequestRecord, RequestState, Result,
    Settlement, Standing, SyncCheckpoint, SyncError, SyncStore,
};
use super::{SyncBody, SyncObject, SyncSettings, Zeroising, sync_collection};
use crate::drafts::DraftSealer;
use crate::services::{
    SyncBackupService, SyncExchanged, SyncPosition, SyncRequestFence, SyncRequestStatus,
};

/// What became of a publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Published {
    /// The service accepted it, leaving the object here.
    Accepted {
        /// Where the service put this write.
        position: SyncPosition,
    },
    /// Another device had written first.
    ///
    /// This device's own object is exactly as it was. What the service held is kept beside it under
    /// `copy`, for the person to choose from, and the note now names where that content stands, so
    /// a caller that has chosen can publish against it.
    Conflicted {
        /// The copy that was kept.
        copy: SyncConflictId,
        /// The revision the other device's object carried.
        other_revision: SyncRevisionId,
        /// Where the service holds the object.
        position: SyncPosition,
    },
    /// The answer came back for work admitted under an earlier privacy generation.
    ///
    /// It is not published and the checkpoint is not moved. Section 24: no late old-generation
    /// result is published, because publishing one would publish content privacy mode had already
    /// disabled.
    Discarded {
        /// The generation the work was produced under.
        produced_under: u64,
        /// The generation in force now.
        current: u64,
    },
}

/// What came down from the service, and the copy it was kept as.
///
/// The object is not applied. Applying it is the caller's own step, and `copy` names the copy this
/// device kept beside its own content when it already held another revision, so a person can see
/// both before choosing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Restored {
    /// Settings another device published.
    Settings {
        /// The object the service held.
        object: SyncObject,
        /// The copy kept beside this device's own, when it held another revision.
        copy: Option<SyncConflictId>,
    },
    /// Where another device was looking.
    ClientSelection {
        /// The object the service held.
        object: SyncObject,
        /// The copy kept beside this device's own, when it held another revision.
        copy: Option<SyncConflictId>,
    },
}

impl Restored {
    /// Returns the object, whichever kind it is.
    #[must_use]
    pub const fn object(&self) -> &SyncObject {
        match self {
            Self::Settings { object, .. } | Self::ClientSelection { object, .. } => object,
        }
    }

    /// Returns the copy this device kept beside its own content, when it kept one.
    #[must_use]
    pub const fn copy(&self) -> Option<SyncConflictId> {
        match self {
            Self::Settings { copy, .. } | Self::ClientSelection { copy, .. } => *copy,
        }
    }
}

/// What one fence did.
///
/// The same two figures the host's own subsystems report: how many content-bearing queues were
/// stopped, and how many items they were holding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fenced {
    /// How many content-bearing queues were stopped. This client has one: its publication outbox.
    pub queues: u64,
    /// How many items that queue was holding.
    pub items: u64,
}

/// What one reconciliation of dispatched work established.
///
/// Every figure is counted from what the service answered about a request, never inferred from
/// what the object holds now. The last is read from the store afterwards, so it counts a record
/// this build cannot open as well: section 24 completes a cleanup when nothing is outstanding, and
/// a record that cannot be read is not one that can be called nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    /// How many dispatched requests the service accounted for, applied or refused.
    pub settled: u64,
    /// How many requests a fence ended, so that nothing will execute under them.
    ///
    /// The barrier releases for every one of them: an exchange under a fenced identity is refused,
    /// so no answer to any of these can arrive afterwards.
    pub fenced: u64,
    /// How many of those were fenced too late for the answer to say whether they had run.
    ///
    /// A fence says the service holds no outcome for the identity, which is what a request that
    /// never arrived and a request whose receipt has passed its retention both look like. Inside
    /// the retention the request provably never ran and nothing of it is anywhere. Past it, the
    /// ciphertext may be on the service, so the account of it stays in [`SyncClient::exported`]
    /// rather than being deleted because this device could not tell which had happened.
    pub accounts_kept: u64,
    /// How many this pass established no outcome for.
    ///
    /// A service that could not be asked and a request it holds no receipt for under the
    /// generation in force are both this: the work stays counted, and the next reconciliation asks
    /// again.
    pub unresolved: u64,
    /// How many answers put a write where this device's records cannot follow: behind or at the
    /// place the write replaced, or at a place another history already holds.
    ///
    /// The request is settled either way and its own record keeps the account of the ciphertext
    /// that left under it, because the object's record can name only one history. The note beside
    /// the object is not moved, so this device is still comparing against a collection the service
    /// it is talking to may never have held; `SyncStore::forget_checkpoint` is the recovery, and
    /// nothing does it automatically.
    pub diverged: u64,
    /// How many refusals were settled without bringing down the content the service holds.
    ///
    /// The refusal is settled either way, because the service answered the comparison. What the
    /// service kept of the refused write is recorded with it.
    /// What is missing is the copy section 20 keeps for the person to choose from, and a later
    /// fetch or publication brings it down.
    pub copies_not_taken: u64,
    /// What still counts as outstanding, read from the store when the pass had finished.
    pub unsettled: u64,
}

/// What one cancellation did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cancelled {
    /// How many admitted, undispatched publications were taken back.
    pub undispatched: u64,
    /// How many publications had already been dispatched and cannot be taken back.
    ///
    /// These are what the late-result rule exists for. They are counted rather than hidden, because
    /// reconciliation is not complete while any of them is outstanding.
    pub in_flight: u64,
    /// What the reconciliation this step ran established.
    ///
    /// A cleanup that reconciles and reports only a total hides which requests the service
    /// accounted for and which it could not be asked about, and those are different answers.
    pub reconciled: Reconciled,
}

/// What one local cleanup removed.
///
/// Local deletion is logical cleanup. This client removes its own files and does not claim the
/// bytes are unrecoverable from the device they were on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Removed {
    /// Bytes of retained content this client stopped holding.
    pub bytes: u64,
    /// Records this client stopped holding.
    pub records: u64,
    /// What the reconciliation this step ran established.
    ///
    /// Settling work is not removing retained content, so a request a reconciliation settled is in
    /// neither figure above. This is where it is reported.
    pub reconciled: Reconciled,
}

/// Something privacy mode keeps, and says it keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptExplicitly {
    /// What is kept.
    pub what: &'static str,
    /// Why keeping it is the honest answer.
    pub why: &'static str,
}

/// Something that had already left this device before privacy mode was enabled.
///
/// It is not erased and this client does not claim it could be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exported {
    /// What kind of copy it is.
    pub kind: String,
    /// The opaque reference a person is shown.
    pub reference: String,
    /// When it left.
    pub left_at_ms: TimestampMs,
    /// Whether this client holds a way to ask for the copy's removal.
    ///
    /// True for a copy the service kept of a refused write, which [`SyncClient::drop_kept_copy`]
    /// asks the service to drop. False for everything else: a synchronisation service is a
    /// compare-and-exchange store, and this client can replace an object's content but has no way
    /// to ask for the object to be deleted, so saying otherwise would be claiming an action it
    /// cannot perform.
    pub deletable: bool,
}

/// What asking the service to drop the copies a person chose about established.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resolutions {
    /// How many copies the service no longer holds: dropped by this call, or gone already.
    pub dropped: u64,
    /// How many the service could not be asked about. Each stays recorded as a choice already
    /// made, and the next call asks again.
    pub pending: u64,
}

/// What recording one of the person's choices did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The copy the person chose about, as this device kept it.
    pub copy: ConflictCopy,
    /// What asking the service to drop its copies established.
    pub service: Resolutions,
}

/// What turning privacy mode off did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resumed {
    /// The generation production starts again under.
    pub generation: u64,
}

/// One device's synchronised settings and position.
///
/// It holds the service client, this device's sealing and the store. It holds no authority, no host
/// connection and no draft store: publishing settings and applying what comes back need none of
/// them, and a client that held one could reach further than section 20 lets a restore reach.
///
/// Every method takes `&self`, so a host holds one behind an [`Arc`] and can fence it while a
/// publication is still out. **The store's lock is what makes that safe**, and it is why the
/// privacy state lives in the store rather than in this value: admitting work, taking it back and
/// settling it each decide against the generation and write under one hold, so a fence cannot land
/// between a decision and what follows from it.
#[derive(Debug)]
pub struct SyncClient {
    service: Arc<dyn SyncBackupService>,
    sealer: Arc<dyn DraftSealer>,
    store: SyncStore,
}

impl SyncClient {
    /// Builds the synchronised half over a service client, this device's sealing and its store.
    ///
    /// The sealing seam is the one the draft store defines, because a device holds one key for what
    /// it puts on a synchronisation service and both halves put objects there. A second seam would
    /// be a second answer to the same question.
    #[must_use]
    pub const fn new(
        service: Arc<dyn SyncBackupService>,
        sealer: Arc<dyn DraftSealer>,
        store: SyncStore,
    ) -> Self {
        Self {
            service,
            sealer,
            store,
        }
    }

    /// Returns the store this client keeps its state in.
    #[must_use]
    pub const fn store(&self) -> &SyncStore {
        &self.store
    }

    /// Returns the privacy generation this device records.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the record cannot be read.
    pub fn generation(&self) -> Result<u64> {
        Ok(self.store.privacy()?.generation.get())
    }

    /// Returns true when sync production is fenced.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the record cannot be read.
    pub fn is_fenced(&self) -> Result<bool> {
        Ok(self.store.privacy()?.fenced)
    }

    // -- publishing ---------------------------------------------------------------------------

    /// Returns the settings this device would publish right now.
    ///
    /// It is a filter a caller applies when it builds the object it is about to store, not
    /// something [`Self::publish`] does on the way out: what goes to the service is the record on
    /// disk, and rewriting it in flight would publish something this device does not hold. While
    /// privacy mode is on the whole publication is refused anyway; this is what a caller uses when
    /// it wants to keep synchronising the rest of a person's settings.
    ///
    /// The pinned labels are left out while privacy mode is on, which is section 24's rule: they
    /// are retained locally unless the person clears them, and excluded from subsequent sync while
    /// private. The device's own copy is untouched either way, so turning privacy mode off does not
    /// have to reconstruct them.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the privacy record cannot be read.
    pub fn settings_to_publish(&self, settings: &SyncSettings) -> Result<SyncSettings> {
        if self.is_fenced()? {
            Ok(SyncSettings {
                values: settings.values.clone(),
                pinned_labels: std::collections::BTreeSet::new(),
            })
        } else {
            Ok(settings.clone())
        }
    }

    /// Publishes the object this device holds, under compare and swap.
    ///
    /// What goes to the service is the record the store holds, not a value the caller supplied: the
    /// caller names which object it means, and the bytes are the ones on disk. A caller that had
    /// edited a copy in memory would otherwise put content on the service that this device does not
    /// hold.
    ///
    /// The fence check, the object, its note and the sealing are one step under the store's lock,
    /// so the generation this work is admitted under is the one that was in force when its
    /// ciphertext was made, and the comparison it sends is the one that went with the revision it
    /// read.
    ///
    /// An answer this device cannot make sense of leaves the work outstanding rather than throwing
    /// it away: only an accepted write and a refused comparison say what became of a request, and
    /// nothing else in this contract can. [`Self::exported`] lists such work as content sent
    /// without an answer.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] while privacy mode is on, [`SyncError::Unknown`] when this
    /// device holds no such object, [`SyncError::StaleCheckpoint`] or
    /// [`SyncError::ForkedHistory`] when what the service holds cannot follow the note beside this
    /// object, and the service's own refusal otherwise.
    pub async fn publish(&self, object_id: SyncObjectId, now: TimestampMs) -> Result<Published> {
        let staged = self.store.admit(object_id, |object| self.seal(object))?;
        let collection = sync_collection(staged.kind, object_id);

        // The store marks the work sent, hands back the record it wrote and hands back ownership
        // of the dispatch, which is an operating-system lock on the request. Nothing else may
        // decide what became of it while this call is out, in this process or in another, and a
        // fence landing since admission is refused here: work that has not gone is work the fence
        // still reaches.
        let (dispatch, ciphertext, signed_at) =
            self.store.begin_dispatch(staged.work_id, object_id, now)?;
        let answer = self
            .service
            .compare_exchange(
                &collection,
                // The work's own identity, which is what makes this request answerable
                // afterwards: the record on disk carries it, so a device that lost the answer asks
                // about the same request rather than about the object.
                staged.work_id,
                // The instant the record says this attempt is signed at, read back out of the
                // record rather than off a clock here. A fence is read against that recorded
                // instant afterwards, so what is signed and what is written down have to be the
                // one value.
                signed_at.get(),
                staged.expected.as_ref().copied(),
                ciphertext.as_slice(),
            )
            .await;

        match answer {
            Ok(SyncExchanged::Applied { position }) => {
                let settled =
                    self.store
                        .settle(&dispatch, &staged, Outcome::Accepted { position })?;
                // The settlement is durable before this is raised. An answer this device's records
                // cannot follow is one it may not carry on from, and the caller is told which it
                // is rather than left to meet it at some later comparison that may never come.
                if let Some(held) = settled.diverged {
                    return Err(diverged(object_id, held, position));
                }
                Ok(match settled.settlement {
                    Settlement::Published | Settlement::AlreadySettled => {
                        Published::Accepted { position }
                    }
                    Settlement::Discarded {
                        produced_under,
                        current,
                    } => Published::Discarded {
                        produced_under,
                        current,
                    },
                })
            }
            Ok(SyncExchanged::Refused { retained }) => {
                // The service answered the comparison and refused it, so this write did not replace
                // the object. That is settled first, along with the account of whatever the service
                // kept of it, so a fetch this device cannot make does not leave a refusal it
                // already knows about sitting outstanding.
                let settled =
                    self.store
                        .settle(&dispatch, &staged, Outcome::Refused { retained })?;
                if let Settlement::Discarded {
                    produced_under,
                    current,
                } = settled.settlement
                {
                    return Ok(Published::Discarded {
                        produced_under,
                        current,
                    });
                }
                self.keep_what_the_service_holds(&staged, &collection, retained, now)
                    .await
            }
            // The identity this request presented already answered a different one. The receipt
            // under it accounts for that request and never for this payload, so nothing may be
            // settled from it, and the service compared this content against that receipt and
            // declined to run it. This payload therefore did not execute and never will under this
            // identity, which ends the request: the work goes, no account is kept because nothing
            // of it is on the service, and nothing asks about the identity again.
            Err(error) if error.code() == ErrorCode::IdConflict => {
                self.store.close_unexecuted(&dispatch, staged.work_id)?;
                Err(error.into())
            }
            // Anything else leaves the outcome open. The staged record stays where it counts as
            // outstanding rather than being retired on a guess about whether the write landed.
            Err(error) => Err(error.into()),
        }
    }

    /// Brings down what the service holds after a refusal, and keeps it beside this device's own.
    ///
    /// The refusal is already settled when this runs: section 20 keeps the other content for the
    /// person to choose from, and a fetch this device cannot make costs that copy rather than the
    /// knowledge that the comparison did not replace the object.
    async fn keep_what_the_service_holds(
        &self,
        staged: &RequestRecord,
        collection: &str,
        retained: Option<SyncConflictId>,
        now: TimestampMs,
    ) -> Result<Published> {
        let (position, other) = self.fetch_current(staged, collection).await?;
        // A refusal keeps a copy whatever this device holds. The comparison did not replace the
        // object, so what came down is another device's content and the person chooses between the
        // two; that is not the fetch's question of whether the two are the same content at all.
        // The copy names what the service kept of the refused write, because the two are the two
        // sides of one choice and the choice takes both with it.
        let copy = ConflictCopy {
            retained: Nullable::from(retained),
            ..self.copy_of(
                staged.object_id,
                staged.revision,
                staged.expected,
                position,
                &other,
                now,
            )?
        };
        let kept = copy.conflict_id;
        let applied = self.store.apply_fetch(
            staged.produced_under.get(),
            staged.object_id,
            SyncCheckpoint {
                position,
                // Where the object stands is this device's to remember; the revision beside it in
                // the note is this device's own, and what came down is the other device's.
                published_revision: Nullable::null(),
            },
            |_| Ok(Some(copy)),
        )?;
        // A note that two histories both claim is a note this device may not move, and the caller
        // is told which rather than left to meet it at some later comparison that may never come.
        forked(staged.object_id, applied.note, position)?;
        match applied.settlement {
            Settlement::Published | Settlement::AlreadySettled => Ok(Published::Conflicted {
                copy: kept,
                other_revision: other.revision,
                position,
            }),
            Settlement::Discarded {
                produced_under,
                current,
            } => Ok(Published::Discarded {
                produced_under,
                current,
            }),
        }
    }

    /// Records the person's choice about one copy, and drops what the service kept of the writes it
    /// decides.
    ///
    /// The choice itself is the caller's, as it always was: it keeps its own content or puts the
    /// copy's in place through [`SyncStore::put_object`], and publishes what was chosen. What this
    /// does is take the copy out of this device's store and tell the service: the copy the service
    /// kept of the refused write this copy answers goes as well, and no other, because another
    /// refused write of the object is a version the person has not decided about. See
    /// [`SyncStore::resolve_conflict`].
    ///
    /// The choice is recorded before the service is asked, so a service that cannot be asked
    /// leaves it recorded: the copy is gone from this device, the service's copies are counted in
    /// [`Resolved::service`] as still to go, and [`Self::finish_resolutions`] asks again.
    ///
    /// It sends identifiers and no content, so privacy mode does not stop it: dropping a copy takes
    /// content off the service rather than putting any there.
    ///
    /// Returns nothing when this device holds no such copy.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the copy or a record cannot be read, written or removed.
    pub async fn resolve(&self, conflict_id: SyncConflictId) -> Result<Option<Resolved>> {
        let Some(copy) = self.store.resolve_conflict(conflict_id)? else {
            return Ok(None);
        };
        let service = self.finish_resolutions().await?;
        Ok(Some(Resolved { copy, service }))
    }

    /// Asks the service to drop one copy it kept of this device's refused write, because the person
    /// asked for exactly that.
    ///
    /// It is the way to a copy with nothing on this device to choose about: [`Self::exported`]
    /// names each copy the service keeps, as deletable and by the identity the service gave it, and
    /// this is the explicit deletion section 24 offers for it. It asks the service about every
    /// other copy still to go as well, as [`Self::finish_resolutions`] does.
    ///
    /// Returns nothing when this device holds no refusal the service kept that copy of.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a record cannot be read, written or removed.
    pub async fn drop_kept_copy(&self, retained: SyncConflictId) -> Result<Option<Resolutions>> {
        if !self.store.drop_kept_copy(retained)? {
            return Ok(None);
        }
        Ok(Some(self.finish_resolutions().await?))
    }

    /// Asks the service to drop every copy the person has chosen about that it has not yet dropped.
    ///
    /// Each one is asked about once per call, and one the service could not be asked about stays
    /// recorded for the next call rather than failing the rest. Asking twice is safe: a copy the
    /// service no longer holds is already resolved, and it says so.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the records cannot be read or removed.
    pub async fn finish_resolutions(&self) -> Result<Resolutions> {
        let mut report = Resolutions::default();
        for record in self.store.resolutions()? {
            let RequestState::Resolving { retained } = record.state else {
                continue;
            };
            let collection = sync_collection(record.kind, record.object_id);
            if self.service.resolve(&collection, retained).await.is_ok() {
                self.store.close_resolution(record.work_id)?;
                report.dropped = report.dropped.saturating_add(1);
            } else {
                report.pending = report.pending.saturating_add(1);
            }
        }
        Ok(report)
    }

    /// Seals one object, clearing the encoding it made on the way.
    fn seal(&self, object: &SyncObject) -> Result<Vec<u8>> {
        let plaintext = Zeroising(kr_cbor::to_canonical_vec(object)?);
        self.sealer
            .seal(&plaintext.0)
            .map_err(|error| Box::new(error).into())
    }

    /// Fetches what the service holds now, diagnosing a service that has gone back or forked.
    async fn fetch_current(
        &self,
        staged: &RequestRecord,
        collection: &str,
    ) -> Result<(SyncPosition, SyncObject)> {
        let (position, ciphertext) = self.service.fetch(collection).await?;
        diagnose(
            staged.object_id,
            staged.expected.as_ref().copied(),
            position,
        )?;
        let other = self.open_object(collection, staged.object_id, &ciphertext)?;
        Ok((position, other))
    }

    /// Fetches one object and keeps what the service holds beside this device's own.
    ///
    /// It never replaces. This device's stored object is untouched, and when it holds a different
    /// revision the content that came down is kept as a copy for the person to choose from, which
    /// is what stops a reconnect putting another device's content where a person's own was.
    /// Applying a choice is the caller's own step, through [`SyncStore::put_object`].
    ///
    /// It is refused while privacy mode is on, because a copy and a note are retained sync content
    /// and recreating either after the cleanup would undo it. An answer that arrives after a fence
    /// is refused for the same reason, and nothing it brought down is written.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] while privacy mode is on, [`SyncError::LateResult`] when a
    /// fence landed while the answer was on its way, the service's refusal,
    /// [`SyncError::NotThatObject`] when the object that came down is not the one this collection
    /// was asked for, [`SyncError::DraftElsewhere`] when a draft is asked for, and
    /// [`SyncError::Storage`] when the copy or the note cannot be written.
    pub async fn fetch(
        &self,
        kind: SyncObjectKind,
        object_id: SyncObjectId,
        now: TimestampMs,
    ) -> Result<Restored> {
        let collection = sync_collection(kind, object_id);
        // A draft belongs to the device's draft store and is published and fetched by its own
        // synchronised half. Asking this client for one is refused before the service is called,
        // because there is no code here that could apply one and adding some would be a second way
        // to write a draft.
        if kind == SyncObjectKind::Draft {
            return Err(SyncError::DraftElsewhere { collection });
        }
        let privacy = self.store.privacy()?;
        if privacy.fenced {
            return Err(SyncError::Fenced {
                generation: privacy.generation.get(),
            });
        }
        // The note this device holds **before** it asks, so a reply another observation overtook is
        // not mistaken for a service that went back. The note may move while this call is out; that
        // is two answers arriving out of order, and the store keeps the later of them.
        let note = self.store.checkpoint(object_id)?;
        let (position, ciphertext) = self.service.fetch(&collection).await?;
        diagnose(object_id, note.map(|note| note.position), position)?;
        let other = self.open_object(&collection, object_id, &ciphertext)?;

        // The copy and the note are written under one hold, against the generation this fetch was
        // started under. A cleanup that landed while the answer was on its way finds nothing to
        // undo, because nothing is written. What this device holds is read inside that hold too,
        // because whether there is a choice to keep is a question about the object as it is when
        // the answer is applied, not as it was when the call left.
        let applied = self.store.apply_fetch(
            privacy.generation.get(),
            object_id,
            SyncCheckpoint {
                position,
                published_revision: Nullable::null(),
            },
            // A device that holds nothing is seeing this object for the first time, and there is
            // nothing for it to conflict with. One that holds another revision has two versions of
            // the same object, which is a choice rather than a replacement.
            |held| match held {
                Some(held) if held.revision != other.revision => Ok(Some(self.copy_of(
                    object_id,
                    held.revision,
                    // A fetch compares nothing. It asked what was there and was told.
                    Nullable::null(),
                    position,
                    &other,
                    now,
                )?)),
                _ => Ok(None),
            },
        )?;
        match applied.settlement {
            Settlement::Published | Settlement::AlreadySettled => {}
            Settlement::Discarded {
                produced_under,
                current,
            } => {
                return Err(SyncError::LateResult {
                    produced_under,
                    current,
                });
            }
        }
        // The note is compared again inside the hold that writes it, against whatever it names by
        // then. A fetch that started against one note and finished against another can meet a fork
        // the diagnosis before the call could not see, and nothing else would report it: the next
        // comparison sees only where the object stands then, which may have moved past the place
        // the two histories disagree about.
        forked(object_id, applied.note, position)?;
        let copy = applied.copy;
        Ok(match other.body {
            SyncBody::Settings(_) => Restored::Settings {
                object: other,
                copy,
            },
            SyncBody::ClientSelection(_) => Restored::ClientSelection {
                object: other,
                copy,
            },
        })
    }

    /// Builds one copy of what the service held, to keep beside this device's own object.
    ///
    /// It names no copy on the service, which is right for a fetch; the one path where the service
    /// kept the other side of the choice says so itself.
    fn copy_of(
        &self,
        object_id: SyncObjectId,
        offered_revision: SyncRevisionId,
        expected: Nullable<SyncPosition>,
        current: SyncPosition,
        other: &SyncObject,
        now: TimestampMs,
    ) -> Result<ConflictCopy> {
        Ok(ConflictCopy {
            conflict_id: SyncConflictId::new(fresh_uuid().map_err(|error| SyncError::Corrupt {
                path: self.store.directory().to_path_buf(),
                reason: error.to_string(),
            })?),
            object_id,
            offered_revision,
            retained: Nullable::null(),
            expected,
            current,
            other: other.clone(),
            recorded_at_ms: now,
        })
    }

    /// Opens what a collection served and checks that it is the object that was asked for.
    ///
    /// Sealing says the bytes came from a device that holds the key. It does not say they belong
    /// where they were found, so the object identity and the kind are both checked against the
    /// collection that was asked for.
    fn open_object(
        &self,
        collection: &str,
        object_id: SyncObjectId,
        ciphertext: &[u8],
    ) -> Result<SyncObject> {
        // The opened buffer holds the settings in the clear and it is this client's own, so it is
        // cleared when it goes out of scope rather than by a statement an early return could skip.
        let plaintext = Zeroising(self.sealer.open(ciphertext).map_err(Box::new)?);
        // Anything that is not settings or a client's position stops here. There is no body variant
        // for a draft and none for authority, so a collection serving either decodes as nothing
        // this module reads rather than as something it applies.
        let object: SyncObject =
            kr_cbor::from_canonical_slice(&plaintext.0, &kr_cbor::Limits::DEFAULT)?;
        if object.object_id != object_id || collection != sync_collection(object.kind(), object_id)
        {
            return Err(SyncError::NotThatObject {
                collection: collection.to_owned(),
                found: object.object_id,
                expected: object_id,
            });
        }
        Ok(object)
    }

    // -- privacy mode -------------------------------------------------------------------------

    /// Stops sync production at `generation`, and says what it was holding.
    ///
    /// The generation is recorded durably here, before anything else happens, so a restart sees the
    /// boundary and a late result cannot cross it. Immediately and prospectively: a publication or
    /// a fetch admitted after this is refused, and one already out has its result discarded rather
    /// than applied.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the generation cannot be recorded, in which case
    /// production is **not** fenced: a boundary this device cannot record is not one it claims.
    pub fn fence(&self, generation: u64) -> Result<Fenced> {
        self.store.record_privacy(PrivacyRecord {
            generation: U64::new(generation),
            fenced: true,
        })?;
        let requests = self.store.requests()?;
        Ok(Fenced {
            queues: 1,
            items: requests.items.iter().filter(|item| item.admitted()).count() as u64,
        })
    }

    /// Asks the service what became of every dispatch this device has no answer for.
    ///
    /// A publication is about an object and its answer is a generation, so a device that lost one
    /// cannot learn anything from what the object holds afterwards: that is a fact about the
    /// object and not about any one write of it. What it can ask about is the request. Every
    /// dispatch carries the staged work's own identity, the service records the reply it gave that
    /// identity, and this asks for it back.
    ///
    /// Each answer settles the request it is about and nothing else:
    ///
    /// - **applied** settles it as an accepted write, which records the publication and, under the
    ///   generation in force, moves the checkpoint;
    /// - **refused** settles it as a write that did not replace the object, records whatever copy
    ///   the service kept of it, and brings down what the service holds instead, beside this
    ///   device's own content;
    /// - **no receipt** settles nothing on its own, because a request that has not been executed
    ///   and one that is still on its way look the same from here. Under the generation in force
    ///   the work stays where it is and the next pass asks again. Under a generation privacy mode
    ///   has moved past, no answer to it could ever be published, so this pass asks the service to
    ///   **fence** it, in the same pass: nothing executes under a fenced identity afterwards, so
    ///   the barrier for it releases, and a request that landed between the two calls comes back
    ///   applied or refused and settles;
    /// - **fenced** is the same end reached by somebody else asking first.
    ///
    /// A fence also says whether anything ever ran under the identity, and the **service** says it
    /// from its own records rather than this device working it out: the fence carries the earliest
    /// and the latest instant an attempt was signed at, and the service answers whether a receipt
    /// of any such attempt would still have been there for the fence to find. Where it never ran,
    /// the work goes and no account is kept; where the service could not establish it, the barrier
    /// still releases and the account of what left this device stays.
    ///
    /// Nothing is retried. Section 23 permits an automatic retry only for an idempotent read or a
    /// request whose receipt proves no dispatch, and a request the service knows nothing about
    /// proves neither.
    ///
    /// A service that cannot be asked, for the status or for the fence, leaves the work counted
    /// rather than failing the pass, which is what lets a privacy cleanup report what is still
    /// outstanding instead of refusing to report at all. Nothing reaches nought until every
    /// request has one of the three answers that end it: applied, refused or fenced.
    ///
    /// Each request is claimed from the store before anything is asked about it, and the claim is
    /// held until the answer has been written down. A request somebody has a call out for is left
    /// counted rather than decided about: a service writes its receipt when it commits the write,
    /// so a request still on the wire has none either, and only the device making that call can
    /// tell the two apart. The claim is the store's and not this value's, so a second window of
    /// the application over the same store meets it as well.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the staged records cannot be read or a settlement
    /// cannot be written.
    pub async fn reconcile_unsettled(&self, now: TimestampMs) -> Result<Reconciled> {
        let mut report = Reconciled::default();
        let dispatched: Vec<Uuid> = self
            .store
            .requests()?
            .items
            .iter()
            .filter(|item| item.dispatched())
            .map(|item| item.work_id)
            .collect();
        for work_id in dispatched {
            // The store decides who may decide. A request somebody has a call out for is not one
            // to conclude about: a service writes its receipt when it commits the write, so a
            // request still on the wire has none either, and only the device making the call can
            // tell the two apart. A request that is gone was settled while this pass ran.
            let (dispatch, staged) = match self.store.claim_dispatched(work_id)? {
                Claimed::Taken(dispatch, staged) => (dispatch, staged),
                Claimed::InHand => {
                    report.unresolved = report.unresolved.saturating_add(1);
                    continue;
                }
                Claimed::Gone => continue,
            };
            let collection = sync_collection(staged.kind, staged.object_id);
            let Ok(status) = self.service.request_status(&collection, work_id).await else {
                report.unresolved = report.unresolved.saturating_add(1);
                continue;
            };
            match status {
                SyncRequestStatus::Applied { position } => {
                    self.settle_acceptance(&dispatch, &staged, position, &mut report)?;
                }
                SyncRequestStatus::Refused { retained } => {
                    self.settle_refusal(
                        &dispatch,
                        &staged,
                        &collection,
                        retained,
                        now,
                        &mut report,
                    )
                    .await?;
                }
                // Somebody fenced this request already, and the fence's own receipt recorded what
                // the service established about the past. Asking again repeats it, so a request
                // fenced once is settled the same way however often it is asked about.
                SyncRequestStatus::Fenced { never_ran } => {
                    self.close_fenced(&dispatch, &staged, never_ran, &mut report)?;
                }
                SyncRequestStatus::Unknown => {
                    // Under the generation that admitted it the work is still wanted, so this pass
                    // leaves it counted and the next one asks again. Past that generation no answer
                    // to it could be published, and a barrier nothing can lift is not a barrier, so
                    // the service is asked to end the request instead of this device guessing that
                    // it never arrived.
                    if !self.store.beyond_its_generation(&staged)? {
                        report.unresolved = report.unresolved.saturating_add(1);
                        continue;
                    }
                    // The fence carries the signing times the record holds, because the service
                    // decides from them both whether anything can still have run and how long the
                    // fence itself must outlive what it fences. A dispatched record always names
                    // them, since the dispatch wrote the state and the instants together; one that
                    // somehow names neither is left counted rather than fenced with a time this
                    // device made up.
                    let Some((first_signed_at, last_signed_at)) = staged.signing_times() else {
                        report.unresolved = report.unresolved.saturating_add(1);
                        continue;
                    };
                    match self
                        .service
                        .fence_request(
                            &collection,
                            work_id,
                            first_signed_at.get(),
                            last_signed_at.get(),
                        )
                        .await
                    {
                        Ok(SyncRequestFence::Fenced { never_ran }) => {
                            self.close_fenced(&dispatch, &staged, never_ran, &mut report)?;
                        }
                        // The request landed between the two calls, so the fence found the receipt
                        // the status query had missed and this is that answer.
                        Ok(SyncRequestFence::Applied { position }) => {
                            self.settle_acceptance(&dispatch, &staged, position, &mut report)?;
                        }
                        Ok(SyncRequestFence::Refused { retained }) => {
                            self.settle_refusal(
                                &dispatch,
                                &staged,
                                &collection,
                                retained,
                                now,
                                &mut report,
                            )
                            .await?;
                        }
                        Err(_) => {
                            report.unresolved = report.unresolved.saturating_add(1);
                        }
                    }
                }
            }
        }
        report.unsettled = self.store.unsettled()?;
        Ok(report)
    }

    /// Settles one accepted write a reconciliation learned about, and counts what it found.
    ///
    /// A pass reports rather than refuses: it is ending a barrier rather than answering a caller
    /// who is waiting for one publication, so an answer this device's records cannot follow is
    /// counted and the account of the write is kept by its own record.
    fn settle_acceptance(
        &self,
        dispatch: &super::store::Dispatch,
        staged: &RequestRecord,
        position: SyncPosition,
        report: &mut Reconciled,
    ) -> Result<()> {
        let settled = self
            .store
            .settle(dispatch, staged, Outcome::Accepted { position })?;
        report.settled = report.settled.saturating_add(1);
        if settled.diverged.is_some() {
            report.diverged = report.diverged.saturating_add(1);
        }
        Ok(())
    }

    /// Settles one refusal and brings down what the service holds instead.
    ///
    /// The refusal is settled first and on its own, because the service answered the comparison: a
    /// fetch this device cannot make costs the copy section 20 keeps for the person to choose from,
    /// never the knowledge that the write did not replace the object.
    async fn settle_refusal(
        &self,
        dispatch: &super::store::Dispatch,
        staged: &RequestRecord,
        collection: &str,
        retained: Option<SyncConflictId>,
        now: TimestampMs,
        report: &mut Reconciled,
    ) -> Result<()> {
        let settled = self
            .store
            .settle(dispatch, staged, Outcome::Refused { retained })?
            .settlement;
        report.settled = report.settled.saturating_add(1);
        // The copy belongs to the generation that admitted the work. A settlement the late-result
        // rule discarded may keep none, because a copy is retained content and the cleanup that
        // opened this generation has already removed it.
        if settled == Settlement::Published
            && self
                .keep_what_the_service_holds(staged, collection, retained, now)
                .await
                .is_err()
        {
            report.copies_not_taken = report.copies_not_taken.saturating_add(1);
        }
        Ok(())
    }

    /// Ends one request the service has fenced, and counts what that left behind.
    ///
    /// The barrier releases either way: nothing executes under a fenced identity, so no answer to
    /// this request can arrive afterwards. What differs is what is left to say about it, and the
    /// service is what says it: `never_ran` is the fence's own statement about its own records, and
    /// this pass neither reads a clock nor compares one instant with another to reach it.
    fn close_fenced(
        &self,
        dispatch: &super::store::Dispatch,
        staged: &RequestRecord,
        never_ran: bool,
        report: &mut Reconciled,
    ) -> Result<()> {
        match self
            .store
            .close_fenced(dispatch, staged.work_id, never_ran)?
        {
            End::NeverRan => report.fenced = report.fenced.saturating_add(1),
            End::Unaccounted => {
                report.fenced = report.fenced.saturating_add(1);
                report.accounts_kept = report.accounts_kept.saturating_add(1);
            }
            End::Nothing => report.unresolved = report.unresolved.saturating_add(1),
        }
        Ok(())
    }

    /// Takes back the publications that were admitted and never dispatched.
    ///
    /// Work that has been dispatched cannot be taken back, so it is reconciled first and whatever
    /// is still unaccounted for is counted: that is what the late-result rule exists for, and
    /// cleanup is not complete while any of it is outstanding. The record this device wrote before
    /// the call left says which is which, and reading it and removing it is one step, so a
    /// publication dispatching itself alongside this cannot have its record taken away.
    ///
    /// The generation is moved forward before the reconciliation, so work admitted under an
    /// earlier one is seen by it as work no answer may be published for.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a staged file cannot be read or removed, and
    /// [`SyncError::LateResult`] when a later generation has overtaken this cleanup.
    pub async fn cancel_undispatched(
        &self,
        generation: u64,
        now: TimestampMs,
    ) -> Result<Cancelled> {
        self.own_generation(generation)?;
        // Before the service is asked, so a cleanup a later generation has overtaken is refused
        // without sending anything.
        let undispatched = self.store.take_back_undispatched(generation)?;
        let reconciled = self.reconcile_unsettled(now).await?;
        Ok(Cancelled {
            undispatched,
            in_flight: self.store.unsettled()?,
            reconciled,
        })
    }

    /// Removes the conflict copies and the checkpoints, and the staged work that never left.
    ///
    /// The figures are what was actually removed, counted from the files that were deleted. What
    /// stays is in [`Self::kept`], named rather than left out.
    ///
    /// Work that has been dispatched is reconciled rather than removed. Its record is what says it
    /// may be out there, and deleting it unreconciled would make [`Self::outstanding`] reach
    /// nought while the write was still unaccounted for. What the service accounts for is settled,
    /// what it holds no receipt for is discarded under the late-result rule with the account of
    /// what left kept, and the rest stays counted. A record a reconciliation settled is not in
    /// these figures: settling work is not removing retained content, and
    /// [`Self::reconcile_unsettled`] is what reports it.
    ///
    /// A cleanup that has been overtaken by a later generation is refused rather than carried out,
    /// so it cannot reach the copies, the notes or the work that the generation now in force
    /// admitted.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a file cannot be removed, and [`SyncError::LateResult`]
    /// when a later generation has overtaken this cleanup.
    pub async fn remove_retained(&self, generation: u64, now: TimestampMs) -> Result<Removed> {
        self.own_generation(generation)?;
        // The local removal first, so a cleanup a later generation has overtaken is refused
        // without sending anything. The reconciliation then settles what was dispatched, which is
        // what lets the ciphertext of a request nothing can account for go as well.
        let (bytes, records) = self.store.remove_content(generation)?;
        let reconciled = self.reconcile_unsettled(now).await?;
        Ok(Removed {
            bytes,
            records,
            reconciled,
        })
    }

    /// Moves the recorded generation forward for a cleanup step.
    ///
    /// Whether the step still owns that generation is decided inside the store, in the same hold
    /// that does the deleting: a check out here could be overtaken between the answer and the
    /// deletion it was meant to authorise.
    fn own_generation(&self, generation: u64) -> Result<()> {
        self.store.advance_privacy(generation)?;
        Ok(())
    }

    /// Returns how much dispatched work has no settled outcome.
    ///
    /// A publication counts from the moment its record says it was sent until the service answers
    /// about that request, so an abandoned call, a failed connection and a restart all leave it
    /// counted: none of them establishes that nothing left this device. A staged record this build
    /// cannot read counts too, because a record it could not open is not a record it can say was
    /// nothing.
    ///
    /// It counts what is recorded, and it asks nobody: [`Self::reconcile_unsettled`] is what turns
    /// a dispatch with no answer into a settled one, and the privacy steps run it before they
    /// measure. A dispatch whose answer was lost therefore stays counted until something asks the
    /// service about it, and one the service holds no receipt for stays counted until privacy mode
    /// moves past the generation that admitted it. [`Self::exported`] lists both as content sent
    /// without an answer, which is what section 24 asks of anything that may already have left.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the staged records cannot be read. A host that must
    /// answer with a number reports one rather than nought: a store it cannot read is not a store
    /// it can say has nothing outstanding.
    pub fn outstanding(&self) -> Result<u64> {
        self.store.unsettled()
    }

    /// Returns what this client keeps, explicitly, whatever privacy mode is doing.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the labels or the publication records cannot be read.
    pub fn kept(&self) -> Result<Vec<KeptExplicitly>> {
        let mut kept = vec![KeptExplicitly {
            what: "the settings this device holds",
            why: "they are this device's own configuration, not something sync retained; a device \
                  that lost them would have to be set up again",
        }];
        if !self.store.pinned_labels()?.is_empty() {
            kept.push(KeptExplicitly {
                what: "the labels you pinned",
                why: "a pinned label is kept until you clear it, and it is left out of what is \
                      synchronised while privacy mode is on",
            });
        }
        // Every account under one hold, because a reconciliation moves a record from one of these
        // lists to another and a report that read them separately could name neither.
        let left = self.store.what_left()?;
        if !left.publications.is_empty() {
            kept.push(KeptExplicitly {
                what: "the record of what this device published",
                why: "it carries no content, and it is the only account of what has already left; \
                      deleting it would hide what privacy mode cannot undo",
            });
        }
        if !left.publications.unreadable.is_empty() {
            kept.push(KeptExplicitly {
                what: "a record of a publication this build cannot read",
                why: "it is kept rather than deleted, and what left under it cannot be listed, so \
                      the account of what has left is incomplete",
            });
        }
        if !left.requests.unreadable.is_empty() {
            kept.push(KeptExplicitly {
                what: "a record of admitted work this build cannot read",
                why: "it is kept rather than deleted, and it counts as outstanding, because a \
                      record that cannot be opened is not one that can be called nothing",
            });
        }
        if left
            .requests
            .items
            .iter()
            .any(|record| kept_copy(record).is_some())
        {
            kept.push(KeptExplicitly {
                what: "the record of a refused write the service kept a copy of",
                why: "it carries no content, and the copy it names is on the service rather than \
                      here, so deleting the record would hide an upload rather than undo one",
            });
        }
        if left
            .requests
            .items
            .iter()
            .any(|record| matches!(record.state, RequestState::Unaccounted))
        {
            kept.push(KeptExplicitly {
                what: "the record of a request that was ended too late to say whether it ran",
                why: "it carries no content, and the content it names left this device; deleting \
                      it would hide an upload that may have happened rather than undo one",
            });
        }
        Ok(kept)
    }

    /// Returns what had already left this device, which privacy mode does not erase.
    ///
    /// A publication record this build cannot read is named as well, because an account of what
    /// left that quietly dropped an entry would be worse than one that says it is incomplete.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the publication records cannot be read.
    pub fn exported(&self) -> Result<Vec<Exported>> {
        let left = self.store.what_left()?;
        let (publications, requests) = (left.publications, left.requests);
        let mut exported: Vec<Exported> = publications
            .items
            .into_iter()
            .map(|record| Exported {
                kind: format!("synchronised {}", record.kind),
                reference: format!(
                    "{} at {}",
                    sync_collection(record.kind, record.object_id),
                    record.position
                ),
                left_at_ms: record.published_at_ms,
                deletable: false,
            })
            .collect();
        for record in requests.items {
            // A refused write the service kept a copy of. The comparison did not replace the
            // object, and the ciphertext is on the service all the same, which is exactly what this
            // list is for. It is the one entry here with a way out: the service drops a copy it
            // kept when asked, and `drop_kept_copy` is the asking.
            if let Some(conflict_id) = kept_copy(&record) {
                exported.push(Exported {
                    kind: format!(
                        "synchronised {}, kept as a copy by the service",
                        record.kind
                    ),
                    reference: format!(
                        "{}, which the service holds as copy {}",
                        sync_collection(record.kind, record.object_id),
                        conflict_id
                    ),
                    left_at_ms: record.left_at(),
                    deletable: true,
                });
                continue;
            }
            // A dispatch with no answer may have reached the service. Saying so is the honest
            // entry: the content was sent, and nothing has yet established what became of it.
            // Asking the service about the request is what establishes it, and until something
            // does, this is what is true of it.
            if record.dispatched() {
                exported.push(Exported {
                    kind: format!("synchronised {}, sent without an answer", record.kind),
                    reference: format!(
                        "{} at revision {}",
                        sync_collection(record.kind, record.object_id),
                        record.revision
                    ),
                    // When this device let the content go. It does not say the service stored it,
                    // and nothing here can find that out.
                    left_at_ms: record.left_at(),
                    deletable: false,
                });
            }
            // A request a fence ended too late for the answer to say whether it had run. Nothing
            // more can happen to it, and the ciphertext may be on the service, so this is the
            // honest entry: it left, and what became of it is not something anything can now
            // establish.
            if matches!(record.state, RequestState::Unaccounted) {
                exported.push(Exported {
                    kind: format!("synchronised {}, sent and never accounted for", record.kind),
                    reference: format!(
                        "{} at revision {}, which the service may hold",
                        sync_collection(record.kind, record.object_id),
                        record.revision
                    ),
                    left_at_ms: record.left_at(),
                    deletable: false,
                });
            }
            // An accepted write is the object's publication record by the time anything reads
            // this, unless the object's record names another write under the same place in the
            // order. Two histories cannot both be the newest publication of one object, so the
            // request's own record is what accounts for this one, and it says so here.
            if let RequestState::Diverged { position } = record.state {
                exported.push(Exported {
                    kind: format!(
                        "synchronised {}, under another history of the collection",
                        record.kind
                    ),
                    reference: format!(
                        "{} at {}",
                        sync_collection(record.kind, record.object_id),
                        position
                    ),
                    left_at_ms: record.left_at(),
                    deletable: false,
                });
            }
            // Nothing else has left: work that was admitted and never sent is still here.
        }
        for path in requests.unreadable {
            exported.push(Exported {
                kind: "work sent without an answer, which this device cannot describe".to_owned(),
                reference: format!(
                    "a record this build cannot read, kept at {}",
                    path.display()
                ),
                left_at_ms: TimestampMs::new(0),
                deletable: false,
            });
        }
        for path in publications.unreadable {
            exported.push(Exported {
                kind: "a publication this device cannot describe".to_owned(),
                reference: format!(
                    "a record this build cannot read, kept at {}",
                    path.display()
                ),
                left_at_ms: TimestampMs::new(0),
                deletable: false,
            });
        }
        Ok(exported)
    }

    /// Returns whether a result produced under `produced_under` may be applied.
    ///
    /// It is the whole rule, and [`SyncStore::settle`] applies it under the store's lock so that a
    /// fence cannot land between the answer and what follows from it. A result is applied only when
    /// the generation it was produced under is exactly the one in force: an older one belongs to
    /// work privacy mode cancelled, and a newer one belongs to no generation this host has opened.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the privacy record cannot be read.
    pub fn accepts_result(&self, produced_under: u64) -> Result<bool> {
        Ok(self.generation()? == produced_under)
    }

    /// Lets production start again, under a generation of its own.
    ///
    /// Turning privacy mode off is a boundary as much as turning it on: leaving the generation
    /// where it was would make every result admitted during the private interval acceptable the
    /// moment privacy mode ended. It reconstructs nothing that was omitted while privacy mode was
    /// on, and the pinned labels it excluded from publication are still on this device.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the generation cannot be recorded, in which case
    /// production stays fenced.
    pub fn resume(&self, generation: u64) -> Result<Resumed> {
        self.store.record_privacy(PrivacyRecord {
            generation: U64::new(generation),
            fenced: false,
        })?;
        Ok(Resumed { generation })
    }
}

/// Returns a fresh identity for one synchronised object.
///
/// # Errors
///
/// Returns the transport's error when the random generator is unavailable.
pub fn fresh_object_id() -> crate::Result<SyncObjectId> {
    Ok(SyncObjectId::new(fresh_uuid()?))
}

/// Returns a fresh revision, which is a value and never a counter.
///
/// # Errors
///
/// Returns the transport's error when the random generator is unavailable.
pub fn fresh_revision() -> crate::Result<SyncRevisionId> {
    Ok(SyncRevisionId::new(fresh_uuid()?))
}

fn fresh_uuid() -> crate::Result<Uuid> {
    Ok(kr_transport::random::fresh_uuid_v4()?)
}

/// Refuses an answer that claims a place in the order this device has already given to another.
///
/// One write sequence names one write for the life of a collection, so two answers under one place
/// in the order come from two histories, and this device's note is about a collection that no
/// longer exists. The recovery is the explicit one: forget the checkpoint and start the object
/// again against the service this device now talks to.
fn forked(object_id: SyncObjectId, note: Standing, found: SyncPosition) -> Result<()> {
    match note {
        Standing::Forked { held } => Err(SyncError::ForkedHistory {
            object_id,
            expected: held,
            found,
        }),
        Standing::Later | Standing::Same | Standing::Earlier => Ok(()),
    }
}

/// Says where an answer stands against a place this device's records hold, when it does not follow.
///
/// Two answers are provably wrong rather than merely surprising, and the error says which: a smaller
/// write sequence than this device's is a service that went back, and the same one is two histories
/// claiming one place.
fn diverged(object_id: SyncObjectId, held: SyncPosition, found: SyncPosition) -> SyncError {
    if found.write_sequence < held.write_sequence {
        SyncError::StaleCheckpoint {
            object_id,
            expected: held.write_sequence,
            found: found.write_sequence,
        }
    } else {
        SyncError::ForkedHistory {
            object_id,
            expected: held,
            found,
        }
    }
}

/// Returns the copy the service kept of one refused write, when it kept one.
///
/// Only a refusal names one, and only a refusal the service kept something of. What the service
/// keeps is ciphertext this device sent, so the record that names it is an account of what left
/// rather than a record of a write that did not land.
fn kept_copy(record: &RequestRecord) -> Option<SyncConflictId> {
    match &record.state {
        RequestState::Refused { retained } => retained.as_ref().copied(),
        // Chosen about, and still on the service until the service says it has dropped it.
        RequestState::Resolving { retained } => Some(*retained),
        RequestState::Admitted { .. }
        | RequestState::Dispatched { .. }
        | RequestState::Applied { .. }
        | RequestState::Diverged { .. }
        | RequestState::Unaccounted => None,
    }
}

/// Checks what the service answered against where this device last saw the object stand.
///
/// The position beside an object is where a write of that object landed, so an answer that carries
/// content at a removal's place, or at nought, is refused before anything else: a device that wrote
/// such a note would compare its next publication against no object while one was there.
///
/// A write sequence only ever goes forward, and one write sequence names one write for the life of
/// a collection. So two answers are provably wrong rather than merely surprising: a smaller
/// sequence is a service that has gone back behind what this device already saw, and the same
/// sequence under another revision is a history that forked. Both say the note is about a
/// collection that no longer exists, and neither is something a fetch may quietly write over.
///
/// A note that records a removal is read the same way. It keeps the place in the order the removal
/// took, so an answer behind it is still a service that went back, and a write claiming the
/// removal's own place is still two histories.
///
/// Anything else is ordinary: a larger sequence is another device's write, and no note at all is a
/// device seeing the object for the first time.
fn diagnose(
    object_id: SyncObjectId,
    held: Option<SyncPosition>,
    found: SyncPosition,
) -> Result<()> {
    // What came down is an object, so the position beside it is where a write of that object
    // landed. A removal produced no object and nought is a place nothing occupies; an answer
    // carrying content at either is an answer this device declines rather than reads.
    if found.is_removal() || found.write_sequence == 0 {
        return Err(SyncError::NotAWrite { object_id, found });
    }
    let Some(held) = held else {
        return Ok(());
    };
    if found.write_sequence < held.write_sequence {
        return Err(SyncError::StaleCheckpoint {
            object_id,
            expected: held.write_sequence,
            found: found.write_sequence,
        });
    }
    if found.write_sequence == held.write_sequence && found.revision != held.revision {
        return Err(SyncError::ForkedHistory {
            object_id,
            expected: held,
            found,
        });
    }
    Ok(())
}
