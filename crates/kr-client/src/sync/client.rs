//! The compare-and-swap client, and the privacy operations a host drives it through.
//!
//! # How a write is decided
//!
//! Section 20: *sync uses per-object revision IDs and compare-and-swap writes*. A publication sends
//! the object this device holds against the generation this device last saw, which is the
//! [`SyncCheckpoint`] beside the object and never the object's own revision. The service answers
//! with the generation it assigned, or it refuses because another device wrote first.
//!
//! A refusal is not a failure. It is the answer that somebody else's content is there, and section
//! 20 keeps that content for the person to choose from instead of taking whichever clock was
//! further ahead. So the refusal brings the other content down **beside** this device's own, as a
//! [`ConflictCopy`], and this device's settings are exactly as they were. Nothing here chooses.
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
//! Their semantics are the host's contract exactly:
//!
//! | This client | The host's subsystem contract |
//! | --- | --- |
//! | [`SyncClient::fence`] | stop every content-bearing queue, at once |
//! | [`SyncClient::cancel_undispatched`] | take back what was admitted and never dispatched |
//! | [`SyncClient::remove_retained`] | remove the retained local content |
//! | [`SyncClient::outstanding`] | how much in-flight work is still being reconciled |
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
use kr_protocol::scalars::{TimestampMs, U64, Uuid};
use kr_protocol::sync::SyncObjectKind;

use super::store::{
    ConflictCopy, Publication, Result, Staged, SyncCheckpoint, SyncError, SyncStore,
};
use super::{SyncBody, SyncObject, SyncSettings, sync_collection};
use crate::drafts::DraftSealer;
use crate::services::SyncBackupService;

/// What became of a publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Published {
    /// The service accepted it, at this generation.
    Accepted {
        /// The generation the service assigned this write.
        generation: u64,
    },
    /// Another device had written first.
    ///
    /// This device's own object is exactly as it was. What the service held is kept beside it under
    /// `copy`, for the person to choose from, and the note now names the generation that content is
    /// at, so a caller that has chosen can publish against it.
    Conflicted {
        /// The copy that was kept.
        copy: SyncConflictId,
        /// The revision the other device's object carried.
        other_revision: SyncRevisionId,
        /// The generation the service holds.
        generation: u64,
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
    /// Always false here. A synchronisation service is a compare-and-exchange store: this client
    /// can replace an object's content and it has no way to ask for the object to be deleted, so
    /// saying otherwise would be claiming an action it cannot perform.
    pub deletable: bool,
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
#[derive(Debug)]
pub struct SyncClient {
    service: Arc<dyn SyncBackupService>,
    sealer: Arc<dyn DraftSealer>,
    store: SyncStore,
    /// The host's privacy generation this client is working under.
    generation: u64,
    /// The generation production was fenced at, while it is fenced.
    fenced_at: Option<u64>,
    /// How many publications have been dispatched and not yet settled.
    in_flight: u64,
}

impl SyncClient {
    /// Builds the synchronised half over a service client, this device's sealing and its store.
    ///
    /// The sealing seam is the one the draft store defines, because a device holds one key for what
    /// it puts on a synchronisation service and both halves put objects there. A second seam would
    /// be a second answer to the same question.
    #[must_use]
    pub fn new(
        service: Arc<dyn SyncBackupService>,
        sealer: Arc<dyn DraftSealer>,
        store: SyncStore,
    ) -> Self {
        Self {
            service,
            sealer,
            store,
            generation: 0,
            fenced_at: None,
            in_flight: 0,
        }
    }

    /// Builds one working under a privacy generation a restart read back.
    #[must_use]
    pub fn restored(
        service: Arc<dyn SyncBackupService>,
        sealer: Arc<dyn DraftSealer>,
        store: SyncStore,
        generation: u64,
        private: bool,
    ) -> Self {
        Self {
            service,
            sealer,
            store,
            generation,
            fenced_at: private.then_some(generation),
            in_flight: 0,
        }
    }

    /// Returns the store this client keeps its state in.
    #[must_use]
    pub const fn store(&self) -> &SyncStore {
        &self.store
    }

    /// Returns the privacy generation this client is working under.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns true when sync production is fenced.
    #[must_use]
    pub const fn is_fenced(&self) -> bool {
        self.fenced_at.is_some()
    }

    // -- publishing ---------------------------------------------------------------------------

    /// Returns the settings this device would publish right now.
    ///
    /// While privacy mode is on the pinned labels are left out, which is section 24's rule: they
    /// are retained locally unless the person clears them, and excluded from subsequent sync while
    /// private. The device's own copy is untouched either way, so turning privacy mode off does not
    /// have to reconstruct them.
    #[must_use]
    pub fn settings_to_publish(&self, settings: &SyncSettings) -> SyncSettings {
        if self.is_fenced() {
            SyncSettings {
                values: settings.values.clone(),
                pinned_labels: std::collections::BTreeSet::new(),
            }
        } else {
            settings.clone()
        }
    }

    /// Publishes the object this device holds, under compare and swap.
    ///
    /// What goes to the service is the record the store holds, not a value the caller supplied: the
    /// caller names which object and which revision it means, and the bytes are the ones on disk. A
    /// caller that had edited a copy in memory would otherwise put content on the service that this
    /// device does not hold.
    ///
    /// The object and its note are read together, so the generation this sends against is the one
    /// that went with the revision it validated.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Fenced`] while privacy mode is on, [`SyncError::Unknown`] when this
    /// device holds no such object, [`SyncError::StaleCheckpoint`] when the service does not hold
    /// the generation the note names, and the service's own refusal otherwise.
    pub async fn publish(
        &mut self,
        object_id: SyncObjectId,
        now: TimestampMs,
    ) -> Result<Published> {
        if let Some(generation) = self.fenced_at {
            return Err(SyncError::Fenced { generation });
        }
        let staged = self.admit(object_id)?;
        let work_id = staged.work_id;
        let collection = sync_collection(staged.kind, object_id);

        // Dispatched: it has left, so it can no longer be taken back, only reconciled.
        self.in_flight = self.in_flight.saturating_add(1);
        let answer = self
            .service
            .compare_exchange(
                &collection,
                staged.expected_generation.get(),
                &staged.ciphertext,
            )
            .await;
        let settled = self.settle(&staged, answer, now).await;
        self.in_flight = self.in_flight.saturating_sub(1);
        // The staged ciphertext has been sent, so it is no longer work waiting to go out. It is
        // discarded whatever the answer was, because a caller that wants to send again stages
        // again from what the store holds.
        self.store.discard(work_id)?;
        settled
    }

    /// Stages one object for publication and records it as admitted.
    ///
    /// Sealing happens here, so the ciphertext that is compared against a generation is the
    /// ciphertext that was admitted under this privacy generation.
    fn admit(&self, object_id: SyncObjectId) -> Result<Staged> {
        let object = self
            .store
            .object(object_id)?
            .ok_or(SyncError::Unknown { object_id })?;
        let note = self.store.checkpoint(object_id)?;
        let plaintext = kr_cbor::to_canonical_vec(&object)?;
        let ciphertext = self.sealer.seal(&plaintext).map_err(Box::new)?;
        let staged = Staged {
            work_id: kr_transport::random::fresh_uuid_v4().map_err(|error| SyncError::Corrupt {
                path: self.store.directory().to_path_buf(),
                reason: error.to_string(),
            })?,
            object_id,
            kind: object.kind(),
            revision: object.revision,
            // Nothing there yet is generation nought, which is the comparison a first publication
            // makes.
            expected_generation: note.map_or(U64::new(0), |note| note.generation),
            produced_under: U64::new(self.generation),
            ciphertext,
        };
        self.store.stage(&staged)?;
        Ok(staged)
    }

    /// Records what the service answered, under the late-result rule.
    async fn settle(
        &self,
        staged: &Staged,
        answer: crate::Result<u64>,
        now: TimestampMs,
    ) -> Result<Published> {
        if !self.accepts_result(staged.produced_under.get()) {
            return Ok(Published::Discarded {
                produced_under: staged.produced_under.get(),
                current: self.generation,
            });
        }
        match answer {
            Ok(accepted) => {
                self.store.record_checkpoint(
                    staged.object_id,
                    SyncCheckpoint {
                        generation: U64::new(accepted),
                        published_revision: kr_protocol::scalars::Nullable::some(staged.revision),
                    },
                )?;
                self.store.record_publication(&Publication {
                    object_id: staged.object_id,
                    kind: staged.kind,
                    generation: U64::new(accepted),
                    published_at_ms: now,
                })?;
                Ok(Published::Accepted {
                    generation: accepted,
                })
            }
            Err(error) if error.code() == ErrorCode::DraftConflict => {
                let fetched = self.fetch_beside(staged, now).await?;
                Ok(fetched)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Brings down what the service holds, beside this device's own object.
    async fn fetch_beside(&self, staged: &Staged, now: TimestampMs) -> Result<Published> {
        let collection = sync_collection(staged.kind, staged.object_id);
        let (generation, ciphertext) = self.service.fetch(&collection).await?;
        let other = self.open_object(&collection, staged.object_id, &ciphertext)?;

        let copy = ConflictCopy {
            conflict_id: SyncConflictId::new(fresh_uuid().map_err(|error| SyncError::Corrupt {
                path: self.store.directory().to_path_buf(),
                reason: error.to_string(),
            })?),
            object_id: staged.object_id,
            offered_revision: staged.revision,
            expected_generation: staged.expected_generation,
            current_generation: U64::new(generation),
            other: other.clone(),
            recorded_at_ms: now,
        };
        self.store.keep_conflict(&copy)?;
        // The generation is this device's to remember; the revision beside it is not, because the
        // revision that fetch carried is the other device's and nothing about this device's own
        // follows from it.
        self.store.record_checkpoint(
            staged.object_id,
            SyncCheckpoint {
                generation: U64::new(generation),
                published_revision: kr_protocol::scalars::Nullable::null(),
            },
        )?;
        Ok(Published::Conflicted {
            copy: copy.conflict_id,
            other_revision: other.revision,
            generation,
        })
    }

    /// Fetches one object and keeps what the service holds beside this device's own.
    ///
    /// It never replaces. This device's stored object is untouched, and when it holds a different
    /// revision the content that came down is kept as a copy for the person to choose from, which
    /// is what stops a reconnect putting another device's content where a person's own was.
    /// Applying a choice is the caller's own step, through [`SyncStore::put_object`].
    ///
    /// # Errors
    ///
    /// Returns the service's refusal, [`SyncError::NotThatObject`] when the object that came down
    /// is not the one this collection was asked for, [`SyncError::DraftElsewhere`] when it is a
    /// draft, and [`SyncError::Storage`] when the copy or the note cannot be written.
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
        let (generation, ciphertext) = self.service.fetch(&collection).await?;
        let other = self.open_object(&collection, object_id, &ciphertext)?;

        // A device that holds nothing is seeing this object for the first time, and there is
        // nothing for it to conflict with. One that holds another revision has two versions of the
        // same object, which is a choice rather than a replacement.
        let held = self.store.object(object_id)?;
        let copy = match held {
            Some(held) if held.revision != other.revision => Some(self.keep_beside(
                object_id,
                held.revision,
                U64::new(generation),
                &other,
                now,
            )?),
            _ => None,
        };

        self.store.record_checkpoint(
            object_id,
            SyncCheckpoint {
                generation: U64::new(generation),
                published_revision: kr_protocol::scalars::Nullable::null(),
            },
        )?;
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

    /// Keeps one copy of what the service held beside this device's own object.
    fn keep_beside(
        &self,
        object_id: SyncObjectId,
        offered_revision: SyncRevisionId,
        expected_generation: U64,
        other: &SyncObject,
        now: TimestampMs,
    ) -> Result<SyncConflictId> {
        let copy = ConflictCopy {
            conflict_id: SyncConflictId::new(fresh_uuid().map_err(|error| SyncError::Corrupt {
                path: self.store.directory().to_path_buf(),
                reason: error.to_string(),
            })?),
            object_id,
            offered_revision,
            expected_generation,
            current_generation: U64::new(0),
            other: other.clone(),
            recorded_at_ms: now,
        };
        let conflict_id = copy.conflict_id;
        self.store.keep_conflict(&copy)?;
        Ok(conflict_id)
    }

    /// Opens what a collection served and checks that it is the object that was asked for.
    ///
    /// Sealing says the bytes came from a device that holds the key. It does not say they belong
    /// where they were found, so the collection, the object identity and the kind are all checked
    /// against what came out.
    fn open_object(
        &self,
        collection: &str,
        object_id: SyncObjectId,
        ciphertext: &[u8],
    ) -> Result<SyncObject> {
        let plaintext = self.sealer.open(ciphertext).map_err(Box::new)?;
        // Anything that is not settings or a client's position stops here. There is no body variant
        // for a draft and none for authority, so a collection serving either decodes as nothing
        // this module reads rather than as something it applies.
        let object: SyncObject =
            kr_cbor::from_canonical_slice(&plaintext, &kr_cbor::Limits::DEFAULT)?;
        if object.object_id != object_id {
            return Err(SyncError::NotThatObject {
                collection: collection.to_owned(),
                found: object.object_id,
                expected: object_id,
            });
        }
        if collection != sync_collection(object.kind(), object_id) {
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
    /// Immediately and prospectively: a publication after this is refused, and the queue that
    /// already holds content stops reaching the service. Fencing first is what stops a queue
    /// emptying itself while a cancellation walks it.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the staged work cannot be counted. The fence is in place
    /// either way: it is set before anything is read.
    pub fn fence(&mut self, generation: u64) -> Result<Fenced> {
        self.generation = generation;
        self.fenced_at = Some(generation);
        Ok(Fenced {
            queues: 1,
            items: self.store.staged()?.len() as u64,
        })
    }

    /// Takes back the publications that were admitted and never dispatched.
    ///
    /// What has already been dispatched cannot be taken back, so it is counted instead: it is what
    /// the late-result rule exists for, and reconciliation is not complete while any of it is
    /// outstanding.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a staged file cannot be removed. What was removed before
    /// the failure stays removed.
    pub fn cancel_undispatched(&mut self, generation: u64) -> Result<Cancelled> {
        self.generation = generation;
        let staged = self.store.staged()?;
        let mut undispatched = 0_u64;
        for item in staged {
            self.store.discard(item.work_id)?;
            undispatched = undispatched.saturating_add(1);
        }
        Ok(Cancelled {
            undispatched,
            in_flight: self.in_flight,
        })
    }

    /// Removes the staged ciphertext, the conflict copies and the checkpoints.
    ///
    /// The figures are what was actually removed, counted from the files that were deleted. What
    /// stays is in [`Self::kept`], named rather than left out.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when a file cannot be removed.
    pub fn remove_retained(&mut self, generation: u64) -> Result<Removed> {
        self.generation = generation;
        let (bytes, records) = self.store.remove_content()?;
        Ok(Removed { bytes, records })
    }

    /// Returns how much in-flight work is still being reconciled.
    ///
    /// Reconciliation is this answer reaching nought. A publication counts from the moment it is
    /// dispatched until its answer has been settled or discarded, so a cleanup cannot report
    /// complete while one is still out.
    #[must_use]
    pub const fn outstanding(&self) -> u64 {
        self.in_flight
    }

    /// Returns what this client keeps, explicitly, whatever privacy mode is doing.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the labels cannot be read.
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
        if !self.store.publications()?.is_empty() {
            kept.push(KeptExplicitly {
                what: "the record of what this device published",
                why: "it carries no content, and it is the only account of what has already left; \
                      deleting it would hide what privacy mode cannot undo",
            });
        }
        Ok(kept)
    }

    /// Returns what had already left this device, which privacy mode does not erase.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Storage`] when the publication records cannot be read.
    pub fn exported(&self) -> Result<Vec<Exported>> {
        Ok(self
            .store
            .publications()?
            .into_iter()
            .map(|record| Exported {
                kind: format!("synchronised {}", record.kind),
                reference: format!(
                    "{} at generation {}",
                    sync_collection(record.kind, record.object_id),
                    record.generation.get()
                ),
                left_at_ms: record.published_at_ms,
                deletable: false,
            })
            .collect())
    }

    /// Returns whether a result produced under `produced_under` may be published.
    ///
    /// It is the whole rule. A result is published only when the generation it was produced under
    /// is exactly the one in force: an older one belongs to work privacy mode cancelled, and a
    /// newer one belongs to no generation this host has opened.
    #[must_use]
    pub const fn accepts_result(&self, produced_under: u64) -> bool {
        produced_under == self.generation
    }

    /// Lets production start again, under a generation of its own.
    ///
    /// Turning privacy mode off is a boundary as much as turning it on: leaving the generation
    /// where it was would make every result admitted during the private interval acceptable the
    /// moment privacy mode ended. It reconstructs nothing that was omitted while privacy mode was
    /// on, and the pinned labels it excluded from publication are still on this device.
    pub const fn resume(&mut self, generation: u64) -> Resumed {
        self.generation = generation;
        self.fenced_at = None;
        Resumed { generation }
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
