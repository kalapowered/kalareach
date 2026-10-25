//! Review work from the change-set store.
//!
//! The change-set store holds, durably, what the review state has to know: each change set's
//! version numbers only go up, and each version's record names the session it was recorded for and
//! the moment it was recorded. This pass makes the attention store's review state catch up with it,
//! for a version a capture recorded, for a version derived from a modified materialisation, and for
//! a version whose pin then failed. It is the review state's one producer of change-set work, so no
//! caller of a capture has an announcement to forget.
//!
//! # What it promises
//!
//! After a pass, every change set whose newest retained version names a session this host holds
//! has review work at that version, and a visit to the session sees it as a change. It cannot
//! recover a version that was deleted, an older version of a change set that was captured into
//! again after it, or the order the captures were made in. A version that names no session raises
//! nothing, because a review subject belongs to a session. A session this host does not hold, one
//! it has neither a worker nor a recorded closure for, gets nothing until it does.
//!
//! # How it stays right
//!
//! The pass keeps no cursor of its own to lose. What it has settled is the newest version it has
//! looked at for each change set, which it rebuilds from the change-set store when the daemon
//! starts; whether a version already is review work is read from the review state, which only moves
//! forward, so a version offered twice is recorded once. The review state is written in one
//! transaction per page, and a page the attention store refused is offered again by the next pass,
//! which is made after a short wait.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kr_attention::{EventCursor, EventKind, Origin, SourceEvent};
use kr_changeset::ChangeSetService;
use kr_changeset::service::VersionHead;
use kr_protocol::attention::{AttentionSource, ReviewSubject};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ChangeSetId, ChangeSetVersion, SessionId};
use kr_protocol::scalars::TimestampMs;

use super::{Answer, AttentionModule, HeldSessions, refusal};

/// How long the store waits before it reads the change-set store again after a pass that failed.
const CHANGE_SETS_EVERY: Duration = Duration::from_secs(2);

/// How long the store waits between looks at the versions whose sessions this host did not hold,
/// when nothing else wakes it: a session is made known a moment after its identifier is, and a
/// version recorded in that moment is offered again here.
const CHANGE_SETS_RECHECK: Duration = Duration::from_secs(60);

/// The versions one write of the review state takes.
const CHANGE_SETS_PAGE: usize = 256;

/// A version recorded for a session this host did not hold when it was read.
#[derive(Clone, Copy, Debug)]
struct Waiting {
    version: ChangeSetVersion,
    session_id: SessionId,
    captured_at_ms: TimestampMs,
}

/// What the pass has settled.
#[derive(Debug, Default)]
pub(super) struct ChangeSetPass {
    /// The newest version of each change set the pass has looked at and settled: raised, found to
    /// be review work already, or found to name no session. A newer version is read again.
    seen: BTreeMap<ChangeSetId, ChangeSetVersion>,
    /// The versions that name a session this host did not hold, tried again at every pass.
    waiting: BTreeMap<ChangeSetId, Waiting>,
}

/// One version offered to the review state.
#[derive(Clone, Copy, Debug)]
struct Offer {
    change_set_id: ChangeSetId,
    version: ChangeSetVersion,
    session_id: SessionId,
    captured_at_ms: TimestampMs,
}

impl Offer {
    fn subject(&self) -> ReviewSubject {
        ReviewSubject::ChangeSet {
            session_id: self.session_id,
            change_set_id: self.change_set_id,
        }
    }

    /// The host's own words for the change the version makes in its session's visit log: its
    /// identifiers and nothing a caller wrote.
    fn summary(&self) -> String {
        format!(
            "version {} of change set {} was recorded",
            self.version.get(),
            self.change_set_id
        )
    }
}

fn storage(what: &str, detail: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(
        ErrorCode::StorageUnavailable,
        format!("the change-set store: {what}: {detail}"),
    )
}

impl AttentionModule {
    fn pass_state(&self) -> std::sync::MutexGuard<'_, ChangeSetPass> {
        self.change_sets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reads the change-set store's versions for as long as the module is held: one pass now, and
    /// another each time the service records a version, and after a wait when a pass failed or
    /// when a version waits for its session to be held.
    ///
    /// The first pass has run when this returns, so a daemon that waits for it at its start has
    /// put right whatever an earlier daemon left between the two stores before it serves anything.
    /// A second call starts nothing further.
    pub async fn consume_change_sets(
        self: &Arc<Self>,
        service: Arc<ChangeSetService>,
        sessions: Arc<dyn HeldSessions>,
    ) {
        if self.change_sets_started.set(()).is_err() {
            return;
        }
        // Set before the first pass reads the store, so a version recorded while it reads wakes the
        // pass after it.
        let wake = Arc::clone(&self.change_sets_wake);
        service.on_version_recorded({
            let wake = Arc::clone(&wake);
            move || wake.notify_one()
        });
        let taken = self.take_change_sets(&service, sessions.as_ref()).await;
        let mut clean = taken.is_ok();
        self.report_change_sets(taken);
        let module = Arc::downgrade(self);
        // The service is held weakly: the daemon that owns it going ends the task with it.
        let service = Arc::downgrade(&service);
        let task = tokio::spawn(async move {
            loop {
                let waiting = match module.upgrade() {
                    Some(held) => held.change_sets_waiting.load(Ordering::Relaxed),
                    None => return,
                };
                let pause = if !clean {
                    Some(CHANGE_SETS_EVERY)
                } else if waiting {
                    Some(CHANGE_SETS_RECHECK)
                } else {
                    None
                };
                match pause {
                    Some(pause) => {
                        tokio::select! {
                            () = wake.notified() => {}
                            () = tokio::time::sleep(pause) => {}
                        }
                    }
                    None => wake.notified().await,
                }
                // Held for one pass and let go of across the wait, so a module its owner has let
                // go of goes, with its store's claim.
                let (Some(held), Some(service)) = (module.upgrade(), service.upgrade()) else {
                    return;
                };
                let taken = held.take_change_sets(&service, sessions.as_ref()).await;
                clean = taken.is_ok();
                held.report_change_sets(taken);
            }
        });
        *self
            .change_sets_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    }

    /// Makes one pass over the change-set store's newest versions.
    ///
    /// # Errors
    ///
    /// Returns why the pass stopped short: the change-set store could not be read, or the attention
    /// store refused the write. Nothing the pass did not commit is counted as settled, so the next
    /// pass offers it again.
    pub async fn take_change_sets(
        self: &Arc<Self>,
        service: &Arc<ChangeSetService>,
        sessions: &dyn HeldSessions,
    ) -> Answer<()> {
        // One pass at a time, from the read of the newest versions to the write of what they owe:
        // a pass that read older versions cannot settle them after a newer pass settled newer ones.
        let _one = self.change_sets_pass.lock().await;
        let module = Arc::clone(self);
        let reader = Arc::clone(service);
        let fresh = blocking(move || {
            let seen = module.pass_state().seen.clone();
            reader
                .newest_versions_after(&seen)
                .map_err(|error| storage("it could not be read", error))
        })
        .await?;
        // The sessions asked about are the new versions' and the ones still waiting to be held.
        let mut asked: BTreeSet<SessionId> =
            fresh.iter().filter_map(|head| head.session_id).collect();
        asked.extend(
            self.pass_state()
                .waiting
                .values()
                .map(|waiting| waiting.session_id),
        );
        let mut held = BTreeSet::new();
        for session_id in asked {
            if sessions.holds(session_id).await {
                held.insert(session_id);
            }
        }
        let module = Arc::clone(self);
        let taken = blocking(move || module.record_change_sets(&fresh, &held)).await;
        #[cfg(any(test, feature = "testing"))]
        self.change_sets_passes.send_modify(|passes| *passes += 1);
        taken
    }

    /// Writes the review work the versions in `fresh` and the versions still waiting for a held
    /// session owe, in one transaction for each page, and then marks them settled.
    fn record_change_sets(&self, fresh: &[VersionHead], held: &BTreeSet<SessionId>) -> Answer<()> {
        // Held across the write and the marking, so a pass that overlaps this one settles nothing
        // this one has not.
        let mut state = self.pass_state();
        let mut offers: Vec<Offer> = state
            .waiting
            .iter()
            .filter(|(change_set_id, _)| {
                !fresh
                    .iter()
                    .any(|head| head.change_set_id == **change_set_id)
            })
            .map(|(change_set_id, waiting)| Offer {
                change_set_id: *change_set_id,
                version: waiting.version,
                session_id: waiting.session_id,
                captured_at_ms: waiting.captured_at_ms,
            })
            .collect();
        offers.extend(fresh.iter().filter_map(|head| {
            head.session_id.map(|session_id| Offer {
                change_set_id: head.change_set_id,
                version: head.version,
                session_id,
                captured_at_ms: head.captured_at_ms,
            })
        }));
        let (offered, unheld): (Vec<Offer>, Vec<Offer>) = offers
            .into_iter()
            .partition(|offer| held.contains(&offer.session_id));
        // The order the versions were recorded in, so a visit sees them in it.
        let mut offered = offered;
        offered.sort_by_key(|offer| (offer.captured_at_ms, offer.change_set_id));
        if !offered.is_empty() {
            self.record_offers(&offered)?;
        }
        for head in fresh {
            state.seen.insert(head.change_set_id, head.version);
            state.waiting.remove(&head.change_set_id);
        }
        for offer in &offered {
            state.waiting.remove(&offer.change_set_id);
        }
        for offer in unheld {
            state.waiting.insert(
                offer.change_set_id,
                Waiting {
                    version: offer.version,
                    session_id: offer.session_id,
                    captured_at_ms: offer.captured_at_ms,
                },
            );
        }
        self.change_sets_waiting
            .store(!state.waiting.is_empty(), Ordering::Relaxed);
        Ok(())
    }

    /// Writes what `offered` owes the review state, in one transaction for each page.
    fn record_offers(&self, offered: &[Offer]) -> Answer<()> {
        self.deciding(|reading| -> Answer<()> {
            let mut store = self.store()?;
            let mut owed = Vec::with_capacity(offered.len());
            {
                let reviews = store.reviews().map_err(refusal)?;
                for offer in offered {
                    // The review state only goes forward: a version it has reached is review work
                    // already, and offering it again changes nothing.
                    if reviews
                        .version_of(&offer.subject())
                        .is_none_or(|reached| reached < offer.version.get())
                    {
                        owed.push(*offer);
                    }
                }
            }
            for page in owed.chunks(CHANGE_SETS_PAGE) {
                // The environment's own semantic source, numbered here: the next number is read
                // and used under one hold of the store, so nothing else numbers it between.
                let consumed = store
                    .engine()
                    .map_err(refusal)?
                    .consumed(Origin::Environment, AttentionSource::Semantic)
                    .unwrap_or_default();
                let events: Vec<SourceEvent> = page
                    .iter()
                    .zip(consumed.saturating_add(1)..)
                    .map(|(offer, sequence)| {
                        SourceEvent::new(
                            EventCursor::new(AttentionSource::Semantic, sequence),
                            // When the version was recorded, so a version read late does not look
                            // newer than it is and a grant's history decides on the right moment.
                            offer.captured_at_ms,
                            EventKind::ChangeSetCaptured {
                                session_id: offer.session_id,
                                change_set_id: offer.change_set_id,
                                version: offer.version.get(),
                                summary: offer.summary(),
                            },
                        )
                    })
                    .collect();
                // The change-set store is a retained source read again, and a version announces
                // nothing by itself, so the pass is a rebuild.
                store.rebuild(&events, reading).map_err(refusal)?;
            }
            Ok(())
        })
    }

    /// Reports a pass that stopped short, once for as long as passes keep stopping.
    fn report_change_sets(&self, taken: Answer<()>) {
        match taken {
            Ok(()) => self.change_sets_failing.store(false, Ordering::Relaxed),
            Err(error) => {
                if !self.change_sets_failing.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "kr-controller: the attention store could not take the change-set \
                         store's versions: {error}"
                    );
                }
            }
        }
    }

    /// A signal that moves each time a pass over the change-set store has finished, for this
    /// crate's own tests and the ones that start the daemon.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn change_set_passes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.change_sets_passes.subscribe()
    }
}

/// Runs `work` on the blocking pool and waits for it without holding a thread of the runtime.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Answer<T> + Send + 'static,
) -> Answer<T> {
    match tokio::task::spawn_blocking(work).await {
        Ok(done) => done,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(_) => Err(ProtocolError::new(
            ErrorCode::StorageUnavailable,
            "the pass over the change-set store was stopped",
        )),
    }
}
