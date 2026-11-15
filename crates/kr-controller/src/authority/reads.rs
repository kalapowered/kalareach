//! What the entry of a revocation's answer read of a worker, and the record kept beside the answer.
//!
//! An entry for a worker reads the report of its own revision and the reports of the revisions its
//! announcement carried ([`super::WorkerFences::told_at`]). The second set lives in memory, so a
//! daemon that starts again cannot tell which reports an answer it kept had read, and the counts
//! of two entries say nothing of that: the extra names of one report pay, in a count, for the names
//! another report owed. The record names the revisions instead, so that a later read can ask
//! whether its own entry reads every revision the kept one did.

use std::collections::{BTreeMap, BTreeSet};

use kr_protocol::action::RevocationBarrier;
use kr_protocol::ids::{AuthorityRevision, SessionId};

/// The most revisions one entry reads: its own, the carried ones it selects, and the ones whose
/// reports went while it read them and are charged to it.
pub(crate) const MAX_READ_REVISIONS: usize =
    1 + super::MAX_CARRIED_REVISIONS + super::MAX_REMEMBERED_REVISIONS;

/// The version of the kept record's shape and of what its members mean. A record of another
/// version reads as not known.
const VERSION: u8 = 1;

/// The revisions one entry read, by what its numbers hold of them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Reads {
    /// The revisions whose report the entry's numbers account for: a report that is held, whether
    /// whole or with names still to come, and one that went for room and was charged to the entry.
    accounted: BTreeSet<AuthorityRevision>,
    /// The revisions the entry read and says so of: no report is held for them, or the worker has
    /// said nothing of its fence under them. None of their names is in the entry's numbers.
    named: BTreeSet<AuthorityRevision>,
}

impl Reads {
    /// What an entry read, or nothing when it read more revisions than an entry ever does: a
    /// record never holds a cut list.
    #[must_use]
    pub(crate) fn new(
        accounted: BTreeSet<AuthorityRevision>,
        named: BTreeSet<AuthorityRevision>,
    ) -> Option<Self> {
        (accounted.len().saturating_add(named.len()) <= MAX_READ_REVISIONS)
            .then_some(Self { accounted, named })
    }

    /// Whether an entry that read `self` is the authority for what the entry that read `now` lacks:
    /// `now` accounts for every report that `self` accounted for, and reads every revision that
    /// `self` named, either accounting for it or saying that it names nothing of it.
    ///
    /// Then every name that `self`'s numbers hold belongs to a report that `now`'s numbers hold too,
    /// so a name that `self` lacked is a name that `now` lacks or lists, and what `now` says is
    /// missing is what is.
    #[must_use]
    pub(crate) fn covered_by(&self, now: &Self) -> bool {
        self.accounted.is_subset(&now.accounted)
            && self
                .named
                .iter()
                .all(|revision| now.accounted.contains(revision) || now.named.contains(revision))
    }

    /// Every revision read, accounted for or named.
    pub(crate) fn revisions(&self) -> impl Iterator<Item = AuthorityRevision> + '_ {
        self.accounted.union(&self.named).copied()
    }
}

/// The record of what an answer's entries read, for the workers the answer carries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct KeptReads {
    workers: BTreeMap<SessionId, Reads>,
}

/// The stored form: canonical CBOR, a version member and one member per worker.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    workers: Vec<StoredWorker>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredWorker {
    session_id: SessionId,
    accounted: Vec<AuthorityRevision>,
    named: Vec<AuthorityRevision>,
}

impl KeptReads {
    /// The record of an answer: what each worker its barrier carries read, where that is known.
    ///
    /// A worker whose entry could not name all it read is not in it.
    #[must_use]
    pub(crate) fn of(barrier: &RevocationBarrier, reads: &BTreeMap<SessionId, Reads>) -> Self {
        let workers = barrier
            .workers
            .iter()
            .filter_map(|worker| {
                reads
                    .get(&worker.session_id)
                    .map(|reads| (worker.session_id, reads.clone()))
            })
            .collect();
        Self { workers }
    }

    /// What the entry for a worker read when the answer was made, when that is known.
    #[must_use]
    pub(crate) fn of_worker(&self, session_id: SessionId) -> Option<&Reads> {
        self.workers.get(&session_id)
    }

    /// For each worker with a record, the revisions its entry read: what a repeat's entry reads too
    /// ([`super::WorkerFences::told_at`]).
    #[must_use]
    pub(crate) fn through(&self) -> BTreeMap<SessionId, Vec<AuthorityRevision>> {
        self.workers
            .iter()
            .map(|(session_id, reads)| (*session_id, reads.revisions().collect()))
            .collect()
    }

    /// The stored form, or nothing when it cannot be made, which reads as not known.
    #[must_use]
    pub(crate) fn encode(&self) -> Option<Vec<u8>> {
        let stored = Stored {
            version: VERSION,
            workers: self
                .workers
                .iter()
                .map(|(session_id, reads)| StoredWorker {
                    session_id: *session_id,
                    accounted: reads.accounted.iter().copied().collect(),
                    named: reads.named.iter().copied().collect(),
                })
                .collect(),
        };
        kr_cbor::to_canonical_vec(&stored).ok()
    }

    /// The record that `stored` holds, or nothing when it is not one this build reads: it does not
    /// decode, it has a member this build does not know, it is of another version, or it is not
    /// ordered and unrepeated as the stored form is. A worker that lists more revisions than an
    /// entry ever reads has no record, and its list is not cut.
    #[must_use]
    pub(crate) fn decode(stored: &[u8]) -> Option<Self> {
        let limits = kr_cbor::Limits {
            max_message_len: stored.len(),
            max_items: stored.len(),
            max_collection_len: stored.len(),
            ..kr_cbor::Limits::DEFAULT
        };
        let stored: Stored = kr_cbor::from_canonical_slice(stored, &limits).ok()?;
        if stored.version != VERSION {
            return None;
        }
        let mut workers = BTreeMap::new();
        let mut last = None;
        for worker in stored.workers {
            if last.is_some_and(|last| last >= worker.session_id) {
                return None;
            }
            last = Some(worker.session_id);
            let ascending =
                |list: &[AuthorityRevision]| list.windows(2).all(|pair| pair[0] < pair[1]);
            if !ascending(&worker.accounted) || !ascending(&worker.named) {
                return None;
            }
            let accounted: BTreeSet<_> = worker.accounted.into_iter().collect();
            let named: BTreeSet<_> = worker.named.into_iter().collect();
            if !accounted.is_disjoint(&named) {
                return None;
            }
            if let Some(reads) = Reads::new(accounted, named) {
                workers.insert(worker.session_id, reads);
            }
        }
        Some(Self { workers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revisions(numbers: &[u64]) -> BTreeSet<AuthorityRevision> {
        numbers
            .iter()
            .map(|number| AuthorityRevision::new(*number))
            .collect()
    }

    fn session(byte: u8) -> SessionId {
        SessionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
    }

    fn encoded(stored: &Stored) -> Vec<u8> {
        kr_cbor::to_canonical_vec(stored).expect("a record")
    }

    fn worker(byte: u8, accounted: &[u64], named: &[u64]) -> StoredWorker {
        StoredWorker {
            session_id: session(byte),
            accounted: accounted
                .iter()
                .map(|number| AuthorityRevision::new(*number))
                .collect(),
            named: named
                .iter()
                .map(|number| AuthorityRevision::new(*number))
                .collect(),
        }
    }

    /// What a repeat reads of a kept record is what the answer was made with, and a record the
    /// build cannot read is not an error: it reads as not known.
    #[test]
    fn a_record_reads_back_as_it_was_kept_and_a_record_this_build_cannot_read_is_not_known() {
        let kept = KeptReads {
            workers: BTreeMap::from([
                (
                    session(1),
                    Reads::new(revisions(&[4, 5]), revisions(&[3])).expect("a few revisions"),
                ),
                (
                    session(2),
                    Reads::new(revisions(&[5]), BTreeSet::new()).expect("a few revisions"),
                ),
            ]),
        };
        let bytes = kept.encode().expect("a record");
        assert_eq!(KeptReads::decode(&bytes), Some(kept));

        let version = |version| Stored {
            version,
            workers: vec![worker(1, &[5], &[])],
        };
        assert!(KeptReads::decode(&encoded(&version(VERSION))).is_some());
        assert_eq!(
            KeptReads::decode(&encoded(&version(VERSION + 1))),
            None,
            "an unknown version"
        );
        assert_eq!(KeptReads::decode(b"not a record"), None);
        assert_eq!(KeptReads::decode(&[]), None);
        // A member this build does not know.
        #[derive(serde::Serialize)]
        struct Wider {
            version: u8,
            workers: Vec<StoredWorker>,
            more: u8,
        }
        let wider = Wider {
            version: VERSION,
            workers: vec![worker(1, &[5], &[])],
            more: 1,
        };
        assert_eq!(
            KeptReads::decode(&kr_cbor::to_canonical_vec(&wider).expect("a record")),
            None,
            "an unknown member"
        );
        // Bytes after the record.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(KeptReads::decode(&trailing), None);
        // Out of order, repeated, or read both ways: not a record this build made.
        for stored in [
            Stored {
                version: VERSION,
                workers: vec![worker(2, &[5], &[]), worker(1, &[5], &[])],
            },
            Stored {
                version: VERSION,
                workers: vec![worker(1, &[5], &[]), worker(1, &[5], &[])],
            },
            Stored {
                version: VERSION,
                workers: vec![worker(1, &[5, 4], &[])],
            },
            Stored {
                version: VERSION,
                workers: vec![worker(1, &[5], &[5])],
            },
        ] {
            assert_eq!(KeptReads::decode(&encoded(&stored)), None);
        }
    }

    /// An entry never reads more revisions than the bound, so a worker past it has no record: the
    /// record is not cut to fit, which would say less than the entry read. On write, a worker past
    /// the bound is not in the record; on read, a decoded record that holds one reads it as having
    /// none, and the workers beside it are still known.
    #[test]
    fn a_worker_past_the_bound_has_no_record_and_never_a_cut_list() {
        assert!(Reads::new(revisions(&(1..=72).collect::<Vec<_>>()), BTreeSet::new()).is_some());
        assert!(Reads::new(revisions(&(1..=73).collect::<Vec<_>>()), BTreeSet::new()).is_none());
        assert!(
            Reads::new(
                revisions(&(1..=40).collect::<Vec<_>>()),
                revisions(&(41..=73).collect::<Vec<_>>())
            )
            .is_none(),
            "the two lists count together"
        );

        let wide: Vec<u64> = (1..=73).collect();
        let stored = Stored {
            version: VERSION,
            workers: vec![worker(1, &wide, &[]), worker(2, &[5], &[])],
        };
        let decoded = KeptReads::decode(&encoded(&stored)).expect("the record decodes");
        assert_eq!(decoded.of_worker(session(1)), None, "no cut list");
        assert!(decoded.of_worker(session(2)).is_some());
    }

    /// The record covers the workers an answer carries, once it is cut to what a frame holds, and
    /// no others; a worker whose entry has no reads is not in it.
    #[test]
    fn the_record_holds_the_workers_the_answer_carries() {
        use kr_protocol::action::{BarrierState, WorkerBarrier};
        use kr_protocol::scalars::{Nullable, U64};

        let entry = |byte| WorkerBarrier {
            session_id: session(byte),
            state: BarrierState::Pending,
            acknowledged_revision: Nullable::null(),
            rejected_actions: Vec::new(),
            rejected_actions_total: U64::new(0),
            possibly_executed: Vec::new(),
            possibly_executed_total: U64::new(0),
            omitted_actions: U64::new(0),
            names_pending: U64::new(0),
            detail: String::new(),
        };
        let barrier = RevocationBarrier::new(AuthorityRevision::new(5), vec![entry(1), entry(2)]);
        let own = Reads::new(revisions(&[5]), BTreeSet::new()).expect("a revision");
        let reads = BTreeMap::from([(session(1), own.clone()), (session(3), own.clone())]);
        let kept = KeptReads::of(&barrier, &reads);
        assert_eq!(kept.of_worker(session(1)), Some(&own));
        assert_eq!(kept.of_worker(session(2)), None, "no reads for this entry");
        assert_eq!(kept.of_worker(session(3)), None, "not in the answer");
    }

    /// An entry is covered by the daemon's own when the daemon's accounts for every report that the
    /// kept entry's did and reads every revision that it named; each failing half is covered by
    /// its own case.
    #[test]
    fn an_entry_covers_the_kept_one_only_when_it_accounts_for_and_reads_all_it_did() {
        let reads = |accounted: &[u64], named: &[u64]| {
            Reads::new(revisions(accounted), revisions(named)).expect("a few revisions")
        };
        let kept = reads(&[4, 5], &[3]);
        assert!(kept.covered_by(&reads(&[3, 4, 5, 6], &[])), "more is read");
        assert!(kept.covered_by(&reads(&[4, 5], &[3])), "the same is read");
        assert!(
            kept.covered_by(&reads(&[4, 5], &[3, 9])),
            "a named revision may be named by the daemon's too"
        );
        assert!(
            !kept.covered_by(&reads(&[5], &[3, 4])),
            "a report the kept entry accounted for is only named by the daemon's"
        );
        assert!(
            !kept.covered_by(&reads(&[5], &[])),
            "a report the daemon's entry does not read at all"
        );
        assert!(
            !kept.covered_by(&reads(&[4, 5], &[])),
            "a revision the kept entry named and the daemon's neither accounts for nor names"
        );
    }
}
