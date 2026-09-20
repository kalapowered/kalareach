//! Queue-wait and execution latency, published separately, at the four session counts.
//!
//! Section 22: *publish queue-wait and execution latency separately for 1, 5, 20 and 50 sessions*.
//! Separately is the operative word and it is enforced by the types: a [`Reading`] holds two
//! distributions and there is no method that adds them. The two answer different questions. Queue
//! wait is what fairness and cadence produce, and it grows with the number of sessions by design.
//! Execution time is what the model and the host produce, and if it grows with the number of
//! sessions the host is oversubscribed. A single figure would hide exactly that.
//!
//! Percentiles are computed by nearest rank over the samples held, and the sample count is
//! published beside every figure, because a p99 over eleven samples is a maximum wearing a
//! percentile's name.

use std::collections::BTreeMap;

/// The session counts section 22 names.
pub const PUBLISHED_SESSION_COUNTS: [u32; 4] = [1, 5, 20, 50];

/// A distribution of one kind of latency.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Distribution {
    /// How many samples it is over.
    pub samples: usize,
    /// The median.
    pub p50_ms: u64,
    /// The 95th percentile.
    pub p95_ms: u64,
    /// The 99th percentile.
    pub p99_ms: u64,
    /// The largest sample.
    pub max_ms: u64,
}

impl Distribution {
    /// Builds a distribution from samples.
    #[must_use]
    pub fn of(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Self {
            samples: sorted.len(),
            p50_ms: nearest_rank(&sorted, 50),
            p95_ms: nearest_rank(&sorted, 95),
            p99_ms: nearest_rank(&sorted, 99),
            max_ms: *sorted.last().unwrap_or(&0),
        }
    }
}

fn nearest_rank(sorted: &[u64], percentile: u64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let count = sorted.len() as u64;
    // Nearest rank, rounding up, so the p99 of a hundred samples is the ninety-ninth rather than a
    // value interpolated between two that were never measured.
    let rank = (percentile * count).div_ceil(100).max(1);
    let index = (rank - 1).min(count - 1) as usize;
    sorted[index]
}

/// One session count's published figures.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reading {
    /// How many sessions were live.
    pub sessions: u32,
    /// How long a job waited in the queue.
    pub queue_wait: Distribution,
    /// How long a job took once it was dequeued.
    pub execution: Distribution,
}

/// The samples one session count has produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Samples {
    queue_wait_ms: Vec<u64>,
    execution_ms: Vec<u64>,
}

/// Every sample a run has taken, kept apart by session count.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LatencyLedger {
    by_sessions: BTreeMap<u32, Samples>,
}

impl LatencyLedger {
    /// Builds an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one job's two latencies at the session count it ran under.
    ///
    /// The two are recorded together because they are one job, and they are stored apart because
    /// they are two measurements. The execution figure is taken from dequeue, which is where
    /// section 22 puts the deadline as well.
    pub fn record(&mut self, sessions: u32, queue_wait_ms: u64, execution_ms: u64) {
        let samples = self.by_sessions.entry(sessions).or_default();
        samples.queue_wait_ms.push(queue_wait_ms);
        samples.execution_ms.push(execution_ms);
    }

    /// Returns the figures for one session count, when anything was measured at it.
    #[must_use]
    pub fn reading(&self, sessions: u32) -> Option<Reading> {
        self.by_sessions.get(&sessions).map(|samples| Reading {
            sessions,
            queue_wait: Distribution::of(&samples.queue_wait_ms),
            execution: Distribution::of(&samples.execution_ms),
        })
    }

    /// Returns the figures at each of section 22's four session counts.
    ///
    /// A count nothing was measured at is absent rather than zero. A published zero would say the
    /// host answered instantly at fifty sessions, when what happened is that nobody ran fifty.
    #[must_use]
    pub fn published(&self) -> Vec<Reading> {
        PUBLISHED_SESSION_COUNTS
            .iter()
            .filter_map(|sessions| self.reading(*sessions))
            .collect()
    }

    /// Returns which of section 22's four counts have not been measured.
    #[must_use]
    pub fn unmeasured(&self) -> Vec<u32> {
        PUBLISHED_SESSION_COUNTS
            .iter()
            .copied()
            .filter(|sessions| !self.by_sessions.contains_key(sessions))
            .collect()
    }
}
