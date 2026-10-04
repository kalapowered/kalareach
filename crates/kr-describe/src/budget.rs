//! Section 22's defaults, and what a resident model actually costs.
//!
//! The figures below are **qualification budgets**. Section 22 says so in as many words: *they are
//! qualification budgets, not claims that the supplied candidates already meet them*. So this
//! module holds two different things and keeps them apart. [`Budgets`] is what a run is allowed to
//! spend. [`ResidentCost`] is what a profile says it will spend, itemised, and what a measurement
//! found. Whether the second fits inside the first is a question with an answer per host, and
//! [`crate::qualification`] is where that answer is recorded.
//!
//! # Why the cost is itemised
//!
//! Section 22: *account for weights, mappings, KV/additional caches, batching and runtime
//! overhead, not file size alone*. A 1.5 GiB file is not a 1.5 GiB process: the key-value cache at
//! 4,096 tokens is hundreds of megabytes on its own, the compute graph for a batch is more, and the
//! runtime's own allocations are more again. A budget check against the file would pass on a host
//! that then runs out of memory, which is the failure the itemisation exists to prevent.

use serde::{Deserialize, Serialize};

/// One gibibyte.
pub const GIB: u64 = 1 << 30;

/// The defaults section 22 fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    /// CPU threads the runtime may use.
    pub cpu_threads: u32,
    /// How many requests may be executing at once.
    pub active_requests: u32,
    /// The context window, in tokens.
    pub context_tokens: u32,
    /// The output bound, in tokens.
    pub max_output_tokens: u32,
    /// How long a context change is coalesced before a job is admitted.
    pub context_debounce_ms: u64,
    /// The shortest interval between two descriptions of one session.
    ///
    /// Section 22 calls this a *minimum cooldown, not a refresh SLA for every session*, and this
    /// crate never treats it as one: the cadence a session actually gets is computed from measured
    /// service time and the number of eligible sessions, and it is longer than this whenever the
    /// host is busy.
    pub session_cooldown_ms: u64,
    /// The process-memory ceiling.
    pub process_memory_ceiling_bytes: u64,
    /// The execution deadline, measured **after dequeue** rather than from admission, so a job
    /// that waited is not killed for waiting.
    pub execution_deadline_ms: u64,
}

impl Budgets {
    /// Section 22's defaults.
    pub const DEFAULTS: Self = Self {
        cpu_threads: 4,
        active_requests: 1,
        context_tokens: 4096,
        max_output_tokens: 128,
        context_debounce_ms: 2_000,
        session_cooldown_ms: 30_000,
        process_memory_ceiling_bytes: 4 * GIB,
        execution_deadline_ms: 30_000,
    };

    /// Returns whether an itemised cost fits inside the process ceiling.
    #[must_use]
    pub const fn admits(&self, cost: &ResidentCost) -> bool {
        cost.total() <= self.process_memory_ceiling_bytes
    }

    /// Returns the ceiling with an owner's stricter figure applied.
    ///
    /// An owner may tighten a budget and never loosen one: a configured ceiling above section 22's
    /// is ignored, because the figure the product was qualified against is the one it claims.
    #[must_use]
    pub const fn with_owner_ceiling(mut self, owner_ceiling_bytes: u64) -> Self {
        if owner_ceiling_bytes < self.process_memory_ceiling_bytes {
            self.process_memory_ceiling_bytes = owner_ceiling_bytes;
        }
        self
    }
}

impl Default for Budgets {
    fn default() -> Self {
        Self::DEFAULTS
    }
}

/// How fast the reference measurement read a prompt, in tokens a second.
///
/// The measurement is the selected profile on the build box at four threads, under a load average
/// of 20 to 40 from other work: 708 tokens in 11.6 s is 61 a second, and 206 in 3.0 s is 69. The
/// figure used is below the slowest of them.
pub const REFERENCE_PROMPT_TOKENS_PER_SECOND: u64 = 55;

/// How long the same measurement took to write one token of the answer under the grammar, in
/// milliseconds: 70 to 85 on the box. The figure used is above that.
pub const REFERENCE_OUTPUT_MS_PER_TOKEN: u64 = 100;

/// What a job costs before the prompt is read, in milliseconds: the context, the grammar and the
/// sampler. The measurement found 0.5 to 0.75 s.
pub const REFERENCE_JOB_OVERHEAD_MS: u64 = 1_000;

/// Returns how many tokens a job's prompt may be.
///
/// Two limits hold, and the smaller is the bound. The prompt and the answer's bound have to fit the
/// context window. And the whole job has to finish inside its deadline at the reference rates: the
/// time left once the job's own cost and an answer of the full output bound are taken out of the
/// deadline is what the prompt may take to read. With section 22's defaults the window leaves room
/// for 3,968 tokens and the deadline for 891, so the deadline decides: 30 s, less 1 s of cost and
/// 12.8 s for 128 tokens of answer, is 16.2 s, and at 55 tokens a second that is 891 tokens.
#[must_use]
pub fn prompt_tokens(context_tokens: u32, max_output_tokens: u32, deadline_ms: u64) -> u32 {
    let room = context_tokens.saturating_sub(max_output_tokens);
    let reading_ms = deadline_ms
        .saturating_sub(REFERENCE_JOB_OVERHEAD_MS)
        .saturating_sub(u64::from(max_output_tokens) * REFERENCE_OUTPUT_MS_PER_TOKEN);
    let by_deadline =
        u32::try_from(reading_ms * REFERENCE_PROMPT_TOKENS_PER_SECOND / 1_000).unwrap_or(u32::MAX);
    room.min(by_deadline)
}

/// What one job is allowed: section 22's budgets, bounded again by what the selected profile asks
/// for. A profile that wants a longer answer or more threads than the budget allows gets the
/// budget; one that wants less gets what it asked for, because that is what it was qualified with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobBounds {
    /// The context window, in tokens.
    pub context_tokens: u32,
    /// The output bound, in tokens.
    pub max_output_tokens: u32,
    /// How many tokens the prompt may be, beside the answer's bound.
    pub prompt_tokens: u32,
    /// How many processor threads the job may use.
    pub cpu_threads: u32,
    /// The deadline, from dequeue, in milliseconds.
    pub deadline_ms: u64,
}

impl Budgets {
    /// Returns what a job of a profile with these settings is allowed.
    #[must_use]
    pub fn bounds(&self, execution: &crate::profile::ExecutionSettings) -> JobBounds {
        let context_tokens = self.context_tokens.min(execution.context_tokens);
        let max_output_tokens = self.max_output_tokens.min(execution.max_output_tokens);
        JobBounds {
            context_tokens,
            max_output_tokens,
            prompt_tokens: prompt_tokens(
                context_tokens,
                max_output_tokens,
                self.execution_deadline_ms,
            ),
            cpu_threads: self.cpu_threads.min(execution.cpu_threads),
            deadline_ms: self.execution_deadline_ms,
        }
    }
}

/// What a resident model costs, itemised.
///
/// A profile records this as its declared estimate; a benchmark records it again as a measurement.
/// They are the same shape so the two can be put beside each other, which is what a qualification
/// note is: the estimate, the measurement and the host they were compared on.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ResidentCost {
    /// The weights themselves.
    pub weights_bytes: u64,
    /// The mapping's own overhead: alignment, page tables and the pages the loader touches.
    pub mapping_bytes: u64,
    /// The key-value cache at the profile's context length.
    pub kv_cache_bytes: u64,
    /// Every other cache the runtime keeps: logits, embeddings and vocabulary buffers.
    pub additional_cache_bytes: u64,
    /// The compute graph and buffers one batch needs.
    pub batch_bytes: u64,
    /// The runtime's own allocations: the backend registry, its threads and its allocator.
    pub runtime_overhead_bytes: u64,
}

impl ResidentCost {
    /// Returns the total.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.weights_bytes
            .saturating_add(self.mapping_bytes)
            .saturating_add(self.kv_cache_bytes)
            .saturating_add(self.additional_cache_bytes)
            .saturating_add(self.batch_bytes)
            .saturating_add(self.runtime_overhead_bytes)
    }

    /// Returns what one job allocates again even when the weights are already resident.
    ///
    /// A runtime that keeps its weights between jobs does not keep its context: the key-value
    /// cache, the other caches and the batch buffers are built for each job and released after it.
    /// So a host with a model resident still needs this much headroom before the next job, and a
    /// reserve check that only asked whether the weights fit would admit a job that then could not
    /// allocate.
    #[must_use]
    pub const fn per_job_peak(&self) -> u64 {
        self.kv_cache_bytes
            .saturating_add(self.additional_cache_bytes)
            .saturating_add(self.batch_bytes)
    }

    /// Returns the total that is not the weights, which is what file size alone would miss.
    #[must_use]
    pub const fn beyond_the_weights(&self) -> u64 {
        self.total().saturating_sub(self.weights_bytes)
    }
}

/// The figures a run reports beside the separated model and runtime ones.
///
/// Section 22: *measure whole-product RSS/CPU alongside the separated model/runtime figures*. Both
/// are here, in one value, because reporting one without the other is how a product comes to
/// believe it costs what its smallest component costs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessFigures {
    /// The whole product's resident set: controller, workers, shared services and the model.
    pub whole_product_rss_bytes: u64,
    /// The model and its runtime alone.
    pub model_rss_bytes: u64,
    /// The whole product's processor use, in hundredths of one core.
    pub whole_product_cpu_centis: u64,
    /// The model and its runtime alone, in hundredths of one core.
    pub model_cpu_centis: u64,
}

impl ProcessFigures {
    /// Returns the product's resident set with the model's share taken out.
    #[must_use]
    pub const fn product_without_model_rss_bytes(&self) -> u64 {
        self.whole_product_rss_bytes
            .saturating_sub(self.model_rss_bytes)
    }

    /// Returns the product's processor use with the model's share taken out.
    #[must_use]
    pub const fn product_without_model_cpu_centis(&self) -> u64 {
        self.whole_product_cpu_centis
            .saturating_sub(self.model_cpu_centis)
    }
}
