//! The llama.cpp runtime, CPU only, as the model the description process runs.
//!
//! This is the only module that talks to the inference library, and it is deliberately small: the
//! decisions were all made above it, so what happens here is check the files, load a model with
//! zero GPU layers, build the sampler the profile describes, constrain it with the grammar, and
//! decode at most the output bound.
//!
//! # Zero GPU layers
//!
//! Section 22 keeps *zero GPU layers as the agreed CPU-only design*, and CPU-only here is two
//! settings rather than one, because zero layers on its own is not enough.
//!
//! The profile records zero GPU layers, [`LlamaRuntime::load`] refuses a profile that records
//! anything else before it opens a file, and the model parameters ask for nought, so no layer's
//! weights are placed on an accelerator. That leaves the library's *operation* offload, which is
//! on by default and will send a large enough matrix multiply to a registered backend even when
//! its weights are in host memory; the context parameters turn it off.
//!
//! Both are needed on Apple silicon, where the pinned binding compiles the Metal backend in
//! whether or not it is wanted - its manifest enables that feature for the target rather than
//! behind an option - so what makes this build CPU-only is the two settings rather than the
//! absence of the backend from the binary.
//!
//! # A context per job
//!
//! The weights stay resident between jobs; the key-value cache does not. A 4,096-token cache is
//! hundreds of megabytes, and holding one between descriptions that are at least thirty seconds
//! apart would be spending most of the process ceiling on a buffer that is idle almost all of the
//! time. So the context is built at the start of a job and dropped at the end, and what sits
//! between jobs is the mapping alone.
//!
//! # The token, the deadline and the ceiling
//!
//! The job's token is the one the process's control thread sets when the daemon cancels, and it is
//! checked between tokens with the deadline and, every few tokens, the process's resident set
//! against the ceiling. Between tokens is the only place a decode loop can be interrupted without
//! leaving the library in a state nobody can describe, so the bound is one token of work rather
//! than instant, and a job that is stopped produces nothing.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;

use kr_describe::priority::Cancellation;
use kr_describe::profile::{Asset, ModelProfile};
use kr_describe::serve::{Generating, Job, LoadWork, Loading, Model, Verifying, own_rss_bytes};
use kr_describe::wire::{JobEnd, LoadEnd, Phases, VerifyResult};
use kr_protocol::scalars::U64;

/// How many tokens one decode batch carries.
const BATCH_TOKENS: usize = 512;

/// How many prompt tokens one decode call reads. The token is checked between calls, so this is
/// what bounds how long a cancellation waits while the prompt is read: a few hundred milliseconds
/// on a busy host rather than the whole prompt.
const PROMPT_CHUNK_TOKENS: usize = 128;

/// The buffer one token's bytes are read into. No tokenizer piece in either profile is near it.
const PIECE_BYTES: usize = 64;

/// How many tokens pass between two readings of the process's resident set.
const RSS_EVERY_TOKENS: u32 = 8;

/// The process-wide backend.
///
/// The library takes a process-wide initialisation and refuses a second one, which is the same
/// shape as section 22's *one shared inference process and model mapping per execution
/// environment*: there is one of these per process however many profiles are mapped over its life.
static BACKEND: OnceLock<std::result::Result<LlamaBackend, String>> = OnceLock::new();

/// Returns where a chunk starts inside the slice it came from.
fn position_of(
    whole: &[llama_cpp_2::token::LlamaToken],
    chunk: &[llama_cpp_2::token::LlamaToken],
) -> usize {
    // `chunks` yields subslices of the original allocation, so the distance between the pointers is
    // the offset. It is computed rather than counted so a long prompt does not cost a scan per
    // batch.
    (chunk.as_ptr() as usize - whole.as_ptr() as usize)
        / std::mem::size_of::<llama_cpp_2::token::LlamaToken>()
}

fn backend() -> std::result::Result<&'static LlamaBackend, String> {
    match BACKEND.get_or_init(|| LlamaBackend::init().map_err(|error| error.to_string())) {
        Ok(backend) => Ok(backend),
        Err(detail) => Err(detail.clone()),
    }
}

/// Returns the milliseconds since `started`.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The model the description process runs: the llama.cpp runtime, once a profile is loaded.
#[derive(Debug, Default)]
pub struct Llama {
    runtime: Option<LlamaRuntime>,
}

impl Llama {
    /// Builds a model with nothing loaded.
    #[must_use]
    pub const fn new() -> Self {
        Self { runtime: None }
    }

    /// Wraps a runtime that is already loaded, which is how the benchmark measures its load apart.
    #[must_use]
    pub const fn loaded(runtime: LlamaRuntime) -> Self {
        Self {
            runtime: Some(runtime),
        }
    }
}

impl Model for Llama {
    fn load(&mut self, work: &LoadWork<'_>, token: &Cancellation, deadline: Instant) -> Loading {
        // Each load checks every file against the profile again, from the one handle it reads, so
        // a file replaced since it was downloaded is refused rather than loaded.
        for placed in work.assets {
            let stop = || token.is_cancelled() || Instant::now() >= deadline;
            match crate::assets::verify_file_unless(&placed.asset, &placed.path, stop) {
                Ok(true) => {}
                Ok(false) if token.is_cancelled() => {
                    return Loading::Ended {
                        why: LoadEnd::Cancelled,
                        detail: None,
                    };
                }
                Ok(false) => {
                    return Loading::Ended {
                        why: LoadEnd::DeadlineExceeded,
                        detail: None,
                    };
                }
                Err(error) => {
                    return Loading::Ended {
                        why: LoadEnd::Refused,
                        detail: Some(error.to_string()),
                    };
                }
            }
        }
        let Some(weights) = work
            .assets
            .iter()
            .find(|placed| placed.asset.role == "weights")
        else {
            return Loading::Ended {
                why: LoadEnd::Refused,
                detail: Some(format!(
                    "{} names no weights file",
                    work.profile.profile_id()
                )),
            };
        };
        match LlamaRuntime::load(work.profile, &weights.path, token, deadline) {
            Ok(runtime) => {
                self.runtime = Some(runtime);
                Loading::Loaded
            }
            Err((why, detail)) => Loading::Ended { why, detail },
        }
    }

    fn generate(&mut self, job: &Job<'_>, token: &Cancellation, deadline: Instant) -> Generating {
        match self.runtime.as_mut() {
            Some(runtime) => runtime.generate(job, token, deadline),
            None => Generating::Ended {
                why: JobEnd::NotLoaded,
                detail: None,
            },
        }
    }

    fn verify(
        &mut self,
        asset: &Asset,
        path: &Path,
        token: &Cancellation,
        deadline: Instant,
    ) -> Verifying {
        // The same check a load makes, stopping between blocks of the file: a gigabyte hashed
        // under the process's background class, and a cancellation heard within one block.
        let stop = || token.is_cancelled() || Instant::now() >= deadline;
        match crate::assets::verify_file_unless(asset, path, stop) {
            Ok(true) => Verifying::Verified,
            Ok(false) if token.is_cancelled() => Verifying::Ended {
                result: VerifyResult::Cancelled,
                detail: None,
            },
            Ok(false) => Verifying::Ended {
                result: VerifyResult::DeadlineExceeded,
                detail: None,
            },
            Err(error @ kr_describe::DescribeError::AssetUnreadable { .. }) => Verifying::Ended {
                result: VerifyResult::Unreadable,
                detail: Some(error.to_string()),
            },
            Err(error) => Verifying::Ended {
                result: VerifyResult::Mismatch,
                detail: Some(error.to_string()),
            },
        }
    }
}

/// A loaded model, on the processor.
#[derive(Debug)]
pub struct LlamaRuntime {
    model: LlamaModel,
    context_tokens: u32,
    weights_path: PathBuf,
}

impl LlamaRuntime {
    /// Loads a profile's weights from a verified file, observing the token and the deadline.
    ///
    /// The caller has already verified the file against the profile's recorded size and digest;
    /// this refuses a profile whose execution settings are not the CPU-only ones, which is the
    /// second of the two places zero GPU layers is enforced. If the token is cancelled or the
    /// deadline passes, loading aborts or the loaded model is dropped at once.
    ///
    /// # Errors
    ///
    /// Returns why there is no model: refused for a profile that is not CPU-only, cancelled, past
    /// its deadline, or failed with what the library said.
    pub fn load(
        profile: &ModelProfile,
        weights: &Path,
        token: &Cancellation,
        deadline: Instant,
    ) -> std::result::Result<Self, (LoadEnd, Option<String>)> {
        if profile.execution().gpu_layers != 0 {
            return Err((
                LoadEnd::Refused,
                Some(format!(
                    "{} states GPU layers, where this runtime offloads none",
                    profile.profile_id()
                )),
            ));
        }
        if token.is_cancelled() {
            return Err((LoadEnd::Cancelled, None));
        }
        if Instant::now() >= deadline {
            return Err((LoadEnd::DeadlineExceeded, None));
        }
        let backend = backend().map_err(|detail| (LoadEnd::Failed, Some(detail)))?;
        let watched = token.clone();
        let parameters = LlamaModelParams::default()
            .with_n_gpu_layers(0)
            .with_progress_callback(move |_progress| {
                !watched.is_cancelled() && Instant::now() < deadline
            });
        let model = match LlamaModel::load_from_file(backend, weights, &parameters) {
            Ok(model) => model,
            Err(error) => {
                if token.is_cancelled() {
                    return Err((LoadEnd::Cancelled, None));
                }
                if Instant::now() >= deadline {
                    return Err((LoadEnd::DeadlineExceeded, None));
                }
                return Err((
                    LoadEnd::Failed,
                    Some(format!(
                        "{} could not be loaded: {error}",
                        weights.display()
                    )),
                ));
            }
        };
        if token.is_cancelled() {
            drop(model);
            return Err((LoadEnd::Cancelled, None));
        }
        if Instant::now() >= deadline {
            drop(model);
            return Err((LoadEnd::DeadlineExceeded, None));
        }
        Ok(Self {
            model,
            context_tokens: profile.execution().context_tokens,
            weights_path: weights.to_path_buf(),
        })
    }

    /// Returns the file this model was loaded from.
    #[must_use]
    pub fn weights_path(&self) -> &Path {
        &self.weights_path
    }

    fn sampler(&self, job: &Job<'_>) -> std::result::Result<LlamaSampler, String> {
        let grammar = LlamaSampler::grammar(&self.model, job.grammar, "root")
            .map_err(|error| format!("the description grammar was refused: {error}"))?;
        let sampler = job.sampler;
        let vocabulary = self.model.n_vocab();
        let mut chain = vec![
            grammar,
            LlamaSampler::penalties(
                vocabulary,
                i32::try_from(sampler.repeat_last_n).unwrap_or(i32::MAX),
                sampler.repeat_penalty as f32,
                0.0,
                0.0,
            ),
        ];
        if sampler.is_greedy() {
            // Greedy decoding, which is what a temperature of nought means. The other values are
            // recorded in the profile and do not apply: a chain that also filtered by top-k would
            // be describing a sampler this profile does not use.
            chain.push(LlamaSampler::greedy());
        } else {
            chain.push(LlamaSampler::top_k(
                i32::try_from(sampler.top_k).unwrap_or(i32::MAX),
            ));
            chain.push(LlamaSampler::top_p(sampler.top_p as f32, 1));
            chain.push(LlamaSampler::min_p(sampler.min_p as f32, 1));
            chain.push(LlamaSampler::temp(sampler.temperature as f32));
            chain.push(LlamaSampler::dist(sampler.seed));
        }
        Ok(LlamaSampler::chain_simple(chain))
    }

    /// Runs one job: reads the prompt, then samples and decodes at most the output bound.
    ///
    /// It ends the job between tokens when the token is cancelled, the deadline passes, or the
    /// process's resident set passes the job's ceiling.
    pub fn generate(
        &mut self,
        job: &Job<'_>,
        token: &Cancellation,
        deadline: Instant,
    ) -> Generating {
        match self.run(job, token, deadline) {
            Ok(generating) => generating,
            Err(detail) => Generating::Ended {
                why: JobEnd::Failed,
                detail: Some(detail),
            },
        }
    }

    fn run(
        &mut self,
        job: &Job<'_>,
        token: &Cancellation,
        deadline: Instant,
    ) -> std::result::Result<Generating, String> {
        let stopped = |why: JobEnd| Generating::Ended { why, detail: None };
        let backend = backend()?;
        let threads = i32::try_from(job.cpu_threads).unwrap_or(1).max(1);
        let context_tokens = job.context_tokens.min(self.context_tokens).max(1);
        let parameters = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(context_tokens))
            .with_n_batch(BATCH_TOKENS as u32)
            .with_n_threads(threads)
            .with_n_threads_batch(threads)
            // Zero GPU layers keeps the weights on the processor; this keeps the *operations*
            // there too. The library's scheduler will otherwise offload an operation whose weights
            // are in host memory to whatever backend is registered, and on Apple silicon the
            // pinned binding registers one whether or not it was asked for.
            .with_op_offload(false);
        let mut context = self
            .model
            .new_context(backend, parameters)
            .map_err(|error| format!("a context could not be created: {error}"))?;

        let tokens = self
            .model
            .str_to_token(job.prompt, AddBos::Always)
            .map_err(|error| format!("the prompt could not be tokenized: {error}"))?;
        // The prompt is bounded by construction, but a model with a short context is not this
        // host's to fix: refusing is better than silently describing the tail of a prompt.
        if tokens.len() + job.max_output_tokens as usize > context_tokens as usize {
            return Err(format!(
                "a prompt of {} tokens and {} of output do not fit in {context_tokens}",
                tokens.len(),
                job.max_output_tokens
            ));
        }

        // The prompt is decoded in chunks smaller than the context's own batch size, which the
        // library refuses a single decode past, and small enough that the token checked between
        // them stops a job soon after it is cancelled.
        let prompt_started = Instant::now();
        let mut batch = LlamaBatch::new(BATCH_TOKENS, 1);
        let last = tokens.len().saturating_sub(1);
        for chunk in tokens.chunks(PROMPT_CHUNK_TOKENS) {
            if token.is_cancelled() {
                return Ok(stopped(JobEnd::Cancelled));
            }
            if Instant::now() >= deadline {
                return Ok(stopped(JobEnd::DeadlineExceeded));
            }
            batch.clear();
            let offset = position_of(&tokens, chunk);
            for (index, piece) in chunk.iter().enumerate() {
                let position = offset + index;
                batch
                    .add(
                        *piece,
                        i32::try_from(position).unwrap_or(i32::MAX),
                        &[0],
                        position == last,
                    )
                    .map_err(|error| format!("the prompt could not be batched: {error}"))?;
            }
            context
                .decode(&mut batch)
                .map_err(|error| format!("the prompt could not be decoded: {error}"))?;
        }
        let prompt_ms = elapsed_ms(prompt_started);

        let mut sampler = self.sampler(job)?;
        let mut produced: Vec<u8> = Vec::new();
        let mut position = i32::try_from(tokens.len()).unwrap_or(i32::MAX);
        let mut sampling_ms = 0_u64;
        let mut decode_ms = 0_u64;
        let mut peak_rss_bytes = own_rss_bytes().unwrap_or(0);
        for step in 0..job.max_output_tokens {
            if token.is_cancelled() {
                return Ok(stopped(JobEnd::Cancelled));
            }
            if Instant::now() >= deadline {
                return Ok(stopped(JobEnd::DeadlineExceeded));
            }
            if step % RSS_EVERY_TOKENS == 0 {
                peak_rss_bytes = peak_rss_bytes.max(own_rss_bytes().unwrap_or(0));
                if peak_rss_bytes > job.ceiling_bytes {
                    return Ok(Generating::Ended {
                        why: JobEnd::MemoryCeiling,
                        detail: Some(format!(
                            "the process's resident set of {peak_rss_bytes} bytes passed the \
                             ceiling of {} bytes",
                            job.ceiling_bytes
                        )),
                    });
                }
            }
            // `sample` accepts the token itself, which the binding documents. Accepting it again
            // would advance the grammar twice and let a second opening brace empty its stack,
            // which the library ends the process over.
            let sampling_started = Instant::now();
            let chosen = sampler.sample(&context, -1);
            sampling_ms = sampling_ms.saturating_add(elapsed_ms(sampling_started));
            if self.model.is_eog_token(chosen) {
                break;
            }
            // Bytes rather than text, and assembled at the end: one token can be half of a
            // codepoint, and a decoder that answered per token would either drop it or invent a
            // replacement character in the middle of a name.
            let piece = self
                .model
                .token_to_piece_bytes(chosen, PIECE_BYTES, false, None)
                .map_err(|error| format!("a token could not be decoded: {error}"))?;
            produced.extend_from_slice(&piece);
            let decode_started = Instant::now();
            batch.clear();
            batch
                .add(chosen, position, &[0], true)
                .map_err(|error| format!("a token could not be batched: {error}"))?;
            position = position.saturating_add(1);
            context
                .decode(&mut batch)
                .map_err(|error| format!("a token could not be decoded: {error}"))?;
            decode_ms = decode_ms.saturating_add(elapsed_ms(decode_started));
        }
        peak_rss_bytes = peak_rss_bytes.max(own_rss_bytes().unwrap_or(0));
        Ok(Generating::Produced {
            bytes: produced,
            phases: Phases {
                prompt_tokens: U64::new(tokens.len() as u64),
                prompt_ms: U64::new(prompt_ms),
                sampling_ms: U64::new(sampling_ms),
                decode_ms: U64::new(decode_ms),
            },
            peak_rss_bytes,
        })
    }
}
