//! The llama.cpp runtime, CPU only.
//!
//! This is the only module that talks to the inference library, and it is deliberately small: the
//! decisions were all made above it, so what happens here is load a model with zero GPU layers,
//! build the sampler the profile describes, constrain it with the grammar, and decode at most the
//! output bound.
//!
//! # Zero GPU layers
//!
//! Section 22 keeps *zero GPU layers as the agreed CPU-only design*, the profile records it, and
//! [`LlamaRuntime::load`] refuses a profile that records anything else before it opens a file.
//! The model parameters then ask for nought, so no layer is offloaded to any backend. On Apple
//! silicon the pinned binding compiles the Metal backend in whether or not it is wanted - its
//! manifest enables that feature for the target rather than behind an option - so the CPU-only
//! guarantee here is the zero layers, enforced in two places, rather than the absence of the
//! backend from the binary.
//!
//! # A context per job
//!
//! The weights stay resident between jobs; the key-value cache does not. A 4,096-token cache is
//! hundreds of megabytes, and holding one between descriptions that are at least thirty seconds
//! apart would be spending most of the process ceiling on a buffer that is idle almost all of the
//! time. So the context is built at the start of a job and dropped at the end, and what sits
//! between jobs is the mapping alone.
//!
//! # The deadline and the cancellation token
//!
//! Both are checked between tokens, which is the only place a decode loop can be interrupted
//! without leaving the library in a state nobody can describe. The bound is therefore one token of
//! work rather than instant, and a job that is cancelled produces nothing.

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

use crate::budget::ResidentCost;
use crate::error::{DescribeError, Result};
use crate::priority::{Applied, background_current_thread};
use crate::profile::ModelProfile;
use crate::runtime::{GenerationRequest, InferenceRuntime, Produced, RuntimeHandle};

/// How many tokens one decode batch carries.
const BATCH_TOKENS: usize = 512;

/// The buffer one token's bytes are read into. No tokenizer piece in either profile is near it.
const PIECE_BYTES: usize = 64;

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

fn backend() -> Result<&'static LlamaBackend> {
    match BACKEND.get_or_init(|| LlamaBackend::init().map_err(|error| error.to_string())) {
        Ok(backend) => Ok(backend),
        Err(detail) => Err(DescribeError::Runtime {
            detail: detail.clone(),
        }),
    }
}

/// A loaded model, on the processor.
#[derive(Debug)]
pub struct LlamaRuntime {
    handle: RuntimeHandle,
    model: LlamaModel,
    cost: ResidentCost,
    context_tokens: u32,
    weights_path: PathBuf,
    priority: Applied,
}

impl LlamaRuntime {
    /// Loads a profile's weights from a verified file.
    ///
    /// The caller has already verified the file against the profile's recorded size and digest;
    /// this refuses a profile whose execution settings are not the CPU-only ones, which is the
    /// second of the two places zero GPU layers is enforced.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::ProfileRefused`] when the profile is not CPU-only and
    /// [`DescribeError::Runtime`] when the library cannot start or the file cannot be loaded.
    pub fn load(profile: &ModelProfile, weights: &Path) -> Result<Self> {
        if profile.execution().gpu_layers != 0 {
            return Err(DescribeError::ProfileRefused {
                profile: profile.profile_id().to_owned(),
                why: "GPU layers, where this runtime offloads none",
            });
        }
        let backend = backend()?;
        // The thread that loads the weights is the thread that runs them, so the background class
        // is applied here rather than per request: applying it per request would leave the caller's
        // thread demoted afterwards, and applying it nowhere would leave the class a claim.
        let priority = background_current_thread();
        let parameters = LlamaModelParams::default().with_n_gpu_layers(0);
        let model = LlamaModel::load_from_file(backend, weights, &parameters).map_err(|error| {
            DescribeError::Runtime {
                detail: format!("{} could not be loaded: {error}", weights.display()),
            }
        })?;
        Ok(Self {
            handle: RuntimeHandle {
                profile_id: profile.profile_id().to_owned(),
                profile_revision: profile.revision(),
            },
            model,
            cost: profile.execution().resident_estimate,
            context_tokens: profile.execution().context_tokens,
            weights_path: weights.to_path_buf(),
            priority,
        })
    }

    /// Returns the file this model was loaded from.
    #[must_use]
    pub fn weights_path(&self) -> &Path {
        &self.weights_path
    }

    fn sampler(&self, request: &GenerationRequest) -> Result<LlamaSampler> {
        let grammar =
            LlamaSampler::grammar(&self.model, request.grammar, "root").map_err(|error| {
                DescribeError::Runtime {
                    detail: format!("the description grammar was refused: {error}"),
                }
            })?;
        let sampler = &request.sampler;
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
}

impl InferenceRuntime for LlamaRuntime {
    fn handle(&self) -> RuntimeHandle {
        self.handle.clone()
    }

    fn resident_cost(&self) -> ResidentCost {
        self.cost
    }

    fn priority(&self) -> Option<Applied> {
        Some(self.priority)
    }

    fn generate(&mut self, request: &GenerationRequest) -> Result<Produced> {
        let started = Instant::now();
        let backend = backend()?;
        let threads = i32::try_from(request.cpu_threads).unwrap_or(1).max(1);
        let context_tokens = request.context_tokens.min(self.context_tokens).max(1);
        let parameters = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(context_tokens))
            .with_n_batch(BATCH_TOKENS as u32)
            .with_n_threads(threads)
            .with_n_threads_batch(threads);
        let mut context = self
            .model
            .new_context(backend, parameters)
            .map_err(|error| DescribeError::Runtime {
                detail: format!("a context could not be created: {error}"),
            })?;

        let tokens = self
            .model
            .str_to_token(&request.prompt, AddBos::Always)
            .map_err(|error| DescribeError::Runtime {
                detail: format!("the prompt could not be tokenized: {error}"),
            })?;
        // The prompt is bounded by construction, but a model with a short context is not this
        // host's to fix: refusing is better than silently describing the tail of a prompt.
        if tokens.len() + request.max_output_tokens as usize > context_tokens as usize {
            return Err(DescribeError::Runtime {
                detail: format!(
                    "a prompt of {} tokens and {} of output do not fit in {context_tokens}",
                    tokens.len(),
                    request.max_output_tokens
                ),
            });
        }

        // The prompt is decoded in batches of at most the context's own batch size. A single
        // decode of more tokens than that is not a slow path, it is one the library refuses
        // outright, and a prompt long enough to reach it is an ordinary long prompt.
        let mut batch = LlamaBatch::new(BATCH_TOKENS, 1);
        let last = tokens.len().saturating_sub(1);
        for chunk in tokens.chunks(BATCH_TOKENS) {
            if request.cancellation.is_cancelled() {
                return Ok(Produced::Cancelled);
            }
            if started.elapsed().as_millis() as u64 >= request.deadline_ms {
                return Ok(Produced::DeadlineExceeded);
            }
            batch.clear();
            let offset = position_of(&tokens, chunk);
            for (index, token) in chunk.iter().enumerate() {
                let position = offset + index;
                batch
                    .add(
                        *token,
                        i32::try_from(position).unwrap_or(i32::MAX),
                        &[0],
                        position == last,
                    )
                    .map_err(|error| DescribeError::Runtime {
                        detail: format!("the prompt could not be batched: {error}"),
                    })?;
            }
            context
                .decode(&mut batch)
                .map_err(|error| DescribeError::Runtime {
                    detail: format!("the prompt could not be decoded: {error}"),
                })?;
        }

        let mut sampler = self.sampler(request)?;
        let mut produced: Vec<u8> = Vec::new();
        let mut position = i32::try_from(tokens.len()).unwrap_or(i32::MAX);
        for _ in 0..request.max_output_tokens {
            if request.cancellation.is_cancelled() {
                return Ok(Produced::Cancelled);
            }
            if started.elapsed().as_millis() as u64 >= request.deadline_ms {
                return Ok(Produced::DeadlineExceeded);
            }
            let token = sampler.sample(&context, -1);
            sampler.accept(token);
            if self.model.is_eog_token(token) {
                break;
            }
            // Bytes rather than text, and assembled at the end: one token can be half of a
            // codepoint, and a decoder that answered per token would either drop it or invent a
            // replacement character in the middle of a name.
            let piece = self
                .model
                .token_to_piece_bytes(token, PIECE_BYTES, false, None)
                .map_err(|error| DescribeError::Runtime {
                    detail: format!("a token could not be decoded: {error}"),
                })?;
            produced.extend_from_slice(&piece);
            batch.clear();
            batch
                .add(token, position, &[0], true)
                .map_err(|error| DescribeError::Runtime {
                    detail: format!("a token could not be batched: {error}"),
                })?;
            position = position.saturating_add(1);
            context
                .decode(&mut batch)
                .map_err(|error| DescribeError::Runtime {
                    detail: format!("a token could not be decoded: {error}"),
                })?;
        }
        Ok(Produced::Json(produced))
    }

    fn unload(&mut self) {
        // The model is released when this value is dropped, which is what the caller does after
        // calling this. There is nothing else holding weights: a context lives for one job.
    }
}
