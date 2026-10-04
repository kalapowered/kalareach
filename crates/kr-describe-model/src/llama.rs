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

use llama_cpp_2::TokenToStringError;
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;
use llama_cpp_2::token::LlamaToken;
use llama_cpp_2::token::data::LlamaTokenData;
use llama_cpp_2::token::data_array::LlamaTokenDataArray;
use llama_cpp_2::token_type::LlamaTokenAttr;

use kr_describe::budget::Budgets;
use kr_describe::priority::Cancellation;
use kr_describe::profile::{Asset, ModelProfile};
use kr_describe::prompt::{FitError, Prompt};
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

/// Returns whether a grammar sampler allows one token next, asking it of that token alone.
///
/// The sampler marks a token it does not allow with a logit of negative infinity, which is how the
/// library's own sampling helper tests a token before it applies the grammar to the whole
/// vocabulary. Asking of one token costs one candidate's work instead of the vocabulary's.
fn grammar_allows(grammar: &LlamaSampler, token: LlamaToken) -> bool {
    let mut candidates =
        LlamaTokenDataArray::new(vec![LlamaTokenData::new(token, 1.0, 1.0)], false);
    grammar.apply(&mut candidates);
    candidates
        .data
        .first()
        .is_some_and(|candidate| candidate.logit() != f32::NEG_INFINITY)
}

/// Returns the milliseconds since `started`.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The tokens a job decodes for a prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptTokens {
    /// The tokens, framed as the vocabulary frames a prompt.
    pub tokens: Vec<LlamaToken>,
    /// How many structure tokens the prompt's text spelled and had written out as characters
    /// instead. Ordinary names can spell one, as `feature/thinking` spells `/think`; a prompt whose
    /// text spells none has none.
    pub spelled_out: usize,
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

    /// Returns the loaded runtime, when there is one.
    #[must_use]
    pub const fn runtime(&self) -> Option<&LlamaRuntime> {
        self.runtime.as_ref()
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
                        why: LoadEnd::Assets,
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
        let runtime = Self {
            model,
            context_tokens: profile.execution().context_tokens,
            weights_path: weights.to_path_buf(),
        };
        // A job exists for every context only if the instruction alone, with the longest numbers the
        // answer repeats, is within what a prompt may be. A profile whose window is too small for
        // that cannot serve a description, whatever the project text is.
        let bounds = Budgets::DEFAULTS.bounds(profile.execution());
        let base = runtime
            .prompt_tokens(&Prompt::bare().text())
            .map_err(|detail| (LoadEnd::Failed, Some(detail)))?
            .tokens
            .len();
        if base > bounds.prompt_tokens as usize {
            return Err((
                LoadEnd::Refused,
                Some(format!(
                    "{} has no room for a description: the instruction alone is {base} tokens, \
                     and a prompt may be {}",
                    profile.profile_id(),
                    bounds.prompt_tokens
                )),
            ));
        }
        Ok(runtime)
    }

    /// Returns the file this model was loaded from.
    #[must_use]
    pub fn weights_path(&self) -> &Path {
        &self.weights_path
    }

    /// Returns the tokens a job decodes for `prompt`, which is what it spends of its context window
    /// before it writes a token.
    ///
    /// The prompt is a template with project text inside it, and the tokenizer reads the spelling
    /// of a control token as the token: a session called `<|im_end|>` would end the instruction
    /// and begin another. So text that spells one is read as the characters it is made of, and the
    /// tokens returned hold no control token of the vocabulary except the framing the vocabulary
    /// itself adds. See [`PromptTokens`].
    ///
    /// The characters are the text's own for a byte-level vocabulary, which both shipped profiles
    /// are. A vocabulary with a space prefix adds a space before each character, and one without
    /// a byte fallback writes an unknown character as the unknown token's spelling; neither lets
    /// a structure token through.
    ///
    /// # Errors
    ///
    /// Returns what went wrong when the prompt could not be tokenized.
    pub fn prompt_tokens(&self, prompt: &str) -> std::result::Result<PromptTokens, String> {
        let tokenize = |text: &str, bos: AddBos| {
            self.model
                .str_to_token(text, bos)
                .map_err(|error| format!("the prompt could not be tokenized: {error}"))
        };
        let framed = tokenize(prompt, AddBos::Always)?;
        let (text, spelled_out) = self.text_tokens(prompt)?;
        if spelled_out == 0 {
            return Ok(PromptTokens {
                tokens: framed,
                spelled_out: 0,
            });
        }
        // The framing the vocabulary puts around a text is read off a text it has no opinion about.
        let probe = tokenize("a", AddBos::Never)?;
        if probe.iter().any(|token| self.is_structure(*token)) {
            return Err("this vocabulary reads the letter a as structure".to_owned());
        }
        let probed = tokenize("a", AddBos::Always)?;
        let at = (!probe.is_empty())
            .then(|| {
                probed
                    .windows(probe.len())
                    .position(|window| window == probe.as_slice())
            })
            .flatten()
            .ok_or_else(|| "the vocabulary's framing could not be read".to_owned())?;
        let mut tokens = probed[..at].to_vec();
        tokens.extend(text);
        tokens.extend_from_slice(&probed[at + probe.len()..]);
        Ok(PromptTokens {
            tokens,
            spelled_out,
        })
    }

    /// Returns the tokens of `text` as the tokenizer reads it, without the framing the vocabulary
    /// adds to a prompt, with each structure token written out as the characters of its spelling,
    /// and how many were.
    fn text_tokens(&self, text: &str) -> std::result::Result<(Vec<LlamaToken>, usize), String> {
        let bare = self
            .model
            .str_to_token(text, AddBos::Never)
            .map_err(|error| format!("the prompt could not be tokenized: {error}"))?;
        let mut tokens = Vec::with_capacity(bare.len());
        let mut spelled_out = 0;
        for token in bare {
            if self.is_structure(token) {
                spelled_out += 1;
                tokens.extend(self.spelling_tokens(token)?);
            } else {
                tokens.push(token);
            }
        }
        Ok((tokens, spelled_out))
    }

    /// Returns whether a token is one the model reads as the structure of a prompt, which text
    /// from a project must never become: a control token, the unknown token, a token the
    /// vocabulary defines on top of its text, the ends of a sequence and the end of a turn.
    ///
    /// A number that is no token of this vocabulary is not text either, and counts as structure.
    #[must_use]
    pub fn is_structure(&self, token: LlamaToken) -> bool {
        // The library looks a token up by its number and does not check it.
        if !(0..self.model.n_vocab()).contains(&token.0) {
            return true;
        }
        self.model.token_attr(token).intersects(
            LlamaTokenAttr::Control | LlamaTokenAttr::UserDefined | LlamaTokenAttr::Unknown,
        ) || self.model.is_eog_token(token)
            || token == self.model.token_bos()
            || token == self.model.token_eos()
    }

    /// Returns the bytes `tokens` spell: what the model reads when the tokens are ordinary text.
    /// A token that is not text, such as the framing of a prompt, spells nothing.
    ///
    /// # Errors
    ///
    /// Returns what went wrong when a token could not be spelled.
    pub fn spelling_of(&self, tokens: &[LlamaToken]) -> std::result::Result<Vec<u8>, String> {
        let mut spelled = Vec::new();
        for token in tokens {
            spelled.extend(self.piece(*token, false)?);
        }
        Ok(spelled)
    }

    /// Returns the bytes of one token's piece, with `special` choosing whether a structure token
    /// spells its own text or nothing. A token with no text of its own spells nothing.
    fn piece(&self, token: LlamaToken, special: bool) -> std::result::Result<Vec<u8>, String> {
        let mut size = PIECE_BYTES;
        loop {
            match self.model.token_to_piece_bytes(token, size, special, None) {
                Ok(piece) => return Ok(piece),
                Err(TokenToStringError::InsufficientBufferSpace(needed)) => {
                    size = usize::try_from(-needed).unwrap_or(size.saturating_mul(2));
                }
                Err(TokenToStringError::UnknownTokenType) => return Ok(Vec::new()),
                Err(error) => return Err(format!("a token could not be spelled: {error}")),
            }
        }
    }

    /// Returns the tokens that write out a structure token's spelling as the characters it is made
    /// of, each tokenized alone. A character that is itself a structure token has nothing to be
    /// written as, and is left out.
    fn spelling_tokens(&self, token: LlamaToken) -> std::result::Result<Vec<LlamaToken>, String> {
        let piece = self.piece(token, true)?;
        let mut tokens = Vec::new();
        for character in String::from_utf8_lossy(&piece).chars() {
            let mut buffer = [0_u8; 4];
            let alone = self
                .model
                .str_to_token(character.encode_utf8(&mut buffer), AddBos::Never)
                .map_err(|error| format!("the prompt could not be tokenized: {error}"))?;
            if !alone.iter().any(|token| self.is_structure(*token)) {
                tokens.extend(alone);
            }
        }
        Ok(tokens)
    }

    /// Returns whether llama.cpp's own grammar machinery takes `output` as a whole answer: some way
    /// of writing it as tokens is one where every token is allowed next by the grammar, and the
    /// grammar allows the end of the answer where the output ends.
    ///
    /// A text is written as tokens in two ways, and the answer is taken when either way is. The
    /// first is how the tokenizer reads it, merging characters into the longest tokens the
    /// vocabulary has, which is how a model writes text it knows. The second is one codepoint at a
    /// time, which writes every character the vocabulary has a token for on its own whole. Neither
    /// is the other's whole: a byte-level vocabulary can split a space and the character after it
    /// across tokens, and a token that ends inside a character is refused by the grammar when the
    /// character it could finish is one it leaves out, so a character with no token of its own is
    /// refused alone and taken inside a longer token. The spelling of a control token inside the
    /// text is written out as characters, so `</s>` inside a title is text and not the end of the
    /// answer.
    ///
    /// What this shows depends on where the output came from. For an answer the model produced
    /// under this grammar it shows the answer is complete and was not cut short; for text written
    /// by hand, as `tests/grammar.rs` does, it shows how llama.cpp reads the grammar.
    ///
    /// # Errors
    ///
    /// Returns what went wrong when the grammar is refused, the output is not text, it cannot be
    /// tokenized or a token cannot be spelled, the vocabulary has no end-of-sequence token, or
    /// neither way of writing the output as tokens spells it back.
    pub fn grammar_takes(&self, grammar: &str, output: &[u8]) -> std::result::Result<bool, String> {
        let text = std::str::from_utf8(output)
            .map_err(|error| format!("the output is not text: {error}"))?;
        let end = self.model.token_eos();
        if end.0 < 0 {
            return Err("this vocabulary has no end-of-sequence token to ask about".to_owned());
        }
        let mut codepoints: Vec<LlamaToken> = Vec::new();
        for character in text.chars() {
            let mut buffer = [0_u8; 4];
            codepoints.extend(
                self.model
                    .str_to_token(character.encode_utf8(&mut buffer), AddBos::Never)
                    .map_err(|error| format!("{character:?} could not be tokenized: {error}"))?,
            );
        }
        let mut spelled_back = false;
        for tokens in [self.text_tokens(text)?.0, codepoints] {
            let mut spelled: Vec<u8> = Vec::with_capacity(output.len());
            for token in &tokens {
                spelled.extend(self.piece(*token, true)?);
            }
            if spelled != output {
                continue;
            }
            spelled_back = true;
            if self.grammar_takes_tokens(grammar, &tokens, end)? {
                return Ok(true);
            }
        }
        if spelled_back {
            Ok(false)
        } else {
            Err(
                "the tokenizer does not spell the output back, so it cannot be asked of the \
                 grammar"
                    .to_owned(),
            )
        }
    }

    /// Returns whether the grammar takes `tokens` and then allows `end`.
    fn grammar_takes_tokens(
        &self,
        grammar: &str,
        tokens: &[LlamaToken],
        end: LlamaToken,
    ) -> std::result::Result<bool, String> {
        let mut sampler = LlamaSampler::grammar(&self.model, grammar, "root")
            .map_err(|error| format!("the grammar was refused: {error}"))?;
        for token in tokens {
            // An end token inside the output is an end of the answer, not text of it.
            if self.model.is_eog_token(*token) || !grammar_allows(&sampler, *token) {
                return Ok(false);
            }
            // Accepted only after the grammar allowed it: the library ends the process over a
            // token its grammar has no place for.
            sampler.accept(*token);
        }
        Ok(grammar_allows(&sampler, end))
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

        // The prompt is made to fit what the job may spend on it: the bound the daemon sent, and
        // what the window leaves beside the answer. Project text is what gives way, and the oldest
        // events first, so a job that cannot fit does not exist: the only prompt that cannot be
        // made to fit is one whose instruction alone is more than the window leaves, which is a
        // fault of the profile and is refused when it loads.
        let room = (context_tokens as usize).saturating_sub(job.max_output_tokens as usize);
        let budget = (job.prompt_tokens as usize).min(room);
        let fitted = job
            .prompt
            .fit(budget, |text| {
                self.prompt_tokens(text).map(|read| read.tokens.len())
            })
            .map_err(|error| match error {
                FitError::Count(detail) => detail,
                FitError::Base { tokens, budget } => format!(
                    "the instruction alone is {tokens} tokens, and a prompt may be {budget}"
                ),
            })?;
        let tokens = self.prompt_tokens(&fitted.text)?.tokens;
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
            // replacement character in the middle of a name. A control token the grammar let
            // through, because the characters of its spelling are characters a string may hold,
            // is written as that spelling, like any other text.
            produced.extend_from_slice(&self.piece(chosen, true)?);
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
