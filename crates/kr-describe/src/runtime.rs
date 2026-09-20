//! The inference seam, and the deterministic runtime the tests drive.
//!
//! Everything above this module works in terms of [`InferenceRuntime`], which is a prompt, a
//! grammar, a bound and a cancellation token. Two things implement it: [`llama::LlamaRuntime`] in a
//! build with the runtime feature, and [`StubRuntime`] here.
//!
//! [`llama::LlamaRuntime`]: crate::llama::LlamaRuntime
//!
//! # Why the tests never download weights
//!
//! A test that downloads two gigabytes of model is a test that does not run on a machine with no
//! network, does not run twice the same way, and takes long enough that nobody runs it. So
//! `cargo test -p kr-describe` drives [`StubRuntime`], which produces a deterministic answer in
//! microseconds.
//!
//! What keeps that honest is that the stub is **behind the same identity checks**. It is built from
//! a [`ModelProfile`] and reports that profile's identifier and revision, so every test of the
//! stale-revision rule, the late-generation rule, the unload-before-map rule and the resident-cost
//! accounting runs through exactly the path the real runtime runs through. What the stub does not
//! exercise is the quality of the text and the real cost of producing it, and those are measured by
//! `scripts/bench-descriptions.sh` against the real weights rather than claimed here.

use crate::budget::ResidentCost;
use crate::error::Result;
use crate::priority::{Applied, Cancellation};
use crate::profile::{ModelProfile, ProfileRevision, SamplerSettings};

/// One request to a runtime.
#[derive(Clone, Debug)]
pub struct GenerationRequest {
    /// The prompt, whose data section holds every piece of project text.
    pub prompt: String,
    /// The grammar the sampler is constrained by.
    pub grammar: &'static str,
    /// The context window, in tokens.
    pub context_tokens: u32,
    /// The output bound, in tokens.
    pub max_output_tokens: u32,
    /// How many CPU threads the runtime may use.
    pub cpu_threads: u32,
    /// The sampler values from the profile.
    pub sampler: SamplerSettings,
    /// The deadline, measured from dequeue.
    pub deadline_ms: u64,
    /// The token that cancels this job.
    pub cancellation: Cancellation,
}

/// What a runtime produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Produced {
    /// Bytes to validate. They are not trusted: [`crate::output::validate`] decides.
    Json(Vec<u8>),
    /// The job was cancelled before it finished. Nothing is published.
    Cancelled,
    /// The job passed its deadline. Nothing is published.
    DeadlineExceeded,
}

/// What loading a model produced.
#[derive(Debug)]
pub enum LoadOutcome {
    /// The model was loaded and is ready for inference.
    Loaded(Box<dyn InferenceRuntime>),
    /// Loading was cancelled before completion.
    Cancelled,
    /// Loading exceeded the execution deadline.
    DeadlineExceeded,
}

/// What a runtime says it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeHandle {
    /// The profile that is loaded.
    pub profile_id: String,
    /// That profile's revision.
    pub profile_revision: ProfileRevision,
}

/// A loaded model that can answer a request.
pub trait InferenceRuntime: std::fmt::Debug {
    /// Returns which profile is loaded.
    fn handle(&self) -> RuntimeHandle;

    /// Returns what this runtime is costing, itemised.
    fn resident_cost(&self) -> ResidentCost;

    /// Returns the background scheduling class this runtime's own thread is running under.
    ///
    /// A runtime that never asked for one answers [`None`], which is what a deterministic runtime
    /// with no thread of its own does. It is reported rather than assumed, because section 22 warns
    /// that low priority is not proof of terminal latency by itself and a report that named a
    /// mechanism the host did not apply would be worse than no report.
    fn priority(&self) -> Option<Applied> {
        None
    }

    /// Produces one answer.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DescribeError::Runtime`] when the runtime itself failed. A cancelled or
    /// timed-out job is not a failure and comes back as [`Produced`].
    fn generate(&mut self, request: &GenerationRequest) -> Result<Produced>;

    /// Releases the model. It is called before another profile is mapped and on an idle unload.
    fn unload(&mut self);
}

/// What the deterministic runtime should do, so a test can drive a rejection path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Behaviour {
    /// Produce a well-formed description from the prompt.
    #[default]
    WellFormed,
    /// Produce bytes that are not the object the grammar describes.
    Malformed,
    /// Produce an object with a field this product does not know.
    UnknownField,
    /// Produce a title with a control character in it.
    ControlCharacter,
    /// Produce a title longer than section 22's bound.
    OverlongTitle,
    /// Produce activity text longer than section 22's bound.
    OverlongActivity,
    /// Produce a description claiming a revision that is not the prompt's.
    WrongRevision(u64),
    /// Take this long, so a test can drive the deadline.
    Slow {
        /// How long the job says it took.
        duration_ms: u64,
    },
    /// Fail, as a runtime whose model file has gone would.
    Fails {
        /// What it says.
        detail: String,
    },
    /// Take this long to load, so a test can drive the load deadline.
    SlowLoad {
        /// How long the load says it took.
        duration_ms: u64,
    },
    /// Fail during load, as a missing or corrupt weights file would.
    FailsLoad {
        /// What it says.
        detail: String,
    },
    /// Cancel the job during load.
    CancelDuringLoad,
}

/// A behaviour two owners share: whatever sets it, and the runtime that reads it.
///
/// A runtime is built by a factory the service owns, so a caller that wants to change what the
/// next answer looks like has no handle on the runtime itself. This is that handle, and it is the
/// only reason the behaviour is not a plain field.
#[derive(Clone, Debug, Default)]
pub struct SharedBehaviour(std::sync::Arc<std::sync::Mutex<Behaviour>>);

impl SharedBehaviour {
    /// Builds a shared behaviour that produces a well-formed description.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets what the next answer looks like.
    pub fn set(&self, behaviour: Behaviour) {
        if let Ok(mut held) = self.0.lock() {
            *held = behaviour;
        }
    }

    /// Returns what the next answer looks like.
    #[must_use]
    pub fn get(&self) -> Behaviour {
        self.0
            .lock()
            .map(|held| held.clone())
            .unwrap_or(Behaviour::WellFormed)
    }
}

/// A runtime that produces a deterministic answer with no model at all.
#[derive(Clone, Debug)]
pub struct StubRuntime {
    handle: RuntimeHandle,
    cost: ResidentCost,
    behaviour: SharedBehaviour,
    calls: u64,
    unloads: u64,
    last_threads: u32,
    last_sampler: Option<SamplerSettings>,
}

impl StubRuntime {
    /// Builds a runtime that reports a profile's own identity and cost.
    #[must_use]
    pub fn of(profile: &ModelProfile) -> Self {
        Self {
            handle: RuntimeHandle {
                profile_id: profile.profile_id().to_owned(),
                profile_revision: profile.revision(),
            },
            cost: profile.execution().resident_estimate,
            behaviour: SharedBehaviour::new(),
            calls: 0,
            unloads: 0,
            last_threads: 0,
            last_sampler: None,
        }
    }

    /// Builds a runtime whose behaviour somebody else holds.
    #[must_use]
    pub fn sharing(profile: &ModelProfile, behaviour: SharedBehaviour) -> Self {
        let mut runtime = Self::of(profile);
        runtime.behaviour = behaviour;
        runtime
    }

    /// Sets what this runtime does next.
    #[must_use]
    pub fn producing(self, behaviour: Behaviour) -> Self {
        self.behaviour.set(behaviour);
        self
    }

    /// Sets what this runtime does next, in place.
    pub fn produce(&mut self, behaviour: Behaviour) {
        self.behaviour.set(behaviour);
    }

    /// Returns how many requests this runtime has answered.
    #[must_use]
    pub const fn calls(&self) -> u64 {
        self.calls
    }

    /// Returns how many times this runtime has been unloaded.
    #[must_use]
    pub const fn unloads(&self) -> u64 {
        self.unloads
    }

    /// Returns the thread count the last request asked for.
    #[must_use]
    pub const fn last_threads(&self) -> u32 {
        self.last_threads
    }

    /// Returns the sampler values the last request carried.
    #[must_use]
    pub const fn last_sampler(&self) -> Option<SamplerSettings> {
        self.last_sampler
    }
}

/// Reads a field out of the prompt's data section.
fn data_field<'a>(prompt: &'a str, label: &str) -> Option<&'a str> {
    prompt.lines().find_map(|line| {
        let rest = line.strip_prefix(label)?.strip_prefix(": <<")?;
        rest.strip_suffix(">>")
    })
}

/// Reads the revision the prompt states.
fn prompt_revision(prompt: &str) -> u64 {
    prompt
        .lines()
        .find_map(|line| line.strip_prefix("context_revision: "))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

/// Reads the cursor interval the prompt states.
fn prompt_cursor(prompt: &str) -> (u64, u64) {
    let Some(line) = prompt
        .lines()
        .find_map(|line| line.strip_prefix("source_cursor: "))
    else {
        return (0, 0);
    };
    let number = |label: &str| -> u64 {
        line.split_once(label)
            .and_then(|(_, rest)| {
                rest.trim_start()
                    .trim_start_matches(':')
                    .trim_start()
                    .split(|character: char| !character.is_ascii_digit())
                    .find(|piece| !piece.is_empty())
                    .and_then(|digits| digits.parse().ok())
            })
            .unwrap_or(0)
    };
    (number("\"from\""), number("\"to\""))
}

impl InferenceRuntime for StubRuntime {
    fn handle(&self) -> RuntimeHandle {
        self.handle.clone()
    }

    fn resident_cost(&self) -> ResidentCost {
        self.cost
    }

    fn generate(&mut self, request: &GenerationRequest) -> Result<Produced> {
        self.calls = self.calls.saturating_add(1);
        self.last_threads = request.cpu_threads;
        self.last_sampler = Some(request.sampler);
        if request.cancellation.is_cancelled() {
            return Ok(Produced::Cancelled);
        }
        let behaviour = self.behaviour.get();
        if let Behaviour::Fails { detail } = &behaviour {
            return Err(crate::DescribeError::Runtime {
                detail: detail.clone(),
            });
        }
        if let Behaviour::Slow { duration_ms } = behaviour
            && duration_ms > request.deadline_ms
        {
            return Ok(Produced::DeadlineExceeded);
        }
        let revision = match behaviour {
            Behaviour::WrongRevision(claimed) => claimed,
            _ => prompt_revision(&request.prompt),
        };
        let (from, to) = prompt_cursor(&request.prompt);
        // The subject is taken from the data section, which is the whole of what a real model has
        // to work with. A stub that invented a title from nothing would pass a test that a real
        // runtime with an empty context would fail.
        let subject = data_field(&request.prompt, "repository")
            .or_else(|| data_field(&request.prompt, "directory"))
            .or_else(|| data_field(&request.prompt, "application"))
            .unwrap_or("Session");
        let doing = data_field(&request.prompt, "intent")
            .or_else(|| data_field(&request.prompt, "thread"))
            .unwrap_or("Working in this session");
        let (title, activity) = match &behaviour {
            Behaviour::ControlCharacter => (format!("{subject}\u{7}"), doing.to_owned()),
            Behaviour::OverlongTitle => ("t".repeat(65), doing.to_owned()),
            Behaviour::OverlongActivity => (subject.to_owned(), "a".repeat(161)),
            _ => (
                subject.chars().take(64).collect(),
                doing.chars().take(160).collect(),
            ),
        };
        let bytes = match behaviour {
            Behaviour::Malformed => b"not an object at all".to_vec(),
            Behaviour::UnknownField => format!(
                "{{\"title\":{title},\"activity_text\":{activity},\
                 \"source_cursor\":{{\"from\":{from},\"to\":{to}}},\
                 \"context_revision\":{revision},\"confidence\":0.9}}",
                title = escape(&title),
                activity = escape(&activity),
            )
            .into_bytes(),
            _ => format!(
                "{{\"title\":{title},\"activity_text\":{activity},\
                 \"source_cursor\":{{\"from\":{from},\"to\":{to}}},\
                 \"context_revision\":{revision}}}",
                title = escape(&title),
                activity = escape(&activity),
            )
            .into_bytes(),
        };
        Ok(Produced::Json(bytes))
    }

    fn unload(&mut self) {
        self.unloads = self.unloads.saturating_add(1);
    }
}

/// Renders a string as a JSON string literal.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if control.is_control() => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}
