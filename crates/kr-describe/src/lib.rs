//! Local session names and status descriptions.
//!
//! Section 22 asks for a small feature with a large number of ways to get it wrong: a shared
//! CPU-only model that names sessions usefully, on an 8 GiB laptop, without touching the shell's
//! input path, without claiming anything it cannot verify, and without becoming the reason a
//! terminal feels slow. This crate is that feature.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`time`] | The clock readings this crate is given. Nothing here reads a clock |
//! | [`metadata`] | Deterministic titles and verified status, which need no model at all |
//! | [`environment`] | Execution environments, where a model may be mapped, and the one mapping each has |
//! | [`profile`] | The signed model profile, its assets, the catalogue and the download policy |
//! | [`context`] | The context revision, what advances it, and the bounded input a job is built from |
//! | [`output`] | The grammar, the validated result and every reason one is rejected |
//! | [`budget`] | Section 22's defaults, and what a resident model actually costs |
//! | [`resource`] | The memory reserve, power and pressure, and `resource_paused` |
//! | [`priority`] | Background CPU and IO priority, through the mechanism each platform qualifies |
//! | [`queue`] | One latest job per session, aging, fairness and the cadence |
//! | [`metrics`] | Queue-wait and execution latency, published separately, beside whole-product figures |
//! | [`error`] | What this crate refuses |
//!
//! # Four properties the design rests on
//!
//! **A host with no model is a host with every title.** [`metadata::deterministic_title`] is a
//! pure function of facts the host already holds, so a mobile device, a WSL distribution with no
//! data-access choice, a machine whose weights are missing and a session in the middle of being
//! described all show a name and a verified status. Everything else in this crate is an
//! improvement on that floor, never a precondition for it.
//!
//! **Nothing here is on the input path.** The only door into the queue is
//! [`context::ContextTracker::observe`], which takes the five meaningful signals section 22 names
//! and has no variant for a keystroke, a terminal query or a resize. It is a proof by the path
//! rather than by a measurement: there is no call from the shell's hot path to reach, so no timing
//! result is needed to show that it is not taken.
//!
//! **Generated text is labelled and powerless.** A validated result carries
//! [`metadata::LabelSource::Generated`] wherever it is shown, and there is no function anywhere in
//! this crate that takes generated text and returns a permission, a workflow transition, a review
//! completion or a [`metadata::VerifiedStatus`]. Section 22's rule is expressed as the absence of
//! the capability rather than as a check.
//!
//! **A result is published only under the generation and revision it was produced under.** Privacy
//! mode's generation and the model profile's revision are both carried on the job and both checked
//! at publication, so an answer that arrives after privacy mode was enabled or after the model was
//! remapped is refused rather than shown.
//!
//! # Example
//!
//! ```
//! use kr_describe::metadata::{LifecycleFacts, RepositoryFacts, SessionFacts, VerifiedStatus};
//! use kr_describe::metadata::SessionLabel;
//!
//! let facts = SessionFacts {
//!     repository: Some(RepositoryFacts {
//!         name: "kalareach".to_owned(),
//!         branch: Some("main".to_owned()),
//!     }),
//!     ..SessionFacts::default()
//! };
//! let status = VerifiedStatus::of(&LifecycleFacts {
//!     started: true,
//!     reachable: true,
//!     ..LifecycleFacts::default()
//! });
//! let label = SessionLabel::from_metadata(&facts, status);
//! assert_eq!(label.title.as_str(), "kalareach (main)");
//! assert_eq!(label.status, VerifiedStatus::Running);
//! ```

pub mod budget;
pub mod context;
pub mod environment;
pub mod error;
pub mod metadata;
pub mod metrics;
pub mod output;
pub mod priority;
pub mod profile;
pub mod queue;
pub mod resource;
pub mod time;

pub use crate::error::{DescribeError, Result};
pub use crate::metadata::{SessionFacts, SessionLabel, Title, VerifiedStatus};
pub use crate::profile::ModelProfile;
pub use crate::profile::catalogue::{Catalogue, Selection};
pub use crate::time::Reading;
