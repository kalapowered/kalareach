//! The KalaReach project service.
//!
//! One service per execution environment owns the repositories the user works in, the working
//! copies selected on them, and every Git invocation this host makes. The command line, the
//! desktop and mobile applications and an automation run are all callers of it.
//!
//! ```text
//! project.init ─┐
//! project.clone ├─▶ a private sibling ─▶ a no-replace publish ─▶ project_repository_id
//! project.adopt ┘        (staging)              (rename)                 │
//!                                                                        ▼
//!                                             workspace.create ─▶ workspace_id
//!                                             (shared_existing or isolated,
//!                                              with the inclusion preview)
//! ```
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`answer`] | The rule applied inside a recorded answer, so a repeat of an action says what the first one did |
//! | [`git`] | The restricted execution profile: the program, the environment, the overrides, the audit |
//! | [`identity`] | Repository identity by stable filesystem identity, and the handles every operation works through |
//! | [`credential`] | Remotes, providers, the approved credential brokers and the transports this host uses |
//! | [`store`] | `projects.sqlite`: repositories, workspaces, operations, retained items, action claims |
//! | [`operation`] | Authorised destinations, the private staging sibling, the publication and its reconciliation |
//! | [`workspace`] | The explicit choice, the inclusion preview, and what a creation copies |
//! | [`service`] | The ten methods, recovery and the sessions a workspace is bound to |
//! | [`error`] | The failures above, each mapped to one stable protocol error code |
//!
//! ## Identity is the object, not the path
//!
//! A repository is identified by the stable filesystem identity of its Git directory and a
//! workspace by that of its own working tree: the device and inode on Unix, the volume serial and
//! file index on Windows. Renaming a checkout keeps both, so a grant still names the same objects
//! afterwards. A different repository at the recorded path, or a linked worktree standing in for
//! the tree a record was made against, has a different identity and is refused. Everything after
//! the first open goes through an [`kr_transfer::AuthorisedDirectory`], which is an open directory
//! descriptor rather than a path.
//!
//! ## What a repository cannot make this host do
//!
//! Section 14 requires brokered Git reads to run under a restricted execution profile, and says
//! that building an argument vector is not that isolation. So every invocation goes through
//! [`git::RestrictedProfile`]: the program and its helper directory are resolved once and passed
//! explicitly, the child's environment is built from nothing, the only configuration file is the
//! repository's own, and the command line carries overrides no configuration file can undo. The
//! repository's configuration is read before anything else runs, every driver it defines is
//! blanked by name, and the keys no override removes are a refusal rather than a warning. The
//! subcommands this service can run are an allowlist that does not include `clean`, `stash`,
//! `reset`, `restore`, `commit`, `push` or any `--force`.
//!
//! ## What this does not promise
//!
//! A Git worktree separates working files and shares the repository's objects, references and
//! configuration under the same operating-system account, so it is not a security sandbox; an
//! independent clone is the stronger choice where that matters. A shared workspace is the user's
//! own working tree, so every session bound to it sees the others' edits. Both limits travel with
//! the inclusion preview rather than being left for a user to discover.
//!
//! # Example
//!
//! ```no_run
//! use kr_project::ProjectService;
//! use kr_protocol::project::{DestinationRequest, ProjectInitParams};
//! use kr_protocol::scalars::Nullable;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let paths: kr_ipc::paths::EnvironmentPaths = unimplemented!();
//! # let actor: kr_protocol::ids::ActorId = unimplemented!();
//! # let action: kr_project::store::Action = unimplemented!();
//! // The host, once:
//! let service = ProjectService::open(&paths)?;
//! service.recover()?;
//!
//! // A repository, created at one name inside a directory the caller chose:
//! let created = service.project_init(
//!     &actor,
//!     &ProjectInitParams {
//!         destination: DestinationRequest {
//!             environment_id: service.environment_id(),
//!             parent_path: "/Users/someone/code".to_owned(),
//!             name: "kalareach".to_owned(),
//!         },
//!         label: "KalaReach".to_owned(),
//!         initial_branch: Nullable(Some("main".to_owned())),
//!     },
//!     Some(&action),
//! )?;
//! assert_eq!(created.project.label, "KalaReach");
//! # Ok(())
//! # }
//! ```

pub mod answer;
pub mod credential;
pub mod error;
pub mod git;
pub mod identity;
pub mod operation;
pub mod service;
pub mod store;
pub mod workspace;

pub use crate::error::{ProjectError, Result};
pub use crate::git::{Cancellation, ConfigurationAudit, GitProgram, RestrictedProfile};
pub use crate::identity::{OpenedRepository, RepositoryIdentity};
pub use crate::service::{ProjectService, Recovery};
