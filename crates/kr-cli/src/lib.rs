//! The KalaReach command line.
//!
//! `kr` is a local client. It reaches the control daemon for the things the daemon owns —
//! creating a session, listing them, diagnostics — and it reaches a worker **directly** for the
//! things a session owns. That second path is deliberate: attaching reads a published descriptor
//! and challenges the worker itself, so it keeps working while the control daemon is restarting.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`cli`] | The command surface: the commands, their short forms and the standard options |
//! | [`account`] | The managed-service account token this host presents, and where it is kept |
//! | [`bind`] | Which session, if any, this process is inside, as the sessions' workers answer |
//! | [`pair`] | `kr pair`: invitations, approving the device that answers one, and the first owner |
//! | [`resolve`] | Finding a session by number or identifier, and reaching its worker |
//! | [`contact`] | The contact tools an agent reaches its person through, over the Model Context Protocol |
//! | [`create`] | The palette a new session starts with |
//! | [`question`] | Reading and answering an agent's questions from the terminal |
//! | [`skill`] | Installing the contact skill and its tool configuration for an agent |
//! | [`bridge`] | `kr bridge`: the process-bridge helper and this host's enrolled environments |
//! | [`attach`] | Attaching a terminal, forwarding bytes, and the restoration guard |
//! | [`session`] | Driving one attachment's input, output and connection in a single loop |
//! | [`render`] | Drawing a projected session into this terminal, at canonical cell positions |
//! | [`terminal`] | Raw mode, terminal size and the saved state the guard holds |
//! | [`platform`] | The one place this crate calls the operating system directly |
//! | [`shell`] | `kr shell`: the guarded startup entries and what the integration resolved to |
//! | [`report`] | Text for people and the `--json` shapes |
//! | [`error`] | The failures above, each with its own exit code |

pub mod account;
pub mod attach;
pub mod bind;
pub mod bridge;
pub mod cli;
pub mod contact;
pub mod create;
pub mod doctor;
pub mod error;
pub mod pair;
pub mod platform;
pub mod question;
pub mod render;
pub mod report;
pub mod resolve;
pub mod session;
pub mod shell;
pub mod skill;
pub mod terminal;
pub mod windows;

pub use crate::error::{CliError, Result};

/// The release this build reports.
pub const RELEASE: &str = env!("CARGO_PKG_VERSION");

/// Returns the build identifier this client presents.
///
/// # Panics
///
/// Panics when the release string is not a well-formed identifier, which would be a build fault
/// rather than a runtime condition.
#[must_use]
pub fn build_id() -> kr_protocol::ids::BuildId {
    kr_protocol::ids::BuildId::new(format!("kr/{RELEASE}"))
        .expect("the build identifier is well formed")
}
