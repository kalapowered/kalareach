//! The KalaReach transfer service.
//!
//! One reusable service moves bytes into and out of an execution environment, and every client
//! uses it: the command line, the desktop and mobile applications, an adapter that needs a staged
//! image, and anything else that speaks the protocol. There is no graphical half; the graphical
//! clients are callers like any other.
//!
//! ```text
//! upload.begin ─▶ upload.chunk ─▶ upload.finish ─▶ attachment handle
//!        │              │               │                   │
//!        │              │               │                   ├─▶ agent.draft.add_attachment
//!        │              │               │                   │        (a separate action)
//!        │              │               │                   └─▶ download.begin ─▶ download.chunk
//!        └──────────────┴── upload.status ──── resume, or resolve a lost reply
//! ```
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`authority`] | Opened directory and object handles, the no-escape policy, identity checks |
//! | [`staging`] | The environment's private staging area and the names payloads are stored under |
//! | [`store`] | `transfers.sqlite`: uploads, the per-chunk journal, snapshots, drafts, grants |
//! | [`service`] | Uploads, attachment handles, drafts, read grants, recovery and expiry sweeps |
//! | [`download`] | Immutable sources, bounded snapshots, and the client's verified publish |
//! | [`preview`] | The bounded image decoder |
//! | [`chunks`] | The attachment-chunk stream, which is how a 1 MiB chunk travels |
//! | [`clock`] | The clock expiries are measured on |
//! | [`error`] | The failures above, each mapped to one stable protocol error code |
//!
//! ## What a handle is, and is not
//!
//! `upload.finish` returns an [`kr_protocol::transfer::AttachmentHandle`]: an opaque,
//! environment-bound identity with the verified size and digest of the bytes behind it. It is never
//! a client-supplied absolute host path, and it is never interchangeable across environments, so a
//! Windows path and a WSL path stay separate rather than aliasing. An adapter whose insertion
//! method needs the agent to open the file asks for an
//! [`kr_protocol::transfer::AttachmentReadGrant`] over that one file; nothing widens a sandbox and
//! nothing puts an upload inside a repository.
//!
//! ## What is separate from what
//!
//! Transfer, storage, insertion and submission are four actions with four records. A completed
//! upload survives a failed insertion, a draft survives a lost connection, and only upstream
//! evidence makes an attachment accepted by an agent. Section 12 requires that separation; here it
//! is four methods and four rows rather than a convention.
//!
//! ## What this does not promise
//!
//! Handle-based resolution removes path-resolution races. It does not make a file private from
//! another process running as the same operating-system user: such a process can open and write an
//! authorised file, and nothing in this crate prevents it. Where immutability is the requirement,
//! as it is for a download, the host stages its own copy and verifies it rather than trusting an
//! open handle.

pub mod authority;
pub mod chunks;
pub mod clock;
pub mod download;
pub mod error;
pub mod preview;
pub mod service;
pub mod staging;
pub mod store;

pub use crate::authority::{
    AuthorisedDirectory, AuthorisedFile, Escape, ObjectIdentity, ObjectPolicy, RelativeName,
};
pub use crate::clock::{Clock, ManualClock, SystemClock};
pub use crate::download::{DownloadWriter, publish_transfer};
pub use crate::error::{Result, TransferError};
pub use crate::service::{
    InsertionOutcome, Recovery, RetainEverything, RetainedOutcome, SessionRetention, Sweep,
    TransferService,
};
pub use crate::staging::{StagingArea, StorageName};
pub use crate::store::{Limits, Store};
