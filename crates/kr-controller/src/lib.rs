//! The KalaReach control daemon.
//!
//! One daemon per environment. It owns the registry, admits session creation, asks the platform's
//! service manager to start workers, keeps a verified directory of the workers that exist, and
//! serves the local endpoint the `kr` command line and paired devices reach.
//!
//! What it does **not** own is a running shell. A worker's lifetime belongs to the service manager,
//! not to this process, so restarting or crashing here never closes a session. When a replacement
//! daemon starts it advances its generation, rebuilds its directory from the registry and the
//! published descriptors, and proves each worker with a fresh challenge.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`registry`] | Reservations, display-number allocation, worker records and closure tombstones |
//! | [`singleton`] | The per-environment lock and the persistent generation |
//! | [`supervision`] | Starting a worker through the platform's own service manager |
//! | [`directory`] | The verified directory of workers, rebuilt by challenge after a restart |
//! | [`service`] | Admission, the rendezvous and the local endpoint |
//! | [`error`] | The failures above, each mapped to one stable protocol error code |

pub mod directory;
pub mod error;
pub mod registry;
pub mod service;
pub mod singleton;
pub mod supervision;

pub use crate::error::{ControllerError, Result};
