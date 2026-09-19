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
//! | [`agent_tools`] | Installing the contact skill for an agent, and undoing exactly what it wrote |
//! | [`archive`] | Closed and crashed sessions: their history, final receipts and retained references, served with no worker |
//! | [`authority`] | The dispatch lease, the revocation barrier and the generation both are bound to |
//! | [`desktop`] | Which profile a session gets, what logout does to it, and the host power setting |
//! | [`registry`] | Reservations, display-number allocation, worker records and closure tombstones |
//! | [`singleton`] | The per-environment lock and the persistent generation |
//! | [`supervision`] | Starting a worker through the platform's own service manager |
//! | [`directory`] | The verified directory of workers, rebuilt by challenge after a restart |
//! | [`grants`] | The grant store, the delegation rule, the revocation cascade and the policy intersection |
//! | [`service`] | Admission, the rendezvous and the local endpoint |
//! | [`sharing`] | Roles compiled to grants, single-use invitations and transfer of control |
//! | [`transfer`] | The environment's transfer service, its attachment-chunk endpoint and its sweep |
//! | [`project`] | The environment's project service: repositories, workspaces and the restricted Git profile |
//! | [`error`] | The failures above, each mapped to one stable protocol error code |

pub mod agent_tools;
pub mod archive;
pub mod authority;
pub mod desktop;
pub mod directory;
pub mod error;
pub mod grants;
pub mod project;
pub mod registry;
pub mod service;
pub mod sharing;
pub mod singleton;
pub mod supervision;
pub mod transfer;

pub use crate::error::{ControllerError, Result};
