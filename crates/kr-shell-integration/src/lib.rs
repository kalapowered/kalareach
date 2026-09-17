//! The contract between a managed shell package and the KalaReach session worker.
//!
//! Section 7 gives the managed root shell a promise no shell integration can keep by guessing:
//! Ctrl-D at an empty root prompt detaches *that* client, a launch button installs a command in the
//! root editor and nowhere else, and neither happens when an application is reading the terminal.
//! Keeping that promise needs the shell's own reader to say what it is doing, at the moments it
//! does them, and it needs the worker to believe only what the reader can prove.
//!
//! This crate is that contract, published once so the four managed packages (Zsh, Bash, Fish and
//! PSReadLine) and the worker can be built and qualified separately against the same rules.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`contract::transport`] | The per-session bridge endpoint, the bootstrap values, the `kr-shell-bridge/1` handshake and what a child shell inherits |
//! | [`contract::events`] | What the bridge reports: reader entry and exit, idle callbacks, the pre-EOF decision, the EOF gesture and accepted commands |
//! | [`contract::requests`] | What the worker asks of the reader thread: the fence exchange, the launch mailbox and non-destructive cancellation |
//! | [`contract::fence`] | The pure state machine over `outside`, `unfenced`, `fenced`, `launch_reserved` and `closing` |
//! | [`contract::qualification`] | Which mechanisms qualify each package, which can never stand in for a delivery fence, the exact detach condition and the phases a session passes through |
//! | [`contract::fixtures`] | The cross-shell scenarios under `fixtures/shell-bridge/`, which every package replays |
//! | [`host`] | The worker's side: the owner-only endpoint, the handshake and the phase gate |
//!
//! # Where the line is
//!
//! [`contract`] performs no input and output. The state machine is pure and takes its clock
//! readings as arguments, so the worker drives it with its own continuous clock and its own
//! sockets, and a test drives it with numbers. Nothing in it opens a socket, spawns a shell or
//! writes to a terminal.
//!
//! [`host`] is where those rules meet the operating system: it binds the session's endpoint, reads
//! the kernel's answer about who connected, and computes the proof over the bootstrap transcript.
//! It still spawns nothing and writes to no terminal, and it holds no second copy of the state
//! machine's rules.
//!
//! # Example
//!
//! A bridge that cannot prove its delivery fence is unqualified, and injecting a private key into
//! the pseudo-terminal is never the fallback:
//!
//! ```
//! use kr_shell_integration::contract::qualification::{
//!     BridgeAbi, FenceProofMechanism, LaunchDelivery, QualificationReason, ShellKind, qualify,
//! };
//!
//! // What each package declares: its own reader's mailbox and pre-EOF mechanism, the reader's own
//! // state as the fence proof, a non-destructive cancellation and the reader's mailbox for a
//! // launch.
//! let qualified = BridgeAbi::qualified(ShellKind::Zsh);
//! assert_eq!(qualify(ShellKind::Zsh, &qualified), Ok(()));
//!
//! let guessing = BridgeAbi {
//!     fence_proof: FenceProofMechanism::PromptHook,
//!     ..qualified
//! };
//! assert_eq!(
//!     qualify(ShellKind::Zsh, &guessing),
//!     Err(QualificationReason::UnprovableFence)
//! );
//!
//! let injecting = BridgeAbi {
//!     launch_delivery: LaunchDelivery::PseudoTerminalKeyInjection,
//!     ..qualified
//! };
//! assert_eq!(
//!     qualify(ShellKind::Zsh, &injecting),
//!     Err(QualificationReason::KeyInjectionForbidden)
//! );
//! ```

pub mod contract;
pub mod host;
