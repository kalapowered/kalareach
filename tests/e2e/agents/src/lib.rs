//! Qualification cases for the bundled agent connectors, run against a real host.
//!
//! Section 12 asks for eight cases per bundled agent, run against the build its connector table is
//! qualified for, and recorded per operating system and architecture. Several cases hold more than
//! one property, and a host can show some of them before it can show the rest, so each test here
//! is one part of one case, and a part a host cannot show is not a test here at all: the record
//! names it as not run, with its reason.
//!
//! | Test | Part | What it shows |
//! | --- | --- | --- |
//! | `unbound_terminal_route` | 2b | an agent on its terminal route is advertised no typed capability, and every typed action for it is refused |
//! | `daemon_crash` | 5a | killing the control daemon leaves the agent's execution and its local terminal running, and a restarted daemon serves the session again |
//! | `upgrade_while_running` | 6a | a live process keeps the build image it started with when the installed agent is upgraded, and the newer build starts on the terminal route |
//! | `forgeries` | 8a | forged titles, transcript paths, session identifiers and hook input leave the host's state unchanged |
//! | `typed_path` | 14.03a | a path typed at the agent's prompt is terminal input that reaches its composer |
//!
//! # The host and the agent
//!
//! Everything a person runs is real: the `kr-controller` daemon, the `kr-worker` it launches for
//! each session, `kr` on terminals of its own and the `kr-hook` forwarder, all copied from this
//! build to the internal disk; the owner device is this repository's native client over loopback
//! iroh, paired as the host's first owner; the agent's connector package is installed from a signed
//! catalogue generation on that device's confirmation; and the agent is a vendor build, started by
//! typing its command at the prompt of a managed shell, as a person starts it. The harness this
//! reuses is the cross-boundary checkpoint's ([`kr_e2e_m1b`]), and so is its rule for processes:
//! each is recorded by its start identity, ended only through that record, and the closing check
//! must find nothing left.
//!
//! # What an agent may do here
//!
//! It signs in nowhere and starts no turn. Its home and working directory are inside the run's own
//! directory, and the home holds a keychain of the run's own as its default one
//! ([`keychain::RunKeychain`]), so a secret the agent writes stays there and nobody is asked to
//! create a keychain. Every proxy variable names a loopback port nothing listens on, and the
//! updater and telemetry switches its build entry names are set. Its shell searches only the
//! run's link to the build, the run's links to the build's runtimes and the system's directories,
//! and every executable image a process beneath its session runs is recorded with its digest and
//! must lie in one of those places or the run's own directory ([`provenance::Provenance`]): a part
//! whose session ran anything else did not test the pinned build, and says so.
//!
//! # Inputs
//!
//! [`BUILD_VARIABLE`] names a JSON file describing the build ([`build::Build`]),
//! [`GENERATION_VARIABLE`] the signed catalogue generation its package is installed from, and
//! [`RESULT_VARIABLE`] the file each test appends its outcome to, one JSON line
//! ([`outcome::Outcome`]). Without them a test says `skipping:` and returns, so an ordinary run of
//! this workspace stays offline and starts no agent; [`REQUIRE_VARIABLE`] set to `1` turns that
//! into a failure. `scripts/e2e-agents.sh` in the plugin repository sets all four.

#[cfg(unix)]
pub mod build;
#[cfg(unix)]
pub mod keychain;
#[cfg(unix)]
pub mod observe;
#[cfg(unix)]
pub mod outcome;
#[cfg(unix)]
pub mod provenance;
#[cfg(unix)]
pub mod stage;

/// The variable naming the JSON file that describes the build under test.
pub const BUILD_VARIABLE: &str = "KR_AGENTS_BUILD";

/// The variable naming the signed catalogue generation the agent's package is installed from.
pub const GENERATION_VARIABLE: &str = "KR_AGENTS_GENERATION";

/// The variable naming the file each test appends its outcome to.
pub const RESULT_VARIABLE: &str = "KR_AGENTS_RESULT";

/// The variable that turns missing inputs into a failure rather than a skip.
pub const REQUIRE_VARIABLE: &str = "KR_REQUIRE_AGENTS";
