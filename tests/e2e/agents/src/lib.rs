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
//! | `a_device_prompts_the_agent_and_adds_an_image_...` | 1 | a device's prompt and image reach the agent a managed shell started, and the local terminal shows the same execution |
//! | `slash_commands_interrupts_queued_prompts_and_steering_...` | 2a | each of the agent's own terminal controls works from a device, on its own |
//! | `an_agent_on_its_terminal_route_is_advertised_no_typed_capability_...` | 2b | a manual launch is detected, offered only observation and the terminal, and every typed action for it is refused |
//! | `under_a_binding_a_supported_action_is_permitted_...` | 2c | under the binding detection made, a supported action is admitted and an unsupported one refused |
//! | `a_local_and_a_remote_answer_raced_to_one_approval_...` | 3 | a local and a remote answer to one approval resolve it once |
//! | `a_disconnection_after_the_agent_took_a_prompt_...` | 4 | a disconnection after the agent took a prompt leaves one reply and no duplicate work |
//! | `a_control_daemon_crash_leaves_the_agent_...` | 5a | killing the control daemon leaves the agent's execution and its local terminal running, and a restarted daemon serves the session again |
//! | `a_running_agent_keeps_its_build_through_an_upgrade_...` | 6a | a live process keeps the build image it started with when the installed agent is upgraded, and the newer build starts on the terminal route |
//! | `a_second_process_on_the_same_saved_conversation_...` | 7 | a second process on one saved conversation is another execution, not merged |
//! | `forged_titles_transcripts_identifiers_and_hook_input_...` | 8a | forged titles, transcript paths, session identifiers and hook input leave the host's state unchanged |
//! | `a_path_typed_at_the_agent_is_terminal_input_...` | 14.03a | a path typed at the agent's prompt is terminal input that reaches its composer |
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
//! must find nothing left. What the host shows about the agent is checked against what section 12
//! requires of a launch the command integration did not make ([`detect`]).
//!
//! # What an agent may do here
//!
//! A part that needs no login signs in nowhere and starts no turn. Its home and working directory
//! are inside the run's own directory, and the home holds a keychain of the run's own as its default
//! one (`keychain::RunKeychain`), so a secret the agent writes stays there and nobody is asked to
//! create a keychain. Every proxy variable names a loopback port nothing listens on, and the
//! updater and telemetry switches its build entry names are set.
//!
//! Parts 1, 2a, 3, 4 and 7 need the person's vendor login, and run only for a build whose list entry
//! names one the person approved (`build::Account`): with the run's own home, which either searches
//! the person's login keychain, borrowed and never created or deleted here, or is given the one
//! variable the login is; or with the person's own home, where the agent keeps its login in files,
//! whose changes a part lists and whose test conversations it removes (`account`). Every turn is
//! charged to the login's budget before it is submitted, and a key a part carried is searched for
//! in the run's files, by path only, before the run's directory is removed, whatever became of the
//! part.
//!
//! In every part the shell searches only the run's link to the build, the run's links to the build's
//! runtimes and the system's directories, and every executable image a process beneath its session
//! runs is recorded with its digest and must lie in one of those places or the run's own directory
//! (`provenance::Provenance`): a part whose session ran anything else did not test the pinned
//! build, and says so.
//!
//! # Inputs
//!
//! [`BUILD_VARIABLE`] names a JSON file describing the build (`build::Build`),
//! [`GENERATION_VARIABLE`] the signed catalogue generation its package is installed from, and
//! [`RESULT_VARIABLE`] the file each test appends its outcome to, one JSON line
//! (`outcome::Outcome`). Without them a test says `skipping:` and returns, so an ordinary run of
//! this workspace stays offline and starts no agent; [`REQUIRE_VARIABLE`] set to `1` turns that
//! into a failure. `scripts/e2e-agents.sh` in the plugin repository sets all four, and for the parts
//! with a login the ledger ([`account::TURNS_VARIABLE`]), the key-scan file
//! ([`account::KEY_SCAN_VARIABLE`]) and, for a login that is a variable, the descriptor its value
//! arrives on ([`account::KEY_DESCRIPTOR_VARIABLE`]); it runs this with a cleared environment.

#[cfg(unix)]
pub mod account;
#[cfg(unix)]
pub mod build;
#[cfg(unix)]
pub mod conversation;
#[cfg(unix)]
pub mod detect;
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
#[cfg(unix)]
pub mod stub;

/// The variable naming the JSON file that describes the build under test.
pub const BUILD_VARIABLE: &str = "KR_AGENTS_BUILD";

/// The variable naming the signed catalogue generation the agent's package is installed from.
pub const GENERATION_VARIABLE: &str = "KR_AGENTS_GENERATION";

/// The variable naming the file each test appends its outcome to.
pub const RESULT_VARIABLE: &str = "KR_AGENTS_RESULT";

/// The variable that turns missing inputs into a failure rather than a skip.
pub const REQUIRE_VARIABLE: &str = "KR_REQUIRE_AGENTS";
