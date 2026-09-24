//! Opt-in command integration, and the command blocks the private hooks report.
//!
//! Two separate things that both live at the boundary between an ordinary command line and the
//! host.
//!
//! **Command integration (§12).** For a gateway-capable agent, an explicitly enabled integration
//! adds the flags that agent needs to an interactive invocation, inside a managed root shell and
//! nowhere else. The command name and the argument vector the person typed are preserved: the flags
//! are added, nothing is removed or reordered, and the resolved profile is what diagnostics show.
//! An absolute-path invocation and a user-disabled integration bypass it, keep their actual
//! execution, and never get a gateway created for them after the fact.
//!
//! **Command blocks (§25).** The shell adapter reports what a command was, when it started and
//! ended, what it exited with and where it ran, from the same private hooks the fence rests on. The
//! attention engine reads typed events; this is the type.

use kr_protocol::root::{CommandBypassReason, RootCommandResolveResult};
use kr_protocol::scalars::Nullable;
use kr_protocol::session::CommandIntegration;
use serde::{Deserialize, Serialize};

/// What the integration resolved one invocation to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// The invocation runs with the agent's flags and a worker-owned backend behind it.
    Integrated {
        /// The command name, exactly as it was typed.
        command: String,
        /// The argument vector that will be run: what was typed, plus the agent's flags.
        arguments: Vec<String>,
        /// The flags this integration added.
        added: Vec<String>,
    },
    /// The invocation runs exactly as it was typed, with no gateway.
    ///
    /// What the session still offers is verified observation and the terminal's own capabilities.
    /// Detecting the agent after it has started never creates a gateway for it.
    Bypassed {
        /// The command name, exactly as it was typed.
        command: String,
        /// The argument vector that will be run: exactly what was typed.
        arguments: Vec<String>,
        /// Why.
        reason: CommandBypassReason,
    },
}

impl Resolution {
    /// Returns the argument vector that will actually run.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        match self {
            Self::Integrated { arguments, .. } | Self::Bypassed { arguments, .. } => arguments,
        }
    }

    /// Returns true when a worker-owned backend is established before the command starts.
    #[must_use]
    pub const fn establishes_backend(&self) -> bool {
        matches!(self, Self::Integrated { .. })
    }

    /// Returns this resolution as the answer the integration's hook reads.
    ///
    /// The backend is the caller's to supply, because establishing one is the worker's work rather
    /// than this decision's. A bypassed invocation is given none, whatever the caller offers: that
    /// is what keeps its execution the one the person asked for.
    #[must_use]
    pub fn to_answer(
        &self,
        backend: Option<kr_protocol::root::CommandBackend>,
    ) -> RootCommandResolveResult {
        match self {
            Self::Integrated {
                arguments, added, ..
            } => RootCommandResolveResult {
                arguments: arguments.clone(),
                added: added.clone(),
                bypass: Nullable::null(),
                backend: Nullable(backend),
            },
            Self::Bypassed {
                arguments, reason, ..
            } => RootCommandResolveResult {
                arguments: arguments.clone(),
                added: Vec::new(),
                bypass: Nullable::some(*reason),
                backend: Nullable::null(),
            },
        }
    }
}

/// What the shell is when an invocation is resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationContext {
    /// Whether this is a managed KalaReach root shell.
    pub managed_root_shell: bool,
    /// Whether the command is being run interactively rather than from a script.
    pub interactive: bool,
}

/// Resolves one invocation against the configured integrations.
///
/// The command name and the argument vector are preserved. What an enabled integration does is add
/// flags where a command line puts an option the caller did not give: after the options, and in
/// front of `--` where the caller wrote one, because everything after that separator is an operand.
#[must_use]
pub fn resolve(
    integrations: &[CommandIntegration],
    context: InvocationContext,
    argv: &[String],
) -> Resolution {
    let Some(command) = argv.first().cloned() else {
        return Resolution::Bypassed {
            command: String::new(),
            arguments: Vec::new(),
            reason: CommandBypassReason::NotIntegrated,
        };
    };
    let bypass = |reason: CommandBypassReason| Resolution::Bypassed {
        command: command.clone(),
        arguments: argv.to_vec(),
        reason,
    };
    if !context.managed_root_shell {
        // Section 12: an integration never intercepts a command in an unmanaged shell.
        return bypass(CommandBypassReason::UnmanagedShell);
    }
    if !context.interactive {
        return bypass(CommandBypassReason::NotInteractive);
    }
    if command.contains('/') {
        // The documented bypass. Somebody who names the binary by path is asking for that binary.
        return bypass(CommandBypassReason::AbsolutePath);
    }
    let Some(integration) = integrations
        .iter()
        .find(|integration| integration.command == command)
    else {
        return bypass(CommandBypassReason::NotIntegrated);
    };
    if !integration.enabled {
        return bypass(CommandBypassReason::Disabled);
    }
    if integration.flags.is_empty() {
        return bypass(CommandBypassReason::NotIntegrated);
    }
    // The options end at the first `--`. What follows is operands, so a word there that looks
    // like a flag is not one the caller gave, and a flag placed there would reach the agent as an
    // operand.
    let options_end = argv
        .iter()
        .skip(1)
        .position(|argument| argument == "--")
        .map_or(argv.len(), |position| position + 1);
    let given = argv.get(1..options_end).unwrap_or_default();
    // Only flags the caller did not already give. Repeating one would change what the agent sees.
    let added: Vec<String> = integration
        .flags
        .iter()
        .filter(|flag| !given.contains(flag))
        .cloned()
        .collect();
    let mut arguments = argv.to_vec();
    arguments.splice(options_end..options_end, added.iter().cloned());
    Resolution::Integrated {
        command,
        arguments,
        added,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn integrations() -> Vec<CommandIntegration> {
        vec![
            CommandIntegration {
                command: "codex".to_owned(),
                flags: vec!["--kr-gateway".to_owned()],
                enabled: true,
            },
            CommandIntegration {
                command: "opencode".to_owned(),
                flags: vec!["--kr-gateway".to_owned()],
                enabled: false,
            },
        ]
    }

    const MANAGED: InvocationContext = InvocationContext {
        managed_root_shell: true,
        interactive: true,
    };

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn an_enabled_integration_keeps_the_name_and_the_vector_and_adds_the_flags() {
        let resolved = resolve(&integrations(), MANAGED, &argv(&["codex", "--model", "o"]));
        let Resolution::Integrated {
            command,
            arguments,
            added,
        } = resolved
        else {
            panic!("an enabled integration adds its flags");
        };
        assert_eq!(command, "codex");
        assert_eq!(arguments, argv(&["codex", "--model", "o", "--kr-gateway"]));
        assert_eq!(added, argv(&["--kr-gateway"]));
        assert!(
            Resolution::Integrated {
                command,
                arguments,
                added
            }
            .establishes_backend()
        );
    }

    #[test]
    fn both_documented_bypasses_keep_the_actual_execution() {
        let cases = [
            (
                argv(&["/usr/local/bin/codex"]),
                MANAGED,
                CommandBypassReason::AbsolutePath,
            ),
            (argv(&["opencode"]), MANAGED, CommandBypassReason::Disabled),
            (
                argv(&["codex"]),
                InvocationContext {
                    managed_root_shell: false,
                    interactive: true,
                },
                CommandBypassReason::UnmanagedShell,
            ),
            (
                argv(&["codex"]),
                InvocationContext {
                    managed_root_shell: true,
                    interactive: false,
                },
                CommandBypassReason::NotInteractive,
            ),
            (argv(&["make"]), MANAGED, CommandBypassReason::NotIntegrated),
        ];
        for (invocation, context, expected) in cases {
            let resolved = resolve(&integrations(), context, &invocation);
            let Resolution::Bypassed {
                arguments, reason, ..
            } = &resolved
            else {
                panic!("{invocation:?} is bypassed");
            };
            assert_eq!(*reason, expected, "{invocation:?}");
            assert_eq!(
                arguments, &invocation,
                "{invocation:?} runs as it was typed"
            );
            assert!(!resolved.establishes_backend());
        }
    }

    #[test]
    fn a_flag_the_caller_already_gave_is_not_repeated() {
        let resolved = resolve(&integrations(), MANAGED, &argv(&["codex", "--kr-gateway"]));
        assert_eq!(resolved.arguments(), argv(&["codex", "--kr-gateway"]));
        assert!(resolved.establishes_backend());
    }

    /// After `--` everything is an operand, so a flag added at the end would reach the agent as
    /// one, and a word there that looks like a flag is not a flag the caller gave.
    #[test]
    fn kr_req_12_07_flags_are_added_before_the_end_of_options() {
        let resolved = resolve(&integrations(), MANAGED, &argv(&["codex", "--", "prompt"]));
        assert_eq!(
            resolved.arguments(),
            argv(&["codex", "--kr-gateway", "--", "prompt"]),
            "the flag goes in front of the separator, and the operand stays where it was"
        );
        let Resolution::Integrated { added, .. } = &resolved else {
            panic!("an enabled integration adds its flags");
        };
        assert_eq!(added, &argv(&["--kr-gateway"]));

        let resolved = resolve(
            &integrations(),
            MANAGED,
            &argv(&["codex", "--model", "o", "--", "--kr-gateway", "--"]),
        );
        assert_eq!(
            resolved.arguments(),
            argv(&[
                "codex",
                "--model",
                "o",
                "--kr-gateway",
                "--",
                "--kr-gateway",
                "--"
            ]),
            "an operand spelled like the flag is not the flag, and only the first separator counts"
        );

        let resolved = resolve(
            &integrations(),
            MANAGED,
            &argv(&["codex", "--kr-gateway", "--", "prompt"]),
        );
        assert_eq!(
            resolved.arguments(),
            argv(&["codex", "--kr-gateway", "--", "prompt"]),
            "a flag given before the separator is given"
        );
        let Resolution::Integrated { added, .. } = &resolved else {
            panic!("an enabled integration adds its flags");
        };
        assert!(added.is_empty());
    }

    #[test]
    fn a_command_block_reports_status_duration_and_directory() {
        use kr_protocol::ids::SessionId;
        use kr_protocol::root::{CwdRevision, PromptGeneration, RootCommandBlockParams};
        use kr_protocol::scalars::{DurationMs, TimestampMs, U64, Uuid};

        let block = RootCommandBlockParams {
            session_id: SessionId::new(Uuid::from_bytes([7; 16])),
            prompt_generation: PromptGeneration::new(12),
            command: "cargo test".to_owned(),
            started_at_ms: TimestampMs::new(1_700_000_000_000),
            duration_ms: Nullable::some(DurationMs::new(4_200)),
            exit_status: Nullable::some(U64::new(101)),
            cwd: "/Users/someone/project".to_owned(),
            cwd_revision: CwdRevision::new(3),
        };
        assert!(block.finished());
        assert!(block.completed_nonzero());
        let running = RootCommandBlockParams {
            duration_ms: Nullable::null(),
            exit_status: Nullable::null(),
            ..block.clone()
        };
        assert!(!running.finished());
        assert!(!running.completed_nonzero());
        let succeeded = RootCommandBlockParams {
            exit_status: Nullable::some(U64::ZERO),
            ..block
        };
        assert!(succeeded.finished());
        assert!(!succeeded.completed_nonzero());
    }
}
