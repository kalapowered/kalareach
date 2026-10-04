//! Opt-in command integration, and the command blocks the private hooks report.
//!
//! Two separate things that both live at the boundary between an ordinary command line and the
//! host.
//!
//! **Command integration (§12).** For a gateway-capable agent, an explicitly enabled integration
//! adds the flags that agent needs to an interactive invocation, inside a managed root shell and
//! nowhere else. The command name and the argument vector the person typed are preserved: the flags
//! are added as the one run the integration declares, nothing is removed or reordered, and the
//! resolved profile is what diagnostics show. An absolute-path invocation, a user-disabled
//! integration and an invocation that already uses the integration's flags another way bypass it,
//! keep their actual execution, and never get a gateway created for them after the fact.
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
        /// The command name of the integration that took it. It is the name the typed one is looked
        /// up by (see [`lookup_name`]), which is the typed name itself where this platform looks
        /// commands up by the exact name; the argument vector keeps what was typed.
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

/// Returns the name a typed command is looked up by.
///
/// A command is the file of that name in a directory of the search path, and a platform decides what
/// names the same file. On Unix that is the exact name. On Windows the file system and the shell
/// ignore the case of ASCII letters and run a program with or without its `.exe` or `.com`, so
/// `Gemini`, `gemini.exe` and `GEMINI.COM` are one command, and the name looked up is the typed one
/// in lower case without that suffix. What is typed is what runs: only the lookup changes.
#[must_use]
pub fn lookup_name(typed: &str) -> std::borrow::Cow<'_, str> {
    if !cfg!(windows) {
        return std::borrow::Cow::Borrowed(typed);
    }
    let folded = typed.to_ascii_lowercase();
    let name = folded
        .strip_suffix(".exe")
        .or_else(|| folded.strip_suffix(".com"))
        .unwrap_or(&folded);
    std::borrow::Cow::Owned(name.to_owned())
}

/// Whether a typed command names a path: a directory separator anywhere in it. Somebody who names a
/// program by path, relative or absolute, is asking for that program and not for what the name
/// stands for. A backslash is a separator on Windows and an ordinary character in a name elsewhere.
fn names_a_path(command: &str) -> bool {
    command.contains('/') || (cfg!(windows) && command.contains('\\'))
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
/// its flags, as the one run it declares, where a command line puts an option the caller did not
/// give: after the options, and in front of `--` where the caller wrote one, because everything
/// after that separator is an operand. An integration that declares no flag adds nothing and still
/// integrates the invocation, whose backend is what it is for.
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
    if names_a_path(&command) {
        // The documented bypass. Somebody who names the binary by path is asking for that binary.
        return bypass(CommandBypassReason::AbsolutePath);
    }
    let looked_up = lookup_name(&command);
    let Some(integration) = integrations
        .iter()
        .find(|integration| lookup_name(&integration.command) == looked_up)
    else {
        return bypass(CommandBypassReason::NotIntegrated);
    };
    if !integration.enabled {
        return bypass(CommandBypassReason::Disabled);
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
    // The flags are one run: a value is never added without its option or an option without its
    // value, and nothing the caller typed is changed. Where the caller gave the run, repeating it
    // would change what the agent sees; where the caller used its flags any other way, adding the
    // run would too.
    let added = match typed_use(given, &integration.flags) {
        TypedUse::Unused => integration.flags.clone(),
        TypedUse::WholeRun => Vec::new(),
        TypedUse::Conflict => return bypass(CommandBypassReason::FlagsConflict),
    };
    let mut arguments = argv.to_vec();
    arguments.splice(options_end..options_end, added.iter().cloned());
    Resolution::Integrated {
        command: integration.command.clone(),
        arguments,
        added,
    }
}

/// How the options a caller typed use an integration's run of flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TypedUse {
    /// Nothing typed uses any of its flags: the run is added whole.
    Unused,
    /// The run is empty, or typed whole once, in its order, with nothing else typed using its
    /// flags: nothing is added.
    WholeRun,
    /// Anything else, which the run cannot be added to without changing what the caller asked for.
    Conflict,
}

/// Returns how `given`, the options a caller typed, use `run`.
fn typed_use(given: &[String], run: &[String]) -> TypedUse {
    if run.is_empty() {
        return TypedUse::WholeRun;
    }
    let uses = |element: &String| run.iter().any(|flag| uses_flag(element, flag));
    let whole: Vec<usize> = (0..given.len())
        .filter(|&at| given.get(at..at + run.len()) == Some(run))
        .collect();
    match whole.as_slice() {
        [] if !given.iter().any(uses) => TypedUse::Unused,
        [at] if !given
            .iter()
            .enumerate()
            .any(|(index, element)| !(*at..*at + run.len()).contains(&index) && uses(element)) =>
        {
            TypedUse::WholeRun
        }
        _ => TypedUse::Conflict,
    }
}

/// Whether one typed element uses one of a run's flags: it is that element, or, for a long option,
/// that option with a value attached after `=`.
fn uses_flag(element: &str, flag: &str) -> bool {
    element == flag
        || (flag.starts_with("--")
            && element
                .strip_prefix(flag)
                .is_some_and(|rest| rest.starts_with('=')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(name: &str) -> kr_protocol::ids::PluginId {
        kr_protocol::ids::PluginId::new(format!("kalareach/{name}")).expect("a plugin identifier")
    }

    fn integrations() -> Vec<CommandIntegration> {
        vec![
            CommandIntegration {
                plugin_id: plugin("codex"),
                command: "codex".to_owned(),
                flags: vec!["--kr-gateway".to_owned()],
                enabled: true,
            },
            CommandIntegration {
                plugin_id: plugin("opencode"),
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

    /// The lookup name is what the platform treats as one command: nothing changes where names are
    /// exact, and on Windows the case of ASCII letters and a trailing `.exe` or `.com` are not part
    /// of it. A name that is not an executable's (`.cmd`, `.ps1`, another suffix, a second suffix)
    /// keeps everything but its case.
    #[test]
    fn a_typed_command_is_looked_up_by_the_name_its_platform_gives_the_same_file() {
        for (typed, windows, elsewhere) in [
            ("codex", "codex", "codex"),
            ("Codex", "codex", "Codex"),
            ("codex.exe", "codex", "codex.exe"),
            ("CODEX.EXE", "codex", "CODEX.EXE"),
            ("Codex.Com", "codex", "Codex.Com"),
            ("codex.cmd", "codex.cmd", "codex.cmd"),
            ("codex.ps1", "codex.ps1", "codex.ps1"),
            ("codex.exe.exe", "codex.exe", "codex.exe.exe"),
            ("\u{c9}cole.exe", "\u{c9}cole", "\u{c9}cole.exe"),
        ] {
            assert_eq!(
                lookup_name(typed),
                if cfg!(windows) { windows } else { elsewhere },
                "{typed}"
            );
        }
    }

    /// KR-REQ-12.07: where names are exact an invocation spelt another way is not integrated, and
    /// where they are not it is, with the vector it was typed in. A path, whatever its spelling, is
    /// the bypass: a backslash is a separator only on Windows.
    #[test]
    fn the_name_an_invocation_is_typed_with_decides_by_what_its_platform_calls_the_same_command() {
        let spelt = ["Codex", "codex.exe", "CODEX.COM"];
        for typed in spelt {
            let resolved = resolve(&integrations(), MANAGED, &argv(&[typed, "--model", "o"]));
            if cfg!(windows) {
                let Resolution::Integrated {
                    command, arguments, ..
                } = resolved
                else {
                    panic!("{typed} is the integrated command here");
                };
                assert_eq!(command, "codex", "the integration's own name");
                assert_eq!(
                    arguments,
                    argv(&[typed, "--model", "o", "--kr-gateway"]),
                    "{typed}: what was typed is what runs"
                );
            } else {
                assert!(
                    matches!(
                        resolved,
                        Resolution::Bypassed {
                            reason: CommandBypassReason::NotIntegrated,
                            ..
                        }
                    ),
                    "{typed} is another command here: {resolved:?}"
                );
            }
        }
        for path in ["./codex", "/usr/bin/codex", "bin/codex"] {
            assert!(
                matches!(
                    resolve(&integrations(), MANAGED, &argv(&[path])),
                    Resolution::Bypassed {
                        reason: CommandBypassReason::AbsolutePath,
                        ..
                    }
                ),
                "{path}"
            );
        }
        let backslashed = resolve(&integrations(), MANAGED, &argv(&["bin\\codex.exe"]));
        let reason = if cfg!(windows) {
            CommandBypassReason::AbsolutePath
        } else {
            CommandBypassReason::NotIntegrated
        };
        assert!(
            matches!(backslashed, Resolution::Bypassed { reason: found, .. } if found == reason),
            "{backslashed:?}"
        );
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

    /// The released integrations' shapes: Claude Code's flag and the plugin it names, Gemini CLI's
    /// no flag at all, and Qoder CLI's `--settings` with its inline value.
    fn released() -> Vec<CommandIntegration> {
        let integration = |command: &str, flags: &[&str]| CommandIntegration {
            plugin_id: plugin(command),
            command: command.to_owned(),
            flags: argv(flags),
            enabled: true,
        };
        vec![
            integration(
                "claude",
                &[
                    "--dangerously-load-development-channels",
                    "plugin:kalareach-channels@skills-dir",
                ],
            ),
            integration("gemini", &[]),
            integration("qodercli", &["--settings", r#"{"hooks":{}}"#]),
        ]
    }

    /// KR-REQ-12.20: an integration that adds no flag still integrates the invocation, which runs
    /// exactly as it was typed behind its backend.
    #[test]
    fn an_integration_that_adds_no_flag_integrates_the_invocation() {
        let typed = argv(&["gemini", "--model", "m"]);
        assert_eq!(
            resolve(&released(), MANAGED, &typed),
            Resolution::Integrated {
                command: "gemini".to_owned(),
                arguments: typed,
                added: Vec::new(),
            }
        );
    }

    /// KR-REQ-12.07: the flags are one run, added whole where the options end.
    #[test]
    fn the_flags_are_added_as_one_run_where_the_options_end() {
        let resolved = resolve(
            &released(),
            MANAGED,
            &argv(&["claude", "--resume", "r", "--", "prompt"]),
        );
        assert_eq!(
            resolved,
            Resolution::Integrated {
                command: "claude".to_owned(),
                arguments: argv(&[
                    "claude",
                    "--resume",
                    "r",
                    "--dangerously-load-development-channels",
                    "plugin:kalareach-channels@skills-dir",
                    "--",
                    "prompt"
                ]),
                added: argv(&[
                    "--dangerously-load-development-channels",
                    "plugin:kalareach-channels@skills-dir"
                ]),
            }
        );
    }

    /// The whole run typed in its order before the options end is given: nothing is added, and
    /// the invocation is integrated as it was typed.
    #[test]
    fn a_run_typed_whole_is_given_and_nothing_is_added() {
        for typed in [
            argv(&[
                "claude",
                "--dangerously-load-development-channels",
                "plugin:kalareach-channels@skills-dir",
                "--resume",
            ]),
            argv(&["qodercli", "-p", "x", "--settings", r#"{"hooks":{}}"#]),
        ] {
            let resolved = resolve(&released(), MANAGED, &typed);
            let Resolution::Integrated {
                arguments, added, ..
            } = &resolved
            else {
                panic!("{typed:?} is integrated");
            };
            assert_eq!(arguments, &typed, "{typed:?} runs as it was typed");
            assert!(added.is_empty(), "{typed:?}: nothing is added");
        }
    }

    /// KR-REQ-12.07: an invocation that already uses the run's flags any other way runs exactly as
    /// it was typed, named as a conflict: part of the run, the run out of its order, an option with
    /// its value attached, or the run and a second use of one of its options.
    #[test]
    fn a_conflicting_use_of_the_run_runs_as_typed() {
        for typed in [
            argv(&[
                "claude",
                "--dangerously-load-development-channels",
                "plugin:another@skills-dir",
            ]),
            argv(&[
                "claude",
                "plugin:kalareach-channels@skills-dir",
                "--dangerously-load-development-channels",
            ]),
            argv(&["qodercli", "--settings=/home/someone/mine.json"]),
            argv(&[
                "qodercli",
                "--settings",
                r#"{"hooks":{}}"#,
                "--settings",
                "mine.json",
            ]),
        ] {
            let resolved = resolve(&released(), MANAGED, &typed);
            let Resolution::Bypassed {
                arguments, reason, ..
            } = &resolved
            else {
                panic!("{typed:?} conflicts with the run");
            };
            assert_eq!(*reason, CommandBypassReason::FlagsConflict, "{typed:?}");
            assert_eq!(arguments, &typed, "{typed:?} runs as it was typed");
            assert!(!resolved.establishes_backend());
        }
    }

    /// Words after `--` are operands: they neither give the run nor conflict with it.
    #[test]
    fn operands_neither_give_the_run_nor_conflict_with_it() {
        let resolved = resolve(
            &released(),
            MANAGED,
            &argv(&["qodercli", "--", "--settings", "mine.json"]),
        );
        assert_eq!(
            resolved.arguments(),
            argv(&[
                "qodercli",
                "--settings",
                r#"{"hooks":{}}"#,
                "--",
                "--settings",
                "mine.json"
            ])
        );
        assert!(resolved.establishes_backend());
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
