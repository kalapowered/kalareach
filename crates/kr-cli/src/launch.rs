//! `kr launch`: the commands that the launch buttons offer beside the installed agents.
//!
//! A saved command is a label, a program and arguments, kept by the host in the environment's
//! state directory. Each command here is a client of one method the daemon serves, and the daemon
//! decides every rule: what a label, a program and an argument may hold, how many commands the
//! host keeps, and whether a write was made from the list the person saw. `kr` holds no check of
//! its own and prints the host's refusal as the host wrote it.
//!
//! The three commands run outside every session. A saved command is typed into a terminal when
//! its button is pressed later, and what the list shows goes into a session's output, which its
//! worker keeps and an agent in it can read. The guard stops an accident; it is not isolation from
//! other code running as this account.
//!
//! A write reads the list and sends its change with the revision it read. It is never sent again
//! by `kr`: a revision that moved is told, with the list as it now stands, and the person runs the
//! command again.

use std::path::Path;

use kr_client::retry::UserAction;
use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::error::ErrorCode;
use kr_protocol::launch_commands::{
    NamedLaunch, ShellLaunchCommandsListParams, ShellLaunchCommandsListResult,
    ShellLaunchCommandsRemoveParams, ShellLaunchCommandsRemoveResult,
    ShellLaunchCommandsSaveParams, ShellLaunchCommandsSaveResult,
};
use kr_protocol::method::Method;
use kr_protocol::organisation::{OrganisationListParams, OrganisationListResult};

use crate::cli::{
    EnvironmentSelector, LaunchAddArguments, LaunchCommand, LaunchListArguments,
    LaunchRemoveArguments,
};
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request};
use crate::report::{self, Completion};
use crate::stdout_line;

/// Why `kr launch list` stays outside a session, ending the guard's refusal.
const WHY_LIST: &str = "a saved command may hold a secret, and an agent in a session can read what \
                        the session shows, so launch commands are listed only outside a session";

/// Why `kr launch add` and `kr launch remove` stay outside a session.
const WHY_CHANGE: &str = "a saved launch command is typed into a terminal when its button is \
                          pressed later, so launch commands are added and removed only outside a \
                          session";

/// What a write says when the list moved after it was read.
const CHANGED: &str =
    "The saved launch commands changed before this request could apply. Run the command again.";

/// What a write says when the host could not confirm it.
const UNCONFIRMED: &str =
    "The host could not confirm the change. Run kr launch list to check the current list.";

/// What a write says when the host answered that it could not write the change.
const NOT_SAVED: &str =
    "The host could not save the change. Run kr launch list to check the current list.";

/// What every command says of a host that does not serve the methods.
const NOT_SERVED: &str = "This host does not serve launch commands.";

/// Runs one `kr launch` command and prints its result.
///
/// # Errors
///
/// Returns the guard's refusal inside a session, a usage mistake, the host's refusal, or a
/// transport failure. A write the host did not apply, or could not confirm, is reported in the
/// form the caller asked for and returned as [`Completion::Reported`].
pub async fn run(paths: &HostPaths, command: LaunchCommand, json: bool) -> Result<Completion> {
    match command {
        LaunchCommand::List(arguments) => list(paths, &arguments, json).await,
        LaunchCommand::Add(arguments) => add(paths, arguments, json).await,
        LaunchCommand::Remove(arguments) => remove(paths, &arguments, json).await,
    }
}

/// `kr launch list`.
async fn list(
    paths: &HostPaths,
    arguments: &LaunchListArguments,
    json: bool,
) -> Result<Completion> {
    crate::bind::require_outside(&crate::build_id(), WHY_LIST).await?;
    let (mut daemon, file) = open(paths, &arguments.selector).await?;
    let listed = read_list(&mut daemon, &file).await?;
    if json {
        output::document(&list_document(&listed));
    } else {
        print_list(&listed.commands);
    }
    Ok(Completion::Done)
}

/// `kr launch add`.
async fn add(paths: &HostPaths, arguments: LaunchAddArguments, json: bool) -> Result<Completion> {
    crate::bind::require_outside(&crate::build_id(), WHY_CHANGE).await?;
    let mut words = arguments.command.into_iter();
    let program = words
        .next()
        .ok_or_else(|| CliError::Usage(Shown::said("a program is needed after --")))?;
    let command = NamedLaunch {
        label: arguments.label,
        program,
        arguments: words.collect(),
    };
    let (mut daemon, file) = open(paths, &arguments.selector).await?;
    let read = read_list(&mut daemon, &file).await?;
    let saved: ShellLaunchCommandsSaveResult = daemon
        .mutate_unconfirmable(
            Method::ShellLaunchCommandsSave,
            &ShellLaunchCommandsSaveParams {
                expected_revision: read.revision,
                command: command.clone(),
            },
        )
        .await
        .map_err(|error| after_a_write(error, &file))?;
    let label = command.label.trim();
    let holds_it = holds(
        &saved.commands,
        &NamedLaunch {
            label: label.to_owned(),
            ..command
        },
    );
    if saved.applied || holds_it {
        if json {
            output::document(&save_document(&saved));
        } else if !saved.applied || !saved.changed {
            output::line(&stdout_line!(
                "The launch command \"{}\" is already saved as written.",
                asked(label)
            ));
        } else if saved.replaced {
            output::line(&stdout_line!(
                "Replaced the launch command \"{}\".",
                asked(label)
            ));
        } else {
            output::line(&stdout_line!(
                "Saved the launch command \"{}\".",
                asked(label)
            ));
        }
        return Ok(Completion::Done);
    }
    conflict(&saved.commands, save_document(&saved), json)
}

/// `kr launch remove`.
async fn remove(
    paths: &HostPaths,
    arguments: &LaunchRemoveArguments,
    json: bool,
) -> Result<Completion> {
    crate::bind::require_outside(&crate::build_id(), WHY_CHANGE).await?;
    let (mut daemon, file) = open(paths, &arguments.selector).await?;
    let read = read_list(&mut daemon, &file).await?;
    let removed: ShellLaunchCommandsRemoveResult = daemon
        .mutate_unconfirmable(
            Method::ShellLaunchCommandsRemove,
            &ShellLaunchCommandsRemoveParams {
                expected_revision: read.revision,
                label: arguments.label.clone(),
            },
        )
        .await
        .map_err(|error| after_a_write(error, &file))?;
    let label = arguments.label.trim();
    let absent = !removed
        .commands
        .iter()
        .any(|held| held.label.to_lowercase() == label.to_lowercase());
    if removed.applied || absent {
        if json {
            output::document(&remove_document(&removed));
        } else if removed.applied && removed.removed {
            output::line(&stdout_line!(
                "Removed the launch command \"{}\".",
                asked(label)
            ));
        } else {
            output::line(&stdout_line!(
                "No launch command is named \"{}\".",
                asked(label)
            ));
        }
        return Ok(Completion::Done);
    }
    conflict(&removed.commands, remove_document(&removed), json)
}

/// Reaches the environment's daemon, and names the file its commands are kept in.
async fn open(
    paths: &HostPaths,
    selector: &EnvironmentSelector,
) -> Result<(Daemon, std::path::PathBuf)> {
    let environment = crate::resolve::select(paths, selector.environment.as_deref())?;
    let file = environment
        .paths
        .state_dir()
        .join(kr_controller::launch_commands::FILE_NAME);
    Ok((Daemon::open(paths, selector).await?, file))
}

/// Reads the list the host holds. A host that lists no such method refuses it as it refuses any
/// method it does not list; the refusal is told from one that has a reason of its own by asking
/// for what the same right reads, and a host that answers that does not serve the commands.
async fn read_list(daemon: &mut Daemon, file: &Path) -> Result<ShellLaunchCommandsListResult> {
    match daemon
        .read(
            Method::ShellLaunchCommandsList,
            &ShellLaunchCommandsListParams {},
        )
        .await
    {
        Ok(listed) => Ok(listed),
        Err(CliError::Refused(refused)) if refused.code == ErrorCode::PermissionDenied => {
            let probe: Result<OrganisationListResult> = daemon
                .read(Method::OrganisationList, &OrganisationListParams::default())
                .await;
            Err(match probe {
                Ok(_) => CliError::refused_in_its_own_words(
                    ErrorCode::UnsupportedCapability,
                    Shown::said(NOT_SERVED),
                ),
                Err(_) => in_the_hosts_words(CliError::Refused(refused), file),
            })
        }
        Err(error) => Err(in_the_hosts_words(error, file)),
    }
}

/// A refusal of a write as `kr launch` tells it. A write is sent only after the list was read, so a
/// `STORAGE_UNAVAILABLE` that answers it is the host failing to write the change, or the file
/// failing between the two requests; an unreadable file stops the read before a write is sent.
/// Neither is told as an unreadable file, so the sentence says nothing of the file and advises no
/// removal. Every other refusal is told as [`in_the_hosts_words`] tells it.
fn after_a_write(error: CliError, file: &Path) -> CliError {
    match error {
        CliError::Refused(refused) if refused.code == ErrorCode::StorageUnavailable => {
            failed(ErrorCode::StorageUnavailable, NOT_SAVED)
        }
        other => in_the_hosts_words(other, file),
    }
}

/// A refusal as `kr launch` tells it: the host's own words alone, except for a file the host
/// could not read, which names the file and the way through, and an outcome the host could not
/// confirm, which says what to check.
fn in_the_hosts_words(error: CliError, file: &Path) -> CliError {
    match error {
        CliError::Refused(refused) => match refused.code {
            ErrorCode::StorageUnavailable => CliError::refused_in_its_own_words(
                ErrorCode::StorageUnavailable,
                shown!(
                    "The saved launch commands could not be read: {}. Move that file away, then \
                     add the commands again.",
                    Shown::host_path(file)
                ),
            ),
            ErrorCode::OutcomeUnknown => failed(ErrorCode::OutcomeUnknown, UNCONFIRMED),
            _ => CliError::ServiceRefused {
                error: refused,
                action: UserAction::Nothing,
            },
        },
        other => other,
    }
}

/// A refusal in this program's own words, with the code it is reported under.
fn failed(code: ErrorCode, words: &'static str) -> CliError {
    CliError::refused_in_its_own_words(code, Shown::said(words))
}

/// A write the host did not apply because the list moved: the list as it now stands, then the
/// failure. In `--json` the answer as written carries the failure's fields. Nothing is applied and
/// nothing is sent again.
fn conflict(commands: &[NamedLaunch], answer: Document, json: bool) -> Result<Completion> {
    let error = failed(ErrorCode::ResyncRequired, CHANGED);
    if json {
        output::document(&report::with_failure(answer, &error));
    } else {
        print_list(commands);
        report::failed(&error);
    }
    Ok(Completion::Reported(error))
}

/// Whether the list holds `command` as written.
fn holds(commands: &[NamedLaunch], command: &NamedLaunch) -> bool {
    commands.contains(command)
}

fn asked(text: &str) -> Asked {
    Asked::text(Request::LaunchCommands, text)
}

/// The list, a line for each command, or the way to add one.
fn print_list(commands: &[NamedLaunch]) {
    if commands.is_empty() {
        output::say(&Shown::said(
            "No launch commands are saved. Add one with: kr launch add <label> -- <program> \
             [arguments...]",
        ));
    }
    for command in commands {
        output::line(&line(command));
    }
}

/// One command as a line for a person: its label, then the program and each argument in double
/// quotes with `\` and `"` escaped.
fn line(command: &NamedLaunch) -> Line {
    let words = std::iter::once(&command.program)
        .chain(&command.arguments)
        .map(|word| quoted(word))
        .collect::<Vec<_>>()
        .join(" ");
    stdout_line!("{}: {}", asked(&command.label), asked(&words))
}

/// A word in double quotes, `\` and `"` escaped.
fn quoted(word: &str) -> String {
    let mut quoted = String::with_capacity(word.len() + 2);
    quoted.push('"');
    for character in word.chars() {
        if matches!(character, '\\' | '"') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

/// `NamedLaunch`, in the shape the protocol answers it.
fn command_document(command: &NamedLaunch) -> Document {
    Document::new()
        .with("label", asked(&command.label))
        .with("program", asked(&command.program))
        .with(
            "arguments",
            command
                .arguments
                .iter()
                .map(|argument| asked(argument))
                .collect::<Vec<_>>(),
        )
}

fn commands_document(commands: &[NamedLaunch]) -> Vec<Document> {
    commands.iter().map(command_document).collect()
}

/// `ShellLaunchCommandsListResult`, in the shape the protocol answers it.
fn list_document(value: &ShellLaunchCommandsListResult) -> Document {
    Document::new()
        .with("commands", commands_document(&value.commands))
        .with("ok", true)
        .with("revision", value.revision)
}

/// `ShellLaunchCommandsSaveResult`, in the shape the protocol answers it.
fn save_document(value: &ShellLaunchCommandsSaveResult) -> Document {
    Document::new()
        .with("applied", value.applied)
        .with("changed", value.changed)
        .with("commands", commands_document(&value.commands))
        .with("ok", true)
        .with("replaced", value.replaced)
        .with("revision", value.revision)
}

/// `ShellLaunchCommandsRemoveResult`, in the shape the protocol answers it.
fn remove_document(value: &ShellLaunchCommandsRemoveResult) -> Document {
    Document::new()
        .with("applied", value.applied)
        .with("commands", commands_document(&value.commands))
        .with("ok", true)
        .with("removed", value.removed)
        .with("revision", value.revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::U64;

    /// KR-REQ-13.11: a word is shown in double quotes with a backslash and a double quote escaped,
    /// so a line says each word of a command exactly and an empty argument is visible.
    #[test]
    fn a_word_is_quoted_with_its_backslashes_and_quotes_escaped() {
        assert_eq!(quoted("claude"), "\"claude\"");
        assert_eq!(quoted(""), "\"\"");
        assert_eq!(quoted("two words"), "\"two words\"");
        assert_eq!(
            quoted("C:\\tools\\agent.exe"),
            "\"C:\\\\tools\\\\agent.exe\""
        );
        assert_eq!(quoted("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    /// KR-REQ-13.11: an outcome the host could not confirm is told in the one sentence that says
    /// what to check, with its own code and exit 8, and a file the host could not read names the
    /// file and the way through; any other refusal is the host's own words alone, with no
    /// instruction added to them.
    #[test]
    fn an_unconfirmed_outcome_and_an_unreadable_file_are_told_and_every_other_refusal_stands() {
        let file = Path::new("/state/launch-commands.json");
        let told = |code: ErrorCode| {
            in_the_hosts_words(
                CliError::Refused(kr_client::error::refusal(
                    code,
                    Shown::said("the host's own words"),
                )),
                file,
            )
        };

        let unconfirmed = told(ErrorCode::OutcomeUnknown);
        assert_eq!(unconfirmed.code(), ErrorCode::OutcomeUnknown);
        assert_eq!(unconfirmed.exit_code(), 8);
        assert_eq!(unconfirmed.to_string(), UNCONFIRMED);

        let unreadable = told(ErrorCode::StorageUnavailable);
        assert_eq!(unreadable.exit_code(), 8);
        assert!(
            unreadable
                .to_string()
                .starts_with("The saved launch commands could not be read: ")
                && unreadable
                    .to_string()
                    .ends_with(". Move that file away, then add the commands again."),
            "{unreadable}"
        );

        let rule = told(ErrorCode::InvalidArgument);
        assert_eq!(rule.exit_code(), 8);
        assert!(
            matches!(
                rule,
                CliError::ServiceRefused {
                    action: UserAction::Nothing,
                    ..
                }
            ),
            "the host's words stand alone"
        );
    }

    /// KR-REQ-13.11: a revision above 2^53 is written as the protocol writes a `U64`, a decimal
    /// string, in the list and in both answers to a change, so that a reader that holds a JSON
    /// number as a double does not round it.
    #[test]
    fn a_revision_above_2_pow_53_is_written_as_a_decimal_string_in_every_document() {
        let revision = U64::new(9_007_199_254_740_993);
        let listed = list_document(&ShellLaunchCommandsListResult {
            revision,
            commands: Vec::new(),
        });
        let saved = save_document(&ShellLaunchCommandsSaveResult {
            applied: true,
            changed: true,
            replaced: false,
            revision,
            commands: Vec::new(),
        });
        let removed = remove_document(&ShellLaunchCommandsRemoveResult {
            applied: true,
            removed: true,
            revision,
            commands: Vec::new(),
        });
        for document in [listed, saved, removed] {
            assert_eq!(
                document.json()["revision"],
                serde_json::Value::String("9007199254740993".to_owned())
            );
        }
    }

    /// KR-REQ-23.25: planted text in a launch command shows only where the person asked for it: the
    /// label, the program and the arguments, in a line and in a document.
    #[test]
    fn planted_text_in_launch_commands_shows_only_where_it_was_asked_for() {
        for command in crate::output::planted::planted::<NamedLaunch>() {
            crate::output::planted::only_asked_lines("kr launch list", &[line(&command)]);
            crate::output::planted::only_asked(
                "kr launch list --json",
                &list_document(&ShellLaunchCommandsListResult {
                    revision: U64::new(7),
                    commands: vec![command],
                }),
            );
        }
    }
}
