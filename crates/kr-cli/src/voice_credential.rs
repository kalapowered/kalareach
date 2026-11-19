//! `kr voice credential`: the key this host keeps for voice calls on the owner's own account.
//!
//! Both commands go through the control daemon on this user's own socket, the only place the
//! methods are served. The key is read from standard input, typed where nothing is shown or piped
//! in, and is never an argument, so the process list and the shell's history do not keep it. It
//! goes to the daemon and into its secret store, and nothing these commands print or fail with
//! carries it.

use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::delivery::SecretText;
use kr_protocol::method::Method;
use kr_protocol::voice_credential::{
    VoiceCredentialForgetCallsParams, VoiceCredentialForgetCallsResult, VoiceCredentialKind,
    VoiceCredentialRemoveParams, VoiceCredentialRemoveResult, VoiceCredentialSetParams,
    VoiceCredentialSetResult, VoiceLateStart,
};

use crate::cli::{
    VoiceCommand, VoiceCredentialCommand, VoiceCredentialRemoveArguments,
    VoiceCredentialSetArguments,
};
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::{self, Document};
use crate::secret_input;

/// Runs one `kr voice` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: VoiceCommand, json: bool) -> Result<()> {
    match command {
        VoiceCommand::Credential(VoiceCredentialCommand::Set(arguments)) => {
            set(paths, &arguments, json).await
        }
        VoiceCommand::Credential(VoiceCredentialCommand::Remove(arguments)) => {
            remove(paths, &arguments, json).await
        }
        VoiceCommand::Credential(VoiceCredentialCommand::ForgetCalls(arguments)) => {
            forget_calls(paths, &arguments, json).await
        }
    }
}

/// The provider a command line names, as the protocol names it. A word that names none is refused
/// without being repeated, since a person can type a key here by mistake.
fn kind_of(provider: &str) -> Result<VoiceCredentialKind> {
    match provider {
        "openai-live" => Ok(VoiceCredentialKind::OpenaiLive),
        _ => Err(CliError::Usage(Shown::said(
            "Only openai-live is accepted.",
        ))),
    }
}

/// `kr voice credential set`.
async fn set(paths: &HostPaths, arguments: &VoiceCredentialSetArguments, json: bool) -> Result<()> {
    // Anything typed after the command is a key in the wrong place. It is refused before anything
    // is read or sent, and what was typed is not repeated.
    if !arguments.refused.is_empty() {
        return Err(CliError::Usage(Shown::said(
            "give the key on standard input, not as an argument: an argument stays in your \
             shell's history and in the process list",
        )));
    }
    let kind = kind_of(&arguments.provider)?;
    // Read before the daemon is reached: a mistake in the entry is the person's to fix, and
    // nothing has been sent anywhere.
    let key = secret_input::read_secret()?;
    // Bytes that are not text cannot be a key. They go to the host as a character it refuses by
    // the shape of a key, in its own words, so no sentence of this program has to describe them.
    let key = SecretText::new(std::str::from_utf8(key.expose()).unwrap_or("\u{fffd}"))
        .map_err(|_| CliError::Usage(Shown::said("no key was entered, so nothing was changed")))?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let held: VoiceCredentialSetResult = daemon
        .mutate(
            Method::VoiceCredentialSet,
            &VoiceCredentialSetParams { kind, key },
        )
        .await?;
    if json {
        output::document(&set_document(&held));
    } else {
        output::say(&Shown::said("This host holds the OpenAI key now."));
    }
    Ok(())
}

/// `kr voice credential remove`.
async fn remove(
    paths: &HostPaths,
    arguments: &VoiceCredentialRemoveArguments,
    json: bool,
) -> Result<()> {
    let kind = kind_of(&arguments.provider)?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let removed: VoiceCredentialRemoveResult = daemon
        .mutate(
            Method::VoiceCredentialRemove,
            &VoiceCredentialRemoveParams { kind },
        )
        .await?;
    if json {
        output::document(&remove_document(&removed));
    } else if removed.removed {
        output::say(&Shown::said(match removed.late_start {
            VoiceLateStart::None => "This host deleted the OpenAI key.",
            VoiceLateStart::Closed => {
                "This host deleted the key. A call that was still starting was closed at OpenAI."
            }
            VoiceLateStart::MayStillRun => {
                "This host deleted the key. A call that was still starting may be running at OpenAI, because this host could not confirm that it was closed or learn whether it was created. Check your OpenAI usage."
            }
        }));
    } else {
        output::say(&Shown::said("This host held no OpenAI key."));
    }
    Ok(())
}

/// `kr voice credential forget-calls`.
async fn forget_calls(
    paths: &HostPaths,
    arguments: &VoiceCredentialRemoveArguments,
    json: bool,
) -> Result<()> {
    let kind = kind_of(&arguments.provider)?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let forgotten: VoiceCredentialForgetCallsResult = daemon
        .mutate(
            Method::VoiceCredentialForgetCalls,
            &VoiceCredentialForgetCallsParams { kind },
        )
        .await?;
    if json {
        output::document(
            &Document::new()
                .with("kind", forgotten.kind.as_str())
                .with("calls_forgotten", u64::from(forgotten.calls_forgotten))
                .with("late_start", late_start_word(forgotten.late_start))
                .with("ok", true),
        );
    } else {
        output::say(&Shown::said(match forgotten.late_start {
            VoiceLateStart::None => {
                "This host forgot every call record and kept the key. No call was still starting."
            }
            VoiceLateStart::Closed => {
                "This host forgot every call record and kept the key. A call that was still starting was closed at OpenAI."
            }
            VoiceLateStart::MayStillRun => {
                "This host forgot every call record and kept the key. A call that was still starting may be running at OpenAI, because this host could not confirm that it was closed or learn whether it was created. Check your OpenAI usage."
            }
        }));
    }
    Ok(())
}

/// The word a script reads for what became of a call that was still starting.
const fn late_start_word(late: VoiceLateStart) -> &'static str {
    match late {
        VoiceLateStart::None => "none",
        VoiceLateStart::Closed => "closed",
        VoiceLateStart::MayStillRun => "may_still_run",
    }
}

/// What setting a key did, for a script, in the shape the protocol answers it.
fn set_document(held: &VoiceCredentialSetResult) -> Document {
    Document::new()
        .with("kind", held.kind.as_str())
        .with("in_force", held.in_force)
        .with("ok", true)
}

/// What removing a key did, for a script, in the shape the protocol answers it.
fn remove_document(removed: &VoiceCredentialRemoveResult) -> Document {
    Document::new()
        .with("kind", removed.kind.as_str())
        .with("removed", removed.removed)
        .with("late_start", late_start_word(removed.late_start))
        .with("ok", true)
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::{Cli, Command};

    const KEY: &str = "sk-sentinel-0123456789abcdef";

    fn parsed(line: &[&str]) -> std::result::Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("kr").chain(line.iter().copied()))
    }

    /// A key given where a command takes none is either caught as the refused argument or turned
    /// away by the parser, and no text the parser makes repeats it.
    #[test]
    fn a_key_given_as_an_argument_is_refused_and_never_repeated() {
        // The control: the command line with no key parses with nothing refused.
        let clean = parsed(&["voice", "credential", "set", "--provider", "openai-live"])
            .unwrap_or_else(|error| panic!("{error}"));
        let Command::Voice(VoiceCommand::Credential(VoiceCredentialCommand::Set(arguments))) =
            clean.command
        else {
            panic!("the line is a voice credential set");
        };
        assert!(arguments.refused.is_empty());

        for line in [
            vec![
                "voice",
                "credential",
                "set",
                "--provider",
                "openai-live",
                KEY,
            ],
            vec![
                "voice",
                "credential",
                "set",
                "--provider",
                "openai-live",
                "--",
                KEY,
            ],
        ] {
            let parsed = parsed(&line).unwrap_or_else(|error| panic!("{error}"));
            let Command::Voice(VoiceCommand::Credential(VoiceCredentialCommand::Set(arguments))) =
                parsed.command
            else {
                panic!("the line is a voice credential set");
            };
            assert!(
                !arguments.refused.is_empty(),
                "{line:?} gives a refused argument"
            );
        }
        for line in [
            vec![
                "voice",
                "credential",
                "set",
                KEY,
                "--provider",
                "openai-live",
            ],
            vec![
                "voice",
                "credential",
                "set",
                "--provider",
                "openai-live",
                "--key",
                KEY,
            ],
            vec![
                "voice",
                "credential",
                "set",
                "--provider",
                "openai-live",
                &format!("--key={KEY}"),
            ],
        ] {
            match parsed(&line) {
                Ok(parsed) => {
                    let Command::Voice(VoiceCommand::Credential(VoiceCredentialCommand::Set(
                        arguments,
                    ))) = parsed.command
                    else {
                        panic!("the line is a voice credential set");
                    };
                    assert!(
                        !arguments.refused.is_empty(),
                        "{line:?} is not a key taken silently"
                    );
                }
                Err(error) => {
                    let text = error.to_string();
                    assert!(
                        !text.contains("sentinel"),
                        "the parser repeats the key: {text}"
                    );
                }
            }
        }
    }

    /// A word that is no provider is refused without being repeated, and the provider that is
    /// one is taken: a key typed where the provider goes is not shown back.
    #[test]
    fn a_word_that_is_no_provider_is_refused_and_never_repeated() {
        assert_eq!(
            kind_of("openai-live").expect("the provider"),
            VoiceCredentialKind::OpenaiLive
        );
        let parsed = parsed(&[
            "voice",
            "credential",
            "remove",
            &format!("--provider={KEY}"),
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        let Command::Voice(VoiceCommand::Credential(VoiceCredentialCommand::Remove(arguments))) =
            parsed.command
        else {
            panic!("the line is a voice credential remove");
        };
        let refused = kind_of(&arguments.provider).expect_err("a key is no provider");
        assert!(!refused.to_string().contains("sentinel"), "{refused}");
    }
}
