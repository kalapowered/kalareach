//! `kr destination`: where this host sends notifications besides paired devices.
//!
//! A paired device is a destination its own registration makes. The others are the owner's: a
//! webhook, Slack, Discord, Telegram or email, each told what a grant the owner names lets it be
//! told. All three commands go through the control daemon on this user's own socket, which is the
//! only place the owner's methods are served: where content goes and who can read it is the
//! owner's act at this machine.
//!
//! Four of the five services send with a credential, and a credential decides who reads session
//! content. It is handed over in a file the owner names, never on the command line, where the
//! process list and the shell's history would keep it. The file is read once, its contents go to
//! the daemon and into its secret store, and nothing this command prints or fails with carries
//! them.

use std::path::Path;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_crypto::secret::SecretVec;
use kr_ipc::paths::HostPaths;
use kr_protocol::delivery::{
    DeliveryDestinationConfigureParams, DeliveryDestinationConfigureResult,
    DeliveryDestinationKind, DeliveryDestinationListParams, DeliveryDestinationListResult,
    DeliveryDestinationRemoveParams, DeliveryDestinationRemoveResult,
    DeliveryDestinationSecretSetParams, DeliveryDestinationSecretSetResult,
    DeliveryDestinationSummary, DestinationSecret, ExternalDestinationKind, MailAccount,
    SecretText,
};
use kr_protocol::ids::GrantId;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

use crate::cli::{
    DestinationCommand, DestinationConfigureArguments, DestinationKindArgument,
    DestinationListArguments, DestinationRemoveArguments,
};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request, closed};
use crate::shown::named;
use crate::stdout_line;

/// The most bytes a credential file may hold: a mail account's document is the longest, and it is
/// a few hundred.
const CREDENTIAL_FILE_LIMIT: u64 = 16 * 1024;

/// Runs one `kr destination` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: DestinationCommand, json: bool) -> Result<()> {
    match command {
        DestinationCommand::List(arguments) => list(paths, &arguments, json).await,
        DestinationCommand::Configure(arguments) => configure(paths, &arguments, json).await,
        DestinationCommand::Remove(arguments) => remove(paths, &arguments, json).await,
    }
}

/// `kr destination list`.
async fn list(paths: &HostPaths, arguments: &DestinationListArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let listed: DeliveryDestinationListResult = daemon
        .read(
            Method::DeliveryDestinationList,
            &DeliveryDestinationListParams {},
        )
        .await?;
    if json {
        output::document(&list_document(&listed));
    } else if listed.destinations.is_empty() {
        output::say(&Shown::said("no destinations"));
    } else {
        for destination in &listed.destinations {
            output::line(&line(destination));
        }
    }
    Ok(())
}

/// `kr destination configure`.
async fn configure(
    paths: &HostPaths,
    arguments: &DestinationConfigureArguments,
    json: bool,
) -> Result<()> {
    let kind = external_kind(arguments.kind);
    let grant_id: GrantId = identifier(&arguments.grant, "a grant")?;
    // Read before the daemon is reached: a mistake in the credential's file is the person's to
    // fix, and nothing has been sent anywhere.
    let secret = credential(kind, arguments.credential_file.as_deref())?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    if let Some(secret) = secret {
        let _: DeliveryDestinationSecretSetResult = daemon
            .mutate(
                Method::DeliveryDestinationSecretSet,
                &DeliveryDestinationSecretSetParams {
                    destination_id: arguments.destination.clone(),
                    secret,
                },
            )
            .await?;
    }
    let configured: DeliveryDestinationConfigureResult = daemon
        .mutate(
            Method::DeliveryDestinationConfigure,
            &DeliveryDestinationConfigureParams {
                destination_id: arguments.destination.clone(),
                kind,
                endpoint: arguments.endpoint.clone(),
                idempotency_header: Nullable(arguments.idempotency_header.clone()),
                rule_name: arguments
                    .rule_name
                    .clone()
                    .unwrap_or_else(|| arguments.destination.clone()),
                grant_id,
            },
        )
        .await?;
    if json {
        output::document(&configure_document(&configured));
    } else {
        output::lines(&configure_lines(&configured));
    }
    Ok(())
}

/// `kr destination remove`.
async fn remove(
    paths: &HostPaths,
    arguments: &DestinationRemoveArguments,
    json: bool,
) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let removed: DeliveryDestinationRemoveResult = daemon
        .mutate(
            Method::DeliveryDestinationRemove,
            &DeliveryDestinationRemoveParams {
                destination_id: arguments.destination.clone(),
            },
        )
        .await?;
    if json {
        output::document(&remove_document(&removed));
    } else {
        output::lines(&remove_lines(&removed));
    }
    Ok(())
}

/// The service a command line names, as the protocol names it.
const fn external_kind(kind: DestinationKindArgument) -> ExternalDestinationKind {
    match kind {
        DestinationKindArgument::Webhook => ExternalDestinationKind::Webhook,
        DestinationKindArgument::Slack => ExternalDestinationKind::Slack,
        DestinationKindArgument::Discord => ExternalDestinationKind::Discord,
        DestinationKindArgument::Telegram => ExternalDestinationKind::Telegram,
        DestinationKindArgument::Email => ExternalDestinationKind::Email,
    }
}

/// The credential a service sends with, read from the file the owner named, or none for a
/// webhook, which sends with none.
///
/// Every failure says which file and what it was expected to hold. None of them repeats what the
/// file held, which is the credential.
fn credential(
    kind: ExternalDestinationKind,
    file: Option<&Path>,
) -> Result<Option<DestinationSecret>> {
    let Some(file) = file else {
        return if kind == ExternalDestinationKind::Webhook {
            Ok(None)
        } else {
            Err(CliError::Usage(shown!(
                "a {} destination sends with a credential: name the file that holds it with \
                 --credential-file",
                kind.as_str()
            )))
        };
    };
    if kind == ExternalDestinationKind::Webhook {
        return Err(CliError::Usage(Shown::said(
            "a webhook sends with no credential: leave out --credential-file",
        )));
    }
    let bytes = read_credential(file)?;
    let refused = |expected: &'static str| {
        CliError::Usage(shown!("{} does not hold {}", named(file), expected))
    };
    match kind {
        ExternalDestinationKind::Webhook => Ok(None),
        ExternalDestinationKind::Slack => text(&bytes, || refused("a webhook address"))
            .map(|webhook_url| Some(DestinationSecret::Slack { webhook_url })),
        ExternalDestinationKind::Discord => text(&bytes, || refused("a webhook address"))
            .map(|webhook_url| Some(DestinationSecret::Discord { webhook_url })),
        ExternalDestinationKind::Telegram => text(&bytes, || refused("a bot token"))
            .map(|bot_token| Some(DestinationSecret::Telegram { bot_token })),
        ExternalDestinationKind::Email => serde_json::from_slice::<MailAccount>(bytes.expose())
            .map(|account| Some(DestinationSecret::Email { account }))
            .map_err(|_| {
                refused(
                    "a mail account: a JSON document with server, port, security, username, \
                     password and from_address",
                )
            }),
    }
}

/// The credential file's bytes, in a buffer that clears itself.
fn read_credential(file: &Path) -> Result<SecretVec> {
    let metadata = std::fs::metadata(file)
        .map_err(|error| CliError::Usage(shown!("{}: {}", named(file), Shown::io(&error))))?;
    if metadata.len() > CREDENTIAL_FILE_LIMIT {
        return Err(CliError::Usage(shown!(
            "{} is larger than a credential",
            named(file)
        )));
    }
    std::fs::read(file)
        .map(SecretVec::new)
        .map_err(|error| CliError::Usage(shown!("{}: {}", named(file), Shown::io(&error))))
}

/// A credential that is a line of text, without the line ending an editor leaves after it.
fn text(bytes: &SecretVec, refused: impl FnOnce() -> CliError) -> Result<SecretText> {
    std::str::from_utf8(bytes.expose())
        .ok()
        .map(str::trim)
        .and_then(|trimmed| SecretText::new(trimmed).ok())
        .ok_or_else(refused)
}

/// What a kind is called, as a word of this program's.
const fn kind_word(kind: DeliveryDestinationKind) -> &'static str {
    match kind {
        DeliveryDestinationKind::Push => "push",
        DeliveryDestinationKind::Webhook => "webhook",
        DeliveryDestinationKind::Slack => "slack",
        DeliveryDestinationKind::Discord => "discord",
        DeliveryDestinationKind::Telegram => "telegram",
        DeliveryDestinationKind::Email => "email",
    }
}

/// One destination as a line for a person. The names are the owner's own, shown back to them.
fn line(destination: &DeliveryDestinationSummary) -> Line {
    let endpoint = destination.endpoint.as_ref().map_or_else(
        || stdout_line!("-"),
        |endpoint| stdout_line!("{}", Asked::text(Request::Destinations, endpoint)),
    );
    let grant = destination.grant_id.as_ref().map_or_else(
        || stdout_line!("no grant"),
        |grant| stdout_line!("grant {}", *grant),
    );
    stdout_line!(
        "{}  {} {}  {}  {}",
        Asked::text(Request::Destinations, &destination.destination_id),
        output::left(8, &kind_word(destination.kind)),
        endpoint,
        grant,
        if destination.in_force {
            "in force"
        } else {
            "out of service"
        }
    )
}

/// The destinations in service, for a script, in the shape the protocol answers them. The
/// identifiers, addresses and names are the owner's own, shown back to them.
fn list_document(listed: &DeliveryDestinationListResult) -> Document {
    Document::new()
        .with(
            "destinations",
            listed
                .destinations
                .iter()
                .map(|destination| {
                    Document::new()
                        .with(
                            "destination_id",
                            Asked::text(Request::Destinations, &destination.destination_id),
                        )
                        .with("kind", kind_word(destination.kind))
                        .with(
                            "endpoint",
                            destination
                                .endpoint
                                .as_ref()
                                .map(|endpoint| Asked::text(Request::Destinations, endpoint)),
                        )
                        .with(
                            "idempotency_header",
                            destination
                                .idempotency_header
                                .as_ref()
                                .map(|header| Asked::text(Request::Destinations, header)),
                        )
                        .with(
                            "rule_name",
                            Asked::text(Request::Destinations, &destination.rule_name),
                        )
                        .with("grant_id", closed(&destination.grant_id))
                        .with("in_force", destination.in_force)
                        .with("configured_at_ms", closed(&destination.configured_at_ms))
                })
                .collect::<Vec<_>>(),
        )
        .with("ok", true)
}

/// What configuring a destination did, as lines for a person: that it is in force, and who can
/// read what it is sent, in the host's own sentence.
fn configure_lines(configured: &DeliveryDestinationConfigureResult) -> Vec<Line> {
    vec![
        stdout_line!(
            "Configured {} destination {}{}.",
            configured.kind.as_str(),
            Asked::text(Request::Destinations, &configured.destination_id),
            if configured.in_force {
                ", in force"
            } else {
                ", out of service"
            }
        ),
        stdout_line!(
            "{}",
            Asked::text(Request::Destinations, &configured.recipients_can_read)
        ),
    ]
}

/// What configuring a destination did, for a script.
fn configure_document(configured: &DeliveryDestinationConfigureResult) -> Document {
    Document::new()
        .with(
            "destination_id",
            Asked::text(Request::Destinations, &configured.destination_id),
        )
        .with("kind", configured.kind.as_str())
        .with("in_force", configured.in_force)
        .with(
            "recipients_can_read",
            Asked::text(Request::Destinations, &configured.recipients_can_read),
        )
        .with("ok", true)
}

/// What removing a destination did, as lines for a person: what was queued for it and taken back,
/// and what could still arrive.
fn remove_lines(removed: &DeliveryDestinationRemoveResult) -> Vec<Line> {
    if !removed.found {
        return vec![stdout_line!(
            "No destination is configured under {}.",
            Asked::text(Request::Destinations, &removed.destination_id)
        )];
    }
    let mut lines = vec![stdout_line!(
        "Removed destination {}.",
        Asked::text(Request::Destinations, &removed.destination_id)
    )];
    let (revoked, unresolved, fenced) = (
        removed.revoked.get(),
        removed.unresolved.get(),
        removed.fenced.get(),
    );
    if revoked > 0 {
        lines.push(stdout_line!(
            "{} queued notification{} taken back unsent.",
            revoked,
            if revoked == 1 { " was" } else { "s were" }
        ));
    }
    if unresolved > 0 {
        lines.push(stdout_line!(
            "{} queued notification{} sent once before, and what became of {} cannot be \
             settled.",
            unresolved,
            if unresolved == 1 { " was" } else { "s were" },
            if unresolved == 1 { "it" } else { "them" }
        ));
    }
    if fenced > 0 {
        lines.push(stdout_line!(
            "{} attempt{} on the wire when it was removed, and the destination may still \
             receive {}.",
            fenced,
            if fenced == 1 { " was" } else { "s were" },
            if fenced == 1 {
                "that message"
            } else {
                "those messages"
            }
        ));
    }
    lines
}

/// What removing a destination did, for a script, in the shape the protocol answers it.
fn remove_document(removed: &DeliveryDestinationRemoveResult) -> Document {
    Document::new()
        .with(
            "destination_id",
            Asked::text(Request::Destinations, &removed.destination_id),
        )
        .with("found", removed.found)
        .with("revoked", closed(&removed.revoked))
        .with("unresolved", closed(&removed.unresolved))
        .with("fenced", closed(&removed.fenced))
        .with("ok", true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-23.25: text planted in every leaf of a destination list, a configuration's answer and
    /// a removal's reaches their documents and lines only as what the owner named: the identifier,
    /// the address, the header and the rule's name, and the host's sentence about who can read.
    #[test]
    fn planted_text_in_destinations_shows_only_where_it_was_asked_for() {
        use crate::output::planted::{only_asked, only_asked_lines, planted, same_encoding};

        let mut shown = std::collections::BTreeSet::new();
        for listed in planted::<DeliveryDestinationListResult>() {
            let document = list_document(&listed);
            shown.extend(only_asked("kr destination list", &document));
            same_encoding(
                "kr destination list",
                &document,
                &serde_json::to_value(&listed).expect("the list encodes"),
                &[],
                &["ok"],
            );
            only_asked_lines(
                "kr destination list",
                &listed.destinations.iter().map(line).collect::<Vec<_>>(),
            );
        }
        for configured in planted::<DeliveryDestinationConfigureResult>() {
            let document = configure_document(&configured);
            shown.extend(only_asked("kr destination configure", &document));
            same_encoding(
                "kr destination configure",
                &document,
                &serde_json::to_value(&configured).expect("the answer encodes"),
                &[],
                &["ok"],
            );
            only_asked_lines("kr destination configure", &configure_lines(&configured));
        }
        for removed in planted::<DeliveryDestinationRemoveResult>() {
            let document = remove_document(&removed);
            shown.extend(only_asked("kr destination remove", &document));
            same_encoding(
                "kr destination remove",
                &document,
                &serde_json::to_value(&removed).expect("the answer encodes"),
                &[],
                &["ok"],
            );
            only_asked_lines("kr destination remove", &remove_lines(&removed));
        }
        for asked in [
            "destinations[].destination_id",
            "destinations[].endpoint",
            "destinations[].idempotency_header",
            "destinations[].rule_name",
            "destination_id",
            "recipients_can_read",
        ] {
            assert!(
                shown.contains(asked),
                "{asked} shows what was asked for: {shown:?}"
            );
        }
    }

    /// A credential is read from the file the owner named, and the failure for a file that does not
    /// hold one names the file and what it should hold, never what it holds.
    #[test]
    fn a_credential_file_that_does_not_hold_a_credential_is_refused_without_repeating_it() {
        let directory = tempfile::tempdir().expect("a directory");
        let planted = "very-secret-material-7c1e";
        let file = directory.path().join("credential");
        for (kind, content) in [
            (
                ExternalDestinationKind::Email,
                format!("{{\"server\": \"{planted}\"}}"),
            ),
            (ExternalDestinationKind::Slack, format!("{planted}\n\u{7}")),
            (ExternalDestinationKind::Telegram, String::new()),
        ] {
            std::fs::write(&file, content).expect("the file");
            let refusal = match credential(kind, Some(&file)) {
                Err(error) => error.to_string(),
                Ok(_) => panic!("{} accepted a file that holds none", kind.as_str()),
            };
            assert!(refusal.contains("does not hold"), "{refusal}");
            assert!(!refusal.contains(planted), "{refusal}");
        }

        // The controls: a Slack address with its line ending is the address, and a mail account is
        // read as the protocol reads one.
        std::fs::write(&file, "https://hooks.slack.com/services/T0/B0/x\n").expect("the file");
        assert!(matches!(
            credential(ExternalDestinationKind::Slack, Some(&file)),
            Ok(Some(DestinationSecret::Slack { .. }))
        ));
        std::fs::write(
            &file,
            r#"{"server":"mail.example.com","port":465,"security":"implicit_tls",
                "username":"u","password":"p","from_address":"a@example.com"}"#,
        )
        .expect("the file");
        assert!(matches!(
            credential(ExternalDestinationKind::Email, Some(&file)),
            Ok(Some(DestinationSecret::Email { .. }))
        ));
    }
}
