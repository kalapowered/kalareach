//! `kr organisation`: enrolling this host in an organisation's policy, and reading what it holds.
//!
//! An enrolment is the owner's. The chain of keys that signs an organisation's policy is read from
//! a file a member exported from the organisation's service, because this host never calls the
//! service itself. The command asks the host for the challenge that confirms exactly that chain,
//! says that an owner device has to confirm it and what that device is shown, and repeats the
//! request until the host spends the owner device's answer or the challenge runs out.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::account::PolicyAuthority;
use kr_protocol::confirmation::{ConfirmationDisplay, ConfirmationSubject};
use kr_protocol::limits::MAX_CONTROL_FRAME_LEN;
use kr_protocol::method::Method;
use kr_protocol::organisation::{
    OrganisationEnrolParams, OrganisationEnrolResult, OrganisationListParams,
    OrganisationListResult,
};

use crate::cli::{OrganisationCommand, OrganisationEnrolArguments, PrivacyArguments};
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Request, closed};
use crate::plugin::confirmed_on_an_owner_device;
use crate::shown::{key_identifier, utc_moment};
use crate::stdout_line;

/// Runs one `kr organisation` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the host's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: OrganisationCommand, json: bool) -> Result<()> {
    match command {
        OrganisationCommand::Enrol(arguments) => enrol(paths, &arguments, json).await,
        OrganisationCommand::List(arguments) => list(paths, &arguments, json).await,
    }
}

/// Reads the chain a member exported.
///
/// The file is bounded by what one control frame carries, which is what the host would refuse a
/// larger chain for, and it is the organisation's published object as JSON. A link and a pipe are
/// refused where the platform can tell: this reads a file, and does not wait for a writer.
fn read_chain(path: &std::path::Path) -> Result<PolicyAuthority> {
    let bytes = read_bounded(path).map_err(|error| {
        CliError::Usage(if error.kind() == std::io::ErrorKind::InvalidData {
            Shown::said(
                "the chain file is not a regular file, or is larger than any chain this host \
                 would take",
            )
        } else {
            shown!("the chain file could not be read: {}", Shown::io(&error))
        })
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        CliError::Usage(Shown::said(
            "the file is not an organisation's published policy-signing chain",
        ))
    })
}

/// The file's bytes, when it is a regular file of at most one control frame.
#[cfg(unix)]
fn read_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    kr_ipc::install::read_regular_file(path, MAX_CONTROL_FRAME_LEN as u64)
}

/// The file's bytes, when it is a regular file of at most one control frame.
#[cfg(not(unix))]
fn read_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let too_much = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file within the bound",
        )
    };
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_CONTROL_FRAME_LEN as u64 {
        return Err(too_much());
    }
    std::fs::read(path)
}

/// `kr organisation enrol`.
async fn enrol(
    paths: &HostPaths,
    arguments: &OrganisationEnrolArguments,
    json: bool,
) -> Result<()> {
    let params = OrganisationEnrolParams {
        authority: read_chain(&arguments.chain)?,
    };
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let (enrolled, _challenge): (OrganisationEnrolResult, _) = confirmed_on_an_owner_device(
        &mut daemon,
        ConfirmationSubject::EnrolOrganisation(Box::new(params.clone())),
        Method::OrganisationEnrol,
        &params,
        json,
        say_what_is_asked,
    )
    .await?;
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("organisation_id", closed(&enrolled.organisation_id))
                .with("enrolment_revision", closed(&enrolled.enrolment_revision))
                .with("accepted_head", closed(&enrolled.accepted_head))
                .with(
                    "root_key_id",
                    output::said(&key_identifier(&enrolled.root_key_id)),
                ),
        );
    } else {
        output::line(&stdout_line!(
            "This host is enrolled in organisation {}: its first key is {}, and its keys are \
             followed from revision {}.",
            enrolled.organisation_id,
            key_identifier(&enrolled.root_key_id),
            enrolled.accepted_head
        ));
        output::line(&stdout_line!(
            "A grant that requires it names enrolment revision {}.",
            enrolled.enrolment_revision
        ));
    }
    Ok(())
}

/// Says what an owner device is asked to confirm, as the host resolved it from the chain: each
/// key by its whole identifier, revision and the moment it took over signing, which is what an
/// administrator reads out and what the confirmation covers.
fn say_what_is_asked(display: &ConfirmationDisplay) {
    if let ConfirmationDisplay::EnrolOrganisation {
        organisation_id,
        root,
        anchor,
    } = display
    {
        let key = |shown: &kr_protocol::confirmation::PolicyKeyShown| {
            key_identifier(&kr_protocol::pairing::key_id(
                kr_protocol::pairing::KeyPurpose::Authorisation,
                shown.public_key.as_bytes(),
            ))
        };
        output::line(&stdout_line!(
            "An owner device is asked to trust organisation {} to sign the access it grants here. \
             Its first key is {} (revision {}, from {}), and the key signing now is {} (revision \
             {}, from {}).",
            *organisation_id,
            key(root),
            root.revision,
            utc_moment(root.not_before_ms.get()),
            key(anchor),
            anchor.revision,
            utc_moment(anchor.not_before_ms.get())
        ));
    }
}

/// `kr organisation list`.
async fn list(paths: &HostPaths, arguments: &PrivacyArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let listed: OrganisationListResult = daemon
        .read(Method::OrganisationList, &OrganisationListParams::default())
        .await?;
    if json {
        output::document(&document(&listed));
        return Ok(());
    }
    if listed.enrolments.is_empty() {
        output::line(&stdout_line!("This host is enrolled in no organisation."));
    }
    for enrolment in &listed.enrolments {
        output::line(&stdout_line!(
            "Organisation {}: first key {}, followed from revision {} (key {}), highest accepted \
             revision {}, enrolment revision {}.",
            enrolment.organisation_id,
            key_identifier(&enrolment.root_key_id),
            enrolment.anchor_revision,
            key_identifier(&enrolment.anchor_key_id),
            enrolment.accepted_head,
            enrolment.enrolment_revision
        ));
        for member in &enrolment.members {
            output::line(&stdout_line!(
                "  device {} is bound to {}, since {}.",
                member.device_id,
                Asked::text(Request::Organisations, member.account_id.as_str()),
                utc_moment(member.bound_at_ms.get())
            ));
            if let Some(lease) = member.lease.as_ref() {
                output::line(&stdout_line!(
                    "    its last lease was issued {} and ends {}.",
                    utc_moment(lease.issued_at_ms.get()),
                    utc_moment(lease.expires_at_ms.get())
                ));
            }
        }
    }
    output::line(&stdout_line!(
        "Exclusive management is {}. This host {} its clock.",
        if listed.exclusive { "on" } else { "off" },
        if listed.clock_trusted {
            "trusts"
        } else {
            "does not trust"
        }
    ));
    for event in &listed.exclusive_events {
        output::line(&stdout_line!(
            "Exclusive management was turned off at {}.",
            utc_moment(event.at_ms.get())
        ));
    }
    Ok(())
}

/// What `list` reports, as a document.
fn document(listed: &OrganisationListResult) -> Document {
    let enrolments: Vec<Document> = listed
        .enrolments
        .iter()
        .map(|enrolment| {
            let members: Vec<Document> = enrolment
                .members
                .iter()
                .map(|member| {
                    let mut held = Document::new()
                        .with("device_id", closed(&member.device_id))
                        .with(
                            "account_id",
                            Asked::text(Request::Organisations, member.account_id.as_str()),
                        )
                        .with(
                            "device_key_id",
                            output::said(&key_identifier(&member.device_key_id)),
                        )
                        .with("bound_at_ms", closed(&member.bound_at_ms));
                    if let Some(lease) = member.lease.as_ref() {
                        held.set(
                            "lease",
                            Document::new()
                                .with("issued_at_ms", closed(&lease.issued_at_ms))
                                .with("expires_at_ms", closed(&lease.expires_at_ms)),
                        );
                    }
                    held
                })
                .collect();
            Document::new()
                .with("organisation_id", closed(&enrolment.organisation_id))
                .with(
                    "root_key_id",
                    output::said(&key_identifier(&enrolment.root_key_id)),
                )
                .with("anchor_revision", closed(&enrolment.anchor_revision))
                .with(
                    "anchor_key_id",
                    output::said(&key_identifier(&enrolment.anchor_key_id)),
                )
                .with("accepted_head", closed(&enrolment.accepted_head))
                .with("enrolment_revision", closed(&enrolment.enrolment_revision))
                .with("members", members)
        })
        .collect();
    let events: Vec<Document> = listed
        .exclusive_events
        .iter()
        .map(|event| {
            Document::new()
                .with("sequence", closed(&event.sequence))
                .with("at_ms", closed(&event.at_ms))
                .with("channel", closed(&event.channel))
                .with("organisation_ids", closed(&event.organisation_ids))
        })
        .collect();
    Document::new()
        .with("ok", true)
        .with("exclusive", listed.exclusive)
        .with("clock_trusted", listed.clock_trusted)
        .with("enrolments", enrolments)
        .with("exclusive_events", events)
}
