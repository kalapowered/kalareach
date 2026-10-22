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
use kr_protocol::account::{OrganisationPolicy, PolicyAuthority};
use kr_protocol::confirmation::{ConfirmationDisplay, ConfirmationSubject};
use kr_protocol::ids::{OrganisationId, PluginId};
use kr_protocol::limits::MAX_CONTROL_FRAME_LEN;
use kr_protocol::method::Method;
use kr_protocol::organisation::{
    MembershipPresentParams, MembershipPresentResult, OrganisationEnrolParams,
    OrganisationEnrolResult, OrganisationExclusiveSetParams, OrganisationExclusiveSetResult,
    OrganisationListParams, OrganisationListResult, OrganisationPolicyApplyParams,
    OrganisationPolicyApplyResult, OrganisationWithdrawParams,
};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::sharing::RevocationResult;

use crate::cli::{
    OrganisationCommand, OrganisationEnrolArguments, OrganisationExclusiveCommand,
    OrganisationPolicyArguments, OrganisationPresentArguments, OrganisationWithdrawArguments,
    PrivacyArguments,
};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Request, closed};
use crate::plugin::confirmed_on_an_owner_device;
use crate::shown::{key_hex, key_identifier, utc_moment};
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
        OrganisationCommand::Withdraw(arguments) => withdraw(paths, &arguments, json).await,
        OrganisationCommand::Present(arguments) => present(paths, &arguments, json).await,
        OrganisationCommand::Policy(arguments) => policy(paths, &arguments, json).await,
        OrganisationCommand::Exclusive(OrganisationExclusiveCommand::On(arguments)) => {
            exclusive_on(paths, &arguments, json).await
        }
        OrganisationCommand::Exclusive(OrganisationExclusiveCommand::Off(arguments)) => {
            crate::pair::end_exclusive_management(paths, &arguments.selector, json).await
        }
    }
}

/// `kr organisation present`.
async fn present(
    paths: &HostPaths,
    arguments: &OrganisationPresentArguments,
    json: bool,
) -> Result<()> {
    let lease: kr_protocol::account::MembershipLease = read_json(
        &arguments.lease,
        ("the lease file", "lease"),
        "the file is not a membership lease an organisation signed",
    )?;
    let authority = arguments
        .chain
        .as_ref()
        .map(|path| read_chain(path))
        .transpose()?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let presented: MembershipPresentResult = daemon
        .mutate(
            Method::MembershipPresent,
            &MembershipPresentParams {
                lease,
                authority: authority.map_or_else(
                    kr_protocol::scalars::Nullable::null,
                    kr_protocol::scalars::Nullable::some,
                ),
            },
        )
        .await?;
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("organisation_id", closed(&presented.organisation_id))
                .with(
                    "account_id",
                    Asked::text(Request::Organisations, presented.account_id.as_str()),
                )
                .with("key_revision", closed(&presented.key_revision))
                .with("expires_at_ms", closed(&presented.expires_at_ms))
                .with("exclusive", presented.exclusive),
        );
    } else {
        output::line(&stdout_line!(
            "This host's local owner answers to organisation {} as {}, signed by key revision {}, \
             until {}.",
            presented.organisation_id,
            Asked::text(Request::Organisations, presented.account_id.as_str()),
            presented.key_revision,
            utc_moment(presented.expires_at_ms.get())
        ));
    }
    Ok(())
}

/// The lines that say an adapter list: the adapters it names, one to a line, none at all, or
/// `every` where the list names no adapter and so allows every one the host qualifies.
fn adapter_lines(
    list: &Nullable<CanonicalSet<PluginId>>,
    every: &'static str,
) -> Vec<output::Line> {
    match list.as_ref() {
        None => vec![stdout_line!("    {}.", Shown::said(every))],
        Some(adapters) if adapters.is_empty() => vec![stdout_line!("    no adapter.")],
        Some(adapters) => adapters
            .iter()
            .map(|adapter| {
                stdout_line!(
                    "    {}",
                    Asked::text(Request::Plugins, &adapter.to_string())
                )
            })
            .collect(),
    }
}

/// An adapter list as a document holds it: the adapters, or null where it names none.
fn adapters_held(list: &Nullable<CanonicalSet<PluginId>>) -> Option<Vec<Asked>> {
    list.as_ref().map(|adapters| {
        adapters
            .iter()
            .map(|adapter| Asked::text(Request::Plugins, &adapter.to_string()))
            .collect()
    })
}

/// `kr organisation policy`.
async fn policy(
    paths: &HostPaths,
    arguments: &OrganisationPolicyArguments,
    json: bool,
) -> Result<()> {
    let policy: OrganisationPolicy = read_json(
        &arguments.policy,
        ("the policy file", "policy"),
        "the file is not a policy an organisation signed",
    )?;
    let authority = arguments
        .chain
        .as_ref()
        .map(|path| read_chain(path))
        .transpose()?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let applied: OrganisationPolicyApplyResult = daemon
        .mutate(
            Method::OrganisationPolicyApply,
            &OrganisationPolicyApplyParams {
                policy,
                authority: Nullable(authority),
            },
        )
        .await?;
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("organisation_id", closed(&applied.organisation_id))
                .with(
                    "organisation_policy_revision",
                    closed(&applied.organisation_policy_revision),
                )
                .with(
                    "adapter_allowlist",
                    adapters_held(&applied.adapter_allowlist),
                )
                .with(
                    "effective_adapter_allowlist",
                    adapters_held(&applied.effective_adapter_allowlist),
                ),
        );
    } else {
        output::line(&stdout_line!(
            "Organisation {}: policy revision {} is applied. It allows:",
            applied.organisation_id,
            output::closed_word(&applied.organisation_policy_revision)
        ));
        output::lines(&adapter_lines(
            &applied.adapter_allowlist,
            "every adapter this host qualifies",
        ));
        output::line(&stdout_line!("The organisations' policies allow together:"));
        output::lines(&adapter_lines(
            &applied.effective_adapter_allowlist,
            "every adapter this host qualifies",
        ));
    }
    Ok(())
}

/// `kr organisation withdraw`.
async fn withdraw(
    paths: &HostPaths,
    arguments: &OrganisationWithdrawArguments,
    json: bool,
) -> Result<()> {
    let organisation_id: OrganisationId = identifier(&arguments.organisation, "an organisation")?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let withdrawn: RevocationResult = daemon
        .mutate(
            Method::OrganisationWithdraw,
            &OrganisationWithdrawParams { organisation_id },
        )
        .await?;
    let pending = crate::device::pending_fence(
        shown!("the withdrawal from organisation {}", organisation_id),
        &withdrawn.barrier,
    );
    if json {
        let document = crate::device::revocation_document(&withdrawn);
        output::document(&match &pending {
            Some(error) => crate::report::with_failure(document, error),
            None => document,
        });
    } else {
        output::lines(&crate::device::barrier_lines(
            stdout_line!(
                "This host left organisation {}, at authority revision {}. Nothing that required \
                 it is honoured now.",
                organisation_id,
                withdrawn.authority_revision
            ),
            &withdrawn.barrier,
        ));
        if let Some(error) = &pending {
            crate::report::failed(error);
        }
    }
    pending.map_or(Ok(()), Err)
}

/// `kr organisation exclusive on`.
async fn exclusive_on(paths: &HostPaths, arguments: &PrivacyArguments, json: bool) -> Result<()> {
    let params = OrganisationExclusiveSetParams { exclusive: true };
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let (made, _challenge): (OrganisationExclusiveSetResult, _) = confirmed_on_an_owner_device(
        &mut daemon,
        ConfirmationSubject::SetExclusiveManagement { exclusive: true },
        Method::OrganisationExclusiveSet,
        &params,
        json,
        say_what_is_asked,
    )
    .await?;
    report_exclusive(&made, json)
}

/// What a change of exclusive management reports.
pub(crate) fn report_exclusive(made: &OrganisationExclusiveSetResult, json: bool) -> Result<()> {
    let pending = made.barrier.0.as_ref().and_then(|barrier| {
        crate::device::pending_fence(Shown::said("making this host exclusive"), barrier)
    });
    if json {
        let mut document = Document::new()
            .with("ok", true)
            .with("exclusive", made.exclusive)
            .with("authority_revision", closed(&made.authority_revision));
        if let Some(barrier) = made.barrier.0.as_ref() {
            document.set("barrier_workers_total", closed(&barrier.workers_total));
        }
        output::document(&match &pending {
            Some(error) => crate::report::with_failure(document, error),
            None => document,
        });
    } else if made.exclusive {
        let first = stdout_line!(
            "This host is exclusively organisation-managed, at authority revision {}: a personal \
             grant answers to a membership lease now.",
            made.authority_revision
        );
        match made.barrier.0.as_ref() {
            Some(barrier) => output::lines(&crate::device::barrier_lines(first, barrier)),
            None => output::line(&first),
        }
        if let Some(error) = &pending {
            crate::report::failed(error);
        }
    } else {
        output::line(&stdout_line!(
            "Exclusive management is off: a personal grant is served on its own again."
        ));
    }
    pending.map_or(Ok(()), Err)
}

/// Reads the chain a member exported.
///
/// The file is bounded by what one control frame carries, which is what the host would refuse a
/// larger chain for, and it is the organisation's published object as JSON. On Unix a link and a
/// pipe are refused: this reads a file, and does not wait for a writer.
fn read_chain(path: &std::path::Path) -> Result<PolicyAuthority> {
    read_json(
        path,
        ("the chain file", "chain"),
        "the file is not an organisation's published policy-signing chain",
    )
}

/// An organisation's published object from a JSON file, bounded as [`read_chain`] says.
fn read_json<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
    (what, object): (&'static str, &'static str),
    not_it: &'static str,
) -> Result<T> {
    let bytes = read_bounded(path).map_err(|error| {
        CliError::Usage(if error.kind() == std::io::ErrorKind::InvalidData {
            shown!(
                "{} is not a regular file, or is larger than any {} this host would take",
                Shown::said(what),
                Shown::said(object)
            )
        } else {
            shown!(
                "{} could not be read: {}",
                Shown::said(what),
                Shown::io(&error)
            )
        })
    })?;
    serde_json::from_slice(&bytes).map_err(|_| CliError::Usage(Shown::said(not_it)))
}

/// The file's bytes, when it is a regular file of at most one control frame.
#[cfg(unix)]
fn read_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    kr_ipc::install::read_regular_file(path, MAX_CONTROL_FRAME_LEN as u64)
}

/// The file's bytes, when it is a regular file of at most one control frame. The limit is put on
/// the read of the file that was opened, so a file that grows after it was looked at is still cut.
/// A link is followed here: this program does not refuse one on this platform.
#[cfg(not(unix))]
fn read_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let refused = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file within the bound",
        )
    };
    let file = std::fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(refused());
    }
    let limit = MAX_CONTROL_FRAME_LEN as u64;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(refused());
    }
    Ok(bytes)
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
pub(crate) fn say_what_is_asked(display: &ConfirmationDisplay) {
    if let Some(line) = what_is_asked(display) {
        output::line(&line);
    }
}

/// The line `say_what_is_asked` writes, for the display of an enrolment.
fn what_is_asked(display: &ConfirmationDisplay) -> Option<output::Line> {
    if let ConfirmationDisplay::ExclusiveManagement {
        exclusive,
        organisation_ids,
    } = display
    {
        let organisations =
            Shown::joined(organisation_ids.iter().map(|id| shown!("{}", *id)), ", ");
        return Some(if *exclusive {
            stdout_line!(
                "An owner device is asked to make this host exclusively managed by {}. A personal \
                 grant, its own included, then answers to a membership lease like a member's.",
                organisations
            )
        } else {
            stdout_line!(
                "An owner device is asked to end the exclusive management of this host by {}.",
                organisations
            )
        });
    }
    let ConfirmationDisplay::EnrolOrganisation {
        organisation_id,
        root,
        anchor,
    } = display
    else {
        return None;
    };
    let key = |shown: &kr_protocol::confirmation::PolicyKeyShown| {
        key_identifier(&kr_protocol::pairing::key_id(
            kr_protocol::pairing::KeyPurpose::Authorisation,
            shown.public_key.as_bytes(),
        ))
    };
    Some(stdout_line!(
        "An owner device is asked to trust organisation {} to sign the access it grants here. \
         Its first key is {} (revision {}, from {}), and the key signing now is {} (revision {}, \
         from {}).",
        *organisation_id,
        key(root),
        root.revision,
        utc_moment(root.not_before_ms.get()),
        key(anchor),
        anchor.revision,
        utc_moment(anchor.not_before_ms.get())
    ))
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
        match enrolment.organisation_policy_revision.as_ref() {
            Some(revision) => {
                output::line(&stdout_line!(
                    "  policy revision {} allows:",
                    output::closed_word(revision)
                ));
                output::lines(&adapter_lines(
                    &enrolment.adapter_allowlist,
                    "every adapter this host qualifies",
                ));
            }
            None => output::line(&stdout_line!("  no policy is applied.")),
        }
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
    if listed.adapter_allowlist_in_force == listed.effective_adapter_allowlist {
        output::line(&stdout_line!(
            "The organisations' policies allow together, and this host admits:"
        ));
        output::lines(&adapter_lines(
            &listed.effective_adapter_allowlist,
            "every adapter this host qualifies",
        ));
    } else {
        output::line(&stdout_line!("The organisations' policies allow together:"));
        output::lines(&adapter_lines(
            &listed.effective_adapter_allowlist,
            "every adapter this host qualifies",
        ));
        output::line(&stdout_line!(
            "This host admits now, until it puts that list in force:"
        ));
        output::lines(&adapter_lines(
            &listed.adapter_allowlist_in_force,
            "every adapter this host qualifies",
        ));
    }
    output::line(&stdout_line!(
        "A lease for this host's own local owner is signed for device {} and authorisation key {} \
         (key identifier {}).",
        listed.host_device.device_id,
        key_hex(listed.host_device.authorisation_key.as_bytes()),
        key_identifier(&kr_protocol::pairing::key_id(
            kr_protocol::pairing::KeyPurpose::Authorisation,
            listed.host_device.authorisation_key.as_bytes(),
        ))
    ));
    for session_id in &listed.workers_without_local_enforcement {
        output::line(&stdout_line!(
            "The worker of session {} cannot be told what this host's local owner may do; end the \
             session with `kr close` to hold it to the lease.",
            output::closed_word(session_id)
        ));
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
                .with(
                    "organisation_policy_revision",
                    enrolment.organisation_policy_revision.as_ref().map(closed),
                )
                .with(
                    "adapter_allowlist",
                    adapters_held(&enrolment.adapter_allowlist),
                )
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
        .with(
            "effective_adapter_allowlist",
            adapters_held(&listed.effective_adapter_allowlist),
        )
        .with(
            "adapter_allowlist_in_force",
            adapters_held(&listed.adapter_allowlist_in_force),
        )
        .with(
            "host_device",
            Document::new()
                .with("device_id", closed(&listed.host_device.device_id))
                .with(
                    "authorisation_key",
                    output::said(&key_hex(listed.host_device.authorisation_key.as_bytes())),
                )
                .with(
                    "authorisation_key_id",
                    output::said(&key_identifier(&kr_protocol::pairing::key_id(
                        kr_protocol::pairing::KeyPurpose::Authorisation,
                        listed.host_device.authorisation_key.as_bytes(),
                    ))),
                ),
        )
        .with(
            "workers_without_local_enforcement",
            closed(&listed.workers_without_local_enforcement),
        )
        .with("enrolments", enrolments)
        .with("exclusive_events", events)
}

#[cfg(test)]
mod tests {
    use super::*;

    use kr_protocol::confirmation::{OrganisationEnrolPlan, PolicyKeyShown};
    use kr_protocol::ids::{OrganisationId, PolicyKeyRevision};
    use kr_protocol::scalars::{AuthorisationKey, TimestampMs, Uuid};

    /// KR-REQ-17.53: what `kr organisation enrol` prints before an owner device confirms is the
    /// whole identifier of each key, its revision and the moment it took over signing: what an
    /// administrator reads out, and what the confirmation covers. Two plans that differ only in an
    /// activation time print two lines, and another display prints none.
    #[test]
    fn the_command_prints_each_key_whole_with_when_it_took_over() {
        let key = |seed: u8, revision: u64, at: u64| PolicyKeyShown {
            revision: PolicyKeyRevision::new(revision),
            public_key: AuthorisationKey::from_bytes([seed; 32]),
            not_before_ms: TimestampMs::new(at),
        };
        let plan = OrganisationEnrolPlan {
            organisation_id: OrganisationId::new(Uuid::from_bytes([0x21; 16])),
            root: key(0x31, 1, 1_767_225_600_000),
            anchor: key(0x32, 2, 1_767_312_000_000),
        };
        let line = what_is_asked(&plan.display()).expect("a line for an enrolment");
        let text = line.text();
        for shown in [&plan.root, &plan.anchor] {
            let identifier = kr_client::pairing::owner::policy_key_identifier(&shown.public_key);
            assert!(text.contains(&identifier), "the whole identifier: {text}");
        }
        assert!(text.contains("2026-01-01 00:00:00 UTC"), "{text}");
        assert!(text.contains("2026-01-02 00:00:00 UTC"), "{text}");
        assert!(text.contains("revision 2"), "{text}");

        let mut later = plan;
        later.anchor.not_before_ms = TimestampMs::new(plan.anchor.not_before_ms.get() + 1_000);
        let other = what_is_asked(&later.display()).expect("a line");
        assert_ne!(text, other.text(), "activation times are printed");
        assert!(what_is_asked(&ConfirmationDisplay::EstablishClock).is_none());
    }

    /// KR-REQ-17.54: what an owner device is asked about exclusive management names every
    /// organisation, in the order the host shows them, and says which way the change goes.
    #[test]
    fn the_command_names_the_organisations_a_change_of_exclusive_management_is_about() {
        let first = OrganisationId::new(Uuid::from_bytes([0x21; 16]));
        let second = OrganisationId::new(Uuid::from_bytes([0x22; 16]));
        let plan = |exclusive| kr_protocol::confirmation::ExclusiveManagementPlan {
            exclusive,
            organisation_ids: [first, second].into_iter().collect(),
        };
        let on = what_is_asked(&plan(true).display()).expect("a line");
        let off = what_is_asked(&plan(false).display()).expect("a line");
        let (on, off) = (on.text(), off.text());
        for text in [&on, &off] {
            assert!(text.contains(&first.to_string()), "{text}");
            assert!(text.contains(&second.to_string()), "{text}");
        }
        assert!(on.contains("make this host exclusively managed"), "{on}");
        assert!(off.contains("end the exclusive management"), "{off}");
    }
}
