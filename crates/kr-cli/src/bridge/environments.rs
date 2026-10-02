//! `kr bridge list`, `enrol`, `forget` and `refresh`.
//!
//! These reach this host's own control daemon, which owns the owner-approved record and the cache
//! built from it. The command translates what a person typed and prints what the daemon answered;
//! it decides nothing about whether an environment is running, because only the daemon has asked.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::identity::{
    EnvironmentAccess, EnvironmentEnrolParams, EnvironmentEnrolResult, EnvironmentEnrolment,
    EnvironmentForgetParams, EnvironmentForgetResult, EnvironmentInventoryParams,
    EnvironmentInventoryResult, EnvironmentPresence, EnvironmentRefreshParams,
    EnvironmentRefreshResult, ObservationSource,
};
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, TimestampMs};

use kr_controller::bridge::launch::CONTAINER_RUNTIME;

use crate::cli::{
    BridgeEnrolArguments, BridgeForgetArguments, BridgeListArguments, BridgeRefreshArguments,
};
use crate::error::{CliError, Result};
use crate::resolve;

/// Parses the access class a person typed.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for anything else.
pub fn access(text: &str) -> Result<EnvironmentAccess> {
    match text {
        "wsl" => Ok(EnvironmentAccess::WslDistribution),
        "container" => Ok(EnvironmentAccess::Container),
        "ssh" => Ok(EnvironmentAccess::SshHost),
        "paired" => Ok(EnvironmentAccess::PairedHost),
        _ => Err(CliError::Usage(Shown::said(
            "--access takes an access class: wsl, container, ssh or paired",
        ))),
    }
}

/// Reads the cached inventory.
///
/// # Errors
///
/// Returns the daemon's refusal, or a transport failure.
pub async fn list(arguments: &BridgeListArguments) -> Result<EnvironmentInventoryResult> {
    let selected = match arguments.access.as_deref() {
        Some(text) => Nullable::some(access(text)?),
        None => Nullable::null(),
    };
    let paths = kr_ipc::paths::HostPaths::discover()?;
    let known = resolve::select(&paths, None)?;
    let mut client = resolve::open_controller(&known.paths, crate::build_id()).await?;
    let answer = client
        .request(
            Method::EnvironmentInventory,
            &EnvironmentInventoryParams { access: selected },
        )
        .await?
        .map_err(CliError::Refused)?;
    answer.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the host's answer is not an inventory: {}",
            Shown::cbor(&error)
        ))
    })
}

/// Records an environment this host may reach.
///
/// # Errors
///
/// Returns the daemon's refusal, a usage failure, or a transport failure.
pub async fn enrol(arguments: &BridgeEnrolArguments) -> Result<EnvironmentEnrolResult> {
    let paths = kr_ipc::paths::HostPaths::discover()?;
    let known = resolve::select(&paths, None)?;
    let access_class = access(&arguments.access)?;
    let target = match access_class {
        EnvironmentAccess::Container => resolve_container_target(&arguments.target)?,
        _ => arguments.target.clone(),
    };
    let named = match arguments.environment_id.as_deref() {
        Some(text) => Some(text.parse::<EnvironmentId>().map_err(|_| {
            CliError::Usage(Shown::said(
                "--environment-id takes an environment identifier, a UUID",
            ))
        })?),
        None => None,
    };
    let environment_id = match named {
        Some(named) if !arguments.probe => named,
        // Asking a destination which environment it is means running the helper inside it, and
        // running anything inside a stopped environment starts it. Section 3 leaves starting to
        // refresh, create and attach, so a probe is asked for by name and is put only to an
        // environment that is already running. An SSH host is asked through ssh, which starts
        // nothing.
        _ if arguments.probe => {
            if access_class != EnvironmentAccess::SshHost {
                probe_permitted(access_class, &target, &arguments.user, &arguments.helper)?;
            }
            let (answered, answered_user) =
                query_helper_identity(access_class, &target, &arguments.user, &arguments.helper)
                    .await
                    .map_err(|error| {
                        CliError::Usage(shown!(
                            "the destination did not say which environment it is ({}); pass \
                             --environment-id <uuid> instead",
                            error
                        ))
                    })?;
            // A refresh checks the user the helper runs as against the record, so a record that
            // names another would fail at its first one. It is refused here, where the person can
            // say which user they meant.
            if answered_user != arguments.user {
                return Err(CliError::Usage(Shown::said(
                    "the helper in the destination runs as a different user from the one --user \
                     names; name the user the helper runs as there",
                )));
            }
            // A socket forwarded from here is answered by this host's own daemon, so an answer
            // that is one of this host's own environments says nothing about the destination.
            if resolve::environments(&paths)?
                .iter()
                .any(|known| known.environment_id == answered)
            {
                return Err(CliError::Usage(Shown::said(
                    "the destination answered as one of this host's own environments, so it is \
                     not another one; socket forwarding does not install the integration",
                )));
            }
            if named.is_some_and(|named| named != answered) {
                return Err(CliError::Usage(Shown::said(
                    "the destination is a different environment from the one --environment-id \
                     names",
                )));
            }
            answered
        }
        _ => {
            return Err(CliError::Usage(Shown::said(
                "an enrolment records the environment's own identity: pass --environment-id \
                 <uuid>, or start the environment and pass --probe to ask it",
            )));
        }
    };
    let enrolment = EnvironmentEnrolment {
        environment_id,
        access: access_class,
        label: arguments.label.clone(),
        target,
        os_user: arguments.user.clone(),
        helper_path: arguments.helper.clone(),
        clipboard_destination: match arguments.clipboard.clone() {
            Some(destination) => Nullable::some(destination),
            None => Nullable::null(),
        },
        approved_at_ms: TimestampMs::new(0),
    };
    enrolment
        .validate()
        .map_err(|error| CliError::Usage(shown!("{}", error)))?;
    let mut client = resolve::open_controller(&known.paths, crate::build_id()).await?;
    let answer = client
        .mutate(
            Method::EnvironmentEnrol,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(known.environment_id),
            &EnvironmentEnrolParams { enrolment },
        )
        .await?
        .map_err(CliError::Refused)?;
    answer.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the host's answer is not an enrolment: {}",
            Shown::cbor(&error)
        ))
    })
}

/// Resolves what a person typed to the identifier the container runtime issued.
///
/// Section 3: a reused human container name is not an identity, and neither is a short prefix of
/// one, because a runtime resolves a prefix to whichever container carries it now. So every target
/// is put to the runtime and the identifier it answers with is what the record keeps. A name that
/// happens to be hexadecimal takes the same path as any other name.
fn resolve_container_target(target: &str) -> Result<String> {
    let output = std::process::Command::new(CONTAINER_RUNTIME)
        .args(["container", "inspect", "--format", "{{.Id}}", "--", target])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| {
            CliError::Usage(shown!(
                "{} could not be run to resolve the target to a container identifier ({}); pass \
                 the identifier the runtime issued",
                CONTAINER_RUNTIME,
                Shown::io(&error)
            ))
        })?;
    // Neither the target nor what the runtime printed is repeated: the target is what was typed,
    // and the runtime's own output is whatever it chose to say.
    if !output.status.success() {
        return Err(CliError::Usage(shown!(
            "{} knows no container by that name ({})",
            CONTAINER_RUNTIME,
            output.status
        )));
    }
    let resolved = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !kr_protocol::identity::is_container_identifier(&resolved) {
        return Err(CliError::Usage(shown!(
            "{} answered with something that is not the whole identifier a container carries",
            CONTAINER_RUNTIME
        )));
    }
    Ok(resolved)
}

/// Decides whether the destination may be asked which environment it is.
///
/// Observing starts nothing, so the platform is asked first. A destination that is not running is
/// refused here rather than started by the question, because starting one belongs to refresh,
/// create and attach.
fn probe_permitted(
    access: EnvironmentAccess,
    target: &str,
    user: &str,
    helper: &str,
) -> Result<()> {
    let observed = kr_controller::bridge::platform::destination_state(access, target, user, helper)
        .map_err(|error| {
            CliError::Usage(shown!(
                "this host could not ask whether the destination is running ({}), so it will not \
                 start it by asking; pass --environment-id <uuid> instead",
                error.code()
            ))
        })?;
    probe_decision(observed)
}

/// The rule a probe follows once the platform has answered.
fn probe_decision(observed: EnvironmentPresence) -> Result<()> {
    match observed {
        EnvironmentPresence::Running => Ok(()),
        EnvironmentPresence::EnvironmentStopped | EnvironmentPresence::Stale => {
            Err(CliError::Usage(Shown::said(
                "the destination is not running, and asking it which environment it is would \
                 start it; start it yourself, or pass --environment-id <uuid>",
            )))
        }
    }
}

/// Asks the destination which environment it is, and which user its helper runs as.
///
/// The helper runs inside the destination and acknowledges with that environment's own identity,
/// the user it runs as and the role it serves. The invoker checks the protocol major and the role;
/// the identity is what is being learned here, so there is nothing yet to compare it against. An
/// SSH host is asked through ssh, which starts nothing, and a paired environment has no process
/// bridge and is enrolled with the identity its owner already knows.
async fn query_helper_identity(
    access: EnvironmentAccess,
    target: &str,
    user: &str,
    helper: &str,
) -> std::result::Result<(EnvironmentId, String), Shown> {
    // What the launch and the destination said is not repeated: it carries the target, the user
    // and whatever the destination wrote.
    let command = kr_controller::bridge::launch::identity_command(access, target, user, helper)
        .map_err(|_| Shown::said("the helper's command could not be built"))?;
    let hello = kr_protocol::identity::BridgeHello {
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        build_id: crate::build_id(),
        origin_environment_id: origin_environment_id(),
        // This is a person at this host's own command line. Nothing else may reach a bridge.
        origin_ingress: kr_protocol::actor::ActorIngress::LocalIpc,
        already_bridged: false,
        // Asking which environment this is starts nothing: enrolment is not a create or an attach.
        start: false,
        target: kr_protocol::identity::BridgeTarget::Controller,
    };
    let acknowledgement = kr_controller::bridge::invoke::discover(&command, &hello)
        .await
        .map_err(|_| Shown::said("the helper did not answer with its environment"))?;
    Ok((acknowledgement.environment_id, acknowledgement.os_user))
}

/// The environment the invocation is made from, for the opening frame.
///
/// The destination records where a request came from, so the opening names this installation
/// rather than a value made up for the occasion. A host that has no environment of its own yet
/// still opens bridges, and says so with the nil identity rather than inventing one.
#[must_use]
pub fn origin_environment_id() -> EnvironmentId {
    kr_ipc::paths::HostPaths::discover()
        .ok()
        .and_then(|paths| resolve::select(&paths, None).ok())
        .map_or_else(
            || EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([0; 16])),
            |known| known.environment_id,
        )
}

/// The environment a command that creates or attaches acts in.
pub enum Selected {
    /// An environment of this installation, on this host.
    Local(crate::resolve::KnownEnvironment),
    /// An enrolled environment this host reaches through a process bridge.
    Enrolled(Box<EnvironmentEnrolment>),
}

kr_client::debug_as_name!(Selected);

/// Resolves what `--environment` named: one of this host's own environments, else an enrolled one.
///
/// A local environment is selected by its identifier, as it always was, and wins. What names no
/// local environment is looked for in this host's own enrolled environments, by label or by
/// identifier, which this host's daemon holds: the owner-approved record stays the daemon's, and
/// a selector that matches two records is refused rather than resolved to the first of them.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for a name that is neither, for one that matches two enrolled
/// environments, and for an environment that is not reached by a process bridge, and the daemon's
/// refusal or a transport failure when its record cannot be read.
pub async fn selected(paths: &kr_ipc::paths::HostPaths, named: Option<&str>) -> Result<Selected> {
    let local = match resolve::select(paths, named) {
        Ok(known) => return Ok(Selected::Local(known)),
        Err(error @ (CliError::Usage(_) | CliError::HostUnavailable(_))) => error,
        Err(other) => return Err(other),
    };
    let Some(wanted) = named else {
        return Err(local);
    };
    let known = resolve::select(paths, None)?;
    let mut client = resolve::open_controller(&known.paths, crate::build_id()).await?;
    let inventory = inventory(&mut client).await?;
    let mut matched = inventory
        .rows
        .into_iter()
        .filter(|row| row.enrolment.selected_by(wanted));
    let Some(first) = matched.next() else {
        // Neither a local environment nor an enrolled one, so what the local lookup said stands.
        return Err(local);
    };
    if matched.next().is_some() {
        return Err(CliError::Usage(Shown::said(
            "that name selects more than one enrolled environment; give the environment \
             identifier",
        )));
    }
    if !first.enrolment.access.is_process_bridge() {
        return Err(CliError::Usage(Shown::said(
            "that environment is not reached by a process bridge: run kr on it after logging in \
             to it, or reach it through its own pairing",
        )));
    }
    Ok(Selected::Enrolled(Box::new(first.enrolment)))
}

/// Reads the cached inventory over a connection that is already open.
async fn inventory(client: &mut kr_ipc::client::LocalClient) -> Result<EnvironmentInventoryResult> {
    let answer = client
        .request(
            Method::EnvironmentInventory,
            &EnvironmentInventoryParams {
                access: Nullable::null(),
            },
        )
        .await?
        .map_err(CliError::Refused)?;
    answer.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the host's answer is not an inventory: {}",
            Shown::cbor(&error)
        ))
    })
}

/// Removes one enrolled environment.
///
/// # Errors
///
/// Returns the daemon's refusal, or a transport failure.
pub async fn forget(arguments: &BridgeForgetArguments) -> Result<EnvironmentForgetResult> {
    let paths = kr_ipc::paths::HostPaths::discover()?;
    let known = resolve::select(&paths, None)?;
    let mut client = resolve::open_controller(&known.paths, crate::build_id()).await?;
    let environment_id = labelled(&mut client, &arguments.label).await?;
    let answer = client
        .mutate(
            Method::EnvironmentForget,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(known.environment_id),
            &EnvironmentForgetParams { environment_id },
        )
        .await?
        .map_err(CliError::Refused)?;
    answer.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the host's answer is not a removal: {}",
            Shown::cbor(&error)
        ))
    })
}

/// Observes one enrolled environment now.
///
/// # Errors
///
/// Returns the daemon's refusal, or a transport failure.
pub async fn refresh(arguments: &BridgeRefreshArguments) -> Result<EnvironmentRefreshResult> {
    let paths = kr_ipc::paths::HostPaths::discover()?;
    let known = resolve::select(&paths, None)?;
    let mut client = resolve::open_controller(&known.paths, crate::build_id()).await?;
    let environment_id = labelled(&mut client, &arguments.label).await?;
    let answer = client
        .mutate(
            Method::EnvironmentRefresh,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(known.environment_id),
            &EnvironmentRefreshParams {
                environment_id,
                start: arguments.start,
            },
        )
        .await?
        .map_err(CliError::Refused)?;
    answer.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the host's answer is not a refresh: {}",
            Shown::cbor(&error)
        ))
    })
}

/// Resolves what a person typed to the identity the record carries.
///
/// A label selects a record; so does the environment identifier, which is how two records that
/// share a label are told apart. Either way the identity is what every later step compares, and a
/// selector that matches two records is refused rather than resolved to the first of them.
async fn labelled(client: &mut kr_ipc::client::LocalClient, label: &str) -> Result<EnvironmentId> {
    let inventory = inventory(client).await?;
    let mut matched = inventory
        .rows
        .iter()
        .filter(|row| row.enrolment.selected_by(label));
    let Some(first) = matched.next() else {
        return Err(CliError::Usage(Shown::said(
            "this host has no enrolled environment by that label",
        )));
    };
    if matched.next().is_some() {
        return Err(CliError::Usage(Shown::said(
            "that label names more than one enrolled environment; give the environment identifier",
        )));
    }
    Ok(first.enrolment.environment_id)
}

/// Returns the text a person reads for one presence value.
#[must_use]
pub const fn presence_text(status: EnvironmentPresence) -> &'static str {
    match status {
        EnvironmentPresence::Running => "running when last seen",
        EnvironmentPresence::EnvironmentStopped => "stopped when last seen",
        EnvironmentPresence::Stale => "not seen recently",
    }
}

/// Returns the text a person reads for where an observation came from.
#[must_use]
pub const fn observation_text(observation: ObservationSource) -> &'static str {
    match observation {
        ObservationSource::Cache => "from this host's cache",
        ObservationSource::Refresh => "observed now",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_is_put_only_to_an_environment_that_is_already_running() {
        probe_decision(EnvironmentPresence::Running).expect("running is asked");
        for quiet in [
            EnvironmentPresence::EnvironmentStopped,
            EnvironmentPresence::Stale,
        ] {
            let refused = probe_decision(quiet).expect_err("not asked");
            assert!(refused.to_string().contains("would start it"), "{refused}");
        }
    }
}
