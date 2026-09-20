//! `kr bridge list`, `enrol`, `forget` and `refresh`.
//!
//! These reach this host's own control daemon, which owns the owner-approved record and the cache
//! built from it. The command translates what a person typed and prints what the daemon answered;
//! it decides nothing about whether an environment is running, because only the daemon has asked.

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

use kr_controller::bridge::launch::CONTAINER_RUNTIME as RUNTIME;

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
        other => Err(CliError::Usage(format!(
            "{other} is not an access class; choose wsl, container, ssh or paired"
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
    answer
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer is not an inventory: {error}")))
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
    let environment_id = match arguments.environment_id.as_deref() {
        Some(text) => text
            .parse::<EnvironmentId>()
            .map_err(|_| CliError::Usage(format!("{text} is not an environment identifier")))?,
        // Asking a destination which environment it is means running the helper inside it, and
        // running anything inside a stopped environment starts it. Section 3 leaves starting to
        // refresh, create and attach, so a probe is asked for by name and is put only to an
        // environment that is already running.
        None if arguments.probe => {
            probe_permitted(access_class, &target, &arguments.user, &arguments.helper)?;
            query_helper_identity(access_class, &target, &arguments.user, &arguments.helper)
                .await
                .map_err(|error| {
                    CliError::Usage(format!(
                        "the destination did not say which environment it is ({error}); pass \
                         --environment-id <uuid> instead"
                    ))
                })?
        }
        None => {
            return Err(CliError::Usage(
                "an enrolment records the environment's own identity: pass --environment-id \
                 <uuid>, or start the environment and pass --probe to ask it"
                    .to_owned(),
            ));
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
        .map_err(|error| CliError::Usage(error.to_string()))?;
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
    answer
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer is not an enrolment: {error}")))
}

/// Resolves what a person typed to the identifier the container runtime issued.
///
/// Section 3: a reused human container name is not an identity, and neither is a short prefix of
/// one, because a runtime resolves a prefix to whichever container carries it now. So every target
/// is put to the runtime and the identifier it answers with is what the record keeps. A name that
/// happens to be hexadecimal takes the same path as any other name.
fn resolve_container_target(target: &str) -> Result<String> {
    let output = std::process::Command::new(RUNTIME)
        .args(["container", "inspect", "--format", "{{.Id}}", "--", target])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| {
            CliError::Usage(format!(
                "{RUNTIME} could not be run to resolve {target} to a container identifier \
                 ({error}); pass the identifier the runtime issued"
            ))
        })?;
    if !output.status.success() {
        return Err(CliError::Usage(format!(
            "{RUNTIME} knows no container {target}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let resolved = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !kr_protocol::identity::is_container_identifier(&resolved) {
        return Err(CliError::Usage(format!(
            "{RUNTIME} answered {resolved:?} for {target}, which is not the whole identifier a \
             container carries"
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
            CliError::Usage(format!(
                "this host could not ask whether {target} is running, so it will not start it by \
                 asking ({error}); pass --environment-id <uuid> instead"
            ))
        })?;
    probe_decision(observed, target)
}

/// The rule a probe follows once the platform has answered.
fn probe_decision(observed: EnvironmentPresence, target: &str) -> Result<()> {
    match observed {
        EnvironmentPresence::Running => Ok(()),
        EnvironmentPresence::EnvironmentStopped | EnvironmentPresence::Stale => {
            Err(CliError::Usage(format!(
                "{target} is not running, and asking it which environment it is would start it; \
                 start it yourself, or pass --environment-id <uuid>"
            )))
        }
    }
}

/// Asks the destination which environment it is.
///
/// The helper runs inside the destination and acknowledges with that environment's own identity,
/// the user it runs as and the role it serves. The invoker checks the protocol major and the role;
/// the identity is what is being learned here, so there is nothing yet to compare it against. An
/// SSH or paired environment has no process bridge, and is enrolled with the identity its owner
/// already knows.
async fn query_helper_identity(
    access: EnvironmentAccess,
    target: &str,
    user: &str,
    helper: &str,
) -> std::result::Result<EnvironmentId, String> {
    let command = kr_controller::bridge::launch::helper_command(access, target, user, helper)
        .map_err(|error| error.to_string())?;
    let hello = kr_protocol::identity::BridgeHello {
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        build_id: crate::build_id(),
        origin_environment_id: origin_environment_id(),
        // This is a person at this host's own command line. Nothing else may reach a bridge.
        origin_ingress: kr_protocol::actor::ActorIngress::LocalIpc,
        already_bridged: false,
        target: kr_protocol::identity::BridgeTarget::Controller,
    };
    let acknowledgement = kr_controller::bridge::invoke::discover(&command, &hello)
        .await
        .map_err(|refusal| refusal.to_string())?;
    Ok(acknowledgement.environment_id)
}

/// The environment the invocation is made from, for the opening frame.
///
/// The destination records where a request came from, so the opening names this installation
/// rather than a value made up for the occasion. A host that has no environment of its own yet
/// still opens bridges, and says so with the nil identity rather than inventing one.
fn origin_environment_id() -> EnvironmentId {
    kr_ipc::paths::HostPaths::discover()
        .ok()
        .and_then(|paths| resolve::select(&paths, None).ok())
        .map_or_else(
            || EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([0; 16])),
            |known| known.environment_id,
        )
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
    answer
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer is not a removal: {error}")))
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
    answer
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer is not a refresh: {error}")))
}

/// Resolves what a person typed to the identity the record carries.
///
/// A label selects a record; so does the environment identifier, which is how two records that
/// share a label are told apart. Either way the identity is what every later step compares, and a
/// selector that matches two records is refused rather than resolved to the first of them.
async fn labelled(client: &mut kr_ipc::client::LocalClient, label: &str) -> Result<EnvironmentId> {
    let answer = client
        .request(
            Method::EnvironmentInventory,
            &EnvironmentInventoryParams {
                access: Nullable::null(),
            },
        )
        .await?
        .map_err(CliError::Refused)?;
    let inventory: EnvironmentInventoryResult = answer.to_typed().map_err(|error| {
        CliError::Other(format!("the host's answer is not an inventory: {error}"))
    })?;
    let mut matched = inventory
        .rows
        .iter()
        .filter(|row| row.enrolment.selected_by(label));
    let Some(first) = matched.next() else {
        return Err(CliError::Usage(format!(
            "this host has no enrolled environment called {label}"
        )));
    };
    if matched.next().is_some() {
        return Err(CliError::Usage(format!(
            "{label} names more than one enrolled environment; give the environment identifier"
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
        probe_decision(EnvironmentPresence::Running, "Ubuntu-24.04").expect("running is asked");
        for quiet in [
            EnvironmentPresence::EnvironmentStopped,
            EnvironmentPresence::Stale,
        ] {
            let refused = probe_decision(quiet, "Ubuntu-24.04").expect_err("not asked");
            assert!(refused.to_string().contains("would start it"), "{refused}");
        }
    }
}
