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
    let environment_id = match arguments.environment_id.as_deref() {
        Some(text) => text
            .parse::<EnvironmentId>()
            .map_err(|_| CliError::Usage(format!("{text} is not an environment identifier")))?,
        // Until the environment has answered for itself, the record names an identity this host
        // allocated for it. A refresh replaces it with the one that environment reports.
        None => EnvironmentId::new(kr_ipc::new_uuid()),
    };
    let enrolment = EnvironmentEnrolment {
        environment_id,
        access: access(&arguments.access)?,
        label: arguments.label.clone(),
        target: arguments.target.clone(),
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

/// Resolves the label a person typed to the identity the record carries.
///
/// A label selects a record; the identity is what every later step compares. Two records that
/// share a label are refused rather than resolved to the first of them.
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
