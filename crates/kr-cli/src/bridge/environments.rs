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
    let access_class = access(&arguments.access)?;
    let target = match access_class {
        EnvironmentAccess::Container => resolve_container_target(&arguments.target)?,
        _ => arguments.target.clone(),
    };
    let environment_id = match arguments.environment_id.as_deref() {
        Some(text) => text
            .parse::<EnvironmentId>()
            .map_err(|_| CliError::Usage(format!("{text} is not an environment identifier")))?,
        None => {
            match query_helper_identity(access_class, &target, &arguments.user, &arguments.helper)
                .await
            {
                Ok(id) => id,
                Err(err) => {
                    return Err(CliError::Usage(format!(
                        "could not obtain environment identity from the destination helper ({err}); \
                     supply --environment-id <uuid> or start the environment with the helper installed"
                    )));
                }
            }
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

/// Resolves a container target to a full container identifier.
fn resolve_container_target(target: &str) -> Result<String> {
    if kr_protocol::identity::is_container_identifier(target) {
        return Ok(target.to_owned());
    }
    // Attempt to resolve reusable human name to full container ID
    let output = std::process::Command::new("podman")
        .args(["container", "inspect", "--format", "{{.Id}}", target])
        .stdin(std::process::Stdio::null())
        .output();
    if let Ok(output) = output
        && output.status.success()
    {
        let id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if kr_protocol::identity::is_container_identifier(&id) {
            return Ok(id);
        }
    }
    Err(CliError::Usage(format!(
        "'{target}' is a container name rather than a container identifier, and could not be \
         resolved to a container ID; pass the container identifier"
    )))
}

/// Queries the destination helper to obtain its verified environment identity.
async fn query_helper_identity(
    access: EnvironmentAccess,
    target: &str,
    user: &str,
    helper: &str,
) -> std::result::Result<EnvironmentId, String> {
    if !access.is_process_bridge() {
        return Err(
            "SSH and paired environments must be enrolled with --environment-id".to_owned(),
        );
    }
    let (program, arguments) = match access {
        EnvironmentAccess::WslDistribution => (
            "wsl.exe".to_owned(),
            vec![
                "--distribution".to_owned(),
                target.to_owned(),
                "--user".to_owned(),
                user.to_owned(),
                "--exec".to_owned(),
                helper.to_owned(),
                "bridge".to_owned(),
                "--stdio".to_owned(),
            ],
        ),
        EnvironmentAccess::Container => (
            "podman".to_owned(),
            vec![
                "exec".to_owned(),
                "--interactive".to_owned(),
                "--user".to_owned(),
                user.to_owned(),
                "--".to_owned(),
                target.to_owned(),
                helper.to_owned(),
                "bridge".to_owned(),
                "--stdio".to_owned(),
            ],
        ),
        _ => return Err("not a process bridge".to_owned()),
    };
    let mut child = tokio::process::Command::new(&program)
        .args(&arguments)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to start helper: {error}"))?;

    let mut stdin = child.stdin.take().ok_or_else(|| "no stdin".to_owned())?;
    let mut stdout = child.stdout.take().ok_or_else(|| "no stdout".to_owned())?;

    let hello =
        kr_protocol::identity::BridgeFrame::Hello(Box::new(kr_protocol::identity::BridgeHello {
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            build_id: crate::build_id(),
            origin_environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            origin_ingress: kr_protocol::actor::ActorIngress::LocalIpc,
            already_bridged: false,
            target: kr_protocol::identity::BridgeTarget::Controller,
        }));
    let encoded = kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control)
        .encode_message(&hello)
        .map_err(|error| error.to_string())?;
    tokio::io::AsyncWriteExt::write_all(&mut stdin, &encoded)
        .await
        .map_err(|error| error.to_string())?;
    tokio::io::AsyncWriteExt::flush(&mut stdin)
        .await
        .map_err(|error| error.to_string())?;

    let mut prefix = [0_u8; 4];
    tokio::io::AsyncReadExt::read_exact(&mut stdout, &mut prefix)
        .await
        .map_err(|error| error.to_string())?;
    let len = u32::from_be_bytes(prefix) as usize;
    if len > kr_protocol::frame::StreamKind::Control.max_payload_len() {
        return Err("oversized frame from helper".to_owned());
    }
    let mut payload = vec![0_u8; len];
    tokio::io::AsyncReadExt::read_exact(&mut stdout, &mut payload)
        .await
        .map_err(|error| error.to_string())?;
    let frame: kr_protocol::identity::BridgeFrame = kr_cbor::from_canonical_slice(
        &payload,
        &kr_protocol::frame::StreamKind::Control.cbor_limits(),
    )
    .map_err(|error| error.to_string())?;

    let _ = child.kill().await;

    match frame {
        kr_protocol::identity::BridgeFrame::HelloAck(ack) => Ok(ack.environment_id),
        kr_protocol::identity::BridgeFrame::Refused(err) => Err(err.to_string()),
        _ => Err("unexpected frame from helper".to_owned()),
    }
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
