//! `kr device`: the devices paired with this host, and revoking one.
//!
//! Both go through the control daemon under this user's own authority on this host, which is the
//! local owner's. A listing shows, beside each device, the last authority revision it
//! acknowledged: a device that is offline cannot apply a revocation it has not received, and a
//! person deciding whether a revocation has taken effect needs to see which have answered. A
//! revocation names the device by its identifier and takes every grant the device holds with it.

use kr_ipc::paths::HostPaths;
use kr_protocol::ids::DeviceId;
use kr_protocol::method::Method;
use kr_protocol::sharing::{
    DeviceListParams, DeviceListResult, DeviceRevokeParams, DeviceSummary, RevocationResult,
};

use kr_protocol::error::{ErrorCode, ProtocolError};

use crate::cli::{DeviceCommand, DeviceListArguments, DeviceRevokeArguments};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::report;

/// Runs one `kr device` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: DeviceCommand, json: bool) -> Result<()> {
    match command {
        DeviceCommand::List(arguments) => list(paths, &arguments, json).await,
        DeviceCommand::Revoke(arguments) => revoke(paths, &arguments, json).await,
    }
}

/// `kr device list`.
async fn list(paths: &HostPaths, arguments: &DeviceListArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let listed: DeviceListResult = daemon
        .read(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: arguments.include_revoked,
            },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&listed)?);
        return Ok(());
    }
    if listed.devices.is_empty() {
        println!("no paired devices");
    }
    for device in &listed.devices {
        println!("{}", line(device));
    }
    println!(
        "authority revision {}{}",
        listed.authority_revision,
        if listed.feed_stale {
            "; the revocation feed is unreachable, so what is shown may be stale"
        } else {
            ""
        }
    );
    Ok(())
}

/// `kr device revoke`.
///
/// The daemon answers a revocation of a device it never paired as one that revoked nothing, which
/// is right for a repeat and says nothing useful about a mistyped identifier. So the device is
/// looked for first, among the revoked ones too, and one this host never paired is refused with
/// nothing sent. A device paired between the two calls is refused as unknown, and asking again
/// finds it.
async fn revoke(paths: &HostPaths, arguments: &DeviceRevokeArguments, json: bool) -> Result<()> {
    let device: DeviceId = identifier(&arguments.device, "a device")?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let known: DeviceListResult = daemon
        .read(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: true,
            },
        )
        .await?;
    if !known
        .devices
        .iter()
        .any(|summary| summary.device_id == device)
    {
        return Err(CliError::Refused(ProtocolError::new(
            ErrorCode::ResourceUnavailable,
            format!("no device {device} has been paired with this host, so nothing was revoked"),
        )));
    }
    let revoked: RevocationResult = daemon
        .mutate(
            Method::DeviceRevoke,
            &DeviceRevokeParams { device_id: device },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&revoked)?);
    } else {
        println!(
            "Revoked device {device} and {} grant{}, at authority revision {}.",
            revoked.revoked_grants.len(),
            if revoked.revoked_grants.len() == 1 {
                ""
            } else {
                "s"
            },
            revoked.authority_revision
        );
    }
    Ok(())
}

/// One device as a line for a person.
fn line(device: &DeviceSummary) -> String {
    let standing = if device.revoked {
        "revoked"
    } else if device.manages_host {
        "owner"
    } else {
        "paired"
    };
    let acknowledged = device.acknowledged_revision.as_ref().map_or_else(
        || "no acknowledgement yet".to_owned(),
        |revision| format!("acknowledged revision {revision}"),
    );
    format!(
        "{}  {standing:<8} {}  {acknowledged}",
        device.device_id, device.display_name
    )
}
