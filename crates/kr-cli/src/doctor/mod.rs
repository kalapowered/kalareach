//! `kr doctor`: what this host is, what it is configured from, and what is wrong with it.
//!
//! The command reads and reports. It repairs nothing, and everything it prints comes from the
//! daemon's own answers rather than from this process looking at the machine a second time.
//!
//! # What it prints
//!
//! The default output is a person glancing at a host: the environment, the execution context, the
//! desktop and its capabilities, the sleep policy, and then each check's verdict, with the
//! evidence under only the checks that did not pass. `--verbose` prints the evidence under every
//! check, including the ones that passed, which is what a person sending a report needs and what
//! makes each value's source visible beside it.
//!
//! `--bundle <path>` writes a support bundle: software versions, capabilities, the diagnostics and
//! redacted errors, as one archive. `--include-content` adds the content-bearing diagnostic
//! export, and the command prints what that export will contain before it writes anything.

pub mod bundle;
pub mod configuration;

use kr_protocol::hostinfo::{
    DoctorStatus, EffectiveConfiguration, HostDoctorResult, HostInfoResult,
};
use serde_json::{Value, json};

use crate::error::{CliError, Result};

/// Renders diagnostics.
#[must_use]
pub fn doctor(result: &HostDoctorResult) -> Value {
    json!({
        "healthy": result.healthy,
        "checks": result.checks.iter().map(|check| json!({
            "id": check.id,
            "title": check.title,
            "status": check.status.as_str(),
            "detail": check.detail,
            "remedy": check.remedy.as_ref().cloned(),
        })).collect::<Vec<_>>(),
    })
}

/// Renders this host's effective configuration.
#[must_use]
pub fn configuration_report(effective: &EffectiveConfiguration) -> Value {
    json!({
        "schema_version": effective.schema_version.to_string(),
        "revision": effective.revision.to_string(),
        "document": effective.document,
        "status": {
            "state": effective.status.state.as_str(),
            "detail": effective.status.detail,
        },
        "runtime_directory": effective.runtime_directory,
        "state_directory": effective.state_directory,
        "precedence": effective.precedence,
        "overrides": effective.overrides.iter().map(|entry| json!({
            "variable": entry.variable,
            "preference": entry.preference,
            "position": entry.position.as_str(),
            "why": entry.why,
            "set": entry.set,
        })).collect::<Vec<_>>(),
        "values": effective.values.iter().map(|value| json!({
            "key": value.key,
            "about": value.about,
            "value": value.value,
            "source": value.source.as_str(),
            "origin": value.origin.as_ref().cloned(),
            "variable": value.variable.as_ref().cloned(),
            "effect": value.effect.as_str(),
        })).collect::<Vec<_>>(),
        "ceilings": effective.ceilings.iter().map(|ceiling| json!({
            "key": ceiling.key,
            "configured": ceiling.configured.as_ref().cloned(),
            "value": ceiling.value,
            "narrowed_by": ceiling.narrowed_by.as_ref().cloned(),
            "refused": ceiling.refused,
        })).collect::<Vec<_>>(),
        "secrets": effective.secrets.iter().map(|reference| json!({
            "name": reference.name,
            "store": reference.store,
            "item": reference.item,
        })).collect::<Vec<_>>(),
        "stale_documents": effective.stale_documents,
    })
}

/// Renders diagnostics as lines for a person.
///
/// Every check's verdict, and its evidence under it. `verbose` decides how much evidence: with it,
/// every check shows the value, its source and its location; without it, only a check that did not
/// pass does, because a person looking for what is wrong should not have to read past twenty lines
/// that are right.
#[must_use]
pub fn doctor_lines(result: &HostDoctorResult, verbose: bool) -> String {
    let mut text = String::new();
    for check in &result.checks {
        text.push_str(&format!("{:<14} {}\n", check.status.as_str(), check.title));
        if verbose || check.status != DoctorStatus::Ok {
            for line in check.evidence() {
                text.push_str(&format!("               {line}\n"));
            }
        }
    }
    text.push_str(&summary(result));
    text
}

/// The last line: how many checks ran and how they came out.
#[must_use]
pub fn summary(result: &HostDoctorResult) -> String {
    let mut failed = 0;
    let mut warning = 0;
    let mut not_applicable = 0;
    for check in &result.checks {
        match check.status {
            DoctorStatus::Failed => failed += 1,
            DoctorStatus::Warning => warning += 1,
            DoctorStatus::NotApplicable => not_applicable += 1,
            DoctorStatus::Ok => {}
        }
    }
    format!(
        "{} checks: {} passed, {warning} with something worth knowing, {failed} failed, \
         {not_applicable} not applicable\n",
        result.checks.len(),
        result.checks.len() - warning - failed - not_applicable
    )
}

/// The lines that name the engineering defaults this host makes configurable.
///
/// Section 1 says the engineering defaults "are configurable where the product needs a choice", so
/// each one is printed with the value in force and where that value came from rather than as a
/// constant a person has to go and look up.
#[must_use]
pub fn configurable_lines(effective: &EffectiveConfiguration) -> Vec<String> {
    let mut lines = vec![format!(
        "configuration {} (schema version {}, revision {}): {}",
        effective.document, effective.schema_version, effective.revision, effective.status.detail
    )];
    for value in &effective.values {
        let origin = value
            .variable
            .as_ref()
            .map(|variable| format!(" ({variable})"))
            .or_else(|| value.origin.as_ref().map(|origin| format!(" ({origin})")))
            .unwrap_or_default();
        lines.push(format!(
            "  {} = {} from {}{origin}, applies {}",
            value.key,
            value.value,
            value.source.as_str(),
            value.effect.as_str()
        ));
    }
    for ceiling in &effective.ceilings {
        let narrowed = ceiling
            .narrowed_by
            .as_ref()
            .map(|why| format!(" ({why})"))
            .unwrap_or_default();
        let origin = ceiling
            .origin
            .as_ref()
            .map(|path| format!(" ({path})"))
            .unwrap_or_default();
        lines.push(format!(
            "  {} ceiling {} from {}{origin}, applies {}{}{narrowed}",
            ceiling.key,
            ceiling.value,
            ceiling.source.as_str(),
            ceiling.effect.as_str(),
            if ceiling.refused {
                ", the configured value was more permissive and was refused"
            } else {
                ""
            }
        ));
    }
    lines
}

/// The software versions a support bundle carries.
#[must_use]
pub fn software(info: &HostInfoResult) -> Vec<kr_protocol::hostinfo::SoftwareComponent> {
    vec![
        kr_protocol::hostinfo::SoftwareComponent {
            component: "kr".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        kr_protocol::hostinfo::SoftwareComponent {
            component: "controller build".to_owned(),
            version: info.build_id.to_string(),
        },
        kr_protocol::hostinfo::SoftwareComponent {
            component: "protocol".to_owned(),
            version: info.protocol_version.to_string(),
        },
        kr_protocol::hostinfo::SoftwareComponent {
            component: "platform".to_owned(),
            version: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        },
    ]
}

/// The content-bearing diagnostic export, built only when the person selected it.
///
/// Section 26 keeps this out of an ordinary bundle: a session's shell command line, its working
/// directory and its title are the person's own material rather than a software version. So it is
/// assembled only under `--include-content`, it names what it holds, and the command prints that
/// before anything is written.
///
/// # Errors
///
/// Returns an error when the host cannot be asked for its sessions.
pub async fn content_export(
    client: &mut kr_ipc::client::LocalClient,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> Result<Vec<bundle::Content>> {
    let listed: kr_protocol::session::SessionListResult = client
        .request(
            kr_protocol::method::Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: kr_protocol::scalars::Nullable::some(environment_id),
                include_closed: true,
            },
        )
        .await
        .map_err(CliError::Ipc)?
        .map_err(CliError::Refused)?
        .to_typed()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let bytes = serde_json::to_vec_pretty(&listed)
        .map_err(|error| CliError::Other(format!("this export could not be written: {error}")))?;
    Ok(vec![bundle::Content {
        entry: format!("{}sessions.json", bundle::CONTENT_PREFIX),
        describes: format!(
            "every live and closed session ({} of them) with its shell command line, working \
             directory and title",
            listed.sessions.len()
        ),
        bytes,
    }])
}

#[cfg(test)]
mod tests;
