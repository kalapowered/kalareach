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

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::hostinfo::{
    DoctorCheck, DoctorStatus, EffectiveConfiguration, HostDoctorResult, HostInfoResult,
};
use serde_json::{Value, json};

use crate::error::{CliError, Result};

/// Adds the service start's own check to the daemon's diagnostics, where there is anything of it
/// to report: whether the definition kr wrote is the one `kr new` would have the service manager
/// start the daemon from.
///
/// The daemon does not know how it was started, so this command, which wrote the definition,
/// looks at it. An environment that neither chooses the service start nor has a definition of it
/// installed gets no check.
#[must_use]
pub fn with_startup(
    mut result: HostDoctorResult,
    environment: &kr_ipc::paths::EnvironmentPaths,
) -> HostDoctorResult {
    if let Some(check) = startup_check(environment) {
        result.healthy &= !check.status.is_failure();
        result.checks.push(check);
    }
    result
}

/// The identifier the service start's check is published under.
pub const STARTUP_CHECK: &str = "startup-definition";

/// What the check examines.
#[cfg(unix)]
const STARTUP_TITLE: &str =
    "The service definition kr new has the service manager start the daemon from";

/// The identifier the standalone start's check is published under on Windows.
pub const TASK_CHECK: &str = "startup-task";

/// What the standalone start's check examines on Windows.
#[cfg(windows)]
const TASK_TITLE: &str = "The scheduled task kr new has start the daemon";

/// The standalone start's check on Windows, when there is anything of it to report: whose the
/// environment's scheduled task is, whether it is the one this installation registers, and that the
/// daemon it starts runs only while the user is signed in.
///
/// An environment that neither chooses the standalone start nor has a task of its own registered
/// gets no check.
#[cfg(windows)]
fn startup_check(environment: &kr_ipc::paths::EnvironmentPaths) -> Option<DoctorCheck> {
    use kr_controller::supervision::windows::Standing;
    use kr_protocol::hostinfo::configuration::ControllerStartup;
    use kr_protocol::hostinfo::export::Sentence;

    let chosen = crate::startup::Chosen::read(environment);
    let selected = chosen.controller == Some(ControllerStartup::Standalone);
    let report = crate::startup::task_report(environment, selected)?;
    let task = Sentence::new()
        .stated("the scheduled task of environment ")
        .identifier(&environment.environment_id());
    if !selected {
        return Some(DoctorCheck::new(
            TASK_CHECK,
            TASK_TITLE,
            DoctorStatus::Warning,
            task.stated(
                " is still registered, and startup.controller no longer chooses the standalone \
                 start; nothing uses it",
            ),
            Some(
                "run kr host startup --clear to remove it, or kr host startup --set standalone to \
                 use it",
            ),
        ));
    }
    let (status, found, remedy) = match &report.standing {
        _ if report.usable() => (
            DoctorStatus::Ok,
            " is this environment's own and the one this installation registers; the daemon it \
             starts runs only while you are signed in, so signing out ends it and every session",
            None,
        ),
        Ok(Standing::Owned(differences)) if differences.is_empty() => (
            DoctorStatus::Failed,
            " is this environment's own and runs this installation's kr-controller, which is not \
             there",
            Some("install kr again, then run kr host startup --set standalone"),
        ),
        Ok(Standing::Owned(_)) => (
            DoctorStatus::Failed,
            " is this environment's own and differs from the one this installation registers",
            Some("run kr host startup --set standalone to repair it"),
        ),
        Ok(Standing::Absent) => (
            DoctorStatus::Failed,
            " is not registered",
            Some("run kr host startup --set standalone to register it"),
        ),
        Ok(Standing::Foreign(_)) => (
            DoctorStatus::Failed,
            " is not registered: a task under its name is not this environment's own",
            Some("remove that task, then run kr host startup --set standalone"),
        ),
        Err(_) => (
            DoctorStatus::Failed,
            " cannot be read",
            Some("run kr host startup to see why"),
        ),
    };
    Some(DoctorCheck::new(
        TASK_CHECK,
        TASK_TITLE,
        status,
        Sentence::new()
            .stated("startup.controller is ")
            .term("standalone")
            .stated(": ")
            .sentence(&task)
            .stated(found),
        remedy,
    ))
}

/// The service start's check, when there is anything of it to report.
#[cfg(unix)]
fn startup_check(environment: &kr_ipc::paths::EnvironmentPaths) -> Option<DoctorCheck> {
    use kr_protocol::hostinfo::configuration::ControllerStartup;
    use kr_protocol::hostinfo::export::Sentence;

    use crate::service_manager::State;

    let chosen = crate::startup::Chosen::read(environment);
    let selected = chosen.controller == Some(ControllerStartup::Service);
    let inspection = match crate::service_manager::inspect(environment, selected)? {
        Ok(inspection) => inspection,
        Err(_) => {
            return Some(DoctorCheck::new(
                STARTUP_CHECK,
                STARTUP_TITLE,
                DoctorStatus::Failed,
                Sentence::new().stated(
                    "what the service start has for this environment cannot be established",
                ),
                Some(
                    "run kr host startup to see why, then kr host startup --set service or --clear",
                ),
            ));
        }
    };
    let started = Sentence::new()
        .stated(inspection.manager.as_str())
        .stated(" starts the daemon of environment ")
        .identifier(&environment.environment_id());
    if !selected {
        return Some(DoctorCheck::new(
            STARTUP_CHECK,
            STARTUP_TITLE,
            DoctorStatus::Warning,
            started.stated(
                " from a definition kr wrote for the service start, which startup.controller no \
                 longer chooses; nothing uses it",
            ),
            Some(
                "run kr host startup --clear to remove it, or kr host startup --set service to use it",
            ),
        ));
    }
    let (status, found, remedy) = match inspection.state {
        State::Matches => (
            DoctorStatus::Ok,
            " from the definition kr wrote, which matches what kr wrote",
            None,
        ),
        State::Missing => (
            DoctorStatus::Failed,
            ", and the definition kr wrote for it is missing",
            Some("run kr host startup --set service to write it again"),
        ),
        State::Changed => (
            DoctorStatus::Failed,
            ", and the definition kr wrote for it was changed after kr wrote it",
            Some("restore the definition or remove it, then run kr host startup --set service"),
        ),
        State::Foreign => (
            DoctorStatus::Failed,
            ", and a definition kr did not write is where its definition belongs",
            Some("remove that definition, then run kr host startup --set service"),
        ),
        State::Outdated => (
            DoctorStatus::Failed,
            ", from a definition that names another program, other directories or another domain \
             than this installation's",
            Some("run kr host startup --set service to write this installation's"),
        ),
        State::Unrecorded => (
            DoctorStatus::Failed,
            ", from a definition that is what kr writes, and kr has no record of writing it",
            Some("run kr host startup --set service to record it"),
        ),
    };
    Some(DoctorCheck::new(
        STARTUP_CHECK,
        STARTUP_TITLE,
        status,
        Sentence::new()
            .stated("startup.controller is ")
            .term("service")
            .stated(": ")
            .sentence(&started)
            .stated(found),
        remedy,
    ))
}

/// Renders diagnostics.
#[must_use]
pub fn doctor(result: &HostDoctorResult) -> Value {
    json!({
        "healthy": result.healthy,
        "checks": result.checks.iter().map(|check| json!({
            "id": check.id(),
            "title": check.title(),
            "status": check.status.as_str(),
            "detail": check.detail(),
            "remedy": check.remedy(),
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
        // Whether the values below are what this host is acting on, and what its workers still
        // owe a fence one of them raised. A reader that saw only the values would have no way to
        // tell a configuration in force from one that could not be applied.
        "not_in_force": effective.not_in_force.as_ref().cloned(),
        "fence_outstanding": effective.fence_outstanding.as_ref().cloned(),
        "runtime_directory": effective.runtime_directory,
        "state_directory": effective.state_directory,
        // Section 26's native OS-appropriate locations: where this host's files are, and the rule
        // this platform followed to put them there. Both, because a rule without the resolved path
        // does not say where anything is, and a path without the rule does not say where the next
        // one would go.
        "locations": effective.locations.iter().map(|location| json!({
            "what": location.what,
            "documented": location.documented,
        })).collect::<Vec<_>>(),
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
            "about": value.about(),
            "value": value.value(),
            // What the value is made of, which is what decides how it leaves this host. A reader
            // that sees a path and a word in the same shape of row has no other way to tell them
            // apart.
            "class": value.class().as_str(),
            "source": value.source.as_str(),
            "origin": value.origin.as_ref().cloned(),
            "variable": value.variable.as_ref().cloned(),
            "effect": value.effect.as_str(),
        })).collect::<Vec<_>>(),
        "ceilings": effective.ceilings.iter().map(|ceiling| json!({
            "key": ceiling.key,
            "configured": ceiling.configured.as_ref().cloned(),
            "value": ceiling.value,
            "source": ceiling.source.as_str(),
            "origin": ceiling.origin.as_ref().cloned(),
            "effect": ceiling.effect.as_str(),
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
        text.push_str(&format!(
            "{:<14} {}\n",
            check.status.as_str(),
            check.title()
        ));
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
    lines.push(format!(
        "  runtime directory {}",
        effective.runtime_directory
    ));
    lines.push(format!("  state directory {}", effective.state_directory));
    // Section 26's native OS-appropriate locations: where this platform puts each of them, beside
    // the three paths above that say where this host's own are. The rule is what an owner needs in
    // order to find the next one, or to know that a variable of theirs chose this one instead.
    for location in &effective.locations {
        lines.push(format!(
            "  {} belongs at {}",
            location.what, location.documented
        ));
    }
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
            value.value(),
            value.source.as_str(),
            value.effect.describe()
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
            ceiling.effect.describe(),
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
    use kr_protocol::hostinfo::export::{BuildIdentity, ContentClass, Sentence, Stated};

    let controller = info.build_id.to_string();
    vec![
        kr_protocol::hostinfo::SoftwareComponent {
            component: Stated::new("kr"),
            version: Sentence::new().stated(env!("CARGO_PKG_VERSION")),
        },
        kr_protocol::hostinfo::SoftwareComponent {
            component: Stated::new("controller build"),
            // Which build of the daemon is running, which is the first thing somebody reading a
            // bundle needs. It arrives in a reply rather than being this command's own, so the
            // parse is what establishes that it is a build identity; text that is not one leaves
            // as its class and its length.
            version: BuildIdentity::parse(&controller).map_or_else(
                || Sentence::new().withheld(ContentClass::Name, &controller),
                |build| Sentence::new().identifier(&build),
            ),
        },
        kr_protocol::hostinfo::SoftwareComponent {
            component: Stated::new("protocol"),
            version: Sentence::new()
                .number(u64::from(info.protocol_version.major))
                .stated(".")
                .number(u64::from(info.protocol_version.minor)),
        },
        kr_protocol::hostinfo::SoftwareComponent {
            component: Stated::new("platform"),
            version: Sentence::new()
                .stated(std::env::consts::OS)
                .stated(" ")
                .stated(std::env::consts::ARCH),
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
        .map_err(|error| {
            CliError::Other(shown!(
                "the host's session list could not be read: {}",
                Shown::cbor(&error)
            ))
        })?;
    let bytes = serde_json::to_vec_pretty(&listed).map_err(|error| {
        CliError::Other(shown!(
            "this export could not be written: {}",
            Shown::json(&error)
        ))
    })?;
    use kr_protocol::hostinfo::export::Sentence;

    Ok(vec![bundle::Content {
        entry: bundle::SESSIONS_ENTRY,
        describes: Sentence::new()
            .stated("every live and closed session (")
            .number(listed.sessions.len() as u64)
            .stated(" of them) with its shell command line, working directory and title"),
        bytes,
    }])
}

#[cfg(test)]
mod tests;
