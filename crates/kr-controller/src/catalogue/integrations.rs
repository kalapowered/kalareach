//! The command integrations a session is launched with.
//!
//! Section 12's opt-in is the environment's configuration: `command_integrations` names the
//! packages whose integration a new session applies. What an integration adds is the release's
//! own, read from its verified manifest, and applies only while the installation holds the
//! owner-confirmed `command_integration.launch` grant. This daemon reads the admitted packages by
//! the same rules a worker reads them, from the admissions the worker is handed first, so a
//! session's entries name exactly the connectors its worker holds: one entry per connector whose
//! integration applies, on where the configuration names its package and off where it does not,
//! so an invocation of an integration left off is answered as a disabled one.
//!
//! The entries are fixed when the session is launched. A later release, grant or configuration
//! reaches the sessions created after it; the worker establishes a backend only while the package
//! an entry names still integrates its command with the entry's flags.
//!
//! The doctor reports the same reading: each integration an admitted release declares or the
//! configuration names, what a session created now gets of it and why, the mode its command runs
//! in, and the executable the daemon's own search path names for the command, with the version a
//! signed qualification record gives that executable's digest.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_protocol::admission::AdmittedPackage;
use kr_protocol::broker::IntegrationMode;
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{
    CommandIntegrationReport, CommandIntegrationState, CommandIntegrationUnavailable, DoctorCheck,
    DoctorStatus,
};
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{CommandIntegration, EnvironmentVariable};
use kr_worker::broker::catalogue::{CheckedPackages, ReadPackage, Reading};
use kr_worker::broker::connectors::InstalledConnector;

use super::admissions::LeftOut;

/// This daemon's reader of the packages its admissions carry, each package checked once.
#[derive(Debug, Default)]
pub struct Integrations {
    checked: CheckedPackages,
}

impl Integrations {
    /// A reader that has checked nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads `packages` by a worker's rules. It reads files, so it belongs on a thread that may
    /// block.
    #[must_use]
    pub fn read(&self, packages: &[AdmittedPackage]) -> Reading {
        self.checked.read(packages)
    }
}

/// The entries a session launched with `reading`'s admissions gets: one for each connector whose
/// integration applies, in command order, on where `enabled` names its package.
#[must_use]
pub fn entries(reading: &Reading, enabled: &[String]) -> Vec<CommandIntegration> {
    let mut entries: Vec<CommandIntegration> = reading
        .packages
        .iter()
        .filter_map(|(_, read)| {
            let Ok(ReadPackage::Connector(connector)) = read else {
                return None;
            };
            let integration = connector.integration()?;
            // The connector the command resolves to, which two packages integrating one command
            // leave none of.
            let resolved = reading.sources.for_command(&integration.command)?;
            if !Arc::ptr_eq(&resolved, connector) {
                return None;
            }
            let plugin_id = connector.plugin_id();
            let on = enabled.iter().any(|named| named == plugin_id.as_str());
            Some(CommandIntegration {
                enabled: on,
                plugin_id,
                command: integration.command.clone(),
                // An entry that is off adds nothing, so it carries nothing to add.
                flags: if on {
                    integration.flags.clone()
                } else {
                    Vec::new()
                },
            })
        })
        .collect();
    entries.sort_by(|left, right| left.command.cmp(&right.command));
    entries
}

/// The most bytes of flags the doctor's reports carry together. A report whose flags would pass it
/// carries none and says so: the doctor's answer is one control frame, and a package may declare
/// sixteen flags of four kilobytes each.
pub const MAX_REPORTED_FLAG_BYTES: usize = 256 * 1024;

/// Leaves out of `specification` the command integrations one control frame cannot carry beside
/// the rest of it, the largest first, and returns the packages it left out: a session is launched
/// without an integration rather than not launched at all.
#[must_use]
pub fn fit_launch_specification(
    specification: &mut kr_protocol::worker::WorkerLaunchSpec,
) -> Vec<kr_protocol::ids::PluginId> {
    let codec = kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control);
    let fits = |specification: &kr_protocol::worker::WorkerLaunchSpec| {
        codec
            .encode_message(&kr_protocol::envelope::ControlFrame::LaunchSpec(Box::new(
                specification.clone(),
            )))
            .is_ok()
    };
    let mut omitted = Vec::new();
    while !fits(specification) {
        let entries = &mut specification.create.launch_profile.command_integrations;
        let largest = entries
            .iter()
            .enumerate()
            .max_by_key(|(_, entry)| entry.flags.iter().map(String::len).sum::<usize>())
            .map(|(index, _)| index);
        let Some(largest) = largest else {
            // What does not fit without any integration is not theirs to make fit.
            break;
        };
        omitted.push(entries.remove(largest).plugin_id);
    }
    omitted
}

/// What the doctor reads of this host beside its admissions.
#[derive(Clone, Debug, Default)]
pub struct Host {
    /// The directories the daemon's own search path names, in order.
    pub search_path: Vec<PathBuf>,
    /// Whether this platform establishes a command backend at all.
    pub backends: bool,
    /// Whether a launcher, `kr-hook`, is installed beside this host's worker.
    pub launcher: bool,
}

/// What a report is built from: the command, flags and variables a release declares.
struct Declared {
    command: String,
    flags: Vec<String>,
    variables: Vec<EnvironmentVariable>,
}

impl Declared {
    /// What the verified manifest of `connector` declares, whether or not its integration applies.
    fn of(connector: &InstalledConnector) -> Option<Self> {
        if let Some(integration) = connector.integration() {
            return Some(Self {
                command: integration.command.clone(),
                flags: integration.flags.clone(),
                variables: integration.variables.clone(),
            });
        }
        connector
            .manifest()
            .command_integration
            .as_ref()
            .map(|declared| Self {
                command: declared.command.clone(),
                flags: declared.flags.clone(),
                variables: declared
                    .variables
                    .iter()
                    .map(|variable| EnvironmentVariable {
                        name: variable.name.clone(),
                        value: variable.value.clone(),
                    })
                    .collect(),
            })
    }
}

/// Every command integration an admitted release declares or the configuration names, as the
/// doctor reports it, in package order.
///
/// `reading` is the admissions in force as a worker reads them, none where they could not be
/// computed; `left_out` the installations those admissions leave out, and why; `enabled` the
/// packages the configuration in force turns on. It resolves each command on the daemon's search
/// path and reads each executable found, so it belongs on a thread that may block.
#[must_use]
pub fn report(
    reading: Option<&Reading>,
    left_out: &[LeftOut],
    enabled: &[String],
    host: &Host,
) -> Vec<CommandIntegrationReport> {
    let configured = |plugin: &str| enabled.iter().any(|named| named == plugin);
    let mut reports: BTreeMap<String, (CommandIntegrationReport, Option<Arc<InstalledConnector>>)> =
        BTreeMap::new();
    if let Some(reading) = reading {
        for (package, read) in &reading.packages {
            let plugin_id = package.plugin_id.as_str();
            let version = Some(package.version.as_str());
            match read {
                Ok(ReadPackage::Connector(connector)) => {
                    let applies = connector.integration().is_some_and(|integration| {
                        reading
                            .sources
                            .for_command(&integration.command)
                            .is_some_and(|resolved| Arc::ptr_eq(&resolved, connector))
                    });
                    let state = if applies && configured(plugin_id) {
                        CommandIntegrationState::On
                    } else if applies {
                        CommandIntegrationState::Off
                    } else if connector.manifest().command_integration.is_some() {
                        CommandIntegrationState::NotGranted
                    } else if configured(plugin_id) {
                        CommandIntegrationState::NoneDeclared
                    } else {
                        continue;
                    };
                    reports.insert(
                        plugin_id.to_owned(),
                        (
                            described(plugin_id, version, state, Declared::of(connector), None),
                            Some(Arc::clone(connector)),
                        ),
                    );
                }
                Ok(ReadPackage::Declarative(manifest)) => {
                    if manifest.command_integration.is_some() || configured(plugin_id) {
                        let declares = manifest.command_integration.is_some();
                        let report = described(
                            plugin_id,
                            version,
                            if declares {
                                CommandIntegrationState::Unreadable
                            } else {
                                CommandIntegrationState::NoneDeclared
                            },
                            None,
                            declares.then(|| {
                                "its package carries no connector table, and a command \
                                 integration launches through a connector"
                                    .to_owned()
                            }),
                        );
                        reports.insert(plugin_id.to_owned(), (report, None));
                    }
                }
                Err(why) => {
                    let conflicting = reading
                        .conflicting
                        .iter()
                        .find(|connector| connector.package_digest() == package.package_digest);
                    if let Some(connector) = conflicting {
                        let report = described(
                            plugin_id,
                            version,
                            CommandIntegrationState::Conflict,
                            Declared::of(connector),
                            Some(why.clone()),
                        );
                        reports.insert(plugin_id.to_owned(), (report, Some(Arc::clone(connector))));
                    } else if configured(plugin_id) {
                        let report = described(
                            plugin_id,
                            version,
                            CommandIntegrationState::Unreadable,
                            None,
                            Some(why.clone()),
                        );
                        reports.insert(plugin_id.to_owned(), (report, None));
                    }
                }
            }
        }
    }
    for plugin_id in enabled {
        if reports.contains_key(plugin_id) {
            continue;
        }
        let report = match left_out
            .iter()
            .find(|left| left.plugin_id.as_str() == plugin_id)
        {
            Some(left) => described(
                plugin_id,
                None,
                CommandIntegrationState::NotAdmitted,
                None,
                Some(left.detail.clone()),
            ),
            None => described(
                plugin_id,
                None,
                CommandIntegrationState::NotInstalled,
                None,
                None,
            ),
        };
        reports.insert(plugin_id.clone(), (report, None));
    }
    let mut reported_flag_bytes = 0usize;
    reports
        .into_values()
        .map(|(mut report, connector)| {
            let flag_bytes: usize = report.flags.iter().map(String::len).sum();
            if reported_flag_bytes + flag_bytes > MAX_REPORTED_FLAG_BYTES {
                let said = format!(
                    "its {} flags, {flag_bytes} bytes, are more than this report carries",
                    report.flags.len()
                );
                report.flags.clear();
                report.reason = Nullable::some(match report.reason.0.take() {
                    Some(reason) => format!("{reason}; {said}"),
                    None => said,
                });
            } else {
                reported_flag_bytes += flag_bytes;
            }
            if report.state == CommandIntegrationState::On {
                report.unavailable = Nullable(if !host.backends {
                    Some(CommandIntegrationUnavailable::Platform)
                } else if !host.launcher {
                    Some(CommandIntegrationUnavailable::NoLauncher)
                } else {
                    None
                });
                if report.unavailable.0.is_none() {
                    // What an integrated launch records as its mode.
                    report.mode = IntegrationMode::NativeBridge;
                }
            }
            if let Some(command) = report.command.0.as_deref()
                && let Some(executable) = resolve(command, &host.search_path)
            {
                report.executable_version = Nullable(connector.and_then(|connector| {
                    super::native_bridge::read_executable(&executable)
                        .ok()
                        .and_then(|digest| connector.qualified_version(&digest).map(str::to_owned))
                }));
                report.executable = Nullable::some(executable.display().to_string());
            }
            report
        })
        .collect()
}

/// One report, before the host's own reading: no resolution, and the terminal as its mode.
fn described(
    plugin_id: &str,
    version: Option<&str>,
    state: CommandIntegrationState,
    declared: Option<Declared>,
    reason: Option<String>,
) -> CommandIntegrationReport {
    let (command, flags, variables) = declared.map_or((None, Vec::new(), Vec::new()), |declared| {
        (Some(declared.command), declared.flags, declared.variables)
    });
    CommandIntegrationReport {
        plugin_id: plugin_id.to_owned(),
        version: Nullable(version.map(str::to_owned)),
        command: Nullable(command),
        flags,
        variables,
        state,
        unavailable: Nullable::null(),
        mode: IntegrationMode::NativeTerminal,
        executable: Nullable::null(),
        executable_version: Nullable::null(),
        reason: Nullable(reason),
    }
}

/// The first executable `command` names on `search_path`, as a shell's search finds it.
fn resolve(command: &str, search_path: &[PathBuf]) -> Option<PathBuf> {
    let extensions: Vec<String> = if cfg!(windows) {
        // A command is found under each of the extensions the platform runs, in its order.
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned())
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    } else {
        vec![String::new()]
    };
    resolve_with(command, search_path, &extensions)
}

/// The first runnable `command` followed by one of `extensions` in a directory of `search_path`:
/// each directory in order, and in each the extensions in theirs.
fn resolve_with(command: &str, search_path: &[PathBuf], extensions: &[String]) -> Option<PathBuf> {
    search_path
        .iter()
        .flat_map(|directory| {
            extensions
                .iter()
                .map(move |extension| directory.join(format!("{command}{extension}")))
        })
        .find(|candidate| runnable(candidate))
}

/// Whether `path` is a file this account may run.
fn runnable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| {
        #[cfg(unix)]
        let permitted = {
            use std::os::unix::fs::PermissionsExt as _;
            metadata.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let permitted = true;
        metadata.is_file() && permitted
    })
}

/// The doctor's check of the command integrations: whether every integration the configuration
/// turns on is one a session created now can use.
#[must_use]
pub fn check(reports: &[CommandIntegrationReport], enabled: &[String]) -> DoctorCheck {
    const ID: &str = "command-integrations";
    const TITLE: &str = "The command integrations new sessions apply";
    if reports.is_empty() {
        return DoctorCheck::new(
            ID,
            TITLE,
            DoctorStatus::NotApplicable,
            Sentence::new().stated(
                "no installed release declares a command integration, and the configuration \
                 turns on none",
            ),
            None,
        );
    }
    let usable = |report: &&CommandIntegrationReport| {
        report.state == CommandIntegrationState::On && report.unavailable.0.is_none()
    };
    let on = reports.iter().filter(usable).count();
    let off = reports
        .iter()
        .filter(|report| report.state == CommandIntegrationState::Off)
        .count();
    let blocked = reports
        .iter()
        .filter(|report| enabled.contains(&report.plugin_id))
        .filter(|report| !usable(report))
        .count();
    DoctorCheck::new(
        ID,
        TITLE,
        if blocked == 0 {
            DoctorStatus::Ok
        } else {
            DoctorStatus::Warning
        },
        Sentence::new()
            .number(on as u64)
            .stated(" on for new sessions, ")
            .number(off as u64)
            .stated(" off, and ")
            .number(blocked as u64)
            .stated(" the configuration turns on that a new session cannot use"),
        (blocked > 0).then_some(
            "kr doctor --verbose names each integration and why a new session cannot use it; kr \
             plugin integration disable takes one out of this host's list.",
        ),
    )
}

/// The check when the installed packages could not be read in time.
#[must_use]
pub fn unread_check() -> DoctorCheck {
    DoctorCheck::new(
        "command-integrations",
        "The command integrations new sessions apply",
        DoctorStatus::Warning,
        Sentence::new().stated(
            "the installed packages could not be read in time, so the command integrations are \
             not reported",
        ),
        None,
    )
}

#[cfg(test)]
mod tests;
