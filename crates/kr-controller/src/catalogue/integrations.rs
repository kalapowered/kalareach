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
//! The doctor reports the same reading: each integration an admitted release declares and each
//! package the configuration names, what a session created now gets of it and why, the mode its
//! command runs in, and the executable the daemon's own search path names for the command, with
//! the version a signed qualification record gives that executable's digest.

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
use kr_protocol::ids::{PluginId, SessionId};
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    CommandIntegration, EnvironmentVariable, MAX_COMMAND_INTEGRATION_ENTRIES,
    MAX_COMMAND_INTEGRATION_FLAG_BYTES,
};
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

/// The forwarder a package writes the path of where it registers it: this installation's `kr-hook`
/// by the path an update keeps current (through the store's `current` link for a release of a store,
/// and beside the daemon otherwise), where one is installed.
///
/// A session's flags, the doctor's reports and the registration files a bridge installs all name
/// this path, and a worker reads the same one, so each says the same text.
#[must_use]
pub fn registered_forwarder() -> Option<PathBuf> {
    kr_ipc::install::this_process()
        .ok()
        .map(|running| running.stable(kr_ipc::install::Program::Hook))
        .filter(|path| path.is_file())
}

/// Returns `flags` written with the forwarder's path where a package names the forwarder, or as
/// declared where that cannot be done here: a worker that cannot write them either runs every
/// invocation as typed, and the doctor says why.
fn written(flags: &[String], forwarder: Option<&Path>) -> Vec<String> {
    kr_plugin_sdk::forwarder::expand_flags(flags, forwarder).unwrap_or_else(|_| flags.to_vec())
}

/// What a session launched with some admissions is given of their command integrations.
#[derive(Debug, Default)]
pub struct Fill {
    /// The session's entries, in command order.
    pub entries: Vec<CommandIntegration>,
    /// The packages whose integration the configuration turns on and the session is launched
    /// without, since their flags are more than one session carries, the largest first.
    pub omitted: Vec<PluginId>,
}

/// What a session launched with `reading`'s admissions gets: an entry for each connector whose
/// integration applies, on where `enabled` names its package, within one session's bounds.
///
/// Every integration turned on is carried whole while their flags together are within
/// [`MAX_COMMAND_INTEGRATION_FLAG_BYTES`]; past it the largest are left out, a tie going to the
/// package named first, and returned. Entries that are off carry no flags, and take the room left
/// under [`MAX_COMMAND_INTEGRATION_ENTRIES`] in command order: one that finds none only loses the
/// record that an invocation of its command ran as typed because the integration is off.
#[must_use]
pub fn fill(reading: &Reading, enabled: &[String], forwarder: Option<&Path>) -> Fill {
    let (mut on, off): (Vec<CommandIntegration>, Vec<CommandIntegration>) =
        entries(reading, enabled, forwarder)
            .into_iter()
            .partition(|entry| entry.enabled);
    on.sort_by(|left, right| {
        flag_bytes(right)
            .cmp(&flag_bytes(left))
            .then_with(|| left.plugin_id.cmp(&right.plugin_id))
    });
    let mut carried: usize = on.iter().map(flag_bytes).sum();
    let mut entries = Vec::new();
    let mut omitted = Vec::new();
    for entry in on {
        if carried > MAX_COMMAND_INTEGRATION_FLAG_BYTES
            || entries.len() == MAX_COMMAND_INTEGRATION_ENTRIES
        {
            carried -= flag_bytes(&entry);
            omitted.push(entry.plugin_id);
        } else {
            entries.push(entry);
        }
    }
    let room = MAX_COMMAND_INTEGRATION_ENTRIES - entries.len();
    entries.extend(off.into_iter().take(room));
    entries.sort_by(|left, right| left.command.cmp(&right.command));
    Fill { entries, omitted }
}

/// The bytes of flags `entry` carries.
fn flag_bytes(entry: &CommandIntegration) -> usize {
    entry.flags.iter().map(String::len).sum()
}

/// The note that names every integration the configuration turns on and a launch of `session_id`
/// left out, or none where it left out none: one note for the launch, whatever it left out, and
/// bounded as the configuration's list is.
#[must_use]
pub fn omission_note(session_id: SessionId, omitted: &[PluginId]) -> Option<String> {
    if omitted.is_empty() {
        return None;
    }
    let named: Vec<&str> = omitted.iter().map(PluginId::as_str).collect();
    Some(format!(
        "session {session_id} was launched without the command integrations the configuration \
         turns on for {}: they are more than one session carries",
        named.join(", ")
    ))
}

/// The entries a session launched with `reading`'s admissions gets: one for each connector whose
/// integration applies, in command order, on where `enabled` names its package.
#[must_use]
fn entries(
    reading: &Reading,
    enabled: &[String],
    forwarder: Option<&Path>,
) -> Vec<CommandIntegration> {
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
                    written(&integration.flags, forwarder)
                } else {
                    Vec::new()
                },
            })
        })
        .collect();
    entries.sort_by(|left, right| left.command.cmp(&right.command));
    entries
}

/// The most command integration reports the doctor's answer carries.
pub const MAX_REPORTS: usize = 256;

/// The most bytes the doctor's command integration reports take in its answer together, each in
/// the larger of the owner's form and the withheld one. The answer is one control frame, and the
/// rest of it has the other checks, the configuration and the catalogue's notes to carry.
pub const MAX_REPORT_BYTES: usize = 384 * 1024;

/// Leaves out of `specification` the command integrations one control frame cannot carry beside
/// the rest of it, the largest first, and returns the entries it left out: a session is launched
/// without an integration rather than not launched at all.
#[must_use]
pub fn fit_launch_specification(
    specification: &mut kr_protocol::worker::WorkerLaunchSpec,
) -> Vec<CommandIntegration> {
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
        omitted.push(entries.remove(largest));
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
    /// Why it does not, where the platform says: what the doctor's check then says beside it.
    pub backends_failure: Option<&'static str>,
    /// Whether a launcher, `kr-hook`, is installed beside this host's worker.
    pub launcher: bool,
    /// The forwarder a package writes the path of where it registers it, where one is installed.
    pub forwarder: Option<PathBuf>,
}

/// What a report is built from: the command, flags and variables a release declares.
struct Declared {
    command: String,
    flags: Vec<String>,
    variables: Vec<EnvironmentVariable>,
}

impl Declared {
    /// What the verified manifest of `connector` declares, whether or not its integration applies.
    fn of(connector: &InstalledConnector, forwarder: Option<&Path>) -> Option<Self> {
        if let Some(integration) = connector.integration() {
            return Some(Self {
                command: integration.command.clone(),
                flags: written(&integration.flags, forwarder),
                variables: integration.variables.clone(),
            });
        }
        connector
            .manifest()
            .command_integration
            .as_ref()
            .map(|declared| Self {
                command: declared.command.clone(),
                flags: written(&declared.flags, forwarder),
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

/// The doctor's command integration reports, and how many it leaves out.
#[derive(Debug, Default)]
pub struct Reported {
    /// The reports the answer carries, in package order.
    pub reports: Vec<CommandIntegrationReport>,
    /// How many it leaves out, since one answer carries no more.
    pub omitted: usize,
    /// Why this platform's command backends do not run, where it says.
    pub backends_failure: Option<&'static str>,
}

/// Every command integration an admitted release declares, and every package the configuration
/// names, as the doctor reports it, in package order. An installation the admissions leave out is
/// reported where the configuration names it: a new session gets nothing of it either way.
///
/// `reading` is the admissions in force as a worker reads them, none where they could not be
/// computed, which leaves every package the configuration names unknown; `left_out` the
/// installations those admissions leave out, and why; `enabled` the packages the configuration in
/// force turns on. It resolves each command on the daemon's search path and reads each executable
/// found, so it belongs on a thread that may block.
#[must_use]
pub fn report(
    reading: Option<&Reading>,
    left_out: &[LeftOut],
    enabled: &[String],
    host: &Host,
) -> Reported {
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
                            described(
                                plugin_id,
                                version,
                                state,
                                Declared::of(connector, host.forwarder.as_deref()),
                                None,
                            ),
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
                            Declared::of(connector, host.forwarder.as_deref()),
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
        // With no admissions read, nothing says whether it is installed.
        if reading.is_none() {
            let report = described(
                plugin_id,
                None,
                CommandIntegrationState::Unknown,
                None,
                None,
            );
            reports.insert(plugin_id.clone(), (report, None));
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
    // What a session created now is launched without.
    let too_large = reading.map_or_else(Vec::new, |reading| {
        fill(reading, enabled, host.forwarder.as_deref()).omitted
    });
    // One answer carries so many reports and so many bytes of them, each whole: the packages the
    // configuration names first, then the others, each in package order, and the rest counted.
    let (named, others): (Vec<_>, Vec<_>) = reports
        .into_iter()
        .partition(|(plugin_id, _)| configured(plugin_id));
    let mut carried = Vec::new();
    let mut bytes = 0usize;
    let mut omitted = 0usize;
    for (_, (report, connector)) in named.into_iter().chain(others) {
        if carried.len() == MAX_REPORTS {
            omitted += 1;
            continue;
        }
        let report = resolved(report, connector.as_deref(), host, &too_large);
        let size = encoded_size(&report);
        if size > MAX_REPORT_BYTES - bytes {
            omitted += 1;
            continue;
        }
        bytes += size;
        carried.push(report);
    }
    carried.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    Reported {
        reports: carried,
        omitted,
        backends_failure: host.backends_failure.filter(|_| !host.backends),
    }
}

/// `report` with what this host reads of it: whether a session created now can launch through it
/// here, the mode its command then runs in, and the executable the search path names, with the
/// version a signed record gives that executable's digest.
fn resolved(
    mut report: CommandIntegrationReport,
    connector: Option<&InstalledConnector>,
    host: &Host,
    too_large: &[PluginId],
) -> CommandIntegrationReport {
    if report.state == CommandIntegrationState::On {
        report.unavailable = Nullable(if !host.backends {
            Some(CommandIntegrationUnavailable::Platform)
        } else if !host.launcher {
            Some(CommandIntegrationUnavailable::NoLauncher)
        } else if too_large
            .iter()
            .any(|plugin_id| plugin_id.as_str() == report.plugin_id)
        {
            Some(CommandIntegrationUnavailable::TooLarge)
        } else {
            None
        });
    }
    // A worker runs every invocation as typed where it cannot use the flags a package declares: it
    // cannot write the forwarder into them, or they name the forwarder by its own name, which an
    // application may look for in its working directory before its search path. The report says so
    // beside the state, read from the declared flags, which are what the worker reads.
    let declared_flags = connector
        .and_then(|connector| connector.manifest().command_integration.as_ref())
        .map(|declared| declared.flags.as_slice());
    if report.state == CommandIntegrationState::On
        && report.reason.0.is_none()
        && let Some(flags) = declared_flags
    {
        if let Err(error) = kr_plugin_sdk::forwarder::expand_flags(flags, host.forwarder.as_deref())
        {
            report.reason = Nullable::some(format!(
                "its flags cannot be written with the installed forwarder, so an invocation runs \
                 as typed: {error}"
            ));
        } else if cfg!(windows) && kr_plugin_sdk::forwarder::names_the_forwarder_itself(flags) {
            report.reason = Nullable::some(
                "its flags name the forwarder by its own name, which an application may look for \
                 in its working directory before its search path, so an invocation runs as typed \
                 until the package names the forwarder by the placeholder"
                    .to_owned(),
            );
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
        // What the shell finds first is what an invocation runs, and a launcher cannot start a
        // shim: an invocation that finds one runs as typed, which a person who turned the
        // integration on is told here, beside the executable.
        if !kr_worker::broker::commands::starts_directly(&executable) && report.reason.0.is_none() {
            report.reason = Nullable::some(format!(
                "first hit is {}, a script or shim that no launcher starts, so an invocation that \
                 finds it runs as typed",
                executable.display()
            ));
        }
    }
    // What an integrated launch records as its mode: only an integration a new session can use.
    if report.state == CommandIntegrationState::On
        && report.unavailable.0.is_none()
        && report.reason.0.is_none()
    {
        report.mode = IntegrationMode::NativeBridge;
    }
    report
}

/// The bytes `report` takes in an answer, in the larger of its two forms: the owner's, and the
/// withheld one anybody else is given.
fn encoded_size(report: &CommandIntegrationReport) -> usize {
    let size = |report: &CommandIntegrationReport| {
        kr_cbor::to_canonical_value(report).map_or(usize::MAX, |value| kr_cbor::encoded_len(&value))
    };
    size(report).max(size(&report.withheld_form()))
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
    let pathext = std::env::var("PATHEXT").ok();
    resolve_with(
        command,
        search_path,
        &extensions(cfg!(windows), pathext.as_deref()),
    )
}

/// The suffixes a command is looked for under in each directory, in order.
///
/// Where names are exact it is looked for as it is. On Windows it is found under each of the
/// extensions the platform runs, `pathext` naming them, and in one directory PowerShell takes a
/// `.ps1` script before the program those extensions name, which is why that one comes first.
fn extensions(windows: bool, pathext: Option<&str>) -> Vec<String> {
    if !windows {
        return vec![String::new()];
    }
    std::iter::once(".ps1".to_owned())
        .chain(
            pathext
                .unwrap_or(".COM;.EXE;.BAT;.CMD")
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(str::to_ascii_lowercase),
        )
        .collect()
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
        .find(|candidate| kr_worker::broker::commands::runnable(candidate))
}

/// The doctor's check of the command integrations: whether every integration the configuration
/// turns on is one a session created now can use.
#[must_use]
pub fn check(reported: &Reported, enabled: &[String]) -> DoctorCheck {
    const ID: &str = "command-integrations";
    const TITLE: &str = "The command integrations new sessions apply";
    let reports = &reported.reports;
    if reports.is_empty() && reported.omitted == 0 {
        return DoctorCheck::new(
            ID,
            TITLE,
            DoctorStatus::NotApplicable,
            Sentence::new().stated(
                "no admitted release declares a command integration, and the configuration \
                 turns on none",
            ),
            None,
        );
    }
    // A reason beside an integration that is on says why an invocation runs as typed here: the
    // flags cannot be written, they name the forwarder by its own name on a platform where that is
    // not safe, or the executable found first is a shim, so a new session gets none of it.
    let usable = |report: &&CommandIntegrationReport| {
        report.state == CommandIntegrationState::On
            && report.unavailable.0.is_none()
            && report.reason.0.is_none()
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
    let mut detail = Sentence::new()
        .number(on as u64)
        .stated(" on for new sessions, ")
        .number(off as u64)
        .stated(" off, and ")
        .number(blocked as u64)
        .stated(" the configuration turns on that a new session cannot use");
    if reported.omitted > 0 {
        detail = detail.stated("; ").number(reported.omitted as u64).stated(
            " more are not listed, since one answer carries no more, the packages the \
                 configuration names first",
        );
    }
    if let Some(why) = reported.backends_failure.filter(|_| blocked > 0) {
        detail = detail
            .stated("; command backends do not run here: ")
            .stated(why);
    }
    DoctorCheck::new(
        ID,
        TITLE,
        if blocked == 0 && reported.omitted == 0 {
            DoctorStatus::Ok
        } else {
            DoctorStatus::Warning
        },
        detail,
        (blocked > 0).then_some(
            "kr doctor --verbose names each integration it lists and why a new session cannot use \
             it; kr plugin integration disable takes one out of this host's list.",
        ),
    )
}

/// The check when the admissions in force could not be computed, or the packages they admit not
/// read, within the doctor's bounds.
#[must_use]
pub fn unread_check() -> DoctorCheck {
    DoctorCheck::new(
        "command-integrations",
        "The command integrations new sessions apply",
        DoctorStatus::Warning,
        Sentence::new().stated(
            "the admissions in force could not be computed, or the packages they admit not read, \
             so what a new session gets of each command integration is not known",
        ),
        None,
    )
}

#[cfg(test)]
mod tests;
