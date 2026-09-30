//! Whether the host detected the agent a part launched, and what section 12 requires of a launch
//! the command integration did not make.
//!
//! Section 12 keeps a manual launch valid through "the same detection and capability process", and
//! gives a launch that bypasses the command integration "only verified observation and terminal
//! capabilities", with no gateway created for it after it started. Section 11's evidence names the
//! exact binary, package and profile it was gathered against. So a part that starts an agent by
//! typing its command checks three things against what it launched, not against whatever the host
//! happens to announce:
//!
//! 1. [`check_detected`]: exactly one live instance for the launched execution, naming the installed
//!    package, integrated as a native terminal with every bridge refused, whose binding a device
//!    reads with the same launch profile, while at least one live binding holds the package; and no
//!    live instance once the execution has ended.
//! 2. [`check_observation_only`]: no capability record usable for a typed action, every typed
//!    mutation sent for the instance refused, no pending resource, and no command backend (its
//!    registration or launch record) anywhere in the host's runtime directory.
//! 3. [`check_unchanged`]: across steps that keep the process, its conversation and its upstream
//!    owner, the same instance at the same binding revision.
//!
//! No read the host serves names the executable an adopted instance runs: its capability map is
//! empty, `plugin.list` counts bindings, and `kr` reports no instance. A part therefore records the
//! image it measured itself beside what the host announced, and says that the host shows none.
//!
//! Each check is also run against observations made wrong on purpose, which it must reject
//! ([`checker_controls`]); the record names those runs as checker controls, apart from a part's own
//! control, which changes what runs rather than what the check is shown.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_e2e_m1b::device::Remote;
use kr_protocol::agent::{AgentCapabilitiesParams, AgentCapabilitiesResult, AgentSubject};
use kr_protocol::broker::IntegrationMode;
use kr_protocol::ids::{AgentBindingRevision, ApplicationInstanceId, PluginId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::projection::AgentInstanceSummary;
use kr_protocol::scalars::Nullable;
use serde_json::{Value, json};

use crate::observe::Answer;
use crate::stage::events_snapshot;

/// How long a part waits after a launch for the host to detect it. The host hashes the executable
/// first, which takes seconds for a build of two hundred megabytes on a loaded machine.
pub const DETECTION_WAIT: Duration = Duration::from_secs(30);

/// How often the session's announcement is read while a part waits.
const LOOK: Duration = Duration::from_millis(250);

/// The capabilities a typed agent action needs. A record for one of them that is usable would
/// advertise a typed route; observation records, such as the binding read, may be usable.
pub const TYPED_CAPABILITIES: [&str; 6] = [
    "agent.prompt",
    "agent.prompt.queue",
    "agent.steer",
    "agent.cancel",
    "agent.approval",
    "agent.attachment",
];

/// The files a command backend or a gateway leaves in the worker's runtime directory: a
/// registration, whose name starts with this, a launch record and a credential; its endpoint is a
/// socket beside them.
const BACKEND_FILES: (&str, [&str; 2]) = ("registration", ["launch", "credential"]);

/// What a session announced about agents once the host had had time to detect the one a part
/// launched.
#[derive(Clone, Debug)]
pub struct Detection {
    /// The live instances the session announced when the wait ended.
    pub instances: Vec<AgentInstanceSummary>,
    /// How long the wait took.
    pub waited_ms: u64,
}

impl Detection {
    /// The one live instance, where there is exactly one.
    #[must_use]
    pub fn only(&self) -> Option<&AgentInstanceSummary> {
        match self.instances.as_slice() {
            [instance] => Some(instance),
            _ => None,
        }
    }

    /// The announcement as evidence.
    #[must_use]
    pub fn evidence(&self) -> Value {
        json!({
            "instances": self.instances.iter().map(|instance| serde_json::to_value(instance).unwrap_or_default()).collect::<Vec<_>>(),
            "waited_ms": self.waited_ms,
        })
    }
}

/// Reads the session's live instances now.
///
/// # Panics
///
/// Panics when the host refuses the read.
#[must_use]
pub fn announced_now(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    session_id: SessionId,
) -> Vec<AgentInstanceSummary> {
    events_snapshot(remote, runtime, session_id)
        .agent_instances
        .instances
        .into_iter()
        .filter(|instance| instance.ended_at.0.is_none())
        .collect()
}

/// Waits up to [`DETECTION_WAIT`] for the session to announce a live instance, and returns what it
/// announces when one appears or the wait ends. `between` is called before each look, for what the
/// part checks while it waits.
#[must_use]
pub fn wait_for_detection(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    session_id: SessionId,
    between: &dyn Fn(),
) -> Detection {
    let started = Instant::now();
    loop {
        between();
        let instances = announced_now(remote, runtime, session_id);
        if !instances.is_empty() || started.elapsed() >= DETECTION_WAIT {
            return Detection {
                instances,
                waited_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            };
        }
        std::thread::sleep(LOOK);
    }
}

/// Waits up to [`DETECTION_WAIT`] for the session to announce no live instance, and returns what
/// it announces when the list is empty or the wait ends. `between` is called before each look.
#[must_use]
pub fn wait_for_no_instance(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    session_id: SessionId,
    between: &dyn Fn(),
) -> Detection {
    let started = Instant::now();
    loop {
        between();
        let instances = announced_now(remote, runtime, session_id);
        if instances.is_empty() || started.elapsed() >= DETECTION_WAIT {
            return Detection {
                instances,
                waited_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            };
        }
        std::thread::sleep(LOOK);
    }
}

/// The instance's binding and capability map as a device reads them, or the host's refusal.
///
/// # Errors
///
/// Returns the host's refusal, in words.
pub fn capabilities_of(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    subject: AgentSubject,
) -> Result<AgentCapabilitiesResult, String> {
    runtime
        .block_on(remote.read::<_, AgentCapabilitiesResult>(
            Method::AgentCapabilities,
            &AgentCapabilitiesParams { subject },
        ))
        .map_err(|error| error.to_string())
}

/// Every command backend or gateway file under `runtime_root`: a registration, a launch record or a
/// credential, and every socket beside one of them, its endpoint.
///
/// # Panics
///
/// Panics when the directory cannot be walked, which would leave the absence unshown.
#[must_use]
pub fn backend_files(runtime_root: &Path) -> Vec<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let mut found = Vec::new();
    let mut sockets = Vec::new();
    let mut holding = std::collections::BTreeSet::new();
    let mut pending = vec![runtime_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            // A worker's directory can go between the listing and the read.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("{}: {error}", directory.display()),
        };
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
            let kind = entry
                .file_type()
                .unwrap_or_else(|error| panic!("{}: {error}", entry.path().display()));
            let name = entry.file_name().to_string_lossy().into_owned();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if name.starts_with(BACKEND_FILES.0) || BACKEND_FILES.1.contains(&name.as_str())
            {
                found.push(entry.path());
                holding.insert(directory.clone());
            } else if kind.is_socket() {
                sockets.push(entry.path());
            }
        }
    }
    found.extend(sockets.into_iter().filter(|socket| {
        socket
            .parent()
            .is_some_and(|parent| holding.contains(parent))
    }));
    found.sort();
    found
}

/// What a part launched: the package installed for it, and whether its execution still runs.
#[derive(Clone, Debug)]
pub struct Launched {
    /// The installed package.
    pub plugin_id: PluginId,
    /// Whether the launched execution still runs, by its recorded start identity.
    pub running: bool,
}

/// What the host showed about a launch.
#[derive(Clone, Debug)]
pub struct Shown {
    /// The session's live instances.
    pub detection: Detection,
    /// The one instance's binding and capabilities, where there is one and the host answered.
    pub binding: Option<AgentCapabilitiesResult>,
    /// How many live bindings `plugin.list` counts for the package.
    pub live_bindings: Option<u64>,
}

/// What check (i) established about a detected launch.
#[derive(Clone, Debug)]
pub struct Detected {
    /// The instance the host announced for the launched execution.
    pub instance: ApplicationInstanceId,
    /// Whether the host showed which executable and release the instance runs. No read it serves
    /// does for a launch the integration did not make, so this names that and stays unproven.
    pub identity: &'static str,
}

/// What check (i) records about the executable and release of an instance the host announced.
pub const IDENTITY_UNPROVEN: &str = "unproven: no read the host serves names the executable or the \
     release an instance it detected runs; the image the launched process maps is under provenance";

/// Why a launch was not detected as section 12 requires: a cause from a closed set, which a record
/// says in words of its own, how many live instances the host announced, and the words that
/// describe it, which can hold what the host named and stay in the part's log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Undetected {
    /// The cause, one of [`Undetected::CAUSES`].
    pub cause: &'static str,
    /// How many live instances the host announced.
    pub announced: usize,
    /// The words that describe it.
    pub why: String,
}

impl Undetected {
    /// The causes, each named for what was not so: the launched execution ended; the host did not
    /// announce exactly one live instance; the instance names another package, is not integrated
    /// as a native terminal or does not say its bridges are refused; a device cannot read its
    /// binding, or the binding is not integrated as a native terminal, does not hold the
    /// announced launch profile, or has no live binding counted by `plugin.list`.
    pub const CAUSES: [&'static str; 9] = [
        "ended",
        "not_one_instance",
        "another_package",
        "not_native_terminal",
        "no_refusal",
        "no_binding",
        "binding_not_native_terminal",
        "binding_profile",
        "no_live_binding",
    ];
}

impl std::fmt::Display for Undetected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.why)
    }
}

/// Check (i): the host detected the launched execution, as section 12 requires of a manual launch:
/// one live instance while the execution runs, naming the installed package, integrated as a native
/// terminal with every bridge refused, whose binding a device reads with the announced profile. Its
/// executable's identity stays unproven ([`IDENTITY_UNPROVEN`]); that the instance is the launched
/// execution's is shown by its ending with it ([`check_ended`]).
///
/// # Errors
///
/// Returns why the launch was not detected as the launched execution.
pub fn check_detected(launched: &Launched, shown: &Shown) -> Result<Detected, Undetected> {
    let instances = &shown.detection.instances;
    let fail = |cause: &'static str, why: String| Undetected {
        cause,
        announced: instances.len(),
        why,
    };
    if !launched.running {
        return Err(fail(
            "ended",
            if instances.is_empty() {
                "the launched execution has ended and no instance is live".to_owned()
            } else {
                format!(
                    "the launched execution has ended and {} instance(s) are still announced live",
                    instances.len()
                )
            },
        ));
    }
    let Some(instance) = shown.detection.only() else {
        return Err(fail(
            "not_one_instance",
            format!(
                "the host announced {} live instance(s) for the launched execution, not one: \
                 section 12 keeps a manual launch valid through the same detection and capability \
                 process",
                instances.len()
            ),
        ));
    };
    if instance.plugin_id.0.as_ref() != Some(&launched.plugin_id) {
        return Err(fail(
            "another_package",
            format!(
                "the instance names {:?}, not the installed package {}",
                instance.plugin_id.0, launched.plugin_id
            ),
        ));
    }
    if instance.mode != IntegrationMode::NativeTerminal {
        return Err(fail(
            "not_native_terminal",
            format!(
                "the instance is integrated as {}, and a launch the integration did not make \
                 keeps only observation and terminal capabilities",
                instance.mode.as_str()
            ),
        ));
    }
    if instance
        .refusal
        .0
        .as_deref()
        .is_none_or(|refusal| refusal.trim().is_empty())
    {
        return Err(fail(
            "no_refusal",
            "the instance does not say that its bridges are refused".to_owned(),
        ));
    }
    let Some(binding) = shown.binding.as_ref() else {
        return Err(fail(
            "no_binding",
            "a device cannot read the instance's binding".to_owned(),
        ));
    };
    if binding.binding.mode != IntegrationMode::NativeTerminal {
        return Err(fail(
            "binding_not_native_terminal",
            format!(
                "the binding is integrated as {}",
                binding.binding.mode.as_str()
            ),
        ));
    }
    if binding.binding.profile_id.0.is_none() || binding.binding.profile_id != instance.profile_id {
        return Err(fail(
            "binding_profile",
            format!(
                "the binding's launch profile {:?} is not the announced one {:?}",
                binding.binding.profile_id.0, instance.profile_id.0
            ),
        ));
    }
    if !shown.live_bindings.is_some_and(|count| count >= 1) {
        return Err(fail(
            "no_live_binding",
            format!(
                "plugin.list counts {:?} live bindings of the package",
                shown.live_bindings
            ),
        ));
    }
    Ok(Detected {
        instance: instance.application_instance_id,
        identity: IDENTITY_UNPROVEN,
    })
}

/// Check (i)'s result as evidence: the instance and what stays unproven, or why detection failed.
#[must_use]
pub fn detected_evidence(detected: &Result<Detected, Undetected>) -> Value {
    match detected {
        Ok(detected) => json!({
            "detected": true,
            "instance": detected.instance.to_string(),
            "identity": detected.identity,
        }),
        Err(undetected) => json!({
            "detected": false,
            "cause": undetected.cause,
            "announced": undetected.announced,
            "why": undetected.why,
        }),
    }
}

/// Check (i)'s other half: once the launched execution has ended, the host announces no live
/// instance for it.
///
/// # Errors
///
/// Returns the instances still announced live.
pub fn check_ended(shown: &Shown) -> Result<(), String> {
    if shown.detection.instances.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} instance(s) are still announced live after the execution ended",
            shown.detection.instances.len()
        ))
    }
}

/// What a device can reach of the instance's typed surface.
#[derive(Clone, Debug, Default)]
pub struct Surface {
    /// Each capability record, as its capability and whether it is usable.
    pub records: Vec<(String, bool)>,
    /// What the host answered each typed mutation sent for the instance.
    pub answers: Vec<Answer>,
    /// How many pending resources the session announces.
    pub resources: usize,
    /// Every command backend file in the host's runtime directory.
    pub backend_files: Vec<PathBuf>,
}

impl Surface {
    /// The capability records of a binding, as capability and usability.
    #[must_use]
    pub fn records_of(binding: Option<&AgentCapabilitiesResult>) -> Vec<(String, bool)> {
        binding
            .map(|binding| {
                binding
                    .capabilities
                    .records
                    .iter()
                    .map(|record| {
                        (
                            record.capability_id.as_str().to_owned(),
                            record.state.is_usable(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The surface as evidence.
    #[must_use]
    pub fn evidence(&self) -> Value {
        json!({
            "capability_records": self.records.iter().map(|(capability, usable)| json!({ "capability": capability, "usable": usable })).collect::<Vec<_>>(),
            "answers": self.answers.iter().map(Answer::evidence).collect::<Vec<_>>(),
            "resources": self.resources,
            "backend_files": self.backend_files,
        })
    }
}

/// Check (ii): only observation and terminal capabilities, as section 12 gives a launch the
/// integration did not make, and no gateway created for it after it started.
///
/// # Errors
///
/// Returns the first thing that offers more than observation and the terminal.
pub fn check_observation_only(surface: &Surface) -> Result<(), String> {
    if let Some((capability, _)) = surface
        .records
        .iter()
        .find(|(capability, usable)| *usable && TYPED_CAPABILITIES.contains(&capability.as_str()))
    {
        return Err(format!("{capability} is advertised as usable"));
    }
    if let Some(answer) = surface.answers.iter().find(|answer| answer.accepted()) {
        return Err(format!("{} was accepted: {}", answer.call, answer.detail));
    }
    if let Some(answer) = surface
        .answers
        .iter()
        .find(|answer| answer.refused.is_none())
    {
        return Err(format!(
            "{} was not answered with a refusal: {}",
            answer.call, answer.detail
        ));
    }
    if surface.resources != 0 {
        return Err(format!(
            "the session announces {} pending resource(s)",
            surface.resources
        ));
    }
    if !surface.backend_files.is_empty() {
        return Err(format!(
            "a command backend exists: {}",
            surface
                .backend_files
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(())
}

/// The instance and binding revision a step is compared against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    /// The instance.
    pub instance: ApplicationInstanceId,
    /// Its binding revision.
    pub revision: AgentBindingRevision,
}

impl Held {
    /// The instance and revision a detection and its binding show, where both show one.
    #[must_use]
    pub fn of(shown: &Shown) -> Option<Self> {
        Some(Self {
            instance: shown.detection.only()?.application_instance_id,
            revision: shown.binding.as_ref()?.binding.binding_revision,
        })
    }
}

/// Check (iii): after a step that keeps the process, its conversation and its upstream owner, the
/// same instance at the same binding revision.
///
/// # Errors
///
/// Returns what changed.
pub fn check_unchanged(before: Option<Held>, after: &Shown) -> Result<(), String> {
    let now = Held::of(after);
    match (before, now) {
        (None, None) if after.detection.instances.is_empty() => Ok(()),
        (Some(before), Some(now)) if before == now => Ok(()),
        (before, now) => Err(format!(
            "the instance and revision were {before:?} and are {now:?} ({} live)",
            after.detection.instances.len()
        )),
    }
}

/// Runs each check against a copy of the real observations made wrong on purpose, and returns what
/// each did. Every one must be rejected; the part fails otherwise.
#[must_use]
pub fn checker_controls(launched: &Launched, shown: &Shown, surface: &Surface) -> Vec<Value> {
    let mut controls = Vec::new();
    let mut control = |check: &str, wrong: &str, outcome: Result<(), String>| {
        controls.push(json!({
            "check": check,
            "wrong": wrong,
            "rejected": outcome.is_err(),
            "said": outcome.err(),
        }));
    };
    // (i): another package named by the one instance, and an execution that has ended.
    let mut other = shown.clone();
    for instance in &mut other.detection.instances {
        instance.plugin_id = Nullable::some(
            PluginId::new("kalareach/not-the-installed-package").expect("a plugin identifier"),
        );
    }
    if other.detection.instances.is_empty() {
        other
            .detection
            .instances
            .push(stand_in_instance("kalareach/not-the-installed-package"));
    }
    control(
        "detected",
        "the instance names another package",
        check_detected(launched, &other)
            .map(|_| ())
            .map_err(|undetected| undetected.why),
    );
    control(
        "detected",
        "the launched execution has ended",
        check_detected(
            &Launched {
                running: false,
                ..launched.clone()
            },
            shown,
        )
        .map(|_| ())
        .map_err(|undetected| undetected.why),
    );
    let mut retained = shown.clone();
    if retained.detection.instances.is_empty() {
        retained
            .detection
            .instances
            .push(stand_in_instance(launched.plugin_id.as_str()));
    }
    control(
        "ended",
        "an instance is still announced after its execution ended",
        check_ended(&retained),
    );
    // (ii): a usable prompt record, an accepted mutation, and a backend's registration.
    let mut usable = surface.clone();
    usable.records.push(("agent.prompt".to_owned(), true));
    control(
        "observation_only",
        "agent.prompt is usable",
        check_observation_only(&usable),
    );
    let mut accepted = surface.clone();
    accepted.answers.push(Answer {
        call: "agent.prompt.submit".to_owned(),
        refused: None,
        error: None,
        detail: "accepted".to_owned(),
    });
    let mut unanswered = surface.clone();
    unanswered.answers.push(Answer {
        call: "agent.prompt.submit".to_owned(),
        refused: None,
        error: Some("the connection ended".to_owned()),
        detail: "the connection ended".to_owned(),
    });
    control(
        "observation_only",
        "a typed mutation is answered by no refusal",
        check_observation_only(&unanswered),
    );
    control(
        "observation_only",
        "a typed mutation is accepted",
        check_observation_only(&accepted),
    );
    for file in ["c0/b0/registration.1.1", "c0/b0/launch", "c0/b0/credential"] {
        let mut backend = surface.clone();
        backend.backend_files.push(PathBuf::from(file));
        control(
            "observation_only",
            &format!("a command backend's {file} exists"),
            check_observation_only(&backend),
        );
    }
    // (iii): the same instance at a later revision.
    let before = Held::of(shown).unwrap_or(Held {
        instance: ApplicationInstanceId::new(kr_ipc::new_uuid()),
        revision: AgentBindingRevision::new(1),
    });
    let later = Held {
        revision: AgentBindingRevision::new(before.revision.get() + 1),
        ..before
    };
    control(
        "unchanged",
        "the binding revision moved on",
        check_unchanged(Some(later), shown),
    );
    controls
}

/// Whether every checker control rejected its wrong observation.
///
/// # Errors
///
/// Returns the controls that were not rejected.
pub fn all_rejected(controls: &[Value]) -> Result<(), String> {
    let accepted: Vec<&Value> = controls
        .iter()
        .filter(|control| control["rejected"] != true)
        .collect();
    if accepted.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "a check accepted an observation made wrong on purpose: {accepted:?}"
        ))
    }
}

/// An instance summary for a checker control where the host announced none.
fn stand_in_instance(plugin: &str) -> AgentInstanceSummary {
    AgentInstanceSummary {
        application_instance_id: ApplicationInstanceId::new(kr_ipc::new_uuid()),
        plugin_id: Nullable::some(PluginId::new(plugin).expect("a plugin identifier")),
        profile_id: Nullable::null(),
        mode: IntegrationMode::NativeTerminal,
        bypass: Nullable::null(),
        started_at: kr_ipc::now_ms(),
        ended_at: Nullable::null(),
        refusal: Nullable::some("stand-in".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::agent::AgentBindingState;
    use kr_protocol::broker::CapabilityMap;
    use kr_protocol::ids::LaunchProfileId;

    fn shown_with(instances: Vec<AgentInstanceSummary>) -> Shown {
        Shown {
            detection: Detection {
                instances,
                waited_ms: 0,
            },
            binding: None,
            live_bindings: None,
        }
    }

    fn launched(running: bool) -> Launched {
        Launched {
            plugin_id: PluginId::new("kalareach/example").expect("a plugin identifier"),
            running,
        }
    }

    /// Each way a launch is not detected as section 12 requires names its cause from the closed
    /// set and the number of instances the host announced, whatever the words say.
    #[test]
    fn each_way_a_launch_is_not_detected_names_its_cause_and_the_instances_announced() {
        let instance = || stand_in_instance("kalareach/example");
        let cause = |launched: &Launched, shown: &Shown| {
            check_detected(launched, shown)
                .expect_err("not detected")
                .cause
        };
        assert_eq!(
            cause(&launched(false), &shown_with(vec![instance()])),
            "ended"
        );
        assert_eq!(
            cause(&launched(true), &shown_with(Vec::new())),
            "not_one_instance"
        );
        assert_eq!(
            cause(&launched(true), &shown_with(vec![instance(), instance()])),
            "not_one_instance"
        );
        assert_eq!(
            cause(
                &launched(true),
                &shown_with(vec![stand_in_instance("kalareach/other")])
            ),
            "another_package"
        );
        let mut integrated = instance();
        integrated.mode = IntegrationMode::Gateway;
        assert_eq!(
            cause(&launched(true), &shown_with(vec![integrated])),
            "not_native_terminal"
        );
        let mut silent = instance();
        silent.refusal = Nullable::null();
        assert_eq!(
            cause(&launched(true), &shown_with(vec![silent])),
            "no_refusal"
        );
        assert_eq!(
            cause(&launched(true), &shown_with(vec![instance()])),
            "no_binding"
        );
        // A binding a device can read, and each way it does not fit the instance.
        let with_binding = |mode: IntegrationMode, profile: &str, live: Option<u64>| {
            let mut announced = instance();
            announced.profile_id = Nullable::some(LaunchProfileId::new("lp-1").expect("valid"));
            let mut shown = shown_with(vec![announced]);
            shown.binding = Some(AgentCapabilitiesResult {
                binding: AgentBindingState {
                    binding_revision: AgentBindingRevision::new(1),
                    thread_id: Nullable::null(),
                    turn_id: Nullable::null(),
                    profile_id: Nullable::some(LaunchProfileId::new(profile).expect("valid")),
                    mode,
                    rich_mutations_suspended: false,
                    suspension_reason: Nullable::null(),
                },
                capabilities: CapabilityMap {
                    records: Vec::new(),
                },
            });
            shown.live_bindings = live;
            shown
        };
        assert_eq!(
            cause(
                &launched(true),
                &with_binding(IntegrationMode::Gateway, "lp-1", Some(1))
            ),
            "binding_not_native_terminal"
        );
        assert_eq!(
            cause(
                &launched(true),
                &with_binding(IntegrationMode::NativeTerminal, "lp-2", Some(1))
            ),
            "binding_profile"
        );
        for live in [None, Some(0)] {
            assert_eq!(
                cause(
                    &launched(true),
                    &with_binding(IntegrationMode::NativeTerminal, "lp-1", live)
                ),
                "no_live_binding"
            );
        }
        assert!(
            check_detected(
                &launched(true),
                &with_binding(IntegrationMode::NativeTerminal, "lp-1", Some(1))
            )
            .is_ok(),
            "an instance that fits every check is detected"
        );
        let undetected = check_detected(&launched(true), &shown_with(vec![instance(), instance()]))
            .expect_err("two instances");
        assert_eq!(undetected.announced, 2);
        assert!(Undetected::CAUSES.contains(&undetected.cause));
        assert_eq!(
            detected_evidence(&Err(undetected.clone()))["cause"],
            "not_one_instance"
        );
        assert_eq!(detected_evidence(&Err(undetected))["announced"], 2);
    }
}
