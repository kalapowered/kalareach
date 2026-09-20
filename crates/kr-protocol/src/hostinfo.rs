//! Host and environment reads, read-only diagnostics, and the configuration they report.
//!
//! `host.doctor` reports; it does not repair unless an individual repair is requested, and it
//! redacts credentials rather than printing an environment snapshot. The redaction is
//! [`redaction::redact`], applied by [`HostDoctorResult::new`] to every check whichever code built
//! it, so it is a property of what leaves this host rather than of what each caller remembered.
//!
//! [`configuration`] holds the versioned per-user host configuration schema, the one precedence
//! function every ordinary preference resolves through, and the allowlist of environment
//! variables that participate in it. [`EffectiveConfiguration`] is what this host publishes about
//! itself: each value, where it came from and whether it applies immediately.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::desktop::SleepInhibitionState;
use crate::hello::ProtocolVersion;
use crate::identity::{BootIdentity, WorkerProfile};
use crate::ids::{BuildId, ControllerGeneration, EnvironmentId};
use crate::scalars::{Nullable, TimestampMs, U64};

/// The result of `host.info`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostInfoResult {
    /// The controller build.
    pub build_id: BuildId,
    /// The protocol version this build implements.
    pub protocol_version: ProtocolVersion,
    /// The environment this controller owns.
    pub environment_id: EnvironmentId,
    /// The controller's current generation. A replacement controller uses a strictly higher one.
    pub generation: ControllerGeneration,
    /// The boot this host is running.
    pub boot_identity: BootIdentity,
    /// When this controller process started serving.
    pub started_at_ms: TimestampMs,
    /// How many sessions are live or creating.
    pub live_sessions: U64,
    /// The configured admission limit.
    pub session_limit: U64,
    /// The worker profile this host creates sessions with unless the request says otherwise.
    pub default_worker_profile: WorkerProfile,
    /// What this host's sleep inhibition is doing, whether it is active or not.
    pub power: SleepInhibitionState,
}

/// One environment this host serves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSummary {
    /// The environment identity. It binds one installation and one OS user.
    pub environment_id: EnvironmentId,
    /// A label for people.
    pub label: String,
    /// The operating system.
    pub os: String,
    /// The processor architecture.
    pub arch: String,
    /// The OS user the environment belongs to.
    pub os_user: String,
    /// The runtime directory holding sockets and worker descriptors.
    pub runtime_directory: String,
    /// The state directory holding the registry, journals and spools.
    pub state_directory: String,
    /// How many sessions are live or creating.
    pub live_sessions: U64,
}

/// The result of `environment.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentListResult {
    /// The environments.
    pub environments: Vec<EnvironmentSummary>,
}

/// What one diagnostic check found.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    /// The check passed.
    Ok,
    /// The check passed with something worth knowing.
    Warning,
    /// The check failed.
    Failed,
    /// The check does not apply to this platform or configuration.
    NotApplicable,
}

impl DoctorStatus {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Failed => "failed",
            Self::NotApplicable => "not_applicable",
        }
    }

    /// Returns true when the check should stop an exit code from being zero.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Failed)
    }
}

/// One diagnostic check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheck {
    /// A stable identifier for the check.
    pub id: String,
    /// What it examines.
    pub title: String,
    /// What it found.
    pub status: DoctorStatus,
    /// A plain description of the finding, with credentials redacted.
    ///
    /// Redacted by [`HostDoctorResult::new`] rather than by whoever wrote the sentence. A check's
    /// detail is built from paths, command lines and errors from libraries, and any of those can
    /// carry a token that the person writing the check never thought about.
    pub detail: String,
    /// What the user should do, when the check did not pass. Redacted the same way.
    pub remedy: Nullable<String>,
}

impl DoctorCheck {
    /// Builds one check.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        status: DoctorStatus,
        detail: impl Into<String>,
        remedy: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            status,
            detail: detail.into(),
            remedy: Nullable(remedy),
        }
    }

    /// Returns this check with every credential-shaped run in it replaced.
    #[must_use]
    pub fn redacted(self) -> Self {
        Self {
            detail: redaction::redact(&self.detail),
            remedy: Nullable(self.remedy.0.as_deref().map(redaction::redact)),
            ..self
        }
    }

    /// Returns the evidence lines `kr doctor --verbose` prints under this check.
    #[must_use]
    pub fn evidence(&self) -> Vec<String> {
        let mut lines = vec![self.detail.clone()];
        if let Some(remedy) = self.remedy.as_ref() {
            lines.push(remedy.clone());
        }
        lines
    }
}

/// The result of `host.doctor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostDoctorResult {
    /// Every check, in the order they ran.
    pub checks: Vec<DoctorCheck>,
    /// True when no check failed.
    pub healthy: bool,
    /// What this host's configuration currently resolves to.
    ///
    /// Section 26 asks `kr doctor` to report the schema, the locations and each effective value
    /// with its source, so the host answers with them rather than leaving a command to read the
    /// document a second time and reach its own conclusion about the platform's defaults.
    pub configuration: EffectiveConfiguration,
}

impl HostDoctorResult {
    /// Builds the result from the checks that ran, redacting every one of them.
    ///
    /// This is the boundary the promise on [`DoctorCheck::detail`] is kept at. A check reaches the
    /// wire only through here, so a credential in a path, a command line or a library's error
    /// message is gone whether or not the check that built the sentence thought about it.
    #[must_use]
    pub fn new(checks: Vec<DoctorCheck>, configuration: EffectiveConfiguration) -> Self {
        let checks: Vec<DoctorCheck> = checks.into_iter().map(DoctorCheck::redacted).collect();
        let healthy = checks.iter().all(|check| !check.status.is_failure());
        Self {
            checks,
            healthy,
            configuration: configuration.redacted(),
        }
    }
}

/// One effective configuration value, with where it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectiveValue {
    /// The key, as the configuration document spells it.
    pub key: String,
    /// What it decides.
    pub about: String,
    /// The value in force, in its stable spelling.
    pub value: String,
    /// The rung of the precedence ladder it came from.
    pub source: configuration::ValueSource,
    /// The profile's name or the document's path, when the rung had one.
    pub origin: Nullable<String>,
    /// The allowlisted environment variable that supplied it, when one did.
    pub variable: Nullable<String>,
    /// Whether it applies immediately or only to sessions created afterwards.
    pub effect: configuration::ValueEffect,
}

/// One ceiling, with what was configured and what it actually came out as.
///
/// A ceiling is an intersection. `configured` is what this host's configuration asked for and
/// `value` is what survived the intersection with authority, the organisation's restrictions, the
/// grant and the hard resource limit; `narrowed_by` names what did the narrowing when they differ.
/// A configured value that was more permissive than the intersection is refused rather than
/// applied, and `refused` says so.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CeilingValue {
    /// The key.
    pub key: String,
    /// What the configuration asked for, when it asked for anything.
    pub configured: Nullable<String>,
    /// What is in force.
    pub value: String,
    /// The rung of the precedence ladder it came from.
    pub source: configuration::ValueSource,
    /// The document's path, when the rung had one.
    pub origin: Nullable<String>,
    /// Whether it applies immediately or only to sessions created afterwards.
    pub effect: configuration::ValueEffect,
    /// What narrowed the configured value, when something did.
    pub narrowed_by: Nullable<String>,
    /// True when the configured value was more permissive and was refused.
    pub refused: bool,
}

/// One documented environment override, and whether it is set here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OverrideReport {
    /// The variable.
    pub variable: String,
    /// The preference it supplies.
    pub preference: String,
    /// The rung it acts at.
    pub position: configuration::ValueSource,
    /// Why it acts there.
    pub why: String,
    /// Whether this host has it set.
    pub set: bool,
}

/// What this host's configuration currently resolves to, and where every part of it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectiveConfiguration {
    /// The schema version this build reads and writes.
    pub schema_version: U64,
    /// The revision this host has applied.
    pub revision: U64,
    /// Where the configuration document is.
    pub document: String,
    /// What that document turned out to be.
    pub status: configuration::DocumentStatus,
    /// The runtime directory this platform uses.
    pub runtime_directory: String,
    /// The state directory this platform uses.
    pub state_directory: String,
    /// The precedence ladder, highest first.
    pub precedence: Vec<String>,
    /// The documented environment overrides.
    pub overrides: Vec<OverrideReport>,
    /// Every ordinary preference, with its source.
    pub values: Vec<EffectiveValue>,
    /// Every ceiling, with what narrowed it.
    pub ceilings: Vec<CeilingValue>,
    /// The secure-store references this configuration names. Names only, never values.
    pub secrets: Vec<configuration::SecretReference>,
    /// Documents found beside the configuration that this build no longer reads.
    pub stale_documents: Vec<String>,
}

impl EffectiveConfiguration {
    /// Returns this report with every credential-shaped run in it replaced.
    ///
    /// A report is built from a parser's own error messages, from paths and from whatever a
    /// document held, so it goes through the same boundary the checks do. Nothing here is
    /// structured differently afterwards: only the free text changes.
    #[must_use]
    pub fn redacted(self) -> Self {
        Self {
            document: redaction::redact(&self.document),
            status: configuration::DocumentStatus {
                state: self.status.state,
                detail: redaction::redact(&self.status.detail),
            },
            runtime_directory: redaction::redact(&self.runtime_directory),
            state_directory: redaction::redact(&self.state_directory),
            values: self
                .values
                .into_iter()
                .map(|value| EffectiveValue {
                    value: redaction::redact(&value.value),
                    origin: Nullable(value.origin.0.as_deref().map(redaction::redact)),
                    ..value
                })
                .collect(),
            ceilings: self
                .ceilings
                .into_iter()
                .map(|ceiling| CeilingValue {
                    configured: Nullable(ceiling.configured.0.as_deref().map(redaction::redact)),
                    value: redaction::redact(&ceiling.value),
                    ..ceiling
                })
                .collect(),
            stale_documents: self
                .stale_documents
                .iter()
                .map(|path| redaction::redact(path))
                .collect(),
            ..self
        }
    }

    /// The report of a host whose configuration has not been read.
    ///
    /// Used where a result is assembled before a document has been looked at, and by tests that
    /// are about the checks rather than about the configuration. It says plainly that nothing was
    /// read, so it can never be mistaken for a host that read a document and found nothing.
    #[must_use]
    pub fn unread() -> Self {
        Self {
            schema_version: U64::new(configuration::VERSION),
            revision: U64::ZERO,
            document: String::new(),
            status: configuration::DocumentStatus {
                state: configuration::DocumentState::Absent,
                detail: "this report was built without reading a configuration document".to_owned(),
            },
            runtime_directory: String::new(),
            state_directory: String::new(),
            precedence: configuration::PRECEDENCE
                .iter()
                .map(|source| source.describe().to_owned())
                .collect(),
            overrides: Vec::new(),
            values: Vec::new(),
            ceilings: Vec::new(),
            secrets: Vec::new(),
            stale_documents: Vec::new(),
        }
    }
}

/// One component's version, for a support bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SoftwareComponent {
    /// What it is.
    pub component: String,
    /// Which version of it.
    pub version: String,
}

/// One error a support bundle carries, already redacted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedactedError {
    /// What produced it.
    pub component: String,
    /// What it said, with anything credential-shaped replaced.
    pub message: String,
}

impl RedactedError {
    /// Records one error, redacted.
    ///
    /// The redaction happens here rather than at the caller, so an error carried in from a library
    /// is redacted by the act of putting it in a bundle.
    #[must_use]
    pub fn new(component: impl Into<String>, message: &str) -> Self {
        Self {
            component: component.into(),
            message: redaction::redact(message),
        }
    }
}

/// What a content-bearing diagnostic export will include.
///
/// Section 26 makes this an explicit user selection, so it exists only when the person asked for
/// it and it names what it will contain before anything is written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentExport {
    /// What the person chose, in the words the command printed to them.
    pub includes: Vec<String>,
    /// The entries the archive carries because of that choice.
    pub entries: Vec<String>,
}

/// A support bundle: software versions, capabilities and redacted errors.
///
/// Section 26 says what one shows, and the word that carries the weight is "redacted".
/// [`SupportBundle::new`] redacts everything it is given, so a bundle cannot carry a credential
/// because a caller forgot. Terminal content, prompts, attachment filenames and anything else
/// content-bearing are not here at all: they arrive only through [`ContentExport`], which exists
/// only when the person explicitly selected it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportBundle {
    /// When it was made.
    pub generated_at_ms: TimestampMs,
    /// The software this host is running.
    pub software: Vec<SoftwareComponent>,
    /// What this host can currently do, as the shared section 11 evidence.
    pub capabilities: Vec<crate::desktop::CapabilityRecord>,
    /// What the diagnostics found.
    pub doctor: HostDoctorResult,
    /// What this host's configuration resolves to.
    pub configuration: EffectiveConfiguration,
    /// The errors this host has to report, redacted.
    pub errors: Vec<RedactedError>,
    /// The content-bearing export, when the person explicitly selected one.
    pub content: Nullable<ContentExport>,
}

impl SupportBundle {
    /// Builds a bundle, redacting everything in it.
    #[must_use]
    pub fn new(
        generated_at_ms: TimestampMs,
        software: Vec<SoftwareComponent>,
        capabilities: Vec<crate::desktop::CapabilityRecord>,
        doctor: HostDoctorResult,
        configuration: EffectiveConfiguration,
        errors: Vec<RedactedError>,
    ) -> Self {
        Self {
            generated_at_ms,
            software,
            // A capability record's user-facing sentence is written by whatever probed the
            // capability, and a probe that named a command line or a path is how a credential
            // would arrive here. It goes through the same boundary as everything else.
            capabilities: capabilities
                .into_iter()
                .map(|record| crate::desktop::CapabilityRecord {
                    disabled_reason: Nullable(
                        record.disabled_reason.0.as_deref().map(redaction::redact),
                    ),
                    // The identity is the binary a probe found and the version it reported, both
                    // of which come from outside this host.
                    identity: crate::desktop::CapabilityIdentity {
                        binary: Nullable(
                            record.identity.binary.0.as_deref().map(redaction::redact),
                        ),
                        version: Nullable(
                            record.identity.version.0.as_deref().map(redaction::redact),
                        ),
                        ..record.identity
                    },
                    ..record
                })
                .collect(),
            doctor: HostDoctorResult::new(doctor.checks, doctor.configuration),
            configuration: configuration.redacted(),
            errors: errors
                .into_iter()
                .map(|error| RedactedError::new(error.component, &error.message))
                .collect(),
            content: Nullable::null(),
        }
    }

    /// Adds the content-bearing export the person explicitly selected.
    #[must_use]
    pub fn with_content(mut self, content: ContentExport) -> Self {
        self.content = Nullable::some(content);
        self
    }
}

/// The versioned per-user host configuration schema, its precedence and its overrides.
///
/// Section 26 asks for one versioned, documented configuration schema, native OS-appropriate
/// locations, one precedence order for ordinary preferences, an allowlist of environment
/// overrides that act at a declared position, and ceilings that intersect rather than default.
/// This module is the half both a writer and a reader agree about: the document's shape, the rule
/// for a version this build does not know, the bound on how much of it is read, the validation an
/// edit passes before a revision is applied, and the one function every ordinary preference
/// resolves through.
///
/// The half it is not is where the file lives. That is the environment's own state directory,
/// which each process already holds, so the two readers in `kr-worker` and `kr-controller` join
/// [`FILE_NAME`] to it and hand the bytes here.
///
/// # The document
///
/// ```json
/// {
///   "version": 1,
///   "revision": 3,
///   "preferences": { "sleep_inhibition": "mains_only" },
///   "profiles": { "review": { "shell_mode": "native_compat" } },
///   "default_profile": null,
///   "ceilings": { "session_limit": 16 },
///   "secrets": [{ "name": "relay", "store": "login_keychain", "item": "kalareach/relay" }]
/// }
/// ```
///
/// Its numbers are ordinary JSON numbers rather than the decimal strings the wire types use. This
/// is a file a person may open and edit, not a message a JavaScript consumer parses, and the
/// counters in it are small enough that no precision is at stake. The report this host publishes
/// *about* the file ([`EffectiveConfiguration`]) is a message, and it uses the wire form.
///
/// # A version this build does not know
///
/// The document is left exactly as it is, nothing is read out of it, every preference takes the
/// product default, and `kr doctor` reports the version it found. Guessing at a newer document's
/// meaning is how a host applies a setting its owner never chose, and rewriting it is how an older
/// build destroys a newer one's choices.
///
/// # Precedence
///
/// Explicit request or CLI option, then the selected session or environment profile, then the
/// per-user host configuration, then the product default. [`resolve`] is the whole of that rule
/// and every ordinary preference goes through it, so a new preference cannot quietly invent an
/// order of its own.
///
/// Environment variables are not a rung. Only the variables in [`ALLOWLIST`] participate, each at
/// the rung its entry declares, and an inherited variable outside it changes nothing at all. No
/// entry may name authority, an organisation restriction, a grant ceiling, a hard resource limit
/// or a provider origin: those are intersections rather than preferences, and [`ALLOWLIST`] is
/// tested against the preference table for exactly that.
///
/// # The creator's shell environment
///
/// A session create request carries it as `SessionCreateParams::environment_snapshot`, and the
/// worker builds the session's shell environment from it. Nothing this host decides is taken from
/// it, and nothing here reads it: [`resolve`] takes its rungs from the request, the document and
/// the product default, and the allowlisted overrides are read from the *host's* own environment.
/// That is what keeps a variable a person happened to export in one terminal from changing how the
/// host behaves for everybody.
pub mod configuration {
    use std::collections::BTreeMap;

    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    use crate::desktop::SleepInhibitionSetting;
    use crate::identity::WorkerProfile;
    use crate::scalars::Nullable;

    /// The configuration document, in the environment's own state directory.
    pub const FILE_NAME: &str = "config.json";

    /// Returns the short prefix for an environment id.
    #[must_use]
    pub fn short_prefix(environment_id: crate::ids::EnvironmentId) -> String {
        let bytes = environment_id.get();
        let bytes = bytes.as_bytes();
        let mut prefix = String::with_capacity(8);
        for byte in &bytes[..4] {
            use std::fmt::Write as _;
            let _ = write!(&mut prefix, "{byte:02x}");
        }
        prefix
    }

    /// Returns where this environment's configuration document is.
    #[must_use]
    pub fn document_path(
        state_dir: &std::path::Path,
        state_root: &std::path::Path,
        environment_id: crate::ids::EnvironmentId,
    ) -> std::path::PathBuf {
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            if is_normal_linux_install(state_root)
                && let Some(config_root) = linux_config_root()
            {
                let prefix = short_prefix(environment_id);
                return config_root
                    .join("environments")
                    .join(prefix)
                    .join(FILE_NAME);
            }
        }
        let _ = (state_root, environment_id);
        state_dir.join(FILE_NAME)
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn linux_config_root() -> Option<std::path::PathBuf> {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(|value| std::path::PathBuf::from(value).join("kalareach"))
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|home| !home.is_empty())
                    .map(|home| {
                        std::path::PathBuf::from(home)
                            .join(".config")
                            .join("kalareach")
                    })
            })
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    fn is_normal_linux_install(state_root: &std::path::Path) -> bool {
        if std::env::var_os("KR_STATE_DIR").is_some() {
            return false;
        }
        let expected = if let Some(value) = std::env::var_os("XDG_STATE_HOME") {
            std::path::PathBuf::from(value).join("kalareach")
        } else if let Some(home) = std::env::var_os("HOME") {
            std::path::PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("kalareach")
        } else {
            return false;
        };
        state_root == expected
    }

    /// Reads a configuration file, bounded by `limit` bytes.
    pub fn read_file(path: &std::path::Path, limit: u64) -> Result<Option<Vec<u8>>, String> {
        use std::io::Read as _;

        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if metadata.uid() != rustix::process::getuid().as_raw() {
                return Err("configuration file is not owned by this user".to_owned());
            }
            if metadata.mode() & 0o077 != 0 {
                return Err("configuration file has permissions wider than owner-only".to_owned());
            }
            if !metadata.is_file() {
                return Err("configuration file must be a regular file".to_owned());
            }
            if metadata.len() > limit {
                return Err(format!("this file is larger than the {limit} byte bound"));
            }
        }
        #[cfg(not(unix))]
        {
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file() {
                return Err("configuration file must be a regular file".to_owned());
            }
            if metadata.len() > limit {
                return Err(format!("this file is larger than the {limit} byte bound"));
            }
        }
        let mut bytes = Vec::new();
        (&file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 > limit {
            return Err(format!("this file is larger than the {limit} byte bound"));
        }
        Ok(Some(bytes))
    }

    /// The version this build writes and reads.
    pub const VERSION: u64 = 1;

    /// The longest configuration document this host reads.
    ///
    /// The document holds a few preferences, a handful of profiles and a list of secret *names*.
    /// A file larger than this is not one of ours, and reading it would be reading something else.
    pub const MAX_LEN: u64 = 64 * 1024;

    /// The document the sleep setting used to live in, before this schema absorbed it.
    ///
    /// Nothing reads it. It is named here only so `kr doctor` can say, in one line, that a file it
    /// found in the state directory is stale and is being ignored.
    pub const SUPERSEDED_FILE_NAME: &str = "power.json";

    /// The longest name a profile, a secret reference or a secret store may have.
    pub const MAX_NAME_LEN: usize = 128;

    /// How many profiles one document may declare.
    pub const MAX_PROFILES: usize = 64;

    /// How many secret references one document may declare.
    pub const MAX_SECRETS: usize = 128;

    /// The default repository metadata budget, in bytes (section 11: 64 MiB).
    pub const DEFAULT_METADATA_BYTES: u64 = 64 * 1024 * 1024;

    /// The default repository metadata budget, in entries (section 11: 100,000).
    pub const DEFAULT_METADATA_ENTRIES: u64 = 100_000;

    /// The default cached payload budget, in bytes (section 11: 1 GiB).
    pub const DEFAULT_CACHED_PAYLOAD_BYTES: u64 = 1024 * 1024 * 1024;

    /// How many metadata generations a repository retains by default.
    ///
    /// Section 11 names a retained-generation budget without a number. Two is the smallest that
    /// keeps a rollback target: the generation in use and the one before it.
    pub const DEFAULT_RETAINED_GENERATIONS: u64 = 2;

    /// The largest single package or asset fetched by default, in bytes.
    pub const DEFAULT_PACKAGE_BYTES: u64 = 256 * 1024 * 1024;

    /// How many objects one package may hold by default.
    pub const DEFAULT_OBJECT_COUNT: u64 = 100_000;

    /// The largest an expanded pack may become by default, in bytes.
    pub const DEFAULT_EXPANDED_PACK_BYTES: u64 = 512 * 1024 * 1024;

    /// How many bytes one synchronisation may transfer by default.
    pub const DEFAULT_TRANSFER_BYTES: u64 = 2 * 1024 * 1024 * 1024;

    /// How long one package's compilation may take by default, in milliseconds.
    pub const DEFAULT_COMPILATION_MS: u64 = 60_000;

    // ---------------------------------------------------------------------------------------
    // The document
    // ---------------------------------------------------------------------------------------

    /// One versioned per-user host configuration document.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    pub struct ConfigurationDocument {
        /// The schema version this document is written against.
        pub version: u64,
        /// The revision this host applied. It rises by one with every validated edit.
        pub revision: u64,
        /// The ordinary preferences that apply when no profile is selected.
        pub preferences: PreferenceSet,
        /// Named profiles, each a set of the same preferences.
        pub profiles: BTreeMap<String, PreferenceSet>,
        /// The profile selected when a request and the allowlist name none.
        pub default_profile: Nullable<String>,
        /// The ceilings this host configures. They intersect; they never raise anything.
        pub ceilings: ConfigurationCeilings,
        /// Named secure-store references. Never a secret value: this schema has no field one fits
        /// in, which is what section 26's "named secure-store references, never config exports"
        /// looks like when it is enforced rather than promised.
        pub secrets: Vec<SecretReference>,
    }

    impl Default for ConfigurationDocument {
        /// A document at this build's version with nothing chosen.
        ///
        /// It is also what an absent section deserialises to, which is why a document naming only
        /// one preference is a complete document rather than a partial one.
        fn default() -> Self {
            Self {
                version: VERSION,
                revision: 0,
                preferences: PreferenceSet::default(),
                profiles: BTreeMap::new(),
                default_profile: Nullable::null(),
                ceilings: ConfigurationCeilings::default(),
                secrets: Vec::new(),
            }
        }
    }

    impl ConfigurationDocument {
        /// A document at this build's version with nothing chosen.
        #[must_use]
        pub fn empty() -> Self {
            Self::default()
        }

        /// Returns the preference set a selected profile contributes, when it names one.
        #[must_use]
        pub fn profile(&self, selected: Option<&str>) -> Option<(&str, &PreferenceSet)> {
            let name = selected.or_else(|| self.default_profile.as_ref().map(String::as_str))?;
            self.profiles
                .get_key_value(name)
                .map(|(name, set)| (name.as_str(), set))
        }
    }

    /// The ordinary preferences, each absent unless this document chooses it.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    pub struct PreferenceSet {
        /// Whether this host keeps itself awake for work it has admitted, and on which power
        /// source.
        pub sleep_inhibition: Nullable<SleepInhibitionSetting>,
        /// The execution context a session is created in when the request does not choose one.
        pub worker_profile: Nullable<WorkerProfile>,
    }

    impl Default for PreferenceSet {
        /// A set that chooses nothing, which is what an absent section means.
        fn default() -> Self {
            Self {
                sleep_inhibition: Nullable::null(),
                worker_profile: Nullable::null(),
            }
        }
    }

    /// The ceilings this host configures.
    ///
    /// Every one of them narrows. A configured value above what authority, an organisation
    /// restriction, a grant or a hard resource limit already allows is rejected rather than
    /// applied, which is section 26's second paragraph and why these are not in
    /// [`PreferenceSet`].
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    pub struct ConfigurationCeilings {
        /// The most sessions this host admits, when the owner chooses a number.
        ///
        /// Section 2 makes 128 the default and says the owner configures it; the intersection is
        /// with what this machine's own resources allow, not with the default.
        pub session_limit: Nullable<u64>,
        /// The rights a grant may carry on this host, as the stable action-right strings.
        ///
        /// Absent leaves the grant's own intersection untouched. Present narrows it: a right not
        /// in this list is not available on this host however a grant was issued.
        pub grant_rights: Nullable<Vec<String>>,
        /// The repository enrolment budgets section 11 calls configuration.
        pub enrolment: Nullable<EnrolmentBudgets>,
    }

    impl Default for ConfigurationCeilings {
        /// No configured ceiling.
        fn default() -> Self {
            Self {
                session_limit: Nullable::null(),
                grant_rights: Nullable::null(),
                enrolment: Nullable::null(),
            }
        }
    }

    impl ConfigurationCeilings {
        /// Returns the enrolment budgets in force, defaulting to section 11's values.
        #[must_use]
        pub fn enrolment_budgets(&self) -> EnrolmentBudgets {
            self.enrolment.0.unwrap_or_default()
        }
    }

    /// The repository enrolment budgets, checked before a fetch and during processing.
    ///
    /// Section 11 sets each default and says a larger full mirror needs an explicit setting. The
    /// catalogue client reads them through this host's configuration rather than carrying its own
    /// copy, so one document answers "what may a repository cost here".
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    pub struct EnrolmentBudgets {
        /// The metadata budget per repository, in bytes.
        pub metadata_bytes: u64,
        /// The metadata budget per repository, in entries.
        pub metadata_entries: u64,
        /// How many metadata generations a repository may retain.
        pub retained_generations: u64,
        /// The cached payload budget per repository, in bytes.
        pub cached_payload_bytes: u64,
        /// The largest single package or asset a repository may fetch, in bytes.
        pub package_bytes: u64,
        /// How many objects one package may hold.
        pub object_count: u64,
        /// The largest an expanded pack may become, in bytes, checked during processing.
        pub expanded_pack_bytes: u64,
        /// How many bytes one synchronisation may transfer.
        pub transfer_bytes: u64,
        /// How long one package's compilation may take, in milliseconds.
        pub compilation_ms: u64,
        /// Whether this host keeps a full offline mirror, which is the explicit setting a payload
        /// budget above the default needs.
        pub full_offline_mirror: bool,
    }

    impl Default for EnrolmentBudgets {
        /// Section 11's own numbers, which are what a repository costs here until an owner says
        /// otherwise.
        fn default() -> Self {
            Self {
                metadata_bytes: DEFAULT_METADATA_BYTES,
                metadata_entries: DEFAULT_METADATA_ENTRIES,
                retained_generations: DEFAULT_RETAINED_GENERATIONS,
                cached_payload_bytes: DEFAULT_CACHED_PAYLOAD_BYTES,
                package_bytes: DEFAULT_PACKAGE_BYTES,
                object_count: DEFAULT_OBJECT_COUNT,
                expanded_pack_bytes: DEFAULT_EXPANDED_PACK_BYTES,
                transfer_bytes: DEFAULT_TRANSFER_BYTES,
                compilation_ms: DEFAULT_COMPILATION_MS,
                full_offline_mirror: false,
            }
        }
    }

    /// A named reference to something in a secure store.
    ///
    /// The name, the store and the item. No value, and no field a value fits in.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct SecretReference {
        /// What this configuration calls it.
        pub name: String,
        /// The secure store it lives in.
        pub store: String,
        /// Its name inside that store.
        pub item: String,
    }

    // ---------------------------------------------------------------------------------------
    // Reading a document
    // ---------------------------------------------------------------------------------------

    /// Which of the five conditions a configuration document is in.
    #[derive(
        Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
    )]
    #[serde(rename_all = "snake_case")]
    pub enum DocumentState {
        /// No document. Every preference is the product default, which is the ordinary first run.
        Absent,
        /// A document this build wrote or understands.
        Loaded,
        /// A document declaring a version this build does not know. It is left alone and nothing
        /// is read out of it.
        UnknownVersion,
        /// A document this host could not read: a link, another user's file, or one larger than
        /// [`MAX_LEN`].
        Unreadable,
        /// A document at this version whose contents are not valid against the schema.
        Invalid,
    }

    impl DocumentState {
        /// Returns the stable wire string.
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Absent => "absent",
                Self::Loaded => "loaded",
                Self::UnknownVersion => "unknown_version",
                Self::Unreadable => "unreadable",
                Self::Invalid => "invalid",
            }
        }

        /// Returns true when this host is running on product defaults because it could not use the
        /// document it found.
        #[must_use]
        pub const fn is_a_problem(self) -> bool {
            matches!(
                self,
                Self::UnknownVersion | Self::Unreadable | Self::Invalid
            )
        }
    }

    /// What a configuration document turned out to be, and what a person is told about it.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct DocumentStatus {
        /// The condition.
        pub state: DocumentState,
        /// A sentence naming what was found.
        pub detail: String,
    }

    /// A document this host read, or the reason it is using defaults instead.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Loaded {
        /// The document, when one could be used.
        pub document: Option<ConfigurationDocument>,
        /// What it turned out to be.
        pub status: DocumentStatus,
    }

    impl Loaded {
        /// Returns the preference set the host-configuration rung contributes.
        #[must_use]
        pub fn preferences(&self) -> Option<&PreferenceSet> {
            self.document.as_ref().map(|document| &document.preferences)
        }

        /// Returns the revision this host has applied, or zero when there is no document.
        #[must_use]
        pub fn revision(&self) -> u64 {
            self.document
                .as_ref()
                .map_or(0, |document| document.revision)
        }

        /// Returns the ceilings this document configures, or the defaults.
        #[must_use]
        pub fn ceilings(&self) -> ConfigurationCeilings {
            self.document
                .as_ref()
                .map(|document| document.ceilings.clone())
                .unwrap_or_default()
        }
    }

    /// Reads the bytes of a configuration document.
    ///
    /// `bytes` is `None` when the file is not there, which is the ordinary first run rather than a
    /// fault. Everything else this build cannot use leaves the document exactly where it is and
    /// falls back to the product defaults with a status that says why, because a host that
    /// silently ran on defaults would be a host whose owner's choices had quietly stopped
    /// applying.
    #[must_use]
    pub fn load(bytes: Option<&[u8]>) -> Loaded {
        let Some(bytes) = bytes else {
            return Loaded {
                document: None,
                status: DocumentStatus {
                    state: DocumentState::Absent,
                    detail: "no configuration document; every value is the product default"
                        .to_owned(),
                },
            };
        };
        let value: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(error) => return invalid(vec![format!("this file is not JSON: {error}")]),
        };
        // The version is read before anything else in the document is believed. A document at a
        // version this build does not know is not this build's to interpret or to rewrite.
        let declared = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(VERSION);
        if declared != VERSION {
            return Loaded {
                document: None,
                status: DocumentStatus {
                    state: DocumentState::UnknownVersion,
                    detail: format!(
                        "this document declares version {declared} and this build knows version \
                         {VERSION}; it is left alone and every value is the product default"
                    ),
                },
            };
        }
        let document: ConfigurationDocument = match serde_json::from_value(value) {
            Ok(document) => document,
            Err(error) => return invalid(vec![error.to_string()]),
        };
        if let Err(problems) = validate(&document) {
            return invalid(problems);
        }
        Loaded {
            document: Some(document),
            status: DocumentStatus {
                state: DocumentState::Loaded,
                detail: format!("version {VERSION}"),
            },
        }
    }

    /// The load a document this host could not read produces.
    #[must_use]
    pub fn unreadable(detail: &str) -> Loaded {
        Loaded {
            document: None,
            status: DocumentStatus {
                state: DocumentState::Unreadable,
                detail: format!(
                    "{detail}; this document is left alone and every value is the product default"
                ),
            },
        }
    }

    /// The load an invalid document produces.
    fn invalid(problems: Vec<String>) -> Loaded {
        Loaded {
            document: None,
            status: DocumentStatus {
                state: DocumentState::Invalid,
                detail: format!(
                    "{}; this document is left alone and every value is the product default",
                    problems.join("; ")
                ),
            },
        }
    }

    /// Returns the file contents that record one document.
    #[must_use]
    pub fn contents(document: &ConfigurationDocument) -> String {
        let mut text = serde_json::to_string_pretty(document)
            .unwrap_or_else(|_| "{\"version\": 1}".to_owned());
        text.push('\n');
        text
    }

    // ---------------------------------------------------------------------------------------
    // Validation and edits
    // ---------------------------------------------------------------------------------------

    /// Checks a document against every rule this schema states.
    ///
    /// # Errors
    ///
    /// Returns every problem it found rather than the first, because an edit is refused once and
    /// a person fixing it should see the whole list.
    pub fn validate(document: &ConfigurationDocument) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();
        if document.version != VERSION {
            problems.push(format!(
                "version {} is not the version this build writes ({VERSION})",
                document.version
            ));
        }
        if document.profiles.len() > MAX_PROFILES {
            problems.push(format!(
                "{} profiles is more than the {MAX_PROFILES} this schema allows",
                document.profiles.len()
            ));
        }
        for name in document.profiles.keys() {
            if name.is_empty() || name.len() > MAX_NAME_LEN {
                problems.push(format!(
                    "profile name {name:?} must be between 1 and {MAX_NAME_LEN} characters"
                ));
            }
        }
        if let Some(selected) = document.default_profile.as_ref()
            && !document.profiles.contains_key(selected)
        {
            problems.push(format!(
                "default_profile {selected:?} names no profile in this document"
            ));
        }
        if let Some(limit) = document.ceilings.session_limit.as_ref()
            && *limit == 0
        {
            problems.push("session_limit 0 would admit no session at all".to_owned());
        }
        if let Some(rights) = document.ceilings.grant_rights.as_ref() {
            for right in rights {
                if crate::rights::ActionRight::from_wire(right).is_none() {
                    problems.push(format!("{right:?} is not an action right"));
                }
            }
        }
        if let Some(budgets) = document.ceilings.enrolment.0.as_ref() {
            for (field, value) in [
                ("metadata_bytes", budgets.metadata_bytes),
                ("metadata_entries", budgets.metadata_entries),
                ("retained_generations", budgets.retained_generations),
                ("cached_payload_bytes", budgets.cached_payload_bytes),
                ("package_bytes", budgets.package_bytes),
                ("object_count", budgets.object_count),
                ("expanded_pack_bytes", budgets.expanded_pack_bytes),
                ("transfer_bytes", budgets.transfer_bytes),
                ("compilation_ms", budgets.compilation_ms),
            ] {
                if value == 0 {
                    problems.push(format!(
                        "an enrolment budget of zero for {field} would enrol no repository"
                    ));
                }
            }
            if budgets.cached_payload_bytes > DEFAULT_CACHED_PAYLOAD_BYTES
                && !budgets.full_offline_mirror
            {
                problems.push(format!(
                    "a cached payload budget above {DEFAULT_CACHED_PAYLOAD_BYTES} bytes is a full \
                     mirror and needs full_offline_mirror set explicitly"
                ));
            }
        }
        if document.secrets.len() > MAX_SECRETS {
            problems.push(format!(
                "{} secret references is more than the {MAX_SECRETS} this schema allows",
                document.secrets.len()
            ));
        }
        for reference in &document.secrets {
            for (field, value) in [
                ("name", &reference.name),
                ("store", &reference.store),
                ("item", &reference.item),
            ] {
                if value.is_empty() || value.len() > MAX_NAME_LEN {
                    problems.push(format!(
                        "secret reference {field} {value:?} must be between 1 and \
                         {MAX_NAME_LEN} characters"
                    ));
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    /// One change to a configuration document.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Change {
        /// Set this host's sleep policy.
        SleepInhibition(SleepInhibitionSetting),
        /// Set the execution context a session is created in by default.
        WorkerProfile(WorkerProfile),
        /// Set this host's configured session ceiling, or clear it.
        SessionLimit(Option<u64>),
        /// Set the rights a grant may carry on this host, or clear the ceiling.
        GrantRights(Option<Vec<String>>),
        /// Set this host's repository enrolment budgets.
        Enrolment(EnrolmentBudgets),
    }

    impl Change {
        /// Returns the preference or ceiling key this change names.
        #[must_use]
        pub const fn key(&self) -> &'static str {
            match self {
                Self::SleepInhibition(_) => SLEEP_INHIBITION.key,
                Self::WorkerProfile(_) => WORKER_PROFILE.key,
                Self::SessionLimit(_) => "session_limit",
                Self::GrantRights(_) => "grant_rights",
                Self::Enrolment(_) => "enrolment",
            }
        }

        /// Returns when this change takes effect.
        #[must_use]
        pub const fn effect(&self) -> ValueEffect {
            match self {
                Self::SleepInhibition(_)
                | Self::SessionLimit(_)
                | Self::GrantRights(_)
                | Self::Enrolment(_) => ValueEffect::Immediately,
                Self::WorkerProfile(_) => ValueEffect::NewSessionsOnly,
            }
        }

        /// Returns true when this change alters what a caller is authorised to do, so dispatch is
        /// fenced before the change is acknowledged.
        ///
        /// One change does: the ceiling on what a grant may carry. Lowering it takes rights away
        /// from grants that are already live, and work admitted under the old ceiling must be
        /// fenced before the person is told the change is in force. A session ceiling, a sleep
        /// policy and an enrolment budget each change what this host admits or costs, not what a
        /// caller is authorised to do, so none of them fences anything.
        #[must_use]
        pub const fn affects_authority(&self) -> bool {
            matches!(self, Self::GrantRights(_))
        }

        /// Returns the capability evidence this change invalidates.
        ///
        /// A profile change moves what a session's processes can reach, so the evidence taken
        /// under the old profile is no longer about this host. Nothing here migrates a worker: a
        /// running session keeps the profile it was created in, and the new one applies to
        /// sessions created afterwards.
        #[must_use]
        pub fn invalidates(&self) -> Vec<crate::desktop::CapabilityInvalidation> {
            match self {
                Self::WorkerProfile(_) => {
                    vec![crate::desktop::CapabilityInvalidation::WorkerProfile]
                }
                _ => Vec::new(),
            }
        }
    }

    /// A validated edit, ready to be written.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Edited {
        /// The document as it will be.
        pub document: ConfigurationDocument,
        /// The bytes to write.
        pub contents: String,
        /// The revision this edit was based on.
        pub based_on: u64,
        /// What the document on disk was when this edit was prepared.
        ///
        /// Compared again before the write. A revision alone is not enough: an absent document and
        /// an unreadable one both report revision zero, so an edit prepared against nothing would
        /// otherwise be allowed to replace a document this build must not touch.
        pub based_on_state: DocumentState,
        /// The document this edit was prepared against, when there was one.
        ///
        /// Compared as well, because two different documents can carry the same revision: one
        /// restored from a backup, or one a person edited by hand without touching the counter.
        /// Comparing the whole document is what makes the check about the thing rather than about
        /// its label.
        pub based_on_document: Option<ConfigurationDocument>,
        /// The revision it applies.
        pub revision: u64,
        /// When it takes effect.
        pub effect: ValueEffect,
    }

    /// Why an edit was refused.
    #[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
    pub enum EditRefused {
        /// The document on disk is one this build must not rewrite.
        #[error("{0}")]
        NotOurs(String),
        /// The edited document does not validate.
        #[error("{}", .0.join("; "))]
        Invalid(Vec<String>),
        /// Another writer is applying an edit to the same document.
        #[error("{0}")]
        Busy(String),
    }

    /// Applies one change to a loaded document and validates the result.
    ///
    /// Validation happens here, before anything is written, which is section 26's "validate edits
    /// before applying a versioned revision". A document this build could not read is not edited
    /// at all: overwriting a document at an unknown version, or one belonging to another user,
    /// would destroy a choice rather than change one.
    ///
    /// # Errors
    ///
    /// Returns [`EditRefused::NotOurs`] for a document this build must not rewrite and
    /// [`EditRefused::Invalid`] with every problem the result has.
    pub fn edit(loaded: &Loaded, change: &Change) -> Result<Edited, EditRefused> {
        let based_on = match (&loaded.document, loaded.status.state) {
            (Some(document), _) => document.revision,
            (None, DocumentState::Absent) => 0,
            (None, _) => return Err(EditRefused::NotOurs(loaded.status.detail.clone())),
        };
        // A revision that cannot rise is a revision that would be reused, and a reused revision is
        // a compare-and-set that no longer compares anything.
        if based_on == u64::MAX {
            return Err(EditRefused::Invalid(vec![format!(
                "this document is already at revision {based_on}, which is the highest this \
                 schema counts to"
            )]));
        }
        let mut document = loaded
            .document
            .clone()
            .unwrap_or_else(ConfigurationDocument::empty);
        match change {
            Change::SleepInhibition(setting) => {
                document.preferences.sleep_inhibition = Nullable::some(*setting);
            }
            Change::WorkerProfile(profile) => {
                document.preferences.worker_profile = Nullable::some(*profile);
            }
            Change::SessionLimit(limit) => {
                document.ceilings.session_limit = Nullable(*limit);
            }
            Change::GrantRights(rights) => {
                // Deduplicated here rather than refused. A ceiling is a set, the same right named
                // twice asks for exactly what it asked for once, and a document that grew without
                // bound because a caller repeated itself would be a document this build could no
                // longer read.
                document.ceilings.grant_rights = Nullable(rights.as_ref().map(|rights| {
                    let mut unique: Vec<String> = rights.clone();
                    unique.sort();
                    unique.dedup();
                    unique
                }));
            }
            Change::Enrolment(budgets) => {
                document.ceilings.enrolment = Nullable::some(*budgets);
            }
        }
        document.version = VERSION;
        document.revision = based_on + 1;
        validate(&document).map_err(EditRefused::Invalid)?;
        let text = contents(&document);
        // The bound the reader enforces, checked against the bytes that would be written rather
        // than against the fields. A document that validated and then could not be read back would
        // take every preference in it with it.
        if text.len() as u64 > MAX_LEN {
            return Err(EditRefused::Invalid(vec![format!(
                "this document would be {} bytes, and this host reads at most {MAX_LEN}",
                text.len()
            )]));
        }
        Ok(Edited {
            contents: text,
            based_on,
            based_on_state: loaded.status.state,
            based_on_document: loaded.document.clone(),
            revision: document.revision,
            effect: change.effect(),
            document,
        })
    }

    /// Refuses an edit whose base revision is no longer the one on disk.
    ///
    /// Called immediately before the write, by every writer. Two writers each read a document,
    /// each apply their own change to the revision they read, and the second to write would erase
    /// the first; comparing the revision again at the last moment is what turns that into a
    /// refusal the person can see.
    ///
    /// # Errors
    ///
    /// Returns [`EditRefused::NotOurs`] naming both revisions when the document moved.
    pub fn still_current(edited: &Edited, current: &Loaded) -> Result<(), EditRefused> {
        if current.status.state == edited.based_on_state
            && current.revision() == edited.based_on
            && current.document == edited.based_on_document
        {
            return Ok(());
        }
        Err(EditRefused::NotOurs(format!(
            "this document was {} at revision {} when the edit to revision {} was prepared and is \
             now {} at revision {}; nothing was written",
            edited.based_on_state.as_str(),
            edited.based_on,
            edited.revision,
            current.status.state.as_str(),
            current.revision()
        )))
    }

    /// The lock one writer holds while it reads, edits and replaces the document.
    ///
    /// Reading the revision and replacing the file are two steps, and two writers that each read
    /// revision `n` would each publish revision `n + 1`, the second erasing the first.
    /// [`still_current`] catches a writer that came and went between the two steps; this closes
    /// the window in which two writers are inside them at once.
    pub const LOCK_NAME: &str = ".config.lock";

    /// The lock, held through an open file handle for as long as this value lives.
    ///
    /// The lock file remains in place. Process termination or dropping this value releases the
    /// kernel file lock immediately without an unlink-and-recreate race.
    #[derive(Debug)]
    pub struct EditLock {
        _file: std::fs::File,
        path: std::path::PathBuf,
    }

    impl EditLock {
        /// Returns the path to the lock file.
        #[must_use]
        pub fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    /// Takes the configuration lock in `state_directory`.
    ///
    /// Uses an operating-system file lock held through an open handle (`flock` on Unix, exclusive
    /// share mode on Windows). The lock file stays in place; exiting releases ownership without
    /// race conditions.
    ///
    /// # Errors
    ///
    /// Returns the sentence a caller reports when another writer holds the lock, or when the lock
    /// cannot be taken at all.
    pub fn lock(state_directory: &std::path::Path) -> Result<EditLock, String> {
        let path = state_directory.join(LOCK_NAME);
        take_lock(state_directory, &path)
    }

    /// The sentence a caller reports when the lock is held.
    fn busy(state_directory: &std::path::Path, lock: &std::path::Path) -> String {
        format!(
            "another writer is applying an edit to {}; {} is held",
            state_directory.join(FILE_NAME).display(),
            lock.display()
        )
    }

    #[cfg(unix)]
    fn take_lock(
        state_directory: &std::path::Path,
        path: &std::path::Path,
    ) -> Result<EditLock, String> {
        use rustix::fs::{FlockOperation, flock};
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600);
        let file = options
            .open(path)
            .map_err(|error| format!("this host could not open {}: {error}", path.display()))?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(EditLock {
                _file: file,
                path: path.to_path_buf(),
            }),
            Err(error)
                if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN =>
            {
                Err(busy(state_directory, path))
            }
            Err(error) => Err(format!(
                "this host could not lock {}: {error}",
                path.display()
            )),
        }
    }

    #[cfg(not(unix))]
    fn take_lock(
        state_directory: &std::path::Path,
        path: &std::path::Path,
    ) -> Result<EditLock, String> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const NO_SHARING: u32 = 0;

            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(NO_SHARING);
            match options.open(path) {
                Ok(file) => Ok(EditLock {
                    _file: file,
                    path: path.to_path_buf(),
                }),
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    Err(busy(state_directory, path))
                }
                Err(error) => Err(format!(
                    "this host could not open {}: {error}",
                    path.display()
                )),
            }
        }
        #[cfg(not(windows))]
        {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            let file = options
                .open(path)
                .map_err(|error| format!("this host could not open {}: {error}", path.display()))?;
            Ok(EditLock {
                _file: file,
                path: path.to_path_buf(),
            })
        }
    }

    // ---------------------------------------------------------------------------------------
    // Precedence
    // ---------------------------------------------------------------------------------------

    /// Which rung of the precedence ladder an effective value came from.
    #[derive(
        Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
    )]
    #[serde(rename_all = "snake_case")]
    pub enum ValueSource {
        /// An explicit request or a command-line option.
        Request,
        /// The selected session or environment profile.
        Profile,
        /// The per-user host configuration document.
        HostConfiguration,
        /// The product default.
        Default,
    }

    impl ValueSource {
        /// Returns the stable wire string.
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Request => "request",
                Self::Profile => "profile",
                Self::HostConfiguration => "host_configuration",
                Self::Default => "default",
            }
        }

        /// Returns what a person is told this rung is.
        #[must_use]
        pub const fn describe(self) -> &'static str {
            match self {
                Self::Request => "an explicit request or command-line option",
                Self::Profile => "the selected session or environment profile",
                Self::HostConfiguration => "the per-user host configuration",
                Self::Default => "the product default",
            }
        }
    }

    /// The ladder, highest first. It is the order [`resolve`] walks and the order `kr doctor`
    /// prints.
    pub const PRECEDENCE: [ValueSource; 4] = [
        ValueSource::Request,
        ValueSource::Profile,
        ValueSource::HostConfiguration,
        ValueSource::Default,
    ];

    /// Whether a new value applies at once or only to sessions created afterwards.
    #[derive(
        Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
    )]
    #[serde(rename_all = "snake_case")]
    pub enum ValueEffect {
        /// The host acts on it the next time it asks itself the question.
        Immediately,
        /// A running session keeps what it was created with; the new value applies to sessions
        /// created afterwards. Nothing migrates a worker.
        NewSessionsOnly,
    }

    impl ValueEffect {
        /// Returns the stable wire string.
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Immediately => "immediately",
                Self::NewSessionsOnly => "new_sessions_only",
            }
        }
    }

    /// One ordinary preference this host resolves.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Preference {
        /// The key, as the document spells it and `kr doctor` prints it.
        pub key: &'static str,
        /// When a new value takes effect.
        pub effect: ValueEffect,
        /// What this preference decides, for the person reading the report.
        pub about: &'static str,
    }

    /// Whether this host keeps itself awake for work it has admitted.
    pub const SLEEP_INHIBITION: Preference = Preference {
        key: "sleep_inhibition",
        effect: ValueEffect::Immediately,
        about: "whether this host keeps itself awake for work it has admitted",
    };

    /// The execution context a session is created in.
    pub const WORKER_PROFILE: Preference = Preference {
        key: "worker_profile",
        effect: ValueEffect::NewSessionsOnly,
        about: "the execution context a session is created in",
    };

    /// The runtime tree this installation uses.
    pub const RUNTIME_DIRECTORY: Preference = Preference {
        key: "runtime_directory",
        effect: ValueEffect::NewSessionsOnly,
        about: "the runtime tree holding sockets and published descriptors",
    };

    /// The state tree this installation uses.
    pub const STATE_DIRECTORY: Preference = Preference {
        key: "state_directory",
        effect: ValueEffect::NewSessionsOnly,
        about: "the state tree holding the registry, journals and this document",
    };

    /// Every preference this host resolves, in the order `kr doctor` prints them.
    ///
    /// The two directories are here because they resolve through [`resolve`] like everything else:
    /// an allowlisted variable supplies them at the request rung, and the platform default is the
    /// bottom rung. Keeping them in this table is also what makes the allowlist checkable, because
    /// every entry must name a key that appears here.
    pub const PREFERENCES: [Preference; 4] = [
        SLEEP_INHIBITION,
        WORKER_PROFILE,
        RUNTIME_DIRECTORY,
        STATE_DIRECTORY,
    ];

    /// Returns the preference `key` names.
    #[must_use]
    pub fn preference(key: &str) -> Option<Preference> {
        PREFERENCES
            .iter()
            .find(|preference| preference.key == key)
            .copied()
    }

    /// A value one rung offered, and what inside that rung produced it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Offered<T> {
        /// The value.
        pub value: T,
        /// The profile's name or the document's path, when the rung has one.
        pub origin: Option<String>,
        /// The allowlisted environment variable that supplied it, when one did.
        pub variable: Option<&'static str>,
    }

    impl<T> Offered<T> {
        /// A value with no further attribution.
        pub const fn plain(value: T) -> Self {
            Self {
                value,
                origin: None,
                variable: None,
            }
        }

        /// A value a named place produced.
        pub fn from(value: T, origin: impl Into<String>) -> Self {
            Self {
                value,
                origin: Some(origin.into()),
                variable: None,
            }
        }

        /// A value an allowlisted variable supplied at this rung.
        pub const fn from_variable(value: T, variable: &'static str) -> Self {
            Self {
                value,
                origin: None,
                variable: Some(variable),
            }
        }
    }

    /// What each rung of the ladder offered for one preference.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Layers<T> {
        /// An explicit request or command-line option.
        pub request: Option<Offered<T>>,
        /// The selected session or environment profile.
        pub profile: Option<Offered<T>>,
        /// The per-user host configuration.
        pub host: Option<Offered<T>>,
        /// The product default, which is always there. It is what makes the ladder total.
        pub default: T,
    }

    impl<T> Layers<T> {
        /// A ladder where only the product default has a value.
        pub const fn of(default: T) -> Self {
            Self {
                request: None,
                profile: None,
                host: None,
                default,
            }
        }
    }

    /// What one preference resolved to, and where it came from.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Effective<T> {
        /// The preference.
        pub preference: Preference,
        /// The value in force.
        pub value: T,
        /// The rung it came from.
        pub source: ValueSource,
        /// The profile's name or the document's path, when the rung had one.
        pub origin: Option<String>,
        /// The allowlisted variable that supplied it, when one did.
        pub variable: Option<&'static str>,
    }

    /// Resolves one ordinary preference.
    ///
    /// This is the whole of section 26's precedence rule: explicit request or CLI option, then the
    /// selected session or environment profile, then the per-user host configuration, then the
    /// product default. Every ordinary preference in this product goes through it, which is what
    /// stops a call site from inventing an order of its own, and it is total: the default rung
    /// always has a value, so there is no fifth outcome to handle.
    ///
    /// An allowlisted environment variable is not a rung. It supplies one of the rungs above, at
    /// the position [`ALLOWLIST`] declares, and it is reported as having done so.
    #[must_use]
    pub fn resolve<T>(preference: Preference, layers: Layers<T>) -> Effective<T> {
        let Layers {
            request,
            profile,
            host,
            default,
        } = layers;
        for (source, offered) in [
            (ValueSource::Request, request),
            (ValueSource::Profile, profile),
            (ValueSource::HostConfiguration, host),
        ] {
            if let Some(offered) = offered {
                return Effective {
                    preference,
                    value: offered.value,
                    source,
                    origin: offered.origin,
                    variable: offered.variable,
                };
            }
        }
        Effective {
            preference,
            value: default,
            source: ValueSource::Default,
            origin: None,
            variable: None,
        }
    }

    // ---------------------------------------------------------------------------------------
    // The environment
    // ---------------------------------------------------------------------------------------

    /// One documented environment override.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OverrideEntry {
        /// The variable.
        pub variable: &'static str,
        /// The preference it supplies, as the effective-value report names it.
        pub preference: &'static str,
        /// The rung it acts at.
        pub position: ValueSource,
        /// Why it acts there.
        pub why: &'static str,
    }

    /// The only environment variables that participate in configuration.
    ///
    /// Both name a *location* rather than a value, which is why both act at the request rung: the
    /// per-user host configuration lives inside the state directory, so a document cannot name the
    /// directory it is read from. Everything else a process inherits changes nothing here, and no
    /// entry may name authority, an organisation restriction, a grant ceiling, a hard resource
    /// limit or a provider origin.
    pub const ALLOWLIST: [OverrideEntry; 2] = [
        OverrideEntry {
            variable: "KR_RUNTIME_DIR",
            preference: "runtime_directory",
            position: ValueSource::Request,
            why: "it selects the runtime tree, which no document inside that tree can name",
        },
        OverrideEntry {
            variable: "KR_STATE_DIR",
            preference: "state_directory",
            position: ValueSource::Request,
            why: "it selects the state tree the configuration document itself is read from",
        },
    ];

    /// One variable this build reads outside the precedence, and what it selects.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct UngovernedVariable {
        /// The variable.
        pub variable: &'static str,
        /// What it selects.
        pub selects: &'static str,
        /// True when what it selects is authority or a provider origin, which section 26 says no
        /// inherited variable may reach.
        pub reaches_authority: bool,
    }

    /// The variables this build still reads that are not part of the precedence.
    ///
    /// Section 26 asks that only documented allowlisted overrides participate and that arbitrary
    /// inherited variables cannot change authority or provider origins. [`ALLOWLIST`] is the first
    /// half. This table is the second, and it exists because a claim is worth nothing unless the
    /// exceptions to it are written down: `kr doctor` prints this list, so what a person is told
    /// about this host matches what this host actually does.
    ///
    /// Two kinds are here. The platform directory variables are how the operating system itself
    /// names its conventional locations, and reading them is what "native OS-appropriate
    /// locations" means rather than an exception to it. The network selections are the ones that
    /// do reach a provider origin and, in one case, the owner signer; they belong in the
    /// configuration document and in the pairing record, and until they are there this host says
    /// so out loud.
    pub const UNGOVERNED: [UngovernedVariable; 16] = [
        UngovernedVariable {
            variable: "TMPDIR",
            selects: "the platform's per-user temporary directory, which is the macOS runtime root",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "XDG_RUNTIME_DIR",
            selects: "the platform's per-user runtime directory on Linux",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "XDG_STATE_HOME",
            selects: "the platform's per-user state directory on Linux",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "HOME",
            selects: "the account's home directory, from which both default roots are derived",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "LOCALAPPDATA",
            selects: "the account's local application data directory on Windows",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "KR_NETWORK",
            selects: "whether this daemon puts itself on the network at all",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_BIND",
            selects: "the address the network endpoint binds to",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_RELAYS",
            selects: "the relay map, which is a provider origin",
            reaches_authority: true,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_PKARR_PUBLISHER",
            selects: "the discovery server this host publishes to, which is a provider origin",
            reaches_authority: true,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_PKARR_RESOLVER",
            selects: "the discovery server this host resolves from, which is a provider origin",
            reaches_authority: true,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_DNS_ORIGIN",
            selects: "the DNS origin peers are resolved from, which is a provider origin",
            reaches_authority: true,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_RELAY_CA",
            selects: "extra certificates trusted for a relay's HTTPS, which is a trust decision",
            reaches_authority: true,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_RELAY_ONLY",
            selects: "whether every packet goes through the relay",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_LOCAL_DISCOVERY",
            selects: "whether this host discovers peers on the local network",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_MAINLINE",
            selects: "whether this host uses the public distributed hash table for discovery",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "KR_NETWORK_OWNER_KEY",
            selects: "the owner signing key this host pairs under, which is authority itself",
            reaches_authority: true,
        },
    ];

    /// Returns the variables in [`UNGOVERNED`] that this process actually has set.
    ///
    /// The report says which of them are set here rather than only that they exist, because what
    /// matters to a person reading a diagnostic is whether this host is running under one.
    #[must_use]
    pub fn ungoverned_here() -> Vec<UngovernedVariable> {
        UNGOVERNED
            .iter()
            .copied()
            .filter(|entry| std::env::var_os(entry.variable).is_some())
            .collect()
    }

    /// Returns the allowlist entry for `variable`, when it has one.
    ///
    /// Anything this returns `None` for changes nothing about how this host behaves, however it
    /// was exported and whoever exported it.
    #[must_use]
    pub fn allowlisted(variable: &str) -> Option<&'static OverrideEntry> {
        ALLOWLIST.iter().find(|entry| entry.variable == variable)
    }
}

/// Redaction of anything that looks like a credential.
///
/// `DoctorCheck::detail` has claimed "credentials are redacted" since the first diagnostic was
/// written, and nothing enforced it: a check built its sentence from whatever it had, and a path,
/// a command line or an error from a library could carry a token into it. Section 26 asks for
/// support bundles that show "software versions, capabilities and redacted errors", which is a
/// promise about what leaves this host rather than about what each caller remembers to do.
///
/// So the redaction happens at the boundary rather than at each caller. [`HostDoctorResult::new`]
/// redacts every check it is given, whichever code built it, and the support bundle redacts every
/// error the same way. A caller that forgets is still redacted; a caller that constructs the wire
/// struct by hand is the only way past, and there is none in this product.
pub mod redaction {
    /// What replaces a redacted value.
    pub const MARKER: &str = "[redacted]";

    /// The shortest run of credential-shaped characters this treats as a secret.
    ///
    /// Short runs are words and identifiers. A generated key is longer than this and an English
    /// word of this length is not written in three character classes at once.
    const OPAQUE_RUN: usize = 28;

    /// Name components that make the value beside them a credential.
    ///
    /// Matched as whole components rather than as substrings, which is what keeps `session_limit`
    /// and `keyboard` out of it: a name is split on its own separators and on case changes, and a
    /// component either is one of these or is not.
    const SECRET_COMPONENTS: &[&str] = &[
        "secret",
        "secrets",
        "token",
        "tokens",
        "password",
        "passwd",
        "passphrase",
        "credential",
        "credentials",
        "authorization",
        "auth",
        "cookie",
        "bearer",
        "key",
        "keys",
        "apikey",
        "privatekey",
    ];

    /// Components that make a *key* public rather than secret.
    ///
    /// A public key is something a diagnostic exists to print: redacting it would lose the one
    /// identifier a person needs to compare two hosts, and it protects nothing. The exception
    /// applies only when `key` was the word that made the name secret, so `public_api_token` is
    /// still a token and `public_key` is still a public key.
    const PUBLIC_COMPONENTS: &[&str] = &["public", "pub", "fingerprint"];

    /// The secret-naming components a [`PUBLIC_COMPONENTS`] word may excuse.
    const PUBLIC_EXCUSES: &[&str] = &["key", "keys"];

    /// Authorization schemes whose value follows the scheme word rather than a separator.
    const SCHEMES: &[&str] = &["Bearer", "Basic", "Token", "Digest"];

    /// Components whose value runs to the end of the line rather than to the next space.
    ///
    /// `Authorization: Bearer <token>` is one value with a space in it. Stopping at the space
    /// would leave the token where it was and redact the word "Bearer".
    const WHOLE_LINE_COMPONENTS: &[&str] = &["authorization", "bearer", "cookie"];

    /// Returns `text` with anything that looks like a credential replaced.
    ///
    /// Three shapes are recognised, and each is the shape a credential actually arrives in.
    ///
    /// * **An assignment whose name says it is one.** `API_KEY=sk-live-...`, `password : hunter2`,
    ///   `"token": "..."`, `Authorization: Bearer ...`. The name stays, because a person reading a
    ///   bundle needs to know which credential the host was talking about; the value goes.
    /// * **Userinfo in a URL.** `https://user:password@host/path` and `https://token@host/path`
    ///   both keep the host and the path and lose what was in front of them, which is where a
    ///   credential in a provider origin lives.
    /// * **A long opaque run.** A token pasted on its own, with nothing naming it: at least
    ///   [`OPAQUE_RUN`] characters from the alphanumeric alphabet, mixing upper case, lower case
    ///   and digits. That is the shape a generated credential has and the shape ordinary text
    ///   does not.
    ///
    /// The last rule is deliberately narrow, because the first two carry the real load and an
    /// eager third rule damages diagnostics for nothing. A run never crosses a path separator, so
    /// a directory this host is trying to tell someone about survives; a lowercase hexadecimal
    /// digest survives, because it has no upper case; and a word survives, because it has no
    /// digits.
    #[must_use]
    pub fn redact(text: &str) -> String {
        let assignments = redact_assignments(text);
        let schemes = redact_schemes(&assignments);
        let userinfo = redact_userinfo(&schemes);
        redact_opaque_runs(&userinfo)
    }

    /// Replaces the value after a standalone authorization scheme word.
    ///
    /// `Bearer <token>` carries a credential with nothing naming it: the scheme word is the name.
    /// It appears that way in a copied header, in a curl command line and in a library's own error
    /// message.
    fn redact_schemes(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for (index, line) in text.split_inclusive(['\n', '\r']).enumerate() {
            let _ = index;
            let mut rest = line;
            let mut wrote = String::new();
            while let Some((scheme, at)) = SCHEMES
                .iter()
                .filter_map(|scheme| rest.find(&format!("{scheme} ")).map(|at| (*scheme, at)))
                .min_by_key(|(_, at)| *at)
            {
                let value_start = at + scheme.len() + 1;
                let value_end = rest[value_start..]
                    .find(|character: char| character.is_whitespace())
                    .map_or(rest.len(), |offset| value_start + offset);
                if value_end > value_start {
                    wrote.push_str(&rest[..value_start]);
                    wrote.push_str(MARKER);
                    rest = &rest[value_end..];
                } else {
                    wrote.push_str(&rest[..value_start]);
                    rest = &rest[value_start..];
                }
            }
            wrote.push_str(rest);
            out.push_str(&wrote);
        }
        out
    }

    /// Returns true when `name` is a name whose value is a credential.
    #[must_use]
    pub fn names_a_secret(name: &str) -> bool {
        let components = components(name);
        let mut naming: Vec<&str> = components
            .iter()
            .map(String::as_str)
            .filter(|component| SECRET_COMPONENTS.contains(component))
            .collect();
        if components
            .windows(2)
            .any(|pair| SECRET_COMPONENTS.contains(&format!("{}{}", pair[0], pair[1]).as_str()))
        {
            naming.push("apikey");
        }
        if naming.is_empty() {
            return false;
        }
        let public = components
            .iter()
            .any(|component| PUBLIC_COMPONENTS.contains(&component.as_str()));
        // A public word excuses a key and nothing else: a name that also says token, secret or
        // password is one whatever else is in front of it.
        !(public && naming.iter().all(|word| PUBLIC_EXCUSES.contains(word)))
    }

    /// Splits a name into its lowercase components, on its own separators and on case changes.
    fn components(name: &str) -> Vec<String> {
        let characters: Vec<char> = name.chars().collect();
        let mut parts = Vec::new();
        let mut current = String::new();
        for (index, character) in characters.iter().copied().enumerate() {
            if !character.is_ascii_alphanumeric() {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
                continue;
            }
            if character.is_ascii_uppercase() && !current.is_empty() {
                let previous = characters[index - 1];
                // `apiKey` breaks between the lower case and the capital. `HTTPAuthorization`
                // breaks before the capital that begins the next word, which is the one followed
                // by lower case; without that the whole run reads as one unknown word and a name
                // that plainly says "authorization" would not be recognised.
                let after_lower = previous.is_ascii_lowercase() || previous.is_ascii_digit();
                let starts_a_word = previous.is_ascii_uppercase()
                    && characters
                        .get(index + 1)
                        .is_some_and(|next| next.is_ascii_lowercase());
                if after_lower || starts_a_word {
                    parts.push(std::mem::take(&mut current));
                }
            }
            current.push(character.to_ascii_lowercase());
        }
        if !current.is_empty() {
            parts.push(current);
        }
        parts
    }

    /// Replaces the value of every assignment whose name says it is a credential.
    fn redact_assignments(text: &str) -> String {
        let characters: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut index = 0;
        while index < characters.len() {
            let character = characters[index];
            if character == '=' || character == ':' {
                let start = name_start(&characters, index);
                let name: String = characters[start..index]
                    .iter()
                    .collect::<String>()
                    .trim()
                    .trim_matches(['"', '\''])
                    .to_owned();
                if names_a_secret(&name) {
                    let whole_line = components(&name)
                        .iter()
                        .any(|component| WHOLE_LINE_COMPONENTS.contains(&component.as_str()));
                    let (value_start, value_end) = value_span(&characters, index + 1, whole_line);
                    if value_end > value_start {
                        out.extend(&characters[index..value_start]);
                        out.push_str(MARKER);
                        index = value_end;
                        continue;
                    }
                }
            }
            out.push(character);
            index += 1;
        }
        out
    }

    /// Where the name in front of a separator at `separator` begins.
    ///
    /// Space in front of the separator is skipped first, so `password = hunter2` is the same
    /// assignment as `password=hunter2`.
    fn name_start(text: &[char], separator: usize) -> usize {
        let mut start = separator;
        while start > 0 && (text[start - 1] == ' ' || text[start - 1] == '\t') {
            start -= 1;
        }
        while start > 0 {
            let character = text[start - 1];
            if character.is_ascii_alphanumeric()
                || character == '_'
                || character == '-'
                || character == '.'
                || character == '"'
                || character == '\''
            {
                start -= 1;
            } else {
                break;
            }
        }
        start
    }

    /// The span of the value that follows a separator, skipping the space and quote in front of it.
    ///
    /// A quoted value ends at its closing quote, and a backslash inside one escapes whatever
    /// follows, so a password containing an escaped quote is not cut in half and left exposed.
    fn value_span(text: &[char], mut start: usize, whole_line: bool) -> (usize, usize) {
        while start < text.len() && (text[start] == ' ' || text[start] == '\t') {
            start += 1;
        }
        let quote = match text.get(start) {
            Some('"') => Some('"'),
            Some('\'') => Some('\''),
            _ => None,
        };
        if quote.is_some() {
            start += 1;
        }
        let mut end = start;
        while end < text.len() {
            let character = text[end];
            if let Some(quote) = quote {
                if character == '\\' {
                    end = (end + 2).min(text.len());
                    continue;
                }
                if character == quote {
                    break;
                }
            } else {
                // A whole-line value ends only at the line; every other value ends at the next
                // space or separator, which is where one field stops and the next begins.
                let ends = character == '\n'
                    || character == '\r'
                    || (!whole_line
                        && (character.is_whitespace() || character == ',' || character == ';'));
                if ends {
                    break;
                }
            }
            end += 1;
        }
        (start, end)
    }

    /// Replaces the userinfo in front of a host.
    ///
    /// With or without a password: a single opaque username in a URL is how a provider origin
    /// carries a token, and `https://<token>@host` is as much a credential as `user:pass@host`.
    fn redact_userinfo(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(scheme) = rest.find("://") {
            let after = scheme + 3;
            let authority_end = rest[after..]
                .find(|character: char| character == '/' || character.is_whitespace())
                .map_or(rest.len(), |offset| after + offset);
            let authority = &rest[after..authority_end];
            match authority.rfind('@') {
                Some(at) if at > 0 => {
                    out.push_str(&rest[..after]);
                    out.push_str(MARKER);
                    out.push_str(&authority[at..]);
                }
                _ => out.push_str(&rest[..authority_end]),
            }
            rest = &rest[authority_end..];
        }
        out.push_str(rest);
        out
    }

    /// Replaces every long run of characters drawn only from the encoded alphabets.
    fn redact_opaque_runs(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut run = String::new();
        for character in text.chars() {
            if character.is_ascii_alphanumeric() || character == '+' {
                run.push(character);
                continue;
            }
            flush_run(&mut out, &mut run);
            out.push(character);
        }
        flush_run(&mut out, &mut run);
        out
    }

    /// Appends one finished run, redacted when it is long enough and encoded enough to be a
    /// credential.
    fn flush_run(out: &mut String, run: &mut String) {
        if run.chars().count() >= OPAQUE_RUN && is_opaque(run) {
            out.push_str(MARKER);
        } else {
            out.push_str(run);
        }
        run.clear();
    }

    /// Whether a run is a generated credential rather than something a person wrote.
    ///
    /// All three of upper case, lower case and digits, across one unbroken run. A generated key
    /// has all three; a word has none of the last two; a hexadecimal digest has no upper case; a
    /// directory name is broken into short runs by its separators. Requiring all three is what
    /// keeps this rule from eating the paths and identifiers a diagnostic exists to report.
    fn is_opaque(run: &str) -> bool {
        run.chars().any(|character| character.is_ascii_digit())
            && run.chars().any(|character| character.is_ascii_uppercase())
            && run.chars().any(|character| character.is_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::configuration::{
        Change, ConfigurationDocument, DocumentState, Layers, Offered, PreferenceSet, ValueSource,
    };
    use super::*;
    use crate::desktop::SleepInhibitionSetting;
    use crate::identity::WorkerProfile;

    /// KR-REQ-26.44: the promise on a check's detail is kept at the boundary, not by each caller.
    #[test]
    fn a_credential_in_a_check_never_reaches_the_wire() {
        let result = HostDoctorResult::new(
            vec![DoctorCheck::new(
                "provider",
                "The provider origin answered",
                DoctorStatus::Warning,
                "called https://user:hunter2@api.example.com with OPENAI_API_KEY=sk-live-abc123",
                Some("rotate the key at https://example.com/keys".to_owned()),
            )],
            EffectiveConfiguration::unread(),
        );
        let detail = &result.checks[0].detail;
        assert!(!detail.contains("hunter2"), "{detail}");
        assert!(!detail.contains("sk-live-abc123"), "{detail}");
        assert!(
            detail.contains("api.example.com"),
            "the host stays, so the diagnostic still says something: {detail}"
        );
        let remedy = result.checks[0].remedy.as_ref().expect("a remedy");
        assert!(remedy.contains("example.com/keys"), "{remedy}");
    }

    /// A long opaque run with nothing naming it is still a credential; a path is not.
    #[test]
    fn an_unnamed_token_is_redacted_and_a_path_is_not() {
        let redacted = redaction::redact(
            concat!("the worker reported ghp", "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5 while starting"),
        );
        assert!(
            !redacted.contains(concat!("ghp", "_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5")),
            "{redacted}"
        );
        assert!(redacted.contains("while starting"), "{redacted}");
        let plain = redaction::redact("the supervisor describes itself as a launchd user agent");
        assert_eq!(
            plain, "the supervisor describes itself as a launchd user agent",
            "an ordinary sentence is left alone"
        );
        // A diagnostic exists to name these. A redaction that ate them would be worse than none.
        for kept in [
            "/var/folders/55/ab_cd/T/kr-41736cb3/s/environments/2513782e/config.json: version 1",
            "/Users/example/Library/Application Support/KalaReach",
            "the package digest is 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        ] {
            assert_eq!(
                redaction::redact(kept),
                kept,
                "a diagnostic still says this"
            );
        }
    }

    /// KR-REQ-26.44: the shapes a credential actually arrives in, and the shapes it does not.
    #[test]
    fn the_redaction_takes_the_credential_and_leaves_the_diagnostic() {
        for (text, gone, kept) in [
            (
                "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.short.signature",
                "eyJhbGciOiJIUzI1NiJ9",
                "Authorization",
            ),
            (
                "HTTPAuthorization: Bearer hunter2",
                "hunter2",
                "HTTPAuthorization",
            ),
            (
                "the header was Bearer hunter2 and it failed",
                "hunter2",
                "it failed",
            ),
            ("'password': 'hunter2'", "hunter2", "password"),
            ("password='two words'", "two words", "password"),
            ("public_api_token=hunter2", "hunter2", "public_api_token"),
            ("password = hunter2", "hunter2", "password"),
            (
                r#"{"api_key": "sk-live-\"escaped\"-tail"}"#,
                "escaped",
                "api_key",
            ),
            (
                "dialled https://gho1234abcd@relay.example.com/path",
                "gho1234abcd",
                "relay.example.com/path",
            ),
            (
                "dialled https://operator:hunter2@relay.example.com/path",
                "hunter2",
                "relay.example.com/path",
            ),
        ] {
            let redacted = redaction::redact(text);
            assert!(!redacted.contains(gone), "{text} -> {redacted}");
            assert!(redacted.contains(kept), "{text} -> {redacted}");
        }
        // A name that merely contains a secret word as a fragment is not one.
        for kept in [
            "session_limit=16",
            "keyboard: unavailable",
            "public_key=7f3ab99c",
            "monkeys: 4",
        ] {
            assert_eq!(redaction::redact(kept), kept, "{kept} says nothing secret");
        }
    }

    /// KR-REQ-26.44: an exported configuration goes through the same boundary as a check.
    #[test]
    fn a_credential_in_a_configuration_report_never_reaches_the_wire() {
        let mut configuration = EffectiveConfiguration::unread();
        configuration.status.detail =
            "this file is not JSON: expected value at line 1 column 1: token=A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
                .to_owned();
        let result = HostDoctorResult::new(Vec::new(), configuration);
        assert!(
            !result.configuration.status.detail.contains("A1b2C3d4E5f6"),
            "{}",
            result.configuration.status.detail
        );
    }

    /// KR-REQ-26.16: an edit that would produce a document this host cannot read is refused.
    #[test]
    fn an_edit_larger_than_the_bound_is_refused_before_it_is_written() {
        let loaded = configuration::load(None);
        let many: Vec<String> = (0..4000)
            .map(|index| format!("a.right.this.build.does.not.know.{index}"))
            .collect();
        let refused = configuration::edit(&loaded, &Change::GrantRights(Some(many)))
            .expect_err("a document larger than the bound");
        assert!(
            format!("{refused}").contains("not an action right"),
            "an unknown right is refused first: {refused}"
        );
        let repeated = vec!["session.view".to_owned(); 4000];
        let applied = configuration::edit(&loaded, &Change::GrantRights(Some(repeated)))
            .expect("the same right named repeatedly asks for what it asked for once");
        assert_eq!(
            applied
                .document
                .ceilings
                .grant_rights
                .as_ref()
                .expect("the ceiling")
                .len(),
            1
        );
        assert!((applied.contents.len() as u64) < configuration::MAX_LEN);
    }

    /// KR-REQ-26.16: an edit is refused when the document underneath it is no longer what it was.
    #[test]
    fn an_edit_is_refused_when_the_document_changed_in_any_way() {
        let absent = configuration::load(None);
        let prepared = configuration::edit(&absent, &Change::SessionLimit(Some(4)))
            .expect("an edit on an absent document");
        let written = configuration::load(Some(prepared.contents.as_bytes()));
        assert!(
            configuration::still_current(&prepared, &written).is_err(),
            "another writer published a document while this edit was being prepared"
        );
        // An unreadable document reports revision zero like an absent one. Comparing the revision
        // alone would let an edit prepared against nothing replace a document this build must not
        // touch.
        let unreadable = configuration::unreadable("this file must not be a symbolic link");
        assert_eq!(unreadable.revision(), prepared.based_on);
        assert!(configuration::still_current(&prepared, &unreadable).is_err());
        assert!(configuration::still_current(&prepared, &absent).is_ok());
    }

    /// KR-REQ-26.14: what this build reads outside the precedence is written down, not implied.
    #[test]
    fn every_variable_this_build_reads_outside_the_precedence_is_named() {
        for entry in &configuration::UNGOVERNED {
            assert!(
                !entry.selects.is_empty(),
                "{} says what it selects",
                entry.variable
            );
            assert!(
                configuration::allowlisted(entry.variable).is_none(),
                "{} cannot be both governed and ungoverned",
                entry.variable
            );
        }
        for reaching in ["KR_NETWORK_OWNER_KEY", "KR_NETWORK_RELAYS"] {
            let entry = configuration::UNGOVERNED
                .iter()
                .find(|entry| entry.variable == reaching)
                .unwrap_or_else(|| panic!("{reaching} is recorded"));
            assert!(
                entry.reaches_authority,
                "{reaching} reaches authority or a provider origin and says so"
            );
        }
    }

    /// KR-REQ-26.13: a document declaring a version this build does not know is left alone.
    #[test]
    fn an_unknown_version_reads_as_defaults_and_says_so() {
        let loaded = configuration::load(Some(br#"{"version": 99, "preferences": {}}"#));
        assert_eq!(loaded.status.state, DocumentState::UnknownVersion);
        assert!(loaded.document.is_none(), "nothing is read out of it");
        assert!(loaded.status.detail.contains("99"), "{:?}", loaded.status);
        assert!(
            configuration::edit(
                &loaded,
                &Change::SleepInhibition(SleepInhibitionSetting::Off)
            )
            .is_err(),
            "and this build never rewrites it"
        );
    }

    /// KR-REQ-26.13: an absent document is the ordinary first run, not a fault.
    #[test]
    fn an_absent_document_is_every_product_default() {
        let loaded = configuration::load(None);
        assert_eq!(loaded.status.state, DocumentState::Absent);
        assert_eq!(loaded.revision(), 0);
        assert_eq!(
            loaded.ceilings().enrolment_budgets().metadata_bytes,
            64 * 1024 * 1024
        );
        assert_eq!(
            loaded.ceilings().enrolment_budgets().metadata_entries,
            100_000
        );
    }

    /// KR-REQ-26.16: an edit is validated before a revision is applied.
    #[test]
    fn an_edit_that_does_not_validate_applies_no_revision() {
        let document = ConfigurationDocument {
            ceilings: configuration::ConfigurationCeilings {
                session_limit: Nullable::some(4),
                ..Default::default()
            },
            ..ConfigurationDocument::empty()
        };
        let loaded = configuration::load(Some(configuration::contents(&document).as_bytes()));
        assert_eq!(loaded.status.state, DocumentState::Loaded);
        let refused = configuration::edit(&loaded, &Change::SessionLimit(Some(0)))
            .expect_err("a ceiling of zero admits nothing");
        assert!(matches!(refused, configuration::EditRefused::Invalid(_)));
        let applied = configuration::edit(&loaded, &Change::SessionLimit(Some(2)))
            .expect("a ceiling below the last one");
        assert_eq!(applied.based_on, 0);
        assert_eq!(applied.revision, 1);
        assert_eq!(applied.effect, configuration::ValueEffect::Immediately);
    }

    /// KR-REQ-26.15: a full mirror above the default payload budget needs the explicit setting.
    #[test]
    fn a_payload_budget_above_the_default_needs_the_mirror_setting() {
        let mut budgets = configuration::EnrolmentBudgets {
            cached_payload_bytes: 4 * 1024 * 1024 * 1024,
            ..configuration::EnrolmentBudgets::default()
        };
        let loaded = configuration::load(None);
        let refused = configuration::edit(&loaded, &Change::Enrolment(budgets))
            .expect_err("a larger mirror is an explicit setting");
        assert!(
            format!("{refused}").contains("full_offline_mirror"),
            "{refused}"
        );
        budgets.full_offline_mirror = true;
        configuration::edit(&loaded, &Change::Enrolment(budgets))
            .expect("with the setting it is the owner's choice");
    }

    /// KR-REQ-26.13: one function, and the order section 26 states.
    #[test]
    fn the_ladder_is_request_then_profile_then_host_then_default() {
        let all = Layers {
            request: Some(Offered::plain(SleepInhibitionSetting::BatteryToo)),
            profile: Some(Offered::from(SleepInhibitionSetting::MainsOnly, "review")),
            host: Some(Offered::from(SleepInhibitionSetting::Off, "/s/config.json")),
            default: SleepInhibitionSetting::Off,
        };
        let effective = configuration::resolve(configuration::SLEEP_INHIBITION, all);
        assert_eq!(effective.source, ValueSource::Request);
        assert_eq!(effective.value, SleepInhibitionSetting::BatteryToo);

        let without_request = Layers {
            request: None,
            profile: Some(Offered::from(SleepInhibitionSetting::MainsOnly, "review")),
            host: Some(Offered::from(SleepInhibitionSetting::Off, "/s/config.json")),
            default: SleepInhibitionSetting::Off,
        };
        let effective = configuration::resolve(configuration::SLEEP_INHIBITION, without_request);
        assert_eq!(effective.source, ValueSource::Profile);
        assert_eq!(effective.origin.as_deref(), Some("review"));

        let host_only = Layers {
            request: None,
            profile: None,
            host: Some(Offered::from(
                SleepInhibitionSetting::BatteryToo,
                "/s/config.json",
            )),
            default: SleepInhibitionSetting::Off,
        };
        let effective = configuration::resolve(configuration::SLEEP_INHIBITION, host_only);
        assert_eq!(effective.source, ValueSource::HostConfiguration);

        let nothing = Layers::of(SleepInhibitionSetting::Off);
        let effective = configuration::resolve(configuration::SLEEP_INHIBITION, nothing);
        assert_eq!(effective.source, ValueSource::Default);
        assert_eq!(
            effective.preference.effect,
            configuration::ValueEffect::Immediately
        );
    }

    /// KR-REQ-26.14: nothing outside the allowlist participates, and no entry reaches authority.
    #[test]
    fn only_the_allowlist_participates_and_none_of_it_names_authority() {
        assert!(configuration::allowlisted("KR_RUNTIME_DIR").is_some());
        assert!(configuration::allowlisted("KR_STATE_DIR").is_some());
        for inherited in [
            "PATH",
            "OPENAI_API_KEY",
            "KR_AUTHORITY",
            "KR_GRANT",
            "KR_PROVIDER_ORIGIN",
            "AWS_SECRET_ACCESS_KEY",
        ] {
            assert!(
                configuration::allowlisted(inherited).is_none(),
                "{inherited} must change nothing"
            );
        }
        for entry in &configuration::ALLOWLIST {
            assert!(
                !redaction::names_a_secret(entry.variable),
                "{} names a credential and cannot be an override",
                entry.variable
            );
            assert!(
                matches!(
                    entry.position,
                    ValueSource::Request | ValueSource::Profile | ValueSource::HostConfiguration
                ),
                "an override acts at a rung of the ladder, never above it"
            );
            assert!(
                configuration::preference(entry.preference).is_some(),
                "{} names {}, which is not an ordinary preference; authority, organisation \
                 restrictions, grant ceilings and hard resource limits intersect and no variable \
                 reaches them",
                entry.variable,
                entry.preference
            );
        }
        for preference in &configuration::PREFERENCES {
            assert!(
                !["session_limit", "grant_rights", "enrolment", "authority"]
                    .contains(&preference.key),
                "{} is a ceiling, not an ordinary preference",
                preference.key
            );
        }
    }

    /// KR-REQ-26.13: a profile contributes only what it chooses.
    #[test]
    fn a_profile_is_selected_by_name_or_by_the_documents_own_default() {
        let mut document = ConfigurationDocument::empty();
        document.profiles.insert(
            "review".to_owned(),
            PreferenceSet {
                worker_profile: Nullable::some(WorkerProfile::HeadlessUser),
                ..PreferenceSet::default()
            },
        );
        document.default_profile = Nullable::some("review".to_owned());
        configuration::validate(&document).expect("a document naming a profile it declares");
        let (name, set) = document.profile(None).expect("the document's own default");
        assert_eq!(name, "review");
        assert_eq!(set.worker_profile.0, Some(WorkerProfile::HeadlessUser));
        assert!(document.profile(Some("absent")).is_none());

        document.default_profile = Nullable::some("missing".to_owned());
        let problems =
            configuration::validate(&document).expect_err("a default that names nothing");
        assert!(problems.iter().any(|problem| problem.contains("missing")));
    }

    /// KR-REQ-26.15: the schema has no field a secret value fits in.
    #[test]
    fn a_secret_is_a_reference_and_the_document_exports_no_value() {
        let mut document = ConfigurationDocument::empty();
        document.secrets.push(configuration::SecretReference {
            name: "relay".to_owned(),
            store: "login_keychain".to_owned(),
            item: "kalareach/relay".to_owned(),
        });
        configuration::validate(&document).expect("a named reference");
        let text = configuration::contents(&document);
        let reparsed = configuration::load(Some(text.as_bytes()));
        assert_eq!(reparsed.status.state, DocumentState::Loaded);
        assert!(
            !text.contains("value"),
            "the schema has no field a value fits in: {text}"
        );
        let rejected = serde_json::from_str::<ConfigurationDocument>(
            r#"{"version": 1, "secrets": [{"name": "relay", "store": "s", "item": "i",
                "value": "hunter2"}]}"#,
        );
        assert!(rejected.is_err(), "an unknown field is refused outright");
    }

    /// KR-REQ-26.13: the document is bounded, and anything unreadable leaves it alone.
    #[test]
    fn an_unreadable_document_falls_back_and_never_claims_a_revision() {
        let loaded = configuration::unreadable("this file must not be a symbolic link");
        assert_eq!(loaded.status.state, DocumentState::Unreadable);
        assert_eq!(loaded.revision(), 0);
        assert!(loaded.status.state.is_a_problem());
        let invalid = configuration::load(Some(b"not json at all"));
        assert_eq!(invalid.status.state, DocumentState::Invalid);
        assert!(invalid.status.state.is_a_problem());
    }

    #[test]
    fn a_failure_status_is_the_only_one_that_makes_a_host_unhealthy() {
        for status in [
            DoctorStatus::Ok,
            DoctorStatus::Warning,
            DoctorStatus::NotApplicable,
        ] {
            let result = HostDoctorResult::new(
                vec![DoctorCheck::new("check", "A check", status, "detail", None)],
                EffectiveConfiguration::unread(),
            );
            assert!(result.healthy, "{status:?}");
        }
        let result = HostDoctorResult::new(
            vec![DoctorCheck::new(
                "check",
                "A check",
                DoctorStatus::Failed,
                "detail",
                None,
            )],
            EffectiveConfiguration::unread(),
        );
        assert!(!result.healthy);
    }
}
