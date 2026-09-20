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
            configuration,
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
            capabilities,
            doctor: HostDoctorResult::new(doctor.checks, doctor.configuration),
            configuration,
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
/// It is recorded as an [`ExecutionSnapshot`]: what the session's own processes run with, and
/// nothing this host decides anything from. The overrides above are read from the *host's* own
/// environment, never from a snapshot, which is what keeps a variable a person happened to export
/// in one terminal from changing how the host behaves for everybody.
pub mod configuration {
    use std::collections::BTreeMap;

    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    use crate::desktop::SleepInhibitionSetting;
    use crate::identity::WorkerProfile;
    use crate::scalars::{Nullable, U64};
    use crate::session::ShellMode;

    /// The configuration document, in the environment's own state directory.
    pub const FILE_NAME: &str = "config.json";

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
        /// The shell mode a session is created with when the request does not choose one.
        pub shell_mode: Nullable<ShellMode>,
    }

    impl Default for PreferenceSet {
        /// A set that chooses nothing, which is what an absent section means.
        fn default() -> Self {
            Self {
                sleep_inhibition: Nullable::null(),
                worker_profile: Nullable::null(),
                shell_mode: Nullable::null(),
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
        /// The most sessions this host admits, when the owner sets one below the built-in limit.
        pub session_limit: Nullable<u64>,
        /// The rights a grant may carry on this host, as the stable action-right strings.
        ///
        /// Absent leaves the grant's own intersection untouched. Present narrows it: a right not
        /// in this list is not available on this host however a grant was issued.
        pub grant_rights: Nullable<Vec<String>>,
        /// The repository enrolment budgets section 11 calls configuration.
        pub enrolment: EnrolmentBudgets,
    }

    impl Default for ConfigurationCeilings {
        /// No configured ceiling, and section 11's own enrolment budgets.
        fn default() -> Self {
            Self {
                session_limit: Nullable::null(),
                grant_rights: Nullable::null(),
                enrolment: EnrolmentBudgets::default(),
            }
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
        /// The cached payload budget per repository, in bytes.
        pub cached_payload_bytes: u64,
        /// Whether this host keeps a full offline mirror, which is the explicit setting a payload
        /// budget above the default needs.
        pub full_offline_mirror: bool,
    }

    impl Default for EnrolmentBudgets {
        fn default() -> Self {
            Self {
                metadata_bytes: DEFAULT_METADATA_BYTES,
                metadata_entries: DEFAULT_METADATA_ENTRIES,
                cached_payload_bytes: DEFAULT_CACHED_PAYLOAD_BYTES,
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
        let budgets = &document.ceilings.enrolment;
        if budgets.metadata_bytes == 0 || budgets.metadata_entries == 0 {
            problems.push("an enrolment budget of zero would enrol no repository".to_owned());
        }
        if budgets.cached_payload_bytes > DEFAULT_CACHED_PAYLOAD_BYTES
            && !budgets.full_offline_mirror
        {
            problems.push(format!(
                "a cached payload budget above {DEFAULT_CACHED_PAYLOAD_BYTES} bytes is a full \
                 mirror and needs full_offline_mirror set explicitly"
            ));
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
        /// Set the shell mode a session is created with by default.
        ShellMode(ShellMode),
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
                Self::ShellMode(_) => SHELL_MODE.key,
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
                Self::WorkerProfile(_) | Self::ShellMode(_) => ValueEffect::NewSessionsOnly,
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
            Change::ShellMode(mode) => {
                document.preferences.shell_mode = Nullable::some(*mode);
            }
            Change::SessionLimit(limit) => {
                document.ceilings.session_limit = Nullable(*limit);
            }
            Change::GrantRights(rights) => {
                document.ceilings.grant_rights = Nullable(rights.clone());
            }
            Change::Enrolment(budgets) => document.ceilings.enrolment = *budgets,
        }
        document.version = VERSION;
        document.revision = based_on.saturating_add(1);
        validate(&document).map_err(EditRefused::Invalid)?;
        Ok(Edited {
            contents: contents(&document),
            based_on,
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
        if current.revision() == edited.based_on {
            return Ok(());
        }
        Err(EditRefused::NotOurs(format!(
            "this document moved to revision {} while the edit to revision {} was being prepared; \
             nothing was written",
            current.revision(),
            edited.revision
        )))
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

    /// The shell mode a session is created with.
    pub const SHELL_MODE: Preference = Preference {
        key: "shell_mode",
        effect: ValueEffect::NewSessionsOnly,
        about: "the shell mode a session is created with",
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
    pub const PREFERENCES: [Preference; 5] = [
        SLEEP_INHIBITION,
        WORKER_PROFILE,
        SHELL_MODE,
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

    /// Returns the allowlist entry for `variable`, when it has one.
    ///
    /// Anything this returns `None` for changes nothing about how this host behaves, however it
    /// was exported and whoever exported it.
    #[must_use]
    pub fn allowlisted(variable: &str) -> Option<&'static OverrideEntry> {
        ALLOWLIST.iter().find(|entry| entry.variable == variable)
    }

    /// The creator's shell environment, recorded as an execution snapshot.
    ///
    /// Section 26 is explicit that this is "a distinct execution snapshot, not control
    /// configuration". It is what the session's own processes run with; nothing this host decides
    /// is taken from it. [`ExecutionSnapshot::variables`] holds names only, because a bundle or a
    /// diagnostic that carried the values would be exporting whatever the person had exported.
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    pub struct ExecutionSnapshot {
        /// The variable names the creator's shell had, in order, with nothing that names a
        /// credential.
        pub variables: Vec<String>,
        /// How many names were left out because they name a credential.
        pub withheld: U64,
    }

    impl ExecutionSnapshot {
        /// Records the names of one shell environment.
        ///
        /// Values never enter: the snapshot says what the session's processes were given, not what
        /// was in it. A name that itself says it is a credential is counted rather than listed,
        /// because "`STRIPE_SECRET_KEY` was set" is already more than a diagnostic needs.
        #[must_use]
        pub fn record<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
            let mut variables = Vec::new();
            let mut withheld = 0;
            for name in names {
                if super::redaction::names_a_secret(name) {
                    withheld += 1;
                } else {
                    variables.push(name.to_owned());
                }
            }
            Self {
                variables,
                withheld: U64::new(withheld),
            }
        }

        /// Returns true when this snapshot names `variable`.
        ///
        /// Reading it is the only thing anything may do with it, and even that is for a report.
        #[must_use]
        pub fn contains(&self, variable: &str) -> bool {
            self.variables.iter().any(|name| name == variable)
        }
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
    /// Short runs are words. A forty-character hexadecimal string is not a word, and neither is a
    /// thirty-character base64 one, so the bound is set where ordinary English stops and encoded
    /// material starts.
    const OPAQUE_RUN: usize = 28;

    /// Words that make the value beside them a credential.
    ///
    /// Matched case-insensitively against the assignment's left-hand side, so `API_KEY=`,
    /// `api-key:` and `"apiKey":` are all the same word here.
    const SECRET_WORDS: &[&str] = &[
        "secret",
        "token",
        "password",
        "passwd",
        "passphrase",
        "credential",
        "authorization",
        "auth",
        "cookie",
        "session",
        "apikey",
        "privatekey",
        "signature",
        "bearer",
        "key",
    ];

    /// Returns `text` with anything that looks like a credential replaced.
    ///
    /// Three shapes are recognised, and each is the shape a credential actually arrives in.
    ///
    /// * **An assignment whose name says it is one.** `API_KEY=sk-live-...`, `password: hunter2`,
    ///   `"token": "..."`. The name stays, because a person reading a bundle needs to know which
    ///   credential the host was talking about; the value goes.
    /// * **Userinfo in a URL.** `https://user:password@host/path` keeps the host and the path and
    ///   loses the pair in front of them, which is where a credential in a provider origin lives.
    /// * **A long opaque run.** A token pasted on its own, with nothing naming it. Anything of
    ///   [`OPAQUE_RUN`] characters or more drawn only from the base64 and hexadecimal alphabets
    ///   goes, and a path, a sentence or an identifier with punctuation in it does not.
    ///
    /// It is deliberately eager. A redacted diagnostic that lost a long identifier is a diagnostic
    /// someone can still read; a bundle that carried a live key is an incident.
    #[must_use]
    pub fn redact(text: &str) -> String {
        let assignments = redact_assignments(text);
        let userinfo = redact_userinfo(&assignments);
        redact_opaque_runs(&userinfo)
    }

    /// Returns true when `name` is a word that makes the value beside it a credential.
    #[must_use]
    pub fn names_a_secret(name: &str) -> bool {
        let folded: String = name
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .map(|character| character.to_ascii_lowercase())
            .collect();
        SECRET_WORDS.iter().any(|word| folded.contains(word))
    }

    /// Replaces the value of every assignment whose name says it is a credential.
    fn redact_assignments(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let bytes: Vec<char> = text.chars().collect();
        let mut index = 0;
        while index < bytes.len() {
            let character = bytes[index];
            if character == '=' || character == ':' {
                // The name is what runs back from the separator: letters, digits and the
                // punctuation a variable or a JSON key is spelled with.
                let start = name_start(&bytes, index);
                let name: String = bytes[start..index].iter().collect();
                let name = name.trim().trim_matches('"');
                if names_a_secret(name) {
                    let (value_start, value_end) = value_span(&bytes, index + 1);
                    if value_end > value_start {
                        out.extend(&bytes[index..value_start]);
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
    fn name_start(text: &[char], separator: usize) -> usize {
        let mut start = separator;
        while start > 0 {
            let character = text[start - 1];
            if character.is_ascii_alphanumeric()
                || character == '_'
                || character == '-'
                || character == '.'
                || character == '"'
            {
                start -= 1;
            } else {
                break;
            }
        }
        start
    }

    /// The span of the value that follows a separator, skipping the space and quote in front of it.
    fn value_span(text: &[char], mut start: usize) -> (usize, usize) {
        while start < text.len() && (text[start] == ' ' || text[start] == '\t') {
            start += 1;
        }
        let quoted = start < text.len() && text[start] == '"';
        if quoted {
            start += 1;
        }
        let mut end = start;
        while end < text.len() {
            let character = text[end];
            let ends = if quoted {
                character == '"'
            } else {
                character.is_whitespace() || character == ',' || character == ';'
            };
            if ends {
                break;
            }
            end += 1;
        }
        (start, end)
    }

    /// Replaces the `user:password@` in front of a host.
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
                Some(at) if authority[..at].contains(':') => {
                    out.push_str(&rest[..after]);
                    out.push_str(MARKER);
                    out.push_str(&authority[at..]);
                    rest = &rest[authority_end..];
                }
                _ => {
                    out.push_str(&rest[..authority_end]);
                    rest = &rest[authority_end..];
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// Replaces every long run of characters drawn only from the encoded alphabets.
    fn redact_opaque_runs(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut run = String::new();
        for character in text.chars() {
            if character.is_ascii_alphanumeric() || character == '+' || character == '/' {
                run.push(character);
                continue;
            }
            // `=` ends a run and belongs to it only as base64 padding, which is why it is taken
            // here rather than treated as an assignment separator a second time.
            if character == '=' && !run.is_empty() {
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

    /// Whether a run is encoded material rather than a word.
    ///
    /// Encoded material mixes cases or mixes letters with digits across its whole length. A run of
    /// one case and no digits is a word, however long, and a bundle that lost the longest word in
    /// a sentence would be harder to read for nothing.
    fn is_opaque(run: &str) -> bool {
        let digits = run.chars().filter(char::is_ascii_digit).count();
        let upper = run.chars().filter(|c| c.is_ascii_uppercase()).count();
        let lower = run.chars().filter(|c| c.is_ascii_lowercase()).count();
        let mixed_case = upper > 0 && lower > 0;
        let has_digits = digits > 0;
        (mixed_case && has_digits) || (has_digits && digits * 4 >= run.len())
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

    /// A long opaque run with nothing naming it is still a credential.
    #[test]
    fn an_unnamed_token_is_redacted_and_a_sentence_is_not() {
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
        assert_eq!(loaded.ceilings().enrolment.metadata_bytes, 64 * 1024 * 1024);
        assert_eq!(loaded.ceilings().enrolment.metadata_entries, 100_000);
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
        let mut budgets = configuration::EnrolmentBudgets::default();
        budgets.cached_payload_bytes = 4 * 1024 * 1024 * 1024;
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

    /// KR-REQ-26.13: the creator's shell environment is a snapshot and carries no value.
    #[test]
    fn the_execution_snapshot_holds_names_and_withholds_the_ones_that_name_a_credential() {
        let snapshot = configuration::ExecutionSnapshot::record([
            "PATH",
            "HOME",
            "OPENAI_API_KEY",
            "STRIPE_SECRET",
        ]);
        assert!(snapshot.contains("PATH"));
        assert!(!snapshot.contains("OPENAI_API_KEY"));
        assert_eq!(snapshot.withheld.get(), 2);
        let json = serde_json::to_string(&snapshot).expect("serialises");
        assert!(!json.contains("sk-"), "{json}");
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
