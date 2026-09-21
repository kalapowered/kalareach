//! Host and environment reads, read-only diagnostics, and the configuration they report.
//!
//! `host.doctor` reports; it does not repair unless an individual repair is requested, and it
//! carries no credential out of this host. What keeps that promise is [`export`]: one allowlist
//! naming every exported field with what its value is made of, applied by [`HostDoctorResult::new`]
//! to every check whichever code built it. It is a property of what leaves this host rather than
//! of what each caller remembered, and nothing in it reads a value to decide about it.
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
    id: String,
    /// What it examines.
    title: String,
    /// What it found.
    pub status: DoctorStatus,
    /// A plain description of the finding, carrying nothing from outside this build.
    ///
    /// Written as an [`export::Sentence`], whose only text is a literal in this source. A check's
    /// detail names paths, command lines and errors from libraries, and any of those can carry a
    /// token the person writing the check never thought about; what the sentence can hold of one
    /// is its class and its length.
    detail: String,
    /// What the user should do, when the check did not pass. Written in this source.
    remedy: Nullable<String>,
}

impl DoctorCheck {
    /// Builds one check.
    ///
    /// The detail is an [`export::Sentence`] and the remedy is a literal in this source, which is
    /// the whole of why a check cannot carry a credential: there is nowhere in either of them to
    /// put text that arrived at runtime. It is also the only way to build one, because the three
    /// text fields are this type's own: a check assembled from strings a caller had lying about
    /// would be the same promise made by habit instead of by the type.
    ///
    /// ```compile_fail
    /// use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
    /// use kr_protocol::scalars::Nullable;
    /// let check = DoctorCheck {
    ///     id: "runtime-directory".to_owned(),
    ///     title: "The runtime directory is owner-only".to_owned(),
    ///     status: DoctorStatus::Ok,
    ///     detail: "token opensesame".to_owned(),
    ///     remedy: Nullable::null(),
    /// };
    /// ```
    #[must_use]
    pub fn new(
        id: &'static str,
        title: &'static str,
        status: DoctorStatus,
        detail: export::Sentence,
        remedy: Option<&'static str>,
    ) -> Self {
        Self {
            id: id.to_owned(),
            title: title.to_owned(),
            status,
            detail: detail.render(),
            remedy: Nullable(remedy.map(str::to_owned)),
        }
    }

    /// The stable identifier this check is published under.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// What this check examines.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// What it found.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// What the person should do about it, when there is something to do.
    #[must_use]
    pub fn remedy(&self) -> Option<&str> {
        self.remedy.0.as_deref()
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
    /// Builds the result from the checks that ran.
    ///
    /// What comes out is the display form: this is the answer to the owner asking their own host
    /// how it is, so it names the document they would open and the directories this host resolved.
    /// The form that leaves for somebody else to read is [`export::ForExport::for_export`], and a
    /// support bundle can hold only that one.
    #[must_use]
    pub fn new(checks: Vec<DoctorCheck>, configuration: EffectiveConfiguration) -> Self {
        let healthy = checks.iter().all(|check| !check.status.is_failure());
        Self {
            checks,
            healthy,
            configuration,
        }
    }
}

impl export::ForExport for HostDoctorResult {
    /// Every check as it stands, and the configuration through the allowlist.
    ///
    /// A check needs nothing done to it: its detail is an [`export::Sentence`] and its remedy is a
    /// literal in this source, so there was never anywhere in one to put text that arrived at
    /// runtime. The configuration beside them is a report about a document a person wrote, and that
    /// is where the two forms differ.
    fn for_export(self) -> export::Exported<Self> {
        export::Exported::of(Self {
            configuration: self.configuration.withheld_form(),
            ..self
        })
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
    ///
    /// What it is made of is [`Self::class`], and the export boundary reads that rather than the
    /// value: `sleep_inhibition` resolves to one of this build's own words and a state directory
    /// resolves to a path, and the two cannot leave this host on the same terms. The pair is
    /// written by [`Self::new`] from one [`export::Declared`], so a row cannot come to describe
    /// itself as something it is not.
    value: String,
    /// What [`Self::value`] is made of.
    class: export::ContentClass,
    /// The rung of the precedence ladder it came from.
    pub source: configuration::ValueSource,
    /// The profile's name or the document's path, when the rung had one.
    pub origin: Nullable<String>,
    /// The allowlisted environment variable that supplied it, when one did.
    pub variable: Nullable<String>,
    /// Whether it applies immediately or only to sessions created afterwards.
    pub effect: configuration::ValueEffect,
}

impl EffectiveValue {
    /// Builds one row from a value and what it is made of.
    #[must_use]
    pub fn new(
        key: &'static str,
        about: &'static str,
        declared: &export::Declared,
        source: configuration::ValueSource,
        origin: Nullable<String>,
        variable: Nullable<String>,
        effect: configuration::ValueEffect,
    ) -> Self {
        Self {
            key: key.to_owned(),
            about: about.to_owned(),
            value: declared.value().to_owned(),
            class: declared.class(),
            source,
            origin,
            variable,
            effect,
        }
    }

    /// The value in force, in its stable spelling.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// What the value is made of.
    #[must_use]
    pub const fn class(&self) -> export::ContentClass {
        self.class
    }
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

/// One native OS-appropriate location, as this build documents it.
///
/// The rule rather than one machine's answer: `$XDG_STATE_HOME/kalareach` says where a state
/// directory belongs on every Linux host, and `/home/someone/.local/state/kalareach` says where
/// one person's is and carries their account name out of this host to say it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportedLocation {
    /// Which location this is, as the report's own key for it.
    pub what: String,
    /// Where this platform puts it, in the form this build documents.
    pub documented: String,
}

/// What this host's configuration currently resolves to, and where every part of it came from.
///
/// This is the display form: what a host tells the owner about their own machine, with the paths
/// they would open. The form that leaves for somebody else to read is
/// [`export::ForExport::for_export`], which carries each of those paths as its class and its length
/// beside the rule this platform follows.
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
    /// The runtime directory this host resolved.
    pub runtime_directory: String,
    /// The state directory this host resolved.
    pub state_directory: String,
    /// The native OS-appropriate locations this platform uses, as this build documents them.
    ///
    /// Section 26 asks `kr doctor` to report the locations, and the rule is half of that answer:
    /// the three fields above say where this host's files are, and these say where this platform
    /// puts them and which of them an allowlisted variable chose instead. The rule is also what
    /// survives an export, because a resolved path carries the account name that composed it.
    pub locations: Vec<ReportedLocation>,
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
    /// Why this host could not put the document into force, when something stopped it.
    ///
    /// Null on an ordinary host. A registry this host cannot write, a fence it cannot raise or
    /// capability evidence it cannot re-read leaves the values above describing what is actually
    /// in force and this sentence saying what the document asked for and did not get. A report
    /// that stayed silent about it would be a report of a value nothing is enforcing.
    pub not_in_force: Nullable<String>,
    /// What this host's workers still owe the authority fence a ceiling here raised.
    ///
    /// Null once every worker has acknowledged it. A revision that advanced is not a completed
    /// revocation: a worker that has not acknowledged its fence still holds work admitted under
    /// the ceiling that was withdrawn, and this says so for as long as that is true. It is not a
    /// failure - the values above are in force for everything admitted from now on.
    pub fence_outstanding: Nullable<String>,
}

impl export::ForExport for EffectiveConfiguration {
    fn for_export(self) -> export::Exported<Self> {
        export::Exported::of(self.withheld_form())
    }
}

impl EffectiveConfiguration {
    /// Returns this report with every field taken through the export allowlist.
    ///
    /// A report is built from a parser's own error messages, from paths and from whatever a
    /// document held. Each field leaves as what its class allows: this build's own words and
    /// numbers as themselves, and everything a person, a platform or a library wrote as its class
    /// and its length. Nothing here is structured differently afterwards.
    ///
    /// Private, because a report reduced this way is still typed as a report: what makes it an
    /// export is [`export::ForExport::for_export`] putting it inside an [`export::Exported`].
    fn withheld_form(self) -> Self {
        Self {
            document: export::carry(
                export::class("EffectiveConfiguration", "document"),
                &self.document,
            ),
            status: configuration::DocumentStatus {
                state: self.status.state,
                detail: export::carry(
                    export::class("DocumentStatus", "detail"),
                    &self.status.detail,
                ),
            },
            runtime_directory: export::carry(
                export::class("EffectiveConfiguration", "runtime_directory"),
                &self.runtime_directory,
            ),
            state_directory: export::carry(
                export::class("EffectiveConfiguration", "state_directory"),
                &self.state_directory,
            ),
            values: self
                .values
                .into_iter()
                .map(|value| EffectiveValue {
                    key: export::carry(export::class("EffectiveValue", "key"), &value.key),
                    variable: export::carry_null(
                        export::class("EffectiveValue", "variable"),
                        &value.variable,
                    ),
                    // The row's own class, not the field's: two preferences of one shape can be
                    // made of different things.
                    value: export::carry(value.class, &value.value),
                    origin: export::carry_null(
                        export::class("EffectiveValue", "origin"),
                        &value.origin,
                    ),
                    ..value
                })
                .collect(),
            ceilings: self
                .ceilings
                .into_iter()
                .map(|ceiling| CeilingValue {
                    key: export::carry(export::class("CeilingValue", "key"), &ceiling.key),
                    configured: export::carry_null(
                        export::class("CeilingValue", "configured"),
                        &ceiling.configured,
                    ),
                    value: export::carry(export::class("CeilingValue", "value"), &ceiling.value),
                    // The origin is the document's own path, which a person chose and may have
                    // spelled with something this boundary exists to keep out of an export.
                    origin: export::carry_null(
                        export::class("CeilingValue", "origin"),
                        &ceiling.origin,
                    ),
                    narrowed_by: export::carry_null(
                        export::class("CeilingValue", "narrowed_by"),
                        &ceiling.narrowed_by,
                    ),
                    ..ceiling
                })
                .collect(),
            stale_documents: self
                .stale_documents
                .iter()
                .map(|path| {
                    export::carry(
                        export::class("EffectiveConfiguration", "stale_documents"),
                        path,
                    )
                })
                .collect(),
            // Three names a person wrote. Section 26 asks a configuration never to export a
            // secret's value, and a name is where an owner who did not read that sentence put one,
            // so what leaves is the count and each reference's shape.
            secrets: self
                .secrets
                .iter()
                .map(|reference| configuration::SecretReference {
                    name: export::carry(export::class("SecretReference", "name"), &reference.name),
                    store: export::carry(
                        export::class("SecretReference", "store"),
                        &reference.store,
                    ),
                    item: export::carry(export::class("SecretReference", "item"), &reference.item),
                })
                .collect(),
            overrides: self
                .overrides
                .into_iter()
                .map(|entry| OverrideReport {
                    variable: export::carry(
                        export::class("OverrideReport", "variable"),
                        &entry.variable,
                    ),
                    preference: export::carry(
                        export::class("OverrideReport", "preference"),
                        &entry.preference,
                    ),
                    ..entry
                })
                .collect(),
            not_in_force: export::carry_null(
                export::class("EffectiveConfiguration", "not_in_force"),
                &self.not_in_force,
            ),
            fence_outstanding: export::carry_null(
                export::class("EffectiveConfiguration", "fence_outstanding"),
                &self.fence_outstanding,
            ),
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
            locations: Vec::new(),
            precedence: configuration::PRECEDENCE
                .iter()
                .map(|source| source.describe().to_owned())
                .collect(),
            overrides: Vec::new(),
            values: Vec::new(),
            ceilings: Vec::new(),
            secrets: Vec::new(),
            stale_documents: Vec::new(),
            not_in_force: Nullable::null(),
            fence_outstanding: Nullable::null(),
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
    component: String,
    /// What it said, as its class and its length.
    ///
    /// A message from a library, the operating system or an upstream is the one thing this build
    /// did not write, so none of its text leaves. The component says which part of this host was
    /// talking, and the length says whether it had anything to say.
    message: String,
}

impl RedactedError {
    /// Records one error.
    ///
    /// The withholding happens here rather than at the caller, so an error carried in from a
    /// library is reduced by the act of putting it in a bundle. Both fields are this type's own,
    /// so this is the only way to make one: an error assembled beside it would carry whatever the
    /// caller had.
    #[must_use]
    pub fn new(component: &'static str, message: &str) -> Self {
        Self {
            component: component.to_owned(),
            message: export::carry(export::class("RedactedError", "message"), message),
        }
    }

    /// Which part of this host was talking.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// What it said, as its class and its length.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
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
/// Section 26 says what one shows, and the word that carries the weight is "redacted". A bundle is
/// written to be sent to somebody else, so every part of it that a person, a platform or a library
/// wrote is typed [`export::Exported`] and there is no way to put a display value in one of those
/// fields. Terminal content, prompts, attachment filenames and anything else content-bearing are
/// not here at all: they arrive only through [`ContentExport`], which exists only when the person
/// explicitly selected it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportBundle {
    /// When it was made.
    pub generated_at_ms: TimestampMs,
    /// The software this host is running.
    pub software: Vec<SoftwareComponent>,
    /// What this host can currently do, as the shared section 11 evidence.
    pub capabilities: Vec<export::Exported<crate::desktop::CapabilityRecord>>,
    /// What the diagnostics found.
    pub doctor: export::Exported<HostDoctorResult>,
    /// What this host's configuration resolves to.
    pub configuration: export::Exported<EffectiveConfiguration>,
    /// The errors this host has to report, redacted.
    pub errors: Vec<RedactedError>,
    /// The content-bearing export, when the person explicitly selected one.
    pub content: Nullable<ContentExport>,
}

impl SupportBundle {
    /// Builds a bundle, taking everything in it through the export allowlist exactly once.
    ///
    /// The configuration is the diagnostics' own, rather than a second copy a caller supplies: one
    /// bundle describes one reading of this host, and two readings of a document that moved between
    /// them would be a bundle disagreeing with itself.
    #[must_use]
    pub fn new(
        generated_at_ms: TimestampMs,
        software: Vec<SoftwareComponent>,
        capabilities: Vec<crate::desktop::CapabilityRecord>,
        doctor: HostDoctorResult,
        errors: Vec<RedactedError>,
    ) -> Self {
        use export::ForExport as _;

        let configuration = doctor.configuration.clone().for_export();
        Self {
            generated_at_ms,
            software,
            capabilities: capabilities
                .into_iter()
                .map(export::ForExport::for_export)
                .collect(),
            doctor: doctor.for_export(),
            configuration,
            // Already recorded through `RedactedError::new`, which is the only constructor: the
            // component is a literal in this source and the message is its class and its length.
            errors,
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
///   "profiles": { "review": { "worker_profile": "headless_user" } },
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

    /// Where this platform puts the per-user state directory, as this build documents it.
    ///
    /// Section 26 asks `kr doctor` to report the native OS-appropriate locations. The rule is what
    /// is reported: a resolved path is one account's answer to it and carries that account's name.
    /// Every rule names the fallback this platform actually uses when the first choice is not set,
    /// because a host with no `XDG_STATE_HOME` still has a state directory and an owner reading the
    /// rule should find the same one this host did.
    pub const DOCUMENTED_STATE_ROOT: &str = if cfg!(target_os = "macos") {
        "~/Library/Application Support/KalaReach/environments/<prefix>"
    } else if cfg!(windows) {
        "%LOCALAPPDATA%\\KalaReach\\environments\\<prefix>"
    } else {
        "$XDG_STATE_HOME/kalareach/environments/<prefix>, or \
         ~/.local/state/kalareach/environments/<prefix> where that variable is not set"
    };

    /// Where this platform puts the per-user runtime directory, as this build documents it.
    pub const DOCUMENTED_RUNTIME_ROOT: &str = if cfg!(target_os = "macos") {
        "$TMPDIR/kalareach/<prefix>, or /tmp/kalareach-<uid>/<prefix> where that variable is not set"
    } else if cfg!(windows) {
        "%LOCALAPPDATA%\\KalaReach\\run\\<prefix> for this environment's own files; the endpoints \
         themselves are names in the user's own named-pipe namespace rather than files"
    } else {
        "$XDG_RUNTIME_DIR/kalareach/<prefix>, or ~/.cache/kalareach/run/<prefix> where that \
         variable is not set"
    };

    /// Where this platform puts the configuration document, as this build documents it.
    pub const DOCUMENTED_DOCUMENT: &str = if cfg!(all(unix, not(target_os = "macos"))) {
        "$XDG_CONFIG_HOME/kalareach/environments/<prefix>/config.json, or \
         ~/.config/kalareach/environments/<prefix>/config.json where that variable is not set"
    } else if cfg!(target_os = "macos") {
        "~/Library/Application Support/KalaReach/environments/<prefix>/config.json"
    } else {
        "%LOCALAPPDATA%\\KalaReach\\environments\\<prefix>\\config.json"
    };

    /// What a location is named when an allowlisted variable chose it instead.
    pub const DOCUMENTED_BY_VARIABLE: &str = "the directory the environment variable names";

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
    ///
    /// One handle, opened once and then checked and read: a path inspected and then read again by
    /// name is two files whenever something replaces it in between. The handle is opened without
    /// following a link and without waiting for a writer, so a symbolic link left where the
    /// document belongs is refused rather than followed and a named pipe with the right name
    /// cannot hold this host's startup open.
    ///
    /// # Errors
    ///
    /// Returns the reason when the file exists but is not one this host wrote, or is larger than
    /// `limit`.
    pub fn read_file(path: &std::path::Path, limit: u64) -> Result<Option<Vec<u8>>, String> {
        use std::io::Read as _;

        #[cfg(unix)]
        let file = {
            use rustix::fs::{Mode, OFlags};

            match rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(file) => std::fs::File::from(file),
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(rustix::io::Errno::LOOP | rustix::io::Errno::MLINK) => {
                    return Err("configuration file must not be a symbolic link".to_owned());
                }
                Err(error) => {
                    return Err(super::export::withheld(
                        super::export::ContentClass::Message,
                        &std::io::Error::from(error).to_string(),
                    ));
                }
            }
        };
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt as _;

            // Open the name itself rather than whatever it points at, so a junction or a symbolic
            // link put where the document belongs is rejected below instead of followed.
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(super::export::withheld(
                        super::export::ContentClass::Message,
                        &error.to_string(),
                    ));
                }
            }
        };
        #[cfg(not(any(unix, windows)))]
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(super::export::withheld(
                    super::export::ContentClass::Message,
                    &error.to_string(),
                ));
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = file.metadata().map_err(|error| {
                super::export::withheld(super::export::ContentClass::Message, &error.to_string())
            })?;
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
            let metadata = file.metadata().map_err(|error| {
                super::export::withheld(super::export::ContentClass::Message, &error.to_string())
            })?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt as _;

                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err("configuration file must not be a link or a junction".to_owned());
                }
            }
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
            .map_err(|error| {
                super::export::withheld(super::export::ContentClass::Message, &error.to_string())
            })?;
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

    /// The largest session ceiling this host can record.
    ///
    /// The registry keeps the number in a signed 64-bit column, which is the limit every SQLite
    /// integer has. A larger one is refused at validation rather than written and then stored one
    /// lower: a report that printed what the document asked for while admission enforced something
    /// else would be a restriction nobody was told about.
    pub const MAX_SESSION_LIMIT: u64 = i64::MAX as u64;

    /// The largest revision this host can record.
    ///
    /// The same signed 64-bit column the session ceiling is bounded by. A document whose revision
    /// is above it could never match the revision this environment recorded as accepted, so every
    /// start would derive its effects again; refusing it at validation keeps the two numbers the
    /// same number.
    pub const MAX_REVISION: u64 = i64::MAX as u64;

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
        pub enrolment: Nullable<ConfiguredEnrolmentBudgets>,
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
        /// Returns the enrolment budgets in force, defaulting to [`EnrolmentBudgets::default`].
        #[must_use]
        pub fn enrolment_budgets(&self) -> EnrolmentBudgets {
            self.enrolment.as_ref().map_or_else(
                EnrolmentBudgets::default,
                ConfiguredEnrolmentBudgets::resolve,
            )
        }
    }

    /// The enrolment budgets a document chooses, each present only where its owner wrote one.
    ///
    /// [`EnrolmentBudgets`] is what a caller acts on: ten numbers, every one of them decided. This
    /// is what the document holds, and a budget nobody wrote is absent here rather than equal to
    /// the default. Keeping the two apart is the whole of what lets a report say which numbers a
    /// person chose: a budget that happens to equal the default is not evidence that anybody set
    /// it, and inferring the source from the value would report the one they did set as the
    /// product's own.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    pub struct ConfiguredEnrolmentBudgets {
        /// The metadata budget per repository, in bytes.
        pub metadata_bytes: Nullable<u64>,
        /// The metadata budget per repository, in entries.
        pub metadata_entries: Nullable<u64>,
        /// How many metadata generations a repository may retain.
        pub retained_generations: Nullable<u64>,
        /// The cached payload budget per repository, in bytes.
        pub cached_payload_bytes: Nullable<u64>,
        /// The largest single package or asset a repository may fetch, in bytes.
        pub package_bytes: Nullable<u64>,
        /// How many objects one package may hold.
        pub object_count: Nullable<u64>,
        /// The largest an expanded pack may become, in bytes, checked during processing.
        pub expanded_pack_bytes: Nullable<u64>,
        /// How many bytes one synchronisation may transfer.
        pub transfer_bytes: Nullable<u64>,
        /// How long one package's compilation may take, in milliseconds.
        pub compilation_ms: Nullable<u64>,
        /// Whether this host keeps a full offline mirror, which is the explicit setting a payload
        /// budget above the default needs.
        pub full_offline_mirror: Nullable<bool>,
    }

    impl ConfiguredEnrolmentBudgets {
        /// Returns the budgets in force: the ones this document chose, and the schema's own for
        /// the rest.
        #[must_use]
        pub fn resolve(&self) -> EnrolmentBudgets {
            let default = EnrolmentBudgets::default();
            EnrolmentBudgets {
                metadata_bytes: self.metadata_bytes.0.unwrap_or(default.metadata_bytes),
                metadata_entries: self.metadata_entries.0.unwrap_or(default.metadata_entries),
                retained_generations: self
                    .retained_generations
                    .0
                    .unwrap_or(default.retained_generations),
                cached_payload_bytes: self
                    .cached_payload_bytes
                    .0
                    .unwrap_or(default.cached_payload_bytes),
                package_bytes: self.package_bytes.0.unwrap_or(default.package_bytes),
                object_count: self.object_count.0.unwrap_or(default.object_count),
                expanded_pack_bytes: self
                    .expanded_pack_bytes
                    .0
                    .unwrap_or(default.expanded_pack_bytes),
                transfer_bytes: self.transfer_bytes.0.unwrap_or(default.transfer_bytes),
                compilation_ms: self.compilation_ms.0.unwrap_or(default.compilation_ms),
                full_offline_mirror: self
                    .full_offline_mirror
                    .0
                    .unwrap_or(default.full_offline_mirror),
            }
        }

        /// Names the budgets this document chose, in schema order.
        ///
        /// Presence, not comparison: a budget written with the same number the schema already
        /// uses was still chosen by the person who wrote it, and one left out was not chosen
        /// however unusual its default looks.
        #[must_use]
        pub fn supplied(&self) -> Vec<&'static str> {
            let mut named = Vec::new();
            for (name, present) in [
                ("metadata_bytes", self.metadata_bytes.is_present()),
                ("metadata_entries", self.metadata_entries.is_present()),
                (
                    "retained_generations",
                    self.retained_generations.is_present(),
                ),
                (
                    "cached_payload_bytes",
                    self.cached_payload_bytes.is_present(),
                ),
                ("package_bytes", self.package_bytes.is_present()),
                ("object_count", self.object_count.is_present()),
                ("expanded_pack_bytes", self.expanded_pack_bytes.is_present()),
                ("transfer_bytes", self.transfer_bytes.is_present()),
                ("compilation_ms", self.compilation_ms.is_present()),
                ("full_offline_mirror", self.full_offline_mirror.is_present()),
            ] {
                if present {
                    named.push(name);
                }
            }
            named
        }

        /// Returns the budgets this document names, each with its number.
        ///
        /// What validation and the intersection ask about: a budget nobody wrote has nothing to
        /// check, and a budget of zero is a refusal wherever it was written.
        #[must_use]
        pub fn written(&self) -> Vec<(&'static str, u64)> {
            [
                ("metadata_bytes", self.metadata_bytes.0),
                ("metadata_entries", self.metadata_entries.0),
                ("retained_generations", self.retained_generations.0),
                ("cached_payload_bytes", self.cached_payload_bytes.0),
                ("package_bytes", self.package_bytes.0),
                ("object_count", self.object_count.0),
                ("expanded_pack_bytes", self.expanded_pack_bytes.0),
                ("transfer_bytes", self.transfer_bytes.0),
                ("compilation_ms", self.compilation_ms.0),
            ]
            .into_iter()
            .filter_map(|(name, value)| value.map(|value| (name, value)))
            .collect()
        }
    }

    /// The repository enrolment budgets, checked before a fetch and during processing.
    ///
    /// Section 11 names the budgets and gives three of the numbers: 64 MiB of metadata, 100,000
    /// metadata entries and a 1 GiB cached payload, above which a full mirror needs an explicit
    /// setting. The rest of the defaults are this build's own, chosen to be the smallest that
    /// still work, and an owner may raise any of them. The catalogue client reads them through
    /// this host's configuration rather than carrying its own copy, so one document answers "what
    /// may a repository cost here".
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
        /// What a repository may cost here until an owner says otherwise: section 11's three
        /// numbers, and this build's own for the budgets it names without one.
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
            Err(error) => {
                // The parser's own sentence names the byte it stopped at and repeats what it
                // found there, which is the document. What leaves is that it did not parse.
                return invalid(vec![format!(
                    "this file is not JSON: {}",
                    super::export::withheld(
                        super::export::ContentClass::Message,
                        &error.to_string()
                    )
                )]);
            }
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
            Err(error) => {
                return invalid(vec![format!(
                    "this document is not valid against the schema: {}",
                    super::export::withheld(
                        super::export::ContentClass::Message,
                        &error.to_string()
                    )
                )]);
            }
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
        if document.revision > MAX_REVISION {
            problems.push(format!(
                "revision {} is above the {MAX_REVISION} this host can record",
                document.revision
            ));
        }
        if document.profiles.len() > MAX_PROFILES {
            problems.push(format!(
                "{} profiles is more than the {MAX_PROFILES} this schema allows",
                document.profiles.len()
            ));
        }
        // A rejected value is named by its class and its length rather than repeated. A problem
        // list is an error message, and an error message travels into a diagnostic, a support
        // bundle and a terminal: a document that spelled a credential into a name it should not
        // have must not have it copied out again on the way to being refused.
        for name in document.profiles.keys() {
            if name.is_empty() || name.len() > MAX_NAME_LEN {
                let name = super::export::withheld(super::export::ContentClass::Name, name);
                problems.push(format!(
                    "a profile name ({name}) must be between 1 and {MAX_NAME_LEN} characters"
                ));
            }
        }
        if let Some(selected) = document.default_profile.as_ref()
            && !document.profiles.contains_key(selected)
        {
            let selected = super::export::withheld(super::export::ContentClass::Name, selected);
            problems.push(format!(
                "default_profile ({selected}) names no profile in this document"
            ));
        }
        if let Some(limit) = document.ceilings.session_limit.as_ref() {
            if *limit == 0 {
                problems.push("session_limit 0 would admit no session at all".to_owned());
            } else if *limit > MAX_SESSION_LIMIT {
                // Refused rather than recorded and then quietly clamped. A number the registry
                // cannot hold would be written down, reported back as written, and enforced one
                // lower, and the report and the admission limit would disagree for ever.
                problems.push(format!(
                    "session_limit {limit} is above the {MAX_SESSION_LIMIT} this host can record"
                ));
            }
        }
        if let Some(rights) = document.ceilings.grant_rights.as_ref() {
            for right in rights {
                if crate::rights::ActionRight::from_wire(right).is_none() {
                    let right = super::export::withheld(super::export::ContentClass::Name, right);
                    problems.push(format!(
                        "a configured right ({right}) is not an action right"
                    ));
                }
            }
        }
        if let Some(budgets) = document.ceilings.enrolment.0.as_ref() {
            // Only the budgets this document actually names. One left out is the schema's own
            // number, which validated when this build chose it.
            for (field, value) in budgets.written() {
                if value == 0 {
                    problems.push(format!(
                        "an enrolment budget of zero for {field} would enrol no repository"
                    ));
                }
            }
            let resolved = budgets.resolve();
            if resolved.cached_payload_bytes > DEFAULT_CACHED_PAYLOAD_BYTES
                && !resolved.full_offline_mirror
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
                    let value = super::export::withheld(super::export::ContentClass::Name, value);
                    problems.push(format!(
                        "a secret reference's {field} ({value}) must be between 1 and \
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
        ///
        /// The whole section, not one budget of it: what this names becomes what the document
        /// says, and a budget left out of it goes back to the schema's own number.
        Enrolment(ConfiguredEnrolmentBudgets),
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
    }

    /// What a document owes beyond being written, once it has moved.
    ///
    /// Derived from the two documents rather than from the request that produced the new one, so
    /// an edit a person makes in a text editor owes exactly what the same edit made through this
    /// host owes. It is the answer to one question - what is different now - and nothing else
    /// decides which effects run.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Owed {
        /// True when the ceiling on what a grant may carry moved.
        ///
        /// Lowering it takes rights away from grants that are already live, so work admitted
        /// under the old ceiling is fenced before anyone is told the change is in force. A
        /// session ceiling, a sleep policy and an enrolment budget each change what this host
        /// admits or costs rather than what a caller is authorised to do, so none of them fences
        /// anything.
        pub fences_dispatch: bool,
        /// The capability evidence this move invalidated.
        ///
        /// Invalidated, never migrated: a running session keeps the profile it was created in,
        /// and the new value applies to sessions created afterwards.
        pub invalidated: Vec<crate::desktop::CapabilityInvalidation>,
    }

    /// Returns what moving from `before` to `after` owes.
    ///
    /// A document this host cannot use is `None` on either side and decides nothing: what was in
    /// force stays in force, which is why an unreadable file never lifts a restriction.
    #[must_use]
    pub fn owed(
        before: Option<&ConfigurationDocument>,
        after: Option<&ConfigurationDocument>,
    ) -> Owed {
        let Some(after) = after else {
            return Owed::default();
        };
        // A host with no usable document is compared against an empty one rather than against
        // nothing, so a document that appears saying what the defaults already said owes nothing.
        let empty = ConfigurationDocument::empty();
        let before = before.unwrap_or(&empty);
        // The profile a session is created in is resolved from the host preference, the named
        // profiles and the default selection together, so any of the three moving is the evidence
        // moving. Re-reading evidence that turns out to be the same costs one reading; not
        // re-reading it publishes records about a profile this host no longer creates sessions in.
        let profile = |document: &ConfigurationDocument| {
            (
                document.preferences.worker_profile,
                document.profiles.clone(),
                document.default_profile.clone(),
            )
        };
        let mut invalidated = Vec::new();
        if profile(before) != profile(after) {
            invalidated.push(crate::desktop::CapabilityInvalidation::WorkerProfile);
        }
        Owed {
            fences_dispatch: before.ceilings.grant_rights != after.ceilings.grant_rights,
            invalidated,
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

    /// How long a writer waits for the lock before it reports that somebody else holds it.
    ///
    /// An edit holds the lock across a read, a validation and one atomic write, which is
    /// microseconds; and a host that starts a worker hands that worker a copy of every descriptor
    /// it has open between the fork and the exec, so a lock this process has already released can
    /// still look held for as long as that child takes to start. Waiting a moment tells those two
    /// apart from a person who really is editing the document in another terminal, and a caller
    /// that waits is never a caller that lost an edit.
    pub const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

    /// How often the wait looks again.
    const LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(20);

    /// Takes the configuration lock in `state_directory`.
    ///
    /// Uses an operating-system file lock held through an open handle (`flock` on Unix, exclusive
    /// share mode on Windows). The lock file stays in place; exiting releases ownership without
    /// race conditions.
    ///
    /// A lock somebody else holds is waited for, up to [`LOCK_WAIT`], and then reported. The wait
    /// is a plain sleep rather than a blocking lock so that the bound is this build's and a writer
    /// that would have waited for ever instead says who it is waiting for.
    ///
    /// # Errors
    ///
    /// Returns the sentence a caller reports when another writer holds the lock, or when the lock
    /// cannot be taken at all.
    pub fn lock(state_directory: &std::path::Path) -> Result<EditLock, String> {
        let path = state_directory.join(LOCK_NAME);
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            match take_lock(state_directory, &path) {
                Ok(lock) => return Ok(lock),
                // A lock this host could not take at all is not a lock to wait for: waiting would
                // repeat the same failure until the bound ran out and report it two seconds later.
                Err(LockRefused::Failed(problem)) => return Err(problem),
                Err(LockRefused::Held(held)) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(held);
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
            }
        }
    }

    /// Why one attempt at the lock did not take it.
    enum LockRefused {
        /// Somebody else holds it, which is worth waiting a moment for.
        Held(String),
        /// This host could not use the lock file at all.
        Failed(String),
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
    ) -> Result<EditLock, LockRefused> {
        use rustix::fs::{FlockOperation, flock};
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600);
        let file = options.open(path).map_err(|error| {
            LockRefused::Failed(format!(
                "this host could not open {}: {error}",
                path.display()
            ))
        })?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(EditLock {
                _file: file,
                path: path.to_path_buf(),
            }),
            Err(error)
                if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN =>
            {
                Err(LockRefused::Held(busy(state_directory, path)))
            }
            Err(error) => Err(LockRefused::Failed(format!(
                "this host could not lock {}: {error}",
                path.display()
            ))),
        }
    }

    #[cfg(not(unix))]
    fn take_lock(
        state_directory: &std::path::Path,
        path: &std::path::Path,
    ) -> Result<EditLock, LockRefused> {
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
                    Err(LockRefused::Held(busy(state_directory, path)))
                }
                Err(error) => Err(LockRefused::Failed(format!(
                    "this host could not open {}: {error}",
                    path.display()
                ))),
            }
        }
        #[cfg(not(windows))]
        {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            let file = options.open(path).map_err(|error| {
                LockRefused::Failed(format!(
                    "this host could not open {}: {error}",
                    path.display()
                ))
            })?;
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
    /// Three kinds are here. The platform directory variables are how the operating system itself
    /// names its conventional locations, and reading them is what "native OS-appropriate
    /// locations" means rather than an exception to it. The session variables are how the
    /// platform describes the login this host is running in, which is a reading of the
    /// environment rather than a choice about it. The network selections are the ones that do
    /// reach a provider origin and, in one case, the owner signer; they belong in the
    /// configuration document and in the pairing record, and until they are there this host says
    /// so out loud.
    ///
    /// The list names what this build reads that decides something: a location, the login this
    /// host describes, or a network selection. It is not an inventory of every variable a process
    /// in this tree ever looks at, and it does not claim to be one. A name that is in neither this
    /// table nor [`ALLOWLIST`] takes no part in the precedence.
    pub const UNGOVERNED: [UngovernedVariable; 22] = [
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
            variable: "XDG_CONFIG_HOME",
            selects: "the platform's per-user configuration directory on Linux",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "HOME",
            selects: "the account's home directory, from which every default root is derived",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "PATH",
            selects: "where a capability probe looks for the tools it reports on",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "DISPLAY",
            selects: "the X display a desktop reading describes",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "XAUTHORITY",
            selects: "the X authority file a desktop reading describes",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "XDG_SESSION_ID",
            selects: "the login session a desktop reading describes on Linux",
            reaches_authority: false,
        },
        UngovernedVariable {
            variable: "SESSIONNAME",
            selects: "the login session a desktop reading describes on Windows",
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

    /// Whether `value` is one of the closed-set words this build defines.
    ///
    /// The allowlist a sentence checks a runtime string against before printing it. Every entry
    /// comes from a table this module or the protocol already owns: the preference keys, the
    /// ceiling keys, the enrolment budgets, the documented environment variables, the variables
    /// this build reads outside the precedence, and the wire words of the closed enumerations a
    /// report names. A string that is none of them is something somebody else wrote, and a
    /// sentence carries its class and its length instead.
    #[must_use]
    pub fn is_known_term(value: &str) -> bool {
        PREFERENCES.iter().any(|preference| preference.key == value)
            || CEILINGS.contains(&value)
            || BUDGETS.contains(&value)
            || ALLOWLIST
                .iter()
                .any(|entry| entry.variable == value || entry.preference == value)
            || ungoverned_here()
                .iter()
                .any(|entry| entry.variable == value)
            || WIRE_WORDS.contains(&value)
            || crate::desktop::SleepInhibitionSetting::from_wire(value).is_some()
            || value.parse::<crate::rights::ActionRight>().is_ok()
    }

    /// The ceilings a report names, which are the ceilings a document may carry.
    pub const CEILINGS: [&str; 3] = ["session_limit", "enrolment", "grant_rights"];

    /// The repository enrolment budgets a document may name.
    pub const BUDGETS: [&str; 10] = [
        "metadata_bytes",
        "metadata_entries",
        "retained_generations",
        "cached_payload_bytes",
        "package_bytes",
        "object_count",
        "expanded_pack_bytes",
        "transfer_bytes",
        "compilation_ms",
        "full_offline_mirror",
    ];

    /// The wire words of the closed enumerations a configuration report names.
    ///
    /// Each one is the `as_str` of an enumeration in this crate. They are listed rather than
    /// derived because a `const` cannot call those methods, and a test asserts the list is exactly
    /// what those methods return.
    pub const WIRE_WORDS: [&str; 17] = [
        "ok",
        "warning",
        "failed",
        "not_applicable",
        "absent",
        "loaded",
        "unknown_version",
        "unreadable",
        "invalid",
        "request",
        "profile",
        "host_configuration",
        "default",
        "immediately",
        "new_sessions_only",
        "desktop_bound",
        "headless_user",
    ];
}

/// What may leave this host, and in what form.
///
/// `DoctorCheck::detail` has claimed "credentials are redacted" since the first diagnostic was
/// written. Section 26 asks for support bundles that show "software versions, capabilities and
/// redacted errors" and section 23 asks the host-and-environment diagnostics to redact
/// credentials. Both are promises about what leaves this host.
///
/// They are kept by knowing what each exported field *is*, not by reading a value and guessing
/// whether a credential is in it. [`EXPORTED`] names every field of every exported type with its
/// [`ContentClass`], and a class either carries its own text out of this host or it does not. The
/// ones that do are the ones whose content this build decides: words it spells out in its own
/// source, members of closed sets it defines, numbers, and identifiers it generated. Everything
/// else - a message from a library, a command line, a path, a URL, a header, the value of an
/// environment variable, a name an account or a person supplied - leaves as its class and its
/// length, or not at all, and never as its text.
///
/// That is why there is no scanner here. A credential in a field of a withheld class is gone
/// because the field is withheld, whatever the credential looks like and whatever case it is
/// written in; a value in a field of a carrying class is one of this build's own words, which is
/// not somewhere a credential can be. A pattern that decided between the two would have to tell a
/// token from a sentence, and no pattern can.
///
/// The sentences this build writes about itself go through [`Sentence`], whose only text is
/// `&'static str`: a literal in this source. A message that arrived at runtime is a `String` and
/// cannot be put in one, so a check's detail cannot come to carry a library's error message by
/// somebody interpolating it.
pub mod export {
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    /// What one exported value is made of.
    ///
    /// The list is closed, and adding to it is a decision about what this host may say about
    /// itself. [`ContentClass::carries_its_text`] is the whole of the rule.
    #[derive(
        Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
    )]
    #[serde(rename_all = "snake_case")]
    pub enum ContentClass {
        /// Words this build spells out in its own source.
        Stated,
        /// One member of a closed set this build defines: a preference key, a wire word, the name
        /// of a documented environment variable.
        Term,
        /// A number this build produced.
        Number,
        /// An identifier this host generated, carrying nothing from outside it.
        Identifier,
        /// A value of another exported type, covered by that type's own rows.
        Structure,
        /// A value whose class the row itself carries, in a `class` field beside it.
        Declared,
        /// A filesystem path.
        Path,
        /// A message from a library, the operating system or something upstream.
        Message,
        /// A command line.
        CommandLine,
        /// A network location.
        Location,
        /// A protocol header's value.
        Header,
        /// The value of an environment variable.
        Variable,
        /// A name an account, a platform or a person supplied.
        Name,
    }

    impl ContentClass {
        /// Returns the stable wire string.
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Stated => "stated",
                Self::Term => "term",
                Self::Number => "number",
                Self::Identifier => "identifier",
                Self::Structure => "structure",
                Self::Declared => "declared",
                Self::Path => "path",
                Self::Message => "message",
                Self::CommandLine => "command_line",
                Self::Location => "location",
                Self::Header => "header",
                Self::Variable => "variable",
                Self::Name => "name",
            }
        }

        /// Whether a value of this class leaves this host as its own text.
        ///
        /// True only where this build decided the content. Everything a person, a platform, a
        /// library or an upstream wrote is false, whether or not anybody expects a credential in
        /// it: the field is what is known, and the value is not looked at.
        #[must_use]
        pub const fn carries_its_text(self) -> bool {
            matches!(
                self,
                Self::Stated | Self::Term | Self::Number | Self::Identifier | Self::Structure
            )
        }
    }

    /// Every class, in the order they are declared.
    pub const CLASSES: [ContentClass; 13] = [
        ContentClass::Stated,
        ContentClass::Term,
        ContentClass::Number,
        ContentClass::Identifier,
        ContentClass::Structure,
        ContentClass::Declared,
        ContentClass::Path,
        ContentClass::Message,
        ContentClass::CommandLine,
        ContentClass::Location,
        ContentClass::Header,
        ContentClass::Variable,
        ContentClass::Name,
    ];

    /// A value that has left this host through the allowlist.
    ///
    /// This is the second of the two forms every diagnostic has. The plain type is what the owner's
    /// own control path shows them about their own machine: the path their document is at, the
    /// directories this host resolved, the name they gave an environment. This one is what goes to
    /// somebody else - into a support bundle, into a file they send on - and it carries each value
    /// on its class's terms instead.
    ///
    /// The distinction is the type rather than a habit, because the failure it prevents is a
    /// habitual one: a display value serialised into an export by a caller who did not think about
    /// where it was going. There is no way to make one of these except by taking a value through
    /// [`ForExport::for_export`], and no way to take an exported value back through it a second
    /// time.
    ///
    /// ```compile_fail
    /// use kr_protocol::hostinfo::{EffectiveConfiguration, export::Exported};
    /// // A report the host built for a person cannot be put where an export belongs.
    /// let display = EffectiveConfiguration::unread();
    /// let exported: Exported<EffectiveConfiguration> = display;
    /// ```
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Exported<T>(T);

    /// An export is its own type in this source and the type it wraps on the wire.
    ///
    /// The distinction it makes is between two ways of using one value, and a reader of a support
    /// bundle needs the value rather than the distinction: the schema therefore describes the type
    /// inside, and a bundle's `doctor` member is a `HostDoctorResult` to everybody who parses one.
    impl<T: JsonSchema> JsonSchema for Exported<T> {
        fn schema_name() -> std::borrow::Cow<'static, str> {
            T::schema_name()
        }

        fn schema_id() -> std::borrow::Cow<'static, str> {
            T::schema_id()
        }

        fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
            T::json_schema(generator)
        }

        fn inline_schema() -> bool {
            T::inline_schema()
        }
    }

    impl<T> Exported<T> {
        /// Records that `value` has just been taken through the allowlist.
        ///
        /// Visible only inside this module's own crate half, so the only callers are the
        /// [`ForExport`] implementations beside the types they reduce.
        pub(super) const fn of(value: T) -> Self {
            Self(value)
        }

        /// Returns what was exported.
        pub const fn get(&self) -> &T {
            &self.0
        }
    }

    /// A diagnostic with a display form and an export form.
    ///
    /// Implemented beside each type that has both. The trait cannot be implemented outside this
    /// crate, because building the value it returns is not possible outside it.
    pub trait ForExport: Sized {
        /// Returns this value with every field taken through the allowlist.
        #[must_use]
        fn for_export(self) -> Exported<Self>;
    }

    /// One exported field, and what its value is made of.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ExportedField {
        /// The type the field belongs to, as the schema names it.
        pub type_name: &'static str,
        /// The field, as the wire spells it.
        pub field: &'static str,
        /// What its value is made of.
        pub class: ContentClass,
    }

    /// Every field of every type this host exports, with its content class.
    ///
    /// The one allowlist. A field that is not here is not exported, and a test walks each type's
    /// schema to keep that true: a field added to an exported type without a decision about what
    /// its value is made of fails the build's own tests rather than reaching a support bundle.
    pub const EXPORTED: &[ExportedField] = &[
        field("DoctorCheck", "id", ContentClass::Stated),
        field("DoctorCheck", "title", ContentClass::Stated),
        field("DoctorCheck", "status", ContentClass::Term),
        field("DoctorCheck", "detail", ContentClass::Stated),
        field("DoctorCheck", "remedy", ContentClass::Stated),
        field("HostDoctorResult", "checks", ContentClass::Structure),
        field("HostDoctorResult", "healthy", ContentClass::Term),
        field("HostDoctorResult", "configuration", ContentClass::Structure),
        field("EffectiveValue", "key", ContentClass::Term),
        field("EffectiveValue", "about", ContentClass::Stated),
        field("EffectiveValue", "value", ContentClass::Declared),
        field("EffectiveValue", "class", ContentClass::Term),
        field("EffectiveValue", "source", ContentClass::Term),
        field("EffectiveValue", "origin", ContentClass::Name),
        field("EffectiveValue", "variable", ContentClass::Term),
        field("EffectiveValue", "effect", ContentClass::Term),
        field("CeilingValue", "key", ContentClass::Term),
        field("CeilingValue", "configured", ContentClass::Stated),
        field("CeilingValue", "value", ContentClass::Stated),
        field("CeilingValue", "source", ContentClass::Term),
        field("CeilingValue", "origin", ContentClass::Name),
        field("CeilingValue", "effect", ContentClass::Term),
        field("CeilingValue", "narrowed_by", ContentClass::Stated),
        field("CeilingValue", "refused", ContentClass::Term),
        field("OverrideReport", "variable", ContentClass::Term),
        field("OverrideReport", "preference", ContentClass::Term),
        field("OverrideReport", "position", ContentClass::Term),
        field("OverrideReport", "why", ContentClass::Stated),
        field("OverrideReport", "set", ContentClass::Term),
        field(
            "EffectiveConfiguration",
            "schema_version",
            ContentClass::Number,
        ),
        field("EffectiveConfiguration", "revision", ContentClass::Number),
        field("EffectiveConfiguration", "document", ContentClass::Path),
        field("EffectiveConfiguration", "status", ContentClass::Structure),
        field(
            "EffectiveConfiguration",
            "runtime_directory",
            ContentClass::Path,
        ),
        field(
            "EffectiveConfiguration",
            "state_directory",
            ContentClass::Path,
        ),
        field("EffectiveConfiguration", "precedence", ContentClass::Stated),
        field(
            "EffectiveConfiguration",
            "overrides",
            ContentClass::Structure,
        ),
        field("EffectiveConfiguration", "values", ContentClass::Structure),
        field(
            "EffectiveConfiguration",
            "ceilings",
            ContentClass::Structure,
        ),
        field("EffectiveConfiguration", "secrets", ContentClass::Structure),
        field(
            "EffectiveConfiguration",
            "stale_documents",
            ContentClass::Path,
        ),
        field(
            "EffectiveConfiguration",
            "not_in_force",
            ContentClass::Stated,
        ),
        field(
            "EffectiveConfiguration",
            "fence_outstanding",
            ContentClass::Stated,
        ),
        field(
            "EffectiveConfiguration",
            "locations",
            ContentClass::Structure,
        ),
        field("DocumentStatus", "state", ContentClass::Term),
        field("DocumentStatus", "detail", ContentClass::Stated),
        field("ReportedLocation", "what", ContentClass::Term),
        field("ReportedLocation", "documented", ContentClass::Stated),
        field("SecretReference", "name", ContentClass::Name),
        field("SecretReference", "store", ContentClass::Name),
        field("SecretReference", "item", ContentClass::Name),
        field("SoftwareComponent", "component", ContentClass::Stated),
        field("SoftwareComponent", "version", ContentClass::Stated),
        field("RedactedError", "component", ContentClass::Stated),
        field("RedactedError", "message", ContentClass::Message),
        field("ContentExport", "includes", ContentClass::Stated),
        field("ContentExport", "entries", ContentClass::Stated),
        field("SupportBundle", "generated_at_ms", ContentClass::Number),
        field("SupportBundle", "software", ContentClass::Structure),
        field("SupportBundle", "capabilities", ContentClass::Structure),
        field("SupportBundle", "doctor", ContentClass::Structure),
        field("SupportBundle", "configuration", ContentClass::Structure),
        field("SupportBundle", "errors", ContentClass::Structure),
        field("SupportBundle", "content", ContentClass::Structure),
        field("CapabilityRecord", "capability", ContentClass::Term),
        field("CapabilityRecord", "version", ContentClass::Number),
        field("CapabilityRecord", "subject", ContentClass::Structure),
        field("CapabilityRecord", "revision", ContentClass::Number),
        field("CapabilityRecord", "state", ContentClass::Term),
        field("CapabilityRecord", "evidence_source", ContentClass::Term),
        field("CapabilityRecord", "identity", ContentClass::Structure),
        field("CapabilityRecord", "invalidation", ContentClass::Term),
        field("CapabilityRecord", "disabled_reason", ContentClass::Message),
        field("CapabilityRecord", "observed_at_ms", ContentClass::Number),
        field(
            "CapabilitySubject",
            "environment_id",
            ContentClass::Identifier,
        ),
        field(
            "CapabilitySubject",
            "desktop_session_id",
            ContentClass::Name,
        ),
        field("CapabilitySubject", "session_id", ContentClass::Identifier),
        field("CapabilitySubject", "application", ContentClass::Name),
        field("CapabilitySubject", "terminal", ContentClass::Name),
        field("CapabilityIdentity", "binary", ContentClass::Path),
        field("CapabilityIdentity", "version", ContentClass::Name),
        field("CapabilityIdentity", "package", ContentClass::Name),
        field("CapabilityIdentity", "schema", ContentClass::Name),
        field("CapabilityIdentity", "profile", ContentClass::Term),
        field("DesktopContext", "desktop_session_id", ContentClass::Name),
        field("DesktopContext", "kind", ContentClass::Term),
        field("DesktopContext", "platform_session", ContentClass::Name),
        field("DesktopContext", "login_generation", ContentClass::Number),
        field("DesktopContext", "generation_source", ContentClass::Term),
        field("DesktopContext", "os_user", ContentClass::Name),
        field("DesktopContext", "uid", ContentClass::Number),
        field("DesktopContext", "boot_identity", ContentClass::Identifier),
        field("DesktopContext", "graphic_access", ContentClass::Term),
        field("DesktopContext", "remote", ContentClass::Term),
        field("DesktopContext", "availability", ContentClass::Term),
        field("DesktopContext", "container", ContentClass::Term),
        field("DesktopContext", "display_server", ContentClass::Term),
        field("DesktopContext", "compositor", ContentClass::Name),
        field("DesktopContext", "worker_profile", ContentClass::Term),
        field("ProfilePersistence", "profile", ContentClass::Term),
        field("ProfilePersistence", "persistence", ContentClass::Term),
        // Both sentences are written in this source: the first by the supervisor this host
        // selected and the second by the per-platform persistence table beside it. The class is
        // the record of that decision and [`Stated`] is what holds the producers to it, so the
        // two agree by construction rather than by inspection.
        field("ProfilePersistence", "mechanism", ContentClass::Stated),
        field("ProfilePersistence", "detail", ContentClass::Stated),
    ];

    const fn field(
        type_name: &'static str,
        field: &'static str,
        class: ContentClass,
    ) -> ExportedField {
        ExportedField {
            type_name,
            field,
            class,
        }
    }

    /// Returns what one exported field's value is made of.
    #[must_use]
    pub fn class_of(type_name: &str, field: &str) -> Option<ContentClass> {
        EXPORTED
            .iter()
            .find(|entry| entry.type_name == type_name && entry.field == field)
            .map(|entry| entry.class)
    }

    /// Renders a value this host does not export as its text.
    ///
    /// What a reader gets is the class and the length, which is enough to tell an empty field from
    /// a full one and one kind of value from another, and is not enough to carry a credential.
    #[must_use]
    pub fn withheld(class: ContentClass, value: &str) -> String {
        format!("[{} withheld, {} bytes]", class.as_str(), value.len())
    }

    /// Returns `value` where its class carries its text, and the withheld record otherwise.
    ///
    /// A term is checked rather than trusted. The class says the field holds one member of a
    /// closed set this build defines, and a string that is not one of them is something somebody
    /// else wrote into a field that was supposed to hold a key: it leaves as a name.
    ///
    /// Nothing looks at whether a value has been here before, because nothing crosses this
    /// boundary twice: each value is carried by the one conversion that puts it inside an
    /// [`Exported`], and there is no conversion from an exported value back to a display one. A
    /// record measured a second time would report the length of the record rather than of the
    /// value it stands for.
    #[must_use]
    pub fn carry(class: ContentClass, value: &str) -> String {
        match class {
            ContentClass::Term if !super::configuration::is_known_term(value) => {
                withheld(ContentClass::Name, value)
            }
            _ if class.carries_its_text() => value.to_owned(),
            _ => withheld(class, value),
        }
    }

    /// Returns a nullable value taken through [`carry`].
    #[must_use]
    pub fn carry_null(
        class: ContentClass,
        value: &crate::scalars::Nullable<String>,
    ) -> crate::scalars::Nullable<String> {
        crate::scalars::Nullable(value.0.as_deref().map(|text| carry(class, text)))
    }

    /// An identifier this host generated, which a sentence may name in full.
    ///
    /// The list is closed and every member is a type whose contents this host composed: a session
    /// identifier, an environment's, a device's, the revision of a capability record. A `String`
    /// is not one of them and neither is anything else that arrived at runtime, so a sentence
    /// cannot come to name one because a caller passed something that happened to print.
    ///
    /// Sealed: the list can only grow here, where adding to it is a decision about what this host
    /// says about itself, rather than in whatever crate wanted its own type in a sentence.
    pub trait HostIdentifier: std::fmt::Display + sealed::Generated {}

    mod sealed {
        /// Implemented beside each identifier this host generates, and nowhere else.
        pub trait Generated {}
    }

    impl sealed::Generated for crate::ids::SessionId {}
    impl HostIdentifier for crate::ids::SessionId {}
    impl sealed::Generated for crate::ids::EnvironmentId {}
    impl HostIdentifier for crate::ids::EnvironmentId {}
    impl sealed::Generated for crate::ids::DeviceId {}
    impl HostIdentifier for crate::ids::DeviceId {}
    impl sealed::Generated for crate::worker::ReservationId {}
    impl HostIdentifier for crate::worker::ReservationId {}
    impl sealed::Generated for crate::ids::AuthorityRevision {}
    impl HostIdentifier for crate::ids::AuthorityRevision {}
    impl sealed::Generated for crate::ids::CapabilityRevision {}
    impl HostIdentifier for crate::ids::CapabilityRevision {}
    impl sealed::Generated for crate::ids::ControllerGeneration {}
    impl HostIdentifier for crate::ids::ControllerGeneration {}

    /// Words this build spells out in its own source, as a wire field holds them.
    ///
    /// A field classed [`ContentClass::Stated`] carries its text out of this host because the text
    /// is this build's own. The class on its own is a claim about the producer, and a claim is
    /// what a caller forgets: the type is how the producer proves it. The only constructor takes
    /// `&'static str`, so a value that arrived at runtime cannot be put in one, and
    /// [`Self::written_here`] answers whether this particular value came that way.
    ///
    /// Reading is the one thing that can produce a value here without a literal, because a parsed
    /// document owns its text. Such a value is an owned one, [`Self::written_here`] returns `None`
    /// for it, and nothing that composes this build's own words will quote it.
    ///
    /// ```compile_fail
    /// use kr_protocol::hostinfo::export::Stated;
    /// // The supervisor a host detected is a runtime value whatever it prints as.
    /// let detected = String::from("launchd, token opensesame");
    /// let stated = Stated::new(&detected);
    /// ```
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct Stated(std::borrow::Cow<'static, str>);

    impl Stated {
        /// Records words written in this source.
        #[must_use]
        pub const fn new(text: &'static str) -> Self {
            Self(std::borrow::Cow::Borrowed(text))
        }

        /// The words, for a reader that only wants to show them.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }

        /// The words when this value was written in this source, and `None` when it was read.
        ///
        /// A borrowed value inside a `Cow<'static, str>` is a `&'static str`, and the only way to
        /// have one is [`Self::new`]: every other route into this type owns its text. That is what
        /// makes this a test of where a value came from rather than of what it says.
        #[must_use]
        pub const fn written_here(&self) -> Option<&'static str> {
            match &self.0 {
                std::borrow::Cow::Borrowed(text) => Some(text),
                std::borrow::Cow::Owned(_) => None,
            }
        }
    }

    impl std::fmt::Display for Stated {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.0)
        }
    }

    /// A stated value is a string on the wire, exactly as it was before it had a type here.
    impl JsonSchema for Stated {
        fn schema_name() -> std::borrow::Cow<'static, str> {
            String::schema_name()
        }

        fn schema_id() -> std::borrow::Cow<'static, str> {
            String::schema_id()
        }

        fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
            String::json_schema(generator)
        }

        fn inline_schema() -> bool {
            String::inline_schema()
        }
    }

    /// One value beside the class it is made of.
    ///
    /// A row that carries its own class is a row that decides its own terms, so the two are built
    /// together here and never separately: [`Declared::path`] takes a path and says so,
    /// [`Declared::term`] takes one of this build's own words. There is no constructor that takes a
    /// class beside a value a caller chose, which is what stops a path declaring itself as this
    /// build's own text.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Declared {
        class: ContentClass,
        value: String,
    }

    impl Declared {
        /// One member of a closed set this build defines.
        #[must_use]
        pub fn term(value: &str) -> Self {
            Self {
                class: ContentClass::Term,
                value: value.to_owned(),
            }
        }

        /// A filesystem path, wherever it came from.
        #[must_use]
        pub fn path(value: &std::path::Path) -> Self {
            Self {
                class: ContentClass::Path,
                value: value.display().to_string(),
            }
        }

        /// A number this build produced.
        #[must_use]
        pub fn number(value: u64) -> Self {
            Self {
                class: ContentClass::Number,
                value: value.to_string(),
            }
        }

        /// Words this build spells out in its own source.
        #[must_use]
        pub fn stated(value: &'static str) -> Self {
            Self {
                class: ContentClass::Stated,
                value: value.to_owned(),
            }
        }

        /// What this value is made of.
        #[must_use]
        pub const fn class(&self) -> ContentClass {
            self.class
        }

        /// The value as it stands, for the report a host shows its owner.
        #[must_use]
        pub fn value(&self) -> &str {
            &self.value
        }
    }

    /// A sentence this build writes about its own host.
    ///
    /// The only text it takes is `&'static str`, which is a literal in this source. A message from
    /// a library, a path, or anything else that arrived at runtime is a `String` and cannot be put
    /// in one; what such a value contributes is a number, a member of a closed set, an identifier
    /// this host generated, or its class and its length.
    ///
    /// That is the whole of why a check's detail cannot come to carry a credential. It is not that
    /// each caller remembers to redact: it is that there is nowhere in a sentence to put text that
    /// came from outside this source.
    ///
    /// ```compile_fail
    /// use kr_protocol::hostinfo::export::Sentence;
    /// // A value that arrived at runtime is not an identifier this host generated, whatever it
    /// // happens to print as.
    /// let arrived = String::from("token opensesame");
    /// let sentence = Sentence::new().identifier(&arrived);
    /// ```
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Sentence(String);

    impl Sentence {
        /// Starts an empty sentence.
        #[must_use]
        pub fn new() -> Self {
            Self(String::new())
        }

        /// Appends text written in this source.
        #[must_use]
        pub fn stated(mut self, text: &'static str) -> Self {
            self.0.push_str(text);
            self
        }

        /// Appends a number.
        #[must_use]
        pub fn number(mut self, value: u64) -> Self {
            use std::fmt::Write as _;
            let _ = write!(&mut self.0, "{value}");
            self
        }

        /// Appends one member of a closed set this build defines.
        ///
        /// A string that is not in one of those sets is withheld rather than printed. The check is
        /// what makes this safe to call with a key read back out of a wire struct: a document that
        /// invented a key it is not this build's to name contributes a class and a length.
        #[must_use]
        pub fn term(mut self, value: &str) -> Self {
            if super::configuration::is_known_term(value) {
                self.0.push_str(value);
            } else {
                self.0.push_str(&withheld(ContentClass::Name, value));
            }
            self
        }

        /// Appends an identifier this host generated.
        ///
        /// The argument is one of the identifier types [`HostIdentifier`] lists, so what is
        /// appended is something this host composed rather than something that printed.
        #[must_use]
        pub fn identifier(mut self, value: &impl HostIdentifier) -> Self {
            use std::fmt::Write as _;
            let _ = write!(&mut self.0, "{value}");
            self
        }

        /// Appends a value's class and length in place of the value.
        #[must_use]
        pub fn withheld(mut self, class: ContentClass, value: &str) -> Self {
            self.0.push_str(&withheld(class, value));
            self
        }

        /// Appends words this build wrote, read back out of a wire field.
        ///
        /// [`Stated`] answers where its text came from, so this appends the words when they were
        /// written in this source and their class and length when they were read from a document
        /// somebody else wrote. That is the difference between quoting this build and quoting a
        /// reply: a sentence composed from a response cannot come to repeat what the response
        /// said.
        #[must_use]
        pub fn stated_value(mut self, value: &Stated) -> Self {
            match value.written_here() {
                Some(text) => self.0.push_str(text),
                None => self
                    .0
                    .push_str(&withheld(ContentClass::Stated, value.as_str())),
            }
            self
        }

        /// Appends the value of another exported field, on the terms its class sets.
        ///
        /// The class comes from [`EXPORTED`] rather than from the caller, so quoting a field into
        /// a sentence and exporting that field are the same decision, and a pair that is not in
        /// the allowlist at all is withheld as a name. This is the only way a sentence takes a
        /// value that is not a literal, a number or an identifier: a value with nowhere in the
        /// allowlist to belong cannot be put in one.
        #[must_use]
        pub fn field(mut self, type_name: &'static str, name: &'static str, value: &str) -> Self {
            self.0.push_str(&carry(class(type_name, name), value));
            self
        }

        /// Appends several terms, separated by `between`.
        #[must_use]
        pub fn terms<'a>(
            mut self,
            values: impl IntoIterator<Item = &'a str>,
            between: &'static str,
        ) -> Self {
            for (index, value) in values.into_iter().enumerate() {
                if index > 0 {
                    self.0.push_str(between);
                }
                self = self.term(value);
            }
            self
        }

        /// Whether nothing has been appended.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        /// Returns the finished sentence.
        #[must_use]
        pub fn render(self) -> String {
            self.0
        }
    }

    impl std::fmt::Display for Sentence {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.0)
        }
    }

    /// Returns a desktop context every field of which has been through the allowlist.
    ///
    /// The context travels beside the capability records, to a paired device, into `kr doctor`'s
    /// output and into a support bundle. The operating-system user name, the platform's own
    /// session identifier, the compositor's name and the desktop identity this host derives are
    /// all names something outside this build supplied, so each leaves as its class and its
    /// length. The derived identity is a typed identifier with nowhere to put such a record, so a
    /// present one leaves as a fixed marker: whether there is a desktop is not a secret, and what
    /// it is called is. The context this host keeps for its own comparisons is untouched.
    #[must_use]
    pub fn desktop_context(
        context: crate::desktop::DesktopContext,
    ) -> crate::desktop::DesktopContext {
        crate::desktop::DesktopContext {
            os_user: carry(class("DesktopContext", "os_user"), &context.os_user),
            platform_session: carry_null(
                class("DesktopContext", "platform_session"),
                &context.platform_session,
            ),
            compositor: carry_null(class("DesktopContext", "compositor"), &context.compositor),
            desktop_session_id: crate::scalars::Nullable(
                context
                    .desktop_session_id
                    .0
                    .as_ref()
                    .map(|_| withheld_identity()),
            ),
            ..context
        }
    }

    /// The identifier a withheld desktop identity leaves as.
    ///
    /// A derived desktop identity spells out the login kind, the account's name, the numeric user,
    /// the platform session and the boot, so none of it may leave. Dropping the field says
    /// something different and untrue: a reader takes an absent identity for a host with no
    /// graphical login at all. This says the identity is withheld and the desktop is there.
    fn withheld_identity() -> crate::ids::DesktopSessionId {
        crate::ids::DesktopSessionId::new("[name withheld]")
            .expect("the withheld marker is a valid identifier")
    }

    /// Returns capability evidence every field of which has been through the allowlist.
    ///
    /// The one place capability records cross a boundary. A record's sentence is written by
    /// whatever probed the capability, and the identity is the binary that probe found on `PATH`
    /// and the version that binary printed: all of it comes from outside this host, and all of it
    /// travels in diagnostics, in a support bundle and in the answer a paired device gets. The
    /// evidence this host keeps for itself is never changed by this, because a withheld path is no
    /// longer a path it can compare.
    #[must_use]
    pub fn capability_records(
        records: Vec<crate::desktop::CapabilityRecord>,
    ) -> Vec<crate::desktop::CapabilityRecord> {
        records.into_iter().map(withheld_capability).collect()
    }

    impl ForExport for crate::desktop::CapabilityRecord {
        fn for_export(self) -> Exported<Self> {
            Exported::of(withheld_capability(self))
        }
    }

    /// One capability record with every field through the allowlist.
    fn withheld_capability(
        record: crate::desktop::CapabilityRecord,
    ) -> crate::desktop::CapabilityRecord {
        {
            crate::desktop::CapabilityRecord {
                disabled_reason: carry_null(
                    class("CapabilityRecord", "disabled_reason"),
                    &record.disabled_reason,
                ),
                subject: crate::desktop::CapabilitySubject {
                    // The same derived desktop identity the context carries, through the same
                    // boundary: one copy of it exported and the other not would be no boundary.
                    desktop_session_id: crate::scalars::Nullable(
                        record
                            .subject
                            .desktop_session_id
                            .0
                            .as_ref()
                            .map(|_| withheld_identity()),
                    ),
                    application: carry_null(
                        class("CapabilitySubject", "application"),
                        &record.subject.application,
                    ),
                    terminal: carry_null(
                        class("CapabilitySubject", "terminal"),
                        &record.subject.terminal,
                    ),
                    ..record.subject
                },
                identity: crate::desktop::CapabilityIdentity {
                    binary: carry_null(
                        class("CapabilityIdentity", "binary"),
                        &record.identity.binary,
                    ),
                    version: carry_null(
                        class("CapabilityIdentity", "version"),
                        &record.identity.version,
                    ),
                    // Every string in the identity, so the boundary does not have to be revisited
                    // the first time a catalogue fills a field this host leaves empty today.
                    package: carry_null(
                        class("CapabilityIdentity", "package"),
                        &record.identity.package,
                    ),
                    schema: carry_null(
                        class("CapabilityIdentity", "schema"),
                        &record.identity.schema,
                    ),
                    ..record.identity
                },
                ..record
            }
        }
    }

    /// The class one exported field's value is made of.
    ///
    /// A field this build exports and never classed is a mistake in [`EXPORTED`] rather than a
    /// value to guess about, so it is withheld as a name: the most conservative class there is.
    pub(super) fn class(type_name: &'static str, field: &'static str) -> ContentClass {
        class_of(type_name, field).unwrap_or(ContentClass::Name)
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

    /// Every credential shape this product has been shown, planted in every free-text field.
    ///
    /// Two of them are the strings a review found reaching a bundle through a scanner that looked
    /// at values: lower-case scheme words in front of something that reads like prose. Nothing
    /// here looks at them. Each one is planted in a field whose class does not carry its text, and
    /// none of their bytes reaches the export.
    const CREDENTIALS: &[(&str, &str)] = &[
        ("basic czpw", "czpw"),
        (
            "request failed for token opensesame at upstream",
            "opensesame",
        ),
        ("Bearer sk-live-abc123", "sk-live-abc123"),
        ("bearer sk-live-abc123", "sk-live-abc123"),
        ("NTLM TlRMTVNTUAAB", "TlRMTVNTUAAB"),
        ("negotiate YIIFrAYGKwYBBQUC", "YIIFrAYGKwYBBQUC"),
        (
            "digest username=\"root\", response=\"deadbeef\"",
            "deadbeef",
        ),
        ("Basic YWxhZGRpbjpvcGVuc2VzYW1l", "YWxhZGRpbjpvcGVuc2VzYW1l"),
        ("https://root:hunter2@api.example.com/v1", "hunter2"),
        ("OPENAI_API_KEY=sk-live-abc123", "sk-live-abc123"),
        ("password: hunter2", "hunter2"),
        ("cookie: session=Ab1Cd2Ef3Gh4", "Ab1Cd2Ef3Gh4"),
        ("hunter2", "hunter2"),
        ("sk-live-abc123", "sk-live-abc123"),
        (
            concat!("xo", "xb-3141592653-abcdefghijklmnop"),
            concat!("xo", "xb-3141592653-abcdefghijklmnop"),
        ),
        ("AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        (concat!("-----BEGIN ", "PRIVATE KEY-----MIIEvQ"), "MIIEvQ"),
    ];

    /// An environment identifier for a test record.
    fn an_environment() -> crate::ids::EnvironmentId {
        crate::ids::EnvironmentId::new(crate::scalars::Uuid::from_bytes([3; 16]))
    }

    /// Builds one support bundle with `secret` planted in every field that can carry text from
    /// outside this build.
    ///
    /// The fields it is not planted in are the ones whose class is stated: a sentence this build
    /// writes. Those cannot hold a credential because [`export::Sentence`] takes no runtime string
    /// at all, so a library's message, a path or a person's name reaches one only as a class and a
    /// length, and every producer of one goes through it. Planting text into such a field here
    /// would test this test's own reach rather than anything the product does.
    fn bundle_carrying(secret: &str) -> SupportBundle {
        let mut configuration = EffectiveConfiguration::unread();
        configuration.document = secret.to_owned();
        configuration.runtime_directory = secret.to_owned();
        configuration.state_directory = secret.to_owned();
        configuration.stale_documents = vec![secret.to_owned()];
        configuration.values = vec![EffectiveValue::new(
            "state_directory",
            "where this host keeps its state",
            &export::Declared::path(std::path::Path::new(secret)),
            ValueSource::Request,
            Nullable(Some(secret.to_owned())),
            Nullable(Some("KR_STATE_DIR".to_owned())),
            configuration::ValueEffect::Immediately,
        )];
        configuration.ceilings = vec![CeilingValue {
            key: secret.to_owned(),
            configured: Nullable(Some("16".to_owned())),
            value: "16".to_owned(),
            source: ValueSource::HostConfiguration,
            origin: Nullable(Some(secret.to_owned())),
            effect: configuration::ValueEffect::Immediately,
            narrowed_by: Nullable(Some("the hard limit".to_owned())),
            refused: false,
        }];
        configuration.secrets = vec![configuration::SecretReference {
            name: secret.to_owned(),
            store: secret.to_owned(),
            item: secret.to_owned(),
        }];
        let check = DoctorCheck::new(
            "configuration-document",
            "This host's configuration document",
            DoctorStatus::Warning,
            export::Sentence::new()
                .stated("the document is ")
                .withheld(export::ContentClass::Path, secret)
                .stated(", naming the profile ")
                .term(secret)
                .stated(" and the ceiling ")
                .field("CeilingValue", "origin", secret),
            Some("Fix the document and run this again."),
        );
        let record = crate::desktop::CapabilityRecord {
            disabled_reason: Nullable(Some(secret.to_owned())),
            subject: crate::desktop::CapabilitySubject {
                desktop_session_id: Nullable(
                    crate::ids::DesktopSessionId::new(format!("kr-{secret}")).ok(),
                ),
                application: Nullable(Some(secret.to_owned())),
                terminal: Nullable(Some(secret.to_owned())),
                session_id: Nullable(None),
                environment_id: an_environment(),
            },
            identity: crate::desktop::CapabilityIdentity {
                binary: Nullable(Some(secret.to_owned())),
                version: Nullable(Some(secret.to_owned())),
                package: Nullable(Some(secret.to_owned())),
                schema: Nullable(Some(secret.to_owned())),
                profile: Nullable(Some(WorkerProfile::HeadlessUser)),
            },
            capability: crate::ids::CapabilityId::new(crate::desktop::capabilities::SCREEN_CAPTURE)
                .expect("a capability"),
            version: crate::scalars::U64::new(1),
            revision: crate::ids::CapabilityRevision::new(1),
            state: crate::desktop::CapabilityState::PermissionRequired,
            evidence_source: crate::desktop::CapabilityEvidenceSource::DisclosedProbe,
            invalidation: Vec::new(),
            observed_at_ms: TimestampMs::new(0),
        };
        SupportBundle::new(
            TimestampMs::new(0),
            vec![SoftwareComponent {
                component: "kr-controller".to_owned(),
                version: "0".to_owned(),
            }],
            vec![record],
            HostDoctorResult::new(vec![check], configuration),
            vec![RedactedError::new("configuration", secret)],
        )
    }

    /// KR-REQ-26.44: no credential shape reaches an export, through any free-text field.
    #[test]
    fn no_credential_shape_reaches_any_export() {
        for (planted, credential) in CREDENTIALS {
            let bundle = bundle_carrying(planted);
            let exported = serde_json::to_string(&bundle).expect("the bundle serialises");
            assert!(
                !exported.contains(planted),
                "{planted:?} reached an export: {exported}"
            );
            // And the credential inside it separately, because a boundary that took the scheme
            // word and left the value would pass the assertion above.
            assert!(
                !exported.contains(credential),
                "{credential:?} of {planted:?} reached an export: {exported}"
            );
        }
    }

    /// KR-REQ-26.44: the allowlist covers every field of every exported type, and nothing else.
    #[test]
    fn every_exported_field_is_classed() {
        let types: Vec<(&str, schemars::Schema)> = vec![
            ("DoctorCheck", schemars::schema_for!(DoctorCheck)),
            ("HostDoctorResult", schemars::schema_for!(HostDoctorResult)),
            ("EffectiveValue", schemars::schema_for!(EffectiveValue)),
            ("CeilingValue", schemars::schema_for!(CeilingValue)),
            ("OverrideReport", schemars::schema_for!(OverrideReport)),
            (
                "EffectiveConfiguration",
                schemars::schema_for!(EffectiveConfiguration),
            ),
            (
                "DocumentStatus",
                schemars::schema_for!(configuration::DocumentStatus),
            ),
            ("ReportedLocation", schemars::schema_for!(ReportedLocation)),
            (
                "SecretReference",
                schemars::schema_for!(configuration::SecretReference),
            ),
            (
                "SoftwareComponent",
                schemars::schema_for!(SoftwareComponent),
            ),
            ("RedactedError", schemars::schema_for!(RedactedError)),
            ("ContentExport", schemars::schema_for!(ContentExport)),
            ("SupportBundle", schemars::schema_for!(SupportBundle)),
            (
                "CapabilityRecord",
                schemars::schema_for!(crate::desktop::CapabilityRecord),
            ),
            (
                "CapabilitySubject",
                schemars::schema_for!(crate::desktop::CapabilitySubject),
            ),
            (
                "CapabilityIdentity",
                schemars::schema_for!(crate::desktop::CapabilityIdentity),
            ),
            (
                "DesktopContext",
                schemars::schema_for!(crate::desktop::DesktopContext),
            ),
            (
                "ProfilePersistence",
                schemars::schema_for!(crate::desktop::ProfilePersistence),
            ),
        ];
        let properties = |schema: &schemars::Schema, name: &str| -> Vec<String> {
            serde_json::to_value(schema)
                .expect("a schema")
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .unwrap_or_else(|| panic!("{name} declares its properties"))
                .keys()
                .cloned()
                .collect()
        };
        for (name, schema) in &types {
            for field in properties(schema, name) {
                assert!(
                    export::class_of(name, &field).is_some(),
                    "{name}.{field} is exported and has no content class"
                );
            }
        }
        for entry in export::EXPORTED {
            let (name, schema) = types
                .iter()
                .find(|(name, _)| *name == entry.type_name)
                .unwrap_or_else(|| panic!("{} is not one of the exported types", entry.type_name));
            assert!(
                properties(schema, name)
                    .iter()
                    .any(|field| field == entry.field),
                "{name}.{} is classed and is not a field",
                entry.field
            );
        }
    }

    /// KR-REQ-26.44: a sentence carries a closed-set word and withholds anything else.
    #[test]
    fn a_sentence_names_a_term_and_withholds_a_name() {
        let sentence = export::Sentence::new()
            .stated("the ceiling ")
            .term("session_limit")
            .stated(" came from ")
            .term("KR_STATE_DIR")
            .stated(" and the profile ")
            .term("hunter2")
            .render();
        assert!(sentence.contains("session_limit"), "{sentence}");
        assert!(sentence.contains("KR_STATE_DIR"), "{sentence}");
        assert!(!sentence.contains("hunter2"), "{sentence}");
        assert!(sentence.contains("[name withheld, 7 bytes]"), "{sentence}");
    }

    /// KR-REQ-26.44: words a reply supplied are not repeated as this build's own.
    ///
    /// The field this covers holds a sentence the product wrote about its own host, and it holds
    /// it out of a wire struct, so the same type arrives both ways: composed here, and parsed from
    /// something another host sent. A composed value is quoted and a parsed one is measured, and
    /// the difference is the value's own rather than a rule each caller has to remember.
    #[test]
    fn a_stated_value_read_from_a_reply_is_measured_rather_than_quoted() {
        let written = crate::desktop::ProfilePersistence::new(
            crate::identity::WorkerProfile::HeadlessUser,
            crate::desktop::LogoutPersistence::NotEstablished,
            "launchd, a per-user job in the background domain",
            "what a logout does here is not established",
        );
        let composed = export::Sentence::new()
            .stated_value(written.mechanism())
            .render();
        assert_eq!(composed, "launchd, a per-user job in the background domain");

        let sent = serde_json::to_string(&written).expect("the answer serialises");
        let hostile = sent.replace(
            "launchd, a per-user job in the background domain",
            "token opensesame",
        );
        let parsed: crate::desktop::ProfilePersistence =
            serde_json::from_str(&hostile).expect("a reply parses");
        assert_eq!(parsed.mechanism().as_str(), "token opensesame");
        assert!(parsed.mechanism().written_here().is_none());

        let quoted = export::Sentence::new()
            .stated_value(parsed.mechanism())
            .render();
        assert!(!quoted.contains("opensesame"), "{quoted}");
        assert_eq!(quoted, "[stated withheld, 16 bytes]");
    }

    /// KR-REQ-26.44: a document's own rejected values reach no export, through the real producer.
    ///
    /// The planted-field test builds the wire structs; this one writes a document and takes it
    /// through `load`, which is where a validation message becomes `DocumentStatus::detail` and
    /// travels into the diagnostics, the doctor's JSON and a bundle.
    #[test]
    fn a_rejected_document_carries_none_of_it_into_an_export() {
        for (planted, credential) in CREDENTIALS {
            let mut document = ConfigurationDocument::empty();
            let long = format!("{planted} {}", "x".repeat(configuration::MAX_NAME_LEN));
            document.secrets.push(configuration::SecretReference {
                name: long.clone(),
                store: long.clone(),
                item: long,
            });
            document
                .profiles
                .insert(String::new(), PreferenceSet::default());
            document.default_profile = Nullable(Some((*planted).to_owned()));
            document
                .ceilings
                .grant_rights
                .0
                .replace(vec![(*planted).to_owned()]);
            let loaded = configuration::load(Some(configuration::contents(&document).as_bytes()));
            assert!(loaded.status.state.is_a_problem(), "{planted:?}");
            let mut configuration = EffectiveConfiguration::unread();
            configuration.status = loaded.status.clone();
            let exported = serde_json::to_string(&HostDoctorResult::new(Vec::new(), configuration))
                .expect("the result serialises");
            assert!(
                !exported.contains(planted),
                "{planted:?} reached an export through a validation message: {exported}"
            );
            assert!(
                !exported.contains(credential),
                "{credential:?} reached an export through a validation message: {exported}"
            );
        }
    }

    /// KR-REQ-26.44: a rejected value is named by its class rather than repeated.
    #[test]
    fn a_rejected_value_is_named_by_its_class_rather_than_repeated() {
        let mut document = ConfigurationDocument::default();
        document
            .ceilings
            .grant_rights
            .0
            .replace(vec!["sk-live-abc123".to_owned()]);
        let problems = configuration::validate(&document).expect_err("an invalid right");
        let listed = problems.join("; ");
        assert!(!listed.contains("sk-live-abc123"), "{listed}");
        assert!(listed.contains("[name withheld, 14 bytes]"), "{listed}");
    }

    /// KR-REQ-26.44: a derived desktop identity is not exported at all.
    #[test]
    fn a_derived_desktop_identity_is_not_exported() {
        let context = crate::desktop::DesktopContext {
            desktop_session_id: Nullable(
                crate::ids::DesktopSessionId::new("kr-someone-hunter2").ok(),
            ),
            kind: crate::desktop::DesktopSessionKind::None,
            platform_session: Nullable(Some("hunter2".to_owned())),
            login_generation: Nullable(None),
            generation_source: crate::desktop::DesktopGenerationSource::Unavailable,
            os_user: "someone".to_owned(),
            uid: Nullable(None),
            boot_identity: BootIdentity {
                source: crate::identity::BootIdentitySource::BootTime,
                value: crate::scalars::Bytes::new(Vec::new()),
            },
            graphic_access: false,
            remote: false,
            availability: crate::desktop::DesktopAvailability::Unknown,
            container: crate::desktop::ContainerEnvironment::Host,
            display_server: crate::desktop::DisplayServer::None,
            compositor: Nullable(Some("hunter2".to_owned())),
            worker_profile: WorkerProfile::HeadlessUser,
        };
        let exported = export::desktop_context(context);
        assert_eq!(
            exported
                .desktop_session_id
                .0
                .as_ref()
                .map(ToString::to_string),
            Some("[name withheld]".to_owned()),
            "the desktop is still there; what it is called is not exported"
        );
        assert_eq!(exported.os_user, "[name withheld, 7 bytes]");
        assert_eq!(
            exported.platform_session.0.as_deref(),
            Some("[name withheld, 7 bytes]")
        );
    }

    /// KR-REQ-26.13, KR-REQ-26.44: the report a host shows its owner names the paths; the one that
    /// leaves for somebody else to read names their class and their length.
    #[test]
    fn a_report_shown_to_its_owner_names_the_paths_and_an_export_does_not() {
        let mut effective = EffectiveConfiguration::unread();
        effective.document = "/home/someone/.config/kalareach/config.json".to_owned();
        effective.runtime_directory = "/run/user/1000/kalareach/ab12cd34".to_owned();
        effective.state_directory = "/home/someone/.local/state/kalareach/ab12cd34".to_owned();
        effective.locations = vec![ReportedLocation {
            what: "state_directory".to_owned(),
            documented: configuration::DOCUMENTED_STATE_ROOT.to_owned(),
        }];

        // The display form: this is the owner's own machine, and the answer is where their files
        // are.
        let shown = HostDoctorResult::new(Vec::new(), effective.clone());
        assert_eq!(shown.configuration.document, effective.document);
        assert_eq!(
            shown.configuration.state_directory,
            effective.state_directory
        );

        // The export form: the same reading, with every path this host composed from an account
        // name reduced to what it is made of. The rule this platform follows survives, because
        // this build wrote it.
        let bundle = SupportBundle::new(
            TimestampMs::new(0),
            Vec::new(),
            Vec::new(),
            shown,
            Vec::new(),
        );
        let exported = bundle.doctor.get();
        assert_eq!(exported.configuration.document, "[path withheld, 43 bytes]");
        assert_eq!(
            exported.configuration.state_directory,
            "[path withheld, 45 bytes]"
        );
        assert_eq!(
            exported.configuration.locations[0].documented,
            configuration::DOCUMENTED_STATE_ROOT
        );
        assert_eq!(
            bundle.configuration.get().runtime_directory,
            "[path withheld, 33 bytes]",
            "and the bundle's own copy of it says the same"
        );
        let written = serde_json::to_string(&bundle).expect("the bundle serialises");
        assert!(
            !written.contains("someone"),
            "no account name reaches an export: {written}"
        );
    }

    /// KR-REQ-26.44: a row's value and the class it is made of are decided together.
    #[test]
    fn a_reported_value_cannot_declare_itself_as_something_else() {
        let path = std::path::Path::new("/home/someone/kalareach");
        let row = EffectiveValue::new(
            "state_directory",
            "where this host keeps its own state",
            &export::Declared::path(path),
            configuration::ValueSource::Default,
            Nullable::null(),
            Nullable::null(),
            configuration::ValueEffect::NewSessionsOnly,
        );
        assert_eq!(row.value(), "/home/someone/kalareach");
        assert_eq!(row.class(), export::ContentClass::Path);

        let mut effective = EffectiveConfiguration::unread();
        effective.values = vec![
            row,
            EffectiveValue::new(
                "sleep_inhibition",
                "whether this host keeps itself awake",
                &export::Declared::term("mains_only"),
                configuration::ValueSource::HostConfiguration,
                Nullable::null(),
                Nullable::null(),
                configuration::ValueEffect::Immediately,
            ),
        ];
        let bundle = SupportBundle::new(
            TimestampMs::new(0),
            Vec::new(),
            Vec::new(),
            HostDoctorResult::new(Vec::new(), effective),
            Vec::new(),
        );
        let exported = &bundle.configuration.get().values;
        assert_eq!(exported[0].value(), "[path withheld, 23 bytes]");
        assert_eq!(
            exported[1].value(),
            "mains_only",
            "and a word of this build's own leaves as itself"
        );
    }

    /// KR-REQ-26.44: a bundle's record of a withheld value is the length that value had.
    ///
    /// Each value crosses the boundary once, so what a reader measures is the value rather than a
    /// placeholder standing in for one.
    #[test]
    fn a_bundle_measures_the_value_and_never_a_placeholder() {
        let secret = "/home/someone/kalareach";
        let mut configuration = EffectiveConfiguration::unread();
        configuration.state_directory = secret.to_owned();
        let bundle = SupportBundle::new(
            TimestampMs::new(0),
            Vec::new(),
            Vec::new(),
            HostDoctorResult::new(Vec::new(), configuration),
            vec![RedactedError::new("relay", secret)],
        );
        let measured = format!("[path withheld, {} bytes]", secret.len());
        assert_eq!(bundle.configuration.get().state_directory, measured);
        assert_eq!(
            bundle.errors[0].message(),
            &format!("[message withheld, {} bytes]", secret.len())
        );
    }

    /// KR-REQ-26.15: a session ceiling above what this host can record is refused, not clamped.
    #[test]
    fn a_session_ceiling_above_the_recordable_range_is_refused() {
        let loaded = configuration::load(None);
        let refused = configuration::edit(
            &loaded,
            &Change::SessionLimit(Some(configuration::MAX_SESSION_LIMIT + 1)),
        )
        .expect_err("a number the registry cannot hold");
        let refused = format!("{refused}");
        assert!(
            refused.contains(&configuration::MAX_SESSION_LIMIT.to_string()),
            "the bound is named: {refused}"
        );
        configuration::edit(
            &loaded,
            &Change::SessionLimit(Some(configuration::MAX_SESSION_LIMIT)),
        )
        .expect("the bound itself is recordable");
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
        let mut budgets = configuration::ConfiguredEnrolmentBudgets {
            cached_payload_bytes: Nullable::some(4 * 1024 * 1024 * 1024),
            ..configuration::ConfiguredEnrolmentBudgets::default()
        };
        let loaded = configuration::load(None);
        let refused = configuration::edit(&loaded, &Change::Enrolment(budgets))
            .expect_err("a larger mirror is an explicit setting");
        assert!(
            format!("{refused}").contains("full_offline_mirror"),
            "{refused}"
        );
        budgets.full_offline_mirror = Nullable::some(true);
        let applied = configuration::edit(&loaded, &Change::Enrolment(budgets))
            .expect("with the setting it is the owner's choice");
        assert_eq!(
            applied
                .document
                .ceilings
                .enrolment
                .as_ref()
                .map(configuration::ConfiguredEnrolmentBudgets::supplied),
            Some(vec!["cached_payload_bytes", "full_offline_mirror"]),
            "and the document holds the two budgets they wrote, not ten"
        );
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
                !entry.variable.to_ascii_lowercase().contains("secret"),
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
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("default_profile ([name withheld, 7 bytes])")),
            "the name is named by its class rather than repeated: {problems:?}"
        );
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
                vec![DoctorCheck::new(
                    "check",
                    "A check",
                    status,
                    export::Sentence::new().stated("detail"),
                    None,
                )],
                EffectiveConfiguration::unread(),
            );
            assert!(result.healthy, "{status:?}");
        }
        let result = HostDoctorResult::new(
            vec![DoctorCheck::new(
                "check",
                "A check",
                DoctorStatus::Failed,
                export::Sentence::new().stated("detail"),
                None,
            )],
            EffectiveConfiguration::unread(),
        );
        assert!(!result.healthy);
    }
}
