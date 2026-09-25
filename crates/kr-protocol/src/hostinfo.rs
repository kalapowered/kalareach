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
///
/// Read-only metadata: a field a newer host adds is explicitly optional, and a client whose schema
/// predates it ignores it rather than refusing the answer. Nothing here is signed or covered by a
/// mutation digest, which is what lets a field be dropped unread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(extend("x-kalareach-read-only-metadata" = true))]
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

impl export::ForExport for HostInfoResult {
    /// This host's metadata as somebody other than its owner at this machine reads it.
    ///
    /// Almost all of it is this build's own: the protocol, the identifiers it generated, its
    /// counters and its closed words. Three values are not. The name the operating system shows
    /// for a sleep assertion and the sentence it gives for withholding one leave as their class and
    /// their length, and the boot this host is in leaves as the facility it was read from with none
    /// of its value, exactly as they leave `environment.capabilities`. The build identity is named
    /// in full when it parses as one of this product's builds, as a support bundle names it, and
    /// as its class and its length when it does not.
    fn for_export(self) -> export::Exported<Self> {
        export::Exported::of(Self {
            build_id: export::build_id(&self.build_id),
            boot_identity: export::boot_identity(&self.boot_identity),
            power: export::sleep_inhibition(self.power),
            ..self
        })
    }
}

impl export::ForExport for EnvironmentListResult {
    /// The environments as somebody other than their owner at this machine reads them.
    ///
    /// What they are, what they run on and how busy they are, with no account and no directory:
    /// the operating-system user leaves as a name's class and length, the runtime and state
    /// directories as a path's, and the label, which names the account for the owner, is written
    /// again from the environment's own short prefix and its platform.
    fn for_export(self) -> export::Exported<Self> {
        export::Exported::of(Self {
            environments: self
                .environments
                .into_iter()
                .map(EnvironmentSummary::withheld_form)
                .collect(),
        })
    }
}

/// One environment this host serves.
///
/// Read-only metadata: a field a newer host adds is explicitly optional, and a client whose schema
/// predates it ignores it rather than refusing the answer. Nothing here is signed or covered by a
/// mutation digest, which is what lets a field be dropped unread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(extend("x-kalareach-read-only-metadata" = true))]
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

impl EnvironmentSummary {
    /// Returns this environment with every field held to what may leave this host.
    ///
    /// Each field goes on the terms the allowlist gives it. The label is the one that is not
    /// measured: a record of its length would say nothing a person could use, so it is written
    /// again from what may leave, `environment <prefix> on <platform>`, with the short prefix this
    /// environment's own directories are named by.
    fn withheld_form(self) -> Self {
        let os = export::carry(export::class("EnvironmentSummary", "os"), &self.os);
        Self {
            label: format!(
                "environment {} on {os}",
                configuration::short_prefix(self.environment_id)
            ),
            arch: export::carry(export::class("EnvironmentSummary", "arch"), &self.arch),
            os_user: export::carry(
                export::class("EnvironmentSummary", "os_user"),
                &self.os_user,
            ),
            runtime_directory: export::carry(
                export::class("EnvironmentSummary", "runtime_directory"),
                &self.runtime_directory,
            ),
            state_directory: export::carry(
                export::class("EnvironmentSummary", "state_directory"),
                &self.state_directory,
            ),
            os,
            ..self
        }
    }
}

/// The result of `environment.list`.
///
/// Read-only metadata: a field a newer host adds is explicitly optional, and a client whose schema
/// predates it ignores it rather than refusing the answer. Nothing here is signed or covered by a
/// mutation digest, which is what lets a field be dropped unread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(extend("x-kalareach-read-only-metadata" = true))]
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
    id: export::Stated,
    /// What it examines.
    title: export::Stated,
    /// What it found.
    pub status: DoctorStatus,
    /// A plain description of the finding, carrying nothing from outside this build.
    ///
    /// An [`export::Sentence`], whose only text is a literal in this source. A check's detail
    /// names paths, command lines and errors from libraries, and any of those can carry a token
    /// the person writing the check never thought about; what the sentence can hold of one is its
    /// class and its length. The type travels with the value, so a check read back out of a reply
    /// is measured on the way into a bundle rather than repeated.
    detail: export::Sentence,
    /// What the user should do, when the check did not pass. Written in this source.
    remedy: Nullable<export::Stated>,
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
            id: export::Stated::new(id),
            title: export::Stated::new(title),
            status,
            detail,
            remedy: Nullable(remedy.map(export::Stated::new)),
        }
    }

    /// The stable identifier this check is published under.
    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// What this check examines.
    #[must_use]
    pub fn title(&self) -> &str {
        self.title.as_str()
    }

    /// What it found.
    #[must_use]
    pub fn detail(&self) -> &str {
        self.detail.as_str()
    }

    /// What the person should do about it, when there is something to do.
    #[must_use]
    pub fn remedy(&self) -> Option<&str> {
        self.remedy.as_ref().map(export::Stated::as_str)
    }

    /// Returns the evidence lines `kr doctor --verbose` prints under this check.
    #[must_use]
    pub fn evidence(&self) -> Vec<String> {
        let mut lines = vec![self.detail().to_owned()];
        if let Some(remedy) = self.remedy() {
            lines.push(remedy.to_owned());
        }
        lines
    }

    /// Returns this check with every word of it held to where it came from.
    ///
    /// A check built here is unchanged: its identifier, title and remedy are literals in this
    /// source and its detail is a sentence composed of them. A check that arrived in a reply is
    /// measured, because nothing about the wire says its words were this build's.
    fn withheld_form(&self) -> Self {
        use export::Provenance as _;

        Self {
            id: self.id.exported(),
            title: self.title.exported(),
            status: self.status,
            detail: self.detail.exported(),
            remedy: export::exported_null(&self.remedy),
        }
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
    /// Every check and the configuration, each word of them held to where it came from.
    ///
    /// A check this host ran needs nothing done to it: its detail is an [`export::Sentence`] and
    /// its remedy is a literal in this source, so there was never anywhere in one to put text that
    /// arrived at runtime. A result that arrived in a reply carries the same fields with none of
    /// that behind them, and the difference is in the values rather than in the caller's memory:
    /// each of those fields knows whether this process composed it, and the ones that did not are
    /// measured here.
    fn for_export(self) -> export::Exported<Self> {
        export::Exported::of(Self {
            checks: self.checks.iter().map(DoctorCheck::withheld_form).collect(),
            healthy: self.healthy,
            configuration: self.configuration.withheld_form(),
        })
    }
}

/// One effective configuration value, with where it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectiveValue {
    /// The key, as the configuration document spells it.
    pub key: String,
    // This type's own, so `new` is the only way to write it. A public field would let a row built
    // through the constructor be given different prose afterwards, and the export carries this
    // field as the product's own words.
    /// What it decides.
    about: export::Stated,
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
    /// When it applies: immediately, only to sessions created afterwards, or at the next start.
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
            about: export::Stated::new(about),
            value: declared.value().to_owned(),
            class: declared.class(),
            source,
            origin,
            variable,
            effect,
        }
    }

    /// What this value decides.
    #[must_use]
    pub fn about(&self) -> &str {
        self.about.as_str()
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
    ///
    /// A sentence rather than a copy of the document: the numbers a document names and the rights
    /// this build recognises, composed here. A right the document invented is not one of them and
    /// leaves as its length.
    pub configured: Nullable<export::Sentence>,
    /// What is in force.
    pub value: export::Sentence,
    /// The rung of the precedence ladder it came from.
    pub source: configuration::ValueSource,
    /// The document's path, when the rung had one.
    pub origin: Nullable<String>,
    /// When it applies: immediately, only to sessions created afterwards, or at the next start.
    pub effect: configuration::ValueEffect,
    /// What narrowed the configured value, when something did. For the rights ceiling, which
    /// narrows grants rather than being narrowed, it names the rights the ceiling in force removes
    /// from every grant on this host.
    pub narrowed_by: Nullable<export::Sentence>,
    /// True when the configured value was more permissive and was refused.
    pub refused: bool,
}

impl CeilingValue {
    /// Returns this row with every word of it held to where it came from.
    fn withheld_form(&self) -> Self {
        use export::Provenance as _;

        Self {
            key: export::carry(export::class("CeilingValue", "key"), &self.key),
            configured: export::exported_null(&self.configured),
            value: self.value.exported(),
            source: self.source,
            // The origin is the document's own path, which a person chose and may have spelled
            // with something this boundary exists to keep out of an export.
            origin: export::carry_null(export::class("CeilingValue", "origin"), &self.origin),
            effect: self.effect,
            narrowed_by: export::exported_null(&self.narrowed_by),
            refused: self.refused,
        }
    }
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
    pub why: export::Stated,
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
    pub documented: export::Stated,
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
    pub precedence: Vec<export::Stated>,
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
    pub not_in_force: Nullable<export::Sentence>,
    /// What this host's workers still owe the authority fence a ceiling here raised.
    ///
    /// Null once every worker has acknowledged it. A revision that advanced is not a completed
    /// revocation: a worker that has not acknowledged its fence still holds work admitted under
    /// the ceiling that was withdrawn, and this says so for as long as that is true. It is not a
    /// failure - the values above are in force for everything admitted from now on.
    pub fence_outstanding: Nullable<export::Sentence>,
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
                detail: {
                    use export::Provenance as _;

                    self.status.detail.exported()
                },
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
                    about: {
                        use export::Provenance as _;

                        value.about.exported()
                    },
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
                .iter()
                .map(CeilingValue::withheld_form)
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
                .iter()
                .map(|entry| {
                    use export::Provenance as _;

                    OverrideReport {
                        variable: export::carry(
                            export::class("OverrideReport", "variable"),
                            &entry.variable,
                        ),
                        preference: export::carry(
                            export::class("OverrideReport", "preference"),
                            &entry.preference,
                        ),
                        position: entry.position,
                        why: entry.why.exported(),
                        set: entry.set,
                    }
                })
                .collect(),
            locations: self
                .locations
                .iter()
                .map(|location| {
                    use export::Provenance as _;

                    ReportedLocation {
                        what: export::carry(
                            export::class("ReportedLocation", "what"),
                            &location.what,
                        ),
                        documented: location.documented.exported(),
                    }
                })
                .collect(),
            precedence: export::exported_each(&self.precedence),
            not_in_force: export::exported_null(&self.not_in_force),
            fence_outstanding: export::exported_null(&self.fence_outstanding),
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
                detail: export::Sentence::new()
                    .stated("this report was built without reading a configuration document"),
            },
            runtime_directory: String::new(),
            state_directory: String::new(),
            locations: Vec::new(),
            precedence: configuration::PRECEDENCE
                .iter()
                .map(|source| export::Stated::new(source.describe()))
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
    pub component: export::Stated,
    /// Which version of it.
    ///
    /// A sentence: this build's own version string, a build identity this host generated, a
    /// protocol number, or the platform constants the compiler wrote in. A version a component
    /// reported for itself in a reply is measured rather than repeated.
    pub version: export::Sentence,
}

impl SoftwareComponent {
    /// Returns this row with every word of it held to where it came from.
    fn withheld_form(&self) -> Self {
        use export::Provenance as _;

        Self {
            component: self.component.exported(),
            version: self.version.exported(),
        }
    }
}

/// One error a support bundle carries, already redacted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RedactedError {
    /// What produced it.
    component: export::Stated,
    /// What it said, as its class and its length.
    ///
    /// A message from a library, the operating system or an upstream is the one thing this build
    /// did not write, so none of its text leaves. The component says which part of this host was
    /// talking, and the length says whether it had anything to say.
    ///
    /// What is stored is the record rather than the message, so the value is this build's own
    /// words about somebody else's. That is why it is a sentence: a row this host wrote keeps the
    /// measure it took, and a row that arrived in a bundle or a reply is measured in turn, because
    /// nothing on the wire says the sender took one.
    message: export::Sentence,
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
            component: export::Stated::new(component),
            message: export::Sentence::new().withheld(export::ContentClass::Message, message),
        }
    }

    /// Which part of this host was talking.
    #[must_use]
    pub fn component(&self) -> &str {
        self.component.as_str()
    }

    /// What it said, as its class and its length.
    #[must_use]
    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    /// Returns this row with every word of it held to where it came from.
    fn withheld_form(&self) -> Self {
        use export::Provenance as _;

        Self {
            component: self.component.exported(),
            message: self.message.exported(),
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
    pub includes: Vec<export::Sentence>,
    /// The entries the archive carries because of that choice.
    pub entries: Vec<export::Sentence>,
}

impl ContentExport {
    /// Returns this selection with every word of it held to where it came from.
    fn withheld_form(&self) -> Self {
        Self {
            includes: export::exported_each(&self.includes),
            entries: export::exported_each(&self.entries),
        }
    }
}

/// A support bundle, as somebody who opens one reads it.
///
/// Section 26 says what one shows, and the word that carries the weight is "redacted". A bundle is
/// written to be sent to somebody else, so every part of it that a person, a platform or a library
/// wrote is typed [`export::Exported`] and there is no way to put a display value in one of those
/// fields. Terminal content, prompts, attachment filenames and anything else content-bearing are
/// not here at all: they arrive only through [`ContentExport`], which exists only when the person
/// explicitly selected it.
///
/// This is the read half. A bundle parses into it - out of a file a person was sent, out of one
/// this host wrote earlier - and its members are public because a reader wants to look at them.
/// Parsing is also the reason it cannot be written: the half that a writer takes is
/// [`ComposedBundle`], which this type does not convert into.
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

/// A support bundle this host composed, as a writer takes one.
///
/// The write half of [`SupportBundle`], and the difference between the two is what makes the
/// redaction hold rather than depend on a caller. Its members are private, it does not
/// deserialise, and [`ComposedBundle::new`] is the only way to make one - which is the one place
/// every member goes through the export allowlist. So a bundle that arrived, whether parsed whole
/// out of a file or assembled from members parsed out of one, has nowhere to go: a writer takes
/// this type, and reading never produces it.
///
/// It serialises exactly as [`SupportBundle`] does, because the two are one document from a
/// reader's side. The schema and the generated types describe the read half.
///
/// ```compile_fail
/// use kr_protocol::hostinfo::ComposedBundle;
/// // A bundle that arrived is not one this host composed, whatever its text says.
/// let arrived: ComposedBundle = serde_json::from_str("{}").expect("a bundle");
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComposedBundle {
    /// When it was made.
    generated_at_ms: TimestampMs,
    /// The software this host is running.
    software: Vec<SoftwareComponent>,
    /// What this host can currently do, as the shared section 11 evidence.
    capabilities: Vec<export::Exported<crate::desktop::CapabilityRecord>>,
    /// What the diagnostics found.
    doctor: export::Exported<HostDoctorResult>,
    /// What this host's configuration resolves to.
    configuration: export::Exported<EffectiveConfiguration>,
    /// The errors this host has to report, redacted.
    errors: Vec<RedactedError>,
    /// The content-bearing export, when the person explicitly selected one.
    content: Nullable<ContentExport>,
}

impl ComposedBundle {
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
            software: software
                .iter()
                .map(SoftwareComponent::withheld_form)
                .collect(),
            capabilities: capabilities
                .into_iter()
                .map(export::ForExport::for_export)
                .collect(),
            doctor: doctor.for_export(),
            configuration,
            errors: errors.iter().map(RedactedError::withheld_form).collect(),
            content: Nullable::null(),
        }
    }

    /// Adds the content-bearing export the person explicitly selected.
    #[must_use]
    pub fn with_content(mut self, content: ContentExport) -> Self {
        self.content = Nullable::some(content.withheld_form());
        self
    }

    /// The software versions it carries.
    #[must_use]
    pub fn software(&self) -> &[SoftwareComponent] {
        &self.software
    }

    /// The capability evidence it carries.
    #[must_use]
    pub fn capabilities(&self) -> &[export::Exported<crate::desktop::CapabilityRecord>] {
        &self.capabilities
    }

    /// What the diagnostics found.
    #[must_use]
    pub const fn doctor(&self) -> &export::Exported<HostDoctorResult> {
        &self.doctor
    }

    /// What this host's configuration resolves to.
    #[must_use]
    pub const fn configuration(&self) -> &export::Exported<EffectiveConfiguration> {
        &self.configuration
    }

    /// The errors it carries, redacted.
    #[must_use]
    pub fn errors(&self) -> &[RedactedError] {
        &self.errors
    }

    /// The content-bearing export, when the person explicitly selected one.
    #[must_use]
    pub const fn content(&self) -> &Nullable<ContentExport> {
        &self.content
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
///   "secrets": [{ "name": "relay", "store": "login_keychain", "item": "kalareach/relay" }],
///   "network": {
///     "enabled": true,
///     "relay_urls": ["https://relay.example.com"],
///     "pkarr_publisher_url": "https://discovery.example.com/pkarr",
///     "pkarr_resolver_url": "https://discovery.example.com/pkarr",
///     "dns_origin": "discovery.example.com"
///   },
///   "voice": { "broker_origin": "https://voice.example.com" }
/// }
/// ```
///
/// The `network` and `voice` sections are the only place a network selection or the voice
/// broker's origin is chosen, and the daemon reads them when it starts ([`NetworkSelection`],
/// [`VoiceSelection`]). No environment variable reaches either.
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

    use super::export::Sentence;
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
    pub fn read_file(path: &std::path::Path, limit: u64) -> Result<Option<Vec<u8>>, Sentence> {
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
                    return Err(
                        Sentence::new().stated("configuration file must not be a symbolic link")
                    );
                }
                Err(error) => {
                    return Err(Sentence::new().withheld(
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
                    return Err(Sentence::new()
                        .withheld(super::export::ContentClass::Message, &error.to_string()));
                }
            }
        };
        #[cfg(not(any(unix, windows)))]
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Sentence::new()
                    .withheld(super::export::ContentClass::Message, &error.to_string()));
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = file.metadata().map_err(|error| {
                Sentence::new().withheld(super::export::ContentClass::Message, &error.to_string())
            })?;
            if metadata.uid() != rustix::process::getuid().as_raw() {
                return Err(Sentence::new().stated("configuration file is not owned by this user"));
            }
            if metadata.mode() & 0o077 != 0 {
                return Err(Sentence::new()
                    .stated("configuration file has permissions wider than owner-only"));
            }
            if !metadata.is_file() {
                return Err(Sentence::new().stated("configuration file must be a regular file"));
            }
            if metadata.len() > limit {
                return Err(Sentence::new()
                    .stated("this file is larger than the ")
                    .number(limit)
                    .stated(" byte bound"));
            }
        }
        #[cfg(not(unix))]
        {
            let metadata = file.metadata().map_err(|error| {
                Sentence::new().withheld(super::export::ContentClass::Message, &error.to_string())
            })?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt as _;

                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(Sentence::new()
                        .stated("configuration file must not be a link or a junction"));
                }
            }
            if !metadata.is_file() {
                return Err(Sentence::new().stated("configuration file must be a regular file"));
            }
            if metadata.len() > limit {
                return Err(Sentence::new()
                    .stated("this file is larger than the ")
                    .number(limit)
                    .stated(" byte bound"));
            }
        }
        let mut bytes = Vec::new();
        (&file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                Sentence::new().withheld(super::export::ContentClass::Message, &error.to_string())
            })?;
        if bytes.len() as u64 > limit {
            return Err(Sentence::new()
                .stated("this file is larger than the ")
                .number(limit)
                .stated(" byte bound"));
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
        /// Whether this host joins the network, and every service it selects there.
        ///
        /// Read when the daemon starts, so a change applies at the next start. No environment
        /// variable reaches any of it.
        pub network: NetworkSelection,
        /// The managed voice broker this host names to its paired devices.
        ///
        /// Read when the daemon starts, so a change applies at the next start. No environment
        /// variable reaches it.
        pub voice: VoiceSelection,
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
                network: NetworkSelection::default(),
                voice: VoiceSelection::default(),
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

    /// Whether this host joins the network, and each service it selects there.
    ///
    /// Section 17 makes every service its own choice: the relay map, the Pkarr publisher, the Pkarr
    /// resolver and the DNS origin are separate selections, and a service this section does not
    /// name is a service this host does not use. There are no defaults to inherit, from a public
    /// service or from the environment the daemon started in: a relay map, a discovery server, a
    /// DNS origin and a trust anchor are provider origins and a trust decision, which section 26
    /// keeps out of reach of any inherited variable.
    ///
    /// Each field is absent unless this document chooses it, so a report can say which of them a
    /// person wrote rather than inferring it from the value. The daemon reads the section when it
    /// starts, which is when its endpoint is built, so a change applies at the next start.
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    pub struct NetworkSelection {
        /// Whether this host joins the network at all. Without it the daemon serves its local
        /// endpoint alone, which is a complete deployment rather than a degraded one.
        pub enabled: Nullable<bool>,
        /// The socket address the endpoint binds to, such as `0.0.0.0:4433`. Absent binds an
        /// unspecified address and a free port.
        pub bind_address: Nullable<String>,
        /// The relay map, as absolute `https` or `http` relay URLs. Absent or empty selects no
        /// relay.
        pub relay_urls: Nullable<Vec<String>>,
        /// The Pkarr server this host publishes its signed record to.
        pub pkarr_publisher_url: Nullable<String>,
        /// The Pkarr server this host resolves peers from.
        pub pkarr_resolver_url: Nullable<String>,
        /// The DNS origin this host resolves peers from: a dotted domain name, with no scheme or
        /// path.
        pub dns_origin: Nullable<String>,
        /// DER certificate files, by absolute path, trusted for a relay's HTTPS beside the public
        /// anchors. A self-hosted relay with a private authority names it here; the public
        /// anchors stay in force, so this adds trust rather than replacing it.
        pub relay_trust_anchors: Nullable<Vec<String>>,
        /// Every packet goes through the relay, and no direct path is used.
        pub relay_only: Nullable<bool>,
        /// Discovery of peers on the local network.
        pub local_discovery: Nullable<bool>,
        /// The public Mainline DHT for discovery. It publishes to a public network and carries no
        /// KalaReach service guarantee, which is why it is never on unless chosen.
        pub mainline_dht: Nullable<bool>,
        /// The HTTP proxy the endpoint reaches its relays and discovery servers through, as an
        /// absolute `http` or `https` origin such as `http://proxy.example.com:3128`. It is this
        /// machine's own choice: no invitation or host bundle carries it. It names no user and no
        /// password, because a proxy that needs credentials is not supported.
        pub proxy_url: Nullable<String>,
    }

    impl NetworkSelection {
        /// Whether this host joins the network.
        #[must_use]
        pub fn joins(&self) -> bool {
            self.enabled.0.unwrap_or(false)
        }

        /// The socket address the endpoint binds to, when one is chosen.
        #[must_use]
        pub fn bind_address(&self) -> Option<&str> {
            self.bind_address.as_ref().map(String::as_str)
        }

        /// The selected relay URLs.
        #[must_use]
        pub fn relay_urls(&self) -> &[String] {
            self.relay_urls.as_ref().map_or(&[], Vec::as_slice)
        }

        /// The Pkarr server this host publishes to, when one is selected.
        #[must_use]
        pub fn pkarr_publisher_url(&self) -> Option<&str> {
            self.pkarr_publisher_url.as_ref().map(String::as_str)
        }

        /// The Pkarr server this host resolves from, when one is selected.
        #[must_use]
        pub fn pkarr_resolver_url(&self) -> Option<&str> {
            self.pkarr_resolver_url.as_ref().map(String::as_str)
        }

        /// The DNS origin this host resolves from, when one is selected.
        #[must_use]
        pub fn dns_origin(&self) -> Option<&str> {
            self.dns_origin.as_ref().map(String::as_str)
        }

        /// The certificate files trusted for a relay's HTTPS beside the public anchors.
        #[must_use]
        pub fn relay_trust_anchors(&self) -> &[String] {
            self.relay_trust_anchors.as_ref().map_or(&[], Vec::as_slice)
        }

        /// Whether every packet goes through the relay.
        #[must_use]
        pub fn relay_only(&self) -> bool {
            self.relay_only.0.unwrap_or(false)
        }

        /// Whether local network discovery is selected.
        #[must_use]
        pub fn local_discovery(&self) -> bool {
            self.local_discovery.0.unwrap_or(false)
        }

        /// Whether the public Mainline DHT is selected.
        #[must_use]
        pub fn mainline_dht(&self) -> bool {
            self.mainline_dht.0.unwrap_or(false)
        }

        /// The HTTP proxy the endpoint reaches its relays and discovery servers through, when one
        /// is selected.
        #[must_use]
        pub fn proxy_url(&self) -> Option<&str> {
            self.proxy_url.as_ref().map(String::as_str)
        }
    }

    /// The managed voice broker this host names to its paired devices.
    ///
    /// A provider origin, so it is this document's to choose and no inherited variable's. The
    /// daemon reads it when it starts its voice service, so a change applies at the next start.
    /// Absent means this host brokers no managed call, which is a complete host: a person's own
    /// provider and the agent already running in a session both still work.
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    pub struct VoiceSelection {
        /// The broker's origin: an absolute `https` or `http` address in lower case, with no path,
        /// no trailing slash and no port its scheme already implies.
        pub broker_origin: Nullable<String>,
    }

    impl VoiceSelection {
        /// The broker's origin, when one is chosen.
        #[must_use]
        pub fn broker_origin(&self) -> Option<&str> {
            self.broker_origin.as_ref().map(String::as_str)
        }
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
        ///
        /// Composed here out of this build's own words, the numbers a document declared and the
        /// measure of every message a parser produced. A status read back out of a reply or a
        /// bundle is not this build's sentence however it reads, and it leaves as its length.
        pub detail: super::export::Sentence,
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
                    detail: Sentence::new()
                        .stated("no configuration document; every value is the product default"),
                },
            };
        };
        let value: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(error) => {
                // The parser's own sentence names the byte it stopped at and repeats what it
                // found there, which is the document. What leaves is that it did not parse.
                return invalid(vec![
                    Sentence::new()
                        .stated("this file is not JSON: ")
                        .withheld(super::export::ContentClass::Message, &error.to_string()),
                ]);
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
                    detail: Sentence::new()
                        .stated("this document declares version ")
                        .number(declared)
                        .stated(" and this build knows version ")
                        .number(VERSION)
                        .stated("; it is left alone and every value is the product default"),
                },
            };
        }
        let document: ConfigurationDocument = match serde_json::from_value(value) {
            Ok(document) => document,
            Err(error) => {
                return invalid(vec![
                    Sentence::new()
                        .stated("this document is not valid against the schema: ")
                        .withheld(super::export::ContentClass::Message, &error.to_string()),
                ]);
            }
        };
        if let Err(problems) = validate(&document) {
            return invalid(problems);
        }
        Loaded {
            document: Some(document),
            status: DocumentStatus {
                state: DocumentState::Loaded,
                detail: Sentence::new().stated("version ").number(VERSION),
            },
        }
    }

    /// The load a document this host could not read produces.
    ///
    /// `detail` is a sentence rather than text, because the reason a file could not be read is the
    /// operating system's message about a path a person chose, and both halves of that belong to
    /// somebody else. The caller composes it out of this build's words and the measure of theirs.
    #[must_use]
    pub fn unreadable(detail: Sentence) -> Loaded {
        Loaded {
            document: None,
            status: DocumentStatus {
                state: DocumentState::Unreadable,
                detail: detail
                    .stated("; this document is left alone and every value is the product default"),
            },
        }
    }

    /// The load an invalid document produces.
    fn invalid(problems: Vec<Sentence>) -> Loaded {
        let mut detail = Sentence::new();
        for (index, problem) in problems.iter().enumerate() {
            if index > 0 {
                detail = detail.stated("; ");
            }
            detail = detail.sentence(problem);
        }
        Loaded {
            document: None,
            status: DocumentStatus {
                state: DocumentState::Invalid,
                detail: detail
                    .stated("; this document is left alone and every value is the product default"),
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
    pub fn validate(document: &ConfigurationDocument) -> Result<(), Vec<Sentence>> {
        use super::export::ContentClass::Name;

        let mut problems = Vec::new();
        if document.version != VERSION {
            problems.push(
                Sentence::new()
                    .stated("version ")
                    .number(document.version)
                    .stated(" is not the version this build writes (")
                    .number(VERSION)
                    .stated(")"),
            );
        }
        if document.revision > MAX_REVISION {
            problems.push(
                Sentence::new()
                    .stated("revision ")
                    .number(document.revision)
                    .stated(" is above the ")
                    .number(MAX_REVISION)
                    .stated(" this host can record"),
            );
        }
        if document.profiles.len() > MAX_PROFILES {
            problems.push(
                Sentence::new()
                    .number(document.profiles.len() as u64)
                    .stated(" profiles is more than the ")
                    .number(MAX_PROFILES as u64)
                    .stated(" this schema allows"),
            );
        }
        // A rejected value is named by its class and its length rather than repeated. A problem
        // list is an error message, and an error message travels into a diagnostic, a support
        // bundle and a terminal: a document that spelled a credential into a name it should not
        // have must not have it copied out again on the way to being refused.
        for name in document.profiles.keys() {
            if name.is_empty() || name.len() > MAX_NAME_LEN {
                problems.push(
                    Sentence::new()
                        .stated("a profile name (")
                        .withheld(Name, name)
                        .stated(") must be between 1 and ")
                        .number(MAX_NAME_LEN as u64)
                        .stated(" characters"),
                );
            }
        }
        if let Some(selected) = document.default_profile.as_ref()
            && !document.profiles.contains_key(selected)
        {
            problems.push(
                Sentence::new()
                    .stated("default_profile (")
                    .withheld(Name, selected)
                    .stated(") names no profile in this document"),
            );
        }
        if let Some(limit) = document.ceilings.session_limit.as_ref() {
            if *limit == 0 {
                problems
                    .push(Sentence::new().stated("session_limit 0 would admit no session at all"));
            } else if *limit > MAX_SESSION_LIMIT {
                // Refused rather than recorded and then quietly clamped. A number the registry
                // cannot hold would be written down, reported back as written, and enforced one
                // lower, and the report and the admission limit would disagree for ever.
                problems.push(
                    Sentence::new()
                        .stated("session_limit ")
                        .number(*limit)
                        .stated(" is above the ")
                        .number(MAX_SESSION_LIMIT)
                        .stated(" this host can record"),
                );
            }
        }
        if let Some(rights) = document.ceilings.grant_rights.as_ref() {
            for right in rights {
                if crate::rights::ActionRight::from_wire(right).is_none() {
                    problems.push(
                        Sentence::new()
                            .stated("a configured right (")
                            .withheld(Name, right)
                            .stated(") is not an action right"),
                    );
                }
            }
        }
        if let Some(budgets) = document.ceilings.enrolment.0.as_ref() {
            // Only the budgets this document actually names. One left out is the schema's own
            // number, which validated when this build chose it.
            for (field, value) in budgets.written() {
                if value == 0 {
                    problems.push(
                        Sentence::new()
                            .stated("an enrolment budget of zero for ")
                            .term(field)
                            .stated(" would enrol no repository"),
                    );
                }
            }
            let resolved = budgets.resolve();
            if resolved.cached_payload_bytes > DEFAULT_CACHED_PAYLOAD_BYTES
                && !resolved.full_offline_mirror
            {
                problems.push(
                    Sentence::new()
                        .stated("a cached payload budget above ")
                        .number(DEFAULT_CACHED_PAYLOAD_BYTES)
                        .stated(
                            " bytes is a full mirror and needs full_offline_mirror set explicitly",
                        ),
                );
            }
        }
        if document.secrets.len() > MAX_SECRETS {
            problems.push(
                Sentence::new()
                    .number(document.secrets.len() as u64)
                    .stated(" secret references is more than the ")
                    .number(MAX_SECRETS as u64)
                    .stated(" this schema allows"),
            );
        }
        for reference in &document.secrets {
            for (field, value) in [
                ("name", &reference.name),
                ("store", &reference.store),
                ("item", &reference.item),
            ] {
                if value.is_empty() || value.len() > MAX_NAME_LEN {
                    problems.push(
                        Sentence::new()
                            .stated("a secret reference's ")
                            .stated(field)
                            .stated(" (")
                            .withheld(Name, value)
                            .stated(") must be between 1 and ")
                            .number(MAX_NAME_LEN as u64)
                            .stated(" characters"),
                    );
                }
            }
        }
        problems.extend(network_problems(&document.network));
        if let Some(origin) = document.voice.broker_origin()
            && !is_broker_origin(origin)
        {
            problems.push(
                Sentence::new()
                    .stated("voice.broker_origin (")
                    .withheld(super::export::ContentClass::Location, origin)
                    .stated(
                        ") is not an https or http origin with a lower-case host or a canonical \
                         address, no port its scheme implies, no path and no trailing slash",
                    ),
            );
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }

    /// What a relay or discovery URL is refused with.
    const NOT_A_SERVICE_URL: &str = "is not an https or http URL with a lower-case host or a \
         canonical address, no port its scheme implies, no user information, a path of letters, \
         digits and - . _ ~ / only, and at most 253 characters as an invitation carries it";

    /// What a proxy that is not named by its origin is refused with.
    const NOT_A_PROXY_ORIGIN: &str = "is not an https or http origin with a lower-case host or a \
         canonical address, no port its scheme implies, no path and no trailing slash, in at most \
         253 characters";

    /// What a proxy URL that names a user or a password is refused with.
    const PROXY_CREDENTIALS: &str =
        "names a user or a password, and a proxy that needs credentials is not supported";

    /// Returns what is wrong with a network section, value by value.
    ///
    /// Each value is named by its key and its class, never repeated: a relay URL can carry a
    /// credential in its user part as easily as any other address.
    fn network_problems(network: &NetworkSelection) -> Vec<Sentence> {
        use super::export::ContentClass::{Location, Path};

        let mut problems = Vec::new();
        if let Some(bind) = network.bind_address()
            && bind.parse::<std::net::SocketAddr>().is_err()
        {
            problems.push(
                Sentence::new()
                    .stated("network.bind_address (")
                    .withheld(Location, bind)
                    .stated(") is not a socket address such as 0.0.0.0:4433"),
            );
        }
        for (key, values) in [
            ("network.relay_urls", network.relay_urls()),
            ("network.relay_trust_anchors", network.relay_trust_anchors()),
        ] {
            if values.len() > MAX_NETWORK_ENTRIES {
                problems.push(
                    Sentence::new()
                        .stated(key)
                        .stated(" names ")
                        .number(values.len() as u64)
                        .stated(", and an invitation carries at most ")
                        .number(MAX_NETWORK_ENTRIES as u64),
                );
            }
        }
        for relay in network.relay_urls() {
            if !is_service_url(relay) {
                problems.push(
                    Sentence::new()
                        .stated("a relay in network.relay_urls (")
                        .withheld(Location, relay)
                        .stated(") ")
                        .stated(NOT_A_SERVICE_URL),
                );
            }
        }
        for (key, value) in [
            (
                "network.pkarr_publisher_url (",
                network.pkarr_publisher_url(),
            ),
            ("network.pkarr_resolver_url (", network.pkarr_resolver_url()),
        ] {
            if let Some(value) = value
                && !is_service_url(value)
            {
                problems.push(
                    Sentence::new()
                        .stated(key)
                        .withheld(Location, value)
                        .stated(") ")
                        .stated(NOT_A_SERVICE_URL),
                );
            }
        }
        if let Some(origin) = network.dns_origin()
            && !is_dns_origin(origin)
        {
            problems.push(
                Sentence::new()
                    .stated("network.dns_origin (")
                    .withheld(Location, origin)
                    .stated(") is not a dotted domain name with no scheme, port or path"),
            );
        }
        for anchor in network.relay_trust_anchors() {
            if !is_anchor_path(anchor) {
                problems.push(
                    Sentence::new()
                        .stated("a certificate in network.relay_trust_anchors (")
                        .withheld(Path, anchor)
                        .stated(") is not named by an absolute path"),
                );
            }
        }
        // A selection the transport would build and nothing could use: no direct path and no
        // relay leaves this host unreachable by every device it has paired.
        if network.relay_only() && network.relay_urls().is_empty() {
            problems.push(Sentence::new().stated(
                "network.relay_only removes every direct path, and network.relay_urls selects no \
                 relay to use instead",
            ));
        }
        // A credential is refused as what it is, whatever else is wrong with the address, so the
        // owner learns why rather than meeting a rule about spelling. It is never used with the
        // credential dropped either: that would send this host's traffic to a proxy that turns
        // it away.
        if let Some(proxy) = network.proxy_url() {
            let refusal = if carries_user_information(proxy) {
                Some(PROXY_CREDENTIALS)
            } else {
                (!is_proxy_origin(proxy)).then_some(NOT_A_PROXY_ORIGIN)
            };
            if let Some(refusal) = refusal {
                problems.push(
                    Sentence::new()
                        .stated("network.proxy_url (")
                        .withheld(Location, proxy)
                        .stated(") ")
                        .stated(refusal),
                );
            }
        }
        problems
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
        NotOurs(Sentence),
        /// The edited document does not validate.
        #[error("{}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
        Invalid(Vec<Sentence>),
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
            return Err(EditRefused::Invalid(vec![
                Sentence::new()
                    .stated("this document is already at revision ")
                    .number(based_on)
                    .stated(", which is the highest this schema counts to"),
            ]));
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
            return Err(EditRefused::Invalid(vec![
                Sentence::new()
                    .stated("this document would be ")
                    .number(text.len() as u64)
                    .stated(" bytes, and this host reads at most ")
                    .number(MAX_LEN),
            ]));
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
        Err(EditRefused::NotOurs(
            Sentence::new()
                .stated("this document was ")
                .term(edited.based_on_state.as_str())
                .stated(" at revision ")
                .number(edited.based_on)
                .stated(" when the edit to revision ")
                .number(edited.revision)
                .stated(" was prepared and is now ")
                .term(current.status.state.as_str())
                .stated(" at revision ")
                .number(current.revision())
                .stated("; nothing was written"),
        ))
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

    /// When a new value takes effect: at once, only for sessions created afterwards, or when the
    /// host next starts.
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
        /// The running host keeps what it started with; the new value applies when it next
        /// starts. A network endpoint and the services it selects are built once, at startup.
        NextStart,
    }

    impl ValueEffect {
        /// Returns the stable wire string.
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Immediately => "immediately",
                Self::NewSessionsOnly => "new_sessions_only",
                Self::NextStart => "next_start",
            }
        }

        /// Returns when it applies, in the words `kr doctor` prints after "applies".
        #[must_use]
        pub const fn describe(self) -> &'static str {
            match self {
                Self::Immediately => "immediately",
                Self::NewSessionsOnly => "to new sessions only",
                Self::NextStart => "at the next start",
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

    /// One selection this host reads when it starts, rather than a preference it resolves.
    ///
    /// A selection has two rungs: this document, and the product default of selecting nothing.
    /// No request, profile or environment variable reaches one, which is section 26's rule for a
    /// provider origin and a trust decision, and it is why these are not [`Preference`]s: an
    /// [`ALLOWLIST`] entry has to name a preference, so none can name one of these.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Selection {
        /// The key, as `kr doctor` prints it: the section, then the field.
        pub key: &'static str,
        /// What it selects, for the person reading the report.
        pub about: &'static str,
    }

    impl Selection {
        /// When a new value takes effect. The endpoint and the voice service are built once, when
        /// the daemon starts.
        pub const EFFECT: ValueEffect = ValueEffect::NextStart;
    }

    /// Whether this host joins the network.
    pub const NETWORK_ENABLED: Selection = Selection {
        key: "network.enabled",
        about: "whether this host joins the network at all",
    };

    /// The address the network endpoint binds to.
    pub const NETWORK_BIND_ADDRESS: Selection = Selection {
        key: "network.bind_address",
        about: "the socket address the network endpoint binds to; none binds an unspecified \
                address and a free port",
    };

    /// The relay map.
    pub const NETWORK_RELAY_URLS: Selection = Selection {
        key: "network.relay_urls",
        about: "the relay map, which is a provider origin",
    };

    /// The Pkarr server this host publishes to.
    pub const NETWORK_PKARR_PUBLISHER_URL: Selection = Selection {
        key: "network.pkarr_publisher_url",
        about: "the discovery server this host publishes its signed record to",
    };

    /// The Pkarr server this host resolves from.
    pub const NETWORK_PKARR_RESOLVER_URL: Selection = Selection {
        key: "network.pkarr_resolver_url",
        about: "the discovery server this host resolves peers from",
    };

    /// The DNS origin this host resolves from.
    pub const NETWORK_DNS_ORIGIN: Selection = Selection {
        key: "network.dns_origin",
        about: "the DNS origin this host resolves peers from",
    };

    /// The extra trust anchors for a relay's HTTPS.
    pub const NETWORK_RELAY_TRUST_ANCHORS: Selection = Selection {
        key: "network.relay_trust_anchors",
        about: "certificate files trusted for a relay's HTTPS beside the public anchors",
    };

    /// Whether every packet goes through the relay.
    pub const NETWORK_RELAY_ONLY: Selection = Selection {
        key: "network.relay_only",
        about: "whether every packet goes through the relay, with no direct path",
    };

    /// Whether this host discovers peers on the local network.
    pub const NETWORK_LOCAL_DISCOVERY: Selection = Selection {
        key: "network.local_discovery",
        about: "whether this host discovers peers on the local network",
    };

    /// Whether this host uses the public Mainline DHT.
    pub const NETWORK_MAINLINE_DHT: Selection = Selection {
        key: "network.mainline_dht",
        about: "whether this host uses the public Mainline DHT for discovery",
    };

    /// The HTTP proxy the endpoint reaches its relays and discovery servers through.
    pub const NETWORK_PROXY_URL: Selection = Selection {
        key: "network.proxy_url",
        about: "the HTTP proxy the network endpoint reaches its relays and discovery servers \
                through",
    };

    /// The managed voice broker this host names to its devices.
    pub const VOICE_BROKER_ORIGIN: Selection = Selection {
        key: "voice.broker_origin",
        about: "the managed voice broker this host names to its paired devices",
    };

    /// Every selection this host reads when it starts, in the order `kr doctor` prints them.
    pub const SELECTIONS: [Selection; 12] = [
        NETWORK_ENABLED,
        NETWORK_BIND_ADDRESS,
        NETWORK_RELAY_URLS,
        NETWORK_PKARR_PUBLISHER_URL,
        NETWORK_PKARR_RESOLVER_URL,
        NETWORK_DNS_ORIGIN,
        NETWORK_RELAY_TRUST_ANCHORS,
        NETWORK_RELAY_ONLY,
        NETWORK_LOCAL_DISCOVERY,
        NETWORK_MAINLINE_DHT,
        NETWORK_PROXY_URL,
        VOICE_BROKER_ORIGIN,
    ];

    /// The words a selection's value is reported in when it is not a location or a path: the two
    /// a switch takes, and the one that says nothing is selected.
    pub const SELECTION_WORDS: [&str; 3] = ["true", "false", "none"];

    /// The most relay URLs, and the most trust anchors, one document may name.
    ///
    /// The pairing bound: every invitation this host issues carries its relay map, and an
    /// invitation carries at most this many.
    pub const MAX_NETWORK_ENTRIES: usize = crate::pairing::MAX_NETWORK_HINTS;

    /// The longest trust-anchor path this schema records.
    pub const MAX_PATH_LEN: usize = 4096;

    /// The longest a relay URL, a discovery URL or origin, or a broker origin may be, as an
    /// invitation carries it: a network hint is at most 253 bytes of printable ASCII.
    pub const MAX_HINT_LEN: usize = 253;

    /// Whether `value` fits a network hint: 1 to [`MAX_HINT_LEN`] bytes of printable ASCII and
    /// no spaces.
    ///
    /// The form an invitation carries a relay URL or a discovery origin in, so a document that
    /// validates is one whose selections this host can hand to a device.
    fn is_network_hint(value: &str) -> bool {
        crate::pairing::NetworkHint::new(value).is_ok()
    }

    /// Splits an `https` or `http` address into its authority, its path and the port its scheme
    /// implies.
    fn service_address(value: &str) -> Option<(&str, &str, u16)> {
        let (rest, implied) = if let Some(rest) = value.strip_prefix("https://") {
            (rest, crate::pairing::HTTPS_DEFAULT_PORT)
        } else {
            (
                value.strip_prefix("http://")?,
                crate::pairing::HTTP_DEFAULT_PORT,
            )
        };
        let (authority, path) = rest.find('/').map_or((rest, ""), |at| rest.split_at(at));
        Some((authority, path, implied))
    }

    /// Whether an authority is one address spelled one way.
    ///
    /// The protocol's own rule for every origin it compares - lower-case names, canonical address
    /// literals, no port the scheme implies, no user information - with one refusal beside it: a
    /// name in its A-label form. A URL parser decodes that punycode and may refuse it, and this
    /// crate cannot decode it the same way, so a document naming one could validate and then be
    /// refused when the daemon starts.
    fn is_canonical_authority(authority: &str, implied: u16) -> bool {
        crate::pairing::validate_authority(authority, implied).is_ok()
            && crate::pairing::split_authority(authority).is_ok_and(|(host, _, bracketed)| {
                bracketed || !host.split('.').any(|label| label.starts_with("xn--"))
            })
    }

    /// Whether `value` is a relay or discovery URL the transport reads exactly as written.
    ///
    /// An `https` or `http` scheme, a canonical authority, and a path of plain characters with no
    /// `.` or `..` segment, so the URL parser the endpoint uses neither escapes nor resolves any
    /// of it. Its length is measured as the transport writes it, with the `/` a URL with no path
    /// gains, because that is the form an invitation carries.
    fn is_service_url(value: &str) -> bool {
        let Some((authority, path, implied)) = service_address(value) else {
            return false;
        };
        let written = value.len() + usize::from(path.is_empty());
        written <= MAX_HINT_LEN
            && is_canonical_authority(authority, implied)
            && path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte))
            && !path
                .split('/')
                .any(|segment| segment == "." || segment == "..")
    }

    /// Whether `value` is a DNS origin: a dotted domain name with no scheme, port or path.
    ///
    /// The transport's own rule, so a document that validates names an origin the endpoint
    /// accepts.
    fn is_dns_origin(value: &str) -> bool {
        is_network_hint(value)
            && !value.contains(['/', ':', '@', '?', '#', ' '])
            && !value.split('.').any(str::is_empty)
    }

    /// Whether `value` is an origin a managed broker is addressed at: an `https` or `http` scheme
    /// and a canonical authority, with no path and no trailing slash.
    ///
    /// The broker compares origins by their spelling, so a second spelling of one address would
    /// be a second service to it, and it reads a host made of the characters a number is written
    /// in as an address. Such a host is refused here unless it is the canonical spelling of an
    /// IPv4 address, which the authority rule has already required of an all-digit one.
    fn is_broker_origin(value: &str) -> bool {
        let Some((authority, path, implied)) = service_address(value) else {
            return false;
        };
        value.len() <= MAX_HINT_LEN
            && path.is_empty()
            && is_canonical_authority(authority, implied)
            && crate::pairing::split_authority(authority).is_ok_and(|(host, _, bracketed)| {
                bracketed
                    || !(host.contains(|character: char| character.is_ascii_digit())
                        && host.contains(|character: char| matches!(character, 'a'..='f' | 'x'))
                        && host.chars().all(|character| {
                            character.is_ascii_hexdigit() || matches!(character, '.' | 'x')
                        }))
            })
    }

    /// Whether `value` is a proxy's origin: an `https` or `http` scheme and a canonical authority,
    /// with no path and no trailing slash, in at most [`MAX_HINT_LEN`] bytes.
    ///
    /// The canonical authority is the rule every other address in the section follows, and it
    /// already refuses user information. [`carries_user_information`] is asked first only so the
    /// refusal can say why.
    fn is_proxy_origin(value: &str) -> bool {
        let Some((authority, path, implied)) = service_address(value) else {
            return false;
        };
        value.len() <= MAX_HINT_LEN && path.is_empty() && is_canonical_authority(authority, implied)
    }

    /// Whether `value` names a user or a password before its host, even an empty one, which is
    /// where a URL carries a credential.
    ///
    /// The authority is read as a URL parser reads it: after the scheme's colon and every `/` or
    /// `\` that follows it, up to the next `/`, `\`, `?` or `#`, whatever the scheme. So an `@` in a
    /// path or a query is not mistaken for one, and extra slashes do not hide one.
    fn carries_user_information(value: &str) -> bool {
        let after_scheme = value
            .split_once(':')
            .filter(|(scheme, _)| {
                scheme.starts_with(|character: char| character.is_ascii_alphabetic())
                    && scheme.chars().all(|character| {
                        character.is_ascii_alphanumeric() || "+-.".contains(character)
                    })
            })
            .map_or(value, |(_, rest)| rest);
        after_scheme
            .trim_start_matches(['/', '\\'])
            .split(['/', '?', '#', '\\'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    }

    /// Whether `value` is a trust anchor's path: absolute, and bounded.
    fn is_anchor_path(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= MAX_PATH_LEN
            && !value.contains('\0')
            && std::path::Path::new(value).is_absolute()
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

    /// The rows the selections contribute to the effective-value report, in [`SELECTIONS`] order.
    ///
    /// Each carries its value, where it came from and "at the next start" as its effect. The
    /// source is the per-user host configuration where `document` wrote the field and the product
    /// default where it did not, and presence decides it rather than comparison: a switch written
    /// as off was still chosen by whoever wrote it. A document this host cannot use is `None`, and
    /// every row is then the default. `origin` is where the document is.
    #[must_use]
    pub fn selection_rows(
        document: Option<&ConfigurationDocument>,
        origin: &str,
    ) -> Vec<super::EffectiveValue> {
        use super::export::Declared;

        let empty = ConfigurationDocument::empty();
        let document = document.unwrap_or(&empty);
        let network = &document.network;
        let row = |selection: Selection, chosen: bool, value: Declared| {
            super::EffectiveValue::new(
                selection.key,
                selection.about,
                &value,
                if chosen {
                    ValueSource::HostConfiguration
                } else {
                    ValueSource::Default
                },
                Nullable(chosen.then(|| origin.to_owned())),
                Nullable::null(),
                Selection::EFFECT,
            )
        };
        let switch = |on: bool| Declared::term(if on { "true" } else { "false" });
        let location =
            |value: Option<&str>| value.map_or_else(|| Declared::term("none"), Declared::location);
        let locations = |values: &[String]| {
            if values.is_empty() {
                Declared::term("none")
            } else {
                Declared::locations(values.iter().map(String::as_str))
            }
        };
        let anchors = network.relay_trust_anchors();
        vec![
            row(
                NETWORK_ENABLED,
                network.enabled.is_present(),
                switch(network.joins()),
            ),
            row(
                NETWORK_BIND_ADDRESS,
                network.bind_address.is_present(),
                location(network.bind_address()),
            ),
            row(
                NETWORK_RELAY_URLS,
                network.relay_urls.is_present(),
                locations(network.relay_urls()),
            ),
            row(
                NETWORK_PKARR_PUBLISHER_URL,
                network.pkarr_publisher_url.is_present(),
                location(network.pkarr_publisher_url()),
            ),
            row(
                NETWORK_PKARR_RESOLVER_URL,
                network.pkarr_resolver_url.is_present(),
                location(network.pkarr_resolver_url()),
            ),
            row(
                NETWORK_DNS_ORIGIN,
                network.dns_origin.is_present(),
                location(network.dns_origin()),
            ),
            row(
                NETWORK_RELAY_TRUST_ANCHORS,
                network.relay_trust_anchors.is_present(),
                if anchors.is_empty() {
                    Declared::term("none")
                } else {
                    Declared::paths(anchors.iter().map(String::as_str))
                },
            ),
            row(
                NETWORK_RELAY_ONLY,
                network.relay_only.is_present(),
                switch(network.relay_only()),
            ),
            row(
                NETWORK_LOCAL_DISCOVERY,
                network.local_discovery.is_present(),
                switch(network.local_discovery()),
            ),
            row(
                NETWORK_MAINLINE_DHT,
                network.mainline_dht.is_present(),
                switch(network.mainline_dht()),
            ),
            row(
                NETWORK_PROXY_URL,
                network.proxy_url.is_present(),
                location(network.proxy_url()),
            ),
            row(
                VOICE_BROKER_ORIGIN,
                document.voice.broker_origin.is_present(),
                location(document.voice.broker_origin()),
            ),
        ]
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
    }

    /// The variables this build still reads that are not part of the precedence.
    ///
    /// Section 26 asks that only documented allowlisted overrides participate and that arbitrary
    /// inherited variables cannot change authority or provider origins. [`ALLOWLIST`] is the first
    /// half. This table is the second, and it exists because a claim is worth nothing unless the
    /// exceptions to it are written down: `kr doctor` prints this list, so what a person is told
    /// about this host matches what this host actually does.
    ///
    /// Two kinds are here, and neither reaches authority or a provider origin. The platform
    /// directory variables are how the operating system itself names its conventional locations,
    /// and reading them is what "native OS-appropriate locations" means rather than an exception
    /// to it. The session variables are how the platform describes the login this host is running
    /// in, which is a reading of the environment rather than a choice about it. Every network
    /// selection and the voice broker's origin are this host's configuration document's
    /// ([`NetworkSelection`], [`VoiceSelection`]), and nothing reads them from the environment. No
    /// variable names this host's owner: the owner is recorded through local IPC, by the pairing
    /// that establishes it.
    ///
    /// The list names what this build reads that decides something: a location or the login this
    /// host describes. It is not an inventory of every variable a process in this tree ever looks
    /// at, and it does not claim to be one. A name that is in neither this table nor
    /// [`ALLOWLIST`] takes no part in the precedence.
    pub const UNGOVERNED: [UngovernedVariable; 11] = [
        UngovernedVariable {
            variable: "TMPDIR",
            selects: "the platform's per-user temporary directory, which is the macOS runtime root",
        },
        UngovernedVariable {
            variable: "XDG_RUNTIME_DIR",
            selects: "the platform's per-user runtime directory on Linux",
        },
        UngovernedVariable {
            variable: "XDG_STATE_HOME",
            selects: "the platform's per-user state directory on Linux",
        },
        UngovernedVariable {
            variable: "XDG_CONFIG_HOME",
            selects: "the platform's per-user configuration directory on Linux",
        },
        UngovernedVariable {
            variable: "HOME",
            selects: "the account's home directory, from which every default root is derived",
        },
        UngovernedVariable {
            variable: "PATH",
            selects: "where a capability probe looks for the tools it reports on",
        },
        UngovernedVariable {
            variable: "DISPLAY",
            selects: "the X display a desktop reading describes",
        },
        UngovernedVariable {
            variable: "XAUTHORITY",
            selects: "the X authority file a desktop reading describes",
        },
        UngovernedVariable {
            variable: "XDG_SESSION_ID",
            selects: "the login session a desktop reading describes on Linux",
        },
        UngovernedVariable {
            variable: "SESSIONNAME",
            selects: "the login session a desktop reading describes on Windows",
        },
        UngovernedVariable {
            variable: "LOCALAPPDATA",
            selects: "the account's local application data directory on Windows",
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
    /// selection keys and the words their values are reported in, the ceiling keys, the enrolment
    /// budgets, the documented environment variables, the variables this build reads outside the
    /// precedence, the wire words of the closed enumerations a report names, and the operating
    /// system and processor words of the platform this build was compiled for. A string that is
    /// none of them is something somebody else wrote, and a sentence carries its class and its
    /// length instead.
    #[must_use]
    pub fn is_known_term(value: &str) -> bool {
        PREFERENCES.iter().any(|preference| preference.key == value)
            || SELECTIONS.iter().any(|selection| selection.key == value)
            || SELECTION_WORDS.contains(&value)
            || CEILINGS.contains(&value)
            || BUDGETS.contains(&value)
            || ALLOWLIST
                .iter()
                .any(|entry| entry.variable == value || entry.preference == value)
            || ungoverned_here()
                .iter()
                .any(|entry| entry.variable == value)
            || WIRE_WORDS.contains(&value)
            // The platform this build was compiled for, in the words the compiler wrote in.
            || value == std::env::consts::OS
            || value == std::env::consts::ARCH
            || crate::desktop::CAPABILITIES.contains(&value)
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
    pub const WIRE_WORDS: [&str; 18] = [
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
        "next_start",
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
/// `&'static str`, which every caller in this product passes as a literal in this source. A
/// message that arrived at runtime is a `String` and cannot be put in one, so a check's detail
/// cannot come to carry a library's error message by somebody interpolating it. The type
/// establishes a lifetime rather than an origin, as [`Stated`] says: it stops the mistake, not a
/// caller that leaks a string on purpose.
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
        field("DesktopContext", "boot_identity", ContentClass::Structure),
        field("BootIdentity", "source", ContentClass::Term),
        // The bytes the kernel handed this host for the boot it is in. Which facility they came
        // from is this platform's own word and leaves; the value identifies one boot of one
        // machine, nothing outside that machine has anything to compare it to, and the type holds
        // bytes rather than a shape. So the export carries the facility and not the value.
        field("BootIdentity", "value", ContentClass::Name),
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
        field("SleepInhibitionState", "setting", ContentClass::Term),
        field("SleepInhibitionState", "active", ContentClass::Term),
        field("SleepInhibitionState", "reason", ContentClass::Term),
        field("SleepInhibitionState", "mechanism", ContentClass::Term),
        field("SleepInhibitionState", "power_source", ContentClass::Term),
        field(
            "SleepInhibitionState",
            "sessions_with_work",
            ContentClass::Number,
        ),
        field(
            "SleepInhibitionState",
            "pending_requests",
            ContentClass::Number,
        ),
        field("SleepInhibitionState", "since_ms", ContentClass::Number),
        // The name the operating system shows for the assertion, and the sentence it gives for
        // withholding one. Both are the platform's words about this machine rather than this
        // build's about itself.
        field("SleepInhibitionState", "holder", ContentClass::Name),
        field(
            "SleepInhibitionState",
            "withheld_reason",
            ContentClass::Message,
        ),
        field(
            "EnvironmentCapabilitiesResult",
            "environment_id",
            ContentClass::Identifier,
        ),
        field(
            "EnvironmentCapabilitiesResult",
            "desktop",
            ContentClass::Structure,
        ),
        field(
            "EnvironmentCapabilitiesResult",
            "default_worker_profile",
            ContentClass::Term,
        ),
        field(
            "EnvironmentCapabilitiesResult",
            "persistence",
            ContentClass::Structure,
        ),
        field(
            "EnvironmentCapabilitiesResult",
            "power",
            ContentClass::Structure,
        ),
        field(
            "DesktopCapabilityReport",
            "desktop",
            ContentClass::Structure,
        ),
        field(
            "DesktopCapabilityReport",
            "records",
            ContentClass::Structure,
        ),
        // `host.info`, as a paired device reads it. The build identity is composed from the closed
        // word and the three numbers a parse keeps, or leaves as a name's record when it does not
        // parse; the boot and the sleep state go through the reductions every other answer uses.
        field("HostInfoResult", "build_id", ContentClass::Identifier),
        field(
            "HostInfoResult",
            "protocol_version",
            ContentClass::Structure,
        ),
        field("HostInfoResult", "environment_id", ContentClass::Identifier),
        field("HostInfoResult", "generation", ContentClass::Identifier),
        field("HostInfoResult", "boot_identity", ContentClass::Structure),
        field("HostInfoResult", "started_at_ms", ContentClass::Number),
        field("HostInfoResult", "live_sessions", ContentClass::Number),
        field("HostInfoResult", "session_limit", ContentClass::Number),
        field(
            "HostInfoResult",
            "default_worker_profile",
            ContentClass::Term,
        ),
        field("HostInfoResult", "power", ContentClass::Structure),
        field("ProtocolVersion", "major", ContentClass::Number),
        field("ProtocolVersion", "minor", ContentClass::Number),
        // `environment.list`, as a paired device reads it. The account and the directories are
        // somebody else's names; the label names the account for the owner, so it is written again
        // from the environment's prefix and its platform rather than measured.
        field(
            "EnvironmentListResult",
            "environments",
            ContentClass::Structure,
        ),
        field(
            "EnvironmentSummary",
            "environment_id",
            ContentClass::Identifier,
        ),
        field("EnvironmentSummary", "label", ContentClass::Name),
        field("EnvironmentSummary", "os", ContentClass::Term),
        field("EnvironmentSummary", "arch", ContentClass::Term),
        field("EnvironmentSummary", "os_user", ContentClass::Name),
        field(
            "EnvironmentSummary",
            "runtime_directory",
            ContentClass::Path,
        ),
        field("EnvironmentSummary", "state_directory", ContentClass::Path),
        field("EnvironmentSummary", "live_sessions", ContentClass::Number),
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

    /// Returns `value` where its text can be checked to be what its class says, and the withheld
    /// record otherwise.
    ///
    /// A class beside a string is a claim about the string, and the claim travels in the same
    /// document the string did: a row that arrived saying its value is a number and putting a
    /// sentence there is a row nobody wrote by hand. So a class is never believed. Two of them can
    /// be checked against the text itself, and those two are the only ones a plain string leaves
    /// as itself:
    ///
    /// * [`ContentClass::Term`], against the closed sets this build defines. A string that is not
    ///   one of them is something somebody else wrote into a field that was supposed to hold a
    ///   key, and it leaves as a name.
    /// * [`ContentClass::Number`], against its digits.
    ///
    /// Everything else is measured. [`ContentClass::Stated`] says the value was written here and a
    /// `&str` cannot answer whether it was: the fields of that class hold [`Stated`] or
    /// [`Sentence`], which answer for themselves, and [`stated`] is what renders them.
    /// [`ContentClass::Identifier`] says this host composed the value, and the fields of that
    /// class hold the typed identifiers that prove it. [`ContentClass::Structure`] is not a string
    /// at all; a structure is taken through its own type's rows.
    ///
    /// Nothing looks at whether a value has been here before, because nothing crosses this
    /// boundary twice: each value is carried by the one conversion that puts it inside an
    /// [`Exported`], and there is no conversion from an exported value back to a display one. A
    /// record measured a second time would report the length of the record rather than of the
    /// value it stands for.
    #[must_use]
    pub fn carry(class: ContentClass, value: &str) -> String {
        match class {
            ContentClass::Term if super::configuration::is_known_term(value) => value.to_owned(),
            ContentClass::Term => withheld(ContentClass::Name, value),
            ContentClass::Number if value.parse::<u64>().is_ok() => value.to_owned(),
            _ => withheld(class, value),
        }
    }

    /// Text inside the export boundary, which knows whether this process composed it.
    ///
    /// The two implementations are [`Stated`], which holds words spelled out in this source, and
    /// [`Sentence`], which composes them with numbers, identifiers this host generated and the
    /// measure of everything else. Every wire field classed [`ContentClass::Stated`] is one of
    /// them, a `Vec` of one or a [`Nullable`](crate::scalars::Nullable) of one, so the provenance
    /// of the text travels in the same value as the text.
    ///
    /// That is what makes the promise checkable rather than remembered. A value this process built
    /// leaves as its own words; a value that arrived - out of a file, out of a worker's reply, out
    /// of a response to a request - leaves as its class and its length, whatever the field it
    /// arrived in was supposed to hold.
    ///
    /// ```compile_fail
    /// use kr_protocol::hostinfo::configuration::{DocumentState, DocumentStatus};
    /// // A field of this class holds text that answers for itself, so a plain string has nowhere
    /// // to go in one: there is no conversion into either type from a runtime value.
    /// let arrived = String::from("token opensesame");
    /// let status = DocumentStatus {
    ///     state: DocumentState::Loaded,
    ///     detail: arrived,
    /// };
    /// ```
    ///
    /// Sealed, because an implementation is a promise about where text came from and a promise
    /// another crate makes about its own `String` is exactly the claim this trait replaces. The
    /// two implementations are here, beside the constructors that keep them true.
    pub trait Provenance: Sized + sealed::Composed {
        /// The text as it stands, for the report a host shows its own owner.
        fn as_str(&self) -> &str;

        /// True when this process composed this value out of this build's own words.
        fn composed_here(&self) -> bool;

        /// This value as somebody else reads it: the words, or their class and their length.
        #[must_use]
        fn exported(&self) -> Self;
    }

    /// Returns the text a reader outside this host gets for one provenance-carrying value.
    #[must_use]
    pub fn stated(value: &impl Provenance) -> String {
        if value.composed_here() {
            value.as_str().to_owned()
        } else {
            withheld(ContentClass::Stated, value.as_str())
        }
    }

    /// Returns every value of a list taken through [`Provenance::exported`].
    #[must_use]
    pub fn exported_each<T: Provenance>(values: &[T]) -> Vec<T> {
        values.iter().map(Provenance::exported).collect()
    }

    /// Returns a nullable value taken through [`Provenance::exported`].
    #[must_use]
    pub fn exported_null<T: Provenance>(
        value: &crate::scalars::Nullable<T>,
    ) -> crate::scalars::Nullable<T> {
        crate::scalars::Nullable(value.0.as_ref().map(Provenance::exported))
    }

    /// Returns a nullable value taken through [`carry`].
    #[must_use]
    pub fn carry_null(
        class: ContentClass,
        value: &crate::scalars::Nullable<String>,
    ) -> crate::scalars::Nullable<String> {
        crate::scalars::Nullable(value.0.as_deref().map(|text| carry(class, text)))
    }

    /// An identifier a sentence may name in full.
    ///
    /// The list is closed and every member is a type that composes what it prints: a session
    /// identifier, an environment's, a device's, the revision of a capability record, and
    /// [`BuildIdentity`], which is read out of a reply and stores a word from a closed set and
    /// three numbers rather than the text it was read from. A `String` is not one of them, so a
    /// sentence cannot come to name one because a caller passed something that happened to print.
    ///
    /// Sealed: the list can only grow here, where adding to it is a decision about what this host
    /// says about itself, rather than in whatever crate wanted its own type in a sentence.
    pub trait HostIdentifier: std::fmt::Display + sealed::Generated {}

    mod sealed {
        /// Implemented beside each identifier this host generates, and nowhere else.
        pub trait Generated {}

        /// Implemented beside each type that records where its own text came from.
        pub trait Composed {}
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

    /// One of the programs this product builds.
    ///
    /// A closed set, spelled here. A build identity names one of these and nothing else, so the
    /// component half of one carries no text that arrived: it carries a word out of this list.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum BuildComponent {
        /// The command line.
        CommandLine,
        /// The host daemon.
        Controller,
        /// A session's worker process.
        Worker,
    }

    impl BuildComponent {
        /// Every component, in the order they are declared.
        pub const ALL: [Self; 3] = [Self::CommandLine, Self::Controller, Self::Worker];

        /// Returns the name this product builds it under.
        #[must_use]
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::CommandLine => "kr",
                Self::Controller => "kr-controller",
                Self::Worker => "kr-worker",
            }
        }

        /// Returns the component of that name, where it is one.
        #[must_use]
        fn named(text: &str) -> Option<Self> {
            Self::ALL
                .into_iter()
                .find(|component| component.as_str() == text)
        }
    }

    impl std::fmt::Display for BuildComponent {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(self.as_str())
        }
    }

    /// The most digits one part of a version may have, which is what a `u32` holds.
    const BUILD_VERSION_DIGITS: usize = 9;

    /// Which program is running, and which build of it.
    ///
    /// `kr-controller/0.1.0` is one. A support bundle names it in full, because which build is
    /// running is the first thing somebody reading one needs and a length would tell them nothing.
    ///
    /// What the parse establishes is a shape, not a build. The text reaches the command that
    /// writes a bundle in a reply, over a socket, so where it came from establishes nothing about
    /// it, and the parse does not change that: `kr-controller/123456.7.8` parses and renders as
    /// itself, so the reply still chooses the three numbers, and a bundle names the build the
    /// daemon reported rather than proving which one is installed. What the shape does establish
    /// is that nothing else gets in: what is stored is a word out of [`BuildComponent`] and three
    /// numbers of at most nine digits, and what is rendered is composed from those, with no
    /// borrowed substring anywhere in it. A version that is anything but three numbers, and a
    /// component that is not one this product builds, fail the parse and leave as their class
    /// and their length like any other name. There is deliberately no accessor returning the text
    /// that was parsed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct BuildIdentity {
        component: BuildComponent,
        major: u32,
        minor: u32,
        patch: u32,
    }

    impl BuildIdentity {
        /// Reads a build identity, or nothing when the text is not one.
        #[must_use]
        pub fn parse(text: &str) -> Option<Self> {
            let (component, version) = text.split_once('/')?;
            let component = BuildComponent::named(component)?;
            let mut parts = version.split('.');
            let major = version_part(parts.next()?)?;
            let minor = version_part(parts.next()?)?;
            let patch = version_part(parts.next()?)?;
            if parts.next().is_some() {
                return None;
            }
            Some(Self {
                component,
                major,
                minor,
                patch,
            })
        }

        /// Which program this identifies.
        #[must_use]
        pub const fn component(&self) -> BuildComponent {
            self.component
        }
    }

    /// Reads one part of a version: digits, and few enough of them to be a version.
    fn version_part(text: &str) -> Option<u32> {
        (!text.is_empty()
            && text.len() <= BUILD_VERSION_DIGITS
            && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
    }

    /// Rendered out of the stored word and the stored numbers, never out of what was parsed.
    impl std::fmt::Display for BuildIdentity {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "{}/{}.{}.{}",
                self.component.as_str(),
                self.major,
                self.minor,
                self.patch
            )
        }
    }

    impl sealed::Generated for BuildIdentity {}
    impl HostIdentifier for BuildIdentity {}

    /// Words this build spells out in its own source, as a wire field holds them.
    ///
    /// A field classed [`ContentClass::Stated`] carries its text out of this host because the text
    /// is this build's own. The class on its own is a claim about the producer, and a claim is
    /// what a caller forgets: the type is how the producer records it. The only constructor takes
    /// `&'static str`, so an ordinary runtime value cannot be put in one, and
    /// [`Self::written_here`] answers whether this particular value came through that constructor.
    ///
    /// Reading is the ordinary way to hold one of these without having built it, because a parsed
    /// document owns its text. Such a value is an owned one, [`Self::written_here`] returns `None`
    /// for it, and nothing that composes this build's own words will quote it.
    ///
    /// What this proves is a lifetime, not an origin. Leaking a runtime string gives it the same
    /// lifetime a literal has, so a caller determined to launder text can. The guarantee is
    /// against the mistake that actually happens - a value read off the wire or out of a library
    /// repeated as though this host had written it - and not against a caller working to defeat
    /// it.
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

    impl sealed::Composed for Stated {}

    impl Provenance for Stated {
        fn as_str(&self) -> &str {
            self.as_str()
        }

        fn composed_here(&self) -> bool {
            self.written_here().is_some()
        }

        /// The words, or the record of a value that arrived claiming to be them.
        ///
        /// The measured form is owned, so it answers `false` to [`Provenance::composed_here`] like
        /// anything else that was not written here. Nothing measures it a second time: a value
        /// crosses this boundary once, and there is no conversion back.
        fn exported(&self) -> Self {
            Self(std::borrow::Cow::Owned(stated(self)))
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

        /// Several filesystem paths as one value, in the order given, wherever they came from.
        #[must_use]
        pub fn paths<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
            Self {
                class: ContentClass::Path,
                value: values.into_iter().collect::<Vec<_>>().join(", "),
            }
        }

        /// A network location - a URL, an origin, a domain name or a socket address - wherever it
        /// came from.
        #[must_use]
        pub fn location(value: &str) -> Self {
            Self {
                class: ContentClass::Location,
                value: value.to_owned(),
            }
        }

        /// Several network locations as one value, in the order given, wherever they came from.
        #[must_use]
        pub fn locations<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
            Self {
                class: ContentClass::Location,
                value: values.into_iter().collect::<Vec<_>>().join(", "),
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
    /// The only text it takes is `&'static str`, which every caller passes as a literal in this
    /// source; like [`Stated`], the type establishes that lifetime rather than the origin. A
    /// message from a library, a path, or anything else that arrived at runtime is a `String` and
    /// cannot be put in one; what such a value contributes is a number, a member of a closed set,
    /// an identifier this host generated, or its class and its length.
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
    ///
    /// # A sentence that arrived
    ///
    /// A sentence is a wire field, so one can be read as easily as written: a support bundle a
    /// person opens, a `host.doctor` reply a command parses, a document somebody else's build
    /// wrote. Such a value was composed somewhere this build cannot see, so it is not this
    /// build's own words however it is spelled, [`Self::composed_here`] says so, and exporting it
    /// states its length instead of repeating it. The flag is written by this module and nothing
    /// else: the field is private, the type is not constructible outside this crate, and reading
    /// is the one route that clears it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Sentence {
        text: String,
        /// False for every value that arrived by reading, and true for one composed here.
        composed_here: bool,
    }

    /// An empty sentence is one this build composed and has said nothing into yet.
    ///
    /// Written out rather than derived: the derived flag would be false, which would make the
    /// empty sentence a value that arrived from somewhere.
    impl Default for Sentence {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Sentence {
        /// Starts an empty sentence.
        #[must_use]
        pub fn new() -> Self {
            Self {
                text: String::new(),
                composed_here: true,
            }
        }

        /// Appends text written in this source.
        #[must_use]
        pub fn stated(mut self, text: &'static str) -> Self {
            self.text.push_str(text);
            self
        }

        /// Appends a number.
        #[must_use]
        pub fn number(mut self, value: u64) -> Self {
            use std::fmt::Write as _;
            let _ = write!(&mut self.text, "{value}");
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
                self.text.push_str(value);
            } else {
                self.text.push_str(&withheld(ContentClass::Name, value));
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
            let _ = write!(&mut self.text, "{value}");
            self
        }

        /// Appends a value's class and length in place of the value.
        #[must_use]
        pub fn withheld(mut self, class: ContentClass, value: &str) -> Self {
            self.text.push_str(&withheld(class, value));
            self
        }

        /// Appends a path as its class and its length.
        #[must_use]
        pub fn path(self, value: &std::path::Path) -> Self {
            let value = value.display().to_string();
            self.withheld(ContentClass::Path, &value)
        }

        /// Appends words this build wrote, read back out of a wire field.
        ///
        /// [`Provenance`] answers where the text came from, so this appends the words when this
        /// process composed them and their class and length when they were read from a document,
        /// a reply or a bundle somebody else wrote. That is the difference between quoting this
        /// build and quoting a response: a sentence composed from a reply cannot come to repeat
        /// what the reply said.
        #[must_use]
        pub fn stated_value(mut self, value: &impl Provenance) -> Self {
            self.text.push_str(&stated(value));
            self
        }

        /// Appends the value of another exported field, on the terms its class sets.
        ///
        /// The class comes from [`EXPORTED`] rather than from the caller, so quoting a field into
        /// a sentence and exporting that field are the same decision, and a pair that is not in
        /// the allowlist at all is withheld as a name. This is the only way a sentence takes a
        /// value that is not a literal, a number or an identifier: a value with nowhere in the
        /// allowlist to belong cannot be put in one.
        ///
        /// A field classed [`ContentClass::Stated`] is measured here rather than quoted, because a
        /// `&str` cannot say whether this process wrote it. Those fields hold [`Stated`] or
        /// [`Sentence`], and [`Self::stated_value`] is how one of them is quoted.
        #[must_use]
        pub fn field(mut self, type_name: &'static str, name: &'static str, value: &str) -> Self {
            self.text.push_str(&carry(class(type_name, name), value));
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
                    self.text.push_str(between);
                }
                self = self.term(value);
            }
            self
        }

        /// Appends another sentence, on the terms its own provenance sets.
        #[must_use]
        pub fn sentence(self, value: &Self) -> Self {
            self.stated_value(value)
        }

        /// The sentence as it stands, for the report a host shows its own owner.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.text
        }

        /// Whether nothing has been appended.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.text.is_empty()
        }

        /// Returns the finished sentence, for the report a host shows its own owner.
        ///
        /// The owner's own report shows what this host found, including what a reply or a document
        /// said; [`Provenance::exported`] is the other reading, for a file that leaves.
        #[must_use]
        pub fn render(self) -> String {
            self.text
        }
    }

    impl sealed::Composed for Sentence {}

    impl Provenance for Sentence {
        fn as_str(&self) -> &str {
            self.as_str()
        }

        fn composed_here(&self) -> bool {
            self.composed_here
        }

        /// The sentence, or the record of one that arrived claiming to be this build's.
        fn exported(&self) -> Self {
            Self {
                text: stated(self),
                composed_here: false,
            }
        }
    }

    impl std::fmt::Display for Sentence {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(&self.text)
        }
    }

    /// A sentence is a string on the wire, exactly as it was before it had a type here.
    impl Serialize for Sentence {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&self.text)
        }
    }

    /// Reading is the one route that clears [`Sentence::composed_here`].
    ///
    /// Written out rather than derived, because the derive would take the flag from the document
    /// and let a file claim its own words were this build's. There is no `From<String>` beside it
    /// for the same reason: a conversion that made a sentence out of arbitrary text would be the
    /// hole this type exists to close.
    impl<'de> Deserialize<'de> for Sentence {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Ok(Self {
                text: String::deserialize(deserializer)?,
                composed_here: false,
            })
        }
    }

    impl JsonSchema for Sentence {
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
            boot_identity: boot_identity(&context.boot_identity),
            ..context
        }
    }

    /// Returns a boot identity as it leaves this host: the facility it was read from, and none of
    /// its value.
    ///
    /// Which kernel facility this platform reads its boot identity from is a word of this build's
    /// own and a useful thing to know about a host. The value is bytes: one boot of one machine,
    /// compared for equality and never interpreted, so nobody reading an export has anything to
    /// compare it to and it does not leave. The one reduction every answer that carries a boot
    /// identity goes through.
    pub(super) fn boot_identity(
        boot: &crate::identity::BootIdentity,
    ) -> crate::identity::BootIdentity {
        crate::identity::BootIdentity {
            source: boot.source,
            value: crate::scalars::Bytes::new(Vec::new()),
        }
    }

    /// Returns this host's sleep inhibition as it leaves this host.
    ///
    /// The name the operating system shows for the assertion and the sentence it gives for
    /// withholding one are the platform's words about this machine, so both leave as their class
    /// and their length, and the class comes from the allowlist rather than from here: a field of
    /// this type added later is classed in the one place every other exported field is, or the
    /// tests refuse it. The one reduction every answer that carries the sleep state goes through.
    pub(super) fn sleep_inhibition(
        power: crate::desktop::SleepInhibitionState,
    ) -> crate::desktop::SleepInhibitionState {
        crate::desktop::SleepInhibitionState {
            holder: carry_null(class("SleepInhibitionState", "holder"), &power.holder),
            withheld_reason: carry_null(
                class("SleepInhibitionState", "withheld_reason"),
                &power.withheld_reason,
            ),
            ..power
        }
    }

    /// Returns a build identifier as it leaves this host.
    ///
    /// Named in full when it parses as one of this product's builds, composed from the closed word
    /// and the three numbers the parse keeps, and as its class and its length when it does not:
    /// the text arrived in a reply or a setup value, and nothing about where it came from says it
    /// is one.
    pub(super) fn build_id(id: &crate::ids::BuildId) -> crate::ids::BuildId {
        let text = BuildIdentity::parse(id.as_str()).map_or_else(
            || withheld(ContentClass::Name, id.as_str()),
            |build| build.to_string(),
        );
        crate::ids::BuildId::new(text).expect("a build identity or its record is an identifier")
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

    /// Returns a capability this build names, or the record of one it does not.
    ///
    /// The five desktop capabilities are words spelled out in this source, and a record carrying
    /// one of them leaves saying so. A record that arrived naming something else - from a worker
    /// process, from a reply, from a bundle somebody sent - is a name somebody else chose, and a
    /// name is not exported.
    fn withheld_capability_name(capability: &crate::ids::CapabilityId) -> crate::ids::CapabilityId {
        let carried = carry(class("CapabilityRecord", "capability"), capability.as_str());
        crate::ids::CapabilityId::new(&carried)
            .unwrap_or_else(|_| withheld_name("the withheld marker is a valid capability"))
    }

    /// The capability a withheld name leaves as.
    fn withheld_name(why: &'static str) -> crate::ids::CapabilityId {
        crate::ids::CapabilityId::new("[name withheld]").expect(why)
    }

    impl ForExport for crate::desktop::EnvironmentCapabilitiesResult {
        /// One environment's capability answer, every part of it through the allowlist.
        ///
        /// The one place this answer crosses a boundary. Every member that carries text is reduced
        /// here rather than at the caller, so a member added to the answer is reduced by this
        /// function or by nothing: a caller that reduced the records and forgot the persistence
        /// table would be the failure this exists to prevent.
        fn for_export(self) -> Exported<Self> {
            Exported::of(Self {
                desktop: crate::desktop::DesktopCapabilityReport {
                    desktop: desktop_context(self.desktop.desktop),
                    records: capability_records(self.desktop.records),
                },
                persistence: self
                    .persistence
                    .iter()
                    .map(crate::desktop::ProfilePersistence::withheld_form)
                    .collect(),
                power: sleep_inhibition(self.power),
                ..self
            })
        }
    }

    /// One capability record with every field through the allowlist.
    fn withheld_capability(
        record: crate::desktop::CapabilityRecord,
    ) -> crate::desktop::CapabilityRecord {
        {
            crate::desktop::CapabilityRecord {
                capability: withheld_capability_name(&record.capability),
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
    fn bundle_carrying(secret: &str) -> ComposedBundle {
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
            configured: Nullable(Some(export::Sentence::new().number(16))),
            value: export::Sentence::new().number(16),
            source: ValueSource::HostConfiguration,
            origin: Nullable(Some(secret.to_owned())),
            effect: configuration::ValueEffect::Immediately,
            narrowed_by: Nullable(Some(export::Sentence::new().stated("the hard limit"))),
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
        ComposedBundle::new(
            TimestampMs::new(0),
            vec![SoftwareComponent {
                component: export::Stated::new("kr-controller"),
                version: export::Sentence::new().number(0),
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

    /// The schema generator the coverage walks read.
    ///
    /// The serialising contract, because an export is what a serialiser writes. A member a reader
    /// skips (`skip_deserializing`) is absent from the deserialising schema and present in every
    /// document this host sends, so a walk of the reader's schema would never see it.
    fn export_generator() -> schemars::SchemaGenerator {
        schemars::generate::SchemaSettings::draft2020_12()
            .for_serialize()
            .into_generator()
    }

    /// Keywords whose value is a subschema the coverage walk does not follow.
    ///
    /// Each could hold members the walk would then never see, so meeting one is a refusal rather
    /// than a gap: a type whose schema needs one has to be walked here before it can be exported.
    const UNFOLLOWED: [&str; 10] = [
        "$defs",
        "definitions",
        "$dynamicRef",
        "$recursiveRef",
        "dependentSchemas",
        "dependencies",
        "unevaluatedProperties",
        "unevaluatedItems",
        "additionalItems",
        "contentSchema",
    ];

    /// Whether a keyword only describes a value rather than constraining it.
    ///
    /// The metadata and content-annotation keywords of the 2020-12 vocabulary, `format` (an
    /// annotation unless a validator opts in), and every extension keyword. A schema made of
    /// nothing else admits any value.
    fn is_annotation(keyword: &str) -> bool {
        matches!(
            keyword,
            "title"
                | "description"
                | "default"
                | "examples"
                | "deprecated"
                | "readOnly"
                | "writeOnly"
                | "$comment"
                | "$schema"
                | "$id"
                | "$anchor"
                | "format"
                | "contentEncoding"
                | "contentMediaType"
        ) || keyword.starts_with("x-")
    }

    /// The keywords that make an object a map, whose keys are text somebody chose.
    ///
    /// The map-key policy is that no export carries one. A member's name is a word this build
    /// declared and the allowlist classes; a map key is a value, and nothing classes it. So a map
    /// reached from an export is refused here, whatever its values are, and a type that wants one
    /// has to decide what its keys are made of first. `additionalProperties: false` is the one
    /// form of these that is not a map: it is how a closed object says it has no other members.
    const MAP_KEYWORDS: [&str; 3] = ["additionalProperties", "patternProperties", "propertyNames"];

    /// Every named object an export's schema reaches, with its members.
    ///
    /// Every reference is followed, and so is every keyword beside it, because a reference with
    /// siblings is one schema rather than two: members written beside it belong to the object
    /// that holds them. Arrays, conditions and negations are descended with the owning name
    /// cleared, so an object with members that has no name of its own is a refusal rather than a
    /// set of members attributed to whatever contained it; alternatives keep the name, because an
    /// alternative is another shape of the same value.
    ///
    /// # Errors
    ///
    /// Returns what it could not account for: a subschema that admits any value, a keyword in
    /// [`UNFOLLOWED`], a map, an object with members and no name, and a reference that is not to a
    /// definition this generator wrote.
    fn reach(
        roots: &[serde_json::Value],
        defined: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<std::collections::BTreeMap<String, std::collections::BTreeSet<String>>, String>
    {
        use std::collections::{BTreeMap, BTreeSet};

        fn walk(
            node: &serde_json::Value,
            defined: &serde_json::Map<String, serde_json::Value>,
            owner: Option<&str>,
            seen: &mut BTreeSet<String>,
            reached: &mut BTreeMap<String, BTreeSet<String>>,
        ) -> Result<(), String> {
            let schema = match node {
                // A schema nothing satisfies holds nothing.
                serde_json::Value::Bool(false) => return Ok(()),
                // A schema whose every keyword only describes the value admits any value, however
                // much it says about it: `{"description": "payload"}` is what a documented
                // `serde_json::Value` member comes out as.
                serde_json::Value::Object(schema)
                    if schema.keys().any(|keyword| !is_annotation(keyword)) =>
                {
                    schema
                }
                _ => {
                    return Err(format!(
                        "an export reaches a value of any shape, which nothing classes: {node}"
                    ));
                }
            };
            if let Some(keyword) = UNFOLLOWED
                .iter()
                .find(|keyword| schema.contains_key(**keyword))
            {
                return Err(format!(
                    "an export reaches {keyword}, which this walk does not follow: {node}"
                ));
            }
            for keyword in MAP_KEYWORDS {
                let map = match schema.get(keyword) {
                    Some(serde_json::Value::Bool(false)) if keyword == "additionalProperties" => {
                        false
                    }
                    Some(_) => true,
                    None => false,
                };
                if map {
                    return Err(format!(
                        "an export reaches a map ({keyword}), whose keys nothing classes: {node}"
                    ));
                }
            }
            if let Some(reference) = schema.get("$ref") {
                let name = reference
                    .as_str()
                    .and_then(|reference| reference.strip_prefix("#/$defs/"))
                    .ok_or_else(|| {
                        format!("an export reaches a reference to no definition here: {node}")
                    })?
                    .replace("~1", "/")
                    .replace("~0", "~");
                if seen.insert(name.clone()) {
                    let definition = defined
                        .get(&name)
                        .ok_or_else(|| format!("{name} is referred to and not defined"))?;
                    walk(definition, defined, Some(&name), seen, reached)?;
                }
                // And on to its siblings, which belong to this node rather than to the reference.
            }
            if let Some(members) = schema.get("properties") {
                let serde_json::Value::Object(members) = members else {
                    return Err(format!("properties that are not an object: {node}"));
                };
                let name = owner.ok_or_else(|| {
                    format!("an export reaches an object with members and no name: {node}")
                })?;
                for (member, below) in members {
                    reached
                        .entry(name.to_owned())
                        .or_default()
                        .insert(member.clone());
                    walk(below, defined, None, seen, reached)?;
                }
            }
            for keyword in ["items", "contains", "not", "if", "then", "else"] {
                if let Some(below) = schema.get(keyword) {
                    walk(below, defined, None, seen, reached)?;
                }
            }
            for keyword in ["anyOf", "oneOf", "allOf", "prefixItems"] {
                if let Some(alternatives) = schema.get(keyword) {
                    let serde_json::Value::Array(alternatives) = alternatives else {
                        return Err(format!("{keyword} that is not an array: {node}"));
                    };
                    for alternative in alternatives {
                        walk(alternative, defined, owner, seen, reached)?;
                    }
                }
            }
            Ok(())
        }

        let mut seen = BTreeSet::new();
        let mut reached = BTreeMap::new();
        for root in roots {
            walk(root, defined, None, &mut seen, &mut reached)?;
        }
        Ok(reached)
    }

    /// KR-REQ-26.44: the allowlist covers every field of every type an export can reach, and of
    /// the four host reads a paired device is sent.
    ///
    /// Walked from the export roots through the schema of what is written rather than through a
    /// list of types somebody keeps up to date, by [`reach`]. So a type reached only inside
    /// another exported type is covered, and a member added to one tomorrow fails this on the day
    /// it is added whether or not anything in this file names it: `host.info`,
    /// `environment.list`, `environment.capabilities` and `host.doctor` are all roots, so a field
    /// added to what a device reads is classed before it can be sent.
    #[test]
    fn every_exported_field_is_classed() {
        let mut generator = export_generator();
        // A support bundle, and the four host-and-environment answers a paired device is sent.
        let roots = vec![
            generator.subschema_for::<SupportBundle>().to_value(),
            generator.subschema_for::<HostInfoResult>().to_value(),
            generator
                .subschema_for::<EnvironmentListResult>()
                .to_value(),
            generator
                .subschema_for::<crate::desktop::EnvironmentCapabilitiesResult>()
                .to_value(),
            generator.subschema_for::<HostDoctorResult>().to_value(),
        ];
        let defined = generator.take_definitions(false);
        let reached = reach(&roots, &defined).unwrap_or_else(|problem| panic!("{problem}"));
        for (name, members) in &reached {
            for member in members {
                assert!(
                    export::class_of(name, member).is_some(),
                    "{name}.{member} is reachable from an export and has no content class"
                );
            }
        }
        assert!(
            reached.len() > 15,
            "the walk reached {} types",
            reached.len()
        );

        // And nothing is classed that an export cannot reach, so the allowlist stays a record of
        // what leaves rather than a place entries accumulate.
        for entry in export::EXPORTED {
            let members = reached.get(entry.type_name).unwrap_or_else(|| {
                panic!("{} is classed and no export reaches it", entry.type_name)
            });
            assert!(
                members.contains(entry.field),
                "{}.{} is classed and is not a member",
                entry.type_name,
                entry.field
            );
        }
    }

    /// KR-REQ-26.44: the coverage walk sees what a reference's siblings add, and refuses every
    /// form it cannot account for rather than passing over it.
    #[test]
    fn the_coverage_walk_follows_a_reference_and_its_siblings_and_refuses_the_rest() {
        let defined = serde_json::json!({
            "Outer": {
                "$ref": "#/$defs/Inner",
                "properties": { "beside": { "type": "string" } }
            },
            "Inner": {
                "type": "object",
                "properties": { "inside": { "type": "string" } }
            }
        });
        let defined = defined.as_object().expect("definitions");
        let reached = reach(&[serde_json::json!({ "$ref": "#/$defs/Outer" })], defined)
            .expect("a reference with a sibling is walked");
        assert!(reached["Outer"].contains("beside"), "{reached:?}");
        assert!(reached["Inner"].contains("inside"), "{reached:?}");

        for (node, named) in [
            (
                serde_json::json!({ "type": "object", "patternProperties": { "^[0-9]+$": { "type": "string" } } }),
                "patternProperties",
            ),
            (
                serde_json::json!({ "type": "object", "additionalProperties": { "type": "string" } }),
                "additionalProperties",
            ),
            (
                serde_json::json!({ "type": "object", "additionalProperties": true }),
                "additionalProperties",
            ),
            (
                serde_json::json!({ "propertyNames": { "type": "string" } }),
                "propertyNames",
            ),
            (
                serde_json::json!({ "unevaluatedProperties": { "type": "string" } }),
                "unevaluatedProperties",
            ),
            (
                serde_json::json!({ "dependentSchemas": { "a": { "type": "string" } } }),
                "dependentSchemas",
            ),
            (serde_json::json!(true), "any shape"),
            (serde_json::json!({}), "any shape"),
            (serde_json::json!({ "description": "payload" }), "any shape"),
            (
                serde_json::json!({ "title": "payload", "x-kalareach-read-only-metadata": true }),
                "any shape",
            ),
            (serde_json::json!({ "items": {} }), "any shape"),
            (
                serde_json::json!({ "$ref": "https://example.com/elsewhere" }),
                "reference to no definition",
            ),
            (
                serde_json::json!({ "$ref": "#/$defs/Missing" }),
                "not defined",
            ),
            (
                serde_json::json!({ "items": { "properties": { "x": { "type": "string" } } } }),
                "no name",
            ),
        ] {
            let refused = reach(std::slice::from_ref(&node), defined)
                .expect_err("a form the walk cannot account for");
            assert!(refused.contains(named), "{node} was refused as: {refused}");
        }
        // A closed object says so with `false`, and that is not a map.
        let closed = serde_json::json!({
            "Closed": {
                "type": "object",
                "additionalProperties": false,
                "properties": { "only": { "type": "string" } }
            }
        });
        let reached = reach(
            &[serde_json::json!({ "$ref": "#/$defs/Closed" })],
            closed.as_object().expect("definitions"),
        )
        .expect("a closed object is walked");
        assert!(reached["Closed"].contains("only"));
    }

    /// KR-REQ-26.44: the coverage walk reads the schema of what is written, so a member a reader
    /// skips is still one the allowlist has to class; and a map is refused however its keys are
    /// written, including the integer keys schemars describes with `patternProperties`.
    #[test]
    fn the_coverage_walk_reads_what_a_serialiser_writes_and_refuses_every_map() {
        #[derive(Serialize, Deserialize, JsonSchema)]
        struct Written {
            shown: String,
            #[serde(skip_deserializing)]
            written_only: String,
        }

        let mut generator = export_generator();
        let root = generator.subschema_for::<Written>().to_value();
        let reached =
            reach(&[root], &generator.take_definitions(false)).expect("a plain object is walked");
        assert!(reached["Written"].contains("written_only"), "{reached:?}");

        // The reader's schema does not have it, which is exactly why the walk does not read that.
        let mut reader = schemars::generate::SchemaSettings::draft2020_12().into_generator();
        let root = reader.subschema_for::<Written>().to_value();
        let reached =
            reach(&[root], &reader.take_definitions(false)).expect("a plain object is walked");
        assert!(!reached["Written"].contains("written_only"), "{reached:?}");

        #[derive(Serialize, JsonSchema)]
        struct ByNumber {
            entries: std::collections::BTreeMap<u32, String>,
        }
        #[derive(Serialize, JsonSchema)]
        struct ByName {
            entries: std::collections::BTreeMap<String, String>,
        }
        let mut generator = export_generator();
        let roots = [
            generator.subschema_for::<ByNumber>().to_value(),
            generator.subschema_for::<ByName>().to_value(),
        ];
        let defined = generator.take_definitions(false);
        for root in roots {
            let refused = reach(std::slice::from_ref(&root), &defined)
                .expect_err("a map reached from an export");
            assert!(refused.contains("a map ("), "{refused}");
        }

        // A member that holds any JSON value at all, documented or not. Its schema is `true`, or
        // an object of annotations alone, and either way nothing in it could be classed.
        #[derive(Serialize, JsonSchema)]
        struct Opaque {
            /// Whatever the sender put here.
            documented: serde_json::Value,
        }
        #[derive(Serialize, JsonSchema)]
        struct Bare {
            bare: serde_json::Value,
        }
        let mut generator = export_generator();
        let roots = [
            generator.subschema_for::<Opaque>().to_value(),
            generator.subschema_for::<Bare>().to_value(),
        ];
        let defined = generator.take_definitions(false);
        for root in roots {
            let refused = reach(std::slice::from_ref(&root), &defined)
                .expect_err("a member of any shape reached from an export");
            assert!(refused.contains("any shape"), "{refused}");
        }
    }

    /// KR-REQ-26.44: a build identity is named in full, and nothing else gets in through it.
    ///
    /// The text reaches a bundle out of a reply, so the parse is what admits it, and what the
    /// parse keeps is a word from a closed set and three numbers. Anything else - a marker, a
    /// sentence, a path, a header, a token that happens to be spelled in letters and digits - is
    /// not a build identity and never becomes one by arriving in the field for one.
    #[test]
    fn a_build_identity_is_the_one_shape_that_may_be_named_in_full() {
        for named in ["kr/0.1.0", "kr-controller/0.1.0", "kr-worker/12.3.456"] {
            let build = export::BuildIdentity::parse(named)
                .unwrap_or_else(|| panic!("{named} is a build identity"));
            assert_eq!(export::Sentence::new().identifier(&build).render(), named);
        }
        for refused in [
            PLANTED,
            "",
            "kr",
            "/0.1.0",
            "kr/",
            "kr/0.1.0 token opensesame",
            "kr/0.1.0\topensesame",
            "kr/0.1.0\u{7}",
            "KR/0.1.0",
            "kr9/0.1.0",
            "kr/0.1.0/extra",
            // The shapes a looser rule would have admitted: an unknown component, a token in the
            // version, build metadata, a prerelease tag, a version part that is not a number.
            "home/hunter2",
            "kr-controller/sk-live-abc123",
            "kr-controller/0.1.0+sk-live-abc123",
            "kr-controller/0.1.0-rc1",
            "kr-worker/0.1.0+g1a2b3c4d.x86_64-unknown-linux-gnu",
            "kr-test/0.1.0",
            "kr/0.1",
            "kr/0.1.0.0",
            "https://operator:hunter2@relay.example.com",
            "Bearer aGVsbG8gdGhlcmU",
            "/home/someone/.config/kalareach/config.json",
            "kr/0.1.0+\u{e9}",
        ] {
            assert!(
                export::BuildIdentity::parse(refused).is_none(),
                "{refused:?} is not a build identity"
            );
        }
        // A number too long to be one, which is the other half of the shape.
        let long_version = format!("kr/{}.1.0", "9".repeat(10));
        assert!(
            export::BuildIdentity::parse(&long_version).is_none(),
            "{long_version:?} is longer than a version part"
        );
        // Nothing of the parsed text is kept, so what is rendered is this build's own arithmetic
        // rather than the spelling a reply used.
        let padded = export::BuildIdentity::parse("kr/00.01.000").expect("three numbers");
        assert_eq!(
            export::Sentence::new().identifier(&padded).render(),
            "kr/0.1.0"
        );
        assert_eq!(padded.component(), export::BuildComponent::CommandLine);
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

    /// The bytes a probe read for the boot a test host is in.
    const BOOT_BYTES: [u8; 16] = [
        0x5a, 0x17, 0xc3, 0x09, 0x8e, 0x42, 0x4d, 0x61, 0xb0, 0x2f, 0x93, 0x7c, 0x11, 0xe8, 0x06,
        0xd4,
    ];

    /// One desktop context, populated the way a probe reports one.
    fn a_desktop() -> crate::desktop::DesktopContext {
        crate::desktop::DesktopContext {
            desktop_session_id: Nullable(crate::ids::DesktopSessionId::new("kr-someone").ok()),
            kind: crate::desktop::DesktopSessionKind::None,
            platform_session: Nullable::some("console".to_owned()),
            login_generation: Nullable(None),
            generation_source: crate::desktop::DesktopGenerationSource::Unavailable,
            os_user: "someone".to_owned(),
            uid: Nullable(None),
            boot_identity: BootIdentity {
                source: crate::identity::BootIdentitySource::MacosBootSessionUuid,
                value: crate::scalars::Bytes::new(BOOT_BYTES.to_vec()),
            },
            graphic_access: false,
            remote: false,
            availability: crate::desktop::DesktopAvailability::Unknown,
            container: crate::desktop::ContainerEnvironment::Host,
            display_server: crate::desktop::DisplayServer::None,
            compositor: Nullable::some("quartz".to_owned()),
            worker_profile: WorkerProfile::HeadlessUser,
        }
    }

    /// One capability record, populated the way a worker process reports one.
    fn capability_record() -> crate::desktop::CapabilityRecord {
        crate::desktop::CapabilityRecord {
            disabled_reason: Nullable::some("the platform refused".to_owned()),
            subject: crate::desktop::CapabilitySubject {
                desktop_session_id: Nullable(crate::ids::DesktopSessionId::new("kr-someone").ok()),
                application: Nullable::some("Terminal".to_owned()),
                terminal: Nullable::some("xterm-256color".to_owned()),
                session_id: Nullable(None),
                environment_id: an_environment(),
            },
            identity: crate::desktop::CapabilityIdentity {
                binary: Nullable::some("/usr/local/bin/kr-worker".to_owned()),
                version: Nullable::some("0.1.0".to_owned()),
                package: Nullable::some("kalareach".to_owned()),
                schema: Nullable::some("1".to_owned()),
                profile: Nullable::some(WorkerProfile::HeadlessUser),
            },
            capability: crate::ids::CapabilityId::new(crate::desktop::capabilities::SCREEN_CAPTURE)
                .expect("a capability"),
            version: crate::scalars::U64::new(1),
            revision: crate::ids::CapabilityRevision::new(1),
            state: crate::desktop::CapabilityState::PermissionRequired,
            evidence_source: crate::desktop::CapabilityEvidenceSource::DisclosedProbe,
            invalidation: Vec::new(),
            observed_at_ms: TimestampMs::new(0),
        }
    }

    /// The marker the class test plants in every text-bearing field.
    ///
    /// Spelled so that no identifier, no wire word and no enumeration in this crate accepts it:
    /// a field that takes it is a field arbitrary text fits in, which is exactly the set this
    /// test is about.
    const PLANTED: &str = "opensesame marker!! 42";

    /// Returns `value` with every string leaf that can hold [`PLANTED`] holding it.
    ///
    /// Each leaf is replaced in turn and kept only when the whole document still parses back into
    /// `T`, which is the type a reader of this document gets. A field with a typed value - an
    /// identifier, a closed enumeration, a number - refuses the marker and keeps what it had, so
    /// what comes back is the set of fields a caller could put anything in. Nothing here consults
    /// the type's field list, so a field added tomorrow is covered on the day it is added.
    ///
    /// The written type and the read type are separate parameters because a support bundle has
    /// one of each: this host composes a [`ComposedBundle`] and a reader parses a
    /// [`SupportBundle`] out of the same text.
    fn plant_everywhere<S: Serialize, T: serde::de::DeserializeOwned>(
        value: &S,
    ) -> (serde_json::Value, usize) {
        fn leaves(value: &serde_json::Value, at: &mut Vec<Vec<String>>, path: Vec<String>) {
            match value {
                serde_json::Value::String(_) => at.push(path),
                serde_json::Value::Array(items) => {
                    for (index, item) in items.iter().enumerate() {
                        let mut next = path.clone();
                        next.push(index.to_string());
                        leaves(item, at, next);
                    }
                }
                serde_json::Value::Object(fields) => {
                    for (name, field) in fields {
                        let mut next = path.clone();
                        next.push(name.clone());
                        leaves(field, at, next);
                    }
                }
                _ => {}
            }
        }

        fn at<'a>(
            value: &'a mut serde_json::Value,
            path: &[String],
        ) -> Option<&'a mut serde_json::Value> {
            let mut cursor = value;
            for step in path {
                cursor = match cursor {
                    serde_json::Value::Array(items) => {
                        items.get_mut(step.parse::<usize>().ok()?)?
                    }
                    serde_json::Value::Object(fields) => fields.get_mut(step)?,
                    _ => return None,
                };
            }
            Some(cursor)
        }

        let mut document = serde_json::to_value(value).expect("the value serialises");
        let mut paths = Vec::new();
        leaves(&document, &mut paths, Vec::new());
        let mut planted = 0;
        for path in paths {
            let mut attempt = document.clone();
            let Some(leaf) = at(&mut attempt, &path) else {
                continue;
            };
            let previous = leaf.clone();
            *leaf = serde_json::Value::String(PLANTED.to_owned());
            if serde_json::from_value::<T>(attempt.clone()).is_ok() {
                document = attempt;
                planted += 1;
            } else {
                let _ = previous;
            }
        }
        (document, planted)
    }

    /// KR-REQ-26.44: no text that arrived by reading leaves this host as its own words.
    ///
    /// The class rather than the sites. Each export root is serialised, every string field that
    /// can hold arbitrary text is filled with a marker, the result is *deserialised* - which is
    /// the route every value that did not originate here takes - and then exported. The marker
    /// must not survive.
    ///
    /// What makes this hold is that each such field carries its own provenance: a
    /// [`export::Stated`] or an [`export::Sentence`] knows whether this process composed it, and
    /// reading clears that. A field that is a plain `String` here would fail this test the day it
    /// was added, whatever its class says and whichever caller filled it.
    #[test]
    fn nothing_this_host_parsed_leaves_it_as_something_this_host_said() {
        use export::ForExport as _;

        let mut effective = EffectiveConfiguration::unread();
        effective.document = "/home/someone/.config/kalareach/config.json".to_owned();
        effective.runtime_directory = "/run/user/1000/kalareach/ab12cd34".to_owned();
        effective.state_directory = "/home/someone/.local/state/kalareach/ab12cd34".to_owned();
        effective.status = configuration::DocumentStatus {
            state: configuration::DocumentState::Loaded,
            detail: export::Sentence::new().stated("version 1"),
        };
        effective.locations = vec![ReportedLocation {
            what: "state_directory".to_owned(),
            documented: export::Stated::new(configuration::DOCUMENTED_STATE_ROOT),
        }];
        effective.values = vec![EffectiveValue::new(
            "sleep_inhibition",
            "whether this host keeps itself awake",
            &export::Declared::term("mains_only"),
            configuration::ValueSource::HostConfiguration,
            Nullable::some("/home/someone/.config/kalareach/config.json".to_owned()),
            Nullable::some("KR_STATE_DIR".to_owned()),
            configuration::ValueEffect::Immediately,
        )];
        effective.ceilings = vec![CeilingValue {
            key: "session_limit".to_owned(),
            configured: Nullable::some(export::Sentence::new().number(16)),
            value: export::Sentence::new().number(4),
            source: configuration::ValueSource::HostConfiguration,
            origin: Nullable::some("/home/someone/.config/kalareach/config.json".to_owned()),
            effect: configuration::ValueEffect::Immediately,
            narrowed_by: Nullable::some(export::Sentence::new().stated("this machine's resources")),
            refused: true,
        }];
        effective.overrides = vec![OverrideReport {
            variable: "KR_STATE_DIR".to_owned(),
            preference: "state_directory".to_owned(),
            position: configuration::ValueSource::Request,
            why: export::Stated::new("it names where this host keeps its own state"),
            set: true,
        }];
        effective.secrets = vec![configuration::SecretReference {
            name: "relay".to_owned(),
            store: "login_keychain".to_owned(),
            item: "kalareach/relay".to_owned(),
        }];
        effective.stale_documents = vec!["/home/someone/.local/state/power.json".to_owned()];
        effective.not_in_force =
            Nullable::some(export::Sentence::new().stated("the registry refused the write"));
        effective.fence_outstanding =
            Nullable::some(export::Sentence::new().stated("one worker has not answered"));

        let result = HostDoctorResult::new(
            vec![DoctorCheck::new(
                "runtime-directory",
                "The runtime directory is owner-only",
                DoctorStatus::Warning,
                export::Sentence::new().stated("it is owner-only"),
                Some("Nothing to do."),
            )],
            effective,
        );
        let bundle = ComposedBundle::new(
            TimestampMs::new(1),
            vec![SoftwareComponent {
                component: export::Stated::new("kr"),
                version: export::Sentence::new().stated("0.1.0"),
            }],
            vec![capability_record()],
            result.clone(),
            vec![RedactedError::new("controller", "a library said something")],
        )
        .with_content(ContentExport {
            includes: vec![export::Sentence::new().stated("every live session")],
            entries: vec![export::Sentence::new().stated("content/sessions.json")],
        });

        // A bundle somebody else's host wrote, opened here and put into one of ours.
        let (planted, count) = plant_everywhere::<_, SupportBundle>(&bundle);
        assert!(count > 20, "the marker reached {count} fields");
        let parsed: SupportBundle = serde_json::from_value(planted).expect("a bundle parses");
        let reexported = ComposedBundle::new(
            TimestampMs::new(2),
            parsed.software.clone(),
            parsed
                .capabilities
                .iter()
                .map(|record| record.get().clone())
                .collect(),
            parsed.doctor.get().clone(),
            parsed.errors.clone(),
        )
        .with_content(
            parsed
                .content
                .as_ref()
                .expect("the selection survives the parse")
                .clone(),
        );
        let written = serde_json::to_string(&reexported).expect("the bundle serialises");
        assert!(!written.contains(PLANTED), "{written}");

        // A `host.doctor` reply, parsed by a command and put into a bundle of this host's own.
        let (planted, count) = plant_everywhere::<_, HostDoctorResult>(&result);
        assert!(count > 15, "the marker reached {count} fields");
        let parsed: HostDoctorResult = serde_json::from_value(planted).expect("a reply parses");
        let written = serde_json::to_string(&parsed.for_export()).expect("the export serialises");
        assert!(!written.contains(PLANTED), "{written}");

        // Capability evidence a worker process reported.
        let (planted, count) =
            plant_everywhere::<_, crate::desktop::CapabilityRecord>(&capability_record());
        assert!(count > 3, "the marker reached {count} fields");
        let parsed: crate::desktop::CapabilityRecord =
            serde_json::from_value(planted).expect("a record parses");
        let written = serde_json::to_string(&parsed.for_export()).expect("the export serialises");
        assert!(!written.contains(PLANTED), "{written}");

        // The whole `environment.capabilities` answer, which is what a paired device is sent.
        let answer = crate::desktop::EnvironmentCapabilitiesResult {
            environment_id: an_environment(),
            desktop: crate::desktop::DesktopCapabilityReport {
                desktop: a_desktop(),
                records: vec![capability_record()],
            },
            default_worker_profile: WorkerProfile::HeadlessUser,
            persistence: vec![crate::desktop::ProfilePersistence::new(
                WorkerProfile::HeadlessUser,
                crate::desktop::LogoutPersistence::NotEstablished,
                "launchd, a per-user job in the background domain",
                "what a logout does here is not established",
            )],
            power: crate::desktop::SleepInhibitionState {
                holder: Nullable::some("com.apple.powerd".to_owned()),
                withheld_reason: Nullable::some("no session has verified work".to_owned()),
                ..crate::desktop::SleepInhibitionState::off(
                    crate::desktop::InhibitionMechanism::None,
                    crate::desktop::PowerSource::Unknown,
                )
            },
        };
        let (planted, count) =
            plant_everywhere::<_, crate::desktop::EnvironmentCapabilitiesResult>(&answer);
        assert!(count > 8, "the marker reached {count} fields");
        let parsed: crate::desktop::EnvironmentCapabilitiesResult =
            serde_json::from_value(planted).expect("an answer parses");
        let written = serde_json::to_string(&export::ForExport::for_export(parsed))
            .expect("the export serialises");
        assert!(!written.contains(PLANTED), "{written}");

        // The host's metadata, which is what `host.info` sends a paired device.
        let (planted, count) = plant_everywhere::<_, HostInfoResult>(&a_host_info());
        assert!(count >= 3, "the marker reached {count} fields");
        let parsed: HostInfoResult = serde_json::from_value(planted).expect("an answer parses");
        let written = serde_json::to_string(&export::ForExport::for_export(parsed))
            .expect("the export serialises");
        assert!(!written.contains(PLANTED), "{written}");

        // The environments, which is what `environment.list` sends a paired device.
        let (planted, count) = plant_everywhere::<_, EnvironmentListResult>(&an_environment_list());
        assert!(count >= 6, "the marker reached {count} fields");
        let parsed: EnvironmentListResult =
            serde_json::from_value(planted).expect("an answer parses");
        let written = serde_json::to_string(&export::ForExport::for_export(parsed))
            .expect("the export serialises");
        assert!(!written.contains(PLANTED), "{written}");
    }

    /// One host's metadata, as the owner's own socket is answered with it.
    fn a_host_info() -> HostInfoResult {
        HostInfoResult {
            build_id: crate::ids::BuildId::new("kr-controller/0.1.0").expect("a build"),
            protocol_version: crate::hello::ProtocolVersion::new(1, 0),
            environment_id: an_environment(),
            generation: crate::ids::ControllerGeneration::new(3),
            boot_identity: a_desktop().boot_identity,
            started_at_ms: TimestampMs::new(1),
            live_sessions: U64::new(2),
            session_limit: U64::new(128),
            default_worker_profile: WorkerProfile::HeadlessUser,
            power: crate::desktop::SleepInhibitionState {
                holder: Nullable::some("kalareach work for someone".to_owned()),
                withheld_reason: Nullable::some("someone asked for battery".to_owned()),
                ..crate::desktop::SleepInhibitionState::off(
                    crate::desktop::InhibitionMechanism::None,
                    crate::desktop::PowerSource::Unknown,
                )
            },
        }
    }

    /// One environment list, as the owner's own socket is answered with it.
    fn an_environment_list() -> EnvironmentListResult {
        EnvironmentListResult {
            environments: vec![EnvironmentSummary {
                environment_id: an_environment(),
                label: format!("someone on {}", std::env::consts::OS),
                os: std::env::consts::OS.to_owned(),
                arch: std::env::consts::ARCH.to_owned(),
                os_user: "someone".to_owned(),
                runtime_directory: "/run/user/1000/kalareach/03030303".to_owned(),
                state_directory: "/home/someone/.local/state/kalareach/environments/03030303"
                    .to_owned(),
                live_sessions: U64::new(2),
            }],
        }
    }

    /// KR-REQ-26.44: a paired device reads no account name and no local path of its host.
    ///
    /// The owner's own socket is answered with the display form of the four host reads, which
    /// names both, and everybody else with the export form. `environment.list` carries the
    /// operating-system user and the runtime and state directories, and its label names the
    /// account; `host.info` carries the name the platform shows for a sleep assertion, its reason
    /// and the boot's bytes. None of it reaches what a device is sent, and what is left still says
    /// which environment this is, what it runs on and how busy it is.
    #[test]
    fn a_device_reads_no_account_and_no_path_of_its_host() {
        let exported = export::ForExport::for_export(an_environment_list());
        let environment = &exported.get().environments[0];
        assert_eq!(
            environment.label,
            format!("environment 03030303 on {}", std::env::consts::OS),
            "the label says which environment this is without naming the account"
        );
        assert_eq!(environment.os, std::env::consts::OS);
        assert_eq!(environment.arch, std::env::consts::ARCH);
        assert_eq!(environment.os_user, "[name withheld, 7 bytes]");
        assert_eq!(environment.runtime_directory, "[path withheld, 33 bytes]");
        assert!(
            environment.state_directory.starts_with("[path withheld, "),
            "{}",
            environment.state_directory
        );
        assert_eq!(environment.live_sessions.get(), 2);
        let written = serde_json::to_string(&exported).expect("the export serialises");
        for leaked in ["someone", "/run/", "/home/", ".local"] {
            assert!(
                !written.contains(leaked),
                "{leaked} reached a device: {written}"
            );
        }

        let info = a_host_info();
        let exported = export::ForExport::for_export(info.clone());
        let sent = exported.get();
        assert_eq!(sent.build_id.as_str(), "kr-controller/0.1.0");
        assert_eq!(sent.boot_identity.source, info.boot_identity.source);
        assert!(sent.boot_identity.value.is_empty());
        assert_eq!(
            sent.power.holder.as_ref().map(String::as_str),
            Some("[name withheld, 26 bytes]")
        );
        assert_eq!(
            sent.power.withheld_reason.as_ref().map(String::as_str),
            Some("[message withheld, 25 bytes]")
        );
        assert_eq!(
            (sent.live_sessions, sent.session_limit, sent.environment_id),
            (info.live_sessions, info.session_limit, info.environment_id)
        );
        let written = serde_json::to_string(&exported).expect("the export serialises");
        assert!(!written.contains("someone"), "{written}");

        // A build identifier that is not one of this product's builds is a name like any other.
        let other = HostInfoResult {
            build_id: crate::ids::BuildId::new("kr-test/0").expect("a build identifier"),
            ..a_host_info()
        };
        assert_eq!(
            export::ForExport::for_export(other).get().build_id.as_str(),
            "[name withheld, 9 bytes]"
        );
    }

    /// KR-REQ-26.44: an exported boot identity says which facility it came from and carries none
    /// of its value, and the context this host keeps for itself keeps every byte.
    ///
    /// The marker walk cannot show this, because the value is bytes and a marker is not valid
    /// base64url: it would leave the field as it was. So the fixture carries real bytes, the reply
    /// is read back the way a command reads one, and the reduction is checked on what came back.
    #[test]
    fn an_exported_boot_identity_keeps_its_source_and_none_of_its_value() {
        let desktop = a_desktop();
        assert_eq!(desktop.boot_identity.value.as_slice(), BOOT_BYTES);
        let answer = crate::desktop::EnvironmentCapabilitiesResult {
            environment_id: an_environment(),
            desktop: crate::desktop::DesktopCapabilityReport {
                desktop: desktop.clone(),
                records: vec![capability_record()],
            },
            default_worker_profile: WorkerProfile::HeadlessUser,
            persistence: Vec::new(),
            power: crate::desktop::SleepInhibitionState::off(
                crate::desktop::InhibitionMechanism::None,
                crate::desktop::PowerSource::Unknown,
            ),
        };
        let read: crate::desktop::EnvironmentCapabilitiesResult =
            serde_json::from_value(serde_json::to_value(&answer).expect("the answer serialises"))
                .expect("a reply parses");
        assert_eq!(
            read.desktop.desktop.boot_identity, desktop.boot_identity,
            "the reply carries the bytes to be reduced"
        );

        let exported = export::ForExport::for_export(read.clone());
        let exported = exported.get();
        assert_eq!(
            exported.desktop.desktop.boot_identity.source, desktop.boot_identity.source,
            "which facility this platform reads is kept"
        );
        assert!(
            exported.desktop.desktop.boot_identity.value.is_empty(),
            "and none of the value leaves"
        );
        let written = serde_json::to_string(&exported).expect("the export serialises");
        assert!(
            !written.contains(&crate::scalars::to_base64url(&BOOT_BYTES)),
            "{written}"
        );
        assert_eq!(
            read.desktop.desktop.boot_identity, desktop.boot_identity,
            "the context this host compares against is untouched"
        );
    }

    /// KR-REQ-26.44: a row that declares its own class does not decide what its text is.
    ///
    /// The class travels in the same document the value did, so a row that arrived saying its
    /// value is a number, an identifier or another structure is making a claim about itself. The
    /// two classes a string can be checked against are checked; the rest are measured.
    #[test]
    fn a_class_a_document_supplied_does_not_carry_its_own_text() {
        for class in export::CLASSES {
            let carried = export::carry(class, PLANTED);
            assert!(
                !carried.contains(PLANTED),
                "a {} claimed beside arbitrary text: {carried}",
                class.as_str()
            );
        }
        // The two that are checked carry what actually is what it says.
        assert_eq!(export::carry(export::ContentClass::Number, "4096"), "4096");
        assert_eq!(
            export::carry(export::ContentClass::Term, "session_limit"),
            "session_limit"
        );

        let mut effective = EffectiveConfiguration::unread();
        effective.values = vec![EffectiveValue::new(
            "session_limit",
            "the most sessions this host admits",
            &export::Declared::number(4096),
            configuration::ValueSource::HostConfiguration,
            Nullable::null(),
            Nullable::null(),
            configuration::ValueEffect::Immediately,
        )];
        let result = HostDoctorResult::new(Vec::new(), effective);
        let mut document = serde_json::to_value(&result).expect("the result serialises");
        for class in ["number", "identifier", "structure", "stated", "term"] {
            let row = &mut document["configuration"]["values"][0];
            row["class"] = serde_json::Value::String(class.to_owned());
            row["value"] = serde_json::Value::String(PLANTED.to_owned());
            let parsed: HostDoctorResult =
                serde_json::from_value(document.clone()).expect("a reply parses");
            let written = serde_json::to_string(&export::ForExport::for_export(parsed))
                .expect("the export serialises");
            assert!(!written.contains(PLANTED), "declared {class}: {written}");
        }
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
        let listed = problems
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
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
            documented: export::Stated::new(configuration::DOCUMENTED_STATE_ROOT),
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
        let bundle = ComposedBundle::new(
            TimestampMs::new(0),
            Vec::new(),
            Vec::new(),
            shown,
            Vec::new(),
        );
        let exported = bundle.doctor().get();
        assert_eq!(exported.configuration.document, "[path withheld, 43 bytes]");
        assert_eq!(
            exported.configuration.state_directory,
            "[path withheld, 45 bytes]"
        );
        assert_eq!(
            exported.configuration.locations[0].documented.as_str(),
            configuration::DOCUMENTED_STATE_ROOT
        );
        assert_eq!(
            bundle.configuration().get().runtime_directory,
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
        let bundle = ComposedBundle::new(
            TimestampMs::new(0),
            Vec::new(),
            Vec::new(),
            HostDoctorResult::new(Vec::new(), effective),
            Vec::new(),
        );
        let exported = &bundle.configuration().get().values;
        assert_eq!(exported[0].value(), "[path withheld, 23 bytes]");
        assert_eq!(
            exported[1].value(),
            "mains_only",
            "and a word of this build's own leaves as itself"
        );
    }

    /// KR-REQ-26.44: the half a host writes and the half a person reads are one document.
    ///
    /// The two types are how a bundle that arrived is kept out of a writer, and the price of that
    /// would be too high if they were two file formats as well. So what a host composes parses
    /// back into what a reader gets, field for field, and a reader never learns that the writer
    /// held a different type.
    #[test]
    fn what_a_host_composes_is_what_a_reader_parses() {
        let composed = bundle_carrying("/home/someone/kalareach").with_content(ContentExport {
            includes: vec![export::Sentence::new().stated("every live session")],
            entries: vec![export::Sentence::new().stated("content/sessions.json")],
        });
        let written = serde_json::to_value(&composed).expect("the bundle serialises");
        let read: SupportBundle =
            serde_json::from_value(written.clone()).expect("a reader parses what a host wrote");
        assert_eq!(
            serde_json::to_value(&read).expect("the read half serialises"),
            written,
            "the two halves are one document"
        );
        assert!(
            read.content.is_present(),
            "including the selection the person made"
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
        let bundle = ComposedBundle::new(
            TimestampMs::new(0),
            Vec::new(),
            Vec::new(),
            HostDoctorResult::new(Vec::new(), configuration),
            vec![RedactedError::new("relay", secret)],
        );
        let measured = format!("[path withheld, {} bytes]", secret.len());
        assert_eq!(bundle.configuration().get().state_directory, measured);
        assert_eq!(
            bundle.errors()[0].message(),
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
        let unreadable = configuration::unreadable(
            export::Sentence::new().stated("this file must not be a symbolic link"),
        );
        assert_eq!(unreadable.revision(), prepared.based_on);
        assert!(configuration::still_current(&prepared, &unreadable).is_err());
        assert!(configuration::still_current(&prepared, &absent).is_ok());
    }

    /// KR-REQ-26.14: what this build reads outside the precedence is written down, not implied,
    /// and it is the platform's own naming of its locations and its login: a variable of this
    /// product's own either takes part in the precedence or is not read at all.
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
            assert!(
                !entry.variable.starts_with("KR_"),
                "{} is this product's own variable, read outside the precedence",
                entry.variable
            );
        }
        // KR-REQ-10.04: a host's owner is recorded through local IPC and nothing names it from
        // the environment, so no variable that could select one is read or listed.
        assert!(
            configuration::UNGOVERNED
                .iter()
                .all(|entry| !entry.variable.contains("OWNER")),
            "no variable names this host's owner"
        );
    }

    /// The variables that used to select this host's network and its voice broker.
    const FORMER_SELECTION_VARIABLES: [&str; 11] = [
        "KR_NETWORK",
        "KR_NETWORK_BIND",
        "KR_NETWORK_RELAYS",
        "KR_NETWORK_PKARR_PUBLISHER",
        "KR_NETWORK_PKARR_RESOLVER",
        "KR_NETWORK_DNS_ORIGIN",
        "KR_NETWORK_RELAY_CA",
        "KR_NETWORK_RELAY_ONLY",
        "KR_NETWORK_LOCAL_DISCOVERY",
        "KR_NETWORK_MAINLINE",
        "KR_VOICE_BROKER_ORIGIN",
    ];

    /// KR-REQ-26.14: a network selection and the voice broker's origin are this document's, and
    /// no environment variable is recorded as selecting one.
    ///
    /// Neither table names any of the variables that used to select them, and no allowlist entry
    /// can name a selection: an entry has to name a preference, and a selection is not one.
    #[test]
    fn no_inherited_variable_selects_the_network_or_the_voice_broker() {
        for variable in FORMER_SELECTION_VARIABLES {
            assert!(
                configuration::allowlisted(variable).is_none(),
                "{variable} is not an override"
            );
            assert!(
                configuration::UNGOVERNED
                    .iter()
                    .all(|entry| entry.variable != variable),
                "{variable} is not something this build reads"
            );
        }
        for selection in &configuration::SELECTIONS {
            assert!(
                configuration::preference(selection.key).is_none(),
                "{} is a selection, so no allowlist entry can supply it",
                selection.key
            );
            assert!(
                configuration::ALLOWLIST
                    .iter()
                    .all(|entry| entry.preference != selection.key),
                "{} is reached by an environment variable",
                selection.key
            );
        }
    }

    /// KR-REQ-26.14: the network section and the voice broker's origin are validated with the
    /// rest of the document, each value is named by its key and its class rather than repeated,
    /// and an edit to any section of a document that does not validate writes nothing.
    #[test]
    fn a_network_selection_is_validated_with_the_document_it_is_in() {
        let mut document = ConfigurationDocument::empty();
        document.network = configuration::NetworkSelection {
            enabled: Nullable::some(true),
            bind_address: Nullable::some("127.0.0.1:4433".to_owned()),
            relay_urls: Nullable::some(vec!["https://relay.example.com".to_owned()]),
            pkarr_publisher_url: Nullable::some("https://discovery.example.com/pkarr".to_owned()),
            pkarr_resolver_url: Nullable::some("http://127.0.0.1:8080/pkarr".to_owned()),
            dns_origin: Nullable::some("discovery.example.com".to_owned()),
            relay_trust_anchors: Nullable::some(vec!["/etc/kalareach/relay-ca.der".to_owned()]),
            relay_only: Nullable::some(true),
            local_discovery: Nullable::some(false),
            mainline_dht: Nullable::some(false),
            proxy_url: Nullable::some("http://proxy.example.com:3128".to_owned()),
        };
        document.voice.broker_origin = Nullable::some("https://voice.example.com".to_owned());
        configuration::validate(&document).expect("a complete selection");
        let written = configuration::contents(&document);
        let loaded = configuration::load(Some(written.as_bytes()));
        assert_eq!(loaded.status.state, DocumentState::Loaded);
        assert_eq!(
            loaded.document.as_ref(),
            Some(&document),
            "it reads back as written"
        );

        let secret = "hunter2";
        for (broken, key) in [
            (
                configuration::NetworkSelection {
                    bind_address: Nullable::some(format!("{secret}:4433")),
                    ..configuration::NetworkSelection::default()
                },
                "network.bind_address",
            ),
            (
                configuration::NetworkSelection {
                    relay_urls: Nullable::some(vec![format!("ftp://{secret}@relay.example.com")]),
                    ..configuration::NetworkSelection::default()
                },
                "network.relay_urls",
            ),
            (
                configuration::NetworkSelection {
                    relay_urls: Nullable::some(vec![format!("https://{secret}@relay.example.com")]),
                    ..configuration::NetworkSelection::default()
                },
                "network.relay_urls",
            ),
            (
                configuration::NetworkSelection {
                    pkarr_publisher_url: Nullable::some(format!("{secret}.example.com/pkarr")),
                    ..configuration::NetworkSelection::default()
                },
                "network.pkarr_publisher_url",
            ),
            (
                configuration::NetworkSelection {
                    pkarr_resolver_url: Nullable::some(format!("https:// {secret}")),
                    ..configuration::NetworkSelection::default()
                },
                "network.pkarr_resolver_url",
            ),
            (
                configuration::NetworkSelection {
                    dns_origin: Nullable::some(format!("https://{secret}.example.com")),
                    ..configuration::NetworkSelection::default()
                },
                "network.dns_origin",
            ),
            (
                configuration::NetworkSelection {
                    relay_trust_anchors: Nullable::some(vec![format!("{secret}/relay-ca.der")]),
                    ..configuration::NetworkSelection::default()
                },
                "network.relay_trust_anchors",
            ),
            (
                configuration::NetworkSelection {
                    relay_urls: Nullable::some(vec![
                        "https://relay.example.com".to_owned();
                        configuration::MAX_NETWORK_ENTRIES + 1
                    ]),
                    ..configuration::NetworkSelection::default()
                },
                "network.relay_urls",
            ),
            (
                configuration::NetworkSelection {
                    relay_only: Nullable::some(true),
                    ..configuration::NetworkSelection::default()
                },
                "network.relay_only",
            ),
        ] {
            let mut document = ConfigurationDocument::empty();
            document.network = broken;
            let problems = configuration::validate(&document).expect_err("a value it refuses");
            let said: Vec<&str> = problems.iter().map(export::Sentence::as_str).collect();
            assert!(
                said.iter().any(|problem| problem.contains(key)),
                "{key} is named: {said:?}"
            );
            assert!(
                said.iter().all(|problem| !problem.contains(secret)),
                "and its value is not repeated: {said:?}"
            );
        }
        // Every address the transport would refuse or rewrite is refused here, so a document that
        // validates never stops the daemon over its syntax.
        for refused in [
            "https://resolver.example:99999",
            "https://resolver.example:0",
            "https://resolver.example:0443",
            "https://resolver.example:443",
            "http://resolver.example:80",
            "http://127.1",
            "http://0x7f000001",
            "http://[0:0:0:0:0:0:0:1]",
            "http://[::ffff:192.0.2.1]",
            "https://Resolver.example",
            "https://resolver.example.",
            "https://xn--zz.example",
            "https://resolver.example/a/../pkarr",
            "https://resolver.example/./pkarr",
            "https://resolver.example/%70karr",
            "https://resolver.example/pkarr?query",
            "https://resolver.example/pkarr#fragment",
            "https://resolver.example?query",
            "https://@resolver.example",
            "https://",
        ] {
            let mut document = ConfigurationDocument::empty();
            document.network.pkarr_resolver_url = Nullable::some(refused.to_owned());
            document.network.relay_urls = Nullable::some(vec![refused.to_owned()]);
            let problems = configuration::validate(&document).expect_err("an address it refuses");
            for key in ["network.pkarr_resolver_url", "network.relay_urls"] {
                assert!(
                    problems
                        .iter()
                        .any(|problem| problem.as_str().contains(key)),
                    "{refused} in {key}: {problems:?}"
                );
            }
        }
        for accepted in [
            "https://relay.example.com",
            "https://relay.example.com/",
            "https://relay.example.com:8443/relay",
            "http://127.0.0.1:8080/pkarr",
            "http://[::1]:8080",
            "https://a1.be",
        ] {
            let mut document = ConfigurationDocument::empty();
            document.network.relay_urls = Nullable::some(vec![accepted.to_owned()]);
            configuration::validate(&document)
                .unwrap_or_else(|problems| panic!("{accepted}: {problems:?}"));
        }
        // The length an invitation carries, which is the URL as the transport writes it: one with
        // no path gains a `/`. The host is dotted labels of at most 60 characters, so the length
        // is the only rule these two URLs test.
        let host = |length: usize| {
            let mut left = length - "https://".len() - ".example".len();
            let mut labels: Vec<String> = Vec::new();
            while left > 0 {
                let dot = usize::from(!labels.is_empty());
                let take = (left - dot).min(60);
                assert!(take > 0, "a label is never empty");
                labels.push("a".repeat(take));
                left -= take + dot;
            }
            format!("https://{}.example", labels.join("."))
        };
        let longest_without_a_path = host(configuration::MAX_HINT_LEN - 1);
        assert_eq!(
            longest_without_a_path.len(),
            configuration::MAX_HINT_LEN - 1
        );
        let mut document = ConfigurationDocument::empty();
        document.network.relay_urls = Nullable::some(vec![longest_without_a_path]);
        configuration::validate(&document).expect("252 bytes, and 253 as written");
        document.network.relay_urls = Nullable::some(vec![host(configuration::MAX_HINT_LEN)]);
        configuration::validate(&document).expect_err("253 bytes, and 254 as written");

        for origin in [
            "voice.example.com",
            "https://voice.example.com/",
            "https://voice.example.com/path",
            "https://Voice.example.com",
            "https://voice.example.com:443",
            "http://voice.example.com:80",
            "https://voice.example:0443",
            "http://127.1",
            "http://[0:0:0:0:0:0:0:1]",
            "https://xn--zz.example",
            // Read by the broker as an address, and not the canonical spelling of one.
            "https://a1.be",
            "https://cafe.b0e",
        ] {
            let mut document = ConfigurationDocument::empty();
            document.voice.broker_origin = Nullable::some(origin.to_owned());
            let problems = configuration::validate(&document).expect_err("an origin it refuses");
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.as_str().contains("voice.broker_origin")),
                "{origin}: {problems:?}"
            );
        }

        // A document whose network section does not validate is not this host's to rewrite, so an
        // edit to any other section of it is refused rather than applied on top.
        let invalid = br#"{"version": 1, "network": {"enabled": true, "bind_address": "nowhere"}}"#;
        let loaded = configuration::load(Some(invalid));
        assert_eq!(loaded.status.state, DocumentState::Invalid);
        assert!(
            loaded
                .status
                .detail
                .as_str()
                .contains("network.bind_address"),
            "{:?}",
            loaded.status
        );
        assert!(
            configuration::edit(&loaded, &Change::SessionLimit(Some(4))).is_err(),
            "and an edit writes nothing"
        );
    }

    /// KR-REQ-10.02, KR-REQ-26.14: the endpoint's proxy is the document's to choose, and it is
    /// absent unless the document names it. It is an origin: an `https` or `http` scheme and a
    /// canonical authority with nothing after it. A proxy that names a user or a password is
    /// refused as one that needs credentials, which is not supported, whatever else is wrong with
    /// it. Every refusal names the key and never repeats the value, and a document that names a
    /// proxy it refuses is not this host's to rewrite. The value is reported where the document
    /// wrote it, as a location.
    #[test]
    fn a_proxy_is_an_origin_the_document_names_without_a_credential() {
        assert_eq!(configuration::NetworkSelection::default().proxy_url(), None);
        let rows = configuration::selection_rows(None, "/config.json");
        let row = rows
            .iter()
            .find(|row| row.key == "network.proxy_url")
            .expect("the proxy is reported");
        assert_eq!(
            (row.value(), row.source, row.effect),
            (
                "none",
                ValueSource::Default,
                configuration::ValueEffect::NextStart
            )
        );

        for accepted in [
            "http://proxy.example.com:3128",
            "https://proxy.example.com",
            "http://127.0.0.1:8080",
            "http://[::1]:3128",
        ] {
            let mut document = ConfigurationDocument::empty();
            document.network.proxy_url = Nullable::some(accepted.to_owned());
            configuration::validate(&document)
                .unwrap_or_else(|problems| panic!("{accepted}: {problems:?}"));
        }

        let secret = "hunter2";
        let credentials = [
            format!("http://user:{secret}@proxy.example.com:3128"),
            format!("http://{secret}@proxy.example.com:3128"),
            format!("https://:{secret}@proxy.example.com"),
            format!("socks5://user:{secret}@proxy.example.com:1080"),
            format!("http://@{secret}.example.com"),
            format!("http://:@{secret}.example.com"),
            format!("http://user:{secret}@proxy.example.com:99999"),
            format!("http:///@{secret}.example.com"),
            format!("http:///:@{secret}.example.com"),
            format!("https:\\\\user:{secret}@proxy.example.com"),
        ];
        let not_origins = [
            format!("socks5://{secret}.example.com:1080"),
            format!("ftp://{secret}.example.com"),
            format!("{secret}.example.com:3128"),
            format!("http://{secret}.example.com:3128/"),
            format!("http://proxy.example.com:3128/{secret}"),
            format!("http://proxy.example.com:3128?{secret}"),
            format!("http://proxy.example.com:3128#{secret}"),
            format!("http://proxy.example.com/{secret}@x"),
            format!("http://{secret}.example.com:80"),
            format!("https://{secret}.example.com:443"),
            format!("http://{secret}.Example.com:3128"),
            format!("http://{secret}.example.com:99999"),
            format!("http://{secret}.example.com:03128"),
            format!("https://xn--{secret}.example"),
            format!("http://{}.{secret}.example", "a".repeat(250)),
            "http://127.1:3128".to_owned(),
            "http://".to_owned(),
        ];
        for (refused, credential) in credentials
            .iter()
            .map(|value| (value, true))
            .chain(not_origins.iter().map(|value| (value, false)))
        {
            let mut document = ConfigurationDocument::empty();
            document.network.proxy_url = Nullable::some(refused.clone());
            let problems = configuration::validate(&document).expect_err("a proxy it refuses");
            let said: Vec<&str> = problems.iter().map(export::Sentence::as_str).collect();
            assert!(
                said.iter()
                    .any(|problem| problem.starts_with("network.proxy_url (")),
                "{refused}: the key is named: {said:?}"
            );
            assert!(
                said.iter().all(|problem| !problem.contains(secret)),
                "{refused}: and its value is not repeated: {said:?}"
            );
            assert_eq!(
                said.iter()
                    .any(|problem| problem
                        .ends_with("a proxy that needs credentials is not supported")),
                credential,
                "{refused}: a credential is refused as one: {said:?}"
            );
        }

        let written = format!(
            r#"{{"version": 1, "network": {{"enabled": true, "proxy_url": "http://user:{secret}@proxy.example.com:3128"}}}}"#
        );
        let loaded = configuration::load(Some(written.as_bytes()));
        assert_eq!(loaded.status.state, DocumentState::Invalid);
        assert!(
            loaded.status.detail.as_str().contains("network.proxy_url"),
            "{:?}",
            loaded.status
        );
        assert!(
            !loaded.status.detail.as_str().contains(secret),
            "{:?}",
            loaded.status
        );
        assert!(
            configuration::edit(&loaded, &Change::SessionLimit(Some(4))).is_err(),
            "and an edit writes nothing"
        );

        let mut document = ConfigurationDocument::empty();
        document.network.proxy_url = Nullable::some("http://proxy.example.com:3128".to_owned());
        let rows = configuration::selection_rows(Some(&document), "/config.json");
        let row = rows
            .iter()
            .find(|row| row.key == "network.proxy_url")
            .expect("the proxy is reported");
        assert_eq!(
            (row.value(), row.source, row.class()),
            (
                "http://proxy.example.com:3128",
                ValueSource::HostConfiguration,
                export::ContentClass::Location
            )
        );
        assert_eq!(row.origin.0.as_deref(), Some("/config.json"));
    }

    /// KR-REQ-26.14: each selection is reported with its value, its source and "at the next
    /// start", and the source is what the document wrote rather than what the value looks like.
    #[test]
    fn a_selection_is_reported_from_the_document_it_was_written_in() {
        let origin = "/home/someone/.config/kalareach/config.json";
        let defaults = configuration::selection_rows(None, origin);
        assert_eq!(
            defaults
                .iter()
                .map(|row| row.key.as_str())
                .collect::<Vec<_>>(),
            configuration::SELECTIONS
                .iter()
                .map(|selection| selection.key)
                .collect::<Vec<_>>()
        );
        for row in &defaults {
            assert_eq!(row.source, ValueSource::Default, "{}", row.key);
            assert_eq!(row.effect, configuration::ValueEffect::NextStart);
            assert!(row.origin.0.is_none());
            assert!(row.variable.0.is_none(), "no variable supplies a selection");
        }
        let enabled = |rows: &[EffectiveValue], key: &str| {
            rows.iter()
                .find(|row| row.key == key)
                .map(|row| (row.value().to_owned(), row.source, row.class()))
                .expect("the row")
        };
        assert_eq!(
            enabled(&defaults, "network.enabled"),
            (
                "false".to_owned(),
                ValueSource::Default,
                export::ContentClass::Term
            )
        );

        let mut document = ConfigurationDocument::empty();
        document.network.enabled = Nullable::some(false);
        document.network.relay_urls = Nullable::some(vec![
            "https://a.example.com".to_owned(),
            "https://b.example.com".to_owned(),
        ]);
        let rows = configuration::selection_rows(Some(&document), origin);
        assert_eq!(
            enabled(&rows, "network.enabled"),
            (
                "false".to_owned(),
                ValueSource::HostConfiguration,
                export::ContentClass::Term
            ),
            "a switch written off was chosen by whoever wrote it"
        );
        assert_eq!(
            enabled(&rows, "network.relay_urls"),
            (
                "https://a.example.com, https://b.example.com".to_owned(),
                ValueSource::HostConfiguration,
                export::ContentClass::Location
            )
        );
        assert_eq!(
            enabled(&rows, "network.dns_origin"),
            (
                "none".to_owned(),
                ValueSource::Default,
                export::ContentClass::Term
            )
        );

        // What leaves this host carries each location as its class and its length.
        let mut effective = EffectiveConfiguration::unread();
        effective.values = rows;
        let exported = export::ForExport::for_export(effective);
        let relays = exported
            .get()
            .values
            .iter()
            .find(|row| row.key == "network.relay_urls")
            .expect("the row");
        assert_eq!(relays.value(), "[location withheld, 44 bytes]");
        assert!(
            relays
                .origin
                .as_ref()
                .is_some_and(|origin| origin.starts_with("[name withheld,")),
            "{relays:?}"
        );
        let switch = exported
            .get()
            .values
            .iter()
            .find(|row| row.key == "network.enabled")
            .expect("the row");
        assert_eq!(
            switch.value(),
            "false",
            "a switch is a word of this build's own"
        );
    }

    /// The wire words a report names are exactly the ones the enumerations spell.
    #[test]
    fn the_wire_words_are_the_enumerations_own() {
        let mut spelled: Vec<&str> = Vec::new();
        spelled.extend(
            [
                DoctorStatus::Ok,
                DoctorStatus::Warning,
                DoctorStatus::Failed,
                DoctorStatus::NotApplicable,
            ]
            .map(DoctorStatus::as_str),
        );
        spelled.extend(
            [
                DocumentState::Absent,
                DocumentState::Loaded,
                DocumentState::UnknownVersion,
                DocumentState::Unreadable,
                DocumentState::Invalid,
            ]
            .map(DocumentState::as_str),
        );
        spelled.extend(configuration::PRECEDENCE.map(ValueSource::as_str));
        spelled.extend(
            [
                configuration::ValueEffect::Immediately,
                configuration::ValueEffect::NewSessionsOnly,
                configuration::ValueEffect::NextStart,
            ]
            .map(configuration::ValueEffect::as_str),
        );
        spelled.extend(
            [WorkerProfile::DesktopBound, WorkerProfile::HeadlessUser].map(WorkerProfile::as_str),
        );
        assert_eq!(spelled, configuration::WIRE_WORDS);
    }

    /// KR-REQ-26.13: a document declaring a version this build does not know is left alone.
    #[test]
    fn an_unknown_version_reads_as_defaults_and_says_so() {
        let loaded = configuration::load(Some(br#"{"version": 99, "preferences": {}}"#));
        assert_eq!(loaded.status.state, DocumentState::UnknownVersion);
        assert!(loaded.document.is_none(), "nothing is read out of it");
        assert!(
            loaded.status.detail.as_str().contains("99"),
            "{:?}",
            loaded.status
        );
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
            problems.iter().any(|problem| problem
                .as_str()
                .contains("default_profile ([name withheld, 7 bytes])")),
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
        let loaded = configuration::unreadable(
            export::Sentence::new().stated("this file must not be a symbolic link"),
        );
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
