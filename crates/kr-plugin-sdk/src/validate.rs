//! Package validation.
//!
//! This is the check a host runs before it trusts anything in a package, a publisher runs before
//! it signs one, and the catalogue pipeline runs on every package it indexes. All three run the
//! same code, so a package that a publisher's build accepted is a package a host accepts.
//!
//! Validation is total and offline. It reads the directory, parses the manifests, and reports
//! every finding it has rather than stopping at the first, because a publisher fixing a package
//! wants the whole list. It executes nothing: no script, no Wasm, no installation step. A signed
//! package establishes provenance, not safety, and this module is where the safety part happens.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::PluginCapability;
use crate::connector::{ConnectorManifest, MAX_CLASSIFIED_METHODS, MAX_FIELD_PATH_DEPTH};
use crate::digest::PayloadDigest;
use crate::effect::{MAX_PARAMETER_CHOICES, MAX_PARAMETERS, ParameterKind, ParameterSchema};
use crate::ids::ActionName;
use crate::package::{
    CONNECTOR_FILE, MANIFEST_FILE, MAX_PACKAGE_BYTES, MAX_PACKAGE_FILES, PRESENTATION_FILE,
    Package, PackageFile,
};
use crate::paths::{PackagePath, find_collisions};
use crate::plugin::{PayloadRole, PluginManifest};
use crate::presentation::{
    Control, MAX_CONTROLS, MAX_DOCUMENT_NODES, NodeBody, PresentationManifest,
};
use crate::version::{sdk_version, wit_version};

/// A stable code for one kind of finding.
///
/// Codes are part of the contract: a publisher's build, a catalogue pipeline and a host all
/// report the same code for the same defect, so a fixture can assert on it and a person can look
/// it up.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingCode {
    /// The package directory could not be read.
    DirectoryUnreadable,
    /// A required manifest was absent.
    ManifestMissing,
    /// A manifest did not parse against the closed schema.
    ManifestUnreadable,
    /// The manifest format version is not the one this build reads.
    ManifestVersionUnsupported,
    /// A path in the package is unsafe.
    UnsafePath,
    /// A directory entry is not a regular file.
    NotARegularFile,
    /// Two paths name the same file after case folding.
    CaseCollidingPath,
    /// The manifest declares the same path twice.
    DuplicatePath,
    /// A file is on disk that the manifest does not declare.
    UndeclaredFile,
    /// The manifest declares a file that is not on disk.
    MissingPayload,
    /// A file's length is not the length the manifest declared.
    SizeMismatch,
    /// A file's digest is not the digest the manifest declared.
    DigestMismatch,
    /// The package is larger than one package may be.
    PackageTooLarge,
    /// The package holds more files than one package may.
    TooManyFiles,
    /// A version range admits every version.
    UnboundedVersionRange,
    /// A version range excludes the SDK that would have to run the package.
    VersionRangeExcludesHost,
    /// The package declares no match rule, so nothing would ever activate it.
    NoMatchRules,
    /// The package declares no platform, so nothing would ever run it.
    NoPlatforms,
    /// Two actions share an identifier.
    DuplicateActionId,
    /// A control names an action the manifest does not register.
    ActionNotRegistered,
    /// An action declares an effect class whose capability the package does not request.
    EffectWithoutCapability,
    /// The package requests the same capability twice.
    DuplicateCapability,
    /// The package ships a native bridge without requesting the capability to install one.
    BridgeWithoutCapability,
    /// The package contributes attachments without requesting the capability to act upstream.
    AttachmentWithoutCapability,
    /// A visibility predicate breaks the grammar's bounds.
    PredicateInvalid,
    /// A parameter schema breaks its bounds.
    ParameterSchemaInvalid,
    /// The presentation document holds more nodes or controls than one document may.
    DocumentTooLarge,
    /// The voice projection names a node or control the document does not hold.
    VoiceProjectionUnknown,
    /// A connector table breaks its bounds.
    ConnectorTableInvalid,
    /// A connector table classifies a method it never routes.
    ConnectorMethodUnrouted,
    /// The manifest declares a connector payload but the package has no connector table.
    ConnectorPayloadMissing,
    /// The package ships a connector table the manifest does not declare.
    ConnectorUndeclared,
    /// The connector belongs to a different package.
    ConnectorPluginMismatch,
    /// An action declares an effect class that is not in the closed vocabulary.
    UnknownEffectClass,
    /// The package requests a capability that is not in the closed vocabulary.
    UnknownCapability,
}

impl FindingCode {
    /// Every finding code, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::DirectoryUnreadable,
        Self::ManifestMissing,
        Self::ManifestUnreadable,
        Self::ManifestVersionUnsupported,
        Self::UnsafePath,
        Self::NotARegularFile,
        Self::CaseCollidingPath,
        Self::DuplicatePath,
        Self::UndeclaredFile,
        Self::MissingPayload,
        Self::SizeMismatch,
        Self::DigestMismatch,
        Self::PackageTooLarge,
        Self::TooManyFiles,
        Self::UnboundedVersionRange,
        Self::VersionRangeExcludesHost,
        Self::NoMatchRules,
        Self::NoPlatforms,
        Self::DuplicateActionId,
        Self::ActionNotRegistered,
        Self::EffectWithoutCapability,
        Self::DuplicateCapability,
        Self::BridgeWithoutCapability,
        Self::AttachmentWithoutCapability,
        Self::PredicateInvalid,
        Self::ParameterSchemaInvalid,
        Self::DocumentTooLarge,
        Self::VoiceProjectionUnknown,
        Self::ConnectorTableInvalid,
        Self::ConnectorMethodUnrouted,
        Self::ConnectorPayloadMissing,
        Self::ConnectorUndeclared,
        Self::ConnectorPluginMismatch,
        Self::UnknownEffectClass,
        Self::UnknownCapability,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectoryUnreadable => "directory_unreadable",
            Self::ManifestMissing => "manifest_missing",
            Self::ManifestUnreadable => "manifest_unreadable",
            Self::ManifestVersionUnsupported => "manifest_version_unsupported",
            Self::UnsafePath => "unsafe_path",
            Self::NotARegularFile => "not_a_regular_file",
            Self::CaseCollidingPath => "case_colliding_path",
            Self::DuplicatePath => "duplicate_path",
            Self::UndeclaredFile => "undeclared_file",
            Self::MissingPayload => "missing_payload",
            Self::SizeMismatch => "size_mismatch",
            Self::DigestMismatch => "digest_mismatch",
            Self::PackageTooLarge => "package_too_large",
            Self::TooManyFiles => "too_many_files",
            Self::UnboundedVersionRange => "unbounded_version_range",
            Self::VersionRangeExcludesHost => "version_range_excludes_host",
            Self::NoMatchRules => "no_match_rules",
            Self::NoPlatforms => "no_platforms",
            Self::DuplicateActionId => "duplicate_action_id",
            Self::ActionNotRegistered => "action_not_registered",
            Self::EffectWithoutCapability => "effect_without_capability",
            Self::DuplicateCapability => "duplicate_capability",
            Self::BridgeWithoutCapability => "bridge_without_capability",
            Self::AttachmentWithoutCapability => "attachment_without_capability",
            Self::PredicateInvalid => "predicate_invalid",
            Self::ParameterSchemaInvalid => "parameter_schema_invalid",
            Self::DocumentTooLarge => "document_too_large",
            Self::VoiceProjectionUnknown => "voice_projection_unknown",
            Self::ConnectorTableInvalid => "connector_table_invalid",
            Self::ConnectorMethodUnrouted => "connector_method_unrouted",
            Self::ConnectorPayloadMissing => "connector_payload_missing",
            Self::ConnectorUndeclared => "connector_undeclared",
            Self::ConnectorPluginMismatch => "connector_plugin_mismatch",
            Self::UnknownEffectClass => "unknown_effect_class",
            Self::UnknownCapability => "unknown_capability",
        }
    }
}

/// One thing wrong with a package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Finding {
    /// What kind of thing it is.
    pub code: FindingCode,
    /// Where in the package it is, where it is in one place.
    pub path: Option<String>,
    /// What exactly is wrong.
    pub detail: String,
}

impl Finding {
    fn new(code: FindingCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            path: None,
            detail: detail.into(),
        }
    }

    fn at(code: FindingCode, path: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code,
            path: Some(path.into()),
            detail: detail.into(),
        }
    }
}

impl core::fmt::Display for Finding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.path {
            Some(path) => write!(formatter, "{}: {path}: {}", self.code.as_str(), self.detail),
            None => write!(formatter, "{}: {}", self.code.as_str(), self.detail),
        }
    }
}

/// Everything validation found.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Report {
    /// The findings, in the order they were produced.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Returns true when nothing is wrong.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns the distinct finding codes, in a stable order.
    #[must_use]
    pub fn codes(&self) -> Vec<FindingCode> {
        let unique: BTreeSet<FindingCode> = self.findings.iter().map(|f| f.code).collect();
        unique.into_iter().collect()
    }

    /// Returns true when the report holds at least one finding with this code.
    #[must_use]
    pub fn has(&self, code: FindingCode) -> bool {
        self.findings.iter().any(|finding| finding.code == code)
    }

    fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }
}

/// The outcome of validating a package directory.
#[derive(Clone, Debug)]
pub struct Validated {
    /// The package, where enough of it parsed to build one.
    pub package: Option<Package>,
    /// Everything that is wrong with it.
    pub report: Report,
}

/// Validates a package directory.
///
/// Nothing in the directory is executed. Symbolic links are rejected rather than followed, so a
/// package cannot reach outside itself by pointing at something.
#[must_use]
pub fn validate_package_directory(directory: &Path) -> Validated {
    let mut report = Report::default();
    let files = match scan(directory, &mut report) {
        Some(files) => files,
        None => {
            return Validated {
                package: None,
                report,
            };
        }
    };

    check_file_set(&files, &mut report);

    let Some(manifest) = read_plugin_manifest(directory, &mut report) else {
        return Validated {
            package: None,
            report,
        };
    };
    let presentation =
        read_manifest::<PresentationManifest>(directory, PRESENTATION_FILE, &mut report);
    let connector_present = directory.join(CONNECTOR_FILE).is_file();
    let connector = if connector_present {
        read_manifest::<ConnectorManifest>(directory, CONNECTOR_FILE, &mut report)
    } else {
        None
    };

    check_manifest(&manifest, &mut report);
    check_payloads(&manifest, &files, &mut report);
    if let Some(presentation) = &presentation {
        check_presentation(&manifest, presentation, &mut report);
    }
    check_connector_presence(
        &manifest,
        connector_present,
        connector.as_ref(),
        &mut report,
    );
    if let Some(connector) = &connector {
        check_connector(connector, &mut report);
    }

    let package = presentation.map(|presentation| Package {
        manifest,
        presentation,
        connector,
        files,
    });
    Validated { package, report }
}

fn scan(directory: &Path, report: &mut Report) -> Option<Vec<PackageFile>> {
    if !directory.is_dir() {
        report.push(Finding::new(
            FindingCode::DirectoryUnreadable,
            format!("{} is not a directory", directory.display()),
        ));
        return None;
    }
    let mut files = Vec::new();
    let mut queue: Vec<(PathBuf, Vec<String>)> = vec![(directory.to_path_buf(), Vec::new())];
    while let Some((current, prefix)) = queue.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error) => {
                report.push(Finding::new(
                    FindingCode::DirectoryUnreadable,
                    format!("{}: {error}", current.display()),
                ));
                return None;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    report.push(Finding::new(
                        FindingCode::DirectoryUnreadable,
                        format!("{}: {error}", current.display()),
                    ));
                    return None;
                }
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let mut segments = prefix.clone();
            segments.push(name.clone());
            let relative = segments.join("/");
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) => {
                    report.push(Finding::at(
                        FindingCode::DirectoryUnreadable,
                        relative,
                        error.to_string(),
                    ));
                    continue;
                }
            };
            if metadata.is_symlink() {
                report.push(Finding::at(
                    FindingCode::NotARegularFile,
                    relative,
                    "a package holds regular files only; a link can point outside the package",
                ));
                continue;
            }
            if metadata.is_dir() {
                if let Err(rejection) = PackagePath::new(relative.clone()) {
                    report.push(Finding::at(
                        FindingCode::UnsafePath,
                        relative,
                        rejection.to_string(),
                    ));
                    continue;
                }
                queue.push((entry.path(), segments));
                continue;
            }
            if !metadata.is_file() {
                report.push(Finding::at(
                    FindingCode::NotARegularFile,
                    relative,
                    "a package holds regular files only",
                ));
                continue;
            }
            let path = match PackagePath::new(relative.clone()) {
                Ok(path) => path,
                Err(rejection) => {
                    report.push(Finding::at(
                        FindingCode::UnsafePath,
                        relative,
                        rejection.to_string(),
                    ));
                    continue;
                }
            };
            match fs::read(entry.path()) {
                Ok(bytes) => files.push(PackageFile {
                    path,
                    size_bytes: bytes.len() as u64,
                    digest: PayloadDigest::of(&bytes),
                }),
                Err(error) => report.push(Finding::at(
                    FindingCode::DirectoryUnreadable,
                    relative,
                    error.to_string(),
                )),
            }
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Some(files)
}

fn check_file_set(files: &[PackageFile], report: &mut Report) {
    if files.len() > MAX_PACKAGE_FILES {
        report.push(Finding::new(
            FindingCode::TooManyFiles,
            format!(
                "the package holds {} files, over the {MAX_PACKAGE_FILES} file limit",
                files.len()
            ),
        ));
    }
    let total: u64 = files.iter().map(|file| file.size_bytes).sum();
    if total > MAX_PACKAGE_BYTES {
        report.push(Finding::new(
            FindingCode::PackageTooLarge,
            format!("the package is {total} bytes, over the {MAX_PACKAGE_BYTES} byte limit"),
        ));
    }
    let paths: Vec<PackagePath> = files.iter().map(|file| file.path.clone()).collect();
    for collision in find_collisions(&paths) {
        report.push(Finding::at(
            FindingCode::CaseCollidingPath,
            collision.second.to_string(),
            format!(
                "names the same file as {} on a case-insensitive filesystem",
                collision.first
            ),
        ));
    }
}

fn read_manifest<T: serde::de::DeserializeOwned>(
    directory: &Path,
    name: &str,
    report: &mut Report,
) -> Option<T> {
    let path = directory.join(name);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            report.push(Finding::at(
                FindingCode::ManifestMissing,
                name,
                "every package carries this manifest",
            ));
            return None;
        }
        Err(error) => {
            report.push(Finding::at(
                FindingCode::ManifestUnreadable,
                name,
                error.to_string(),
            ));
            return None;
        }
    };
    match serde_json::from_str::<T>(&text) {
        Ok(value) => Some(value),
        Err(error) => {
            report.push(Finding::at(
                FindingCode::ManifestUnreadable,
                name,
                error.to_string(),
            ));
            None
        }
    }
}

/// Reads `plugin.json` in two stages.
///
/// The closed vocabularies and the declared paths are checked against the raw document first, so
/// an unsafe path or an invented effect class is reported as itself rather than as a parse error
/// in a nested field. A package that fails either check is not parsed further: a manifest whose
/// paths cannot be trusted is not a manifest a host reads the rest of.
fn read_plugin_manifest(directory: &Path, report: &mut Report) -> Option<PluginManifest> {
    let raw = read_manifest::<serde_json::Value>(directory, MANIFEST_FILE, report)?;
    let before = report.findings.len();
    check_declared_paths(&raw, report);
    check_closed_vocabularies(&raw, report);
    if report.findings.len() > before {
        return None;
    }
    match serde_json::from_value::<PluginManifest>(raw) {
        Ok(manifest) => Some(manifest),
        Err(error) => {
            report.push(Finding::at(
                FindingCode::ManifestUnreadable,
                MANIFEST_FILE,
                error.to_string(),
            ));
            None
        }
    }
}

/// The manifest members that name a file.
const PATH_MEMBERS: &[&str] = &["path", "source", "destination", "file"];

/// Checks every declared path in the raw manifest.
fn check_declared_paths(value: &serde_json::Value, report: &mut Report) {
    match value {
        serde_json::Value::Object(members) => {
            for (key, member) in members {
                if PATH_MEMBERS.contains(&key.as_str())
                    && let Some(text) = member.as_str()
                    && let Err(rejection) = PackagePath::new(text)
                {
                    report.push(Finding::at(
                        FindingCode::UnsafePath,
                        text,
                        rejection.to_string(),
                    ));
                }
                check_declared_paths(member, report);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                check_declared_paths(item, report);
            }
        }
        _ => {}
    }
}

/// Checks the closed vocabularies a manifest draws on.
///
/// A name outside a closed vocabulary is reported as an unknown member of that vocabulary. The
/// alternative, a parse error deep in an array, tells a publisher that something is wrong without
/// telling them what.
fn check_closed_vocabularies(value: &serde_json::Value, report: &mut Report) {
    for action in value
        .get("actions")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(effect) = action.get("effect").and_then(serde_json::Value::as_str)
            && crate::effect::EffectClass::from_wire(effect).is_none()
        {
            report.push(Finding::at(
                FindingCode::UnknownEffectClass,
                MANIFEST_FILE,
                format!(
                    "{effect} is not an effect class; the vocabulary is {}",
                    crate::effect::EffectClass::ALL
                        .iter()
                        .map(|class| class.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    for request in value
        .get("capabilities")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(capability) = request
            .get("capability")
            .and_then(serde_json::Value::as_str)
            && !PluginCapability::ALL
                .iter()
                .any(|known| known.as_str() == capability)
        {
            report.push(Finding::at(
                FindingCode::UnknownCapability,
                MANIFEST_FILE,
                format!("{capability} is not a capability a package may request"),
            ));
        }
    }
}

fn check_manifest(manifest: &PluginManifest, report: &mut Report) {
    if manifest.manifest_version != PluginManifest::CURRENT_VERSION {
        report.push(Finding::at(
            FindingCode::ManifestVersionUnsupported,
            MANIFEST_FILE,
            format!(
                "manifest version {} is not version {}",
                manifest.manifest_version,
                PluginManifest::CURRENT_VERSION
            ),
        ));
    }
    if manifest.sdk_range.is_unbounded() {
        report.push(Finding::at(
            FindingCode::UnboundedVersionRange,
            MANIFEST_FILE,
            "sdk_range admits every version, including releases nobody qualified this against",
        ));
    } else if !manifest.sdk_range.admits(&sdk_version()) {
        report.push(Finding::at(
            FindingCode::VersionRangeExcludesHost,
            MANIFEST_FILE,
            format!(
                "sdk_range {} excludes the SDK version {}",
                manifest.sdk_range,
                sdk_version()
            ),
        ));
    }
    if manifest.wit_range.is_unbounded() {
        report.push(Finding::at(
            FindingCode::UnboundedVersionRange,
            MANIFEST_FILE,
            "wit_range admits every version",
        ));
    } else if !manifest.wit_range.admits(&wit_version()) {
        report.push(Finding::at(
            FindingCode::VersionRangeExcludesHost,
            MANIFEST_FILE,
            format!(
                "wit_range {} excludes the WIT package version {}",
                manifest.wit_range,
                wit_version()
            ),
        ));
    }
    if manifest.match_rules.is_empty() {
        report.push(Finding::at(
            FindingCode::NoMatchRules,
            MANIFEST_FILE,
            "a package with no match rule never activates",
        ));
    }
    if manifest.platforms.is_empty() {
        report.push(Finding::at(
            FindingCode::NoPlatforms,
            MANIFEST_FILE,
            "a package with no platform never runs",
        ));
    }

    let mut seen_capabilities: BTreeSet<PluginCapability> = BTreeSet::new();
    for request in &manifest.capabilities {
        if !seen_capabilities.insert(request.capability) {
            report.push(Finding::at(
                FindingCode::DuplicateCapability,
                MANIFEST_FILE,
                format!("{} is requested more than once", request.capability),
            ));
        }
    }

    let mut seen_actions: BTreeSet<ActionName> = BTreeSet::new();
    for action in &manifest.actions {
        if !seen_actions.insert(action.id.clone()) {
            report.push(Finding::at(
                FindingCode::DuplicateActionId,
                MANIFEST_FILE,
                format!("two actions share the identifier {}", action.id),
            ));
        }
        let needed = action.effect.required_capability();
        if !seen_capabilities.contains(&needed) && !manifest.requests(needed) {
            report.push(Finding::at(
                FindingCode::EffectWithoutCapability,
                MANIFEST_FILE,
                format!(
                    "the action {} declares the effect {} but the package does not request {needed}",
                    action.id, action.effect
                ),
            ));
        }
        check_parameters(&action.parameters, &format!("action {}", action.id), report);
    }

    if manifest.native_bridge.0.is_some()
        && !manifest.requests(PluginCapability::NativeBridgeInstall)
    {
        report.push(Finding::at(
            FindingCode::BridgeWithoutCapability,
            MANIFEST_FILE,
            "the package installs a native bridge without requesting native_bridge.install",
        ));
    }
    if manifest.attachments.0.is_some() && !manifest.requests(PluginCapability::UpstreamAction) {
        report.push(Finding::at(
            FindingCode::AttachmentWithoutCapability,
            MANIFEST_FILE,
            "the package contributes attachments without requesting upstream.action",
        ));
    }
}

fn check_parameters(schema: &ParameterSchema, owner: &str, report: &mut Report) {
    if schema.parameters.len() > MAX_PARAMETERS {
        report.push(Finding::new(
            FindingCode::ParameterSchemaInvalid,
            format!(
                "{owner} declares {} parameters, over the {MAX_PARAMETERS} parameter limit",
                schema.parameters.len()
            ),
        ));
    }
    let mut seen = BTreeSet::new();
    for parameter in &schema.parameters {
        if !seen.insert(parameter.name.clone()) {
            report.push(Finding::new(
                FindingCode::ParameterSchemaInvalid,
                format!("{owner} declares the parameter {} twice", parameter.name),
            ));
        }
        match &parameter.kind {
            ParameterKind::Choice { choices } => {
                if choices.is_empty() || choices.len() > MAX_PARAMETER_CHOICES {
                    report.push(Finding::new(
                        FindingCode::ParameterSchemaInvalid,
                        format!(
                            "{owner} offers {} choices for {}; the range is 1 to {MAX_PARAMETER_CHOICES}",
                            choices.len(),
                            parameter.name
                        ),
                    ));
                }
            }
            ParameterKind::Integer { minimum, maximum } if minimum > maximum => {
                report.push(Finding::new(
                    FindingCode::ParameterSchemaInvalid,
                    format!("{owner} declares an empty range for {}", parameter.name),
                ));
            }
            ParameterKind::Text { max_length, .. } if *max_length == 0 => {
                report.push(Finding::new(
                    FindingCode::ParameterSchemaInvalid,
                    format!(
                        "{owner} declares a zero-length text parameter {}",
                        parameter.name
                    ),
                ));
            }
            _ => {}
        }
    }
}

fn check_payloads(manifest: &PluginManifest, files: &[PackageFile], report: &mut Report) {
    let mut declared: BTreeSet<PackagePath> = BTreeSet::new();
    for payload in &manifest.payloads {
        if !declared.insert(payload.path.clone()) {
            report.push(Finding::at(
                FindingCode::DuplicatePath,
                payload.path.to_string(),
                "the manifest declares this path more than once",
            ));
            continue;
        }
        let Some(file) = files.iter().find(|file| file.path == payload.path) else {
            report.push(Finding::at(
                FindingCode::MissingPayload,
                payload.path.to_string(),
                "the manifest declares this payload but the package does not hold it",
            ));
            continue;
        };
        if file.size_bytes != payload.size_bytes.get() {
            report.push(Finding::at(
                FindingCode::SizeMismatch,
                payload.path.to_string(),
                format!(
                    "the manifest declares {} bytes and the package holds {}",
                    payload.size_bytes.get(),
                    file.size_bytes
                ),
            ));
        }
        if file.digest != payload.digest {
            report.push(Finding::at(
                FindingCode::DigestMismatch,
                payload.path.to_string(),
                format!(
                    "the manifest declares {} and the package holds {}",
                    payload.digest, file.digest
                ),
            ));
        }
    }
    for collision in find_collisions(&declared.iter().cloned().collect::<Vec<_>>()) {
        report.push(Finding::at(
            FindingCode::CaseCollidingPath,
            collision.second.to_string(),
            format!(
                "the manifest declares {}, which names the same file on a case-insensitive filesystem",
                collision.first
            ),
        ));
    }
    for file in files {
        if file.path.as_str() == MANIFEST_FILE {
            continue;
        }
        if !declared.contains(&file.path) {
            report.push(Finding::at(
                FindingCode::UndeclaredFile,
                file.path.to_string(),
                "the package holds this file but the manifest does not declare it",
            ));
        }
    }
    let declared_total = manifest.declared_size_bytes();
    let actual_total: u64 = files
        .iter()
        .filter(|file| file.path.as_str() != MANIFEST_FILE)
        .map(|file| file.size_bytes)
        .sum();
    if actual_total > declared_total {
        report.push(Finding::new(
            FindingCode::SizeMismatch,
            format!(
                "the package expands to {actual_total} bytes against {declared_total} declared"
            ),
        ));
    }
}

fn check_presentation(
    manifest: &PluginManifest,
    presentation: &PresentationManifest,
    report: &mut Report,
) {
    if presentation.nodes.len() > MAX_DOCUMENT_NODES {
        report.push(Finding::at(
            FindingCode::DocumentTooLarge,
            PRESENTATION_FILE,
            format!(
                "the document holds {} nodes, over the {MAX_DOCUMENT_NODES} node limit",
                presentation.nodes.len()
            ),
        ));
    }
    let registered: BTreeSet<&ActionName> = manifest.actions.iter().map(|a| &a.id).collect();
    let mut controls: Vec<&Control> = Vec::new();
    let mut node_ids = BTreeSet::new();
    for node in &presentation.nodes {
        node_ids.insert(node.id.clone());
        controls.extend(node.body.controls());
        for action_id in node.body.action_ids() {
            if !registered.contains(&action_id) {
                report.push(Finding::at(
                    FindingCode::ActionNotRegistered,
                    PRESENTATION_FILE,
                    format!(
                        "the node {} invokes {action_id}, which the manifest does not register",
                        node.id
                    ),
                ));
            }
        }
    }
    if controls.len() > MAX_CONTROLS {
        report.push(Finding::at(
            FindingCode::DocumentTooLarge,
            PRESENTATION_FILE,
            format!(
                "the document holds {} controls, over the {MAX_CONTROLS} control limit",
                controls.len()
            ),
        ));
    }
    let mut control_ids = BTreeSet::new();
    for control in &controls {
        control_ids.insert(control.id.clone());
        for (name, predicate) in [
            ("visible_when", &control.visible_when),
            ("enabled_when", &control.enabled_when),
        ] {
            if let Err(error) = predicate.validate() {
                report.push(Finding::at(
                    FindingCode::PredicateInvalid,
                    PRESENTATION_FILE,
                    format!("the control {} has an invalid {name}: {error}", control.id),
                ));
            }
        }
        check_parameters(
            &control.parameters,
            &format!("control {}", control.id),
            report,
        );
    }
    for node_id in presentation
        .voice
        .status_nodes
        .iter()
        .chain(&presentation.voice.detail_nodes)
    {
        if !node_ids.contains(node_id) {
            report.push(Finding::at(
                FindingCode::VoiceProjectionUnknown,
                PRESENTATION_FILE,
                format!(
                    "the voice projection names the node {node_id}, which is not in the document"
                ),
            ));
        }
    }
    for control_id in &presentation.voice.choice_controls {
        if !control_ids.contains(control_id) {
            report.push(Finding::at(
                FindingCode::VoiceProjectionUnknown,
                PRESENTATION_FILE,
                format!(
                    "the voice projection names the control {control_id}, which is not in the document"
                ),
            ));
        }
    }
    let uses_nodes = presentation
        .nodes
        .iter()
        .any(|node| !matches!(node.body, NodeBody::Markdown { .. }));
    if uses_nodes && !manifest.requests(PluginCapability::DeclarativePresentation) {
        report.push(Finding::at(
            FindingCode::EffectWithoutCapability,
            MANIFEST_FILE,
            "the package presents a document without requesting presentation.declarative",
        ));
    }
}

fn check_connector_presence(
    manifest: &PluginManifest,
    connector_present: bool,
    connector: Option<&ConnectorManifest>,
    report: &mut Report,
) {
    let declared = manifest.payload(PayloadRole::Connector).is_some();
    if declared && !connector_present {
        report.push(Finding::at(
            FindingCode::ConnectorPayloadMissing,
            CONNECTOR_FILE,
            "the manifest declares a connector payload but the package does not hold one",
        ));
    }
    if connector_present && !declared {
        report.push(Finding::at(
            FindingCode::ConnectorUndeclared,
            CONNECTOR_FILE,
            "the package holds a connector table the manifest does not declare",
        ));
    }
    if let Some(connector) = connector
        && connector.plugin_id != manifest.plugin_id()
    {
        report.push(Finding::at(
            FindingCode::ConnectorPluginMismatch,
            CONNECTOR_FILE,
            format!(
                "the connector names {} and the manifest names {}",
                connector.plugin_id,
                manifest.plugin_id()
            ),
        ));
    }
}

fn check_connector(connector: &ConnectorManifest, report: &mut Report) {
    if connector.methods.len() > MAX_CLASSIFIED_METHODS {
        report.push(Finding::at(
            FindingCode::ConnectorTableInvalid,
            CONNECTOR_FILE,
            format!(
                "the table classifies {} methods, over the {MAX_CLASSIFIED_METHODS} method limit",
                connector.methods.len()
            ),
        ));
    }
    if connector.protocol.qualified_range.is_unbounded() {
        report.push(Finding::at(
            FindingCode::ConnectorTableInvalid,
            CONNECTOR_FILE,
            "qualified_range admits every protocol version, including ones nobody tested",
        ));
    } else if !connector
        .protocol
        .qualified_range
        .admits(&connector.protocol.tested_version)
    {
        report.push(Finding::at(
            FindingCode::ConnectorTableInvalid,
            CONNECTOR_FILE,
            format!(
                "qualified_range {} excludes the tested version {}",
                connector.protocol.qualified_range, connector.protocol.tested_version
            ),
        ));
    }
    for path in [&connector.request_id_path, &connector.method_path] {
        if path.segments.is_empty() || path.segments.len() > MAX_FIELD_PATH_DEPTH {
            report.push(Finding::at(
                FindingCode::ConnectorTableInvalid,
                CONNECTOR_FILE,
                format!(
                    "a field path has {} segments; the range is 1 to {MAX_FIELD_PATH_DEPTH}",
                    path.segments.len()
                ),
            ));
        }
    }
    if connector.framing.max_message_bytes() == 0 {
        report.push(Finding::at(
            FindingCode::ConnectorTableInvalid,
            CONNECTOR_FILE,
            "a framing that accepts no bytes cannot carry a message",
        ));
    }
    let routed: BTreeSet<_> = connector.routes.iter().map(|route| &route.method).collect();
    for entry in &connector.methods {
        if !routed.contains(&entry.method) {
            report.push(Finding::at(
                FindingCode::ConnectorMethodUnrouted,
                CONNECTOR_FILE,
                format!(
                    "the table classifies {} without routing it, so the classification is never used",
                    entry.method
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_directory_is_one_finding() {
        let validated = validate_package_directory(Path::new("/nonexistent/kalareach/package"));
        assert!(validated.package.is_none());
        assert!(validated.report.has(FindingCode::DirectoryUnreadable));
    }

    #[test]
    fn finding_codes_render_as_their_wire_strings() {
        assert_eq!(FindingCode::UnsafePath.as_str(), "unsafe_path");
        assert_eq!(FindingCode::DigestMismatch.as_str(), "digest_mismatch");
    }
}
