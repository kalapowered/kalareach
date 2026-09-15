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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::PluginCapability;
use crate::connector::{
    ConnectorManifest, FieldPath, Framing, MAX_CLASSIFIED_METHODS, MAX_FIELD_PATH_DEPTH,
    MethodClass, RouteDirection,
};
use crate::digest::PayloadDigest;
use crate::effect::{
    ActionDeclaration, ActionImplementation, AttachmentInsertion, MAX_PARAMETER_CHOICES,
    MAX_PARAMETERS, MAX_TEXT_SEGMENTS, ParameterKind, ParameterSchema,
};
use crate::ids::ActionName;
use crate::limits::MANIFEST_BYTES;
use crate::package::{
    CONNECTOR_FILE, MANIFEST_FILE, MAX_PACKAGE_BYTES, MAX_PACKAGE_FILES, PRESENTATION_FILE,
    Package, PackageFile,
};
use crate::paths::{PackagePath, find_collisions};
use crate::plugin::{
    BridgeRemoval, BridgeStep, NativeBridge, PayloadRef, PayloadRole, PluginManifest,
};
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
    /// A file name is not valid UTF-8.
    NameNotUtf8,
    /// A JSON document repeats a member name.
    DuplicateMember,
    /// A structural payload role is declared at the wrong path or more than once.
    PayloadRoleInvalid,
    /// An action's implementation cannot produce the effect class it declares.
    ImplementationMismatch,
    /// An action's implementation refers to something the package does not carry.
    ImplementationUnsatisfied,
    /// A native bridge recipe is incomplete or refers to something absent.
    BridgeRecipeInvalid,
    /// Two document nodes or two controls share an identifier.
    DuplicateElementId,
    /// A control's parameters do not narrow its action's.
    ControlParametersWiden,
    /// A catalogue qualification result claims something the catalogue cannot know.
    QualificationInvalid,
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
        Self::NameNotUtf8,
        Self::DuplicateMember,
        Self::PayloadRoleInvalid,
        Self::ImplementationMismatch,
        Self::ImplementationUnsatisfied,
        Self::BridgeRecipeInvalid,
        Self::DuplicateElementId,
        Self::ControlParametersWiden,
        Self::QualificationInvalid,
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
            Self::NameNotUtf8 => "name_not_utf8",
            Self::DuplicateMember => "duplicate_member",
            Self::PayloadRoleInvalid => "payload_role_invalid",
            Self::ImplementationMismatch => "implementation_mismatch",
            Self::ImplementationUnsatisfied => "implementation_unsatisfied",
            Self::BridgeRecipeInvalid => "bridge_recipe_invalid",
            Self::DuplicateElementId => "duplicate_element_id",
            Self::ControlParametersWiden => "control_parameters_widen",
            Self::QualificationInvalid => "qualification_invalid",
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
    let Some(Scanned { files, manifests }) = scan(directory, &mut report) else {
        return Validated {
            package: None,
            report,
        };
    };

    check_file_set(&files, &mut report);

    let Some(manifest) = read_plugin_manifest(&manifests, &mut report) else {
        return Validated {
            package: None,
            report,
        };
    };
    let presentation =
        read_manifest::<PresentationManifest>(&manifests, PRESENTATION_FILE, &mut report);
    let connector_present = manifests.contains_key(CONNECTOR_FILE);
    let connector = if connector_present {
        read_manifest::<ConnectorManifest>(&manifests, CONNECTOR_FILE, &mut report)
    } else {
        None
    };

    if let Some(presentation) = &presentation
        && presentation.manifest_version != PresentationManifest::CURRENT_VERSION
    {
        report.push(Finding::at(
            FindingCode::ManifestVersionUnsupported,
            PRESENTATION_FILE,
            format!(
                "manifest version {} is not version {}",
                presentation.manifest_version,
                PresentationManifest::CURRENT_VERSION
            ),
        ));
    }
    if let Some(connector) = &connector
        && connector.manifest_version != ConnectorManifest::CURRENT_VERSION
    {
        report.push(Finding::at(
            FindingCode::ManifestVersionUnsupported,
            CONNECTOR_FILE,
            format!(
                "manifest version {} is not version {}",
                connector.manifest_version,
                ConnectorManifest::CURRENT_VERSION
            ),
        ));
    }

    check_manifest(&manifest, connector.as_ref(), &mut report);
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

/// What one pass over a package directory found.
struct Scanned {
    /// Every file, by path, with its length and digest.
    files: Vec<PackageFile>,
    /// The text of each manifest, exactly as it was hashed.
    ///
    /// The manifests are parsed from these bytes rather than read again. Reading a file twice is
    /// two chances for it to be a different file, and the digest a package is pinned by would then
    /// cover something other than what was validated.
    manifests: BTreeMap<String, Vec<u8>>,
}

fn scan(directory: &Path, report: &mut Report) -> Option<Scanned> {
    // The walk is anchored to a directory handle. Every open below resolves inside that handle, so
    // a link, an absolute path or a `..` cannot reach outside the package, and a directory replaced
    // during the walk cannot redirect a read: the handle refers to the directory that was opened,
    // not to the name it was opened by. Checking each path as text and then opening it by path
    // would leave the gap between the two.
    let root = match Dir::open_ambient_dir(directory, ambient_authority()) {
        Ok(root) => root,
        Err(error) => {
            report.push(Finding::new(
                FindingCode::DirectoryUnreadable,
                format!("{}: {error}", directory.display()),
            ));
            return None;
        }
    };

    let mut files = Vec::new();
    let mut manifests: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total: u64 = 0;
    let mut queue: Vec<(Dir, Vec<String>)> = vec![(root, Vec::new())];
    while let Some((current, prefix)) = queue.pop() {
        let entries = match current.entries() {
            Ok(entries) => entries,
            Err(error) => {
                report.push(Finding::new(
                    FindingCode::DirectoryUnreadable,
                    format!("{}: {error}", display_prefix(directory, &prefix)),
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
                        format!("{}: {error}", display_prefix(directory, &prefix)),
                    ));
                    return None;
                }
            };
            let name_os = entry.file_name();
            let Some(name) = name_os.to_str().map(str::to_owned) else {
                report.push(Finding::at(
                    FindingCode::NameNotUtf8,
                    format!("{}/{}", prefix.join("/"), name_os.to_string_lossy()),
                    "a package file name is valid UTF-8; a name that is not cannot be declared",
                ));
                continue;
            };
            let mut segments = prefix.clone();
            segments.push(name);
            let relative = segments.join("/");

            let metadata = match current.symlink_metadata(&name_os) {
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
            let kind = metadata.file_type();
            if kind.is_symlink() {
                report.push(Finding::at(
                    FindingCode::NotARegularFile,
                    relative,
                    "a package holds regular files only; a link can point outside the package",
                ));
                continue;
            }
            if kind.is_dir() {
                if let Err(rejection) = PackagePath::new(relative.clone()) {
                    report.push(Finding::at(
                        FindingCode::UnsafePath,
                        relative,
                        rejection.to_string(),
                    ));
                    continue;
                }
                // The open refuses a link, so a directory replaced by one between the metadata
                // check and this call is refused rather than descended into.
                match current.open_dir_nofollow(&name_os) {
                    Ok(child) => queue.push((child, segments)),
                    Err(error) => report.push(Finding::at(
                        FindingCode::DirectoryUnreadable,
                        relative,
                        error.to_string(),
                    )),
                }
                continue;
            }
            if !kind.is_file() {
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

            // The length comes from the directory entry, so a file is measured against the package
            // budget before any of it is read into memory.
            let size_bytes = metadata.len();
            total = total.saturating_add(size_bytes);
            if size_bytes > MAX_PACKAGE_BYTES || total > MAX_PACKAGE_BYTES {
                report.push(Finding::at(
                    FindingCode::PackageTooLarge,
                    relative,
                    format!(
                        "reading it would take the package past the {MAX_PACKAGE_BYTES} byte limit"
                    ),
                ));
                return Some(Scanned { files, manifests });
            }
            let limit = if is_manifest_name(path.as_str()) {
                MANIFEST_BYTES
            } else {
                MAX_PACKAGE_BYTES
            };
            match read_bounded(&current, &name_os, limit) {
                Ok(bytes) => {
                    if is_manifest_name(path.as_str()) {
                        manifests.insert(path.to_string(), bytes.clone());
                    }
                    files.push(PackageFile {
                        path,
                        size_bytes: bytes.len() as u64,
                        digest: PayloadDigest::of(&bytes),
                    });
                }
                Err(rejection) => {
                    report.push(Finding::at(rejection.code, relative, rejection.detail));
                }
            }
            if files.len() > MAX_PACKAGE_FILES {
                report.push(Finding::new(
                    FindingCode::TooManyFiles,
                    format!(
                        "the package holds more than {MAX_PACKAGE_FILES} files; nothing past that was read"
                    ),
                ));
                return Some(Scanned { files, manifests });
            }
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Some(Scanned { files, manifests })
}

/// Names a directory inside the package for a message.
fn display_prefix(directory: &Path, prefix: &[String]) -> String {
    if prefix.is_empty() {
        directory.display().to_string()
    } else {
        format!("{}/{}", directory.display(), prefix.join("/"))
    }
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
    let total: u64 = files
        .iter()
        .fold(0u64, |total, file| total.saturating_add(file.size_bytes));
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
    manifests: &BTreeMap<String, Vec<u8>>,
    name: &str,
    report: &mut Report,
) -> Option<T> {
    let text = manifest_text(manifests, name, report)?;
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

/// Returns one manifest's text from the bytes the scan read.
///
/// The scan already opened the file through a handle it checked, hashed what it read and bounded
/// the read. Parsing those same bytes is what makes the digest in the index cover the document the
/// validator actually looked at.
fn manifest_text(
    manifests: &BTreeMap<String, Vec<u8>>,
    name: &str,
    report: &mut Report,
) -> Option<String> {
    let Some(bytes) = manifests.get(name) else {
        report.push(Finding::at(
            FindingCode::ManifestMissing,
            name,
            "every package carries this manifest",
        ));
        return None;
    };
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text.to_owned()),
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

/// Reads one directory entry through the handle its directory was opened with.
///
/// The entry is opened from a directory handle rather than by path, so nothing between the
/// directory scan and the read can redirect it. The handle's own metadata is the check: a
/// non-regular file is refused, and so is a file with more than one name, because a second name is
/// a way to make one file's bytes answer for two declared payloads. The read stops one byte past
/// the limit rather than trusting the length reported before it started.
fn read_bounded(directory: &Dir, name: &std::ffi::OsStr, limit: u64) -> Result<Vec<u8>, Finding> {
    use std::io::Read as _;

    let reject = |code: FindingCode, detail: String| Finding {
        code,
        path: None,
        detail,
    };

    // The open refuses a link and does not wait. `O_NOFOLLOW` stops a name replaced by a link from
    // redirecting the read, and `O_NONBLOCK` stops one replaced by a named pipe from holding the
    // validator open until somebody writes to it. The handle's own metadata then decides.
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = directory
        .open_with(name, &options)
        .map_err(|error| reject(FindingCode::NotARegularFile, error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| reject(FindingCode::NotARegularFile, error.to_string()))?;
    if !metadata.is_file() {
        return Err(reject(
            FindingCode::NotARegularFile,
            "a package holds regular files only".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt as _;
        if metadata.nlink() > 1 {
            return Err(reject(
                FindingCode::NotARegularFile,
                "a package holds one name per file".to_owned(),
            ));
        }
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len().min(limit)).unwrap_or(0));
    let read = file
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| reject(FindingCode::DirectoryUnreadable, error.to_string()))?;
    if read as u64 > limit {
        return Err(reject(
            FindingCode::PackageTooLarge,
            format!("it is over the {limit} byte limit"),
        ));
    }
    Ok(bytes)
}

/// Returns true when a path names one of the package's own manifests.
fn is_manifest_name(path: &str) -> bool {
    matches!(path, MANIFEST_FILE | PRESENTATION_FILE | CONNECTOR_FILE)
}

/// Reports every member name a JSON document repeats.
///
/// `serde_json::Value` keeps the last of two members with the same name, so a document parsed into
/// one has already lost the duplicate. A manifest that says `"effect"` twice would then be read as
/// whichever spelling came last, which is a way to show a reviewer one thing and a host another.
fn check_duplicate_members(name: &str, text: &str, report: &mut Report) {
    use serde::de::Deserialize as _;

    #[derive(Debug)]
    struct Duplicates(Vec<String>);

    impl<'de> serde::de::Deserialize<'de> for Duplicates {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Duplicates;

                fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    formatter.write_str("any JSON value")
                }

                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut seen: BTreeSet<String> = BTreeSet::new();
                    let mut repeated = Vec::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if !seen.insert(key.clone()) {
                            repeated.push(key);
                        }
                        let nested: Duplicates = map.next_value()?;
                        repeated.extend(nested.0);
                    }
                    Ok(Duplicates(repeated))
                }

                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut repeated = Vec::new();
                    while let Some(nested) = seq.next_element::<Duplicates>()? {
                        repeated.extend(nested.0);
                    }
                    Ok(Duplicates(repeated))
                }

                fn visit_unit<E>(self) -> Result<Self::Value, E> {
                    Ok(Duplicates(Vec::new()))
                }
            }

            deserializer
                .deserialize_any(Visitor)
                .or_else(|_| Ok(Duplicates(Vec::new())))
        }
    }

    let mut deserializer = serde_json::Deserializer::from_str(text);
    let Ok(duplicates) = Duplicates::deserialize(&mut deserializer) else {
        return;
    };
    for member in duplicates.0 {
        report.push(Finding::at(
            FindingCode::DuplicateMember,
            name,
            format!("the member {member:?} appears more than once"),
        ));
    }
}

/// Reads `plugin.json` in two stages.
///
/// The closed vocabularies and the declared paths are checked against the raw document first, so
/// an unsafe path or an invented effect class is reported as itself rather than as a parse error
/// in a nested field. A package that fails either check is not parsed further: a manifest whose
/// paths cannot be trusted is not a manifest a host reads the rest of.
fn read_plugin_manifest(
    manifests: &BTreeMap<String, Vec<u8>>,
    report: &mut Report,
) -> Option<PluginManifest> {
    let text = manifest_text(manifests, MANIFEST_FILE, report)?;
    let before = report.findings.len();
    check_duplicate_members(MANIFEST_FILE, &text, report);
    let raw: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            report.push(Finding::at(
                FindingCode::ManifestUnreadable,
                MANIFEST_FILE,
                error.to_string(),
            ));
            return None;
        }
    };
    check_declared_paths(&raw, report);
    check_closed_vocabularies(&raw, report);
    if report.findings.len() > before {
        return None;
    }
    // The typed parse reads the original text rather than the value tree, so a repeated member is
    // a parse error here as well as a finding above.
    match serde_json::from_str::<PluginManifest>(&text) {
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

fn check_manifest(
    manifest: &PluginManifest,
    connector: Option<&ConnectorManifest>,
    report: &mut Report,
) {
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
        check_implementation(manifest, connector, action, report);
    }

    if let Some(bridge) = &manifest.native_bridge.0 {
        if !manifest.requests(PluginCapability::NativeBridgeInstall) {
            report.push(Finding::at(
                FindingCode::BridgeWithoutCapability,
                MANIFEST_FILE,
                "the package installs a native bridge without requesting native_bridge.install",
            ));
        }
        check_bridge(manifest, bridge, report);
    }
    if let Some(attachments) = &manifest.attachments.0 {
        if !manifest.requests(PluginCapability::UpstreamAction) {
            report.push(Finding::at(
                FindingCode::AttachmentWithoutCapability,
                MANIFEST_FILE,
                "the package contributes attachments without requesting upstream.action",
            ));
        }
        // Writing a path into the terminal draft is terminal input, whatever it is for. Section 11
        // keeps input authority separate from every other grant, so the capability is separate too.
        if attachments.insertion == AttachmentInsertion::TerminalDraftPath
            && !manifest.requests(PluginCapability::TerminalInput)
        {
            report.push(Finding::at(
                FindingCode::AttachmentWithoutCapability,
                MANIFEST_FILE,
                "inserting an attachment path into the terminal draft is terminal input; the package does not request terminal.input",
            ));
        }
        if attachments.max_bytes.get() == 0 || attachments.max_count.get() == 0 {
            report.push(Finding::at(
                FindingCode::ParameterSchemaInvalid,
                MANIFEST_FILE,
                "an attachment contribution that accepts no bytes or no files accepts nothing",
            ));
        }
    }
}

/// Checks that an action's implementation can produce its effect and reaches only what the package
/// carries.
fn check_implementation(
    manifest: &PluginManifest,
    connector: Option<&ConnectorManifest>,
    action: &ActionDeclaration,
    report: &mut Report,
) {
    let implementation = &action.implementation;
    if !implementation.permits(action.effect) {
        report.push(Finding::at(
            FindingCode::ImplementationMismatch,
            MANIFEST_FILE,
            format!(
                "the action {} is implemented as {} but declares the effect {}",
                action.id,
                implementation.kind(),
                action.effect
            ),
        ));
    }
    if implementation.needs_component() && !manifest.has_component() {
        report.push(Finding::at(
            FindingCode::ImplementationUnsatisfied,
            MANIFEST_FILE,
            format!(
                "the action {} is prepared by a component and the package ships none",
                action.id
            ),
        ));
    }
    let declared: BTreeSet<&crate::ids::ParameterName> = action
        .parameters
        .parameters
        .iter()
        .map(|parameter| &parameter.name)
        .collect();
    for referenced in implementation.referenced_parameters() {
        if !declared.contains(referenced) {
            report.push(Finding::at(
                FindingCode::ImplementationUnsatisfied,
                MANIFEST_FILE,
                format!(
                    "the action {} refers to the parameter {referenced}, which it does not declare",
                    action.id
                ),
            ));
        }
    }
    match implementation {
        ActionImplementation::UpstreamMethod { method, bindings } => {
            match connector {
                None => report.push(Finding::at(
                    FindingCode::ImplementationUnsatisfied,
                    MANIFEST_FILE,
                    format!(
                        "the action {} sends the method {method} and the package ships no connector table",
                        action.id
                    ),
                )),
                Some(connector) => {
                    match connector.routes.iter().find(|route| &route.method == method) {
                        None => report.push(Finding::at(
                            FindingCode::ImplementationUnsatisfied,
                            MANIFEST_FILE,
                            format!(
                                "the action {} sends the method {method}, which the connector table does not route",
                                action.id
                            ),
                        )),
                        Some(route) => {
                            if route.direction == RouteDirection::UpstreamToHost {
                                report.push(Finding::at(
                                    FindingCode::ImplementationUnsatisfied,
                                    MANIFEST_FILE,
                                    format!(
                                        "the action {} sends {method}, which the connector table routes from the application to the host",
                                        action.id
                                    ),
                                ));
                            }
                        }
                    }
                    if connector.classify(method) == MethodClass::Unsupported {
                        report.push(Finding::at(
                            FindingCode::ImplementationUnsatisfied,
                            MANIFEST_FILE,
                            format!(
                                "the action {} sends {method}, which the connector table classifies as unsupported",
                                action.id
                            ),
                        ));
                    }
                    for binding in bindings {
                        for reserved in [&connector.request_id_path, &connector.method_path] {
                            if paths_overlap(&binding.field, reserved) {
                                report.push(Finding::at(
                                    FindingCode::ImplementationUnsatisfied,
                                    MANIFEST_FILE,
                                    format!(
                                        "the action {} binds {} over a field the broker owns",
                                        action.id, binding.parameter
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
            let mut bound = BTreeSet::new();
            for (index, binding) in bindings.iter().enumerate() {
                if !bound.insert(&binding.parameter) {
                    report.push(Finding::at(
                        FindingCode::ImplementationUnsatisfied,
                        MANIFEST_FILE,
                        format!(
                            "the action {} binds the parameter {} more than once",
                            action.id, binding.parameter
                        ),
                    ));
                }
                check_field_path(&binding.field, &format!("action {}", action.id), report);
                // Two parameters that write the same field, or one that writes inside another's
                // object, leave the broker choosing which value wins.
                for other in &bindings[index + 1..] {
                    if paths_overlap(&binding.field, &other.field) {
                        report.push(Finding::at(
                            FindingCode::ImplementationUnsatisfied,
                            MANIFEST_FILE,
                            format!(
                                "the action {} binds {} and {} to overlapping fields",
                                action.id, binding.parameter, other.parameter
                            ),
                        ));
                    }
                }
            }
            for parameter in &action.parameters.parameters {
                if parameter.required && !bound.contains(&parameter.name) {
                    report.push(Finding::at(
                        FindingCode::ImplementationUnsatisfied,
                        MANIFEST_FILE,
                        format!(
                            "the action {} requires the parameter {} and binds it to nothing",
                            action.id, parameter.name
                        ),
                    ));
                }
            }
        }
        ActionImplementation::TerminalText { template }
            if template.is_empty() || template.len() > MAX_TEXT_SEGMENTS =>
        {
            report.push(Finding::at(
                FindingCode::ImplementationUnsatisfied,
                MANIFEST_FILE,
                format!(
                    "the action {} has {} template segments; the range is 1 to {MAX_TEXT_SEGMENTS}",
                    action.id,
                    template.len()
                ),
            ));
        }
        _ => {}
    }
}

/// Checks a native bridge recipe against the payloads the package declares.
fn check_bridge(manifest: &PluginManifest, bridge: &NativeBridge, report: &mut Report) {
    if bridge.install.is_empty() {
        report.push(Finding::at(
            FindingCode::BridgeRecipeInvalid,
            MANIFEST_FILE,
            "a native bridge recipe that installs nothing has nothing to grant",
        ));
    }
    if bridge.application_range.is_unbounded() {
        report.push(Finding::at(
            FindingCode::BridgeRecipeInvalid,
            MANIFEST_FILE,
            "the bridge's application range admits versions nobody wrote the recipe for",
        ));
    }
    // An install step and the removal that undoes it name the same thing exactly. A configuration
    // key is a JSON member, where case is part of the name, and a path spelled differently is a
    // different file on Linux. Case-folded collisions between two install destinations are a
    // separate problem, reported separately below.
    let mut written: BTreeMap<(String, Option<String>), Option<PayloadDigest>> = BTreeMap::new();
    for step in &bridge.install {
        let (path, key) = step.writes();
        let target = (path.to_string(), key.map(str::to_owned));
        let digest = match step {
            BridgeStep::InstallFile { digest, .. } => Some(*digest),
            BridgeStep::AddConfigurationKey { .. } => None,
        };
        if written.insert(target, digest).is_some() {
            report.push(Finding::at(
                FindingCode::BridgeRecipeInvalid,
                MANIFEST_FILE,
                format!("the recipe writes {path} more than once"),
            ));
        }
        match step {
            BridgeStep::InstallFile { source, digest, .. } => {
                match manifest
                    .payloads
                    .iter()
                    .find(|payload| &payload.path == source)
                {
                    None => report.push(Finding::at(
                        FindingCode::BridgeRecipeInvalid,
                        MANIFEST_FILE,
                        format!(
                            "the recipe installs {source}, which the manifest does not declare"
                        ),
                    )),
                    Some(payload) => {
                        if payload.role != PayloadRole::NativeBridge {
                            report.push(Finding::at(
                                FindingCode::BridgeRecipeInvalid,
                                MANIFEST_FILE,
                                format!(
                                    "{source} is installed as a bridge file and declared as {:?}",
                                    payload.role
                                ),
                            ));
                        }
                        if &payload.digest != digest {
                            report.push(Finding::at(
                                FindingCode::BridgeRecipeInvalid,
                                MANIFEST_FILE,
                                format!(
                                    "the recipe installs {source} as {digest} and the manifest declares {}",
                                    payload.digest
                                ),
                            ));
                        }
                    }
                }
            }
            BridgeStep::AddConfigurationKey { file, key, value } => {
                if key.is_empty() {
                    report.push(Finding::at(
                        FindingCode::BridgeRecipeInvalid,
                        MANIFEST_FILE,
                        format!("the recipe adds an unnamed key to {file}"),
                    ));
                }
                if serde_json::from_str::<serde_json::Value>(value).is_err() {
                    report.push(Finding::at(
                        FindingCode::BridgeRecipeInvalid,
                        MANIFEST_FILE,
                        format!("the value the recipe writes to {file} {key} is not JSON"),
                    ));
                }
            }
        }
    }
    // Two steps that write one file on macOS or Windows are a defect wherever the application's
    // plugin directory happens to live. Configuration files count: two edits to `Settings.json` and
    // `settings.json` are two edits to one document there. Several keys in one file are not a
    // collision, so each file is counted once.
    let mut destinations: Vec<crate::paths::PackagePath> = Vec::new();
    for step in &bridge.install {
        let (path, _) = step.writes();
        if !destinations.contains(path) {
            destinations.push(path.clone());
        }
    }
    for collision in find_collisions(&destinations) {
        report.push(Finding::at(
            FindingCode::BridgeRecipeInvalid,
            MANIFEST_FILE,
            format!(
                "the recipe installs {} and {}, which are one file on a case-insensitive filesystem",
                collision.first, collision.second
            ),
        ));
    }

    let mut undone: BTreeMap<(String, Option<String>), Option<PayloadDigest>> = BTreeMap::new();
    for step in &bridge.remove {
        let (path, key) = step.undoes();
        let digest = match step {
            BridgeRemoval::RemoveFile { digest, .. } => Some(*digest),
            BridgeRemoval::RemoveConfigurationKey { .. } => None,
        };
        // One removal per target. A second removal of the same target would replace the first
        // before either was checked, so a recipe could hide a removal that names the wrong bytes.
        if undone
            .insert((path.to_string(), key.map(str::to_owned)), digest)
            .is_some()
        {
            report.push(Finding::at(
                FindingCode::BridgeRecipeInvalid,
                MANIFEST_FILE,
                format!("the recipe removes {path} more than once"),
            ));
        }
    }
    for (target, installed) in &written {
        let (path, key) = target;
        match undone.get(target) {
            None => report.push(Finding::at(
                FindingCode::BridgeRecipeInvalid,
                MANIFEST_FILE,
                match key {
                    Some(key) => format!("the recipe adds {path} {key} and never removes it"),
                    None => format!("the recipe installs {path} and never removes it"),
                },
            )),
            Some(removed) => {
                // Removal checks the digest before it deletes, so it must be the digest the recipe
                // installed. A removal that names different bytes never matches and never removes.
                if removed != installed {
                    report.push(Finding::at(
                        FindingCode::BridgeRecipeInvalid,
                        MANIFEST_FILE,
                        format!("the recipe removes {path} by a digest it never installed"),
                    ));
                }
            }
        }
    }
    for (path, key) in undone.keys() {
        if !written.contains_key(&(path.clone(), key.clone())) {
            report.push(Finding::at(
                FindingCode::BridgeRecipeInvalid,
                MANIFEST_FILE,
                format!("the recipe removes {path}, which it never installed"),
            ));
        }
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
            ParameterKind::Text { max_length, .. } if max_length.get() == 0 => {
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
    check_payload_roles(manifest, report);

    if manifest.declares_more_than(MAX_PACKAGE_BYTES) {
        report.push(Finding::at(
            FindingCode::PackageTooLarge,
            MANIFEST_FILE,
            format!("the manifest declares more than the {MAX_PACKAGE_BYTES} byte package limit"),
        ));
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

/// Checks that the structural payload roles sit where the package contract puts them.
///
/// A host that asks for the connector payload gets one answer, and validation checks one file. If
/// a package could declare `connector.json` as an asset and something else as the connector, those
/// two would be different files.
fn check_payload_roles(manifest: &PluginManifest, report: &mut Report) {
    const STRUCTURAL: &[(PayloadRole, &str)] = &[
        (PayloadRole::Presentation, PRESENTATION_FILE),
        (PayloadRole::Connector, CONNECTOR_FILE),
    ];
    for (role, expected) in STRUCTURAL {
        let declared: Vec<&PayloadRef> = manifest
            .payloads
            .iter()
            .filter(|payload| payload.role == *role)
            .collect();
        if declared.len() > 1 {
            report.push(Finding::at(
                FindingCode::PayloadRoleInvalid,
                MANIFEST_FILE,
                format!(
                    "the manifest declares {} payloads with the role {role:?}",
                    declared.len()
                ),
            ));
        }
        for payload in declared {
            if payload.path.as_str() != *expected {
                report.push(Finding::at(
                    FindingCode::PayloadRoleInvalid,
                    payload.path.to_string(),
                    format!("a payload with the role {role:?} is {expected}"),
                ));
            }
        }
        for payload in &manifest.payloads {
            if payload.path.as_str() == *expected && payload.role != *role {
                report.push(Finding::at(
                    FindingCode::PayloadRoleInvalid,
                    payload.path.to_string(),
                    format!(
                        "{expected} is declared as {:?} rather than {role:?}",
                        payload.role
                    ),
                ));
            }
        }
    }
    let components: Vec<&PayloadRef> = manifest
        .payloads
        .iter()
        .filter(|payload| payload.role == PayloadRole::Component)
        .collect();
    if components.len() > 1 {
        report.push(Finding::at(
            FindingCode::PayloadRoleInvalid,
            MANIFEST_FILE,
            "the manifest declares more than one component",
        ));
    }
    for payload in components {
        if !payload.path.as_str().ends_with(".wasm") {
            report.push(Finding::at(
                FindingCode::PayloadRoleInvalid,
                payload.path.to_string(),
                "a component is a .wasm file",
            ));
        }
    }
    if manifest
        .payloads
        .iter()
        .any(|payload| payload.path.as_str() == MANIFEST_FILE)
    {
        report.push(Finding::at(
            FindingCode::PayloadRoleInvalid,
            MANIFEST_FILE,
            "the manifest does not declare itself; its digest belongs in the catalogue index entry",
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
        if !node_ids.insert(node.id.clone()) {
            report.push(Finding::at(
                FindingCode::DuplicateElementId,
                PRESENTATION_FILE,
                format!("two nodes share the identifier {}", node.id),
            ));
        }
        controls.extend(node.body.controls());
        if let NodeBody::Form { fields, submit, .. } = &node.body {
            check_parameters(fields, &format!("the form {}", node.id), report);
            // A form's fields are what a person fills in and what the submission then carries, so
            // they are checked against the submit action exactly as a control's parameters are.
            if let Some(action) = manifest
                .actions
                .iter()
                .find(|action| action.id == submit.action_id)
            {
                check_control_narrows(fields, &format!("the form {}", node.id), action, report);
            }
        }
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
        if !control_ids.insert(control.id.clone()) {
            report.push(Finding::at(
                FindingCode::DuplicateElementId,
                PRESENTATION_FILE,
                format!("two controls share the identifier {}", control.id),
            ));
        }
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
        if let Some(action) = manifest
            .actions
            .iter()
            .find(|action| action.id == control.action_id)
        {
            check_control_narrows(
                &control.parameters,
                &format!("the control {}", control.id),
                action,
                report,
            );
        }
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

/// Checks that a set of parameters narrows an action's rather than widening them.
///
/// A control may tighten what its action accepts and may require what the action treats as
/// optional. It may not introduce a parameter the action does not declare, accept values the
/// action would reject, treat a required parameter as optional, or omit one. The host checks every
/// invocation against the action's own schema, so a control that promises otherwise is a control
/// that fails when somebody uses it.
fn check_control_narrows(
    parameters: &ParameterSchema,
    owner: &str,
    action: &ActionDeclaration,
    report: &mut Report,
) {
    for parameter in &parameters.parameters {
        match action
            .parameters
            .parameters
            .iter()
            .find(|declared| declared.name == parameter.name)
        {
            None => report.push(Finding::at(
                FindingCode::ControlParametersWiden,
                PRESENTATION_FILE,
                format!(
                    "{owner} declares the parameter {}, which the action {} does not",
                    parameter.name, action.id
                ),
            )),
            Some(declared) => {
                if !parameter.kind.narrows(&declared.kind) {
                    report.push(Finding::at(
                        FindingCode::ControlParametersWiden,
                        PRESENTATION_FILE,
                        format!(
                            "{owner} accepts values for {} that the action {} does not",
                            parameter.name, action.id
                        ),
                    ));
                }
                // Requiring what the action treats as optional is narrowing. Treating what the
                // action requires as optional is not: the person could leave it out, and the
                // invocation would then fail the action's own schema.
                if declared.required && !parameter.required {
                    report.push(Finding::at(
                        FindingCode::ControlParametersWiden,
                        PRESENTATION_FILE,
                        format!(
                            "{owner} treats {} as optional, which the action {} requires",
                            parameter.name, action.id
                        ),
                    ));
                }
            }
        }
    }
    for declared in &action.parameters.parameters {
        if declared.required
            && !parameters
                .parameters
                .iter()
                .any(|parameter| parameter.name == declared.name)
        {
            report.push(Finding::at(
                FindingCode::ControlParametersWiden,
                PRESENTATION_FILE,
                format!(
                    "{owner} omits {}, which the action {} requires",
                    declared.name, action.id
                ),
            ));
        }
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

/// Returns true when two field paths cannot both be written into one request.
///
/// Two paths conflict when they name the same field, when one is inside the other, or when they
/// disagree about what a shared prefix is. `params.0` and `params.name` need `params` to be both an
/// array and an object, so writing both is not a thing a broker can do, and the manifest says so
/// rather than leaving it to find out.
fn paths_overlap(left: &FieldPath, right: &FieldPath) -> bool {
    use crate::connector::FieldSegment;

    for (one, other) in left.segments.iter().zip(&right.segments) {
        if one == other {
            continue;
        }
        return matches!(
            (one, other),
            (FieldSegment::Member { .. }, FieldSegment::Index { .. })
                | (FieldSegment::Index { .. }, FieldSegment::Member { .. })
        );
    }
    true
}

/// Checks one bounded field path.
fn check_field_path(path: &FieldPath, owner: &str, report: &mut Report) {
    if path.segments.is_empty() || path.segments.len() > MAX_FIELD_PATH_DEPTH {
        report.push(Finding::new(
            FindingCode::ConnectorTableInvalid,
            format!(
                "{owner} has a field path with {} segments; the range is 1 to {MAX_FIELD_PATH_DEPTH}",
                path.segments.len()
            ),
        ));
    }
    for segment in &path.segments {
        if let crate::connector::FieldSegment::Member { name } = segment
            && name.is_empty()
        {
            report.push(Finding::new(
                FindingCode::ConnectorTableInvalid,
                format!("{owner} has a field path with an unnamed member"),
            ));
        }
    }
}

/// Returns true when text is a usable header name.
fn is_header_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|character| character.is_ascii_graphic() && character != ':')
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
            "qualified_range admits protocol versions nobody tested",
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

    check_field_path(&connector.request_id_path, "the connector table", report);
    check_field_path(&connector.method_path, "the connector table", report);
    if let crate::connector::ResponseCorrelation::MatchingId { id_path } =
        &connector.response_correlation
    {
        check_field_path(id_path, "the response correlation", report);
    }

    let bytes = connector.framing.max_message_bytes();
    if !Framing::MESSAGE_BYTES_RANGE.contains(&bytes) {
        report.push(Finding::at(
            FindingCode::ConnectorTableInvalid,
            CONNECTOR_FILE,
            format!(
                "the framing accepts {bytes} bytes per message; the range is {} to {}",
                Framing::MESSAGE_BYTES_RANGE.start(),
                Framing::MESSAGE_BYTES_RANGE.end()
            ),
        ));
    }
    match &connector.framing {
        Framing::LengthPrefixed { prefix_bytes, .. }
            if !Framing::PREFIX_WIDTHS.contains(prefix_bytes) =>
        {
            report.push(Finding::at(
                FindingCode::ConnectorTableInvalid,
                CONNECTOR_FILE,
                format!(
                    "a length prefix is {:?} bytes wide, not {prefix_bytes}",
                    Framing::PREFIX_WIDTHS
                ),
            ));
        }
        Framing::ContentLength { length_header, .. } if !is_header_name(length_header) => {
            report.push(Finding::at(
                FindingCode::ConnectorTableInvalid,
                CONNECTOR_FILE,
                format!("{length_header:?} is not a header name"),
            ));
        }
        _ => {}
    }

    // One method, one route, one classification. A table that answers a question twice is a table
    // whose answer depends on which copy a reader happens to look at.
    let mut routed = BTreeSet::new();
    let mut wire_names = BTreeSet::new();
    for route in &connector.routes {
        if !routed.insert(&route.method) {
            report.push(Finding::at(
                FindingCode::ConnectorTableInvalid,
                CONNECTOR_FILE,
                format!("the table routes {} more than once", route.method),
            ));
        }
        if route.wire_name.is_empty() {
            report.push(Finding::at(
                FindingCode::ConnectorTableInvalid,
                CONNECTOR_FILE,
                format!("the route for {} has no wire name", route.method),
            ));
        }
        if !wire_names.insert(route.wire_name.as_str()) {
            report.push(Finding::at(
                FindingCode::ConnectorTableInvalid,
                CONNECTOR_FILE,
                format!(
                    "two routes share the wire name {:?}, so a message cannot be routed",
                    route.wire_name
                ),
            ));
        }
    }
    let mut classified = BTreeSet::new();
    for entry in &connector.methods {
        if !classified.insert(&entry.method) {
            report.push(Finding::at(
                FindingCode::ConnectorTableInvalid,
                CONNECTOR_FILE,
                format!("the table classifies {} more than once", entry.method),
            ));
        }
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
    for route in &connector.routes {
        if !classified.contains(&route.method) {
            report.push(Finding::at(
                FindingCode::ConnectorTableInvalid,
                CONNECTOR_FILE,
                format!(
                    "the table routes {} without classifying it; an unclassified method is treated as a mutation",
                    route.method
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
