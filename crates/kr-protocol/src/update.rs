//! Updating a host: what one release is, the compatibility level two builds must share, and the
//! handover by which a control daemon makes way for another release's.
//!
//! Section 26 lets a host replace its control daemon while its workers, their agents and their
//! shell trees stay on the release they started from. That needs three things written down in one
//! place, because the processes that read them are of different releases:
//!
//! * **A release** is an immutable tree: `bin/` with the host's executables, `shells/` with the
//!   qualified shell packages the release was tested with, `share/` with the release's own data,
//!   the update channel's root among it, and `release.json`, the [`ReleaseManifest`] that names
//!   every other file. A host keeps several side by side and runs each process from the one it
//!   started from. Which executables a release carries is `scripts/release-programs.json`'s to
//!   say ([`required_programs`]); a host takes in only a release that lists them all.
//! * **A compatibility level** ([`CompatibilityLevel`]) says which frames a build reads: two
//!   builds read each other's when their protocol package versions share one. A control daemon
//!   speaks to a worker only at a level its release retains, and an update waits while a live
//!   worker runs at a level the new release does not retain.
//! * **The handover** (`host.update.handover`) is how the release that updates a host asks a
//!   running control daemon to make way: close its gate to new sessions, let the creates it has
//!   started settle, say how it was started, and stop. Nothing else about a daemon changes, and a
//!   session is never stopped by it.
//!
//! # The manifest's document
//!
//! `release.json` is the manifest in the envelope the update channel's metadata uses:
//! `{"signed": <manifest>, "signatures": [{"keyid": <hex>, "sig": <hex>}]}`, each signature over
//! the canonical JSON of `signed`. The manifest's own `_type` member, `kalareach-release`, is inside
//! what is signed, so a signature over the channel's own metadata never passes for one over a
//! release. Who may sign is not this crate's to say: the host that installs a release checks a
//! threshold of the keys its channel root names, and this crate only reads.
//!
//! A reader reads past a member it does not know. A later release may describe itself with more
//! than an earlier one knows, and the earlier release's updater still has to be able to install
//! it; what it does check is everything it knows.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::hello::{PACKAGE_VERSION, PackageVersion};
use crate::scalars::{Digest256, Nullable, U64, Uuid};

/* -------------------------------------------------------------------------------------------- */
/* Compatibility levels                                                                         */
/* -------------------------------------------------------------------------------------------- */

/// A compatibility level: what two builds' protocol package versions must share for each to read
/// the other's frames.
///
/// Below 1.0.0 it is the major and minor number together, and from 1.0.0 the major number alone
/// ([`PackageVersion::shares_frames_with`], which this agrees with for every pair of versions).
/// Written as text: `0.48` below 1.0.0, `1` from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompatibilityLevel {
    major: u16,
    /// The minor number below 1.0.0, and zero from it, where the minor number does not decide.
    minor: u16,
}

impl CompatibilityLevel {
    /// The level a protocol package version is at.
    #[must_use]
    pub const fn of(version: PackageVersion) -> Self {
        Self {
            major: version.major,
            minor: if version.major == 0 { version.minor } else { 0 },
        }
    }

    /// Whether a build of `version` reads and writes the frames of this level.
    #[must_use]
    pub const fn admits(self, version: PackageVersion) -> bool {
        let other = Self::of(version);
        self.major == other.major && self.minor == other.minor
    }

    /// The major number.
    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    /// The minor number, below 1.0.0, where it is part of the level.
    #[must_use]
    pub const fn minor(self) -> Option<u16> {
        if self.major == 0 {
            Some(self.minor)
        } else {
            None
        }
    }
}

/// This build's own level: the level of the protocol package it was built from.
pub const THIS_LEVEL: CompatibilityLevel = CompatibilityLevel::of(PACKAGE_VERSION);

impl fmt::Display for CompatibilityLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.minor() {
            Some(minor) => write!(formatter, "{}.{minor}", self.major),
            None => write!(formatter, "{}", self.major),
        }
    }
}

/// Text that is not a compatibility level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "a compatibility level is `0.<minor>` below 1.0.0 and `<major>` from it, each a number \
     without leading zeros"
)]
pub struct LevelError;

impl FromStr for CompatibilityLevel {
    type Err = LevelError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.split_once('.') {
            // Below 1.0.0 the minor number is part of the level, and it is written.
            Some((major, minor)) => {
                let major = number(major).ok_or(LevelError)?;
                let minor = number(minor).ok_or(LevelError)?;
                if major != 0 {
                    return Err(LevelError);
                }
                Ok(Self { major, minor })
            }
            // From 1.0.0 the major number alone is the level, and zero is never written alone.
            None => {
                let major = number(text).ok_or(LevelError)?;
                if major == 0 {
                    return Err(LevelError);
                }
                Ok(Self { major, minor: 0 })
            }
        }
    }
}

/// A decimal number without leading zeros that fits a version's number.
fn number(text: &str) -> Option<u16> {
    let well_formed = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if well_formed { text.parse().ok() } else { None }
}

impl Serialize for CompatibilityLevel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CompatibilityLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for CompatibilityLevel {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CompatibilityLevel".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::CompatibilityLevel".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^(0\\.(0|[1-9][0-9]*)|[1-9][0-9]*)$",
            "description": "A compatibility level: `0.<minor>` below protocol 1.0.0 and `<major>` from it."
        })
    }
}

/* -------------------------------------------------------------------------------------------- */
/* Release names                                                                                */
/* -------------------------------------------------------------------------------------------- */

/// The longest release name.
pub const MAX_RELEASE_NAME_LEN: usize = 64;

/// The name of one release: its version and the first twelve hexadecimal digits of its commit,
/// `<version>+<commit>`, as its tag names it (`0.2.0+4254aa6e62e5`).
///
/// It names the release's directory on a host and follows the program's name in each of its build
/// identifiers, so nothing a path or a reader could take for something else gets in: the version is
/// three numbers separated by dots, and the commit is twelve lower-case hexadecimal digits.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ReleaseName(String);

/// Text that is not a release name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "a release name is `<version>+<commit>`: three numbers separated by dots, a plus sign and \
     twelve lower-case hexadecimal digits"
)]
pub struct ReleaseNameError;

impl ReleaseName {
    /// Checks and wraps a release name.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseNameError`] when the text is not `<version>+<commit>`.
    pub fn new(value: impl Into<String>) -> Result<Self, ReleaseNameError> {
        let value = value.into();
        if value.len() > MAX_RELEASE_NAME_LEN {
            return Err(ReleaseNameError);
        }
        let (version, commit) = value.split_once('+').ok_or(ReleaseNameError)?;
        let commit_well_formed = commit.len() == 12
            && commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !commit_well_formed {
            return Err(ReleaseNameError);
        }
        let mut parts = version.split('.');
        for _ in 0..3 {
            number(parts.next().ok_or(ReleaseNameError)?).ok_or(ReleaseNameError)?;
        }
        if parts.next().is_some() {
            return Err(ReleaseNameError);
        }
        Ok(Self(value))
    }

    /// Returns the name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReleaseName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ReleaseName {
    type Err = ReleaseNameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl<'de> Deserialize<'de> for ReleaseName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ReleaseName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ReleaseName".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::ReleaseName".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "maxLength": MAX_RELEASE_NAME_LEN,
            "pattern": "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\+[0-9a-f]{12}$",
            "description": "One release of the host: its version and the first twelve hexadecimal digits of its commit."
        })
    }
}

/* -------------------------------------------------------------------------------------------- */
/* The manifest                                                                                 */
/* -------------------------------------------------------------------------------------------- */

/// The name of a release's manifest in its tree.
pub const MANIFEST_FILE: &str = "release.json";

/// The largest manifest a host reads.
///
/// A release lists a few hundred files; this is far more than one ever needs, and a bound on what
/// every host process reads at its start.
pub const MAX_MANIFEST_LEN: u64 = 4 * 1024 * 1024;

/// The top-level directories a release's files are in.
pub const RELEASE_DIRECTORIES: [&str; 3] = ["bin", "shells", "share"];

/// The programs a host needs, as `scripts/release-programs.json` names them: the one list the
/// release builds, the archive checks and this check read. It is taken in when this crate is
/// built, so a build of the host carries the list its own release was built from.
const RELEASE_PROGRAMS: &str = include_str!("../../../scripts/release-programs.json");

/// The list of programs, read as far as this crate needs it. The file also says which package
/// builds each program, which only a build reads.
#[derive(Deserialize)]
struct ProgramList {
    programs: Vec<ListedProgram>,
}

/// One program of the list, and the targets that do not carry it.
#[derive(Deserialize)]
struct ListedProgram {
    name: String,
    #[serde(default)]
    not_on: Vec<String>,
}

/// The programs a release for `target` has to carry in `bin/`, by name and without the suffix a
/// Windows executable has.
///
/// # Panics
///
/// Panics when the list this crate was built with is not a list of programs, which a test of this
/// crate rules out.
pub fn required_programs(target: &str) -> impl Iterator<Item = &'static str> {
    static LIST: std::sync::LazyLock<ProgramList> = std::sync::LazyLock::new(|| {
        serde_json::from_str(RELEASE_PROGRAMS).unwrap_or_else(|error| {
            panic!("scripts/release-programs.json is not a list of programs: {error}")
        })
    });
    LIST.programs
        .iter()
        .filter(move |program| !program.not_on.iter().any(|named| named == target))
        .map(|program| program.name.as_str())
}

/// What one release is, as `release.json` states it and a threshold of the release keys signs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    /// What this document is: always [`ManifestKind::Release`].
    #[serde(rename = "_type")]
    pub kind: ManifestKind,
    /// The release, which also names its directory on a host.
    pub release: ReleaseName,
    /// Where it stands among releases: a later release has a larger sequence.
    pub sequence: U64,
    /// The commit it was built from, in full.
    pub commit: CommitId,
    /// The target it was built for, as its triple (`aarch64-apple-darwin`).
    pub target: String,
    /// The oldest operating system it runs on.
    pub os_floor: OsFloor,
    /// The protocol package version its processes were built from.
    pub protocol_version: PackageVersion,
    /// The public protocol majors its hosts accept from a device.
    pub public_majors: Vec<u16>,
    /// The compatibility levels its control daemon speaks to a worker at. A live worker at any
    /// other level holds an update to it.
    pub retained_levels: Vec<CompatibilityLevel>,
    /// The qualified shell packages under `shells/`.
    pub shells: Vec<ReleaseShell>,
    /// Every file of the release but this manifest.
    pub files: Vec<ReleaseFile>,
}

/// What a manifest document is, which its signatures cover as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestKind {
    /// A release manifest.
    #[serde(rename = "kalareach-release")]
    Release,
}

/// A commit identifier: forty lower-case hexadecimal digits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CommitId(String);

impl CommitId {
    /// Checks and wraps a commit identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the text is not forty lower-case hexadecimal digits.
    pub fn new(value: impl Into<String>) -> Result<Self, ManifestError> {
        let value = value.into();
        let well_formed = value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if well_formed {
            Ok(Self(value))
        } else {
            Err(ManifestError::Malformed(
                "a commit is forty lower-case hexadecimal digits".to_owned(),
            ))
        }
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CommitId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

/// The oldest operating system a release runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsFloor {
    /// Which system the version is of.
    pub system: FloorSystem,
    /// The oldest version.
    pub version: FloorVersion,
}

/// What an operating system floor is a version of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FloorSystem {
    /// The macOS release, `14.0`.
    Macos,
    /// The GNU C library's version on Linux, `2.35`.
    Glibc,
    /// The Windows version, `10.0`.
    Windows,
}

impl FloorSystem {
    /// The system's name, as the manifest writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Glibc => "glibc",
            Self::Windows => "windows",
        }
    }
}

/// A version of the form `<major>.<minor>`, compared number by number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FloorVersion {
    /// The major number.
    pub major: u16,
    /// The minor number.
    pub minor: u16,
}

impl FloorVersion {
    /// Reads `<major>.<minor>`, or `<major>` alone as `<major>.0`, from the start of `text`,
    /// ignoring anything after a further dot.
    ///
    /// This is how an operating system states its own version (`14.6.1`, `2.35`), and the floor
    /// is compared on its first two numbers.
    #[must_use]
    pub fn leading(text: &str) -> Option<Self> {
        let mut parts = text.trim().split('.');
        let major = number(parts.next()?)?;
        let minor = match parts.next() {
            Some(minor) => number(minor)?,
            None => 0,
        };
        Some(Self { major, minor })
    }
}

impl fmt::Display for FloorVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

impl Serialize for FloorVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for FloorVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        match text.split_once('.') {
            Some((major, minor)) if !minor.contains('.') => Ok(Self {
                major: number(major).ok_or_else(|| serde::de::Error::custom(FLOOR_FORM))?,
                minor: number(minor).ok_or_else(|| serde::de::Error::custom(FLOOR_FORM))?,
            }),
            _ => Err(serde::de::Error::custom(FLOOR_FORM)),
        }
    }
}

/// What a floor's version is written as.
const FLOOR_FORM: &str = "a floor's version is `<major>.<minor>`";

/// One qualified shell package a release carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseShell {
    /// Which shell: `zsh`, `bash`, `fish` or `powershell`.
    pub shell: String,
    /// The package's identity, which names its directory under `shells/<shell>/`.
    pub identity: String,
    /// The reader patches built into it, by their revisions.
    pub patch_revisions: Vec<String>,
}

/// One file of a release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseFile {
    /// Where it is, relative to the release's directory, its parts separated by `/`.
    pub path: ReleasePath,
    /// Its length in bytes.
    pub length: U64,
    /// Its SHA-256 digest.
    pub sha256: Digest256,
    /// Whether it is a program.
    pub mode: FileMode,
}

/// Whether a release's file is a program.
///
/// A release holds regular files and nothing else: no links, no devices, no empty directories.
/// A host installs each read-only, and a program runnable as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileMode {
    /// A file that is read.
    Regular,
    /// A program.
    Executable,
}

/// The longest path of a file in a release.
pub const MAX_RELEASE_PATH_LEN: usize = 1024;

/// Where a file is in a release: relative, its parts separated by `/`, under one of
/// [`RELEASE_DIRECTORIES`], and naming nothing outside the release.
///
/// No part is empty, `.` or `..`, and none holds a backslash, a colon or a control character, so
/// the same text names the same file on every system a release is installed on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ReleasePath(String);

impl ReleasePath {
    /// Checks and wraps a path.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Path`] when the path could name something outside the release, or
    /// something a system reads differently.
    pub fn new(value: impl Into<String>) -> Result<Self, ManifestError> {
        let value = value.into();
        let refuse = |reason: &'static str| ManifestError::Path {
            path: value.clone(),
            reason,
        };
        if value.is_empty() || value.len() > MAX_RELEASE_PATH_LEN {
            return Err(refuse("is empty or longer than a release's paths are"));
        }
        let mut parts = value.split('/');
        let first = parts.next().unwrap_or_default();
        if !RELEASE_DIRECTORIES.contains(&first) {
            return Err(refuse("is not under bin, shells or share"));
        }
        let mut depth = 1;
        for part in parts {
            depth += 1;
            if part.is_empty() || part == "." || part == ".." {
                return Err(refuse("has an empty, `.` or `..` part"));
            }
            if part
                .chars()
                .any(|character| character.is_control() || matches!(character, '\\' | ':'))
            {
                return Err(refuse(
                    "has a part with a backslash, a colon or a control character",
                ));
            }
        }
        if depth < 2 {
            return Err(refuse("names a directory rather than a file in it"));
        }
        Ok(Self(value))
    }

    /// Returns the path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns its parts, in order.
    pub fn parts(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }
}

impl fmt::Display for ReleasePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ReleasePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

/// Why a manifest cannot be read, or cannot be a release's.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// The document is not a signed release manifest this build reads.
    #[error("it is not a signed release manifest: {0}")]
    Malformed(String),
    /// A file's path could name something outside the release.
    #[error("it lists `{path}`, which {reason}")]
    Path {
        /// The path, as the manifest writes it.
        path: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// Two of its files are the same file, or one is inside another.
    #[error("it lists `{first}` and `{second}`, which a host cannot install both of")]
    Overlapping {
        /// One of them.
        first: String,
        /// The other.
        second: String,
    },
}

/// The part of `release.json` this crate reads: the manifest's members, whatever signs them.
#[derive(Deserialize)]
struct Envelope {
    signed: SignedMembers,
}

/// A manifest's members held exactly as they were read: what the release keys signed, members
/// this build does not know included, so a signature is checked over the document its signer
/// wrote rather than over this build's reading of it.
///
/// Serialised, it is those members again; a checker computes their canonical form from this.
///
/// Read strictly: an object that names one member twice, at any depth, is refused. A reading that
/// kept one of the two would check a signature over a document other than the one a program of the
/// release reads when it starts, and the two readings of one release must agree. Every reading of
/// a manifest, the updater's and each program's own, goes through this one.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SignedMembers(serde_json::Value);

impl<'de> Deserialize<'de> for SignedMembers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Strict).map(Self)
    }
}

/// Reads any JSON value, refusing an object that names one member twice, at any depth.
struct Strict;

impl<'de> serde::de::DeserializeSeed<'de> for Strict {
    type Value = serde_json::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for Strict {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value whose objects name each member once")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("a number JSON cannot hold"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(serde_json::Value::String(value))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Strict)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut members = serde_json::Map::new();
        while let Some(name) = map.next_key::<String>()? {
            if members.contains_key(&name) {
                return Err(serde::de::Error::custom(
                    "an object names one of its members twice",
                ));
            }
            let value = map.next_value_seed(Strict)?;
            members.insert(name, value);
        }
        Ok(serde_json::Value::Object(members))
    }
}

impl SignedMembers {
    /// The members a manifest serialises to, which is what a signer signs.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Malformed`] when the manifest does not serialise, which a manifest
    /// of these types always does.
    pub fn of(manifest: &ReleaseManifest) -> Result<Self, ManifestError> {
        serde_json::to_value(manifest)
            .map(Self)
            .map_err(|error| ManifestError::Malformed(error.to_string()))
    }

    /// Reads the manifest these members are, past members this build does not know, and checks
    /// that it can be a release's.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the members are not a release manifest, or list files a
    /// host cannot install.
    pub fn manifest(&self) -> Result<ReleaseManifest, ManifestError> {
        let manifest: ReleaseManifest = serde_json::from_value(self.0.clone())
            .map_err(|error| ManifestError::Malformed(error.to_string()))?;
        manifest.check()?;
        Ok(manifest)
    }
}

impl ReleaseManifest {
    /// Reads the manifest out of a release's `release.json`, without looking at its signatures,
    /// and checks that it can be a release's.
    ///
    /// Every host process reads its own release's manifest this way when it starts, to learn
    /// which release it is: that release was checked when it was installed, and nothing but the
    /// installer writes the directory it is in. An updater checks the signatures before it reads a
    /// release this way.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the document is not a release manifest, or lists files a host
    /// cannot install.
    pub fn read_document(bytes: &[u8]) -> Result<Self, ManifestError> {
        let envelope: Envelope = serde_json::from_slice(bytes)
            .map_err(|error| ManifestError::Malformed(error.to_string()))?;
        envelope.signed.manifest()
    }

    /// Checks what a host must know before it installs anything a manifest lists: that no two of
    /// its files are one file, on a system that compares names without regard to case as well, and
    /// that none is inside another.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Overlapping`] naming the first such pair.
    pub fn check(&self) -> Result<(), ManifestError> {
        let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
        for file in &self.files {
            let folded = file.path.as_str().to_ascii_lowercase();
            if let Some(first) = seen.insert(folded.clone(), file.path.as_str()) {
                return Err(ManifestError::Overlapping {
                    first: first.to_owned(),
                    second: file.path.as_str().to_owned(),
                });
            }
        }
        // A file whose path is another's with more after a `/` would need that other to be a
        // directory. Sorted, such a pair is adjacent but for paths between them that share the
        // same prefix, so each path is compared with every earlier one it starts with.
        for (folded, original) in &seen {
            let mut prefix = String::new();
            for part in folded.split('/') {
                if !prefix.is_empty() {
                    if let Some(first) = seen.get(&prefix) {
                        return Err(ManifestError::Overlapping {
                            first: (*first).to_owned(),
                            second: (*original).to_owned(),
                        });
                    }
                    prefix.push('/');
                }
                prefix.push_str(part);
            }
        }
        Ok(())
    }

    /// The file a path names, where the manifest lists one.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&ReleaseFile> {
        self.files.iter().find(|file| file.path.as_str() == path)
    }

    /// The programs a host of this release's target needs that the release does not list as
    /// programs: each is a file of `bin/` that is absent, or is there as a file that is not
    /// runnable.
    ///
    /// This is a question about a release being taken in. A release already in a store was checked
    /// when it was installed, by the build that installed it, and is read as it is: every host
    /// process reads its own release's manifest without asking it.
    #[must_use]
    pub fn missing_programs(&self) -> Vec<&'static str> {
        let suffix = if self.target.contains("-windows-") {
            ".exe"
        } else {
            ""
        };
        required_programs(&self.target)
            .filter(|name| {
                !self
                    .file(&format!("bin/{name}{suffix}"))
                    .is_some_and(|file| file.mode == FileMode::Executable)
            })
            .collect()
    }

    /// Whether this release's control daemon speaks to a worker built from `version`.
    #[must_use]
    pub fn retains(&self, version: PackageVersion) -> bool {
        self.retained_levels
            .iter()
            .any(|level| level.admits(version))
    }
}

/* -------------------------------------------------------------------------------------------- */
/* The handover                                                                                 */
/* -------------------------------------------------------------------------------------------- */

/// How long a daemon keeps its gate closed after it is asked to prepare, unless it is told to stop
/// or to resume first.
///
/// The updater that asked may itself stop before it says either, and a daemon whose gate stayed
/// closed would refuse every new session until somebody noticed. Long enough for an updater to
/// prepare every environment of a host, record how each was started and tell each to stop.
pub const HANDOVER_HOLD_MS: u64 = 300_000;

/// How long a daemon asked to prepare waits for the creates it has already started to settle,
/// before it says the handover cannot happen now.
///
/// A create waits up to thirty seconds for its worker to report itself; this covers that, and the
/// window the create's own answer takes.
pub const HANDOVER_SETTLE_MS: u64 = 45_000;

/// One step of `host.update.handover`.
///
/// A handover is an attempt: `prepare` begins one and answers its identity, and only a `stop` that
/// names that identity stops the daemon. An attempt ends at its first `stop` or `resume`, when its
/// hold lapses, or when a later `prepare` begins another; nothing can act on an attempt that has
/// ended, so a `stop` that arrives late, after the update it belonged to gave up, ends nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandoverStep {
    /// Begin an attempt: close the gate to new sessions, wait for the creates already started to
    /// settle, and say how this daemon was started and under which attempt. The gate stays closed
    /// for [`HANDOVER_HOLD_MS`], until a `stop` or a `resume`, or until a later `prepare`.
    Prepare,
    /// Stop, having prepared, under the attempt `prepare` answered. Refused for any other
    /// attempt, and when the gate is open or its hold has lapsed, so a daemon is never stopped by
    /// a handover that is over or with its gate open.
    Stop,
    /// End the attempt named, or whichever is open when none is named: the update is not going
    /// ahead now, and the gate opens again. Refused once the daemon has been told to stop, so a
    /// daemon that resumes is one no stop of an attempt can end. An attempt that is not open is
    /// already over, and resuming it changes nothing.
    Resume,
}

/// `host.update.handover` parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostUpdateHandoverParams {
    /// The step to take.
    pub step: HandoverStep,
    /// The release the host is being updated to, which a create refused meanwhile is told.
    pub target: ReleaseName,
    /// The attempt the step is for: what a `stop` must name, and what a `resume` may name. Null
    /// for `prepare`, which begins one, and for a `resume` that ends whichever is open.
    pub attempt: Nullable<Uuid>,
}

/// `host.update.handover` result: how the daemon was started, which a daemon of the release that
/// replaces it is started like, and the attempt the step was for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostUpdateHandoverResult {
    /// The attempt the answer is for: the one `prepare` began, the one `stop` stopped under, and
    /// for `resume` the one it ended, null when none was open.
    pub attempt: Nullable<Uuid>,
    /// The release this daemon runs, where it runs an installed one.
    pub release: Nullable<ReleaseName>,
    /// Its process identifier.
    pub pid: U64,
    /// The arguments it was started with, its program's own name left out. A `prepare` answers how
    /// the daemon was started, and refuses where it cannot say; a `stop` or a `resume` is taken all
    /// the same and answers this empty where it cannot.
    pub arguments: Vec<String>,
    /// The directory it was started in; empty, as `arguments` is, where a `stop` or a `resume` cannot
    /// say.
    pub working_directory: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A level agrees with `shares_frames_with` for every pair of versions: two builds share a
    /// level exactly when each reads the other's frames.
    #[test]
    fn two_versions_share_a_level_exactly_when_their_frames_are_shared() {
        let versions = [
            PackageVersion::new(0, 47, 0),
            PackageVersion::new(0, 47, 3),
            PackageVersion::new(0, 48, 0),
            PackageVersion::new(0, 48, 9),
            PackageVersion::new(1, 0, 0),
            PackageVersion::new(1, 7, 2),
            PackageVersion::new(2, 0, 0),
        ];
        for one in versions {
            for other in versions {
                assert_eq!(
                    CompatibilityLevel::of(one) == CompatibilityLevel::of(other),
                    one.shares_frames_with(other),
                    "{one} and {other}"
                );
                assert_eq!(
                    CompatibilityLevel::of(one).admits(other),
                    one.shares_frames_with(other),
                    "{one} and {other}"
                );
            }
        }
        assert_eq!(THIS_LEVEL, CompatibilityLevel::of(PACKAGE_VERSION));
    }

    /// Below 1.0.0 a level is written with its minor number, and from 1.0.0 without one; nothing
    /// else reads as a level.
    #[test]
    fn a_level_is_written_with_its_minor_below_one_and_without_it_from_one() {
        assert_eq!(
            CompatibilityLevel::of(PackageVersion::new(0, 48, 2)).to_string(),
            "0.48"
        );
        assert_eq!(
            CompatibilityLevel::of(PackageVersion::new(3, 4, 5)).to_string(),
            "3"
        );
        for text in ["0.48", "0.0", "1", "12"] {
            let level: CompatibilityLevel = text.parse().expect("a level");
            assert_eq!(level.to_string(), text);
            let json = serde_json::to_string(&level).expect("encodes");
            assert_eq!(json, format!("\"{text}\""));
            let back: CompatibilityLevel = serde_json::from_str(&json).expect("decodes");
            assert_eq!(back, level);
        }
        // The control: each of these is refused, and a level that was merely read loosely would
        // have taken some of them.
        for text in [
            "0", "1.2", "0.048", "00.4", "", "0.", ".4", "0.4.1", "-1", "0.x",
        ] {
            assert!(
                text.parse::<CompatibilityLevel>().is_err(),
                "{text:?} is not a level"
            );
        }
    }

    /// A release name is a version and twelve hexadecimal digits, and nothing a path could read
    /// as something else gets in.
    #[test]
    fn a_release_name_is_a_version_and_a_commit_and_nothing_a_path_misreads() {
        for text in [
            "0.1.0+4254aa6e62e5",
            "12.0.3+0123456789ab",
            "1.0.0+ffffffffffff",
        ] {
            let name = ReleaseName::new(text).expect("a release name");
            assert_eq!(name.as_str(), text);
            let json = serde_json::to_string(&name).expect("encodes");
            let back: ReleaseName = serde_json::from_str(&json).expect("decodes");
            assert_eq!(back, name);
        }
        for text in [
            "",
            "0.1.0",
            "0.1.0+4254aa6e62e",
            "0.1.0+4254aa6e62e5a",
            "0.1.0+4254AA6E62E5",
            "0.1+4254aa6e62e5",
            "0.1.0.0+4254aa6e62e5",
            "00.1.0+4254aa6e62e5",
            "../0.1.0+4254aa6e62e5",
            "0.1.0/..+4254aa6e62e5",
            "0.1.0-rc.1+4254aa6e62e5",
            "0.1.0-+4254aa6e62e5",
            "0.1.0+4254aa6e62e5+4254aa6e62e5",
            "999999.0.0+4254aa6e62e5",
        ] {
            assert!(ReleaseName::new(text).is_err(), "{text:?} is not a name");
        }
    }

    /// A file's path stays inside the release and reads the same on every system.
    #[test]
    fn a_release_path_stays_inside_the_release() {
        for text in ["bin/kr", "shells/zsh/abc/bin/zsh", "share/update-root.json"] {
            let path = ReleasePath::new(text).expect("a path");
            assert_eq!(path.as_str(), text);
        }
        for text in [
            "",
            "bin",
            "/bin/kr",
            "bin/",
            "bin//kr",
            "bin/./kr",
            "bin/../kr",
            "lib/kr",
            "release.json",
            "bin/k\\r",
            "bin/c:kr",
            "bin/k\nr",
            "Bin/kr",
        ] {
            assert!(ReleasePath::new(text).is_err(), "{text:?} is refused");
        }
    }

    fn file(path: &str) -> ReleaseFile {
        ReleaseFile {
            path: ReleasePath::new(path).expect("a path"),
            length: U64::new(1),
            sha256: Digest256::from_bytes([7; 32]),
            mode: FileMode::Regular,
        }
    }

    fn manifest(files: Vec<ReleaseFile>) -> ReleaseManifest {
        ReleaseManifest {
            kind: ManifestKind::Release,
            release: ReleaseName::new("0.1.0+4254aa6e62e5").expect("a name"),
            sequence: U64::new(3),
            commit: CommitId::new("4254aa6e62e585478ff8dcff5518f23c7263f4ce").expect("a commit"),
            target: "aarch64-apple-darwin".to_owned(),
            os_floor: OsFloor {
                system: FloorSystem::Macos,
                version: FloorVersion {
                    major: 14,
                    minor: 0,
                },
            },
            protocol_version: PackageVersion::new(0, 48, 0),
            public_majors: vec![1],
            retained_levels: vec![CompatibilityLevel::of(PackageVersion::new(0, 48, 0))],
            shells: Vec::new(),
            files,
        }
    }

    /// Two files that are one file on a system that ignores case, or one inside the other, are
    /// refused before anything is installed; files that merely share a beginning are not.
    #[test]
    fn a_manifest_never_lists_one_file_twice_or_one_inside_another() {
        manifest(vec![
            file("bin/kr"),
            file("bin/kr-worker"),
            file("bin/kr.d/x"),
        ])
        .check()
        .expect("files that share a beginning are different files");
        for (first, second) in [
            ("bin/kr", "bin/kr"),
            ("bin/kr", "bin/KR"),
            ("bin/kr", "bin/kr/x"),
            ("share/a/b", "share/A/b/c"),
        ] {
            let refused = manifest(vec![file(first), file(second)])
                .check()
                .expect_err("refused");
            assert!(
                matches!(refused, ManifestError::Overlapping { .. }),
                "{first} and {second}: {refused}"
            );
        }
    }

    /// KR-REQ-26.09: every release target needs the seven executables a host runs, but for the
    /// description process on Windows on Arm, where no model profile lists the target and the
    /// process is not built. The names are written out here, apart from the list they are read from,
    /// so that a program dropped from it is caught.
    #[test]
    fn a_host_needs_seven_programs_and_one_target_needs_six() {
        fn sorted(mut names: Vec<&'static str>) -> Vec<&'static str> {
            names.sort_unstable();
            names
        }
        let seven = vec![
            "kr",
            "kr-attach-guard",
            "kr-controller",
            "kr-describe-inference",
            "kr-hook",
            "kr-plugin-host",
            "kr-worker",
        ];
        for target in [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
        ] {
            assert_eq!(
                sorted(required_programs(target).collect()),
                seven,
                "{target}"
            );
        }
        let without_description: Vec<&str> = seven
            .iter()
            .copied()
            .filter(|name| *name != "kr-describe-inference")
            .collect();
        assert_eq!(
            sorted(required_programs("aarch64-pc-windows-msvc").collect()),
            without_description
        );
    }

    /// KR-REQ-26.09: a program is a file of `bin/` under the name its target gives an executable:
    /// a Windows release lists `kr.exe`, and `kr` there is not the program. A manifest that lists a
    /// program as data is refused through the command, by the update tests.
    #[test]
    fn a_program_has_the_file_name_its_target_gives_an_executable() {
        let listed = |target: &str, suffix: &str| {
            let files = required_programs(target)
                .map(|name| ReleaseFile {
                    mode: FileMode::Executable,
                    ..file(&format!("bin/{name}{suffix}"))
                })
                .collect();
            ReleaseManifest {
                target: target.to_owned(),
                ..manifest(files)
            }
        };
        for (target, suffix) in [
            ("aarch64-apple-darwin", ""),
            ("x86_64-pc-windows-msvc", ".exe"),
            ("aarch64-pc-windows-msvc", ".exe"),
        ] {
            assert_eq!(
                listed(target, suffix).missing_programs(),
                Vec::<&str>::new(),
                "{target}"
            );
        }
        assert_eq!(
            listed("x86_64-pc-windows-msvc", "")
                .missing_programs()
                .len(),
            7
        );
    }

    /// The manifest is read out of its signed document, and a member a later release adds is read
    /// past rather than refused.
    #[test]
    fn a_manifest_is_read_from_its_document_past_members_a_later_release_adds() {
        let written = manifest(vec![file("bin/kr")]);
        let mut signed = serde_json::to_value(&written).expect("encodes");
        signed["stores"] = serde_json::json!([{"store": "registry", "version": 6}]);
        let document = serde_json::json!({
            "signed": signed,
            "signatures": [{"keyid": "00", "sig": "00"}],
        });
        let read = ReleaseManifest::read_document(document.to_string().as_bytes())
            .expect("a later release's manifest is read");
        assert_eq!(read, written);
        assert_eq!(signed["_type"], "kalareach-release");
        assert_eq!(signed["sequence"], "3");
        // The control: the same document with another type is not a release's manifest.
        let mut other = document.clone();
        other["signed"]["_type"] = serde_json::json!("targets");
        assert!(ReleaseManifest::read_document(other.to_string().as_bytes()).is_err());
        let mut outside = document;
        outside["signed"]["files"][0]["path"] = serde_json::json!("bin/../../escape");
        assert!(ReleaseManifest::read_document(outside.to_string().as_bytes()).is_err());
    }

    /// A document that names a member twice is refused by every reading of it, the same value
    /// twice included, at any depth; the same document without the repetition is read.
    #[test]
    fn a_member_named_twice_is_refused_by_every_reading() {
        let written = manifest(vec![file("bin/kr")]);
        let members = serde_json::to_string(&written).expect("encodes");
        let release = format!("\"release\":\"{}\",", written.release);
        let document = |signed: &str| format!("{{\"signed\":{signed},\"signatures\":[]}}");
        // The control: once, it is read.
        assert!(ReleaseManifest::read_document(document(&members).as_bytes()).is_ok());
        let twice_at_the_top = members.replacen('{', &format!("{{{release}"), 1);
        let file_twice = members.replacen("\"mode\":", "\"mode\":\"regular\",\"mode\":", 1);
        for signed in [twice_at_the_top, file_twice] {
            assert!(
                ReleaseManifest::read_document(document(&signed).as_bytes()).is_err(),
                "{signed}"
            );
            assert!(
                serde_json::from_str::<SignedMembers>(&signed).is_err(),
                "{signed}"
            );
        }
    }

    /// Signed members are what the signer wrote: read back, a member this build does not know is
    /// still there to be checked, and the manifest they are is read past it.
    #[test]
    fn signed_members_keep_what_this_build_does_not_know() {
        let written = manifest(vec![file("bin/kr")]);
        let mut value = serde_json::to_value(&written).expect("encodes");
        value["stores"] = serde_json::json!([]);
        let members: SignedMembers = serde_json::from_value(value.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&members).expect("encodes"), value);
        assert_eq!(members.manifest().expect("a manifest"), written);
        assert_eq!(
            SignedMembers::of(&written)
                .expect("serialises")
                .manifest()
                .expect("a manifest"),
            written
        );
    }

    /// A release retains the levels it names and no others.
    #[test]
    fn a_release_retains_the_levels_it_names() {
        let release = manifest(Vec::new());
        assert!(release.retains(PackageVersion::new(0, 48, 5)));
        assert!(!release.retains(PackageVersion::new(0, 47, 0)));
        assert!(!release.retains(PackageVersion::new(1, 48, 0)));
    }

    /// An operating system states its version with more numbers than a floor has, and the floor
    /// is compared on the first two.
    #[test]
    fn a_floor_is_compared_on_the_first_two_numbers() {
        let floor = FloorVersion {
            major: 14,
            minor: 0,
        };
        assert!(FloorVersion::leading("14.6.1").expect("read") >= floor);
        assert!(FloorVersion::leading("15").expect("read") >= floor);
        assert!(FloorVersion::leading("13.7.4").expect("read") < floor);
        assert_eq!(
            FloorVersion::leading("2.35"),
            Some(FloorVersion {
                major: 2,
                minor: 35
            })
        );
        assert_eq!(FloorVersion::leading("glibc"), None);
        let json = serde_json::to_string(&floor).expect("encodes");
        assert_eq!(json, "\"14.0\"");
        assert!(serde_json::from_str::<FloorVersion>("\"14\"").is_err());
        assert!(serde_json::from_str::<FloorVersion>("\"14.0.1\"").is_err());
    }

    /// The handover's parameters and result are closed schemas and round-trip through the
    /// canonical encoding.
    #[test]
    fn the_handover_round_trips_and_refuses_what_it_does_not_define() {
        let attempt = Uuid::from_bytes([7; 16]);
        for named in [Nullable::null(), Nullable::some(attempt)] {
            let params = HostUpdateHandoverParams {
                step: HandoverStep::Stop,
                target: ReleaseName::new("0.2.0+4254aa6e62e5").expect("a name"),
                attempt: named,
            };
            let bytes = kr_cbor::to_canonical_vec(&params).expect("encodes");
            let back: HostUpdateHandoverParams =
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
            assert_eq!(back, params);
        }
        let result = HostUpdateHandoverResult {
            attempt: Nullable::some(attempt),
            release: Nullable::null(),
            pid: U64::new(42),
            arguments: vec!["--runtime-dir".to_owned(), "/r".to_owned()],
            working_directory: "/s".to_owned(),
        };
        let bytes = kr_cbor::to_canonical_vec(&result).expect("encodes");
        let back: HostUpdateHandoverResult =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
        assert_eq!(back, result);
        let unknown = serde_json::json!({
            "step": "stop",
            "target": "0.2.0+4254aa6e62e5",
            "attempt": null,
            "force": true,
        });
        assert!(serde_json::from_value::<HostUpdateHandoverParams>(unknown).is_err());
        // The attempt is stated, as null where there is none: a request that leaves it out is
        // refused rather than read as one that names none.
        let unstated = serde_json::json!({ "step": "stop", "target": "0.2.0+4254aa6e62e5" });
        assert!(serde_json::from_value::<HostUpdateHandoverParams>(unstated).is_err());
    }
}
