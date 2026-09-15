//! Package versions and the ranges a package accepts.
//!
//! A package states its own version, the SDK versions it is written against and the WIT package
//! versions its component targets. The host resolves a package by exact version and content hash;
//! the ranges say which host it can run on, never which build it becomes.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use semver::{Version, VersionReq};
use serde::{Deserialize, Deserializer, Serialize};

/// The SDK version this crate implements.
///
/// A package whose `sdk_range` does not admit this version is rejected before any payload is
/// fetched, which is what keeps an old host from guessing at a manifest field it never learned.
pub const SDK_VERSION: &str = "0.1.0";

/// The WIT package version this crate publishes.
pub const WIT_VERSION: &str = "0.1.0";

/// The pattern an exact semantic version matches, from the semantic versioning specification.
pub const VERSION_PATTERN: &str = r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$";

/// An exact semantic version.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PackageVersion(Version);

impl PackageVersion {
    /// Parses an exact semantic version.
    ///
    /// # Errors
    ///
    /// Returns [`semver::Error`] when the text is not a semantic version.
    pub fn parse(text: &str) -> Result<Self, semver::Error> {
        Version::parse(text).map(Self)
    }

    /// Returns the underlying version.
    #[must_use]
    pub const fn get(&self) -> &Version {
        &self.0
    }
}

impl From<Version> for PackageVersion {
    fn from(value: Version) -> Self {
        Self(value)
    }
}

impl fmt::Display for PackageVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl FromStr for PackageVersion {
    type Err = semver::Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl<'de> Deserialize<'de> for PackageVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for PackageVersion {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PackageVersion".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::PackageVersion".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 5,
            "maxLength": 64,
            "pattern": VERSION_PATTERN,
            "description": "An exact semantic version, such as 1.4.0 or 2.0.0-rc.1."
        })
    }
}

/// A range of versions a package accepts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct VersionRange(VersionReq);

impl VersionRange {
    /// Parses a version range.
    ///
    /// # Errors
    ///
    /// Returns [`semver::Error`] when the text is not a version requirement.
    pub fn parse(text: &str) -> Result<Self, semver::Error> {
        VersionReq::parse(text).map(Self)
    }

    /// Returns true when the range admits `version`.
    #[must_use]
    pub fn admits(&self, version: &PackageVersion) -> bool {
        self.0.matches(version.get())
    }

    /// Returns true when the range admits every version, which a package may not declare.
    ///
    /// An unbounded range says the package works on hosts that did not exist when it was
    /// reviewed. The manifest validator rejects it for that reason.
    #[must_use]
    pub fn is_unbounded(&self) -> bool {
        self.0.comparators.is_empty()
    }

    /// Returns the underlying requirement.
    #[must_use]
    pub const fn get(&self) -> &VersionReq {
        &self.0
    }
}

impl fmt::Display for VersionRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl FromStr for VersionRange {
    type Err = semver::Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl<'de> Deserialize<'de> for VersionRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for VersionRange {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "VersionRange".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::VersionRange".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "description": "A semantic version range, such as '>=0.1, <0.2'. An unbounded range is rejected."
        })
    }
}

/// Returns the SDK version this crate implements.
///
/// # Panics
///
/// Panics when [`SDK_VERSION`] is not a semantic version, which is a compile-time constant.
#[must_use]
pub fn sdk_version() -> PackageVersion {
    PackageVersion::parse(SDK_VERSION).expect("SDK_VERSION is a semantic version")
}

/// Returns the WIT package version this crate publishes.
///
/// # Panics
///
/// Panics when [`WIT_VERSION`] is not a semantic version, which is a compile-time constant.
#[must_use]
pub fn wit_version() -> PackageVersion {
    PackageVersion::parse(WIT_VERSION).expect("WIT_VERSION is a semantic version")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_admits_the_versions_it_names() {
        let range = VersionRange::parse(">=0.1, <0.2").expect("valid range");
        assert!(range.admits(&sdk_version()));
        assert!(!range.admits(&PackageVersion::parse("0.2.0").expect("valid version")));
        assert!(!range.is_unbounded());
    }

    #[test]
    fn the_wildcard_range_is_unbounded() {
        assert!(
            VersionRange::parse("*")
                .expect("valid range")
                .is_unbounded()
        );
    }
}
