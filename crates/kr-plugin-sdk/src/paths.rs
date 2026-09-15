//! Safe package paths.
//!
//! Section 11 requires the host to reject unsafe extraction paths, links, duplicate or
//! case-colliding names and undeclared size expansion. This module owns the first three.
//!
//! A [`PackagePath`] is a relative POSIX path that names one unambiguous file on every platform
//! KalaReach runs on. That is stricter than "no `..`", because a path that is harmless on Linux can
//! escape or collide on macOS and Windows: `NUL` is a device on Windows, `a.` and `a` are the same
//! file there, `A` and `a` are the same file on a default macOS volume, `e\u{0301}` and `\u{e9}`
//! are the same file on a default APFS volume, and a backslash is a separator on Windows and an
//! ordinary character elsewhere.
//!
//! The alphabet is therefore ASCII letters, digits, `.`, `-` and `_`. Restricting it rather than
//! enumerating the ways Unicode collides is the only version of this rule that stays true: macOS
//! normalises, Windows resolves device names through their extension and through compatibility
//! forms such as `COM\u{b9}`, and invisible characters make two different names render
//! identically. None of that can happen inside this alphabet. Package paths are internal file
//! names rather than anything a person reads, so the restriction costs nothing.

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeMap;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

/// Maximum length in bytes of a whole package path.
pub const MAX_PATH_LEN: usize = 512;

/// Maximum length in bytes of one path segment.
pub const MAX_SEGMENT_LEN: usize = 128;

/// Maximum number of segments in a package path.
pub const MAX_PATH_DEPTH: usize = 8;

/// The pattern a package path matches, for consumers that check the JSON Schema alone.
///
/// A regular expression cannot express every rule in this module: Windows device names and
/// case-folded collisions need the code below. It does carry the rules that matter most to a
/// consumer reading the schema without a KalaReach implementation beside it: relative, no
/// traversal, no backslash, no drive prefix, and none of the characters that make one name mean
/// two files.
pub const PACKAGE_PATH_PATTERN: &str =
    r#"^(?!.*(?:^|/)\.{1,2}(?:/|$))[^\x00-\x1F\x7F/\\<>:"|?*]+(?:/[^\x00-\x1F\x7F/\\<>:"|?*]+)*$"#;

/// Device names that Windows resolves regardless of directory or extension.
const WINDOWS_DEVICE_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "com0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9", "lpt0",
];

/// Why a path may not appear in a package.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PathRejection {
    /// The path was empty.
    #[error("the path is empty")]
    Empty,
    /// The path was longer than [`MAX_PATH_LEN`] bytes.
    #[error("the path is {len} bytes, over the {MAX_PATH_LEN} byte limit")]
    TooLong {
        /// The byte length of the supplied path.
        len: usize,
    },
    /// The path had more than [`MAX_PATH_DEPTH`] segments.
    #[error("the path has {depth} segments, over the {MAX_PATH_DEPTH} segment limit")]
    TooDeep {
        /// The segment count of the supplied path.
        depth: usize,
    },
    /// The path began at the filesystem root or a drive.
    #[error("the path is absolute; package paths are relative to the package directory")]
    Absolute,
    /// The path contained a backslash, which is a separator on Windows only.
    #[error("the path contains a backslash; package paths use '/' on every platform")]
    Backslash,
    /// A segment was made only of dots, which no platform treats as an ordinary name.
    #[error("the segment {segment:?} is only dots")]
    DotsOnly {
        /// The offending segment.
        segment: String,
    },
    /// The path had an empty segment, from a leading, trailing or doubled separator.
    #[error("the path has an empty segment; separators are single and never leading or trailing")]
    EmptySegment,
    /// The path used `.` or `..` as a segment.
    #[error("the path contains the {segment:?} segment; package paths never traverse")]
    Traversal {
        /// The offending segment.
        segment: String,
    },
    /// One segment was longer than [`MAX_SEGMENT_LEN`] bytes.
    #[error("the segment {segment:?} is over the {MAX_SEGMENT_LEN} byte limit")]
    SegmentTooLong {
        /// The offending segment.
        segment: String,
    },
    /// A segment carried a character outside the portable alphabet.
    #[error(
        "the segment {segment:?} contains U+{codepoint:04X}; package paths use A-Z, a-z, 0-9, '.', '-' and '_'"
    )]
    ForbiddenCharacter {
        /// The offending segment.
        segment: String,
        /// The offending code point.
        codepoint: u32,
    },
    /// A segment ended with a dot, which Windows silently strips.
    #[error("the segment {segment:?} ends with a dot, which Windows strips")]
    TrailingDot {
        /// The offending segment.
        segment: String,
    },
    /// A segment named a Windows device.
    #[error("the segment {segment:?} names the Windows device {device:?}")]
    WindowsDevice {
        /// The offending segment.
        segment: String,
        /// The device the segment resolves to.
        device: String,
    },
}

/// A relative path inside a package.
///
/// Construction is the only way to obtain one, so holding a [`PackagePath`] is proof that the
/// rules in this module were applied to it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PackagePath(String);

impl PackagePath {
    /// Checks a path against every rule in this module.
    ///
    /// # Errors
    ///
    /// Returns the first [`PathRejection`] that applies.
    pub fn new(value: impl Into<String>) -> Result<Self, PathRejection> {
        let value = value.into();
        if value.is_empty() {
            return Err(PathRejection::Empty);
        }
        if value.len() > MAX_PATH_LEN {
            return Err(PathRejection::TooLong { len: value.len() });
        }
        if value.contains('\\') {
            return Err(PathRejection::Backslash);
        }
        if value.starts_with('/') || is_drive_prefixed(&value) {
            return Err(PathRejection::Absolute);
        }
        let segments: Vec<&str> = value.split('/').collect();
        if segments.len() > MAX_PATH_DEPTH {
            return Err(PathRejection::TooDeep {
                depth: segments.len(),
            });
        }
        for segment in segments {
            check_segment(segment)?;
        }
        Ok(Self(value))
    }

    /// Returns the path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the path segments.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// Returns the last segment.
    ///
    /// # Panics
    ///
    /// Panics on an empty path, which construction rejects.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.0
            .rsplit('/')
            .next()
            .expect("a path has a last segment")
    }

    /// Returns the key two paths share when they name one file on a case-insensitive filesystem.
    ///
    /// Two package paths with the same collision key are the same file on macOS and Windows. The
    /// package contract treats them as a duplicate rather than deciding which one wins.
    #[must_use]
    pub fn collision_key(&self) -> String {
        self.0.to_ascii_lowercase()
    }

    /// Returns true when this path needs a directory where `other` needs a file.
    ///
    /// `a/b` needs `a` to be a directory and `A` needs it to be a file. One of the two cannot be
    /// extracted, and which one fails depends on the order a host happens to write them in.
    #[must_use]
    pub fn shadows(&self, other: &Self) -> bool {
        let mine = self.collision_key();
        let theirs = other.collision_key();
        mine.len() > theirs.len()
            && mine.starts_with(&theirs)
            && mine.as_bytes().get(theirs.len()) == Some(&b'/')
    }
}

fn is_drive_prefixed(value: &str) -> bool {
    let mut characters = value.chars();
    match (characters.next(), characters.next()) {
        (Some(letter), Some(':')) => letter.is_ascii_alphabetic(),
        _ => false,
    }
}

fn check_segment(segment: &str) -> Result<(), PathRejection> {
    if segment.is_empty() {
        return Err(PathRejection::EmptySegment);
    }
    if segment == "." || segment == ".." {
        return Err(PathRejection::Traversal {
            segment: segment.to_owned(),
        });
    }
    if segment.len() > MAX_SEGMENT_LEN {
        return Err(PathRejection::SegmentTooLong {
            segment: segment.to_owned(),
        });
    }
    if let Some(character) = segment.chars().find(|c| !is_portable_path_char(*c)) {
        return Err(PathRejection::ForbiddenCharacter {
            segment: segment.to_owned(),
            codepoint: character as u32,
        });
    }
    if segment.chars().all(|character| character == '.') {
        return Err(PathRejection::DotsOnly {
            segment: segment.to_owned(),
        });
    }
    if segment.ends_with('.') {
        return Err(PathRejection::TrailingDot {
            segment: segment.to_owned(),
        });
    }
    let stem = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .to_ascii_lowercase();
    if WINDOWS_DEVICE_NAMES.contains(&stem.as_str()) {
        return Err(PathRejection::WindowsDevice {
            segment: segment.to_owned(),
            device: stem,
        });
    }
    Ok(())
}

/// Returns true when a character may appear in a package path segment.
///
/// The alphabet is ASCII letters, digits, `.`, `-` and `_`. Everything outside it is rejected
/// rather than filtered, because the ways two Unicode names become one file differ per platform
/// and per volume, and a rule that has to enumerate them is a rule that will be incomplete.
#[must_use]
pub fn is_portable_path_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
}

/// Two package paths that cannot both exist on a case-insensitive filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathCollision {
    /// The path seen first.
    pub first: PackagePath,
    /// The path that collides with it.
    pub second: PackagePath,
    /// The key they share.
    pub key: String,
    /// How they collide.
    pub kind: CollisionKind,
}

/// How two package paths collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollisionKind {
    /// They fold to the same name.
    SameFile,
    /// One needs a directory where the other needs a file.
    FileAndDirectory,
}

/// Finds every pair of paths that cannot both exist on a case-insensitive filesystem.
///
/// The result is ordered by the shared key, so a validator reports collisions in the same order on
/// every run.
#[must_use]
pub fn find_collisions(paths: &[PackagePath]) -> Vec<PathCollision> {
    let mut seen: BTreeMap<String, PackagePath> = BTreeMap::new();
    let mut collisions = Vec::new();
    for path in paths {
        let key = path.collision_key();
        match seen.get(&key) {
            Some(first) => collisions.push(PathCollision {
                first: first.clone(),
                second: path.clone(),
                key,
                kind: CollisionKind::SameFile,
            }),
            None => {
                seen.insert(key, path.clone());
            }
        }
    }
    for (index, path) in paths.iter().enumerate() {
        for other in &paths[index + 1..] {
            let (file, directory) = if path.shadows(other) {
                (other, path)
            } else if other.shadows(path) {
                (path, other)
            } else {
                continue;
            };
            collisions.push(PathCollision {
                first: file.clone(),
                second: directory.clone(),
                key: file.collision_key(),
                kind: CollisionKind::FileAndDirectory,
            });
        }
    }
    collisions.sort_by(|left, right| {
        (&left.key, left.second.as_str()).cmp(&(&right.key, right.second.as_str()))
    });
    collisions
}

impl fmt::Display for PackagePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for PackagePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PackagePath({:?})", self.0)
    }
}

impl FromStr for PackagePath {
    type Err = PathRejection;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl<'de> Deserialize<'de> for PackagePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for PackagePath {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PackagePath".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::PackagePath".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_PATH_LEN,
            "pattern": PACKAGE_PATH_PATTERN,
            "description": "A relative POSIX path inside the package. No '..', no absolute or drive-prefixed path, no backslash, no Windows device name, no trailing dot or space, at most 8 segments."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> PackagePath {
        PackagePath::new(text).expect("valid package path")
    }

    #[test]
    fn accepts_ordinary_package_paths() {
        for text in [
            "plugin.json",
            "assets/icon.svg",
            "fixtures/sessions/start.json",
            "component.wasm",
        ] {
            assert!(PackagePath::new(text).is_ok(), "rejected {text:?}");
        }
    }

    #[test]
    fn rejects_traversal_and_absolute_paths() {
        assert_eq!(
            PackagePath::new("../escape"),
            Err(PathRejection::Traversal {
                segment: "..".to_owned()
            })
        );
        assert_eq!(
            PackagePath::new("assets/../../escape"),
            Err(PathRejection::Traversal {
                segment: "..".to_owned()
            })
        );
        assert_eq!(
            PackagePath::new("/etc/passwd"),
            Err(PathRejection::Absolute)
        );
        assert_eq!(
            PackagePath::new("C:/Windows/System32"),
            Err(PathRejection::Absolute)
        );
        assert_eq!(
            PackagePath::new("assets\\icon.svg"),
            Err(PathRejection::Backslash)
        );
    }

    #[test]
    fn rejects_windows_hostile_names() {
        assert!(matches!(
            PackagePath::new("nul"),
            Err(PathRejection::WindowsDevice { .. })
        ));
        assert!(matches!(
            PackagePath::new("assets/COM1.txt"),
            Err(PathRejection::WindowsDevice { .. })
        ));
        assert!(matches!(
            PackagePath::new("assets/icon."),
            Err(PathRejection::TrailingDot { .. })
        ));
        for outside in ["assets/icon ", "assets/a:b", "assets/COM\u{b9}.txt"] {
            assert!(
                matches!(
                    PackagePath::new(outside),
                    Err(PathRejection::ForbiddenCharacter { .. })
                ),
                "accepted {outside:?}"
            );
        }
        assert!(matches!(
            PackagePath::new("assets/..."),
            Err(PathRejection::DotsOnly { .. })
        ));
    }

    #[test]
    fn rejects_everything_outside_the_portable_alphabet() {
        // Two spellings of the same word that a default macOS volume stores as one file.
        for outside in [
            "assets/caf\u{e9}.svg",
            "assets/cafe\u{301}.svg",
            "assets/ic\u{34f}on.svg",
            "assets/\u{1F600}.svg",
            "assets/my file.svg",
        ] {
            assert!(
                matches!(
                    PackagePath::new(outside),
                    Err(PathRejection::ForbiddenCharacter { .. })
                ),
                "accepted {outside:?}"
            );
        }
    }

    #[test]
    fn rejects_empty_segments_and_excess_depth() {
        assert_eq!(
            PackagePath::new("assets//icon.svg"),
            Err(PathRejection::EmptySegment)
        );
        assert_eq!(
            PackagePath::new("assets/"),
            Err(PathRejection::EmptySegment)
        );
        let deep = (0..=MAX_PATH_DEPTH)
            .map(|index| format!("d{index}"))
            .collect::<Vec<_>>()
            .join("/");
        assert!(matches!(
            PackagePath::new(deep),
            Err(PathRejection::TooDeep { .. })
        ));
    }

    #[test]
    fn finds_case_folded_collisions() {
        let paths = vec![
            path("assets/Icon.svg"),
            path("assets/icon.svg"),
            path("plugin.json"),
        ];
        let collisions = find_collisions(&paths);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].key, "assets/icon.svg");
        assert_eq!(collisions[0].kind, CollisionKind::SameFile);
    }

    #[test]
    fn finds_a_file_that_shadows_another_paths_directory() {
        let paths = vec![path("Assets"), path("assets/icon.svg")];
        let collisions = find_collisions(&paths);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].kind, CollisionKind::FileAndDirectory);
        assert_eq!(collisions[0].first.as_str(), "Assets");
        assert_eq!(collisions[0].second.as_str(), "assets/icon.svg");
    }

    #[test]
    fn no_collision_between_distinct_names() {
        let paths = vec![
            path("a.json"),
            path("b.json"),
            path("nested/a.json"),
            path("nest/a.json"),
        ];
        assert!(find_collisions(&paths).is_empty());
    }
}
