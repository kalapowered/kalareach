//! What a Windows file system does not accept as a name, or reads as another name.
//!
//! A release is built where any name is a name and installed where some are not, so the host that
//! installs one refuses, before it writes anything, a path that Windows would give another meaning
//! or fold into another path: a device name, a stream, a drive, a name with a trailing dot or space,
//! two names that differ only in case. The rules are plain functions of text so that the host's
//! archive reading, its tree copy and its tests apply the same ones on every platform.

use std::collections::HashMap;

/// The longest a single name may be: the file systems' limit, in UTF-16 code units.
pub const MAX_COMPONENT_UNITS: usize = 255;

/// Why a name is not one Windows keeps as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameFault {
    /// The name is empty.
    Empty,
    /// The name is `.` or `..`, which name a directory and its parent.
    DotName,
    /// The name holds a character no name holds: a control character, or one of `<>:"/\|?*`. A
    /// colon also starts an alternate data stream (`file:stream`) and ends a drive (`C:`).
    ForbiddenCharacter,
    /// The name ends in a dot or a space, which Windows removes.
    TrailingDotOrSpace,
    /// The name is a device's, with or without an extension: `CON`, `NUL`, `COM1`, `LPT1`.
    DeviceName,
    /// The name is longer than a file system keeps.
    TooLong,
}

impl std::fmt::Display for NameFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "is empty",
            Self::DotName => "names a directory and its parent",
            Self::ForbiddenCharacter => {
                "holds a character no Windows name holds, or starts a data stream or names a drive"
            }
            Self::TrailingDotOrSpace => "ends in a dot or a space, which Windows removes",
            Self::DeviceName => "is the name of a device",
            Self::TooLong => "is longer than a Windows name can be",
        })
    }
}

/// The device names, which Windows opens as a device whatever extension follows them.
const DEVICES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];

/// Whether `name` (one component) is a device's, by the rule Windows applies: the part before the
/// first dot, with the spaces at its end removed, compared without regard to case.
fn is_device(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ');
    let upper = stem.to_uppercase();
    if DEVICES.contains(&upper.as_str()) {
        return true;
    }
    // `COM` and `LPT` with one digit, which includes the superscript digits Windows reads as digits.
    let numbered = |prefix: &str| {
        upper.strip_prefix(prefix).is_some_and(|digit| {
            let mut characters = digit.chars();
            matches!(
                (characters.next(), characters.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        })
    };
    numbered("COM") || numbered("LPT")
}

/// Why `name`, one component of a path, is not kept as written by Windows, or `None` when it is.
#[must_use]
pub fn component_fault(name: &str) -> Option<NameFault> {
    if name.is_empty() {
        return Some(NameFault::Empty);
    }
    if name == "." || name == ".." {
        return Some(NameFault::DotName);
    }
    if name.encode_utf16().count() > MAX_COMPONENT_UNITS {
        return Some(NameFault::TooLong);
    }
    if name
        .chars()
        .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character))
    {
        return Some(NameFault::ForbiddenCharacter);
    }
    if name.ends_with(['.', ' ']) {
        return Some(NameFault::TrailingDotOrSpace);
    }
    is_device(name).then_some(NameFault::DeviceName)
}

/// A name as a case-folding file system compares it: each character in its single upper-case form
/// where it has one, and as it is where upper-casing makes it several.
#[must_use]
pub fn folded(name: &str) -> String {
    name.chars()
        .map(|character| {
            let mut upper = character.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(single), None) => single,
                _ => character,
            }
        })
        .collect()
}

/// Why a path is not kept as written by Windows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathFault {
    /// A component of the path is not kept as written.
    Component {
        /// The path.
        path: String,
        /// The component.
        name: String,
        /// What is wrong with it.
        fault: NameFault,
    },
    /// Two paths are one path on a file system that folds case.
    Collides {
        /// The path.
        path: String,
        /// The path already seen that it folds to.
        with: String,
    },
    /// A path is a file and, as the parent of another, a directory.
    FileAndDirectory {
        /// The path.
        path: String,
    },
}

impl std::fmt::Display for PathFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Component { path, name, fault } => {
                write!(formatter, "{path}: the name {name} {fault}")
            }
            Self::Collides { path, with } => write!(
                formatter,
                "{path} and {with} are one path on a file system that does not tell capitals from small letters"
            ),
            Self::FileAndDirectory { path } => {
                write!(formatter, "{path} is a file and a directory")
            }
        }
    }
}

/// Every path of a release, by the rules above: no component is refused, no two paths fold to one,
/// and no path is both a file and the parent of another. Checked as paths arrive, so that an
/// archive is refused at the first entry that breaks them.
///
/// The paths are kept as a tree of their components, so that what is kept grows with the bytes of
/// the names and not with the square of the parts a name has.
#[derive(Debug)]
pub struct PathRules {
    /// The root, which is a directory with no component, and then every component seen below it.
    nodes: Vec<Node>,
}

/// One component of a path seen, below its parent.
#[derive(Debug)]
struct Node {
    /// The spelling it first came in.
    component: String,
    /// The node of the path above it.
    parent: usize,
    /// Whether it is a directory.
    directory: bool,
    /// The folded form of each component below it, with its node.
    children: HashMap<String, usize>,
}

impl Default for PathRules {
    fn default() -> Self {
        Self {
            nodes: vec![Node {
                component: String::new(),
                parent: 0,
                directory: true,
                children: HashMap::new(),
            }],
        }
    }
}

impl PathRules {
    /// Rules with no path seen.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The path a node stands for, in the spelling it first came in.
    fn spelled(&self, mut at: usize) -> String {
        let mut parts = Vec::new();
        while at != 0 {
            parts.push(self.nodes[at].component.as_str());
            at = self.nodes[at].parent;
        }
        parts.reverse();
        parts.join("/")
    }

    /// Takes in a path of `/`-separated components that is a file, or a directory when
    /// `directory`; its parents are directories.
    ///
    /// # Errors
    ///
    /// Returns the first rule the path breaks.
    pub fn admit(&mut self, path: &str, directory: bool) -> Result<(), PathFault> {
        let parts: Vec<&str> = path.split('/').collect();
        for part in &parts {
            if let Some(fault) = component_fault(part) {
                return Err(PathFault::Component {
                    path: path.to_owned(),
                    name: (*part).to_owned(),
                    fault,
                });
            }
        }
        let mut at = 0;
        for (depth, part) in parts.iter().enumerate() {
            let is_directory = directory || depth + 1 < parts.len();
            let key = folded(part);
            if let Some(&child) = self.nodes[at].children.get(&key) {
                let first = &self.nodes[child];
                if first.component != *part {
                    return Err(PathFault::Collides {
                        path: parts[..=depth].join("/"),
                        with: self.spelled(child),
                    });
                }
                if first.directory != is_directory {
                    return Err(PathFault::FileAndDirectory {
                        path: parts[..=depth].join("/"),
                    });
                }
                at = child;
            } else {
                let child = self.nodes.len();
                self.nodes.push(Node {
                    component: (*part).to_owned(),
                    parent: at,
                    directory: is_directory,
                    children: HashMap::new(),
                });
                self.nodes[at].children.insert(key, child);
                at = child;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names Windows does not keep as written, each with the rule that refuses it: golden vectors
    /// for the rules a release path is held to.
    #[test]
    fn a_name_windows_would_read_as_another_is_refused_with_its_rule() {
        let refused = [
            ("", NameFault::Empty),
            (".", NameFault::DotName),
            ("..", NameFault::DotName),
            ("file:stream", NameFault::ForbiddenCharacter),
            ("C:", NameFault::ForbiddenCharacter),
            ("a<b", NameFault::ForbiddenCharacter),
            ("a>b", NameFault::ForbiddenCharacter),
            ("a\"b", NameFault::ForbiddenCharacter),
            ("a\\b", NameFault::ForbiddenCharacter),
            ("a|b", NameFault::ForbiddenCharacter),
            ("a?b", NameFault::ForbiddenCharacter),
            ("a*b", NameFault::ForbiddenCharacter),
            ("a\u{1}b", NameFault::ForbiddenCharacter),
            ("a\0b", NameFault::ForbiddenCharacter),
            ("name.", NameFault::TrailingDotOrSpace),
            ("name ", NameFault::TrailingDotOrSpace),
            ("CON", NameFault::DeviceName),
            ("con", NameFault::DeviceName),
            ("Nul.txt", NameFault::DeviceName),
            ("aux.tar.gz", NameFault::DeviceName),
            ("COM1", NameFault::DeviceName),
            ("com9.exe", NameFault::DeviceName),
            ("LPT0", NameFault::DeviceName),
            ("COM\u{b9}", NameFault::DeviceName),
            ("CONIN$", NameFault::DeviceName),
            ("CONOUT$", NameFault::DeviceName),
            ("PRN  .txt", NameFault::DeviceName),
        ];
        for (name, fault) in refused {
            assert_eq!(component_fault(name), Some(fault), "{name:?}");
        }
        assert_eq!(
            component_fault(&"a".repeat(MAX_COMPONENT_UNITS + 1)),
            Some(NameFault::TooLong)
        );
    }

    /// The names a release holds are kept, including ones that only look like the refused:
    /// the control cases of the vectors above.
    #[test]
    fn the_names_a_release_holds_are_kept() {
        for name in [
            "kr.exe",
            "release.json",
            "bin",
            "kr-controller.exe",
            "share",
            "update-root.json",
            "console",
            "COM10",
            "LPT",
            "COMA",
            "con-sole.txt",
            "a b",
            "a.b",
            ".hidden",
            "0.1.0+4254aa6e62e5",
            "caf\u{e9}",
        ] {
            assert_eq!(component_fault(name), None, "{name:?}");
        }
        assert_eq!(component_fault(&"a".repeat(MAX_COMPONENT_UNITS)), None);
    }

    /// Two paths that differ only in case are one path, whether they are files or directories,
    /// and a path is not a file and a directory.
    #[test]
    fn paths_that_fold_to_one_or_are_a_file_and_a_directory_are_refused() {
        let mut rules = PathRules::new();
        rules.admit("bin/kr.exe", false).expect("a file");
        rules.admit("bin/kr-worker.exe", false).expect("another");
        rules.admit("shells/pwsh", true).expect("a directory");
        assert!(matches!(
            rules.admit("bin/KR.exe", false),
            Err(PathFault::Collides { .. })
        ));
        assert!(matches!(
            rules.admit("BIN/other.exe", false),
            Err(PathFault::Collides { .. })
        ));
        assert!(matches!(
            rules.admit("Shells/x", false),
            Err(PathFault::Collides { .. })
        ));
        assert!(matches!(
            rules.admit("bin/kr.exe/inner", false),
            Err(PathFault::FileAndDirectory { .. })
        ));
        assert!(matches!(
            rules.admit("shells/pwsh", false),
            Err(PathFault::FileAndDirectory { .. })
        ));
        assert!(matches!(
            rules.admit("bin/nul.txt", false),
            Err(PathFault::Component {
                fault: NameFault::DeviceName,
                ..
            })
        ));
        // Said twice in one spelling is no collision: the archive reading refuses a repeated file
        // by itself.
        rules.admit("bin/kr.exe", false).expect("the same spelling");
    }

    /// Folding is simple upper-casing, as a file system's table does it: `ß` stays `ß`.
    #[test]
    fn folding_is_one_character_to_one_character() {
        assert_eq!(folded("Stra\u{df}e"), "STRA\u{df}E");
        assert_eq!(folded("kr.EXE"), "KR.EXE");
        assert_eq!(folded("\u{e9}"), "\u{c9}");
    }
}
