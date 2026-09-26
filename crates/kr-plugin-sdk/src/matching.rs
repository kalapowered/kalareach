//! Declarative match rules.
//!
//! The catalogue is indexed by executable and distribution so a host can decide which packages
//! are relevant without instantiating any of them. Downloading the full catalogue does not
//! activate every module: only matching, enabled packages are instantiated, and an explicit
//! application selection by the user wins any conflict between rules.
//!
//! The matching grammar is deliberately small. There is no regular expression and no glob,
//! because the host evaluates these rules against every candidate executable on the machine, and
//! a pattern language is a place for a catalogue entry to spend the host's time.

use kr_protocol::scalars::Nullable;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{PluginId, PluginName};
use crate::version::VersionRange;

/// Maximum length of a match token, such as a file stem or a package name.
pub const MAX_MATCH_TOKEN_LEN: usize = 128;

/// An operating system a package supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    /// Linux, including the WSL2 distributions.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
}

impl OperatingSystem {
    /// Every supported operating system.
    pub const ALL: &'static [Self] = &[Self::Linux, Self::MacOs, Self::Windows];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "mac_os",
            Self::Windows => "windows",
        }
    }
}

impl JsonSchema for OperatingSystem {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "OperatingSystem".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::OperatingSystem".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "enum": ["linux", "mac_os", "windows"],
            "description": "An operating system a package supports."
        })
    }
}

/// A processor architecture a package supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    /// 64-bit x86.
    X86_64,
    /// 64-bit ARM.
    Aarch64,
}

impl Architecture {
    /// Every supported architecture.
    pub const ALL: &'static [Self] = &[Self::X86_64, Self::Aarch64];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

impl JsonSchema for Architecture {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Architecture".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::Architecture".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "enum": ["x86_64", "aarch64"],
            "description": "A processor architecture a package supports."
        })
    }
}

/// One operating system and the architectures a package supports on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PlatformSupport {
    /// The operating system.
    pub os: OperatingSystem,
    /// The architectures supported on it.
    pub architectures: Vec<Architecture>,
}

/// How an executable is recognised.
///
/// The file stem is the executable's name without a directory or a `.exe` suffix, compared
/// case-insensitively because Windows and macOS compare it that way. A path suffix narrows the
/// rule to an installation location; it is a suffix over whole path segments, never a substring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExecutableMatch {
    /// The executable's file stem.
    pub file_stem: String,
    /// Whole path segments the executable's directory must end with.
    pub path_suffix: Vec<String>,
    /// The versions the rule covers, where the host can read a version.
    pub version_range: Nullable<VersionRange>,
}

impl ExecutableMatch {
    /// Returns true when `path` names an executable this rule recognises.
    ///
    /// `path` is a POSIX or Windows path as the host observed it. Comparison folds ASCII case and
    /// accepts a `.exe` suffix, because those are the two ways the same executable spells itself
    /// across the supported platforms.
    #[must_use]
    pub fn matches_path(&self, path: &str) -> bool {
        let normalised = path.replace('\\', "/");
        let mut segments: Vec<&str> = normalised.split('/').collect();
        // A trailing separator names a directory, and a directory is not an executable. The empty
        // last segment stays in the list so that `/usr/bin/app/` fails rather than matching `app`.
        let Some(file) = segments.pop().filter(|file| !file.is_empty()) else {
            return false;
        };
        segments.retain(|segment| !segment.is_empty());
        // Sliced by character boundary rather than by byte, because a file name is not always
        // ASCII and splitting inside a character is a panic rather than a mismatch.
        let stem = match file
            .len()
            .checked_sub(4)
            .and_then(|start| file.get(start..))
        {
            Some(suffix) if suffix.eq_ignore_ascii_case(".exe") => &file[..file.len() - 4],
            _ => file,
        };
        if !stem.eq_ignore_ascii_case(&self.file_stem) {
            return false;
        }
        if self.path_suffix.is_empty() {
            return true;
        }
        if self.path_suffix.len() > segments.len() {
            return false;
        }
        let tail = &segments[segments.len() - self.path_suffix.len()..];
        tail.iter()
            .zip(&self.path_suffix)
            .all(|(observed, expected)| observed.eq_ignore_ascii_case(expected))
    }
}

/// How a package recognises the distribution an application was installed from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "registry", rename_all = "snake_case", deny_unknown_fields)]
pub enum DistributionMatch {
    /// An npm package name.
    Npm {
        /// The package name.
        package: String,
    },
    /// A PyPI project name.
    PyPi {
        /// The project name.
        project: String,
    },
    /// A Homebrew formula or cask.
    Homebrew {
        /// The formula or cask name.
        formula: String,
    },
    /// A crates.io crate name.
    Cargo {
        /// The crate name.
        crate_name: String,
    },
    /// A Go module path.
    GoModule {
        /// The module path.
        module: String,
    },
    /// A Debian or Ubuntu package name.
    Deb {
        /// The package name.
        package: String,
    },
    /// A macOS application bundle identifier.
    MacBundle {
        /// The bundle identifier.
        bundle_id: String,
    },
    /// A Windows package family or product identifier.
    WindowsPackage {
        /// The package identifier.
        package_id: String,
    },
    /// A container image reference without a tag.
    ContainerImage {
        /// The image reference.
        image: String,
    },
}

impl DistributionMatch {
    /// Returns the registry name used in the index.
    #[must_use]
    pub const fn registry(&self) -> &'static str {
        match self {
            Self::Npm { .. } => "npm",
            Self::PyPi { .. } => "py_pi",
            Self::Homebrew { .. } => "homebrew",
            Self::Cargo { .. } => "cargo",
            Self::GoModule { .. } => "go_module",
            Self::Deb { .. } => "deb",
            Self::MacBundle { .. } => "mac_bundle",
            Self::WindowsPackage { .. } => "windows_package",
            Self::ContainerImage { .. } => "container_image",
        }
    }

    /// Returns the identifier inside that registry.
    #[must_use]
    pub fn identifier(&self) -> &str {
        match self {
            Self::Npm { package } | Self::Deb { package } => package,
            Self::PyPi { project } => project,
            Self::Homebrew { formula } => formula,
            Self::Cargo { crate_name } => crate_name,
            Self::GoModule { module } => module,
            Self::MacBundle { bundle_id } => bundle_id,
            Self::WindowsPackage { package_id } => package_id,
            Self::ContainerImage { image } => image,
        }
    }
}

/// How certain a rule is about what it recognised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchConfidence {
    /// The rule identifies the application exactly: a bundle identifier, a package name.
    Exact,
    /// The rule is a reasonable guess from a name on disk.
    ///
    /// An inferred match is presented as inferred. It never silently wins over a selection the
    /// user made.
    Inferred,
}

/// One declarative match rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct MatchRule {
    /// The rule identifier, unique inside the package.
    pub id: PluginName,
    /// How the executable is recognised.
    pub executable: ExecutableMatch,
    /// The distribution the application was installed from, where the rule names one.
    pub distribution: Nullable<DistributionMatch>,
    /// How certain the rule is.
    pub confidence: MatchConfidence,
}

/// One package whose rules recognise what is running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The package.
    pub plugin_id: PluginId,
    /// Which of its rules recognised the application.
    pub rule_id: String,
    /// How certain that rule is.
    pub confidence: MatchConfidence,
    /// Whether the distribution was compared as well as the executable.
    pub distribution_matched: bool,
}

/// What matching decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Nothing recognised the application.
    None,
    /// One package recognised it.
    Selected(Candidate),
    /// Several packages recognised it, and the person decides.
    ///
    /// A host does not pick one on the package's behalf. An exact rule beats every inferred one,
    /// so an inferred match reaches this only where nothing matched exactly and more than one
    /// package guessed from a name on disk.
    Conflict(Vec<Candidate>),
}

/// Decides which candidate wins, given the selection the person made.
///
/// An explicit selection wins outright. That is the rule section 11 states, and it is why the
/// selection is compared before confidence: a person who chose a package is not overruled by a
/// rule that calls itself exact. The catalogue's search and the worker's binder both decide with
/// this, so there is one rule wherever a running application meets the packages that recognise it.
#[must_use]
pub fn resolve(candidates: Vec<Candidate>, selected: Option<&PluginId>) -> Resolution {
    if candidates.is_empty() {
        return Resolution::None;
    }
    if let Some(selected) = selected
        && let Some(chosen) = candidates
            .iter()
            .find(|candidate| &candidate.plugin_id == selected)
    {
        return Resolution::Selected(chosen.clone());
    }
    let exact: Vec<Candidate> = candidates
        .iter()
        .filter(|candidate| candidate.confidence == MatchConfidence::Exact)
        .cloned()
        .collect();
    let considered = if exact.is_empty() { candidates } else { exact };

    let mut distinct: Vec<&Candidate> = Vec::new();
    for candidate in &considered {
        if !distinct
            .iter()
            .any(|seen| seen.plugin_id == candidate.plugin_id)
        {
            distinct.push(candidate);
        }
    }
    match distinct.as_slice() {
        [] => Resolution::None,
        [one] => Resolution::Selected((*one).clone()),
        _ => Resolution::Conflict(considered),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(plugin: &str, confidence: MatchConfidence) -> Candidate {
        Candidate {
            plugin_id: PluginId::new(plugin).expect("a plugin identifier"),
            rule_id: "executable".to_owned(),
            confidence,
            distribution_matched: false,
        }
    }

    #[test]
    fn an_explicit_selection_wins_and_an_exact_rule_beats_an_inferred_one() {
        let one = candidate("kalareach/one", MatchConfidence::Exact);
        let two = candidate("kalareach/two", MatchConfidence::Exact);
        let guess = candidate("kalareach/guess", MatchConfidence::Inferred);
        assert_eq!(resolve(Vec::new(), None), Resolution::None);
        assert!(matches!(
            resolve(vec![one.clone(), two.clone()], None),
            Resolution::Conflict(_)
        ));
        assert_eq!(
            resolve(vec![one.clone(), two.clone()], Some(&two.plugin_id)),
            Resolution::Selected(two)
        );
        assert_eq!(
            resolve(vec![guess.clone(), one.clone()], None),
            Resolution::Selected(one)
        );
        // Two guesses with nothing exact are for the person to decide between.
        let other = candidate("kalareach/other-guess", MatchConfidence::Inferred);
        assert!(matches!(
            resolve(vec![guess, other], None),
            Resolution::Conflict(_)
        ));
    }

    fn rule(file_stem: &str, path_suffix: &[&str]) -> ExecutableMatch {
        ExecutableMatch {
            file_stem: file_stem.to_owned(),
            path_suffix: path_suffix.iter().map(|s| (*s).to_owned()).collect(),
            version_range: Nullable(None),
        }
    }

    #[test]
    fn matches_the_executable_name_across_platforms() {
        let codex = rule("codex", &[]);
        assert!(codex.matches_path("/usr/local/bin/codex"));
        assert!(codex.matches_path("C:\\Program Files\\Codex\\codex.exe"));
        assert!(codex.matches_path("/opt/homebrew/bin/CODEX"));
        assert!(codex.matches_path("C:\\Program Files\\Codex\\CODEX.EXE"));
        assert!(!codex.matches_path("/usr/local/bin/codex-helper"));
        assert!(!codex.matches_path("/usr/local/bin/"));
        // A directory named after the executable is not the executable.
        assert!(!codex.matches_path("/usr/local/codex/"));
        assert!(!codex.matches_path(""));
        // A name whose last four bytes are inside one character must not split it.
        for unicode in [
            "/usr/bin/\u{e9}abc",
            "/usr/bin/\u{1F600}",
            "/usr/bin/caf\u{e9}",
        ] {
            assert!(!codex.matches_path(unicode), "matched {unicode:?}");
        }
        let accented = ExecutableMatch {
            file_stem: "caf\u{e9}".to_owned(),
            path_suffix: Vec::new(),
            version_range: Nullable(None),
        };
        assert!(accented.matches_path("/usr/bin/caf\u{e9}"));
        assert!(accented.matches_path("/usr/bin/caf\u{e9}.EXE"));
    }

    #[test]
    fn a_path_suffix_matches_whole_segments_only() {
        let scoped = rule("claude", &["node_modules", ".bin"]);
        assert!(scoped.matches_path("/home/u/project/node_modules/.bin/claude"));
        assert!(!scoped.matches_path("/home/u/project/node_modules/claude"));
        assert!(!scoped.matches_path("/home/u/my_node_modules/.bin/claude"));
        assert!(!scoped.matches_path("claude"));
    }

    #[test]
    fn a_distribution_names_its_registry_and_identifier() {
        let distribution = DistributionMatch::Npm {
            package: "@anthropic-ai/claude-code".to_owned(),
        };
        assert_eq!(distribution.registry(), "npm");
        assert_eq!(distribution.identifier(), "@anthropic-ai/claude-code");
    }
}
