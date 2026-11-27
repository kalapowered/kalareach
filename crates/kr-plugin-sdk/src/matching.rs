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
use crate::version::{PackageVersion, VersionRange};

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

impl MatchRule {
    /// Returns the candidate this rule makes of the package `plugin_id` for a program at `path`,
    /// where it recognises one.
    ///
    /// This is the one place a rule's confidence and rank are decided, for the catalogue's lookup
    /// and the worker's binder alike. A rule is exact only for a program whose distribution the
    /// host established as the one the rule names (`observed`). A name and a location on disk say
    /// nothing about which product is installed, so a program recognised by them alone is
    /// recognised as a guess, whatever confidence the rule declares. A host that established no
    /// distribution passes `None`, and every rule then recognises as an inferred one does. Where
    /// `observed` names another distribution the rule is lowered the same way and not dropped,
    /// because the distribution a registry names for a platform's image need not be the one the
    /// rule names.
    ///
    /// `authority` names what vouches for the package's publisher: the enrolment of the repository
    /// the package came through, which has a root of its own. A publisher's name stands for one
    /// publisher only within one authority.
    ///
    /// `installed` is the version the host established for the program, where it did, and `ranges`
    /// are the further ranges the package holds that version to besides the rule's own. A host
    /// that established no version passes `None`, and every candidate then has the neutral
    /// coverage.
    #[must_use]
    pub fn candidate(
        &self,
        plugin_id: &PluginId,
        authority: &str,
        path: &str,
        observed: Option<&DistributionMatch>,
        _installed: Option<&PackageVersion>,
        _ranges: &[&VersionRange],
    ) -> Option<Candidate> {
        let executable_matched = self.executable.matches_path(path);
        let distribution_matched = match (self.distribution.0.as_ref(), observed) {
            (Some(declared), Some(observed)) => {
                declared.registry() == observed.registry()
                    && declared
                        .identifier()
                        .eq_ignore_ascii_case(observed.identifier())
            }
            _ => false,
        };
        if !executable_matched && !distribution_matched {
            return None;
        }
        let confidence = if distribution_matched {
            self.confidence
        } else {
            MatchConfidence::Inferred
        };
        Some(Candidate {
            plugin_id: plugin_id.clone(),
            authority: authority.to_owned(),
            rule_id: self.id.to_string(),
            confidence,
            distribution_matched,
            located: executable_matched && !self.executable.path_suffix.is_empty(),
            coverage: Coverage::Neutral,
        })
    }
}

/// How far the version a host established for a program fits the ranges a package declares.
///
/// The variants are in rank order: a package that covers the version ranks above one that says
/// nothing about it, and that above one that refuses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Coverage {
    /// The version is known and some range the package declares refuses it.
    Excludes,
    /// The package declares no range, or the host established no version: nothing is established
    /// for or against the package.
    Neutral,
    /// The version is known and every range the package declares admits it.
    Covers,
}

/// One package whose rules recognise what is running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The package.
    pub plugin_id: PluginId,
    /// What vouches for the package's publisher: the enrolment of the repository it came through.
    /// A lookup over one repository's index has one authority, and passes an empty one.
    pub authority: String,
    /// Which of its rules recognised the application.
    pub rule_id: String,
    /// How certain that rule is.
    pub confidence: MatchConfidence,
    /// Whether the distribution was compared as well as the executable.
    pub distribution_matched: bool,
    /// Whether the rule recognised the program by an installation location it names, as well as
    /// by the executable's name.
    pub located: bool,
    /// How far the program's version fits the ranges this rule and its package declare.
    pub coverage: Coverage,
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
    /// and among rules of one confidence a rule that names the installation location beats one
    /// that names only the executable when one publisher in one repository published every
    /// package left, so this is reached where several packages are left that recognise the
    /// program equally well.
    Conflict(Vec<Candidate>),
}

/// Decides which candidate wins, given the selection the person made.
///
/// An explicit selection wins outright. That is the rule section 11 states, and it is why the
/// selection is compared before confidence: a person who chose a package is not overruled by a
/// rule that calls itself exact. Then an exact rule beats an inferred one. Of the rules left, one
/// that matched an installation location its package names beats one that matched the executable's
/// name alone, when one publisher published every package left, through one repository: the
/// location says which product is installed there, and the name is shared by products that are
/// not. A publisher's name is vouched for by the root of the repository that lists it, and two
/// roots can list one name, so a package of another publisher, or of the same name from another
/// repository, that names a location does not take a program from a package this way: packages of
/// different publishers, or of one name from different repositories, that recognise a program
/// equally well conflict, and the person settles it. The catalogue's search and the worker's binder both decide with this and read their
/// rules with [`MatchRule::candidate`], so there is one rule wherever a running application meets
/// the packages that recognise it.
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
    // The publisher in its authority: the name of a publisher stands for one publisher only within
    // the repository whose root vouches for it.
    let publisher = |candidate: &Candidate| {
        candidate
            .plugin_id
            .as_str()
            .split_once('/')
            .map(|(publisher, _)| (publisher.to_owned(), candidate.authority.clone()))
    };
    let located: Vec<Candidate> = considered
        .iter()
        .filter(|candidate| candidate.located)
        .cloned()
        .collect();
    let one_publisher = considered
        .first()
        .map(publisher)
        .is_some_and(|first| first.is_some() && considered.iter().all(|c| publisher(c) == first));
    let considered = if located.is_empty() || !one_publisher {
        considered
    } else {
        located
    };

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
            authority: String::new(),
            rule_id: "executable".to_owned(),
            confidence,
            distribution_matched: false,
            located: false,
            coverage: Coverage::Neutral,
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

    fn named_rule(
        stem: &str,
        suffix: &[&str],
        distribution: Option<DistributionMatch>,
        confidence: MatchConfidence,
    ) -> MatchRule {
        MatchRule {
            id: PluginName::new("rule").expect("a rule identifier"),
            executable: ExecutableMatch {
                file_stem: stem.to_owned(),
                path_suffix: suffix.iter().map(|s| (*s).to_owned()).collect(),
                version_range: Nullable(None),
            },
            distribution: Nullable(distribution),
            confidence,
        }
    }

    #[test]
    fn a_rule_is_exact_only_for_a_program_of_the_distribution_it_names() {
        let package = PluginId::new("kalareach/sample").expect("a plugin identifier");
        let npm = |name: &str| DistributionMatch::Npm {
            package: name.to_owned(),
        };
        let rule = named_rule(
            "sample",
            &[],
            Some(npm("@vendor/sample")),
            MatchConfidence::Exact,
        );
        let path = "/usr/local/bin/sample";
        // The host established nothing about where the program came from: its name is a guess.
        let unknown = rule
            .candidate(&package, "", path, None, None, &[])
            .expect("recognised");
        assert_eq!(unknown.confidence, MatchConfidence::Inferred);
        assert!(!unknown.distribution_matched);
        // Established as another distribution: still recognised by name, and still a guess.
        let other = rule
            .candidate(&package, "", path, Some(&npm("another")), None, &[])
            .expect("recognised");
        assert_eq!(other.confidence, MatchConfidence::Inferred);
        // Established as the rule's own, in either case of the identifier: what the rule declares.
        let own = rule
            .candidate(&package, "", path, Some(&npm("@Vendor/Sample")), None, &[])
            .expect("recognised");
        assert_eq!(own.confidence, MatchConfidence::Exact);
        assert!(own.distribution_matched);
        // A rule that names no distribution has nothing to establish, so a name alone is a guess
        // whatever it declares: it does not outrank a package that is honest about guessing.
        let plain = named_rule("sample", &[], None, MatchConfidence::Exact);
        assert_eq!(
            plain
                .candidate(&package, "", path, None, None, &[])
                .expect("recognised")
                .confidence,
            MatchConfidence::Inferred
        );
        // And nothing is recognised that neither the name nor the distribution recognises.
        assert!(
            rule.candidate(&package, "", "/usr/local/bin/other", None, None, &[])
                .is_none()
        );
    }

    #[test]
    fn a_rule_that_names_the_installation_location_beats_a_rule_that_names_only_the_executable() {
        let located = PluginId::new("kalareach/located").expect("a plugin identifier");
        let named = PluginId::new("kalareach/named").expect("a plugin identifier");
        let also_named = PluginId::new("kalareach/also-named").expect("a plugin identifier");
        let at_home = named_rule("tool", &[".tool", "bin"], None, MatchConfidence::Inferred);
        let by_name = named_rule("tool", &[], None, MatchConfidence::Inferred);
        let candidates = |path: &str| {
            [
                (&located, &at_home),
                (&named, &by_name),
                (&also_named, &by_name),
            ]
            .into_iter()
            .filter_map(|(plugin, rule)| rule.candidate(plugin, "", path, None, None, &[]))
            .collect::<Vec<_>>()
        };
        match resolve(candidates("/home/u/.tool/bin/tool"), None) {
            Resolution::Selected(chosen) => assert_eq!(chosen.plugin_id, located),
            other => panic!("the location should win: {other:?}"),
        }
        // Where the location is not the program's, only the name is known, and the two packages
        // that claim it equally are for the person to decide between.
        assert!(matches!(
            resolve(candidates("/opt/bin/tool"), None),
            Resolution::Conflict(_)
        ));
    }

    #[test]
    fn a_package_of_another_publisher_does_not_take_a_program_by_naming_it() {
        let shipped = PluginId::new("kalareach/tool").expect("a plugin identifier");
        let vendor = PluginId::new("example-vendor/tool").expect("a plugin identifier");
        let path = "/home/u/.tool/bin/tool";
        let by_name = named_rule("tool", &[], None, MatchConfidence::Inferred);
        let at_home = named_rule("tool", &[".tool", "bin"], None, MatchConfidence::Inferred);
        // The shipped package guesses by name, and the vendor's names a location: neither wins.
        let located = [(&shipped, &by_name), (&vendor, &at_home)]
            .into_iter()
            .filter_map(|(plugin, rule)| rule.candidate(plugin, "", path, None, None, &[]))
            .collect::<Vec<_>>();
        assert!(matches!(resolve(located, None), Resolution::Conflict(_)));
        // The vendor's package declares its name exact, and it names no distribution to establish:
        // it is a guess like the shipped package's, so the two still conflict.
        let bold = named_rule("tool", &[], None, MatchConfidence::Exact);
        let exact = [(&shipped, &by_name), (&vendor, &bold)]
            .into_iter()
            .filter_map(|(plugin, rule)| rule.candidate(plugin, "", path, None, None, &[]))
            .collect::<Vec<_>>();
        assert!(matches!(resolve(exact, None), Resolution::Conflict(_)));
        // The same publisher name from another repository is not the same publisher: the name is
        // vouched for by the root of the repository that lists it, and two roots can list one.
        let helper = PluginId::new("kalareach/tool-helper").expect("a plugin identifier");
        let from = |authority: &'static str| {
            [
                (&shipped, &by_name, "official"),
                (&helper, &at_home, authority),
            ]
            .into_iter()
            .filter_map(|(plugin, rule, authority)| {
                rule.candidate(plugin, authority, path, None, None, &[])
            })
            .collect::<Vec<_>>()
        };
        match resolve(from("official"), None) {
            Resolution::Selected(candidate) => assert_eq!(candidate.plugin_id, helper),
            other => panic!("one publisher in one repository: the location wins: {other:?}"),
        }
        assert!(matches!(
            resolve(from("another root"), None),
            Resolution::Conflict(_)
        ));
        // And the person's own choice still decides.
        let chosen = [(&shipped, &by_name), (&vendor, &bold)]
            .into_iter()
            .filter_map(|(plugin, rule)| rule.candidate(plugin, "", path, None, None, &[]))
            .collect::<Vec<_>>();
        match resolve(chosen, Some(&vendor)) {
            Resolution::Selected(candidate) => assert_eq!(candidate.plugin_id, vendor),
            other => panic!("the selection should win: {other:?}"),
        }
    }

    const TOOL: &str = "/home/u/.tool/bin/tool";

    fn version(text: &str) -> PackageVersion {
        PackageVersion::parse(text).expect("a version")
    }

    fn within(mut rule: MatchRule, range: &str) -> MatchRule {
        rule.executable.version_range =
            Nullable(Some(VersionRange::parse(range).expect("a version range")));
        rule
    }

    /// The candidate `rule` makes of `plugin`, for a program of the version `installed` where one
    /// is established, held to the further `ranges` as well.
    fn recognised(
        plugin: &str,
        authority: &str,
        rule: &MatchRule,
        installed: Option<&str>,
        ranges: &[&str],
    ) -> Candidate {
        let plugin = PluginId::new(plugin).expect("a plugin identifier");
        let installed = installed.map(version);
        let ranges: Vec<VersionRange> = ranges
            .iter()
            .map(|range| VersionRange::parse(range).expect("a version range"))
            .collect();
        let ranges: Vec<&VersionRange> = ranges.iter().collect();
        rule.candidate(&plugin, authority, TOOL, None, installed.as_ref(), &ranges)
            .expect("recognised")
    }

    fn covering(plugin: &str, confidence: MatchConfidence, coverage: Coverage) -> Candidate {
        Candidate {
            coverage,
            ..candidate(plugin, confidence)
        }
    }

    fn chosen(resolution: Resolution) -> String {
        match resolution {
            Resolution::Selected(chosen) => chosen.plugin_id.to_string(),
            other => panic!("one package should be chosen: {other:?}"),
        }
    }

    #[test]
    fn a_rule_covers_a_version_it_admits_excludes_one_it_refuses_and_is_neutral_otherwise() {
        let open = named_rule("tool", &[], None, MatchConfidence::Inferred);
        let bounded = within(open.clone(), ">=1.0.0, <2.0.0");
        let coverage = |rule: &MatchRule, installed: Option<&str>, ranges: &[&str]| {
            recognised("kalareach/sample", "", rule, installed, ranges).coverage
        };
        // A rule that declares no range says nothing about a version, known or not.
        assert_eq!(coverage(&open, Some("1.4.0"), &[]), Coverage::Neutral);
        assert_eq!(coverage(&open, None, &[]), Coverage::Neutral);
        // A declared range is held against a known version.
        assert_eq!(coverage(&bounded, Some("1.4.0"), &[]), Coverage::Covers);
        assert_eq!(coverage(&bounded, Some("2.1.0"), &[]), Coverage::Excludes);
        // A version nothing established never counts against the package.
        assert_eq!(coverage(&bounded, None, &[]), Coverage::Neutral);
        assert_eq!(coverage(&bounded, None, &["=1.4.0"]), Coverage::Neutral);
        // A further range ranks a rule that declares none.
        assert_eq!(
            coverage(&open, Some("1.4.0"), &["=1.4.0"]),
            Coverage::Covers
        );
        assert_eq!(
            coverage(&open, Some("1.4.1"), &["=1.4.0"]),
            Coverage::Excludes
        );
        // Every range must admit the version, so two ranges are held as their intersection.
        assert_eq!(
            coverage(&bounded, Some("1.4.0"), &["=1.4.0"]),
            Coverage::Covers
        );
        assert_eq!(
            coverage(&bounded, Some("1.5.0"), &["=1.4.0"]),
            Coverage::Excludes
        );
        assert_eq!(
            coverage(&bounded, Some("2.0.0"), &[">=1.0.0"]),
            Coverage::Excludes
        );
        // A prerelease is outside a plain range, as the version grammar has it.
        assert_eq!(
            coverage(&bounded, Some("1.5.0-rc.1"), &[]),
            Coverage::Excludes
        );
        assert_eq!(
            coverage(&open, Some("1.5.0-rc.1"), &[">=1.5.0-rc.1"]),
            Coverage::Covers
        );
    }

    #[test]
    fn a_covering_package_beats_a_neutral_one_and_a_neutral_one_beats_an_excluding_one() {
        let by_name = named_rule("tool", &[], None, MatchConfidence::Inferred);
        let from_one = within(by_name.clone(), ">=1.0.0, <2.0.0");
        let from_two = within(by_name.clone(), ">=2.0.0");
        let candidates = |installed: &str| {
            vec![
                recognised("kalareach/one", "", &from_one, Some(installed), &[]),
                recognised("kalareach/two", "", &from_two, Some(installed), &[]),
                recognised("kalareach/plain", "", &by_name, Some(installed), &[]),
            ]
        };
        // At 1.4.0 the first covers, the second refuses and the third declares nothing.
        assert_eq!(chosen(resolve(candidates("1.4.0"), None)), "kalareach/one");
        let mut reversed = candidates("1.4.0");
        reversed.reverse();
        assert_eq!(chosen(resolve(reversed, None)), "kalareach/one");
        // At 2.1.0 the second covers.
        assert_eq!(chosen(resolve(candidates("2.1.0"), None)), "kalareach/two");
        // Without the covering package, the one that says nothing beats the one that refuses.
        let rest = candidates("1.4.0").split_off(1);
        assert_eq!(chosen(resolve(rest, None)), "kalareach/plain");
        // Equal coverage is still for the person to decide.
        let alike = vec![
            recognised("kalareach/one", "", &from_one, Some("1.4.0"), &[]),
            recognised("kalareach/same", "", &from_one, Some("1.4.0"), &[]),
        ];
        assert!(matches!(resolve(alike, None), Resolution::Conflict(_)));
        // And the person's own choice still decides, over a package that refuses the version.
        let excluded = PluginId::new("kalareach/two").expect("a plugin identifier");
        assert_eq!(
            chosen(resolve(candidates("1.4.0"), Some(&excluded))),
            "kalareach/two"
        );
    }

    #[test]
    fn coverage_ranks_before_an_exact_rule() {
        let exact = |coverage| covering("kalareach/exact", MatchConfidence::Exact, coverage);
        let guess = |coverage| covering("kalareach/guess", MatchConfidence::Inferred, coverage);
        // A package whose exact rule refuses the version loses to a guess that admits it, and to a
        // guess that says nothing.
        assert_eq!(
            chosen(resolve(
                vec![exact(Coverage::Excludes), guess(Coverage::Covers)],
                None
            )),
            "kalareach/guess"
        );
        assert_eq!(
            chosen(resolve(
                vec![exact(Coverage::Excludes), guess(Coverage::Neutral)],
                None
            )),
            "kalareach/guess"
        );
        // An exact rule still beats a guess of the same coverage.
        assert_eq!(
            chosen(resolve(
                vec![guess(Coverage::Covers), exact(Coverage::Covers)],
                None
            )),
            "kalareach/exact"
        );
    }

    #[test]
    fn coverage_ranks_before_the_installation_location() {
        let located = |coverage| Candidate {
            located: true,
            ..covering("kalareach/located", MatchConfidence::Inferred, coverage)
        };
        let named = |coverage| covering("kalareach/named", MatchConfidence::Inferred, coverage);
        // The shape of two packages for one program, one of which names its install location: a
        // package that refuses the version does not take the program by its location.
        assert_eq!(
            chosen(resolve(
                vec![located(Coverage::Excludes), named(Coverage::Covers)],
                None
            )),
            "kalareach/named"
        );
        // Among packages of one coverage, the location still decides.
        assert_eq!(
            chosen(resolve(
                vec![named(Coverage::Covers), located(Coverage::Covers)],
                None
            )),
            "kalareach/located"
        );
    }

    #[test]
    fn a_package_ranks_by_its_best_rule() {
        // One package with two rules, one of which refuses the version and one of which admits it,
        // against a package that says nothing: the first covers.
        let both = |rule_id: &str, coverage| Candidate {
            rule_id: rule_id.to_owned(),
            ..covering("kalareach/both", MatchConfidence::Inferred, coverage)
        };
        let plain = covering(
            "kalareach/plain",
            MatchConfidence::Inferred,
            Coverage::Neutral,
        );
        assert_eq!(
            chosen(resolve(
                vec![
                    both("refuses", Coverage::Excludes),
                    plain.clone(),
                    both("admits", Coverage::Covers),
                ],
                None
            )),
            "kalareach/both"
        );
        // A package with a rule that says nothing and one that refuses it is neutral, so it beats
        // a package whose only rule refuses.
        let refusing = covering(
            "kalareach/refusing",
            MatchConfidence::Inferred,
            Coverage::Excludes,
        );
        assert_eq!(
            chosen(resolve(
                vec![
                    refusing,
                    both("refuses", Coverage::Excludes),
                    both("silent", Coverage::Neutral),
                ],
                None
            )),
            "kalareach/both"
        );
    }

    #[test]
    fn coverage_does_not_rank_packages_of_other_publishers_or_repositories() {
        let shipped = |coverage| covering("kalareach/tool", MatchConfidence::Inferred, coverage);
        let vendor =
            |coverage| covering("example-vendor/tool", MatchConfidence::Inferred, coverage);
        // A publisher's own record of a build is a claim only its repository vouches for, so a
        // package of another publisher that names the program's version cannot take the program
        // from the shipped package by it.
        for (shipped_coverage, vendor_coverage) in [
            (Coverage::Neutral, Coverage::Covers),
            (Coverage::Excludes, Coverage::Covers),
            (Coverage::Excludes, Coverage::Neutral),
        ] {
            let candidates = vec![shipped(shipped_coverage), vendor(vendor_coverage)];
            assert_eq!(
                resolve(candidates.clone(), None),
                Resolution::Conflict(candidates),
                "{shipped_coverage:?} against {vendor_coverage:?}"
            );
        }
        // The same publisher's name from another repository is not the same publisher.
        let from = |authority: &str, coverage| Candidate {
            authority: authority.to_owned(),
            ..covering("kalareach/tool", MatchConfidence::Inferred, coverage)
        };
        let elsewhere = Candidate {
            plugin_id: PluginId::new("kalareach/tool-helper").expect("a plugin identifier"),
            ..from("another root", Coverage::Covers)
        };
        let candidates = vec![from("official", Coverage::Neutral), elsewhere];
        assert_eq!(
            resolve(candidates.clone(), None),
            Resolution::Conflict(candidates)
        );
        // Within one repository the same two coverages are ranked.
        let candidates = vec![
            from("official", Coverage::Neutral),
            Candidate {
                plugin_id: PluginId::new("kalareach/tool-helper").expect("a plugin identifier"),
                ..from("official", Coverage::Covers)
            },
        ];
        assert_eq!(chosen(resolve(candidates, None)), "kalareach/tool-helper");
        // A third package of another publisher in the set keeps the whole set unranked.
        let candidates = vec![
            shipped(Coverage::Covers),
            covering(
                "kalareach/other",
                MatchConfidence::Inferred,
                Coverage::Neutral,
            ),
            vendor(Coverage::Neutral),
        ];
        assert_eq!(
            resolve(candidates.clone(), None),
            Resolution::Conflict(candidates)
        );
        // And the person's own choice still decides.
        let selected = PluginId::new("example-vendor/tool").expect("a plugin identifier");
        assert_eq!(
            chosen(resolve(
                vec![shipped(Coverage::Covers), vendor(Coverage::Excludes)],
                Some(&selected)
            )),
            "example-vendor/tool"
        );
    }

    #[test]
    fn a_lone_excluding_package_stays_selected_and_all_excluding_packages_conflict() {
        let one = covering(
            "kalareach/one",
            MatchConfidence::Inferred,
            Coverage::Excludes,
        );
        let two = covering(
            "kalareach/two",
            MatchConfidence::Inferred,
            Coverage::Excludes,
        );
        // A program only one package recognises is that package's, whatever its version: the
        // package's own typed routes are refused later, not the binding.
        assert_eq!(chosen(resolve(vec![one.clone()], None)), "kalareach/one");
        // Packages that all refuse the version are alike, so nothing is preferred.
        assert_eq!(
            resolve(vec![one.clone(), two.clone()], None),
            Resolution::Conflict(vec![one, two])
        );
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
