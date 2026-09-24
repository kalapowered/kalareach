//! Offline search, and the match index activation reads.
//!
//! The host holds the whole signed metadata snapshot, so search never needs the network and never
//! needs a payload. Both things this module does are reads of that snapshot.
//!
//! * **Search** is over every entry: the name a person reads, the compact description, the plugin
//!   name and the publisher. Downloading the full catalogue is what makes that possible, and
//!   keeping the index small enough to hold is what makes downloading it reasonable.
//! * **Matching** is the other direction. Declarative match rules are indexed by executable file
//!   stem and by distribution, so recognising a running application is a lookup rather than a scan
//!   of every rule in the catalogue. A catalogue of ten thousand definitions is a map with ten
//!   thousand small buckets, and terminal input never waits behind it.
//!
//! Downloading the full catalogue does not activate every module. A candidate is an entry whose
//! rules recognise something; the host still asks whether that package is installed, enabled here
//! and not revoked before anything is instantiated.

use std::collections::BTreeMap;

use kr_plugin_sdk::catalogue::{CatalogueIndex, IndexEntry};
use kr_plugin_sdk::ids::PluginId;
use kr_plugin_sdk::matching::{DistributionMatch, MatchConfidence};

/// What the host observed about a running application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// The executable's path, as the host saw it.
    pub executable_path: String,
    /// Where the application was installed from, where the host knows.
    pub distribution: Option<DistributionMatch>,
}

/// One entry whose rules recognise an observation.
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

/// The match rules of one index, indexed for lookup.
#[derive(Debug)]
pub struct MatchIndex<'a> {
    index: &'a CatalogueIndex,
    by_stem: BTreeMap<String, Vec<usize>>,
    by_distribution: BTreeMap<(String, String), Vec<usize>>,
}

impl<'a> MatchIndex<'a> {
    /// Builds the lookup over one index.
    #[must_use]
    pub fn build(index: &'a CatalogueIndex) -> Self {
        let mut by_stem: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut by_distribution: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        for (position, entry) in index.entries.iter().enumerate() {
            for rule in &entry.match_rules {
                by_stem
                    .entry(rule.executable.file_stem.to_ascii_lowercase())
                    .or_default()
                    .push(position);
                if let Some(distribution) = rule.distribution.0.as_ref() {
                    by_distribution
                        .entry((
                            distribution.registry().to_owned(),
                            distribution.identifier().to_ascii_lowercase(),
                        ))
                        .or_default()
                        .push(position);
                }
            }
        }
        for positions in by_stem.values_mut().chain(by_distribution.values_mut()) {
            positions.dedup();
        }
        Self {
            index,
            by_stem,
            by_distribution,
        }
    }

    /// Returns the index this lookup was built over.
    #[must_use]
    pub const fn index(&self) -> &'a CatalogueIndex {
        self.index
    }

    /// Returns how many distinct executable stems the catalogue recognises.
    #[must_use]
    pub fn executable_count(&self) -> usize {
        self.by_stem.len()
    }

    /// Returns how many distinct distributions the catalogue recognises.
    #[must_use]
    pub fn distribution_count(&self) -> usize {
        self.by_distribution.len()
    }

    /// Returns every entry whose rules recognise the observation.
    ///
    /// A revoked release is not a candidate: it stops receiving new bindings, which is what a
    /// candidate would become. Its existing bindings are the installation's business, not this
    /// lookup's.
    #[must_use]
    pub fn candidates(&self, observation: &Observation) -> Vec<Candidate> {
        let stem = executable_stem(&observation.executable_path);
        let mut positions: Vec<usize> = self.by_stem.get(&stem).cloned().unwrap_or_default();
        if let Some(distribution) = observation.distribution.as_ref()
            && let Some(more) = self.by_distribution.get(&(
                distribution.registry().to_owned(),
                distribution.identifier().to_ascii_lowercase(),
            ))
        {
            positions.extend(more.iter().copied());
        }
        positions.sort_unstable();
        positions.dedup();

        let mut candidates = Vec::new();
        for position in positions {
            let Some(entry) = self.index.entries.get(position) else {
                continue;
            };
            if !entry.accepts_new_bindings() {
                continue;
            }
            for rule in &entry.match_rules {
                let executable_matched = rule.executable.matches_path(&observation.executable_path);
                let distribution_matched = match (
                    rule.distribution.0.as_ref(),
                    observation.distribution.as_ref(),
                ) {
                    (Some(declared), Some(observed)) => {
                        declared.registry() == observed.registry()
                            && declared
                                .identifier()
                                .eq_ignore_ascii_case(observed.identifier())
                    }
                    _ => false,
                };
                if !executable_matched && !distribution_matched {
                    continue;
                }
                candidates.push(Candidate {
                    plugin_id: entry.plugin_id.clone(),
                    rule_id: rule.id.to_string(),
                    confidence: rule.confidence,
                    distribution_matched,
                });
            }
        }
        candidates.sort_by(|left, right| {
            left.plugin_id
                .as_str()
                .cmp(right.plugin_id.as_str())
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });
        candidates
    }
}

/// Decides which candidate wins, given the selection the person made.
///
/// An explicit selection wins outright. That is the rule section 11 states, and it is why the
/// selection is compared before confidence: a person who chose a package is not overruled by a
/// rule that calls itself exact.
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

/// Searches the whole index offline.
///
/// The comparison folds ASCII case and is a substring over the fields a person would type: the
/// display name, the description, the plugin name and the publisher. An empty query returns the
/// first `limit` entries, which is what a catalogue view opens on.
#[must_use]
pub fn search<'a>(index: &'a CatalogueIndex, query: &str, limit: usize) -> Vec<&'a IndexEntry> {
    let needle = query.trim().to_ascii_lowercase();
    index
        .entries
        .iter()
        .filter(|entry| {
            needle.is_empty()
                || entry
                    .display_name
                    .as_str()
                    .to_ascii_lowercase()
                    .contains(&needle)
                || entry
                    .description
                    .as_str()
                    .to_ascii_lowercase()
                    .contains(&needle)
                || entry
                    .plugin_name
                    .to_string()
                    .to_ascii_lowercase()
                    .contains(&needle)
                || entry
                    .publisher_id
                    .to_string()
                    .to_ascii_lowercase()
                    .contains(&needle)
        })
        .take(limit)
        .collect()
}

/// Returns the executable's file stem, folded to lower case.
///
/// The same rules the SDK's executable match uses: either separator, a `.exe` suffix that Windows
/// spells and other platforms do not, and a trailing separator that names a directory rather than
/// a program.
fn executable_stem(path: &str) -> String {
    let normalised = path.replace('\\', "/");
    let Some(file) = normalised
        .rsplit('/')
        .next()
        .filter(|file| !file.is_empty())
    else {
        return String::new();
    };
    let stem = match file
        .len()
        .checked_sub(4)
        .and_then(|start| file.get(start..))
    {
        Some(suffix) if suffix.eq_ignore_ascii_case(".exe") => &file[..file.len() - 4],
        _ => file,
    };
    stem.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_plugin_sdk::digest::PayloadDigest;
    use kr_plugin_sdk::example::example_manifest;
    use kr_plugin_sdk::ids::PluginName;
    use kr_plugin_sdk::matching::{ExecutableMatch, MatchRule};
    use kr_plugin_sdk::version::PackageVersion;
    use kr_protocol::ids::RepositoryGeneration;
    use kr_protocol::scalars::{Nullable, TimestampMs};

    fn rule(id: &str, stem: &str, confidence: MatchConfidence) -> MatchRule {
        MatchRule {
            id: PluginName::new(id).expect("a valid rule identifier"),
            executable: ExecutableMatch {
                file_stem: stem.to_owned(),
                path_suffix: Vec::new(),
                version_range: Nullable(None),
            },
            distribution: Nullable(None),
            confidence,
        }
    }

    fn index(entries: Vec<IndexEntry>) -> CatalogueIndex {
        CatalogueIndex {
            index_version: kr_plugin_sdk::catalogue::INDEX_VERSION,
            generation: RepositoryGeneration::new(1),
            produced_at: TimestampMs::new(1_760_000_000_000),
            publishers: Vec::new(),
            entries,
        }
    }

    fn entry(name: &str, rules: Vec<MatchRule>) -> IndexEntry {
        let mut manifest = example_manifest();
        manifest.plugin_name = PluginName::new(name).expect("a valid plugin name");
        manifest.match_rules = rules;
        IndexEntry::from_manifest(&manifest, PayloadDigest::of(name.as_bytes()), 4_096)
    }

    #[test]
    fn rules_are_indexed_by_executable_and_by_distribution() {
        let mut with_distribution = rule("npm", "helper", MatchConfidence::Exact);
        with_distribution.distribution = Nullable(Some(DistributionMatch::Npm {
            package: "@vendor/sample-helper".to_owned(),
        }));
        let catalogue = index(vec![
            entry("one", vec![rule("a", "sampletool", MatchConfidence::Exact)]),
            entry("two", vec![with_distribution]),
        ]);
        let lookup = MatchIndex::build(&catalogue);
        assert_eq!(lookup.executable_count(), 2);
        assert_eq!(lookup.distribution_count(), 1);

        let found = lookup.candidates(&Observation {
            executable_path: "/usr/local/bin/sampletool".to_owned(),
            distribution: None,
        });
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "a");

        // The distribution alone recognises an executable whose name says nothing.
        let by_distribution = lookup.candidates(&Observation {
            executable_path: "/opt/node/bin/node".to_owned(),
            distribution: Some(DistributionMatch::Npm {
                package: "@vendor/sample-helper".to_owned(),
            }),
        });
        assert_eq!(by_distribution.len(), 1);
        assert!(by_distribution[0].distribution_matched);
    }

    #[test]
    fn an_explicit_selection_wins_a_conflict() {
        let catalogue = index(vec![
            entry("one", vec![rule("a", "sampletool", MatchConfidence::Exact)]),
            entry("two", vec![rule("b", "sampletool", MatchConfidence::Exact)]),
        ]);
        let lookup = MatchIndex::build(&catalogue);
        let observed = Observation {
            executable_path: "/usr/local/bin/sampletool".to_owned(),
            distribution: None,
        };
        let found = lookup.candidates(&observed);
        assert_eq!(found.len(), 2);
        assert!(matches!(
            resolve(found.clone(), None),
            Resolution::Conflict(_)
        ));

        let chosen = catalogue.entries[1].plugin_id.clone();
        match resolve(found, Some(&chosen)) {
            Resolution::Selected(candidate) => assert_eq!(candidate.plugin_id, chosen),
            other => panic!("the selection should win: {other:?}"),
        }
    }

    #[test]
    fn an_exact_rule_beats_an_inferred_one() {
        let catalogue = index(vec![
            entry(
                "guess",
                vec![rule("a", "sampletool", MatchConfidence::Inferred)],
            ),
            entry(
                "exact",
                vec![rule("b", "sampletool", MatchConfidence::Exact)],
            ),
        ]);
        let lookup = MatchIndex::build(&catalogue);
        let found = lookup.candidates(&Observation {
            executable_path: "/usr/local/bin/sampletool.EXE".to_owned(),
            distribution: None,
        });
        match resolve(found, None) {
            Resolution::Selected(candidate) => {
                assert_eq!(candidate.confidence, MatchConfidence::Exact);
                assert_eq!(candidate.plugin_id, catalogue.entries[1].plugin_id);
            }
            other => panic!("the exact rule should win: {other:?}"),
        }
    }

    #[test]
    fn a_revoked_release_is_never_a_candidate() {
        let mut catalogue = index(vec![entry(
            "one",
            vec![rule("a", "sampletool", MatchConfidence::Exact)],
        )]);
        catalogue.entries[0].revocation =
            Nullable(Some(kr_plugin_sdk::catalogue::RevocationRecord {
                reason: kr_plugin_sdk::catalogue::RevocationReason::Vulnerable,
                revoked_at: TimestampMs::new(1_760_000_100_000),
                statement: kr_plugin_sdk::text::Summary::new("Replaced by 0.1.1")
                    .expect("a valid statement"),
            }));
        let lookup = MatchIndex::build(&catalogue);
        assert!(
            lookup
                .candidates(&Observation {
                    executable_path: "/usr/local/bin/sampletool".to_owned(),
                    distribution: None,
                })
                .is_empty()
        );
    }

    #[test]
    fn search_reads_the_whole_index_and_touches_nothing_else() {
        let mut second = entry(
            "custom-cli",
            vec![rule("a", "custom-cli", MatchConfidence::Exact)],
        );
        second.display_name = kr_plugin_sdk::text::Label::new("Custom CLI").expect("a valid label");
        second.version = PackageVersion::parse("0.2.0").expect("a valid version");
        let catalogue = index(vec![
            entry(
                "sampletool",
                vec![rule("a", "sampletool", MatchConfidence::Exact)],
            ),
            second,
        ]);
        assert_eq!(search(&catalogue, "custom-cli", 10).len(), 1);
        assert_eq!(search(&catalogue, "CUSTOM CLI", 10).len(), 1);
        assert_eq!(search(&catalogue, "", 10).len(), 2);
        assert_eq!(search(&catalogue, "", 1).len(), 1);
        assert!(search(&catalogue, "nothing here", 10).is_empty());
    }

    #[test]
    fn a_stem_is_read_the_way_every_platform_spells_it() {
        assert_eq!(
            executable_stem("C:\\Program Files\\SampleTool\\SAMPLETOOL.EXE"),
            "sampletool"
        );
        assert_eq!(executable_stem("/usr/local/bin/sampletool"), "sampletool");
        assert_eq!(executable_stem("/usr/local/bin/"), "");
        assert_eq!(executable_stem(""), "");
    }
}
