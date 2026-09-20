//! What a package may contain, checked before it is fetched and again before it is activated.
//!
//! A signed package establishes provenance, not safety. Whoever signed it, its contents are still
//! untrusted input, so the same rules apply to an official package and to one from a repository
//! somebody added an hour ago.
//!
//! The checks run twice, against different things.
//!
//! * **Before anything is fetched**, against what the index declares: every payload path is a
//!   package-relative name the rules admit, no two of them collide on a case-insensitive
//!   filesystem, the manifest does not declare itself, and the declared sizes and file count are
//!   inside one package's limits. A repository that declares a gigabyte never gets a fetch
//!   started.
//! * **Before anything is activated**, against the bytes that arrived, with
//!   [`kr_plugin_sdk::validate::validate_package_directory`]. That is the publishing pipeline's
//!   own validator: a package this host accepts is a package that repository's build accepted,
//!   and the two cannot drift. It rejects a path that escapes, an entry that is not a regular
//!   file, case collisions, a file the manifest does not declare, a payload that is absent, and a
//!   length or digest that is not what was declared.
//!
//! Nothing here executes anything. Section 11 says sync executes no installation scripts, and
//! this module is the whole of what a sync does with a package's bytes: it writes them as data,
//! without an execute bit, and reads them back to check them.

use std::collections::BTreeSet;

use kr_plugin_sdk::catalogue::IndexEntry;
use kr_plugin_sdk::package::MANIFEST_FILE;
use kr_plugin_sdk::paths::{CollisionKind, PackagePath, find_collisions};
use kr_plugin_sdk::plugin::PluginManifest;
use kr_plugin_sdk::validate::{Validated, validate_package_directory};

use crate::catalogue::budget::{BudgetLedger, Stage};
use crate::catalogue::error::{CatalogueError, CatalogueResult};

/// Checks what an index entry declares, before a single byte is fetched.
///
/// # Errors
///
/// Returns [`CatalogueError::UnsafePackage`] when the declared layout breaks a rule, and
/// [`CatalogueError::ResourceLimit`] when the declared sizes are past one package's limits.
pub fn check_declared(entry: &IndexEntry, ledger: &BudgetLedger) -> CatalogueResult<()> {
    let subject = format!(
        "{}/{} {}",
        entry.publisher_id, entry.plugin_name, entry.version
    );

    let mut paths: Vec<PackagePath> = Vec::with_capacity(entry.payloads.len() + 1);
    let manifest =
        PackagePath::new(MANIFEST_FILE).map_err(|source| CatalogueError::UnsafePackage {
            detail: format!("{MANIFEST_FILE} is not a package path: {source}"),
        })?;
    for payload in &entry.payloads {
        if payload.path == manifest {
            return Err(CatalogueError::UnsafePackage {
                detail: format!(
                    "{subject} declares {MANIFEST_FILE} as one of its own payloads; the manifest \
                     is the document doing the declaring, and its digest is the index's"
                ),
            });
        }
        paths.push(payload.path.clone());
    }
    paths.push(manifest);
    check_collisions(&paths, &subject)?;

    let declared_total = entry.total_size_bytes.get();
    let summed = entry
        .payloads
        .iter()
        .fold(entry.manifest_size_bytes.get(), |total, payload| {
            total.saturating_add(payload.size_bytes.get())
        });
    if declared_total != summed {
        return Err(CatalogueError::UnsafePackage {
            detail: format!(
                "{subject} declares a total of {declared_total} bytes over payloads summing to \
                 {summed}; the total is what a budget is checked against before a fetch"
            ),
        });
    }
    ledger.check_package(
        declared_total,
        paths.len() as u64,
        Stage::Declared,
        &subject,
    )?;
    Ok(())
}

/// Checks the declared paths against the case-insensitive filesystems a host may sit on.
///
/// # Errors
///
/// Returns [`CatalogueError::UnsafePackage`] naming both paths and how they collide.
pub fn check_collisions(paths: &[PackagePath], subject: &str) -> CatalogueResult<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for path in paths {
        if !seen.insert(path.as_str()) {
            return Err(CatalogueError::UnsafePackage {
                detail: format!("{subject} declares {} twice", path.as_str()),
            });
        }
    }
    if let Some(collision) = find_collisions(paths).first() {
        let how = match collision.kind {
            CollisionKind::SameFile => "fold to the same name",
            CollisionKind::FileAndDirectory => "need the same name as a file and as a directory",
        };
        return Err(CatalogueError::UnsafePackage {
            detail: format!(
                "{subject} declares {} and {}, which {how} on a case-insensitive filesystem",
                collision.first.as_str(),
                collision.second.as_str()
            ),
        });
    }
    Ok(())
}

/// Returns the relative name a target inside this package carries.
///
/// A target name is `packages/<publisher>/<plugin>/<version>/<relative>`. The relative part is
/// compared with what the manifest declares rather than trusted, because a target name is chosen
/// by whoever built the generation and a package path is checked by the rules in the SDK.
///
/// # Errors
///
/// Returns [`CatalogueError::UnsafePackage`] when the name is not inside this package's prefix or
/// its remainder is not a package path.
pub fn relative_target(prefix: &str, target: &str) -> CatalogueResult<PackagePath> {
    let rest = target
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
        .ok_or_else(|| CatalogueError::UnsafePackage {
            detail: format!("{target} is not inside {prefix}"),
        })?;
    PackagePath::new(rest).map_err(|source| CatalogueError::UnsafePackage {
        detail: format!("{target} carries the unsafe package path {rest}: {source}"),
    })
}

/// Checks the bytes that arrived, with the validator the publishing pipeline uses.
///
/// # Errors
///
/// Returns [`CatalogueError::UnsafePackage`] listing every finding, so somebody fixing a package
/// gets the whole list rather than one finding per attempt.
pub fn check_staged(directory: &std::path::Path, subject: &str) -> CatalogueResult<PluginManifest> {
    let Validated { package, report } = validate_package_directory(directory);
    if !report.is_valid() {
        let detail = report
            .findings
            .iter()
            .map(|finding| match &finding.path {
                Some(path) => format!("{}: {path}: {}", finding.code.as_str(), finding.detail),
                None => format!("{}: {}", finding.code.as_str(), finding.detail),
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(CatalogueError::UnsafePackage {
            detail: format!("{subject} is not a package this host will install: {detail}"),
        });
    }
    package
        .map(|package| package.manifest)
        .ok_or_else(|| CatalogueError::UnsafePackage {
            detail: format!("{subject} has no readable manifest"),
        })
}

/// Checks that what arrived is the package the index pointed at.
///
/// # Errors
///
/// Returns [`CatalogueError::Integrity`] when the staged manifest names a different package, and
/// [`CatalogueError::ResourceLimit`] when the bytes that arrived are past one package's limits.
pub fn check_actual(
    entry: &IndexEntry,
    manifest: &PluginManifest,
    staged_bytes: u64,
    staged_files: u64,
    ledger: &BudgetLedger,
) -> CatalogueResult<()> {
    let subject = format!(
        "{}/{} {}",
        entry.publisher_id, entry.plugin_name, entry.version
    );
    reconcile(entry, manifest, &subject)?;
    // Undeclared expansion: the bytes on disk are measured, not the bytes the index promised.
    let declared = entry.total_size_bytes.get();
    if staged_bytes > declared {
        return Err(CatalogueError::UnsafePackage {
            detail: format!(
                "{subject} declared {declared} bytes and expanded to {staged_bytes}; a package \
                 does not grow during processing"
            ),
        });
    }
    ledger.check_package(staged_bytes, staged_files, Stage::Actual, &subject)?;
    Ok(())
}

/// Checks that the index entry describes the package that actually arrived.
///
/// An index is signed, and so is a manifest, and they are signed by the same repository. That does
/// not make them agree: an entry that omits a capability the manifest requests would be an
/// installation decided against a shorter list than the package carries, and an entry whose
/// identity names another package would label somebody else's manifest.
///
/// Everything the entry derives from the manifest is compared with what the manifest says. What
/// the entry adds on its own, the qualification results and the revocation record, is the
/// catalogue's and is not in the manifest to compare against.
fn reconcile(entry: &IndexEntry, manifest: &PluginManifest, subject: &str) -> CatalogueResult<()> {
    let derived = IndexEntry::from_manifest(
        manifest,
        entry.manifest_digest,
        entry.manifest_size_bytes.get(),
    );
    let mismatch = if derived.plugin_id != entry.plugin_id {
        Some("plugin identifier")
    } else if derived.publisher_id != entry.publisher_id || derived.plugin_name != entry.plugin_name
    {
        Some("publisher and name")
    } else if derived.version != entry.version {
        Some("version")
    } else if derived.capabilities != entry.capabilities {
        Some("requested capabilities")
    } else if derived.match_rules != entry.match_rules {
        Some("match rules")
    } else if derived.platforms != entry.platforms {
        Some("platform support")
    } else if derived.payloads != entry.payloads {
        Some("payloads")
    } else if derived.sdk_range != entry.sdk_range || derived.wit_range != entry.wit_range {
        Some("SDK and WIT ranges")
    } else if derived.total_size_bytes != entry.total_size_bytes {
        Some("total size")
    } else if derived.has_component != entry.has_component {
        Some("component")
    } else {
        None
    };
    if let Some(field) = mismatch {
        return Err(CatalogueError::Integrity {
            detail: format!(
                "{subject}: the index and the package's own manifest disagree about its {field}; \
                 an installation is decided against the manifest the host verified"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_plugin_sdk::digest::{ByteSize, PayloadDigest};
    use kr_plugin_sdk::example::example_manifest;
    use kr_plugin_sdk::limits::RepositoryBudgets;
    use kr_plugin_sdk::plugin::{PayloadRef, PayloadRole};

    fn ledger() -> BudgetLedger {
        BudgetLedger::new(RepositoryBudgets::defaults())
    }

    fn entry() -> IndexEntry {
        IndexEntry::from_manifest(&example_manifest(), PayloadDigest::of(b"manifest"), 4_096)
    }

    fn path(text: &str) -> PackagePath {
        PackagePath::new(text).expect("a safe path")
    }

    #[test]
    fn a_declared_layout_that_collides_is_refused_before_a_fetch() {
        let paths = vec![path("assets/Readme.md"), path("assets/README.md")];
        let refusal = check_collisions(&paths, "acme/tool 1.0.0").expect_err("a case collision");
        assert!(
            refusal.to_string().contains("case-insensitive"),
            "{refusal}"
        );

        let shadowed = vec![path("assets"), path("assets/logo.png")];
        let refusal = check_collisions(&shadowed, "acme/tool 1.0.0").expect_err("a shadow");
        assert!(matches!(refusal, CatalogueError::UnsafePackage { .. }));

        let twice = vec![path("assets/logo.png"), path("assets/logo.png")];
        let refusal = check_collisions(&twice, "acme/tool 1.0.0").expect_err("a duplicate");
        assert!(refusal.to_string().contains("twice"), "{refusal}");
    }

    #[test]
    fn a_package_that_declares_its_own_manifest_is_refused() {
        let mut entry = entry();
        entry.payloads.push(PayloadRef {
            role: PayloadRole::Asset,
            path: path(MANIFEST_FILE),
            digest: PayloadDigest::of(b"manifest"),
            size_bytes: ByteSize::new(4_096),
        });
        entry.total_size_bytes = ByteSize::new(entry.total_size_bytes.get() + 4_096);
        let refusal = check_declared(&entry, &ledger()).expect_err("the manifest declares itself");
        assert!(
            refusal.to_string().contains("doing the declaring"),
            "{refusal}"
        );
    }

    #[test]
    fn a_total_that_does_not_match_its_payloads_is_refused() {
        let mut entry = entry();
        entry.total_size_bytes = ByteSize::new(1);
        let refusal = check_declared(&entry, &ledger()).expect_err("a lying total");
        assert!(
            refusal.to_string().contains("total is what a budget"),
            "{refusal}"
        );
    }

    #[test]
    fn a_declared_package_past_the_package_limit_never_starts_a_fetch() {
        let mut entry = entry();
        let over = kr_plugin_sdk::package::MAX_PACKAGE_BYTES + 1;
        entry.payloads[0].size_bytes = ByteSize::new(over);
        entry.total_size_bytes = ByteSize::new(
            entry
                .payloads
                .iter()
                .fold(entry.manifest_size_bytes.get(), |total, payload| {
                    total + payload.size_bytes.get()
                }),
        );
        let refusal = check_declared(&entry, &ledger()).expect_err("over the package limit");
        let message = refusal.to_string();
        assert!(message.contains("package_bytes"), "{message}");
        assert!(message.contains("declared"), "{message}");
    }

    #[test]
    fn a_target_name_outside_the_package_is_refused() {
        let prefix = "packages/kalareach/example-declarative/0.1.0";
        assert_eq!(
            relative_target(prefix, &format!("{prefix}/presentation.json"))
                .expect("inside")
                .as_str(),
            "presentation.json"
        );
        for name in [
            "packages/other/tool/0.1.0/plugin.json",
            "index.json",
            "packages/kalareach/example-declarative/0.1.0/../../../etc/passwd",
            "packages/kalareach/example-declarative/0.1.0//plugin.json",
        ] {
            assert!(
                relative_target(prefix, name).is_err(),
                "{name} should be refused"
            );
        }
    }

    #[test]
    fn a_package_that_expands_past_its_declaration_is_refused() {
        let entry = entry();
        let manifest = example_manifest();
        let declared = entry.total_size_bytes.get();
        assert!(check_actual(&entry, &manifest, declared, 4, &ledger()).is_ok());
        let refusal =
            check_actual(&entry, &manifest, declared + 1, 4, &ledger()).expect_err("an expansion");
        assert!(refusal.to_string().contains("does not grow"), "{refusal}");
    }

    #[test]
    fn a_package_that_is_not_the_one_the_index_pointed_at_is_refused() {
        let entry = entry();
        let mut manifest = example_manifest();
        manifest.version =
            kr_plugin_sdk::version::PackageVersion::parse("9.9.9").expect("a valid version");
        let refusal = check_actual(&entry, &manifest, 1, 1, &ledger()).expect_err("a swap");
        assert!(matches!(refusal, CatalogueError::Integrity { .. }));
    }

    #[test]
    fn an_index_that_understates_a_package_is_refused() {
        // A signed index that lists fewer capabilities than the package's own manifest requests
        // would be an installation decided against a shorter list than the package carries.
        let mut understated = entry();
        understated.capabilities.clear();
        let manifest = example_manifest();
        let refusal = check_actual(
            &understated,
            &manifest,
            understated.total_size_bytes.get(),
            2,
            &ledger(),
        )
        .expect_err("an understated entry");
        assert!(
            refusal.to_string().contains("requested capabilities"),
            "{refusal}"
        );

        // And one whose match rules were widened after the manifest was signed.
        let mut widened = entry();
        widened.match_rules.clear();
        let refusal = check_actual(
            &widened,
            &manifest,
            widened.total_size_bytes.get(),
            2,
            &ledger(),
        )
        .expect_err("a widened entry");
        assert!(refusal.to_string().contains("match rules"), "{refusal}");
    }
}
