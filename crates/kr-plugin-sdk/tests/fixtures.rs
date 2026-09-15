//! Validates every fixture package.
//!
//! The valid packages must validate cleanly. Each invalid package must produce exactly the
//! findings its `expected.json` names, so a change that stops detecting a defect fails here
//! rather than in somebody's installation.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kr_plugin_sdk::validate::{FindingCode, validate_package_directory};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins")
}

fn directories(under: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(under)
        .unwrap_or_else(|error| panic!("{}: {error}", under.display()))
        .map(|entry| entry.expect("a readable directory entry").path())
        .filter(|path| path.is_dir())
        .collect();
    entries.sort();
    entries
}

#[test]
fn every_valid_fixture_validates() {
    let valid = directories(&fixtures_root().join("valid"));
    assert!(!valid.is_empty(), "there are no valid fixtures");
    for package in valid {
        let validated = validate_package_directory(&package);
        assert!(
            validated.report.is_valid(),
            "{} is not valid: {:?}",
            package.display(),
            validated.report.findings
        );
        assert!(
            validated.package.is_some(),
            "{} produced no package",
            package.display()
        );
    }
}

#[test]
fn every_invalid_fixture_produces_exactly_its_expected_findings() {
    let cases = directories(&fixtures_root().join("invalid"));
    assert!(!cases.is_empty(), "there are no invalid fixtures");
    for case in cases {
        let expectation: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(case.join("expected.json"))
                .unwrap_or_else(|error| panic!("{}: {error}", case.display())),
        )
        .expect("expected.json parses");
        let expected: BTreeSet<FindingCode> = expectation["codes"]
            .as_array()
            .expect("codes is an array")
            .iter()
            .map(|value| {
                serde_json::from_value(value.clone()).unwrap_or_else(|error| {
                    panic!("{}: {value} is not a finding code: {error}", case.display())
                })
            })
            .collect();

        let validated = validate_package_directory(&case.join("package"));
        let produced: BTreeSet<FindingCode> = validated.report.codes().into_iter().collect();
        assert_eq!(
            produced,
            expected,
            "{} produced {:?}",
            case.display(),
            validated.report.findings
        );
        assert!(
            !validated.report.is_valid(),
            "{} validated cleanly",
            case.display()
        );
    }
}

#[test]
fn the_invalid_fixtures_cover_the_defects_the_package_contract_names() {
    let mut covered: BTreeSet<FindingCode> = BTreeSet::new();
    for case in directories(&fixtures_root().join("invalid")) {
        let validated = validate_package_directory(&case.join("package"));
        covered.extend(validated.report.codes());
    }
    for required in [
        FindingCode::UnsafePath,
        FindingCode::CaseCollidingPath,
        FindingCode::DuplicatePath,
        FindingCode::SizeMismatch,
        FindingCode::DigestMismatch,
        FindingCode::UndeclaredFile,
        FindingCode::UnknownEffectClass,
        FindingCode::ActionNotRegistered,
        FindingCode::EffectWithoutCapability,
        FindingCode::UnboundedVersionRange,
        FindingCode::PredicateInvalid,
        FindingCode::ConnectorUndeclared,
    ] {
        assert!(
            covered.contains(&required),
            "no fixture produces {}",
            required.as_str()
        );
    }
}
