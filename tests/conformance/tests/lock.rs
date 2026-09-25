//! The application lock: every program of the matrix pinned for every platform the report runs
//! it on, with its cases, and a reason wherever it does not run.

use std::path::{Path, PathBuf};

use kr_conformance::report;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// KR-ACC-004, KR-REQ-27.04: every program of the matrix is pinned by URL and SHA-256 for each
/// platform the report runs it on, has its cases, and on a platform with no build is recorded as
/// not run there, with the reason.
#[test]
fn every_program_is_pinned_has_cases_and_says_why_it_does_not_run_where_it_does_not() {
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repository().join("tests/conformance/applications.lock"))
            .expect("the lock"),
    )
    .expect("JSON");
    let programs: Vec<&serde_json::Value> = lock["applications"]
        .as_array()
        .expect("applications")
        .iter()
        .filter(|application| application["role"] == "program")
        .collect();
    let ids: Vec<&str> = programs
        .iter()
        .filter_map(|program| program["id"].as_str())
        .collect();
    assert_eq!(ids, ["neovim", "htop", "lazygit", "fzf", "tmux", "screen"]);
    for program in &programs {
        let id = program["id"].as_str().expect("an id");
        let sources = program["sources"].as_array().expect("sources");
        for platform in [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
        ] {
            assert!(
                sources
                    .iter()
                    .any(|source| source["platform"] == platform || source["platform"] == "unix"),
                "{id} has a source for {platform}"
            );
        }
        for source in sources {
            let digest = source["sha256"].as_str().expect("a digest");
            assert!(
                digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "{id}: {digest}"
            );
            assert!(
                source["url"]
                    .as_str()
                    .is_some_and(|url| url.starts_with("https://")),
                "{id}"
            );
        }
        assert!(
            program["not_run"]["windows"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "{id}"
        );
        assert!(
            repository()
                .join("tests/conformance/tests/applications")
                .join(format!("{id}.rs"))
                .is_file(),
            "{id} has its cases"
        );
    }
    let recorded = report::lock_applications(&repository(), "windows").expect("reads the lock");
    assert_eq!(recorded.len(), programs.len());
    assert!(
        recorded
            .iter()
            .all(|record| record.status == "unsupported_platform" && record.reason.is_some())
    );
}
