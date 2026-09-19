//! The shell-integration qualification: every managed package against the startup customisations
//! people actually run.
//!
//! Section 7 names the set — zsh-autosuggestions, zsh-syntax-highlighting, Powerlevel10k with its
//! instant prompt, starship, oh-my-zsh, fzf's widgets, atuin and ordinary distribution
//! customisations — and says what has to hold under each of them: the person's bindings and the
//! normal profile order survive, a PowerShell profile runs exactly once, a buffer a plugin has
//! rewritten is never read as an empty prompt, and a native module this build cannot load is
//! diagnosed rather than loaded silently.
//!
//! The corpus under `tests/shells/` is that set as data, and this suite reads it the way
//! `tests/harness.rs` reads `fixtures/shell-bridge/`: one directory per shell and stack with the
//! startup files it installs, and one list per shell of the combinations that do not exist, each
//! with its reason. Nothing here is substituted: a stack the fetcher could not reach is reported
//! as one this run did not qualify.
//!
//! A run with no built package, or with no stacks fetched, prints why and stops. Continuous
//! integration builds the packages and fetches the stacks in the same job and sets
//! `KR_REQUIRE_SHELL_PACKAGES` and `KR_REQUIRE_SHELL_STACKS`, where either absence is a failure.

// The corpus drives built Unix shells over a Unix socket in a pseudo-terminal. The Windows leg of
// the PowerShell module — its named pipe and its configured chord — is qualified on Windows.
#![cfg(unix)]

mod shellpkg;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use kr_shell_integration::contract::qualification::{BridgeAbi, ShellKind};

use shellpkg::{
    CaseOutcome, CaseSetup, Package, QualificationCase, Session, StackIndex, StackLock, cases,
    corpus_root, record_outcomes, repository_root, settle, unsupported,
};

/// The environment variable that turns an unfetched stack into a failure rather than a skip.
const REQUIRE_STACKS: &str = "KR_REQUIRE_SHELL_STACKS";

/// Every check a case may claim. A name outside this set is a corpus that says something this
/// runner does not do, which is worse than a check that fails.
const KNOWN_CHECKS: &[&str] = &[
    "identity",
    "profile_order",
    "user_bindings",
    "plugin_buffer",
    "native_module",
    "profile_once",
];

/// The customisations a case may name that are not pinned archives.
const UNPINNED_STACKS: &[&str] = &["none", "distribution", "native-module"];

#[test]
fn every_combination_of_a_shell_and_a_startup_customisation_is_accounted_for() {
    let lock = StackLock::read();
    let corpus = cases();
    let lists = unsupported();
    assert!(
        corpus.len() >= 20,
        "the corpus has shrunk to {} cases",
        corpus.len()
    );

    let mut identifiers = BTreeSet::new();
    for case in &corpus {
        assert!(
            identifiers.insert(case.id.clone()),
            "two cases are called {}",
            case.id
        );
        assert!(
            !case.covers.is_empty(),
            "{} names no requirement row",
            case.id
        );
        assert!(
            case.supported == case.reason.is_none(),
            "{} is supported and gives a reason, or is not and gives none",
            case.id
        );
        for check in &case.checks {
            assert!(
                KNOWN_CHECKS.contains(&check.as_str()),
                "{} claims {check}, which this suite does not run",
                case.id
            );
        }
        assert!(
            case.checks.contains(&"identity".to_owned()),
            "{} does not say which package it qualified",
            case.id
        );
        if case.checks.contains(&"native_module".to_owned()) {
            assert!(
                case.native_module.is_some(),
                "{} drives a native module and describes none",
                case.id
            );
        }
        assert!(
            UNPINNED_STACKS.contains(&case.stack.as_str())
                || lock.stacks.iter().any(|pinned| pinned.id == case.stack),
            "{} names the stack {}, which is not pinned",
            case.id,
            case.stack
        );
        for required in &case.requires {
            assert!(
                lock.stacks.iter().any(|pinned| pinned.id == *required),
                "{} needs {required}, which is not pinned",
                case.id
            );
        }
        for file in &case.home {
            let path = case.directory.join("home").join(&file.file);
            assert!(
                path.is_file(),
                "{} names {}, which is not there",
                case.id,
                path.display()
            );
        }
    }

    // Section 7 names the set once. Every pinned stack is therefore either driven on a shell or
    // recorded as one that shell does not have, with the reason, and nothing is silently absent.
    for shell in ShellKind::ALL {
        assert!(
            corpus_root().join(shell.as_str()).is_dir(),
            "{} has no cases at all",
            shell.as_str()
        );
        let list = lists
            .iter()
            .find(|list| list.shell == *shell)
            .unwrap_or_else(|| {
                panic!(
                    "{} has no record of what it does not support",
                    shell.as_str()
                )
            });
        for entry in &list.unsupported {
            assert!(
                lock.stacks.iter().any(|pinned| pinned.id == entry.stack),
                "{} records {} as unsupported, and it is not pinned",
                shell.as_str(),
                entry.stack
            );
            assert!(
                entry.reason.len() > 20,
                "{} records {} as unsupported without saying why",
                shell.as_str(),
                entry.stack
            );
        }
        for pinned in &lock.stacks {
            if !pinned.shells.iter().any(|named| named == shell.as_str()) {
                assert!(
                    list.unsupported
                        .iter()
                        .any(|entry| entry.stack == pinned.id),
                    "{} is not pinned for {} and no reason is recorded",
                    pinned.id,
                    shell.as_str()
                );
                continue;
            }
            let driven = corpus
                .iter()
                .any(|case| case.shell == *shell && case.requires.contains(&pinned.id));
            let excused = list
                .unsupported
                .iter()
                .any(|entry| entry.stack == pinned.id);
            assert!(
                driven || excused,
                "{} is pinned for {} and neither driven nor recorded as unsupported",
                pinned.id,
                shell.as_str()
            );
            assert!(
                !(driven && excused),
                "{} is both driven and recorded as unsupported on {}",
                pinned.id,
                shell.as_str()
            );
        }
    }

    // The specification names these by name, so the corpus has to carry all of them.
    for named in [
        "zsh-autosuggestions",
        "zsh-syntax-highlighting",
        "powerlevel10k",
        "starship",
        "oh-my-zsh",
        "fzf",
        "atuin",
    ] {
        assert!(
            corpus
                .iter()
                .any(|case| case.requires.iter().any(|id| id == named)),
            "no case drives {named}"
        );
    }
    assert!(
        corpus.iter().any(|case| case.stack == "distribution"),
        "no case drives an ordinary distribution startup customisation"
    );
}

#[test]
fn the_stacks_installed_here_are_the_ones_the_corpus_pins() {
    let lock = StackLock::read();
    let Some(index) = installed_stacks() else {
        return;
    };
    let committed = std::fs::read(repository_root().join("fixtures/shells/stacks.lock"))
        .expect("the pinned set is committed");
    let digest = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&committed);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        index.lock_sha256, digest,
        "the installed stacks were fetched from another pinned set; run scripts/fetch-shell-stacks.sh"
    );
    for stack in &index.stacks {
        let pinned = lock
            .stacks
            .iter()
            .find(|pinned| pinned.id == stack.id)
            .unwrap_or_else(|| panic!("{} is installed and is not pinned", stack.id));
        assert_eq!(
            stack.version, pinned.version,
            "{} is installed at another version than the one pinned",
            stack.id
        );
        if stack.installed() {
            let digest = stack.sha256.as_deref().unwrap_or_default();
            assert!(
                pinned.sources.iter().any(|source| source.sha256 == digest),
                "{} was installed from an archive this set does not pin",
                stack.id
            );
        }
    }
}

#[test]
fn every_case_holds_against_the_package_it_names() {
    let corpus = cases();
    let index = installed_stacks();
    let mut outcomes = Vec::new();
    let mut failures = Vec::new();
    let mut ran = 0;

    for case in &corpus {
        if !case.supported {
            outcomes.push(CaseOutcome::skipped(
                case,
                &format!(
                    "not supported: {}",
                    case.reason.as_deref().unwrap_or("no reason recorded")
                ),
            ));
            continue;
        }
        let Some(index) = index.as_ref() else {
            outcomes.push(CaseOutcome::skipped(case, "no stacks are fetched here"));
            continue;
        };
        let package = match Package::find(case.shell) {
            Ok(package) => package,
            Err(reason) => {
                assert!(
                    std::env::var_os(shellpkg::REQUIRE).is_none(),
                    "{} is set and {} is missing: {reason}",
                    shellpkg::REQUIRE,
                    case.shell.as_str()
                );
                outcomes.push(CaseOutcome::skipped(case, &format!("no package: {reason}")));
                continue;
            }
        };
        let mut missing = Vec::new();
        let mut versions = BTreeMap::new();
        for required in &case.requires {
            match index.get(required) {
                Some(stack) if stack.installed() => {
                    versions.insert(required.clone(), stack.version.clone());
                }
                Some(stack) => missing.push(format!(
                    "{required} is {} ({})",
                    stack.status,
                    stack.reason.as_deref().unwrap_or("no reason recorded")
                )),
                None => missing.push(format!("{required} is not in the index")),
            }
        }
        if !missing.is_empty() {
            let reason = missing.join("; ");
            assert!(
                std::env::var_os(REQUIRE_STACKS).is_none(),
                "{REQUIRE_STACKS} is set and {} cannot run: {reason}",
                case.id
            );
            outcomes.push(CaseOutcome::skipped(case, &reason));
            continue;
        }

        ran += 1;
        let mut outcome = CaseOutcome::skipped(case, "qualified");
        outcome.package_identity = Some(package.identity.clone());
        outcome.stack_versions = versions;
        outcome.checks = case.checks.clone();
        if let Err(reason) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_case(case, &package);
        })) {
            let message = reason
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| reason.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                .unwrap_or_else(|| "the case panicked".to_owned());
            outcome.verdict = format!("failed: {message}");
            failures.push(format!("{}: {message}", case.id));
        }
        outcomes.push(outcome);
    }

    record_outcomes("qualification-cases.tsv", &outcomes);
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    assert!(
        ran > 0,
        "no case ran: no package is built here and no stack is fetched here"
    );
}

/// Reads the index the fetcher wrote, or records why there is none.
fn installed_stacks() -> Option<StackIndex> {
    match StackIndex::read() {
        Ok(index) => Some(index),
        Err(reason) => {
            assert!(
                std::env::var_os(REQUIRE_STACKS).is_none(),
                "{REQUIRE_STACKS} is set and no stacks are fetched: {reason}"
            );
            println!("skipped: {reason}");
            None
        }
    }
}

/// Drives one case's shell through the checks it claims.
fn run_case(case: &QualificationCase, package: &Package) {
    let index = StackIndex::read().expect("the index was read before this case was chosen");
    let setup = CaseSetup::prepare(case, package, &index);
    let mut session = Session::start_for(package, case, &setup);
    let enter = session.first_prompt();
    // Several of these prompts are drawn by a program that runs at every prompt, so the reader is
    // given until its drawing stops before anything is typed at it.
    settle(&mut session, Duration::from_millis(300), REPLY);
    session.ensure_reading();

    for check in &case.checks {
        match check.as_str() {
            "identity" => {
                assert_eq!(
                    session.hello.shell.kind, case.shell,
                    "{} declared another shell",
                    case.id
                );
                assert_eq!(
                    session.hello.abi,
                    BridgeAbi::qualified(case.shell),
                    "{} declared a mechanism this shell is not qualified for",
                    case.id
                );
                let declared: Vec<String> = session
                    .hello
                    .shell
                    .patches
                    .iter()
                    .map(|patch| patch.name.clone())
                    .collect();
                assert_eq!(
                    declared,
                    package.patch_names(),
                    "{} declared patches the installed package does not record",
                    case.id
                );
                assert_eq!(
                    session.hello.shell.executable,
                    package.executable.display().to_string(),
                    "{} qualified a binary other than the one the record names",
                    case.id
                );
            }
            "profile_order" => {
                let recorded = setup.recorded_order();
                assert_eq!(
                    recorded,
                    case.order,
                    "{} ran its startup in another order; the terminal showed:\n{}",
                    case.id,
                    session.terminal_output()
                );
            }
            "profile_once" => {
                let recorded = setup.recorded_order();
                for marker in &case.order {
                    assert_eq!(
                        recorded.iter().filter(|line| *line == marker).count(),
                        1,
                        "{} ran the profile that records {marker} more than once",
                        case.id
                    );
                }
            }
            "plugin_buffer" => {
                // A plugin that rewrites the line on every keystroke is exactly what section 7
                // says a prompt hook cannot tell from an empty prompt. The reader's own answer is
                // what the fence carries, so it is asked with the line held and again once it is
                // cleared, under the same plugin.
                session.type_bytes(b"k");
                settle(&mut session, Duration::from_millis(200), REPLY);
                let held = session.fence_exchange(&enter, shellpkg::fence_id(1));
                assert!(
                    !held.editor.buffer_empty,
                    "{}: a line the plugin had rewritten was reported as an empty prompt",
                    case.id
                );
                session.clear_line();
                settle(&mut session, Duration::from_millis(200), REPLY);
                let cleared = session.fence_exchange(&enter, shellpkg::fence_id(2));
                assert!(
                    cleared.editor.buffer_empty,
                    "{}: a cleared line was still reported as holding something",
                    case.id
                );
            }
            "user_bindings" => {
                assert!(
                    session.user_binding_ran(),
                    "{}: the person's own binding {} did not survive the integration; the \
                     terminal showed:\n{}",
                    case.id,
                    case.binding,
                    session.terminal_output()
                );
                session.clear_line();
            }
            "native_module" => {
                let module = case
                    .native_module
                    .as_ref()
                    .expect("the corpus check refused a case without one");
                let recorded = setup.recorded_order();
                assert!(
                    recorded.contains(&module.marker),
                    "{}: {} was not diagnosed; the startup recorded {recorded:?}",
                    case.id,
                    module.name
                );
                assert!(
                    !recorded.iter().any(|line| line == "kr-module-loaded"),
                    "{}: {} was loaded",
                    case.id,
                    module.name
                );
                let diagnosis =
                    std::fs::read_to_string(setup.home.join("module-error")).unwrap_or_default();
                assert!(
                    !diagnosis.trim().is_empty(),
                    "{}: nothing said why {} was not loaded",
                    case.id,
                    module.name
                );
                // The integration is what it was before: the reader is there and answers.
                let acknowledgement = session.fence_exchange(&enter, shellpkg::fence_id(3));
                assert_eq!(acknowledgement.prompt_generation, enter.prompt_generation);
            }
            other => panic!("{}: {other} is not a check this suite runs", case.id),
        }
    }

    assert!(
        session.alive(),
        "{}: the shell did not survive its own qualification",
        case.id
    );
}

/// How long a reader is given before a case calls it a failure.
const REPLY: Duration = Duration::from_secs(20);

#[test]
fn every_case_names_the_requirement_rows_it_closes() {
    let corpus = cases();
    let covered: BTreeSet<String> = corpus
        .iter()
        .flat_map(|case| case.covers.iter().cloned())
        .collect();
    assert!(
        covered.contains("KR-REQ-07.87"),
        "no case covers the plugin-stack qualification"
    );
    assert!(
        covered.contains("KR-REQ-07.85"),
        "no case covers the managed baselines"
    );
}
