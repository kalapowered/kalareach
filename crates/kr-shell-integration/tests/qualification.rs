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

use kr_protocol::root::{
    DETACH_HINT, FENCE_EXCHANGE_TIMEOUT, FenceCause, LaunchCommand, RootEditorFenceParams,
    RootEditorFenceResult,
};
use kr_shell_integration::contract::events::{BridgeEvent, ConsumeReason, EofGesture};
use kr_shell_integration::contract::qualification::{BridgeAbi, DetachExclusion, ShellKind};
use kr_shell_integration::contract::requests::{
    BridgeAnswer, CancelKeyWait, LaunchDecision, LaunchMailboxRequest, LaunchRejectionReason,
    LaunchTransactionId, WorkerRequest,
};

use shellpkg::{
    CaseOutcome, CaseSetup, DriveObservation, Package, QualificationCase, Session, StackIndex,
    StackLock, cases, corpus_root, record_outcomes, repository_root, settle, unsupported,
};

/// The environment variable that turns an unfetched stack into a failure rather than a skip.
const REQUIRE_STACKS: &str = "KR_REQUIRE_SHELL_STACKS";

/// Every check a case may claim. A name outside this set is a corpus that says something this
/// runner does not do, which is worse than a check that fails.
/// They run in this order whatever order a case lists them in: a probe that runs a command ends
/// the prompt the checks before it were asked at.
const KNOWN_CHECKS: &[&str] = &[
    "identity",
    "profile_order",
    "profile_once",
    "native_module",
    "plugin_active",
    "plugin_writes_buffer",
    "plugin_buffer",
    "user_bindings",
    "gesture_detaches",
    "gesture_is_native_outside_the_condition",
    "every_exclusion_accounted_for",
    "escape_then_gesture_is_native",
    "unattributable_gesture_hints",
    "gesture_follows_the_line_discipline",
    "takeover_under_the_stack",
    "launch_deadline_installs_nothing",
    "instant_prompt",
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
        if case.supported {
            for required in [
                "identity",
                "profile_order",
                "user_bindings",
                "gesture_detaches",
            ] {
                assert!(
                    case.checks.iter().any(|check| check == required),
                    "{} is a supported combination and does not claim {required}",
                    case.id
                );
            }
            // A case that names the plugin-stack row has to be about a customisation: one the
            // pinned set carries, an ordinary distribution one, or a native module.
            if case.covers.iter().any(|row| row == "KR-REQ-07.87") {
                assert!(
                    !case.requires.is_empty()
                        || ["distribution", "native-module"].contains(&case.stack.as_str()),
                    "{} claims the plugin-stack row and installs no customisation",
                    case.id
                );
            }
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
                entry.reason.split_whitespace().count() >= 8,
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
            // A case recorded as unsupported is not coverage: it would let a stack be taken out
            // of the qualification by marking it unsupported and still satisfy the rule that says
            // the stack is covered.
            let driven = corpus.iter().any(|case| {
                case.shell == *shell && case.supported && case.requires.contains(&pinned.id)
            });
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
                .any(|case| case.supported && case.requires.iter().any(|id| id == named)),
            "no case drives {named}"
        );
    }
    assert!(
        corpus
            .iter()
            .any(|case| case.supported && case.stack == "distribution"),
        "no case drives an ordinary distribution startup customisation"
    );
    // A case that says a customisation is loaded has to ask the shell, or it proves only that a
    // startup file ran.
    for case in &corpus {
        assert_eq!(
            case.supported && !case.requires.is_empty(),
            case.plugin.is_some(),
            "{} installs a customisation and asks the shell nothing about it, or the other way \
             round",
            case.id
        );
        if let Some(plugin) = case.plugin.as_ref() {
            assert_eq!(
                plugin.operation.is_some(),
                plugin.operation_marker.is_some(),
                "{} gives the customisation something to do and does not say what it should \
                 print, or the other way round",
                case.id
            );
        }
        assert_eq!(
            case.checks.contains(&"plugin_active".to_owned()),
            case.plugin.is_some(),
            "{} claims a customisation is active and asks the shell nothing, or the other way \
             round",
            case.id
        );
        // The whole invoking sequence being the gesture is a rule of the two patched readers
        // that have an escape prefix and a setting of the person's own for the native answer.
        assert_eq!(
            case.checks
                .contains(&"escape_then_gesture_is_native".to_owned()),
            case.supported && shellpkg::dialect(case.shell).ignore_eof_on.is_some(),
            "{} claims the escape rule for a reader that has no such prefix or no setting to \
             make the native answer observable, or the other way round",
            case.id
        );
        for skipped in &case.skip_exclusions {
            assert!(
                DetachExclusion::ALL
                    .iter()
                    .any(|exclusion| exclusion.as_str() == skipped),
                "{} skips {skipped}, which is not one of the excluded states",
                case.id
            );
        }
        assert!(
            !case.checks.contains(&"takeover_under_the_stack".to_owned())
                || shellpkg::pending_wait(case.shell).is_some(),
            "{} claims a takeover for a reader this session cannot leave inside a key wait",
            case.id
        );
        if case.checks.contains(&"instant_prompt".to_owned()) {
            assert!(
                case.warm_order.is_some(),
                "{} drives a second start and does not say what it should record",
                case.id
            );
        }
    }
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
        "the installed stacks were fetched from another pinned set; run \
         scripts/fetch-shell-stacks.sh"
    );
    assert_eq!(
        index.platform,
        host_platform(),
        "the installed stacks were fetched for another platform"
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
                pinned.sources.iter().any(|source| source.sha256 == digest
                    && (source.platform == "any" || source.platform == index.platform)),
                "{} was installed from an archive this set does not pin for {}",
                stack.id,
                index.platform
            );
            let root = std::path::PathBuf::from(
                stack
                    .root
                    .as_deref()
                    .expect("an installed stack has a root"),
            );
            if let Some(entry) = pinned.entry.as_deref() {
                assert!(
                    root.join(entry).is_file(),
                    "{} is recorded as installed and {entry} is not in its tree",
                    stack.id
                );
            }
            if let Some(program) = pinned.program.as_deref() {
                assert!(
                    root.join(program).is_file(),
                    "{} is recorded as installed and holds no {program}",
                    stack.id
                );
            }
            // The archive's digest says which bytes were unpacked here. This says that what was
            // unpacked is still what is there: the fetcher takes it over every path in the tree
            // when it unpacks, and checks it against the tree on every run afterwards, so a run
            // that unpacked nothing has still read what it is about to qualify against.
            let recorded = stack.tree_sha256.as_deref().unwrap_or_else(|| {
                panic!(
                    "{} is recorded as installed with no digest of its tree; run \
                     scripts/fetch-shell-stacks.sh",
                    stack.id
                )
            });
            let taken = std::fs::read_to_string(format!("{}.tree", root.display())).unwrap_or_else(
                |error| {
                    panic!(
                        "{} kept no digest of the tree it unpacked: {error}",
                        stack.id
                    )
                },
            );
            assert_eq!(
                recorded,
                taken.trim(),
                "{} is recorded under a digest that is not the one beside its tree",
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

    // One case at a time, for a run that is looking at one of them.
    let only = std::env::var("KR_QUALIFICATION_CASE").ok();
    for case in &corpus {
        if only.as_deref().is_some_and(|wanted| wanted != case.id) {
            continue;
        }
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
    // An ordinary workspace run has neither the packages nor the stacks: this suite says so and
    // stops. A run that asked for them is the one that fails when nothing ran.
    if std::env::var_os(shellpkg::REQUIRE).is_some() || std::env::var_os(REQUIRE_STACKS).is_some() {
        assert!(
            ran > 0,
            "the packages or the stacks were required and no case ran"
        );
    } else if ran == 0 && only.is_none() {
        println!(
            "skipped: no package is built here and no stack is fetched here; run \
             scripts/build-shells.sh --all and scripts/fetch-shell-stacks.sh"
        );
    }
}

/// The platform triple the fetcher records, for the host this run is on.
fn host_platform() -> String {
    let architecture = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "unknown"
    };
    let system = if cfg!(target_os = "macos") {
        "apple-darwin"
    } else if cfg!(target_os = "linux") {
        "unknown-linux-gnu"
    } else {
        "unknown"
    };
    format!("{architecture}-{system}")
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

/// Drives one case through the checks it claims, a fresh shell for each group of them.
///
/// A group is a set of checks that can share one reader without one of them deciding what the
/// next one sees. Driving an excluded state leaves the editor somewhere — inside a listing, a
/// search, a pending sequence — and a check that started from there would be measuring the drive
/// before it rather than the package. A shell costs a second to start; a check that measured the
/// wrong thing costs a qualification that says nothing.
fn run_case(case: &QualificationCase, package: &Package) {
    let index = StackIndex::read().expect("the index was read before this case was chosen");
    let setup = CaseSetup::prepare(case, package, &index);
    let claimed = |name: &str| case.checks.iter().any(|check| check == name);

    the_startup_and_the_customisation(case, package, &setup);

    if claimed("gesture_detaches") || claimed("unattributable_gesture_hints") {
        let mut session = fresh(case, package, &setup);
        if claimed("gesture_detaches") {
            the_gesture_detaches_at_an_eligible_prompt(case, &mut session);
        }
        if claimed("unattributable_gesture_hints") {
            an_unattributable_gesture_is_consumed_with_one_hint(case, &mut session);
        }
    }

    if claimed("gesture_is_native_outside_the_condition") {
        let mut session = fresh(case, package, &setup);
        outside_the_condition_the_editor_keeps_the_key(
            case,
            package,
            &setup,
            &mut session,
            claimed("every_exclusion_accounted_for"),
        );
    }

    if claimed("escape_then_gesture_is_native") {
        let mut session = fresh(case, package, &setup);
        the_whole_invoking_sequence_is_the_gesture(case, &mut session);
    }

    if claimed("gesture_follows_the_line_discipline") {
        let mut session = fresh(case, package, &setup);
        the_gesture_follows_the_terminals_own_character(case, &mut session);
    }

    if claimed("takeover_under_the_stack") {
        let mut session = fresh(case, package, &setup);
        a_takeover_ends_a_wait_the_customisation_left_the_reader_in(case, &mut session);
    }

    if claimed("launch_deadline_installs_nothing") {
        let mut session = fresh(case, package, &setup);
        a_launch_past_its_reader_budget_installs_nothing(case, &mut session);
    }

    if claimed("instant_prompt") {
        a_second_start_draws_from_the_cache_the_first_wrote(case, package, &setup);
    }
}

/// A shell of this case's own, at its first prompt and reading.
fn fresh(case: &QualificationCase, package: &Package, setup: &CaseSetup) -> Session {
    setup.forget_order();
    let mut session = Session::start_for(package, case, setup);
    session.first_prompt_within(STARTUP);
    settle(&mut session, Duration::from_millis(300), REPLY);
    session.ensure_reading();
    session
}

/// What the startup files did, and what the customisation does to the line the reader holds.
fn the_startup_and_the_customisation(
    case: &QualificationCase,
    package: &Package,
    setup: &CaseSetup,
) {
    let claimed = |name: &str| case.checks.iter().any(|check| check == name);
    let mut session = Session::start_for(package, case, setup);
    let mut enter = session.first_prompt_within(STARTUP);
    // Several of these prompts are drawn by a program that runs at every prompt, so the reader is
    // given until its drawing stops before anything is typed at it.
    settle(&mut session, Duration::from_millis(300), REPLY);
    session.ensure_reading();

    if claimed("identity") {
        the_package_is_the_one_the_record_names(case, &session, package);
    }

    if claimed("profile_order") {
        let recorded = setup.recorded_order();
        assert_eq!(
            recorded,
            case.order,
            "{} ran its startup in another order; the terminal showed:\n{}",
            case.id,
            session.terminal_output()
        );
    }

    if claimed("profile_once") {
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

    if claimed("native_module") {
        the_module_this_build_cannot_load_is_diagnosed(case, &mut session, setup, &enter);
    }

    if claimed("plugin_active") {
        let probe = case
            .plugin
            .as_ref()
            .expect("the corpus check refused a case without one");
        if let Err(reason) = session.plugin_is_active(probe) {
            panic!(
                "{}: the customisation this case is about did not answer: {reason}; the terminal \
                 showed:\n{}",
                case.id,
                session.terminal_output()
            );
        }
        enter = session.next_prompt();
        settle(&mut session, Duration::from_millis(300), REPLY);
        session.ensure_reading();
    }

    if claimed("plugin_writes_buffer") {
        enter = plugin_writes_the_buffer(case, &mut session);
    }

    if claimed("plugin_buffer") {
        // A customisation that rewrites the line on every keystroke is exactly what section 7
        // says a prompt hook cannot tell from an empty prompt. The reader's own answer is what
        // the fence carries, so it is asked with the line held and again once it is cleared,
        // under the same customisation.
        session.ensure_reading();
        session.type_bytes(b"k");
        settle(&mut session, Duration::from_millis(200), REPLY);
        let held = session.fence_exchange(&enter, shellpkg::fence_id(1));
        assert!(
            !held.editor.buffer_empty,
            "{}: a line the customisation had drawn over was reported as an empty prompt",
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

    if claimed("user_bindings") {
        session.ensure_reading();
        if let Err(reason) = session.user_binding_ran() {
            panic!(
                "{}: {reason}, so the person's own binding {} is not qualified here; the \
                 terminal showed:\n{}",
                case.id,
                case.binding,
                session.terminal_output()
            );
        }
        session.clear_line();
    }

    assert!(
        session.alive(),
        "{}: the shell did not survive its own startup",
        case.id
    );
}

/// The declaration against the identity record the build wrote beside the binary.
fn the_package_is_the_one_the_record_names(
    case: &QualificationCase,
    session: &Session,
    package: &Package,
) {
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
    // The handshake this harness answers takes the hello's own editor ABI as supported, so the
    // record beside the binary is what makes this an identity rather than a declaration about
    // itself.
    let record = &package.record["shell"];
    for (field, declared) in [
        ("executable", session.hello.shell.executable.clone()),
        ("editor_abi", session.hello.shell.editor_abi.clone()),
        (
            "integration_version",
            session.hello.shell.integration_version.clone(),
        ),
        (
            "upstream_version",
            session.hello.shell.upstream_version.clone(),
        ),
    ] {
        let recorded = record[field]
            .as_str()
            .unwrap_or_else(|| panic!("{} has no {field} in its identity record", case.id));
        assert_eq!(
            declared, recorded,
            "{} declared a {field} the installed package does not record",
            case.id
        );
    }
    // Every field of every patch and every module, not the names alone: a patch whose revision
    // moved, or a module whose search path did, is another package.
    let declared: Vec<(String, String, String)> = session
        .hello
        .shell
        .patches
        .iter()
        .map(|patch| {
            (
                patch.name.clone(),
                patch.revision.clone(),
                patch.upstream_revision.clone(),
            )
        })
        .collect();
    let recorded: Vec<(String, String, String)> = record["patches"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .map(|patch| {
                    (
                        patch["name"].as_str().unwrap_or_default().to_owned(),
                        patch["revision"].as_str().unwrap_or_default().to_owned(),
                        patch["upstream_revision"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        declared, recorded,
        "{} declared patches the installed package does not record",
        case.id
    );
    let modules: Vec<(String, String, String)> = session
        .hello
        .shell
        .modules
        .iter()
        .map(|module| {
            (
                module.name.clone(),
                module.search_path.clone(),
                module.editor_abi.clone(),
            )
        })
        .collect();
    let recorded: Vec<(String, String, String)> = record["modules"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .map(|module| {
                    (
                        module["name"].as_str().unwrap_or_default().to_owned(),
                        module["search_path"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                        module["editor_abi"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        modules.len(),
        recorded.len(),
        "{} declared a module tree of another size than the installed package records",
        case.id
    );
    for (declared, recorded) in modules.iter().zip(recorded.iter()) {
        assert_eq!(
            (&declared.0, &declared.2),
            (&recorded.0, &recorded.2),
            "{} declared a module the installed package does not record",
            case.id
        );
        // One package records where the shell searches and the module declares where it is, and
        // the two are the same tree read from different ends. A module that moved out of the
        // recorded tree fails here; which end of it a package names does not.
        let declared_path = std::path::Path::new(&declared.1);
        let recorded_path = std::path::Path::new(&recorded.1);
        assert!(
            !declared.1.is_empty()
                && (declared_path.starts_with(recorded_path)
                    || recorded_path.starts_with(declared_path)),
            "{}: {} is declared at {} and recorded under {}",
            case.id,
            declared.0,
            declared.1,
            recorded.1
        );
    }
}

/// A module this build cannot load, diagnosed rather than loaded silently.
fn the_module_this_build_cannot_load_is_diagnosed(
    case: &QualificationCase,
    session: &mut Session,
    setup: &CaseSetup,
    enter: &kr_protocol::root::RootEditorEnterParams,
) {
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
    assert!(
        recorded.iter().any(|line| line == "kr-module-absent"),
        "{}: {} is in the shell's own list of loaded modules",
        case.id,
        module.name
    );
    let diagnosis = std::fs::read_to_string(setup.home.join("module-error")).unwrap_or_default();
    assert!(
        diagnosis.contains(&module.name),
        "{}: what was said about {} does not name it: {diagnosis:?}",
        case.id,
        module.name
    );
    // The integration is what it was before: the reader is there and answers.
    let acknowledgement = session.fence_exchange(enter, shellpkg::fence_id(3));
    assert_eq!(acknowledgement.prompt_generation, enter.prompt_generation);
}

/// A character at the end of a longer sequence is part of that sequence, so the editor keeps it.
fn the_whole_invoking_sequence_is_the_gesture(case: &QualificationCase, session: &mut Session) {
    // The person's own end-of-file setting is what makes the editor's own answer observable
    // without ending the session, and it is left exactly as they set it.
    let speech = shellpkg::dialect(case.shell);
    let ready = speech
        .ignore_eof_on
        .expect("the corpus check refused this claim for a shell with no such setting");
    assert!(
        session.run(ready, "kr-ready"),
        "{}: the shell did not answer before the sequence was driven",
        case.id
    );
    let _ = session.fenced_after_a_command(16);
    settle(session, Duration::from_millis(200), REPLY);
    session.ensure_reading();
    session.type_bytes(shellpkg::ESCAPE);
    std::thread::sleep(Duration::from_millis(120));
    session.type_bytes(shellpkg::CTRL_D);
    assert!(
        !session.saw_event(Duration::from_millis(600), |event| matches!(
            event,
            BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
        )),
        "{}: a gesture at the end of a longer sequence was taken as a detach",
        case.id
    );
    assert!(
        session.alive(),
        "{}: a gesture at the end of a longer sequence ended the shell",
        case.id
    );
}

/// An eligible gesture at a fenced empty primary prompt is an attributable detach.
///
/// The customisation the case installs is live while this runs, which is the point: a plugin that
/// wrapped the reader's widgets, redrew the line or bound the key itself would take the gesture
/// somewhere else, and the decision section 7 asks for is made before any of that.
fn the_gesture_detaches_at_an_eligible_prompt(
    case: &QualificationCase,
    session: &mut Session,
) -> kr_protocol::root::RootEditorEnterParams {
    let (enter, fence) = session.fenced_after_a_command(11);
    settle(session, Duration::from_millis(200), REPLY);
    // The command this fence follows ended a prompt, and the gesture belongs to the reader at the
    // one after it: it is offered once that reader has said it is inside its read.
    session.ensure_reading();
    session.type_bytes(shellpkg::CTRL_D);

    let (id, event) = session.expect_event("eof_detach", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    let BridgeEvent::EofDetach(detach) = event else {
        unreachable!()
    };
    assert_eq!(detach.fence_id, fence.fence_id, "{}", case.id);
    assert_eq!(
        detach.prompt_generation, enter.prompt_generation,
        "{}",
        case.id
    );
    assert_eq!(detach.input_epoch, fence.input_epoch, "{}", case.id);
    session.answer_event(id, shellpkg::detached(shellpkg::attachment_id(1)));
    assert!(
        !session.saw_event(Duration::from_millis(400), |event| matches!(
            event,
            BridgeEvent::PreEofConsumed(_)
        )),
        "{}: an attributable gesture was consumed rather than submitted",
        case.id
    );
    assert!(
        session.alive(),
        "{}: the gesture ended the shell instead of detaching an attachment",
        case.id
    );

    // After a detach the bridge drops its fence, so a repeated gesture cannot take on the next
    // attachment's identity. The reader that reported the detach reported it from inside its own
    // read, and nothing since has taken it out of one, so this key needs no probe of its own.
    session.type_bytes(shellpkg::CTRL_D);
    let (_, repeated) = session.expect_event("pre_eof_consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(repeated) = repeated else {
        unreachable!()
    };
    assert_eq!(repeated.reason, ConsumeReason::FenceMissing, "{}", case.id);
    assert!(session.alive(), "{}", case.id);
    enter
}

/// Every state section 7 excludes, driven where this reader has it and recorded where it does not.
fn outside_the_condition_the_editor_keeps_the_key(
    case: &QualificationCase,
    package: &Package,
    setup: &CaseSetup,
    session: &mut Session,
    exhaustive: bool,
) {
    let speech = shellpkg::dialect(case.shell);
    // Outside the condition the key is the editor's own, and at an empty prompt the editor's own
    // answer can be to end the shell. Where the shell has a setting of its own for that, the
    // person's setting is what makes the answer observable without ending this session.
    session.clear_line();
    session.forget_events();
    assert!(
        match speech.ignore_eof_on {
            Some(ready) => session.run(ready, "kr-ready"),
            None => session.answered("kr-ready"),
        },
        "{}: the shell did not answer before the exclusions were driven",
        case.id
    );
    let (_entered, _fence) = session.fenced_prompt(12);
    settle(session, Duration::from_millis(200), REPLY);

    let mut seen: Vec<DriveObservation> = Vec::new();
    let mut skipped = Vec::new();
    for drive in shellpkg::exclusion_drives(case.shell) {
        if case
            .skip_exclusions
            .iter()
            .any(|named| named == drive.exclusion.as_str())
        {
            // The customisation this case installs takes the key this state is reached through,
            // so what the key reaches is its own reader rather than the managed one.
            skipped.push(drive.exclusion);
            continue;
        }
        if let Some((command, marker)) = drive.prepare {
            assert!(
                session.run(command, marker),
                "{}: {} could not be prepared",
                case.id,
                drive.exclusion.as_str()
            );
            std::thread::sleep(Duration::from_millis(200));
            session.forget_events();
        }
        // The state this drive puts the reader into is reached by the keys below, so they are
        // offered to a reader that has said it is inside its read: keys the terminal holds instead
        // reach the editor as a line, and the state they are for is never entered.
        session.ensure_reading();
        for bytes in drive.setup {
            session.type_bytes(bytes);
            std::thread::sleep(Duration::from_millis(80));
        }
        session.type_bytes(shellpkg::CTRL_D);
        assert!(
            !session.saw_event(Duration::from_millis(500), |event| matches!(
                event,
                BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
            )),
            "{}: {} did not exclude the gesture; the terminal showed:\n{}",
            case.id,
            drive.exclusion.as_str(),
            session.terminal_output()
        );
        for bytes in drive.teardown {
            session.type_bytes(bytes);
            std::thread::sleep(Duration::from_millis(80));
        }
        session.clear_line();
        assert!(
            session.alive(),
            "{}: {} ended the shell",
            case.id,
            drive.exclusion.as_str()
        );
        seen.push(DriveObservation {
            exclusion: drive.exclusion,
            before: format!(
                "the reader said it was inside its read, and {} of its own {} typed at it",
                drive.setup.len(),
                if drive.setup.len() == 1 {
                    "key was"
                } else {
                    "keys were"
                }
            ),
            after: "neither managed event in 500 ms, and the shell was still running".to_owned(),
        });
    }

    if exhaustive {
        seen.extend(the_states_that_need_a_command_first(case, package, setup));
    }
    let driven: Vec<DetachExclusion> = seen.iter().map(|drive| drive.exclusion).collect();

    // What is not driven here is recorded with its reason rather than left out, so nothing is
    // quietly absent from the qualification.
    let mut accounted: Vec<String> = shellpkg::exclusions_accounted_for(case.shell)
        .into_iter()
        .map(|(exclusion, reason)| format!("{}: {reason}", exclusion.as_str()))
        .collect();
    for exclusion in DetachExclusion::ALL {
        if let Some(reason) = shellpkg::not_driven_by_the_qualification(case.shell, *exclusion) {
            accounted.push(format!("{}: {reason}", exclusion.as_str()));
        }
    }
    if exhaustive {
        for exclusion in DetachExclusion::ALL
            .iter()
            .copied()
            .chain(std::iter::once(DetachExclusion::NotManagedRootEditor))
        {
            assert!(
                driven.contains(&exclusion)
                    || skipped.contains(&exclusion)
                    || shellpkg::not_constructible_here(case.shell, exclusion).is_some()
                    || shellpkg::not_driven_by_the_qualification(case.shell, exclusion).is_some(),
                "{}: {} is neither driven here nor recorded as one this reader cannot be put \
                 into",
                case.id,
                exclusion.as_str()
            );
        }
    }
    // Every line of this record is something a drive read off the reader or watched the shell do.
    // Nothing is added beside them.
    shellpkg::record(
        &format!("exclusions-{}.txt", case.id),
        &format!(
            "skipped, the customisation takes the key: {}\ndriven and observed:\n{}\naccounted \
             for: {}\n",
            skipped
                .iter()
                .map(|exclusion| exclusion.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            seen.iter()
                .map(|drive| format!("  {}", drive.line()))
                .collect::<Vec<_>>()
                .join("\n"),
            accounted.join("; ")
        ),
    );
}

/// The excluded states that need a command run first: a continuation reader, the shell's own
/// `read` through the editor, a vi motion waiting for its target, and a macro being replayed.
///
/// Each is a state the reader is in rather than a key it is holding, so each needs the shell told
/// something first. Each also gets a shell of its own. A drive that ran in a shell another drive
/// had already used would be measuring what that one left behind: a gesture offered in a
/// continuation reader leaves one of these shells part way through a command it could not parse, a
/// macro binding stays bound, and a keymap the drive changed is the keymap the next one starts in.
/// A shell costs a second to start, and a drive that starts its own says what it proves.
fn the_states_that_need_a_command_first(
    case: &QualificationCase,
    package: &Package,
    setup: &CaseSetup,
) -> Vec<DriveObservation> {
    let speech = shellpkg::dialect(case.shell);
    let mut seen = Vec::new();

    if let Some((open, _)) = speech.continuation {
        seen.push(a_continuation_reader_keeps_the_key(
            case, package, setup, open,
        ));
    }
    if let Some(command) = shellpkg::read_builtin_command(case.shell) {
        seen.push(the_read_builtin_keeps_the_key(
            case, package, setup, command,
        ));
    }
    if let Some(command) = shellpkg::macro_binding(case.shell) {
        seen.push(a_replayed_character_never_reaches_the_decision(
            case, package, setup, command,
        ));
    }
    if let Some((vi_mode, _)) = shellpkg::vi_keymap_commands(case.shell) {
        seen.push(a_vi_motion_keeps_the_key(case, package, setup, vi_mode));
    }
    seen
}

/// The gesture offered to a reader that is reading the rest of an unfinished command.
fn a_continuation_reader_keeps_the_key(
    case: &QualificationCase,
    package: &Package,
    setup: &CaseSetup,
    open: &str,
) -> DriveObservation {
    let mut session = fresh(case, package, setup);
    session.forget_events();
    session.type_line(open);
    let (_, event) = session.expect_event("a continuation reader", |event| {
        matches!(
            event,
            BridgeEvent::EditorEnter(params)
                if params.reader_context == kr_protocol::root::ReaderContext::Continuation
        )
    });
    let BridgeEvent::EditorEnter(entered) = event else {
        unreachable!("the predicate accepted an entry")
    };
    let before = format!(
        "the reader that entered was a {} reader at prompt {} revision {}",
        entered.reader_context.as_str(),
        entered.prompt_generation.get(),
        entered.reader_revision.get()
    );
    session.type_bytes(shellpkg::CTRL_D);
    assert!(
        !session.saw_event(Duration::from_millis(600), |event| matches!(
            event,
            BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
        )),
        "{}: a gesture in a continuation reader reached the managed decision; the terminal \
         showed:\n{}",
        case.id,
        session.terminal_output()
    );
    assert!(
        session.alive(),
        "{}: a continuation gesture ended the shell",
        case.id
    );
    DriveObservation {
        exclusion: DetachExclusion::ContinuationInput,
        before,
        after: "neither managed event in 600 ms, and the shell was still running".to_owned(),
    }
}

/// The gesture offered to the shell's own `read`, reading through the same editor.
fn the_read_builtin_keeps_the_key(
    case: &QualificationCase,
    package: &Package,
    setup: &CaseSetup,
    command: &str,
) -> DriveObservation {
    let mut session = fresh(case, package, setup);
    session.forget_events();
    session.type_line(command);
    // The reader this gesture is for is the builtin's own, and its entry report is written from
    // inside it: waiting for that report is what says the gesture is being offered to that reader
    // rather than to the terminal, which would answer the key itself.
    let (_, event) = session.expect_event("the read builtin's own reader", |event| {
        matches!(
            event,
            BridgeEvent::EditorEnter(params)
                if params.reader_context == kr_protocol::root::ReaderContext::ReadBuiltin
        )
    });
    let BridgeEvent::EditorEnter(entered) = event else {
        unreachable!("the predicate accepted an entry")
    };
    let before = format!(
        "the reader that entered was a {} reader at prompt {} revision {}",
        entered.reader_context.as_str(),
        entered.prompt_generation.get(),
        entered.reader_revision.get()
    );
    session.type_bytes(shellpkg::CTRL_D);
    assert!(
        !session.saw_event(Duration::from_millis(600), |event| matches!(
            event,
            BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
        )),
        "{}: a gesture inside the read builtin reached the managed decision; the terminal \
         showed:\n{}",
        case.id,
        session.terminal_output()
    );
    assert!(
        session.alive(),
        "{}: the read builtin's gesture ended the shell",
        case.id
    );
    DriveObservation {
        exclusion: DetachExclusion::ReadBuiltin,
        before,
        after: "neither managed event in 600 ms, and the shell was still running".to_owned(),
    }
}

/// A character the reader replayed out of a macro is the editor's own, not the person's gesture.
///
/// Two offers at one prompt, with one difference between them. The first character arrives from
/// the reader's own replay, and the managed decision is never reached: what happens to it is
/// whatever this editor's own binding does with it, which is either the shell's own end of file or
/// the reader carrying on. The second is typed at that same empty prompt, and there the managed
/// decision is reached. One prompt, one buffer, one key, and the only thing that differs is where
/// the character came from.
fn a_replayed_character_never_reaches_the_decision(
    case: &QualificationCase,
    package: &Package,
    setup: &CaseSetup,
    command: &str,
) -> DriveObservation {
    let mut session = fresh(case, package, setup);
    assert!(
        session.run(command, "kr-macro-bound"),
        "{}: the macro could not be bound",
        case.id
    );
    let entered = session.latest_prompt();
    settle(&mut session, Duration::from_millis(200), REPLY);
    session.ensure_reading();
    session.forget_events();
    let held = session.fence_exchange(&entered, shellpkg::fence_id(21));
    assert!(
        held.editor.buffer_empty && held.editor.pending.is_idle(),
        "{}: the macro drive started at a prompt that was not empty and idle: {:?} {:?}",
        case.id,
        held.editor,
        held.snapshot
    );
    let before = format!(
        "prompt {} revision {}, keymap {}, buffer empty, nothing pending",
        entered.prompt_generation.get(),
        entered.reader_revision.get(),
        held.editor.keymap.as_str()
    );
    session.forget_events();

    session.type_bytes(shellpkg::CTRL_T);
    // Neither managed answer is right here. A detach would take the macro's character for the
    // person's gesture, and a consume would take it for one this reader could not attribute: the
    // character came from the reader's own replay, so the decision is never the worker's at all.
    assert!(
        !session.saw_event(Duration::from_millis(600), |event| matches!(
            event,
            BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
        )),
        "{}: a character a macro replayed reached the managed decision; the terminal showed:\n{}",
        case.id,
        session.terminal_output()
    );

    let after = if session.ended_within(Duration::from_secs(2)) {
        // The editor's own binding for that character at an empty prompt is this shell's end of
        // file, and the shell took it. That is the native answer, and nothing else could have
        // produced it: the managed decision was never reached.
        "the shell ended, which is this editor's own answer to that key at an empty prompt"
            .to_owned()
    } else {
        // This case's own binding answers the key without ending the shell, so the native answer
        // is proved the other way round: the same key typed at the same empty prompt does reach
        // the managed decision, and the only difference between the two is where it came from.
        session.forget_events();
        session.ensure_reading();
        session.type_bytes(shellpkg::CTRL_D);
        let (_, reached) = session.expect_event("the managed decision", |event| {
            matches!(
                event,
                BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
            )
        });
        format!(
            "the reader carried on, and the same key typed at that prompt reached the managed \
             decision as {}",
            shellpkg::name_of_event(&reached)
        )
    };
    DriveObservation {
        exclusion: DetachExclusion::MacroInput,
        before,
        after,
    }
}

/// The gesture offered to a vi motion that is waiting for the text it is to act on.
///
/// The keymap and the wait are both read out of the reader's own reports rather than assumed from
/// the keys that were typed: a setup that went wrong would otherwise pass through some other
/// exclusion and record this one as proved. Where a package reports no wait of its own, the drive
/// says so in its record instead of claiming one.
fn a_vi_motion_keeps_the_key(
    case: &QualificationCase,
    package: &Package,
    setup: &CaseSetup,
    vi_mode: &str,
) -> DriveObservation {
    let mut session = fresh(case, package, setup);
    assert!(
        session.run(vi_mode, "kr-vi-on"),
        "{}: the editor did not take vi bindings",
        case.id
    );
    let _ = session.latest_prompt();
    settle(&mut session, Duration::from_millis(300), REPLY);
    session.ensure_reading();

    session.forget_events();
    session.type_bytes(shellpkg::ESCAPE);
    let commanding = session
        .reader_said(REPLY)
        .unwrap_or_else(|| panic!("{}: the reader said nothing after the keymap key", case.id));
    assert_eq!(
        commanding.editor.keymap,
        kr_protocol::root::EditorKeymap::ViCommand,
        "{}: the reader is not in its command keymap, so what follows is not a vi motion",
        case.id
    );

    session.forget_events();
    session.type_bytes(b"d");
    let waiting = session.reader_said(REPLY).unwrap_or_else(|| {
        panic!(
            "{}: the reader said nothing after the operator key",
            case.id
        )
    });
    let pending = waiting.editor.pending.vi_motion;
    let before = format!(
        "keymap {} at prompt {} revision {}, and the reader {}",
        waiting.editor.keymap.as_str(),
        waiting.prompt_generation.get(),
        waiting.editor.buffer_revision.get(),
        if pending {
            "reported a vi motion waiting for its target"
        } else {
            "reported no wait of its own, so this drive claims the keymap and nothing more"
        }
    );

    session.type_bytes(shellpkg::CTRL_D);
    assert!(
        !session.saw_event(Duration::from_millis(600), |event| matches!(
            event,
            BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
        )),
        "{}: a gesture in the vi command keymap reached the managed decision; the terminal \
         showed:\n{}",
        case.id,
        session.terminal_output()
    );
    assert!(
        session.alive(),
        "{}: a vi motion's gesture ended the shell",
        case.id
    );
    DriveObservation {
        exclusion: DetachExclusion::ViMotion,
        before,
        after: "neither managed event in 600 ms, and the shell was still running".to_owned(),
    }
}

/// A gesture no fence can attribute is consumed, with one short hint per prompt.
fn an_unattributable_gesture_is_consumed_with_one_hint(
    case: &QualificationCase,
    session: &mut Session,
) {
    session.recover();
    session.forget_events();
    assert!(
        session.answered("kr-hint-ready"),
        "{}: the shell did not reach a prompt with no fence",
        case.id
    );
    let enter = session.next_prompt();
    settle(session, Duration::from_millis(200), REPLY);
    session.forget_events();

    session.ensure_reading();
    session.type_bytes(shellpkg::CTRL_D);
    let (_, first) = session.expect_event("pre_eof_consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(first) = first else {
        unreachable!()
    };
    assert!(
        matches!(
            first.reason,
            ConsumeReason::FenceMissing | ConsumeReason::FenceStale
        ),
        "{}: a gesture no fence can attribute was consumed for {:?}",
        case.id,
        first.reason
    );
    assert!(first.hint_printed, "{}", case.id);
    assert_eq!(
        first.prompt_generation, enter.prompt_generation,
        "{}",
        case.id
    );
    assert!(
        session.wait_for_output(DETACH_HINT, REPLY),
        "{}: the hint was not printed; the terminal showed:\n{}",
        case.id,
        session.terminal_output()
    );
    let after_first = session.terminal_output().matches(DETACH_HINT).count();

    session.type_bytes(shellpkg::CTRL_D);
    let (_, second) = session.expect_event("a second pre_eof_consumed", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(second) = second else {
        unreachable!()
    };
    // The reader answered the first gesture from inside its own read, and the second is offered
    // at that same read, so nothing needs to be established again between them.
    assert!(
        !second.hint_printed,
        "{}: the hint is printed at most once per prompt",
        case.id
    );
    assert_eq!(
        session.terminal_output().matches(DETACH_HINT).count(),
        after_first,
        "{}: a second gesture at one prompt printed the hint again",
        case.id
    );
    assert!(session.alive(), "{}", case.id);

    // A fence from an earlier prompt is as stale as none at all.
    let stale = shellpkg::fence_for(
        &enter,
        shellpkg::fence_id(13),
        shellpkg::attachment_id(2),
        shellpkg::epoch(6),
    );
    session.publish(&stale);
    assert!(
        session.answered("kr-stale-ready"),
        "{}: the shell did not reach the next prompt",
        case.id
    );
    let _ = session.next_prompt();
    settle(session, Duration::from_millis(200), REPLY);
    session.ensure_reading();
    session.type_bytes(shellpkg::CTRL_D);
    let (_, third) = session.expect_event("a stale-fence consume", |event| {
        matches!(event, BridgeEvent::PreEofConsumed(_))
    });
    let BridgeEvent::PreEofConsumed(third) = third else {
        unreachable!()
    };
    assert_eq!(third.reason, ConsumeReason::FenceStale, "{}", case.id);
    assert!(
        third.hint_printed,
        "{}: a new prompt prints the hint again",
        case.id
    );
}

/// The gesture moves with the terminal's own end-of-file character, at the next prompt.
///
/// One of these readers holds the terminal in the shell's own modes and refreshes them from the
/// terminal after every command, which is where a `stty eof` of the person's own lands. A command
/// is run between the change and the gesture for exactly that reason.
fn the_gesture_follows_the_terminals_own_character(
    case: &QualificationCase,
    session: &mut Session,
) {
    let speech = shellpkg::dialect(case.shell);
    let (Some(change), Some(disable)) = (speech.veof_change, speech.veof_disable) else {
        panic!(
            "{}: this case claims a gesture change its shell cannot be told to make",
            case.id
        );
    };
    session.forget_events();
    assert!(
        session.run(change, "kr-veof-set"),
        "{}: the terminal's end-of-file character was not changed",
        case.id
    );
    let (_, changed) = session.expect_event("gesture_changed", |event| {
        matches!(event, BridgeEvent::GestureChanged(_))
    });
    let BridgeEvent::GestureChanged(changed) = changed else {
        unreachable!()
    };
    assert_eq!(
        changed.gesture,
        EofGesture::TerminalEof {
            byte: kr_protocol::scalars::U64::new(0x07)
        },
        "{}: the gesture did not follow the terminal's own character",
        case.id
    );

    // A command runs between the change and the gesture: this reader takes the terminal back into
    // its own modes afterwards, and the change has to survive that rather than the first prompt.
    assert!(
        session.answered("kr-veof-between"),
        "{}: the shell did not run a command after the change",
        case.id
    );
    let (_, fence) = session.fenced_after_a_command(14);
    settle(session, Duration::from_millis(200), REPLY);
    // The character the gesture has moved to is the terminal's own end-of-file character now, so
    // a terminal still in its line mode would answer this key itself.
    session.ensure_reading();
    session.type_bytes(shellpkg::CTRL_G);
    let (id, event) = session.expect_event("eof_detach on the new gesture", |event| {
        matches!(event, BridgeEvent::EofDetach(_))
    });
    let BridgeEvent::EofDetach(detach) = event else {
        unreachable!()
    };
    assert_eq!(detach.fence_id, fence.fence_id, "{}", case.id);
    session.answer_event(id, shellpkg::detached(shellpkg::attachment_id(3)));
    assert!(session.alive(), "{}", case.id);

    // With no end-of-file character there is no gesture at all.
    assert!(
        session.run(disable, "kr-veof-undef"),
        "{}: the terminal's end-of-file character was not taken away",
        case.id
    );
    let (_, gone) = session.expect_event("gesture_changed to none", |event| {
        matches!(
            event,
            BridgeEvent::GestureChanged(change) if change.gesture == EofGesture::Disabled
        )
    });
    let BridgeEvent::GestureChanged(_) = gone else {
        unreachable!()
    };
    // A terminal with no end-of-file character has no gesture, so no character is one.
    let (_, _fence) = session.fenced_after_a_command(15);
    session.ensure_reading();
    session.type_bytes(shellpkg::CTRL_G);
    assert!(
        !session.saw_event(Duration::from_millis(500), |event| matches!(
            event,
            BridgeEvent::EofDetach(_) | BridgeEvent::PreEofConsumed(_)
        )),
        "{}: a terminal with no gesture still produced one",
        case.id
    );
}

/// The customisation itself writes the line, and the reader reports what it wrote.
///
/// Typing a character proves only that typing fills a buffer. This drives the customisation's own
/// operation: a line it remembered is offered as a suggestion for a prefix, the person accepts it
/// with the key the customisation bound, and what ends up in the reader's buffer is text nobody
/// typed.
fn plugin_writes_the_buffer(
    case: &QualificationCase,
    session: &mut Session,
) -> kr_protocol::root::RootEditorEnterParams {
    if case.stack == "fzf" {
        return the_widget_puts_its_own_choice_in_the_line(case, session);
    }
    // The line the customisation remembers prints something its own text does not contain, so a
    // run of it is the buffer having held the whole line rather than the editor having drawn one.
    const REMEMBERED: &str = "echo kr-sugg''estion-ran";
    const PREFIX: &str = "echo kr-sugg";
    const PRINTED: &str = "kr-suggestion-ran";
    const OFFERED: &str = "estion-ran";
    const ACCEPT: &[u8] = &[0x05];

    assert!(
        session.run(REMEMBERED, PRINTED),
        "{}: the line the customisation is to remember did not run",
        case.id
    );
    let entered = session.next_prompt();
    settle(session, Duration::from_millis(300), REPLY);
    session.ensure_reading();

    let before = session.written();
    session.type_bytes(PREFIX.as_bytes());
    settle(session, Duration::from_millis(250), REPLY);
    assert!(
        session.wait_for_output_after(before, OFFERED, Duration::from_secs(5)),
        "{}: the customisation offered nothing for {PREFIX:?}; the terminal showed:\n{}",
        case.id,
        session.terminal_output()
    );

    session.type_bytes(ACCEPT);
    settle(session, Duration::from_millis(250), REPLY);
    let held = session.fence_exchange(&entered, shellpkg::fence_id(6));
    assert!(
        !held.editor.buffer_empty,
        "{}: the reader reported an empty prompt while holding a line the customisation wrote",
        case.id
    );
    assert!(
        held.editor.buffer_revision.get() > 0,
        "{}: the reader reported no edit at all",
        case.id
    );

    let accepted = session.written();
    session.type_bytes(b"\r");
    assert!(
        session.wait_for_output_after(accepted, PRINTED, REPLY),
        "{}: what the customisation put in the buffer did not run; the terminal showed:\n{}",
        case.id,
        session.terminal_output()
    );
    let entered = session.next_prompt();
    settle(session, Duration::from_millis(300), REPLY);
    session.ensure_reading();
    entered
}

/// A takeover while the customisation has the reader waiting for the rest of a key sequence.
///
/// Section 7 says a takeover cancels the incomplete decoder and editor operations through the
/// native cancellation path, discards the old lease's unread input and keeps the edit buffer. A
/// plugin that binds a multi-key sequence is exactly how a reader ends up in such a wait in an
/// ordinary session, so the wait is entered through the customisation's own bindings where the
/// shell has them and through the reader's own escape prefix where it does not.
fn a_takeover_ends_a_wait_the_customisation_left_the_reader_in(
    case: &QualificationCase,
    session: &mut Session,
) {
    let wait = shellpkg::pending_wait(case.shell)
        .expect("the corpus check refused this claim for a reader with no such wait");
    let (mut enter, _fence) = session.fenced_after_a_command(17);
    settle(session, Duration::from_millis(200), REPLY);
    if let Some((command, marker)) = wait.prepare {
        assert!(
            session.run(command, marker),
            "{}: the wait could not be prepared",
            case.id
        );
        // The preparation ran a command, so the reader the fence was about has gone. The one this
        // takeover is about is the one running now.
        let (entered, _) = session.fenced_after_a_command(18);
        enter = entered;
        settle(session, Duration::from_millis(200), REPLY);
    }

    // A line of the person's, which the cancellation has to keep.
    session.ensure_reading();
    session.type_bytes(b"kr-kept");
    std::thread::sleep(Duration::from_millis(120));
    session.type_bytes(wait.enter);
    std::thread::sleep(Duration::from_millis(150));

    // A fence asked while the reader is inside that wait reports the queue that is holding it,
    // rather than a clear one.
    let held = session.ask(WorkerRequest::Fence(RootEditorFenceParams {
        session_id: session.session_id,
        fence_id: shellpkg::fence_id(18),
        prompt_generation: enter.prompt_generation,
        reader_revision: enter.reader_revision,
        deadline_ms: FENCE_EXCHANGE_TIMEOUT,
        cause: FenceCause::LeaseChange,
    }));
    match session.answer(held) {
        BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(acknowledgement)) => {
            if wait.partial_key_queue {
                assert!(
                    !acknowledgement.queues.partial_key_drained,
                    "{}: the reader reported every queue clear while it was waiting for a key",
                    case.id
                );
            }
        }
        BridgeAnswer::Fence(RootEditorFenceResult::Refused(_)) => {}
        other => panic!("{}: the reader answered a fence with {other:?}", case.id),
    }

    // The takeover's own cancellation ends that wait without taking the line away.
    let cancelled = session.ask(WorkerRequest::Cancel(CancelKeyWait {
        session_id: session.session_id,
        sequence: kr_protocol::scalars::U64::new(1),
        epoch: enter_epoch(),
        prompt_generation: enter.prompt_generation,
        reader_revision: enter.reader_revision,
    }));
    let BridgeAnswer::Cancel(report) = session.answer(cancelled) else {
        panic!(
            "{}: the reader answered a cancellation with something else",
            case.id
        )
    };
    assert_eq!(
        report.sequence,
        kr_protocol::scalars::U64::new(1),
        "{}",
        case.id
    );
    assert!(
        report.buffer_preserved,
        "{}: a cancellation took the person's line away",
        case.id
    );

    // The retried fence finds the reader out of its wait and its queues clear, with the line still
    // there: what was discarded was the key the wait was holding, not the edit buffer.
    let retried = session.fence_exchange(&enter, shellpkg::fence_id(19));
    assert!(
        retried.queues.partial_key_drained,
        "{}: the partial-key queue is still holding something after the cancellation",
        case.id
    );
    assert!(
        !retried.editor.buffer_empty,
        "{}: the line the person had typed did not survive the takeover",
        case.id
    );
}

/// A launch whose reader budget has already gone installs nothing.
///
/// Section 7 bounds the reservation at 250 ms and says that on timeout the launch is rejected with
/// `EDITOR_BUSY` and no command is installed. The reader is bound by the same budget, which is
/// what makes "no command is installed" true rather than a hope that the worker's own answer wins
/// the race: this asks for a launch whose budget is already spent and checks the editor.
fn a_launch_past_its_reader_budget_installs_nothing(
    case: &QualificationCase,
    session: &mut Session,
) {
    let (entered, fence) = session.fenced_after_a_command(20);
    settle(session, Duration::from_millis(200), REPLY);

    let id = session.ask(WorkerRequest::Launch(LaunchMailboxRequest {
        session_id: session.session_id,
        transaction: LaunchTransactionId::new(kr_protocol::scalars::Uuid::from_bytes([0x63; 16])),
        fence_id: fence.fence_id,
        command: LaunchCommand::Arguments(vec![
            "printf".to_owned(),
            "kr-launch-must-not-run".to_owned(),
        ]),
        expected_prompt_generation: entered.prompt_generation,
        expected_buffer_revision: entered.editor.buffer_revision,
        expected_cwd_revision: entered.cwd_revision,
        // Already spent: the reader measures it from when the request reached it.
        deadline_ms: kr_protocol::scalars::DurationMs::new(0),
    }));
    let BridgeAnswer::Launch(decision) = session.answer(id) else {
        panic!(
            "{}: the reader answered a launch with something else",
            case.id
        )
    };
    let rejected = match decision {
        LaunchDecision::Rejected(rejected) => rejected,
        LaunchDecision::Accepted(_) => {
            panic!("{}: a launch with no budget left was installed", case.id)
        }
    };
    assert_eq!(
        rejected.reason,
        LaunchRejectionReason::Timeout,
        "{}: a spent budget was refused for another reason",
        case.id
    );

    // Nothing is in the editor and nothing ran.
    let after = session.fence_exchange(&entered, shellpkg::fence_id(21));
    assert!(
        after.editor.buffer_empty,
        "{}: the editor is holding a command a refused launch did not install",
        case.id
    );
    assert!(
        !session.terminal_output().contains("kr-launch-must-not-run"),
        "{}: a refused launch ran",
        case.id
    );
}

/// The lease epoch the harness's own fences are published under.
fn enter_epoch() -> kr_protocol::ids::InputLeaseEpoch {
    shellpkg::epoch(4)
}

/// The customisation's own widget runs a program inside the reader and puts its choice in the line.
///
/// Two keys are sent and neither is a character: the chord the widget is bound to, and the return
/// that chooses. What is in the reader's buffer afterwards is the widget's, and the reader reports
/// it as a line rather than as an empty prompt — which is what section 7 says a prompt hook cannot
/// tell apart.
fn the_widget_puts_its_own_choice_in_the_line(
    case: &QualificationCase,
    session: &mut Session,
) -> kr_protocol::root::RootEditorEnterParams {
    const CHORD: &[u8] = &[0x14];
    const CHOICE: &str = "kr-fzf-choice";

    let (entered, _fence) = session.fenced_after_a_command(24);
    settle(session, Duration::from_millis(200), REPLY);
    let empty = session.fence_exchange(&entered, shellpkg::fence_id(25));
    assert!(
        empty.editor.buffer_empty,
        "{}: the prompt the widget is about was not empty",
        case.id
    );

    let before = session.written();
    session.ensure_reading();
    session.type_bytes(CHORD);
    assert!(
        session.wait_for_output_after(before, CHOICE, REPLY),
        "{}: the widget drew nothing to choose from; the terminal showed:\n{}",
        case.id,
        session.terminal_output()
    );
    session.type_bytes(b"\r");
    settle(session, Duration::from_millis(400), REPLY);

    let held = session.fence_exchange(&entered, shellpkg::fence_id(26));
    assert!(
        !held.editor.buffer_empty,
        "{}: the widget's own choice did not reach the reader's buffer; the terminal showed:\n{}",
        case.id,
        session.terminal_output()
    );
    assert!(
        held.editor.buffer_revision.get() > empty.editor.buffer_revision.get(),
        "{}: the reader reported no edit between the empty prompt and the widget's choice",
        case.id
    );
    session.clear_line();
    settle(session, Duration::from_millis(200), REPLY);
    entered
}

/// A second start over the same home, which is the only one a cached early prompt exists for.
///
/// The theme draws a prompt from that cache before the startup file has finished, so what this
/// asserts is the order the warm start records and the reader that ends up running afterwards:
/// the early prompt is drawing, not a reader, and the managed one is what answers a fence.
fn a_second_start_draws_from_the_cache_the_first_wrote(
    case: &QualificationCase,
    package: &Package,
    setup: &CaseSetup,
) {
    let warm = case
        .warm_order
        .as_ref()
        .expect("the corpus check refused a case without one");
    setup.forget_order();
    let mut session = Session::start_for(package, case, setup);
    let enter = session.first_prompt_within(STARTUP);
    settle(&mut session, Duration::from_millis(300), REPLY);
    session.ensure_reading();
    assert_eq!(
        &setup.recorded_order(),
        warm,
        "{}: a second start over the same home did not draw from the cache the first wrote; the \
         terminal showed:\n{}",
        case.id,
        session.terminal_output()
    );
    let acknowledgement = session.fence_exchange(&enter, shellpkg::fence_id(7));
    assert_eq!(acknowledgement.prompt_generation, enter.prompt_generation);
    assert!(
        acknowledgement.editor.buffer_empty,
        "{}: the reader that came out of the early prompt was holding something",
        case.id
    );
    assert!(
        session.alive(),
        "{}: the shell did not survive its warm start",
        case.id
    );
}

/// How long a reader is given before a case calls it a failure.
const REPLY: Duration = Duration::from_secs(20);

/// How long a person's own startup is given to finish and draw its first prompt.
///
/// A framework that reads hundreds of files and builds a completion cache is slow on a machine
/// running several of these at once, and being slow there is not a package that failed.
const STARTUP: Duration = Duration::from_secs(90);

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

/// One row of a table in the upstream register.
fn register_rows(body: &str, marker: &str) -> Vec<Vec<String>> {
    let open = format!("<!-- kr:{marker} -->");
    let close = format!("<!-- /kr:{marker} -->");
    let start = body
        .find(&open)
        .unwrap_or_else(|| panic!("docs/shell-integration/upstream.md has no {open}"))
        + open.len();
    let end = body[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("docs/shell-integration/upstream.md has no {close}"))
        + start;
    body[start..end]
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_owned())
                .collect::<Vec<_>>()
        })
        // The header and the separator under it are not rows.
        .skip(2)
        .collect()
}

/// Today, as the register writes its dates.
fn today() -> (i64, u32, u32) {
    let days = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_secs()
            / 86_400,
    )
    .expect("a date inside this era");
    // Days from the civil epoch to the year, month and day, by Howard Hinnant's algorithm.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * shifted_month + 2) / 5 + 1).expect("a day");
    let month = u32::try_from(if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    })
    .expect("a month");
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Reads a `YYYY-MM-DD` cell.
fn as_date(cell: &str) -> (i64, u32, u32) {
    let mut parts = cell.split('-');
    let mut next = |what: &str| -> i64 {
        parts
            .next()
            .and_then(|part| part.parse().ok())
            .unwrap_or_else(|| panic!("{cell:?} is not a date: no {what}"))
    };
    let year = next("year");
    let month = u32::try_from(next("month")).expect("a month");
    let day = u32::try_from(next("day")).expect("a day");
    assert!(
        parts.next().is_none(),
        "{cell:?} has more than a year, a month and a day"
    );
    assert!(
        (2020..=2100).contains(&year),
        "{cell:?} is not a date this register could carry"
    );
    assert!((1..=12).contains(&month), "{cell:?} names no month");
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let longest = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if leap => 29,
        _ => 28,
    };
    assert!(
        (1..=longest).contains(&day),
        "{cell:?} names a day that month does not have"
    );
    (year, month, day)
}

/// KR-REQ-07.88: the register, the pins and what is installed are one thing.
#[test]
fn the_upstream_register_agrees_with_the_pins_and_with_what_is_installed() {
    let path = repository_root().join("docs/shell-integration/upstream.md");
    let body = std::fs::read_to_string(&path).expect("the register is committed");
    let pins = register_rows(&body, "pins");
    assert!(
        pins.len() >= 4,
        "the register names {} packages",
        pins.len()
    );

    let target = {
        let open = "<!-- kr:target -->";
        let close = "<!-- /kr:target -->";
        let start = body.find(open).expect("the register states its target") + open.len();
        let end = body[start..].find(close).expect("the target block closes") + start;
        body[start..end].to_owned()
    };
    for phrase in [
        "within one working day",
        "within fourteen days",
        "requalified",
        "already running",
    ] {
        assert!(
            target.contains(phrase),
            "the published update target does not say {phrase:?}"
        );
    }
    // The people who consume a release read the release page, so the target is published there as
    // well as here, and the two say the same thing.
    let releases = std::fs::read_to_string(repository_root().join("docs/releases/packages.md"))
        .expect("the release page is committed");
    for phrase in [
        "within one working day",
        "within fourteen days",
        "native_compat",
        "docs/shell-integration/upstream.md",
    ] {
        assert!(
            releases.contains(phrase),
            "the release page does not carry the update target: no {phrase:?}"
        );
    }

    // Every pin the register names is the pin the builder uses, and the identity record the build
    // wrote beside the binary is read rather than left in the file.
    for row in &pins {
        let [package, _upstream, revision, source, digest, watched] = row.as_slice() else {
            panic!("a pin row has {} cells", row.len());
        };
        assert!(
            !watched.is_empty(),
            "{package} names no source of advisories"
        );
        let manifest_path = repository_root().join(format!("shells/{package}/manifest.json"));
        let manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest_path).expect("a manifest"))
                .expect("the manifest decodes");
        if package == "psreadline" {
            // This package fetches nothing: what it pins is the range it was qualified against.
            let qualified = &manifest["qualified"];
            for version in [
                qualified["psreadline_from"].as_str().unwrap_or_default(),
                qualified["psreadline_before"].as_str().unwrap_or_default(),
            ] {
                assert!(
                    revision.contains(version.trim_end_matches(".0")) || revision.contains(version),
                    "the register's range for psreadline does not carry {version}"
                );
            }
            continue;
        }
        let upstream = &manifest["upstream"];
        assert_eq!(
            revision,
            upstream["revision"].as_str().unwrap_or_default(),
            "the register and {package}'s manifest name different revisions"
        );
        assert_eq!(
            source,
            upstream["url"].as_str().unwrap_or_default(),
            "the register and {package}'s manifest name different sources"
        );
        assert_eq!(
            digest,
            upstream["sha256"].as_str().unwrap_or_default(),
            "the register and {package}'s manifest name different archives"
        );

        let kind = match package.as_str() {
            "zsh" => ShellKind::Zsh,
            "bash" => ShellKind::Bash,
            "fish" => ShellKind::Fish,
            other => panic!("the register names a package called {other}"),
        };
        let Ok(installed) = Package::find(kind) else {
            continue;
        };
        let record = &installed.record;
        assert_eq!(
            record["build"]["upstream"]["url"]
                .as_str()
                .unwrap_or_default(),
            source,
            "the {package} package installed here was built from another source"
        );
        assert_eq!(
            record["build"]["upstream"]["sha256"]
                .as_str()
                .unwrap_or_default(),
            digest,
            "the {package} package installed here was built from another archive"
        );
        assert_eq!(
            record["shell"]["upstream_version"]
                .as_str()
                .unwrap_or_default(),
            upstream["version"].as_str().unwrap_or_default(),
            "the {package} package installed here records another upstream version"
        );
        let declared: Vec<String> = manifest["patches"]
            .as_array()
            .expect("a patch list")
            .iter()
            .filter_map(|patch| patch["name"].as_str().map(str::to_owned))
            .collect();
        assert_eq!(
            installed.patch_names(),
            declared,
            "the {package} package installed here records another patch set"
        );
        let modules: Vec<String> = record["shell"]["modules"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|module| module["name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let expected: Vec<String> = manifest["modules"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|module| module.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            modules, expected,
            "the {package} package installed here records another module tree"
        );
    }

    // Every package has been triaged, every row has a target date, and a row past its date that
    // has not been released says so rather than leaving a stale package as a silent default.
    let triage = register_rows(&body, "triage");
    assert!(!triage.is_empty(), "the triage record is empty");
    let now = today();
    for row in &triage {
        let [date, change, packages, assessment, target_release, status] = row.as_slice() else {
            panic!("a triage row has {} cells", row.len());
        };
        let _ = as_date(date);
        assert!(!change.is_empty() && assessment.split_whitespace().count() >= 8);
        assert!(
            ["released", "scheduled", "flagged", "not-affected"].contains(&status.as_str()),
            "{status:?} is not one of the statuses the register defines"
        );
        if status == "released" {
            // A package was published, so the record says which one: an identity is sixteen
            // hexadecimal characters, and a claim that names none is a claim with no evidence.
            assert!(
                assessment.split_whitespace().any(|word| {
                    let word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
                    word.len() == 16 && word.chars().all(|c| c.is_ascii_hexdigit())
                }),
                "the triage row of {date} says a package was released and names no identity"
            );
        }
        let due = as_date(target_release);
        if due < now && status == "scheduled" {
            panic!(
                "the triage row of {date} is past its target release and is still scheduled; a \
                 package that cannot meet its target is flagged with its compatibility-mode \
                 choices"
            );
        }
        for package in packages.split(", ") {
            assert!(
                pins.iter().any(|pin| pin[0] == package),
                "the triage record names {package}, which the register does not pin"
            );
        }
    }
    for pin in &pins {
        assert!(
            triage
                .iter()
                .any(|row| row[2].split(", ").any(|package| package == pin[0])),
            "{} has never been triaged",
            pin[0]
        );
    }
    // A row that is flagged has to say what was chosen, and the choices have to be there to
    // choose from: a package past its target with nothing said is the silent stale default
    // section 7 rules out.
    for row in &triage {
        if row[5] == "flagged" {
            assert!(
                [
                    "keep the pinned package",
                    "native_compat",
                    "a different managed shell"
                ]
                .iter()
                .any(|choice| row[3].to_lowercase().contains(choice)),
                "the triage row of {} is flagged and names none of the choices",
                row[0]
            );
        }
    }
    for choice in [
        "Keep the pinned package",
        "native_compat",
        "Run a different managed shell",
    ] {
        assert!(
            body.contains(choice),
            "the register does not offer {choice:?} as a compatibility-mode choice"
        );
    }
}

/// KR-REQ-07.88: no unqualified binary is hot-swapped into a session that is already running.
///
/// The installation is what a new session resolves its package from, and the product's own
/// resolver is what reads it. This makes an installation of its own out of two builds this host
/// really has — the directories are the real ones, so each package's own record and its own
/// binary are what a session starts — starts a session from the first, and then points the
/// installation at the second while that session is running. The resolver a new session would use
/// answers the second, and the session that is running is still executing the first.
#[test]
fn a_live_session_keeps_the_package_it_started_with() {
    let Some(installed) = Package::found(ShellKind::Zsh) else {
        return;
    };
    let Some(index) = installed_stacks() else {
        return;
    };
    let case = cases()
        .into_iter()
        .find(|case| case.id == "zsh-plain")
        .expect("the plain Zsh case is committed");

    // Two installations of one package is what a person has after an update, so this needs two
    // builds. They cannot be made by copying one under another name: a package declares the build
    // it is, and a copy declares the original, which the handshake refuses as another build.
    let Some(older) = another_build(&installed) else {
        let reason = format!(
            "this host holds one build of the {} package, so there is no second one to install \
             over it; build one from different inputs, as scripts/e2e-fence.sh does",
            ShellKind::Zsh.as_str()
        );
        assert!(
            std::env::var_os(shellpkg::REQUIRE).is_none(),
            "{} is set and {reason}",
            shellpkg::REQUIRE
        );
        println!("skipped: {reason}");
        shellpkg::record("no-replacement-to-install.txt", &format!("{reason}\n"));
        return;
    };
    assert_ne!(
        installed.identity, older.identity,
        "the two builds carry one identity between them"
    );
    assert_ne!(
        std::fs::read(&installed.executable).expect("a binary"),
        std::fs::read(&older.executable).expect("a binary"),
        "the two builds produced the same binary, so neither could be told from the other"
    );

    let root = tempfile::Builder::new()
        .prefix("kr-installation-")
        .tempdir()
        .expect("an installation root on the internal disk");
    let shell = root.path().join(ShellKind::Zsh.as_str());
    std::fs::create_dir_all(&shell).expect("an installation directory");
    for build in [&installed, &older] {
        let directory = build
            .executable
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the package directory");
        std::os::unix::fs::symlink(directory, shell.join(&build.identity))
            .expect("an installed build");
    }
    std::fs::write(shell.join("current"), &installed.identity).expect("the pointer");
    // The installation reaches each build through a directory of its own, so what the resolver
    // answers is compared as the kernel spells it rather than as this root writes it.
    assert_eq!(
        canonical(&resolved_executable(root.path())),
        canonical(&installed.executable)
    );

    let setup = CaseSetup::prepare(&case, &installed, &index);
    let mut session = Session::start_for(&installed, &case, &setup);
    session.first_prompt_within(STARTUP);
    settle(&mut session, Duration::from_millis(300), REPLY);
    // What the operating system says this process is executing, rather than what it was invoked
    // as: an invocation name can be anything, and the question is which image is running.
    assert_eq!(
        running_image(&mut session),
        canonical(&installed.executable),
        "the session did not start the build it was given"
    );

    // A newer package is installed while that session is running.
    std::fs::write(shell.join("current"), &older.identity).expect("the pointer");
    assert_eq!(
        canonical(&resolved_executable(root.path())),
        canonical(&older.executable),
        "a new session would still resolve the installation that was replaced"
    );
    assert_eq!(
        running_image(&mut session),
        canonical(&installed.executable),
        "the live session took up the build that replaced it"
    );

    // A session started now takes the installation the pointer names, and the package it starts
    // from is the product resolver's own answer rather than one this test chose.
    assert_eq!(
        canonical(&resolved_executable(root.path())),
        canonical(&older.executable)
    );
    let second = CaseSetup::prepare(&case, &older, &index);
    let mut next = Session::start_for(&older, &case, &second);
    next.first_prompt_within(STARTUP);
    settle(&mut next, Duration::from_millis(300), REPLY);
    assert_eq!(
        running_image(&mut next),
        canonical(&older.executable),
        "the session started after the update is running the build it replaced"
    );
    assert!(next.alive());
    assert!(session.alive());

    // A replacement that reads perfectly well and is not this package is refused rather than
    // launched: the record names a binary outside the package it is in.
    let intruder = shell.join("cccccccccccccccc");
    std::fs::create_dir_all(&intruder).expect("an installation directory");
    let mut record = installed.record.clone();
    record["identity"] = serde_json::Value::String("cccccccccccccccc".to_owned());
    record["shell"]["executable"] = serde_json::Value::String("/bin/zsh".to_owned());
    std::fs::write(
        intruder.join("kr-shell-identity.json"),
        serde_json::to_string_pretty(&record).expect("the record encodes"),
    )
    .expect("the record");
    std::fs::write(shell.join("current"), "cccccccccccccccc").expect("the pointer");
    assert!(
        offered(root.path(), ShellKind::Zsh).is_none(),
        "an installation that names a binary outside itself was offered anyway"
    );

    // And one whose record cannot be read at all.
    std::fs::write(intruder.join("kr-shell-identity.json"), "{").expect("the record");
    assert!(
        offered(root.path(), ShellKind::Zsh).is_none(),
        "an installation whose record cannot be read was offered anyway"
    );
    // An installation is read shell by shell, so a record that cannot be read refuses the shell it
    // belongs to and leaves the packages beside it alone. The Bash package is put into this same
    // installation to check that, rather than to say it.
    match Package::found(ShellKind::Bash) {
        Some(beside) => {
            let directory = beside
                .executable
                .parent()
                .and_then(std::path::Path::parent)
                .expect("the package directory");
            let bash = root.path().join(ShellKind::Bash.as_str());
            std::fs::create_dir_all(&bash).expect("an installation directory");
            std::os::unix::fs::symlink(directory, bash.join(&beside.identity))
                .expect("an installed build");
            std::fs::write(bash.join("current"), &beside.identity).expect("the pointer");
            assert_eq!(
                offered(root.path(), ShellKind::Bash)
                    .as_deref()
                    .and_then(canonical),
                canonical(&beside.executable),
                "a Zsh record that cannot be read took the Bash package beside it with it"
            );
        }
        None => {
            let reason = "this host holds no Bash package, so what a Zsh record that cannot be \
                          read leaves beside it is not checked here";
            assert!(
                std::env::var_os(shellpkg::REQUIRE).is_none(),
                "{} is set and {reason}",
                shellpkg::REQUIRE
            );
            println!("skipped: {reason}");
        }
    }
}

/// KR-REQ-07.87, KR-REQ-07.88: a package binds into the editor it was qualified against, and says
/// so about any other.
///
/// The PowerShell package builds no editor. It binds into the PSReadLine the person installed, so
/// what makes its qualification true of a running session is that editor being the one the
/// qualification ran against. A supported version range does not say that: two installations can
/// both be inside one range, and only one of them was qualified. The package records which one,
/// and this drives that record against the module itself.
#[test]
fn the_package_binds_into_the_editor_it_was_qualified_against() {
    let Some(package) = Package::found(ShellKind::PowerShell) else {
        return;
    };
    let directory = package
        .executable
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the package directory")
        .to_owned();

    // A copy of the package, because what is driven here is its own record and the installed one
    // is what every other case in this run qualifies against.
    let root = tempfile::Builder::new()
        .prefix("kr-qualified-editor-")
        .tempdir()
        .expect("a root on the internal disk");
    let copy = root.path().join("package");
    let copied = std::process::Command::new("cp")
        .arg("-R")
        .arg(&directory)
        .arg(&copy)
        .status()
        .expect("a copy of the package");
    assert!(copied.success(), "the package did not copy");
    let record_path = copy.join("kr-shell-identity.json");
    let published: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record_path).expect("the record"))
            .expect("the record reads");
    let qualified = published["qualified"].clone();
    assert!(
        qualified["psreadline_module_base"].is_string(),
        "the package published no editor to be qualified against: {published}"
    );

    assert_eq!(
        refusal(&package, &copy),
        "",
        "the package refused the editor it was qualified against"
    );

    // The same version somewhere else: an editor a person moved, or a second installation of it,
    // is not the one this package was qualified against.
    let mut elsewhere = published.clone();
    elsewhere["qualified"]["psreadline_module_base"] = serde_json::Value::String(format!(
        "{}-elsewhere",
        qualified["psreadline_module_base"]
            .as_str()
            .expect("the published module base")
    ));
    write_record(&record_path, &elsewhere);
    assert_eq!(
        refusal(&package, &copy),
        "psreadline_not_the_qualified_editor",
        "a package bound into an editor it was never qualified against"
    );

    // And the same place at another version, which is what an update to the editor leaves behind.
    let mut updated = published.clone();
    updated["qualified"]["psreadline_found"] = serde_json::Value::String("0.0.1".to_owned());
    write_record(&record_path, &updated);
    assert_eq!(
        refusal(&package, &copy),
        "psreadline_not_the_qualified_editor",
        "a package bound into an editor whose version it never qualified"
    );

    // A directory that is not the qualified editor, refused for being another directory rather
    // than for how its name is spelt: this one exists and reads perfectly well.
    let base = qualified["psreadline_module_base"]
        .as_str()
        .expect("the published module base");
    let another = root.path().join("another-editor");
    std::fs::create_dir_all(&another).expect("a directory that is not the qualified editor");
    let mut other_directory = published.clone();
    other_directory["qualified"]["psreadline_module_base"] =
        serde_json::Value::String(another.display().to_string());
    write_record(&record_path, &other_directory);
    assert_eq!(
        refusal(&package, &copy),
        "psreadline_not_the_qualified_editor",
        "a package bound into a directory that is not the editor it was qualified against"
    );

    // A name whose case is turned over is another directory on a filesystem that keeps both, and
    // another spelling of one directory on a filesystem that does not. Which of the two this host
    // has is the filesystem's answer rather than this test's, so it is asked, and the package has
    // to say what it says: refusing a spelling of the very directory the package is holding would
    // refuse the installation itself.
    let flipped = flip_case(base);
    let one_and_the_same = one_directory(&flipped, base);
    let mut spelled = published.clone();
    spelled["qualified"]["psreadline_module_base"] = serde_json::Value::String(flipped.clone());
    write_record(&record_path, &spelled);
    assert_eq!(
        refusal(&package, &copy),
        if one_and_the_same {
            ""
        } else {
            "psreadline_not_the_qualified_editor"
        },
        "this filesystem makes {flipped} and {base} {}, and the package said otherwise",
        if one_and_the_same {
            "one directory"
        } else {
            "two directories"
        }
    );

    // One directory reached by two paths is one editor, whether the link is the last name in the
    // path or one of the directories above it. Both are how a module search path reaches an
    // installed editor, and refusing either would refuse the installation this package holds.
    let through = root.path().join("through-a-link");
    std::os::unix::fs::symlink(base, &through).expect("a link to the qualified editor");
    let mut linked = published.clone();
    linked["qualified"]["psreadline_module_base"] =
        serde_json::Value::String(through.display().to_string());
    write_record(&record_path, &linked);
    assert_eq!(
        refusal(&package, &copy),
        "",
        "the package refused the editor it was qualified against, reached through a link"
    );
    let editor = std::path::Path::new(base);
    let above = root.path().join("through-a-parent");
    std::os::unix::fs::symlink(
        editor
            .parent()
            .expect("the editor's own directory has a parent"),
        &above,
    )
    .expect("a link to the directory the qualified editor is in");
    let mut linked_above = published.clone();
    linked_above["qualified"]["psreadline_module_base"] = serde_json::Value::String(
        above
            .join(editor.file_name().expect("the editor's own name"))
            .display()
            .to_string(),
    );
    write_record(&record_path, &linked_above);
    assert_eq!(
        refusal(&package, &copy),
        "",
        "the package refused the editor it was qualified against, reached through a link above it"
    );

    // A record that names no editor decides nothing, whether it holds no qualification at all,
    // one that is empty, or one that is missing either half of the answer.
    let mut silent = published.clone();
    silent
        .as_object_mut()
        .expect("the record is an object")
        .remove("qualified");
    write_record(&record_path, &silent);
    assert_eq!(
        refusal(&package, &copy),
        "package_qualification_unreadable",
        "a package that says nothing about its editor bound into one anyway"
    );
    let mut empty = published.clone();
    empty["qualified"] = serde_json::json!({});
    write_record(&record_path, &empty);
    assert_eq!(
        refusal(&package, &copy),
        "package_qualification_unreadable",
        "a package whose qualification holds nothing bound into an editor anyway"
    );
    let mut half = published.clone();
    half["qualified"] = serde_json::json!({ "psreadline_module_base": base });
    write_record(&record_path, &half);
    assert_eq!(
        refusal(&package, &copy),
        "package_qualification_unreadable",
        "a package that named no version bound into an editor anyway"
    );
    std::fs::write(&record_path, "{").expect("the record");
    assert_eq!(
        refusal(&package, &copy),
        "package_qualification_unreadable",
        "a package whose record cannot be read bound into an editor anyway"
    );
}

/// The same path with the case of its letters turned over, which is another directory wherever the
/// filesystem keeps one and another spelling wherever it does not.
fn flip_case(path: &str) -> String {
    path.chars()
        .map(|character| {
            if character.is_uppercase() {
                character.to_lowercase().to_string()
            } else {
                character.to_uppercase().to_string()
            }
        })
        .collect()
}

/// Whether two paths name one directory, as the filesystem this test runs on answers it.
///
/// The device and the inode, which is the same question the package asks and the only thing that
/// tells a second directory from a second spelling of one.
fn one_directory(left: &str, right: &str) -> bool {
    use std::os::unix::fs::MetadataExt;

    match (std::fs::metadata(left), std::fs::metadata(right)) {
        (Ok(one), Ok(other)) => one.dev() == other.dev() && one.ino() == other.ino(),
        _ => false,
    }
}

/// Writes one package record back the way a package holds it.
fn write_record(path: &std::path::Path, record: &serde_json::Value) {
    std::fs::write(
        path,
        serde_json::to_string_pretty(record).expect("the record encodes"),
    )
    .expect("the record");
}

/// What the module at `package_root` says about the editor in a host this package starts, as the
/// name of its refusal, or nothing when it accepts that editor.
fn refusal(package: &Package, package_root: &std::path::Path) -> String {
    let module = package_root
        .join("modules/KalaReach.ShellBridge/KalaReach.ShellBridge.psd1")
        .display()
        .to_string();
    let script = format!(
        "$ErrorActionPreference = 'Stop'; Import-Module '{module}'; \
         $answer = & (Get-Module KalaReach.ShellBridge) {{ Test-KrQualifiedEditor }}; \
         Write-Output \"kr-editor=[$($answer.Reason)]\""
    );
    // The package's own launcher, which is how a session starts this host: the runtime location
    // the host needs is the launcher's to pass, not this test's to guess. Nothing of a session's
    // is in this environment, so the module answers the question and attempts no handshake.
    let asked = std::process::Command::new(&package.executable)
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .env_remove("KR_SHELL_BRIDGE")
        .env_remove("KR_SHELL_BRIDGE_SECRET")
        .env_remove("KR_SESSION")
        .output()
        .expect("the package's host runs");
    let said = String::from_utf8_lossy(&asked.stdout).into_owned();
    let told = String::from_utf8_lossy(&asked.stderr);
    let start = said
        .find("kr-editor=[")
        .unwrap_or_else(|| panic!("the module answered nothing:\n{said}\n{told}"))
        + "kr-editor=[".len();
    let end = said[start..]
        .find(']')
        .unwrap_or_else(|| panic!("the module's answer did not end:\n{said}"))
        + start;
    said[start..end].to_owned()
}

/// The package of one shell this installation offers a new session, where it offers one.
fn offered(root: &std::path::Path, kind: ShellKind) -> Option<std::path::PathBuf> {
    kr_shell_integration::host::package::PackageSet::discover(root)
        .ok()?
        .get(kind)
        .map(kr_shell_integration::host::package::ShellPackage::executable)
}

/// What the product's own resolver would launch for a new session at this installation.
fn resolved_executable(root: &std::path::Path) -> std::path::PathBuf {
    kr_shell_integration::host::package::PackageSet::discover(root)
        .expect("the installation reads")
        .get(ShellKind::Zsh)
        .expect("the installation holds a Zsh package")
        .executable()
}

/// Another identity of the same package this host has built before, where it has one.
///
/// The build keeps every identity it produces, so a machine that has rebuilt the package from
/// different inputs has two real builds of it. A host with one build has one, and the test that
/// uses this says so rather than copying the same bytes twice and calling them two packages.
fn another_build(current: &Package) -> Option<Package> {
    let root = current
        .executable
        .parent()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)?;
    let mut others: Vec<std::path::PathBuf> = std::fs::read_dir(root)
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_dir()
                && path.join("kr-shell-identity.json").is_file()
                && path.file_name().map(std::ffi::OsStr::to_os_string)
                    != std::path::Path::new(&current.identity)
                        .file_name()
                        .map(std::ffi::OsStr::to_os_string)
        })
        .collect();
    others.sort();
    let chosen = others.into_iter().next_back()?;
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(chosen.join("kr-shell-identity.json")).ok()?)
            .ok()?;
    let executable = std::path::PathBuf::from(record["shell"]["executable"].as_str()?);
    if !executable.exists() {
        return None;
    }
    Some(Package {
        kind: current.kind,
        identity: chosen.file_name()?.to_string_lossy().into_owned(),
        executable,
        startup_entry: chosen
            .join("startup")
            .join(current.startup_entry.file_name()?),
        module_directory: chosen.join("modules"),
        record,
    })
}

/// A path as the kernel spells it, so a directory reached through a link compares equal.
fn canonical(path: &std::path::Path) -> Option<std::path::PathBuf> {
    Some(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()))
}

/// The image a session's shell is actually executing, as the kernel reports it.
///
/// Not what it was invoked as: a process can be started with any name in its argument vector, and
/// the question here is which file is executing. Each platform is asked the question it answers
/// exactly — the link the kernel keeps beside the process, or the call that reads its path.
#[cfg(target_os = "linux")]
fn running_image(session: &mut Session) -> Option<std::path::PathBuf> {
    let pid = session.child_pid()?;
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|path| canonical(&path))
}

#[cfg(target_os = "macos")]
fn running_image(session: &mut Session) -> Option<std::path::PathBuf> {
    // The open-file listing names the text file a process is executing. `ps` answers with the
    // first word of the argument vector instead, which a process chooses for itself, so a
    // different binary started under the expected name would satisfy it.
    let pid = session.child_pid()?;
    let listed = std::process::Command::new("lsof")
        .args(["-p", &pid.to_string(), "-a", "-d", "txt", "-Fn"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix('n'))
        .find(|path| !path.starts_with("/usr/lib/"))
        .and_then(|path| canonical(std::path::Path::new(path)))
}

// ---------------------------------------------------------------------------------------------
// The worker's own race rules, on a clock this suite moves.
//
// The cases above drive a real reader in a real terminal. These drive the other half: the machine
// the worker runs, which decides what a hold releases, in what order, and what a caller is told.
// `FenceMachine::apply` takes the moment as an argument, so a deadline is reached by naming it
// rather than by waiting for it, and a rule that depends on 250 ms passing is checked without a
// test that is slower than the rule it is about.
// ---------------------------------------------------------------------------------------------

use kr_protocol::root::{
    CwdRevision, EditorBufferRevision, EditorKeymap, EditorState, KeyQueueSnapshot,
    PendingReaderInput, PromptGeneration, QueueDrainReport, ReaderContext, ReaderRevision,
    RootEditorEnterParams, ShellLaunchParams,
};
use kr_shell_integration::contract::events::ReaderIdle;
use kr_shell_integration::contract::fence::{
    ActionShape, ContinuousMs, EditorEntered, FenceMachine, InputArrived, InputRef,
    LaunchRequested, LeaseView, ReaderIdled, Stimulus,
};

fn race_session() -> kr_protocol::ids::SessionId {
    kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes([0x63; 16]))
}

fn race_process() -> kr_protocol::identity::ProcessStartIdentity {
    kr_protocol::identity::ProcessStartIdentity::new(
        4242,
        kr_protocol::identity::ProcessStartSource::LinuxProcStat,
        99,
    )
}

fn empty_reader(revision: u64) -> EditorState {
    EditorState {
        buffer_revision: EditorBufferRevision::new(revision),
        buffer_empty: true,
        keymap: EditorKeymap::Emacs,
        pending: PendingReaderInput::NONE,
    }
}

fn at(milliseconds: u64) -> ContinuousMs {
    ContinuousMs::new(milliseconds)
}

fn entered(prompt: u64, revision: u64, candidate: u8) -> Stimulus {
    Stimulus::EditorEntered(EditorEntered {
        params: RootEditorEnterParams {
            session_id: race_session(),
            root_process: race_process(),
            prompt_generation: PromptGeneration::new(prompt),
            reader_revision: ReaderRevision::new(revision),
            reader_context: ReaderContext::Primary,
            editor: empty_reader(1),
            cwd_revision: CwdRevision::new(2),
        },
        candidate_fence: shellpkg::fence_id(candidate),
    })
}

fn arrived(label: &str, bytes: u64) -> Stimulus {
    arrived_under(label, bytes, 1)
}

/// A batch from the attachment that holds one epoch of the lease.
fn arrived_under(label: &str, bytes: u64, epoch: u64) -> Stimulus {
    Stimulus::InputArrived(InputArrived {
        input: InputRef::new(label),
        attachment_id: shellpkg::attachment_id(u8::try_from(epoch).expect("a small epoch")),
        epoch: shellpkg::epoch(epoch),
        bytes: kr_protocol::scalars::U64::new(bytes),
    })
}

fn acknowledged(candidate: u8, prompt: u64, revision: u64, queues: QueueDrainReport) -> Stimulus {
    Stimulus::FenceAcknowledged(kr_protocol::root::FenceAcknowledgement {
        fence_id: shellpkg::fence_id(candidate),
        reader_context: ReaderContext::Primary,
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(revision),
        queues,
        snapshot: KeyQueueSnapshot::drained(),
        editor: empty_reader(1),
        cwd_revision: CwdRevision::new(2),
    })
}

fn idled(prompt: u64, revision: u64, candidate: u8) -> Stimulus {
    Stimulus::ReaderIdled(ReaderIdled {
        idle: ReaderIdle {
            session_id: race_session(),
            prompt_generation: PromptGeneration::new(prompt),
            reader_revision: ReaderRevision::new(revision),
            reader_context: ReaderContext::Primary,
            snapshot: KeyQueueSnapshot::drained(),
            editor: empty_reader(1),
            cwd_revision: CwdRevision::new(2),
        },
        candidate_fence: shellpkg::fence_id(candidate),
    })
}

/// One report of the reader's, as a package sends it at a key boundary or as it enters its read.
fn reported(prompt: u64, revision: u64, empty: bool, queued: u64, pending: u64) -> ReaderIdle {
    ReaderIdle {
        session_id: race_session(),
        prompt_generation: PromptGeneration::new(prompt),
        reader_revision: ReaderRevision::new(prompt),
        reader_context: ReaderContext::Primary,
        snapshot: KeyQueueSnapshot {
            keys: kr_protocol::scalars::Bytes::new(Vec::new()),
            pending_bytes: kr_protocol::scalars::U64::new(pending),
            queued_keys: kr_protocol::scalars::U64::new(queued),
        },
        editor: EditorState {
            buffer_revision: EditorBufferRevision::new(revision),
            buffer_empty: empty,
            keymap: EditorKeymap::Emacs,
            pending: PendingReaderInput::NONE,
        },
        cwd_revision: CwdRevision::new(2),
    }
}

/// KR-REQ-07.87: a key is offered only after the reader says it is inside the read it is meant for.
///
/// Every report here is one a package really sends, put to the rule directly rather than waited
/// for from a shell. The one this exists for is the report a reader sends as it enters: it goes
/// out before the editor takes the terminal, it carries an empty line and empty queues, and it
/// belongs to a prompt this session has not probed. Read as readiness it offers the chord to an
/// editor that is not reading, which is the failure this qualification kept meeting under load.
/// The rule's answer to it is another probe at that prompt, never a longer wait at the old one.
#[test]
fn a_report_the_probe_did_not_produce_never_says_the_reader_is_reading() {
    let probe = shellpkg::ReaderMark {
        prompt_generation: 7,
        buffer_revision: 40,
    };

    // The report a reader sends as it enters the prompt after the probe's. It looks exactly like
    // readiness and proves none of it.
    assert_eq!(
        shellpkg::readiness_of(probe, &reported(8, 41, true, 0, 0)),
        shellpkg::ReadinessStep::Moved,
        "a later prompt's first report was taken for the probe's reader being ready"
    );
    // A prompt before the probe's, whatever it says about itself.
    assert_eq!(
        shellpkg::readiness_of(probe, &reported(6, 99, true, 0, 0)),
        shellpkg::ReadinessStep::Behind
    );
    // The probe's own report, and one from before it at the same prompt.
    assert_eq!(
        shellpkg::readiness_of(probe, &reported(7, 40, true, 0, 0)),
        shellpkg::ReadinessStep::Behind
    );
    assert_eq!(
        shellpkg::readiness_of(probe, &reported(7, 39, true, 0, 0)),
        shellpkg::ReadinessStep::Behind
    );
    // At the probe's own prompt and after it, with the line or a queue still holding something.
    for (empty, queued, pending) in [(false, 0, 0), (true, 1, 0), (true, 0, 3)] {
        assert_eq!(
            shellpkg::readiness_of(probe, &reported(7, 41, empty, queued, pending)),
            shellpkg::ReadinessStep::Busy,
            "a reader still holding something was called ready"
        );
    }
    // The one report that says it: the clear ran, at the prompt the probe was drawn at, after the
    // report that proved that reader was inside its read.
    assert_eq!(
        shellpkg::readiness_of(probe, &reported(7, 41, true, 0, 0)),
        shellpkg::ReadinessStep::Ready
    );
}

/// A machine at a published fence, with the moment that fence was published.
fn fenced_machine() -> (FenceMachine, ContinuousMs) {
    let mut machine = FenceMachine::new(
        race_session(),
        LeaseView::held(shellpkg::epoch(1), shellpkg::attachment_id(1)),
    );
    machine.apply(at(0), &entered(1, 1, 1));
    let published = machine.apply(at(20), &acknowledged(1, 1, 1, QueueDrainReport::CLEAR));
    assert!(
        published
            .shapes()
            .iter()
            .any(|shape| matches!(shape, ActionShape::PublishFence { .. })),
        "an acknowledged exchange with clear queues did not publish: {:?}",
        published.shapes()
    );
    (machine, at(20))
}

/// KR-REQ-07.79, KR-REQ-07.83: the 250 ms release, in the order the input arrived, with one
/// `EDITOR_BUSY` attachment event and no refusal of the input itself.
#[test]
fn the_hold_releases_what_it_held_in_order_with_one_editor_busy_and_no_refusal() {
    let mut machine = FenceMachine::new(
        race_session(),
        LeaseView::held(shellpkg::epoch(1), shellpkg::attachment_id(1)),
    );
    let opened = machine.apply(at(0), &entered(1, 1, 1));
    assert!(
        opened
            .shapes()
            .iter()
            .any(|shape| matches!(shape, ActionShape::AskFence { .. })),
        "entry started no exchange: {:?}",
        opened.shapes()
    );

    for (index, label) in ["first", "second", "third"].iter().enumerate() {
        let held = machine.apply(at(10 + 10 * index as u64), &arrived(label, 4));
        assert!(
            held.shapes()
                .iter()
                .any(|shape| matches!(shape, ActionShape::Hold { .. })),
            "{label} was not held while the exchange was open: {:?}",
            held.shapes()
        );
    }
    assert_eq!(
        machine.held(),
        vec![
            InputRef::new("first"),
            InputRef::new("second"),
            InputRef::new("third")
        ],
        "the hold is not in arrival order"
    );
    assert_eq!(
        machine.deadline(),
        Some(at(250)),
        "the hold's deadline is not the 250 ms section 7 gives it"
    );

    let expired = machine.apply(at(250), &Stimulus::HoldExpired);
    let shapes = expired.shapes();
    let release = shapes
        .iter()
        .position(|shape| matches!(shape, ActionShape::Release { .. }))
        .unwrap_or_else(|| panic!("the hold released nothing: {shapes:?}"));
    let busy = shapes
        .iter()
        .position(|shape| matches!(shape, ActionShape::EmitEditorBusy { .. }))
        .unwrap_or_else(|| panic!("nothing told the attachment why: {shapes:?}"));
    assert!(
        release < busy,
        "the event that explains the release came before it: {shapes:?}"
    );
    assert_eq!(
        shapes
            .iter()
            .filter(|shape| matches!(shape, ActionShape::EmitEditorBusy { .. }))
            .count(),
        1,
        "the release explained itself more than once: {shapes:?}"
    );
    match expired
        .actions
        .iter()
        .find(|action| matches!(action.shape(), ActionShape::EmitEditorBusy { .. }))
    {
        Some(kr_shell_integration::contract::fence::Action::EmitEditorBusy(event)) => {
            assert_eq!(
                event.attachment_id,
                shellpkg::attachment_id(1),
                "the event went to an attachment that held nothing"
            );
            assert_eq!(
                event.input_epoch,
                shellpkg::epoch(1),
                "the event names another epoch than the one the input arrived under"
            );
        }
        other => panic!("the event is {other:?}"),
    }
    assert!(
        shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::WithholdFence { .. })),
        "the bridge was not told that no fence was published: {shapes:?}"
    );
    assert!(
        !shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::RefuseInput { .. })),
        "the release refused the input it was releasing: {shapes:?}"
    );
    assert!(
        !shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::Discard { .. })),
        "the release discarded input rather than delivering it: {shapes:?}"
    );
    match expired
        .actions
        .iter()
        .find(|action| matches!(action.shape(), ActionShape::Release { .. }))
    {
        Some(kr_shell_integration::contract::fence::Action::Release(batches)) => assert_eq!(
            batches,
            &vec![
                InputRef::new("first"),
                InputRef::new("second"),
                InputRef::new("third")
            ],
            "the held input was released out of its original order"
        ),
        other => panic!("the release is {other:?}"),
    }
    assert!(machine.held().is_empty(), "the hold still holds something");
}

/// KR-REQ-07.79, KR-REQ-07.82: a lease change inside a hold is acknowledged with what the worker
/// itself is holding, and it does not restart the hold.
///
/// The lease change stands whatever the reader says, so the acknowledgement is what the takeover
/// receipt is built from: the bytes the previous epoch lost and the batches behind them. The hold
/// belongs to the input rather than to the reader, so the deadline the first batch started is the
/// one the release happens at.
#[test]
fn a_lease_change_inside_a_hold_is_acknowledged_with_what_it_held() {
    let (mut machine, published) = fenced_machine();
    // Input arriving under a published fence is forwarded, so the hold this is about is the one a
    // second exchange opens. The lease change is what opens it.
    let opened = machine.apply(
        at(published.get() + 10),
        &Stimulus::LeaseChanged(kr_shell_integration::contract::fence::LeaseChanged {
            lease: LeaseView::held(shellpkg::epoch(2), shellpkg::attachment_id(2)),
            discarded_bytes: kr_protocol::scalars::U64::new(0),
            candidate_fence: shellpkg::fence_id(2),
        }),
    );
    assert!(
        opened
            .shapes()
            .iter()
            .any(|shape| matches!(shape, ActionShape::InvalidateFence { .. })),
        "the fence outlived the lease change: {:?}",
        opened.shapes()
    );
    machine.apply(at(published.get() + 20), &arrived_under("first", 4, 2));
    machine.apply(at(published.get() + 30), &arrived_under("second", 6, 2));

    let changed = machine.apply(
        at(published.get() + 40),
        &Stimulus::LeaseChanged(kr_shell_integration::contract::fence::LeaseChanged {
            lease: LeaseView::held(shellpkg::epoch(3), shellpkg::attachment_id(3)),
            discarded_bytes: kr_protocol::scalars::U64::new(3),
            candidate_fence: shellpkg::fence_id(3),
        }),
    );
    match changed
        .actions
        .iter()
        .find(|action| matches!(action.shape(), ActionShape::AcknowledgeLeaseChange { .. }))
    {
        Some(kr_shell_integration::contract::fence::Action::AcknowledgeLeaseChange(
            acknowledgement,
        )) => {
            assert_eq!(
                acknowledgement.lease,
                LeaseView::held(shellpkg::epoch(3), shellpkg::attachment_id(3)),
                "the acknowledgement names another lease than the one that took over"
            );
            assert_eq!(
                acknowledgement.discarded_bytes,
                kr_protocol::scalars::U64::new(13),
                "the receipt does not account for the worker's own queue and the batches it held"
            );
            assert_eq!(
                acknowledgement.discarded_input,
                vec![InputRef::new("first"), InputRef::new("second")],
                "the receipt does not name the batches the takeover cost"
            );
        }
        other => panic!("the lease change was acknowledged with {other:?}"),
    }
    // The change stands whatever the reader says, and the exchange it starts has a bound of its
    // own. What the receipt is about is the epoch that ended, which is what the count above says.
    assert!(
        machine.deadline().is_some(),
        "the exchange the lease change started has no bound"
    );
    assert!(
        machine.held().is_empty(),
        "input from the epoch that ended was kept rather than discarded: {:?}",
        machine.held()
    );
}

/// KR-REQ-07.79: a retried fence waits for mixed queues to drain rather than discarding them.
#[test]
fn a_retried_fence_waits_for_the_mixed_queues_rather_than_discarding_them() {
    let mut machine = FenceMachine::new(
        race_session(),
        LeaseView::held(shellpkg::epoch(1), shellpkg::attachment_id(1)),
    );
    machine.apply(at(0), &entered(1, 1, 1));
    machine.apply(at(10), &arrived("typed", 3));
    machine.apply(at(250), &Stimulus::HoldExpired);

    // The retry happens at the reader's own next idle report, which is one of the points section 7
    // names.
    let retried = machine.apply(at(300), &idled(1, 1, 2));
    let shapes = retried.shapes();
    assert!(
        shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::AskFence { .. })),
        "an idle reader did not retry the exchange: {shapes:?}"
    );
    assert!(
        !shapes.iter().any(|shape| matches!(
            shape,
            ActionShape::Discard { .. } | ActionShape::CancelNativeOperations { .. }
        )),
        "the retry threw away what the queues were holding: {shapes:?}"
    );

    // The queues the release left mixed are still holding something, so nothing is published and
    // nothing is thrown away.
    let mixed = machine.apply(
        at(310),
        &acknowledged(
            2,
            1,
            1,
            QueueDrainReport {
                tty_typeahead_drained: false,
                macro_input_drained: true,
                partial_key_drained: true,
            },
        ),
    );
    let shapes = mixed.shapes();
    assert!(
        shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::WithholdFence { .. })),
        "a fence was published over queues that had not drained: {shapes:?}"
    );
    assert!(
        !shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::PublishFence { .. })),
        "a fence was published over queues that had not drained: {shapes:?}"
    );
    assert!(
        !shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::Discard { .. })),
        "the retry discarded the mixed queues instead of waiting: {shapes:?}"
    );

    // They drain, and the next retry publishes.
    machine.apply(at(320), &idled(1, 1, 3));
    let published = machine.apply(at(330), &acknowledged(3, 1, 1, QueueDrainReport::CLEAR));
    assert!(
        published
            .shapes()
            .iter()
            .any(|shape| matches!(shape, ActionShape::PublishFence { .. })),
        "drained queues still published nothing: {:?}",
        published.shapes()
    );
}

/// KR-REQ-07.83: a launch that reaches its reservation timeout installs no command.
#[test]
fn a_launch_that_reaches_its_reservation_timeout_installs_no_command() {
    let (mut machine, published) = fenced_machine();
    let transaction = kr_shell_integration::contract::requests::LaunchTransactionId::new(
        kr_protocol::scalars::Uuid::from_bytes([0x17; 16]),
    );
    let fence = machine.fence().expect("a published fence").clone();
    let requested = machine.apply(
        at(published.get() + 5),
        &Stimulus::LaunchRequested(LaunchRequested {
            params: ShellLaunchParams {
                session_id: race_session(),
                command: kr_protocol::root::LaunchCommand::Arguments(vec![
                    "printf".to_owned(),
                    "kr-must-not-install".to_owned(),
                ]),
                expected_prompt_generation: fence.prompt_generation,
                expected_buffer_revision: EditorBufferRevision::new(1),
            },
            requester: shellpkg::attachment_id(1),
            transaction,
        }),
    );
    assert!(
        requested
            .shapes()
            .iter()
            .any(|shape| matches!(shape, ActionShape::SendLaunch { .. })),
        "the launch never reached the reader's mailbox: {:?}",
        requested.shapes()
    );
    let deadline = machine.deadline().expect("a reservation has a deadline");
    assert_eq!(
        deadline.get() - (published.get() + 5),
        250,
        "the reservation holds input for something other than the 250 ms section 7 gives it"
    );

    // Input that arrives while the reservation stands is held, and the reservation's own timeout
    // is what releases it.
    machine.apply(at(deadline.get() - 10), &arrived("during", 2));
    let expired = machine.apply(deadline, &Stimulus::HoldExpired);
    let shapes = expired.shapes();
    assert!(
        shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::Release { .. })),
        "the reservation's timeout released nothing: {shapes:?}"
    );
    assert!(
        shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::RevokeLaunch { .. })),
        "the bridge was not told the transaction was over: {shapes:?}"
    );
    assert!(
        !shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::InstallLaunch { .. })),
        "a command was installed at the reservation's timeout: {shapes:?}"
    );

    // The reader answers that it installed nothing, and that is what the caller is told, with the
    // code section 7 names.
    let answered = machine.apply(
        at(deadline.get() + 30),
        &Stimulus::LaunchDecided(
            kr_shell_integration::contract::requests::LaunchDecision::Rejected(
                kr_shell_integration::contract::requests::LaunchRejection {
                    transaction,
                    fence_id: fence.fence_id,
                    reason:
                        kr_shell_integration::contract::requests::LaunchRejectionReason::Timeout,
                    prompt_generation: fence.prompt_generation,
                    buffer_revision: EditorBufferRevision::new(1),
                },
            ),
        ),
    );
    let shapes = answered.shapes();
    assert!(
        !shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::InstallLaunch { .. })),
        "a refused launch installed a command: {shapes:?}"
    );
    match answered
        .actions
        .iter()
        .find(|action| matches!(action.shape(), ActionShape::RejectLaunch { .. }))
    {
        Some(kr_shell_integration::contract::fence::Action::RejectLaunch { code, .. }) => {
            assert_eq!(
                *code,
                kr_protocol::error::ErrorCode::EditorBusy,
                "the caller was refused with another code"
            );
        }
        other => panic!("the caller was answered with {other:?}"),
    }
}

/// KR-REQ-07.83: what a reader answers after its reservation ended is still the reader's word, and
/// the session records that it came late.
///
/// The revocation and the install cross on the wire, so the worker cannot make the answer arrive
/// sooner and cannot take a line out of an editor that already holds it. The published contract
/// therefore gives the caller the reader's own outcome and records the late installation beside
/// it: a caller told nothing was installed while the editor holds a command would be the worse
/// answer of the two.
#[test]
fn a_launch_answered_after_its_reservation_ended_is_recorded_as_late() {
    let (mut machine, published) = fenced_machine();
    let transaction = kr_shell_integration::contract::requests::LaunchTransactionId::new(
        kr_protocol::scalars::Uuid::from_bytes([0x18; 16]),
    );
    let fence = machine.fence().expect("a published fence").clone();
    machine.apply(
        at(published.get() + 5),
        &Stimulus::LaunchRequested(LaunchRequested {
            params: ShellLaunchParams {
                session_id: race_session(),
                command: kr_protocol::root::LaunchCommand::Arguments(vec!["printf".to_owned()]),
                expected_prompt_generation: fence.prompt_generation,
                expected_buffer_revision: EditorBufferRevision::new(1),
            },
            requester: shellpkg::attachment_id(1),
            transaction,
        }),
    );
    let deadline = machine.deadline().expect("a reservation has a deadline");
    machine.apply(deadline, &Stimulus::HoldExpired);

    let late = machine.apply(
        at(deadline.get() + 40),
        &Stimulus::LaunchDecided(
            kr_shell_integration::contract::requests::LaunchDecision::Accepted(
                kr_shell_integration::contract::requests::LaunchAccepted {
                    transaction,
                    installed: kr_protocol::root::LaunchCommand::Arguments(vec![
                        "printf".to_owned(),
                    ]),
                    fence_id: fence.fence_id,
                    prompt_generation: fence.prompt_generation,
                    buffer_revision: EditorBufferRevision::new(2),
                    reader_revision: fence.reader_revision,
                },
            ),
        ),
    );
    let shapes = late.shapes();
    assert!(
        shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::LateInstallation { .. })),
        "a command installed after the reservation ended was not recorded: {shapes:?}"
    );
    let late = shapes
        .iter()
        .position(|shape| matches!(shape, ActionShape::LateInstallation { .. }))
        .expect("the record is there");
    let installed = shapes
        .iter()
        .position(|shape| matches!(shape, ActionShape::InstallLaunch { .. }))
        .unwrap_or_else(|| panic!("the caller was told nothing at all: {shapes:?}"));
    assert!(
        late < installed,
        "the answer came before the record that it was late: {shapes:?}"
    );
    assert!(
        !shapes
            .iter()
            .any(|shape| matches!(shape, ActionShape::RejectLaunch { .. })),
        "the caller was both answered and refused: {shapes:?}"
    );
}

/// What this qualification cannot reach, recorded rather than left out.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Unreachable {
    description: String,
    unreachable: Vec<UnreachableBehaviour>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UnreachableBehaviour {
    id: String,
    what: String,
    why_here: String,
    owner: String,
    next_step: String,
}

/// KR-REQ-07.83, KR-REQ-07.79: the behaviours section 7 names that this suite cannot provoke are
/// named here with the reason and whose they are.
///
/// Both are conditions of the host rather than of a package: one needs a worker holding its own
/// session while a desktop reading is taken, the other needs a control daemon deciding whether the
/// machine may sleep. This suite drives a package against a bridge endpoint, so neither exists in
/// it. A qualification that simply left them out would read as though it had covered them.
#[test]
fn what_this_qualification_cannot_reach_is_recorded_with_its_reason_and_its_owner() {
    let path = corpus_root().join("unreachable.json");
    let body = std::fs::read_to_string(&path).expect("the record is committed beside the corpus");
    let record: Unreachable = serde_json::from_str(&body)
        .unwrap_or_else(|error| panic!("{} does not decode: {error}", path.display()));
    assert!(record.description.split_whitespace().count() >= 10);
    assert!(
        record.unreachable.len() >= 2,
        "the record names {} behaviours",
        record.unreachable.len()
    );
    for behaviour in &record.unreachable {
        assert!(!behaviour.id.is_empty());
        for (field, text) in [
            ("what", &behaviour.what),
            ("why_here", &behaviour.why_here),
            ("next_step", &behaviour.next_step),
        ] {
            assert!(
                text.split_whitespace().count() >= 12,
                "{}'s {field} does not say enough to act on",
                behaviour.id
            );
        }
        assert!(
            [
                "kr-worker",
                "kr-controller",
                "kr-shell-integration",
                "packaging"
            ]
            .contains(&behaviour.owner.as_str()),
            "{} belongs to {}, which is not a component of this build",
            behaviour.id,
            behaviour.owner
        );
    }
    let ids: Vec<&str> = record
        .unreachable
        .iter()
        .map(|behaviour| behaviour.id.as_str())
        .collect();
    for named in [
        "desktop-probe-outlasts-the-launch-hold",
        "the-sleep-demand-scan-cannot-see-an-outstanding-launch",
    ] {
        assert!(ids.contains(&named), "{named} is not recorded");
    }
}

/// KR-REQ-07.87, KR-REQ-07.16: an installation that holds every managed package still admits each
/// of them.
///
/// The installation is read shell by shell: a record the host cannot resolve refuses the shell it
/// belongs to and leaves the packages beside it alone. The package that builds no shell is
/// the one that can say something the rule refuses, because the host and the editor it qualifies
/// are the person's and live outside it. What it installs of its own — the launcher that starts
/// that host, the module that binds into that editor, the marked startup entry — is what it
/// records, and this is the case that says so for a whole installation rather than one package.
#[test]
fn an_installation_holding_every_package_still_resolves_each_of_them() {
    let installed: Vec<Package> = ShellKind::ALL
        .iter()
        .filter_map(|kind| Package::find(*kind).ok())
        .collect();
    if installed.len() < ShellKind::ALL.len() {
        let missing: Vec<&str> = ShellKind::ALL
            .iter()
            .filter(|kind| !installed.iter().any(|package| package.kind == **kind))
            .map(|kind| kind.as_str())
            .collect();
        let reason = format!("this host holds no {} package", missing.join(", no "));
        assert!(
            std::env::var_os(shellpkg::REQUIRE).is_none(),
            "{} is set and {reason}",
            shellpkg::REQUIRE
        );
        println!("skipped: {reason}");
        return;
    }

    let set = kr_shell_integration::host::package::PackageSet::discover(&shellpkg::package_root())
        .unwrap_or_else(|fault| {
            panic!(
                "an installation holding every managed package could not be read, so no managed \
                 session could be created on it at all: {fault}"
            )
        });
    for package in &installed {
        let resolved = set.get(package.kind).unwrap_or_else(|| {
            panic!(
                "the installation holds a {} package and the host resolved none",
                package.kind.as_str()
            )
        });
        let executable = resolved.executable();
        assert!(
            executable.is_file(),
            "the {} package resolves to {}, which is not there",
            package.kind.as_str(),
            executable.display()
        );
        // Every path a package records is its own, so the one the host would launch is inside the
        // package it came from rather than in somebody else's installation.
        let directory = shellpkg::package_root()
            .join(package.kind.as_str())
            .join(&package.identity);
        assert!(
            executable.starts_with(&directory),
            "the {} package would launch {}, which is outside {}",
            package.kind.as_str(),
            executable.display(),
            directory.display()
        );
    }
}
