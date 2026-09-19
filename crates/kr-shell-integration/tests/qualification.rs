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
            case.checks.contains(&"plugin_active".to_owned()),
            case.plugin.is_some(),
            "{} claims a customisation is active and asks the shell nothing, or the other way \
             round",
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
    // An ordinary workspace run has neither the packages nor the stacks: this suite says so and
    // stops. A run that asked for them is the one that fails when nothing ran.
    if std::env::var_os(shellpkg::REQUIRE).is_some() || std::env::var_os(REQUIRE_STACKS).is_some() {
        assert!(
            ran > 0,
            "the packages or the stacks were required and no case ran"
        );
    } else if ran == 0 {
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

/// Drives one case's shell through the checks it claims, in this suite's own order.
fn run_case(case: &QualificationCase, package: &Package) {
    let index = StackIndex::read().expect("the index was read before this case was chosen");
    let setup = CaseSetup::prepare(case, package, &index);
    let mut session = Session::start_for(package, case, &setup);
    let mut enter = session.first_prompt();
    // Several of these prompts are drawn by a program that runs at every prompt, so the reader is
    // given until its drawing stops before anything is typed at it.
    settle(&mut session, Duration::from_millis(300), REPLY);
    session.ensure_reading();

    let claimed = |name: &str| case.checks.iter().any(|check| check == name);

    if claimed("identity") {
        // What the package declares is checked against the record the build wrote beside the
        // binary, rather than against itself: the handshake this harness answers takes the hello's
        // own editor ABI as supported, so the record is what makes this an identity at all.
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
        let record = &package.record["shell"];
        for (field, declared) in [
            ("executable", package.executable.display().to_string()),
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
            let declared = if field == "executable" {
                package.executable.display().to_string()
            } else {
                declared
            };
            assert_eq!(
                declared, recorded,
                "{} declared a {field} the installed package does not record",
                case.id
            );
        }
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
        let modules: Vec<String> = session
            .hello
            .shell
            .modules
            .iter()
            .map(|module| module.name.clone())
            .collect();
        let recorded: Vec<String> = package.record["shell"]["modules"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|module| module["name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(
            modules, recorded,
            "{} declared a module tree the installed package does not record",
            case.id
        );
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
        let diagnosis =
            std::fs::read_to_string(setup.home.join("module-error")).unwrap_or_default();
        assert!(
            diagnosis.contains(&module.name),
            "{}: what was said about {} does not name it: {diagnosis:?}",
            case.id,
            module.name
        );
        // The integration is what it was before: the reader is there and answers.
        let acknowledgement = session.fence_exchange(&enter, shellpkg::fence_id(3));
        assert_eq!(acknowledgement.prompt_generation, enter.prompt_generation);
    }

    if claimed("plugin_active") {
        let probe = case
            .plugin
            .as_ref()
            .expect("the corpus check refused a case without one");
        assert!(
            session.plugin_is_active(probe),
            "{}: the customisation this case is about is not loaded; {} printed nothing like \
             {}; the terminal showed:\n{}",
            case.id,
            probe.probe,
            probe.marker,
            session.terminal_output()
        );
        enter = session.next_prompt();
        settle(&mut session, Duration::from_millis(300), REPLY);
        session.ensure_reading();
    }

    if claimed("plugin_writes_buffer") {
        enter = plugin_writes_the_buffer(case, &mut session, &enter);
    }

    if claimed("plugin_buffer") {
        // A customisation that rewrites the line on every keystroke is exactly what section 7
        // says a prompt hook cannot tell from an empty prompt. The reader's own answer is what
        // the fence carries, so it is asked with the line held and again once it is cleared,
        // under the same customisation.
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
        assert!(
            session.user_binding_ran(),
            "{}: the person's own binding {} did not survive the integration; the terminal \
             showed:\n{}",
            case.id,
            case.binding,
            session.terminal_output()
        );
        session.clear_line();
    }

    assert!(
        session.alive(),
        "{}: the shell did not survive its own qualification",
        case.id
    );

    if claimed("instant_prompt") {
        // The shell has to have gone before the second one starts: the cache the theme draws its
        // early prompt from is written by the run that is ending.
        drop(session);
        a_second_start_draws_from_the_cache_the_first_wrote(case, package, &setup);
    }
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
    enter: &kr_protocol::root::RootEditorEnterParams,
) -> kr_protocol::root::RootEditorEnterParams {
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
    let _ = enter;
    let entered = session.next_prompt();
    settle(session, Duration::from_millis(300), REPLY);
    session.ensure_reading();
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
    let enter = session.first_prompt();
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
