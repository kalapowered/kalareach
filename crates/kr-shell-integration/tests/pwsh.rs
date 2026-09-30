//! The qualified PSReadLine package, driven through the installed host in a real pseudo-terminal.
//!
//! Section 7 puts a reader-thread request queue and a signal behind this package rather than a
//! patched shell: PSReadLine is the editor the person already has, and the module binds into it.
//! The queue is answered on the reader's own thread, with the editor's real buffer and invocation
//! state, and the end-of-file decision is taken there too, under the configured gesture. Each test
//! below drives one of those through the host the qualification recorded, against the expectations
//! in `fixtures/shell-bridge/`.
//!
//! The cases that drive the package need this tree's qualified package, which an ordinary run does
//! not have, so they are left out of one. A run that published the qualification runs them with
//! `--include-ignored`, as continuous integration's shell-packages job does, and there a package
//! that is not this tree's fails the case that needed it.
//!
//! Running the module on Windows is qualified separately, with the host's own named pipe and the
//! configured chord; this file drives the Unix host, where the harness speaks over a Unix socket.

#![cfg(unix)]

mod shellpkg;

use kr_shell_integration::contract::qualification::ShellKind;

const PWSH: ShellKind = ShellKind::PowerShell;

/// KR-REQ-07.37, KR-REQ-07.85
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_handshake_declares_the_qualified_editor_and_the_module_tree_it_binds_into() {
    shellpkg::the_handshake_declares_the_packaged_reader(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_child_of_the_managed_root_shell_inherits_no_activation() {
    shellpkg::a_child_shell_has_nothing_to_activate_from(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_reader_reports_its_boundaries_and_proves_its_own_queues() {
    shellpkg::the_reader_reports_its_boundaries_and_proves_its_own_state(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn an_eligible_gesture_under_a_fence_becomes_an_attributable_detach() {
    shellpkg::an_eligible_gesture_under_a_fence_is_an_attributable_detach(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn an_unattributable_gesture_is_consumed_with_one_hint_per_prompt() {
    shellpkg::an_unattributable_gesture_is_consumed_with_one_hint_per_prompt(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_detach_the_worker_refuses_is_consumed_with_the_hint() {
    shellpkg::a_refused_detach_is_consumed_with_the_hint(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn outside_the_detach_condition_the_state_handler_keeps_the_key() {
    shellpkg::the_detach_condition_excludes_what_the_corpus_names(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_launch_is_installed_and_accepted_on_the_reader_thread() {
    shellpkg::a_launch_is_installed_and_accepted_on_the_reader_thread(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_reader_refuses_a_launch_its_own_state_does_not_match() {
    shellpkg::the_reader_refuses_a_launch_its_own_state_does_not_match(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_revoked_launch_installs_nothing() {
    shellpkg::a_revoked_launch_installs_nothing(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_revocation_in_the_same_read_binds_its_launch_whichever_order_it_arrives_in() {
    shellpkg::a_revocation_in_the_same_read_binds_the_launch(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_reader_reports_itself_idle_so_a_withheld_fence_can_be_retried() {
    shellpkg::the_reader_reports_itself_idle(PWSH);
}

/// KR-REQ-07.37
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_shell_whose_bridge_has_gone_still_consumes_an_eligible_gesture() {
    shellpkg::a_lost_bridge_does_not_restore_a_native_empty_prompt_end_of_file(PWSH);
}

/// KR-REQ-07.37
///
/// This editor runs a nested read of its own for each operation that waits for another key, and
/// nothing of this package's runs on the reader's thread while one is running, so it has no key
/// wait a takeover or a cancellation can end. What a cancellation does to a reader with nothing in
/// progress is this case; the takeover case the other packages have is not one of this editor's.
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone() {
    shellpkg::a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73, `psreadline-chord-gesture`
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_configured_chord_detaches_and_any_other_key_is_the_editors_own() {
    shellpkg::the_configured_chord_carries_the_detach_and_any_other_key_is_the_editors_own(PWSH);
}

/// The editors this suite stands in for the real one with: each is a .NET type with the two fields
/// the module reads its queue from, or something short of that.
///
/// `live` is what the qualified editor looks like from the module's side: a static instance whose
/// queue holds two keys. The others each leave out one thing a fence rests on, and each was
/// accepted by a check that only asked whether the two fields existed.
const STAND_IN_EDITORS: &str = r#"
using System.Collections.Generic;
public class KrEditorLive { private static KrEditorLive _singleton = new KrEditorLive(); private Queue<object> _queuedKeys = new Queue<object>(new object[] { 1, 2 }); }
public class KrEditorRenamed { private static KrEditorRenamed _singleton = new KrEditorRenamed(); private Queue<object> _pendingKeys = new Queue<object>(); }
public class KrEditorNoInstance { private static KrEditorNoInstance _singleton = null; private Queue<object> _queuedKeys = new Queue<object>(); }
public class KrEditorNoQueue { private static KrEditorNoQueue _singleton = new KrEditorNoQueue(); private Queue<object> _queuedKeys = null; }
public class KrEditorNotAQueue { private static KrEditorNotAQueue _singleton = new KrEditorNotAQueue(); private string _queuedKeys = "none"; }
"#;

/// KR-REQ-07.85: the package qualifies an editor only when the queue a fence rests on answers.
///
/// A check that the queue's two fields exist accepts an editor whose instance is not made yet,
/// whose queue is null or whose field holds something that is not a queue, and the reader would then
/// report every queue clear because it read nothing. The module reads the live queue instead, through
/// the function a fence reads it with. Each stand-in editor here is put in the module's place in
/// turn, and the control is the editor the package was qualified against, which the module read
/// before any of them was.
#[test]
#[ignore = "needs this tree's built shell packages; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_package_refuses_an_editor_whose_key_queue_it_cannot_read() {
    let package = shellpkg::Package::built(PWSH);
    let directory = package
        .executable
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the package directory");
    let module = directory
        .join("modules/KalaReach.ShellBridge/KalaReach.ShellBridge.psd1")
        .display()
        .to_string();
    let script = format!(
        "$ErrorActionPreference = 'Stop'; Import-Module '{module}'; \
         Add-Type -IgnoreWarnings -WarningAction SilentlyContinue -TypeDefinition @'{STAND_IN_EDITORS}'@; \
         $module = Get-Module KalaReach.ShellBridge; \
         $real = & $module {{ @{{ Reason = (Test-KrQualifiedEditor).Reason; Keys = Get-KrQueuedKeys }} }}; \
         Write-Output \"kr-queue[real]=[$($real.Reason)] keys=[$($real.Keys)]\"; \
         foreach ($name in 'KrEditorLive', 'KrEditorRenamed', 'KrEditorNoInstance', 'KrEditorNoQueue', 'KrEditorNotAQueue') {{ \
             $answer = & $module {{ param($editor) \
                 $script:SingletonField = $null; $script:QueuedKeysField = $null; $script:Rl = $editor; \
                 @{{ Reason = (Test-KrQualifiedEditor).Reason; Keys = Get-KrQueuedKeys }} }} ([type]$name); \
             Write-Output \"kr-queue[$name]=[$($answer.Reason)] keys=[$($answer.Keys)]\" \
         }}"
    );
    let asked = std::process::Command::new(&package.executable)
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .env_remove("KR_SHELL_BRIDGE")
        .env_remove("KR_SHELL_BRIDGE_SECRET")
        .env_remove("KR_SESSION")
        .output()
        .expect("the package's host runs");
    let said = String::from_utf8_lossy(&asked.stdout).into_owned();
    let told = String::from_utf8_lossy(&asked.stderr);
    let answer = |name: &str| -> (String, String) {
        let line = said
            .lines()
            .find_map(|line| line.strip_prefix(&format!("kr-queue[{name}]=[")))
            .unwrap_or_else(|| panic!("the module said nothing about {name}:\n{said}\n{told}"));
        let (reason, keys) = line.split_once("] keys=[").expect("the answer's shape");
        (reason.to_owned(), keys.trim_end_matches(']').to_owned())
    };

    assert_eq!(
        answer("real"),
        (String::new(), "0".to_owned()),
        "the editor the package was qualified against reads as an empty queue and is accepted"
    );
    assert_eq!(
        answer("KrEditorLive"),
        (String::new(), "2".to_owned()),
        "an editor whose queue answers is read for what it holds, not for whether it has fields"
    );
    for stand_in in [
        "KrEditorRenamed",
        "KrEditorNoInstance",
        "KrEditorNoQueue",
        "KrEditorNotAQueue",
    ] {
        assert_eq!(
            answer(stand_in),
            ("psreadline_queue_unreadable".to_owned(), "0".to_owned()),
            "{stand_in} keeps no queue the module can read, and the package qualified it anyway"
        );
    }
}

/// KR-REQ-07.85, KR-REQ-26.11
#[test]
#[ignore = "drives this tree's qualified PSReadLine package; it runs with --include-ignored where the packages are built and qualified, as continuous integration's shell-packages job does"]
fn the_package_declares_the_qualified_baseline_and_its_reproducible_identity() {
    shellpkg::the_package_declares_the_baseline_the_specification_names(PWSH);
}

/// KR-REQ-07.37, KR-REQ-07.73
#[test]
fn every_committed_scenario_naming_powershell_holds_against_the_contract() {
    shellpkg::every_scenario_naming_this_shell_holds(PWSH);
}

/// KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_startup_prompt_reads_its_answer_and_the_session_is_ready_only_after_the_profile() {
    shellpkg::a_startup_prompt_reads_its_answer_and_readiness_waits_for_the_profile(PWSH);
}

/// KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_startup_prompt_nobody_answers_holds_readiness_without_hanging_the_shell() {
    shellpkg::a_startup_prompt_nobody_answers_holds_readiness_and_does_not_hang_the_shell(PWSH);
}

/// KR-REQ-07.22, KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_profile_that_fails_after_startup_closes_the_creating_session_with_its_diagnostics() {
    shellpkg::a_profile_that_fails_after_startup_closes_the_creating_session_with_its_diagnostics(
        PWSH,
    );
}

/// KR-REQ-07.23, KR-REQ-07.85
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_editor_the_profile_replaced_is_diagnosed_when_the_hooks_activate() {
    shellpkg::an_editor_the_profile_replaced_is_diagnosed_when_the_hooks_activate(PWSH);
}

/// The cursor position query the editor asks at every prompt reaches the terminal in pieces on a
/// loaded machine, and the editor waits for its answer before it reads a key.
#[test]
fn the_terminal_answers_a_cursor_query_whichever_way_the_output_is_cut() {
    shellpkg::a_terminal_query_the_output_splits_across_reads_is_answered_once(
        b"\x1b[6n",
        b"\x1b[1;1R",
    );
}

/// KR-REQ-01.06
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn ordinary_commands_and_agent_names_run_as_they_do_without_the_integration() {
    shellpkg::ordinary_commands_and_agent_names_run_as_in_an_unmanaged_shell(PWSH);
}

/// KR-REQ-01.06
#[test]
#[ignore = "drives this tree's built PSReadLine package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_alias_that_changes_an_agent_name_is_reported_by_the_comparison() {
    shellpkg::a_planted_alias_that_changes_an_agent_name_is_reported_not_hidden(PWSH);
}
