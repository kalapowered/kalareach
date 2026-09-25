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
