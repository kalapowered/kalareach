//! The managed Bash package, driven through the built shell in a real pseudo-terminal.
//!
//! Section 7 puts a published patch to Bash's bundled Readline behind this package: a mailbox the
//! reader reads once it has consumed everything it had buffered, the same reader events, a
//! cancellation that keeps the edit buffer, and the end-of-file decision immediately before
//! Readline's own end-of-file branch, after the next character has been selected from its input
//! sources. Each test below drives one of those through the shell the build script installed,
//! against the expectations in `fixtures/shell-bridge/`.
//!
//! A run with no built package prints why and stops; continuous integration builds the package in
//! the same job and sets `KR_REQUIRE_SHELL_PACKAGES`, where an absent package is a failure.

// The two packages this file drives are Unix shells with patched Unix readers, and the harness
// speaks to them over a Unix socket in a pseudo-terminal. Windows is a separate package.
#![cfg(unix)]

mod shellpkg;

use kr_shell_integration::contract::qualification::ShellKind;

const BASH: ShellKind = ShellKind::Bash;

/// KR-REQ-07.35, KR-REQ-07.85
#[test]
fn the_handshake_declares_the_published_readline_patches_and_the_reader_they_build() {
    shellpkg::the_handshake_declares_the_packaged_reader(BASH);
}

/// KR-REQ-07.35
#[test]
fn a_child_of_the_managed_root_shell_inherits_no_activation() {
    shellpkg::a_child_shell_has_nothing_to_activate_from(BASH);
}

/// KR-REQ-07.35
#[test]
fn the_readline_reader_reports_its_boundaries_and_proves_its_own_queues() {
    shellpkg::the_reader_reports_its_boundaries_and_proves_its_own_state(BASH);
}

/// KR-REQ-07.71
#[test]
fn an_eligible_gesture_under_a_fence_becomes_an_attributable_detach() {
    shellpkg::an_eligible_gesture_under_a_fence_is_an_attributable_detach(BASH);
}

/// KR-REQ-07.71
#[test]
fn an_unattributable_gesture_is_consumed_with_one_hint_per_prompt() {
    shellpkg::an_unattributable_gesture_is_consumed_with_one_hint_per_prompt(BASH);
}

/// KR-REQ-07.71
#[test]
fn a_detach_the_worker_refuses_is_consumed_with_the_hint() {
    shellpkg::a_refused_detach_is_consumed_with_the_hint(BASH);
}

/// KR-REQ-07.71
#[test]
fn outside_the_detach_condition_readline_keeps_the_key() {
    shellpkg::the_detach_condition_excludes_what_the_corpus_names(BASH);
}

/// KR-REQ-07.71
#[test]
fn the_gesture_follows_the_terminals_own_end_of_file_character() {
    shellpkg::the_gesture_follows_the_line_discipline(BASH);
}

/// KR-REQ-07.71
#[test]
fn the_decision_before_readlines_eof_branch_leaves_ignore_eof_alone() {
    shellpkg::the_ignore_eof_setting_is_left_as_the_person_set_it(BASH);
}

/// KR-REQ-07.35
#[test]
fn a_launch_is_installed_and_accepted_on_the_reader_thread() {
    shellpkg::a_launch_is_installed_and_accepted_on_the_reader_thread(BASH);
}

/// KR-REQ-07.35
#[test]
fn the_reader_refuses_a_launch_its_own_state_does_not_match() {
    shellpkg::the_reader_refuses_a_launch_its_own_state_does_not_match(BASH);
}

/// KR-REQ-07.35
#[test]
fn a_revoked_launch_installs_nothing() {
    shellpkg::a_revoked_launch_installs_nothing(BASH);
}

/// KR-REQ-07.35
#[test]
fn a_revocation_in_the_same_read_binds_its_launch_whichever_order_it_arrives_in() {
    shellpkg::a_revocation_in_the_same_read_binds_the_launch(BASH);
}

/// KR-REQ-07.35
#[test]
fn the_reader_reports_itself_idle_so_a_withheld_fence_can_be_retried() {
    shellpkg::the_reader_reports_itself_idle(BASH);
}

/// KR-REQ-07.35
#[test]
fn a_shell_whose_bridge_has_gone_still_consumes_an_eligible_gesture() {
    shellpkg::a_lost_bridge_does_not_restore_a_native_empty_prompt_end_of_file(BASH);
}

/// KR-REQ-07.35
#[test]
fn a_takeover_ends_a_pending_key_wait_and_keeps_the_edit_buffer() {
    shellpkg::a_takeover_ends_a_pending_key_wait_and_keeps_the_buffer(BASH);
}

/// KR-REQ-07.35
#[test]
fn a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone() {
    shellpkg::a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone(BASH);
}

/// KR-REQ-07.85, KR-REQ-26.11
#[test]
fn the_package_declares_the_managed_bash_baseline_and_its_reproducible_identity() {
    shellpkg::the_package_declares_the_baseline_the_specification_names(BASH);
}

/// KR-REQ-07.34, KR-REQ-07.35
#[test]
fn every_committed_scenario_naming_bash_holds_against_the_contract() {
    shellpkg::every_scenario_naming_this_shell_holds(BASH);
}
