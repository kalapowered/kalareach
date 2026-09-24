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

/// KR-REQ-12.07, KR-REQ-07.45
#[test]
fn an_interactive_command_asks_once_before_it_starts_and_a_bypass_runs_it_as_typed() {
    shellpkg::an_interactive_command_asks_once_and_runs_as_typed(BASH);
}

/// KR-REQ-12.07
#[test]
fn a_pipeline_subshell_substitution_background_job_sourced_script_or_script_never_asks() {
    shellpkg::forms_the_root_shell_does_not_start_itself_never_ask(BASH);
}

/// KR-REQ-12.07
#[test]
fn assignments_in_front_of_a_command_run_the_file_and_vector_they_select() {
    shellpkg::assignments_in_front_of_a_command_run_what_they_select(BASH);
}

/// KR-REQ-07.44
#[test]
fn diagnostics_that_cannot_be_written_never_hold_a_command_up() {
    shellpkg::diagnostics_that_cannot_be_written_never_hold_a_command_up(BASH);
}

/// KR-REQ-07.34, KR-REQ-07.35
#[test]
fn frames_that_arrive_while_a_command_waits_reach_the_reader_once() {
    shellpkg::frames_that_arrive_while_a_command_waits_reach_the_reader_once(BASH);
}

/// KR-REQ-12.07
#[test]
fn an_absolute_path_invocation_runs_as_typed() {
    shellpkg::an_absolute_path_invocation_runs_as_typed(BASH);
}

/// KR-REQ-12.07
#[test]
fn a_worker_that_does_not_answer_leaves_the_command_as_typed_after_the_deadline() {
    shellpkg::an_unanswered_question_runs_the_command_as_typed_after_the_deadline(BASH);
}

/// KR-REQ-12.07, KR-REQ-07.45
#[test]
fn a_backend_runs_the_command_through_the_launcher_it_names() {
    shellpkg::a_backend_runs_the_command_through_the_launcher_it_names(BASH);
}

/// KR-REQ-25.05
#[test]
fn each_line_reports_its_command_block_with_status_duration_and_directory() {
    shellpkg::each_line_reports_its_block_with_status_duration_and_directory(BASH);
}

/// KR-REQ-07.84
#[test]
fn a_line_exports_the_capability_minted_for_it_and_no_other() {
    shellpkg::a_line_exports_the_capability_minted_for_it(BASH);
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
