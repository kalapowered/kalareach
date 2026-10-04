//! The managed fish package, driven through the built shell in a real pseudo-terminal.
//!
//! Section 7 puts a reader-event bridge behind this package, against the shell's own Rust reader:
//! a mailbox the reader waits on alongside the terminal and reads at every key-sequence boundary,
//! immediate line acceptance through the editor's own execute, non-destructive cancellation of a
//! pending key wait, enter, leave and fence events, and an end-of-file decision taken by a named
//! binding with the actual reader context. Each test below drives one of those through the shell
//! the build script installed, against the expectations in `fixtures/shell-bridge/`.
//!
//! The cases that drive the package need this tree's built package, which an ordinary run does not
//! have, so they are left out of one. A run that built the packages runs them with
//! `--include-ignored`, as continuous integration's shell-packages job does, and there a package
//! that is not this tree's fails the case that needed it.

// This package is a Unix shell with a patched Unix reader, and the harness speaks to it over a
// Unix socket in a pseudo-terminal.
#![cfg(unix)]

mod shellpkg;

use kr_shell_integration::contract::qualification::ShellKind;

const FISH: ShellKind = ShellKind::Fish;

/// KR-REQ-07.36, KR-REQ-07.85
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_handshake_declares_the_published_reader_patches_and_the_reader_they_build() {
    shellpkg::the_handshake_declares_the_packaged_reader(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_child_of_the_managed_root_shell_inherits_no_activation() {
    shellpkg::a_child_shell_has_nothing_to_activate_from(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_reader_reports_its_boundaries_and_proves_its_own_queues() {
    shellpkg::the_reader_reports_its_boundaries_and_proves_its_own_state(FISH);
}

/// KR-REQ-07.36, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_eligible_gesture_under_a_fence_becomes_an_attributable_detach() {
    shellpkg::an_eligible_gesture_under_a_fence_is_an_attributable_detach(FISH);
}

/// KR-REQ-07.36, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_unattributable_gesture_is_consumed_with_one_hint_per_prompt() {
    shellpkg::an_unattributable_gesture_is_consumed_with_one_hint_per_prompt(FISH);
}

/// KR-REQ-07.36, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_detach_the_worker_refuses_is_consumed_with_the_hint() {
    shellpkg::a_refused_detach_is_consumed_with_the_hint(FISH);
}

/// KR-REQ-07.36, KR-REQ-07.73
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn outside_the_detach_condition_the_named_binding_keeps_the_key() {
    shellpkg::the_detach_condition_excludes_what_the_corpus_names(FISH);
}

/// KR-REQ-07.73
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_gesture_follows_the_terminals_own_end_of_file_character() {
    shellpkg::the_gesture_follows_the_line_discipline(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_launch_is_installed_and_accepted_on_the_reader_thread() {
    shellpkg::a_launch_is_installed_and_accepted_on_the_reader_thread(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_reader_refuses_a_launch_its_own_state_does_not_match() {
    shellpkg::the_reader_refuses_a_launch_its_own_state_does_not_match(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_revoked_launch_installs_nothing() {
    shellpkg::a_revoked_launch_installs_nothing(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_revocation_in_the_same_read_binds_its_launch_whichever_order_it_arrives_in() {
    shellpkg::a_revocation_in_the_same_read_binds_the_launch(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_reader_reports_itself_idle_so_a_withheld_fence_can_be_retried() {
    shellpkg::the_reader_reports_itself_idle(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_shell_whose_bridge_has_gone_still_consumes_an_eligible_gesture() {
    shellpkg::a_lost_bridge_does_not_restore_a_native_empty_prompt_end_of_file(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_takeover_ends_a_pending_key_wait_and_keeps_the_edit_buffer() {
    shellpkg::a_takeover_ends_a_pending_key_wait_and_keeps_the_buffer(FISH);
}

/// KR-REQ-07.36
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone() {
    shellpkg::a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone(FISH);
}

/// KR-REQ-07.85, KR-REQ-26.11
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_package_declares_the_managed_fish_baseline_and_its_reproducible_identity() {
    shellpkg::the_package_declares_the_baseline_the_specification_names(FISH);
}

/// KR-REQ-07.36
#[test]
fn every_committed_scenario_naming_fish_holds_against_the_contract() {
    shellpkg::every_scenario_naming_this_shell_holds(FISH);
}

/// KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_startup_prompt_reads_its_answer_and_the_session_is_ready_only_after_the_profile() {
    shellpkg::a_startup_prompt_reads_its_answer_and_readiness_waits_for_the_profile(FISH);
}

/// KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_startup_prompt_nobody_answers_holds_readiness_without_hanging_the_shell() {
    shellpkg::a_startup_prompt_nobody_answers_holds_readiness_and_does_not_hang_the_shell(FISH);
}

/// KR-REQ-07.22, KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_profile_that_fails_after_startup_closes_the_creating_session_with_its_diagnostics() {
    shellpkg::a_profile_that_fails_after_startup_closes_the_creating_session_with_its_diagnostics(
        FISH,
    );
}

/// KR-REQ-01.06
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn ordinary_commands_and_agent_names_run_as_they_do_without_the_integration() {
    shellpkg::ordinary_commands_and_agent_names_run_as_in_an_unmanaged_shell(FISH);
}

/// KR-REQ-01.06
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_alias_that_changes_an_agent_name_is_reported_by_the_comparison() {
    shellpkg::a_planted_alias_that_changes_an_agent_name_is_reported_not_hidden(FISH);
}

/// KR-REQ-12.07, KR-REQ-07.45
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_interactive_command_asks_once_before_it_starts_and_a_bypass_runs_it_as_typed() {
    shellpkg::an_interactive_command_asks_once_and_runs_as_typed(FISH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_pipeline_group_substitution_background_job_sourced_file_function_event_or_script_never_asks() {
    shellpkg::forms_the_root_shell_does_not_start_itself_never_ask(FISH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn assignments_in_front_of_a_command_keep_it_out_of_the_questions_and_run_with_them() {
    shellpkg::assignments_in_front_of_a_command_run_what_they_select(FISH);
}

/// KR-REQ-07.44
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn diagnostics_that_cannot_be_written_never_hold_a_command_up() {
    shellpkg::diagnostics_that_cannot_be_written_never_hold_a_command_up(FISH);
}

/// KR-REQ-07.34, KR-REQ-07.35
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn frames_that_arrive_while_a_command_waits_reach_the_reader_once() {
    shellpkg::frames_that_arrive_while_a_command_waits_reach_the_reader_once(FISH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_absolute_path_invocation_runs_as_typed() {
    shellpkg::an_absolute_path_invocation_runs_as_typed(FISH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_worker_that_does_not_answer_leaves_the_command_as_typed_after_the_deadline() {
    shellpkg::an_unanswered_question_runs_the_command_as_typed_after_the_deadline(FISH);
}

/// KR-REQ-12.07, KR-REQ-07.45
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_backend_runs_the_command_through_the_launcher_it_names() {
    shellpkg::a_backend_runs_the_command_through_the_launcher_it_names(FISH);
}

/// KR-REQ-25.05
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn each_line_reports_its_command_block_with_status_duration_and_directory() {
    shellpkg::each_line_reports_its_block_with_status_duration_and_directory(FISH);
}

/// KR-REQ-07.84
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_line_exports_the_capability_minted_for_it_and_no_other() {
    shellpkg::a_line_exports_the_capability_minted_for_it(FISH);
}

/// KR-REQ-01.06, KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_enabled_integration_flags_only_the_named_agents_interactive_invocation() {
    shellpkg::an_enabled_integration_adds_its_flags_only_to_the_agents_interactive_invocation(FISH);
}

/// KR-REQ-12.07, KR-REQ-25.05
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_cancellation_while_the_worker_is_told_of_a_line_starts_nothing() {
    shellpkg::a_cancellation_while_the_worker_is_told_starts_nothing(FISH);
}

/// KR-REQ-12.07, KR-REQ-25.05
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_termination_while_the_worker_is_asked_starts_no_command_and_ends_the_shell() {
    shellpkg::a_termination_while_the_worker_is_asked_starts_nothing_and_ends_the_shell(FISH);
}

/// KR-REQ-25.05
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_cancellation_left_at_the_prompt_skips_no_line() {
    shellpkg::a_cancellation_left_at_the_prompt_skips_no_line(FISH);
}

/// KR-REQ-25.05
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_line_that_ends_the_shell_finishes_its_block() {
    shellpkg::a_line_that_ends_the_shell_finishes_its_block(FISH);
}

/// KR-REQ-07.84
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_capability_reaches_a_lines_commands_and_nothing_around_them() {
    shellpkg::the_capability_reaches_a_lines_commands_and_nothing_around_them(FISH);
}

/// KR-REQ-07.84, KR-REQ-25.05
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_reader_a_line_starts_keeps_the_lines_block_and_capability() {
    shellpkg::a_reader_a_line_starts_keeps_the_lines_block_and_capability(FISH);
}
