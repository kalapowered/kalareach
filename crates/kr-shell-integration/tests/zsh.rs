//! The managed Zsh package, driven through the built shell in a real pseudo-terminal.
//!
//! Section 7 puts a published ZLE patch behind this package: a reader mailbox at key-sequence
//! boundaries, immediate line acceptance that returns from the read loop, non-destructive
//! cancellation of a pending key wait, enter, leave and fence events, and the end-of-file decision
//! immediately before ZLE's empty-EOF branch. Each test below drives one of those through the
//! shell the build script installed, against the expectations in `fixtures/shell-bridge/`.
//!
//! The cases that drive the package need this tree's built package, which an ordinary run does not
//! have, so they are left out of one. A run that built the packages runs them with
//! `--include-ignored`, as continuous integration's shell-packages job does, and there a package
//! that is not this tree's fails the case that needed it.

// The two packages this file drives are Unix shells with patched Unix readers, and the harness
// speaks to them over a Unix socket in a pseudo-terminal. Windows is a separate package.
#![cfg(unix)]

mod shellpkg;

use kr_shell_integration::contract::qualification::ShellKind;

const ZSH: ShellKind = ShellKind::Zsh;

/// KR-REQ-07.88: no native file of the package depends on a library of the machine that built it.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_zsh_package_links_no_library_of_the_machine_that_built_it() {
    shellpkg::the_shell_links_no_library_of_the_machine_that_built_it(ZSH);
}

/// KR-REQ-08.49: bytes the host put into the terminal are input the reader has not taken.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_reader_counts_what_the_host_put_into_its_terminal_as_input_it_has_not_taken() {
    shellpkg::bytes_the_host_put_into_the_terminal_are_input_the_reader_has_not_taken(ZSH);
}

/// KR-REQ-07.34, KR-REQ-07.85, KR-REQ-20.03: the proof the package's own SHA-256 and HMAC-SHA-256
/// compute is the worker's HMAC-SHA-256 of the same transcript.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_handshake_declares_the_published_zle_patches_and_the_reader_they_build() {
    shellpkg::the_handshake_declares_the_packaged_reader(ZSH);
}

/// KR-REQ-07.40: the bridge holds no copy of the bootstrap secret once the handshake is accepted.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_bootstrap_secret_is_wiped_once_the_handshake_is_accepted() {
    shellpkg::the_bootstrap_secret_does_not_outlive_the_accepted_handshake(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_child_of_the_managed_root_shell_inherits_no_activation() {
    shellpkg::a_child_shell_has_nothing_to_activate_from(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_zle_reader_reports_its_boundaries_and_proves_its_own_queues() {
    shellpkg::the_reader_reports_its_boundaries_and_proves_its_own_state(ZSH);
}

/// KR-REQ-07.72
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_eligible_gesture_under_a_fence_becomes_an_attributable_detach() {
    shellpkg::an_eligible_gesture_under_a_fence_is_an_attributable_detach(ZSH);
}

/// KR-REQ-07.72
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_unattributable_gesture_is_consumed_with_one_hint_per_prompt() {
    shellpkg::an_unattributable_gesture_is_consumed_with_one_hint_per_prompt(ZSH);
}

/// KR-REQ-07.72
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_detach_the_worker_refuses_is_consumed_with_the_hint() {
    shellpkg::a_refused_detach_is_consumed_with_the_hint(ZSH);
}

/// KR-REQ-07.72
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn outside_the_detach_condition_zle_keeps_the_key() {
    shellpkg::the_detach_condition_excludes_what_the_corpus_names(ZSH);
}

/// KR-REQ-07.72
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_gesture_follows_the_terminals_own_end_of_file_character() {
    shellpkg::the_gesture_follows_the_line_discipline(ZSH);
}

/// KR-REQ-07.72
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_decision_before_the_empty_eof_branch_leaves_ignore_eof_alone() {
    shellpkg::the_ignore_eof_setting_is_left_as_the_person_set_it(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_launch_is_installed_and_accepted_on_the_reader_thread() {
    shellpkg::a_launch_is_installed_and_accepted_on_the_reader_thread(ZSH);
}

/// KR-REQ-23.54
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_launch_is_quoted_for_its_own_shell_and_never_evaluated() {
    shellpkg::a_launch_is_quoted_for_its_own_shell_and_never_evaluated(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_reader_refuses_a_launch_its_own_state_does_not_match() {
    shellpkg::the_reader_refuses_a_launch_its_own_state_does_not_match(ZSH);
}

/// KR-REQ-23.38: the reader refuses a launch for another working directory and installs nothing.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_launch_for_another_working_directory_is_a_conflict_and_installs_nothing() {
    shellpkg::a_launch_for_another_working_directory_is_a_conflict_and_installs_nothing(ZSH);
}

/// KR-REQ-23.38: the reader refuses a launch over typed text and installs nothing.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_launch_over_typed_text_is_a_conflict_and_installs_nothing() {
    shellpkg::a_launch_over_typed_text_is_a_conflict_and_installs_nothing(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_revoked_launch_installs_nothing() {
    shellpkg::a_revoked_launch_installs_nothing(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_revocation_in_the_same_read_binds_its_launch_whichever_order_it_arrives_in() {
    shellpkg::a_revocation_in_the_same_read_binds_the_launch(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_reader_reports_itself_idle_so_a_withheld_fence_can_be_retried() {
    shellpkg::the_reader_reports_itself_idle(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_reader_that_reported_idle_reports_again_when_its_fence_is_withheld() {
    shellpkg::a_reader_reports_itself_idle_again_when_the_worker_withholds_a_fence(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_reader_that_holds_input_does_not_report_idle_when_its_fence_is_withheld() {
    shellpkg::a_reader_that_holds_input_does_not_report_idle_again_when_the_worker_withholds_a_fence(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_shell_whose_bridge_has_gone_still_consumes_an_eligible_gesture() {
    shellpkg::a_lost_bridge_does_not_restore_a_native_empty_prompt_end_of_file(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_takeover_ends_a_pending_key_wait_and_keeps_the_edit_buffer() {
    shellpkg::a_takeover_ends_a_pending_key_wait_and_keeps_the_buffer(ZSH);
}

/// KR-REQ-07.34
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone() {
    shellpkg::a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone(ZSH);
}

/// KR-REQ-12.07, KR-REQ-07.45
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_interactive_command_asks_once_before_it_starts_and_a_bypass_runs_it_as_typed() {
    shellpkg::an_interactive_command_asks_once_and_runs_as_typed(ZSH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_pipeline_subshell_substitution_background_job_sourced_script_or_script_never_asks() {
    shellpkg::forms_the_root_shell_does_not_start_itself_never_ask(ZSH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn assignments_in_front_of_a_command_run_the_file_and_vector_they_select() {
    shellpkg::assignments_in_front_of_a_command_run_what_they_select(ZSH);
}

/// KR-REQ-07.44
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn diagnostics_that_cannot_be_written_never_hold_a_command_up() {
    shellpkg::diagnostics_that_cannot_be_written_never_hold_a_command_up(ZSH);
}

/// KR-REQ-07.34, KR-REQ-07.35
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn frames_that_arrive_while_a_command_waits_reach_the_reader_once() {
    shellpkg::frames_that_arrive_while_a_command_waits_reach_the_reader_once(ZSH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_absolute_path_invocation_runs_as_typed() {
    shellpkg::an_absolute_path_invocation_runs_as_typed(ZSH);
}

/// KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_worker_that_does_not_answer_leaves_the_command_as_typed_after_the_deadline() {
    shellpkg::an_unanswered_question_runs_the_command_as_typed_after_the_deadline(ZSH);
}

/// KR-REQ-12.07, KR-REQ-07.45
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_backend_runs_the_command_through_the_launcher_it_names() {
    shellpkg::a_backend_runs_the_command_through_the_launcher_it_names(ZSH);
}

/// KR-REQ-25.05
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn each_line_reports_its_command_block_with_status_duration_and_directory() {
    shellpkg::each_line_reports_its_block_with_status_duration_and_directory(ZSH);
}

/// KR-REQ-07.84
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_line_exports_the_capability_minted_for_it_and_no_other() {
    shellpkg::a_line_exports_the_capability_minted_for_it(ZSH);
}

/// KR-REQ-07.85, KR-REQ-26.11
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_package_declares_the_managed_zsh_baseline_and_its_reproducible_identity() {
    shellpkg::the_package_declares_the_baseline_the_specification_names(ZSH);
}

/// KR-REQ-07.34, KR-REQ-07.35
#[test]
fn every_committed_scenario_naming_zsh_holds_against_the_contract() {
    shellpkg::every_scenario_naming_this_shell_holds(ZSH);
}

/// KR-REQ-26.11
#[test]
fn the_shell_independent_bridge_is_the_same_source_in_both_packages() {
    shellpkg::the_bridge_core_is_identical_in_both_packages();
}

/// KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_startup_prompt_reads_its_answer_and_the_session_is_ready_only_after_the_profile() {
    shellpkg::a_startup_prompt_reads_its_answer_and_readiness_waits_for_the_profile(ZSH);
}

/// KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_startup_prompt_nobody_answers_holds_readiness_without_hanging_the_shell() {
    shellpkg::a_startup_prompt_nobody_answers_holds_readiness_and_does_not_hang_the_shell(ZSH);
}

/// KR-REQ-07.22, KR-REQ-07.23
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_profile_that_fails_after_startup_closes_the_creating_session_with_its_diagnostics() {
    shellpkg::a_profile_that_fails_after_startup_closes_the_creating_session_with_its_diagnostics(
        ZSH,
    );
}

/// KR-REQ-01.06
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn ordinary_commands_and_agent_names_run_as_they_do_without_the_integration() {
    shellpkg::ordinary_commands_and_agent_names_run_as_in_an_unmanaged_shell(ZSH);
}

/// KR-REQ-01.06
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_alias_that_changes_an_agent_name_is_reported_by_the_comparison() {
    shellpkg::a_planted_alias_that_changes_an_agent_name_is_reported_not_hidden(ZSH);
}

/// KR-REQ-01.06, KR-REQ-12.07
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn an_enabled_integration_flags_only_the_named_agents_interactive_invocation() {
    shellpkg::an_enabled_integration_adds_its_flags_only_to_the_agents_interactive_invocation(ZSH);
}

/// KR-REQ-07.44
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn the_integration_stays_in_the_root_shell_and_adds_no_global_accept_line_or_mark() {
    shellpkg::the_integration_stays_in_the_root_shell_and_adds_no_global_accept_line_or_mark(ZSH);
}

/// KR-REQ-23.54
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built, as continuous integration's shell-packages job does"]
fn a_launch_passes_every_word_it_is_given() {
    shellpkg::a_launch_passes_every_word_it_is_given(ZSH);
}
