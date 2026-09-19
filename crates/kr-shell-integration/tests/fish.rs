//! The managed fish package, driven through the built shell in a real pseudo-terminal.
//!
//! Section 7 puts a reader-event bridge behind this package, against the shell's own Rust reader:
//! a mailbox the reader waits on alongside the terminal and reads at every key-sequence boundary,
//! immediate line acceptance through the editor's own execute, non-destructive cancellation of a
//! pending key wait, enter, leave and fence events, and an end-of-file decision taken by a named
//! binding with the actual reader context. Each test below drives one of those through the shell
//! the build script installed, against the expectations in `fixtures/shell-bridge/`.
//!
//! A run with no built package prints why and stops; continuous integration builds the package in
//! the same job and sets `KR_REQUIRE_SHELL_PACKAGES`, where an absent package is a failure.

// This package is a Unix shell with a patched Unix reader, and the harness speaks to it over a
// Unix socket in a pseudo-terminal.
#![cfg(unix)]

mod shellpkg;

use kr_shell_integration::contract::qualification::ShellKind;

const FISH: ShellKind = ShellKind::Fish;

/// KR-REQ-07.36, KR-REQ-07.85
#[test]
fn the_handshake_declares_the_published_reader_patches_and_the_reader_they_build() {
    shellpkg::the_handshake_declares_the_packaged_reader(FISH);
}

/// KR-REQ-07.36
#[test]
fn a_child_of_the_managed_root_shell_inherits_no_activation() {
    shellpkg::a_child_shell_has_nothing_to_activate_from(FISH);
}

/// KR-REQ-07.36
#[test]
fn the_reader_reports_its_boundaries_and_proves_its_own_queues() {
    shellpkg::the_reader_reports_its_boundaries_and_proves_its_own_state(FISH);
}

/// KR-REQ-07.36, KR-REQ-07.73
#[test]
fn an_eligible_gesture_under_a_fence_becomes_an_attributable_detach() {
    shellpkg::an_eligible_gesture_under_a_fence_is_an_attributable_detach(FISH);
}

/// KR-REQ-07.36, KR-REQ-07.73
#[test]
fn an_unattributable_gesture_is_consumed_with_one_hint_per_prompt() {
    shellpkg::an_unattributable_gesture_is_consumed_with_one_hint_per_prompt(FISH);
}

/// KR-REQ-07.36, KR-REQ-07.73
#[test]
fn a_detach_the_worker_refuses_is_consumed_with_the_hint() {
    shellpkg::a_refused_detach_is_consumed_with_the_hint(FISH);
}

/// KR-REQ-07.36, KR-REQ-07.73
#[test]
fn outside_the_detach_condition_the_named_binding_keeps_the_key() {
    shellpkg::the_detach_condition_excludes_what_the_corpus_names(FISH);
}

/// KR-REQ-07.73
#[test]
fn the_gesture_follows_the_terminals_own_end_of_file_character() {
    shellpkg::the_gesture_follows_the_line_discipline(FISH);
}

/// KR-REQ-07.36
#[test]
fn a_launch_is_installed_and_accepted_on_the_reader_thread() {
    shellpkg::a_launch_is_installed_and_accepted_on_the_reader_thread(FISH);
}

/// KR-REQ-07.36
#[test]
fn the_reader_refuses_a_launch_its_own_state_does_not_match() {
    shellpkg::the_reader_refuses_a_launch_its_own_state_does_not_match(FISH);
}

/// KR-REQ-07.36
#[test]
fn a_revoked_launch_installs_nothing() {
    shellpkg::a_revoked_launch_installs_nothing(FISH);
}

/// KR-REQ-07.36
#[test]
fn a_revocation_in_the_same_read_binds_its_launch_whichever_order_it_arrives_in() {
    shellpkg::a_revocation_in_the_same_read_binds_the_launch(FISH);
}

/// KR-REQ-07.36
#[test]
fn the_reader_reports_itself_idle_so_a_withheld_fence_can_be_retried() {
    shellpkg::the_reader_reports_itself_idle(FISH);
}

/// KR-REQ-07.36
#[test]
fn a_shell_whose_bridge_has_gone_still_consumes_an_eligible_gesture() {
    shellpkg::a_lost_bridge_does_not_restore_a_native_empty_prompt_end_of_file(FISH);
}

/// KR-REQ-07.36
#[test]
fn a_takeover_ends_a_pending_key_wait_and_keeps_the_edit_buffer() {
    shellpkg::a_takeover_ends_a_pending_key_wait_and_keeps_the_buffer(FISH);
}

/// KR-REQ-07.36
#[test]
fn a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone() {
    shellpkg::a_cancellation_that_ends_nothing_leaves_the_next_sequence_alone(FISH);
}

/// KR-REQ-07.85, KR-REQ-26.11
#[test]
fn the_package_declares_the_managed_fish_baseline_and_its_reproducible_identity() {
    shellpkg::the_package_declares_the_baseline_the_specification_names(FISH);
}

/// KR-REQ-07.36
#[test]
fn every_committed_scenario_naming_fish_holds_against_the_contract() {
    shellpkg::every_scenario_naming_this_shell_holds(FISH);
}
