#!/usr/bin/env bash
# Runs the cases that need the managed shell packages a run has built. An ordinary run leaves them
# out, because they are ignored unless the packages exist; this script is where a run that built
# them runs every one.
#
#   KR_SHELL_PACKAGES=<prefix> bash scripts/real-package-cases.sh
#
# <prefix> is the installation the packages were built into (the prefix `build-shells.sh`
# installed to). The script runs from anywhere inside the repository and exits non-zero when any
# command below fails; each command runs even when an earlier one failed, so one run shows every
# case that does not hold.
set -u

: "${KR_SHELL_PACKAGES:?KR_SHELL_PACKAGES names the installation the packages were built into}"
packages="$KR_SHELL_PACKAGES"
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

# The shells the `shells` suite starts are found on its PATH: the built packages' own.
shell_path="$packages/zsh/$(cat "$packages/zsh/current")/bin:$packages/fish/$(cat "$packages/fish/current")/bin"

failed=0
step() {
  echo "== $*"
  "$@" || failed=1
}

step cargo test -p kr-controller --test shell -- --ignored
# The fence suite also holds a case that is ignored off macOS for want of a graphical login, which a
# host without one fails on purpose; so the real-package cases are named, and a new one is named here.
step cargo test -p kr-worker --test fence -- --ignored --exact \
  a_real_qualified_package_registers_and_qualifies_on_this_hosts_endpoint \
  a_startup_prompt_takes_its_answer_through_the_worker_and_the_session_is_ready_after_the_profile \
  a_startup_prompt_nobody_answers_leaves_the_session_not_ready_and_it_still_closes \
  a_real_package_asks_the_real_worker_before_each_command_and_runs_a_bypass_as_typed \
  a_real_shell_that_ran_cd_is_described_by_its_new_directory_at_the_next_prompt \
  a_real_shell_names_the_program_it_resolved_and_not_a_word_it_found_no_file_for \
  a_real_readers_fence_is_invalidated_by_the_hosts_answer_and_proven_again
step env -u KR_SHELL_PACKAGES PATH="$shell_path:$PATH" cargo test -p kr-worker --test shells -- --ignored

exit "$failed"
