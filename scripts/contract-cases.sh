#!/usr/bin/env bash
# Runs the contract cases of the core: the cases that hold an installed app, a live worker, a
# plugin host and a published plugin of one release to what a build of another release reads and
# writes.
#
#   scripts/contract-cases.sh fast       the cases that need this tree alone
#   scripts/contract-cases.sh upgrade    the upgrade suite, beside a build of the release before
#   scripts/contract-cases.sh windows    the upgrade suite's Windows case
#
# A command passes only when its test programs say that cases passed and that none failed, and,
# for a command that names its cases (`--exact`), that as many passed as it names. Cargo exits 0
# for a name that matches no test, so a case that is renamed would otherwise pass by not running.
# A command that runs a whole target names the fewest cases it may pass (`--at-least`), so a case
# removed from the target fails the job until the number is lowered with it.
# A test command that fails does not stop the commands after it, and the script then exits 1; a build
# that fails stops the script at once, with its own status.
#
# A case that returns at once counts as passed, because a test program reports no more than that.
# While the history holds no release of the level after the release before, two cases of the upgrade
# suite do this; the cases that update from and roll back to the release before still run.

set -euo pipefail

mode="${1:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failed=0
commands=0

# Runs one cargo test command and holds its result to the rule above.
expect() {
  local log named=0 seen=0 word minimum=0
  if [ "${1:-}" = --at-least ]; then
    minimum="$2"
    shift 2
  fi
  log="$(mktemp)"
  commands=$((commands + 1))
  echo "== $*"
  for word in "$@"; do
    if [ "$seen" = 1 ]; then
      case "$word" in
        --*) seen=2 ;;
        *) named=$((named + 1)) ;;
      esac
    elif [ "$word" = --exact ]; then
      seen=1
    fi
  done
  if ! "$@" 2>&1 | tee "$log"; then
    echo "== FAILED: the command ended with an error"
    failed=1
  fi
  if ! awk -v named="$named" -v minimum="$minimum" '
    /^test result: / {
      lines++
      if ($3 == "ok." && $4 > 0 && $6 == 0) { good++; passed += $4 }
    }
    END {
      if (lines == 0 || good != lines) { exit 1 }
      if (named > 0 && passed != named) { exit 1 }
      if (passed < minimum) { exit 1 }
    }' "$log"; then
    echo "== FAILED: a test program did not report only passed cases, or fewer cases passed than the command names ($named) or than its minimum ($minimum)"
    failed=1
  fi
  rm -f "$log"
}

# The cases that need this tree alone. Each boundary names the cases that hold it. The other cases of
# the same kind, such as the lifecycle cases that start a worker of another build and the plugin
# runtime's refusal of an earlier protocol, run in the `rust` job's test of the whole workspace.
fast() {
  # An installed app and the host: what each retained release's surface and frames say, the support
  # window of the public majors, the version a client and a daemon settle on, the matrix check a
  # release makes, and a host too old for a method.
  expect --at-least 20 cargo test --locked -p kr-protocol --test retained
  expect --at-least 10 cargo test --locked -p kr-protocol --test public_majors
  expect --at-least 128 cargo test --locked -p kr-cli --test retained_surface
  expect --at-least 6 cargo test --locked -p kr-client --test release_check
  expect cargo test --locked -p kr-client --test network_chunks -- --exact \
    a_host_of_an_earlier_build_is_told_to_update_before_anything_is_reserved

  # A client and a daemon or a worker of another release or another major. The startup case talks to
  # a stand-in daemon; its set-up places the held daemon and the worker, which it finds built beside
  # it, and starts each once with `--version`.
  cargo build --locked -p kr-controller --features testing --bin kr-controller-held
  cargo build --locked -p kr-worker
  expect cargo test --locked -p kr-cli --test bridge -- --exact \
    a_daemon_of_an_earlier_build_is_named_and_not_reported_absent \
    a_daemon_of_this_level_that_ends_a_connection_is_not_said_to_be_of_an_earlier_build \
    a_worker_of_an_earlier_build_is_named_and_not_reported_absent
  expect cargo test --locked -p kr-cli --test startup -- --exact \
    a_daemon_that_answers_the_hello_with_another_major_is_refused_with_exit_3_and_no_stop_asked
  expect --at-least 39 cargo test --locked -p kr-protocol --test contracts

  # A client and a worker of an earlier build: the client names the worker and stops rather than wait
  # on its screens, and a refusal names it beside a worker that cannot be reached.
  expect cargo test --locked -p kr-cli --test lifecycle -- --exact \
    kr_names_a_worker_of_an_earlier_build_and_stops_rather_than_waiting_on_its_screens
  expect cargo test --locked -p kr-cli --test kept_answers -- --exact \
    a_worker_that_cannot_be_reached_is_named_beside_one_of_an_earlier_build

  # A forwarder and a worker of the release before: the frames, the registration and the hello that
  # release wrote are read as it wrote them.
  expect cargo test --locked -p kr-hook --test channel -- --exact \
    kr_req_12_18_the_frames_of_a_worker_of_the_release_before_cross_as_it_wrote_and_read_them
  expect cargo test --locked -p kr-hook --test registration -- --exact \
    the_registration_a_worker_of_the_release_before_wrote_is_read_whole_and_names_its_release \
    the_hello_this_forwarder_writes_has_the_members_of_the_one_the_release_before_wrote
  expect cargo test --locked -p kr-worker --test channels -- --exact \
    kr_req_12_18_an_answer_goes_out_on_the_channel_as_the_applications_verdict
  expect cargo test --locked -p kr-worker --lib -- --exact \
    broker::attach::tests::the_hello_a_forwarder_of_the_release_before_wrote_is_read_as_it_always_was

  # A plugin host of the release before and one of another protocol.
  expect --at-least 5 cargo test --locked -p kr-plugin-service --test retained_host_frames
  expect cargo test --locked -p kr-plugin-service --lib -- --exact \
    launcher::tests::the_endpoint_of_the_protocol_is_the_name_every_release_that_speaks_it_derives \
    launcher::tests::a_descriptor_round_trips_and_a_foreign_protocol_is_refused

  # A published plugin whose SDK range does not take this host.
  expect --at-least 5 cargo test --locked -p kr-plugin-sdk --test sdk_range_first
  expect cargo test --locked -p kr-plugin-catalogue --test catalogue -- --exact \
    a_package_that_needs_a_newer_sdk_is_refused_before_it_is_fetched

  # The released packages the repository keeps, held to the package contract and to the host's
  # package check.
  expect --at-least 12 cargo test --locked -p kr-hook --test fixtures
  expect --at-least 2 cargo test --locked -p kr-worker --test bundled_codex
}

# The programs a release is assembled from, built beside the test.
build_programs() {
  cargo build --locked -p kr-controller -p kr-worker -p kr-hook -p kr-plugin-host
  cargo build --locked -p kr-controller --features testing --bin kr-controller-held
  cargo build --locked -p kr-describe-model --bin kr-describe-inference
}

# The upgrade suite builds the release before from its commit and assembles this tree's release from
# the programs built beside the test.
upgrade() {
  # The suite writes plugin packages around the test components, which the repository does not hold,
  # so a fresh checkout builds them first.
  bash "$here/build-plugin-fixtures.sh"
  build_programs
  expect --at-least 51 cargo test --locked -p kr-cli --features upgrade-suite --test upgrade -- --nocapture
  # A plugin host that cannot bind beside the daemon of the release before: the suite leaves this
  # case out, because it runs where no service manager is reachable.
  expect env -u XDG_RUNTIME_DIR -u DBUS_SESSION_BUS_ADDRESS cargo test --locked -p kr-cli \
    --features upgrade-suite --test upgrade -- --nocapture --ignored --exact \
    plugin_host_frames::a_host_that_cannot_bind_beside_the_daemon_of_the_release_before_leaves_it_serving
}

# The case of a Windows host that ran the release before in place.
windows() {
  build_programs
  expect --at-least 1 cargo test --locked -p kr-cli --features upgrade-suite --test upgrade_windows -- --nocapture
}

case "$mode" in
  fast) fast ;;
  upgrade) upgrade ;;
  windows) windows ;;
  *)
    echo "usage: scripts/contract-cases.sh fast|upgrade|windows" >&2
    exit 2
    ;;
esac

echo "== contract cases: $commands command(s), $([ "$failed" = 0 ] && echo 'none failed' || echo 'some failed')"
exit "$failed"
