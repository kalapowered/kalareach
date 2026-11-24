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
# Every command runs whatever an earlier one did, and the script exits 1 if any of them failed.

set -euo pipefail

mode="${1:-}"
failed=0
commands=0

# Runs one cargo test command and holds its result to the rule above.
expect() {
  local log named=0 seen=0 word
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
  if ! awk -v named="$named" '
    /^test result: / {
      lines++
      if ($3 == "ok." && $4 > 0 && $6 == 0) { good++; passed += $4 }
    }
    END {
      if (lines == 0 || good != lines) { exit 1 }
      if (named > 0 && passed != named) { exit 1 }
    }' "$log"; then
    echo "== FAILED: a test program did not report only passed cases, or fewer cases passed than the command names ($named)"
    failed=1
  fi
  rm -f "$log"
}

# The cases that need this tree alone.
fast() {
  # An installed app and the host: what each retained release's surface and frames say, the support
  # window of the public majors, the matrix check a release makes, and a host too old for a method.
  expect cargo test --locked -p kr-protocol --test retained --test public_majors
  expect cargo test --locked -p kr-cli --test retained_surface
  expect cargo test --locked -p kr-client --test release_check
  expect cargo test --locked -p kr-client --test network_chunks -- --exact \
    a_host_of_an_earlier_build_is_told_to_update_before_anything_is_reserved

  # A client and a daemon or a worker of another release or another major. The startup case starts
  # the daemon and the worker, which it finds built beside it.
  cargo build --locked -p kr-controller --features testing --bin kr-controller-held
  cargo build --locked -p kr-worker
  expect cargo test --locked -p kr-cli --test bridge -- --exact \
    a_daemon_of_an_earlier_build_is_named_and_not_reported_absent \
    a_daemon_of_this_level_that_ends_a_connection_is_not_said_to_be_of_an_earlier_build \
    a_worker_of_an_earlier_build_is_named_and_not_reported_absent
  expect cargo test --locked -p kr-cli --test startup -- --exact \
    a_daemon_that_answers_the_hello_with_another_major_is_refused_with_exit_3_and_no_stop_asked

  # A plugin host of the release before and one of another protocol.
  expect cargo test --locked -p kr-plugin-service --test retained_host_frames
  expect cargo test --locked -p kr-plugin-service --lib -- --exact \
    launcher::tests::the_endpoint_of_the_protocol_is_the_name_every_release_that_speaks_it_derives \
    launcher::tests::a_descriptor_round_trips_and_a_foreign_protocol_is_refused

  # A published plugin whose SDK range does not take this host.
  expect cargo test --locked -p kr-plugin-sdk --test sdk_range_first
  expect cargo test --locked -p kr-plugin-catalogue --test catalogue -- --exact \
    a_package_that_needs_a_newer_sdk_is_refused_before_it_is_fetched
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
  build_programs
  expect cargo test --locked -p kr-cli --features upgrade-suite --test upgrade -- --nocapture
  # A plugin host that cannot bind beside the daemon of the release before: the suite leaves this
  # case out, because it runs where no service manager is reachable.
  expect env -u XDG_RUNTIME_DIR -u DBUS_SESSION_BUS_ADDRESS cargo test --locked -p kr-cli \
    --features upgrade-suite --test upgrade -- --nocapture --ignored --exact \
    plugin_host_frames::a_host_that_cannot_bind_beside_the_daemon_of_the_release_before_leaves_it_serving
}

# The case of a Windows host that ran the release before in place.
windows() {
  build_programs
  expect cargo test --locked -p kr-cli --features upgrade-suite --test upgrade_windows -- --nocapture
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
