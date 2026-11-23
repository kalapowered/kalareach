#!/usr/bin/env bash
# Runs the cases that need a real squid proxy, against proxies that scripts/real-proxy.sh starts.
#
#   scripts/real-proxy-cases.sh
#
# It checks the squid program (`real-proxy.sh check`), starts three proxies in a run folder made for
# the run (one that asks for a Basic login, one that offers Digest only, one that intercepts TLS),
# names them to the cases through each proxy's `env.sh`, runs the ignored cases of the four test
# targets that read those names, and stops every proxy it started, whatever happened. SQUID and
# SQUID_LIBEXEC name the squid program and its helpers, as for real-proxy.sh.
#
# A target passes only when its test program says that exactly the number of cases it names passed
# and none failed. Cargo exits 0 for a name that matches no test, so a case that is renamed, or that
# stops being ignored, would otherwise pass by not running.
#
# What the proxies and the cases wrote is kept in the real-proxy folder of the run's evidence
# directory (the one scripts/lib/artifacts-dir.sh resolves) and printed: each proxy's access log, its
# own log, the squid version and the output of each target. The logins and the interception
# authority's key, which the run folder holds, are not kept, and the run folder is removed at the
# end.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/lib/artifacts-dir.sh
. "$here/lib/artifacts-dir.sh"
kr_artifacts_dir
evidence="$kr_artifacts/real-proxy"
modes="basic digest bump"

mkdir -p "$evidence"
bash "$here/real-proxy.sh" check
"${SQUID:-squid}" -v >"$evidence/squid-version.txt"
run="$(mktemp -d)"
failed=0
targets=0

# The files of each proxy's run folder that say what happened and hold no login or key.
keep_logs() {
  local mode file
  for mode in $modes; do
    for file in access.log cache.log parse.log squid.out; do
      if [ -f "$run/$mode/$file" ]; then
        cp "$run/$mode/$file" "$evidence/$mode-$file"
      fi
    done
  done
}

show() {
  local file="$1"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::group::$(basename "$file")"
  else
    echo "== $(basename "$file")"
  fi
  cat "$file"
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::endgroup::"
  fi
}

finish() {
  local status=$? mode file
  set +e
  trap - EXIT
  for mode in $modes; do
    if [ -f "$run/$mode/proxy.pid" ]; then
      bash "$here/real-proxy.sh" stop "$run/$mode" || status=1
    fi
  done
  keep_logs
  for mode in $modes; do
    for file in access.log cache.log; do
      if [ -f "$evidence/$mode-$file" ]; then
        show "$evidence/$mode-$file"
      fi
    done
  done
  rm -rf "${run:?}"
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT TERM

# Runs one target's cases and holds it to the number of cases it names: `expect <count> <command>`.
expect() {
  local count="$1" log
  shift
  targets=$((targets + 1))
  log="$evidence/target-$targets.log"
  echo "real-proxy-cases: $*"
  if ! "$@" 2>&1 | tee "$log"; then
    echo "real-proxy-cases: the command failed" >&2
    failed=1
    return 0
  fi
  if [ "$(grep -c -E "test result: ok\. $count passed; 0 failed;" "$log")" -ne 1 ]; then
    echo "real-proxy-cases: the output does not say that exactly $count cases passed and none failed" >&2
    failed=1
  fi
}

for mode in $modes; do
  bash "$here/real-proxy.sh" start "$run/$mode" "$mode"
  # shellcheck disable=SC1090
  . "$run/$mode/env.sh"
done

expect 4 cargo test --locked -p kr-transport --test real_proxy -- --ignored --exact a_client_with_the_right_login_reaches_an_origin_through_a_real_proxy a_wrong_login_is_refused_by_a_real_proxy_once_and_stops_every_request a_client_with_no_login_is_told_by_a_real_proxy_that_one_is_needed a_plain_http_target_is_refused_before_a_real_proxy_is_asked --nocapture --test-threads=1
expect 2 cargo test --locked -p kr-transport --test real_proxy_bump -- --ignored --exact a_relay_only_attempt_through_a_real_proxy_that_refuses_the_upgrade_says_so a_real_intercepting_proxy_is_trusted_only_when_its_authority_is_named --nocapture --test-threads=1
expect 1 cargo test --locked -p kr-controller --test proxy_front -- --ignored --exact an_endpoint_reaches_its_relay_through_a_real_proxy_by_its_front --nocapture --test-threads=1
expect 3 cargo test --locked -p kr-controller --test proxy_login_daemon -- --ignored --exact a_daemon_behind_a_real_proxy_starts_says_so_and_takes_the_login_at_its_next_start a_wrong_login_is_written_to_a_real_proxy_once_and_the_daemon_stops_every_request_through_it a_real_proxy_that_offers_digest_only_is_unsupported_whether_or_not_a_login_is_held --nocapture --test-threads=1

exit "$failed"
