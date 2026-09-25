#!/usr/bin/env bash
# Holds the text records a release asks people to check to what their checkers will read.
#
#   scripts/check-release-sums.sh <directory> [<record>...]
#   scripts/check-release-sums.sh self-test
#
# <directory> holds SHA256SUMS and the files it names. SHA256SUMS, and every other record named
# after the directory, must end each of its lines in a line feed alone. A carriage return is
# refused wherever it appears: `shasum -a 256 -c` and the sha256sum macOS ships read it as the last
# character of the file name and report the file missing, while GNU sha256sum drops it and passes,
# so a check made with GNU sha256sum alone would never see it. Then `sha256sum -c` reads
# SHA256SUMS in the directory, and so does `shasum -a 256 -c` wherever it is installed.
#
# `self-test` drives the check with records made to fail, beside a control it must accept: a check
# that passes everything looks exactly like a check that works.
set -euo pipefail

check() {
  local directory=$1
  shift
  local failed=0 record returns

  if [ ! -s "$directory/SHA256SUMS" ]; then
    echo "REFUSED: $directory holds no SHA256SUMS, or an empty one"
    return 1
  fi

  for record in "$directory/SHA256SUMS" "$@"; do
    if [ ! -s "$record" ]; then
      echo "REFUSED: $record is missing or empty"
      failed=1
      continue
    fi
    returns=$(LC_ALL=C tr -dc '\r' <"$record" | wc -c | tr -d ' ')
    if [ "$returns" != 0 ]; then
      echo "REFUSED: $record carries carriage returns ($returns); every line must end in a line feed alone"
      failed=1
    fi
    # The substitution drops a trailing line feed, so anything left is a last line without one.
    if [ -n "$(tail -c 1 "$record")" ]; then
      echo "REFUSED: $record does not end in a line feed"
      failed=1
    fi
  done

  if ! (cd "$directory" && sha256sum -c SHA256SUMS); then
    echo "REFUSED: sha256sum -c SHA256SUMS failed in $directory"
    failed=1
  fi
  if command -v shasum >/dev/null 2>&1; then
    if ! (cd "$directory" && shasum -a 256 -c SHA256SUMS); then
      echo "REFUSED: shasum -a 256 -c SHA256SUMS failed in $directory"
      failed=1
    fi
  else
    echo "shasum is not installed here, so sha256sum alone read SHA256SUMS"
  fi

  if [ "$failed" -ne 0 ]; then
    return 1
  fi
  echo "ACCEPTED: SHA256SUMS in $directory and $# other records"
}

self_test() {
  local script work passed=0 failed=0
  script=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
  work=$(mktemp -d)
  # shellcheck disable=SC2064 # the directory is fixed now, and the trap must remove this one
  trap "rm -rf '${work:?}'" EXIT

  # One release directory per case: a stand-in archive, its SHA256SUMS and a second record, each
  # record's lines ended with the characters the case names.
  make_case() {
    local name=$1 sums_ending=$2 record_ending=$3 digest
    mkdir -p "$work/$name"
    printf 'a stand-in for the release archive\n' >"$work/$name/kalareach.zip"
    digest=$(sha256sum <"$work/$name/kalareach.zip" | cut -d' ' -f1)
    printf '%s  %s%s' "$digest" kalareach.zip "$sums_ending" >"$work/$name/SHA256SUMS"
    printf '# a record people check%s%s  kalareach.zip%s' "$record_ending" "$digest" "$record_ending" \
      >"$work/$name/signatures.txt"
  }

  # The check runs as a separate process, so its exit code is exactly what a workflow step reads.
  expect() {
    local name=$1 wanted=$2 reason=$3 output code
    shift 3
    set +e
    output=$(bash "$script" "$@" 2>&1)
    code=$?
    set -e
    if [ "$wanted" = accepted ] && [ "$code" -eq 0 ]; then
      echo "PASS $name"
      passed=$((passed + 1))
    elif [ "$wanted" = refused ] && [ "$code" -ne 0 ] && [[ $output == *"$reason"* ]]; then
      echo "PASS $name"
      passed=$((passed + 1))
    else
      echo "FAIL $name: wanted it $wanted${reason:+ ($reason)}, and the check exited $code:"
      printf '%s\n' "$output" | sed 's/^/    /'
      failed=$((failed + 1))
    fi
  }

  make_case control $'\n' $'\n'
  expect 'records ending in a line feed alone are accepted' accepted '' \
    "$work/control" "$work/control/signatures.txt"

  make_case sums-crlf $'\r\n' $'\n'
  expect 'a SHA256SUMS ending its line in CRLF is refused' refused 'carriage returns' \
    "$work/sums-crlf" "$work/sums-crlf/signatures.txt"

  make_case record-crlf $'\n' $'\r\n'
  expect 'another record with CRLF line endings is refused' refused 'signatures.txt carries' \
    "$work/record-crlf" "$work/record-crlf/signatures.txt"

  make_case unterminated '' $'\n'
  expect 'a SHA256SUMS whose last line has no line feed is refused' refused 'does not end in a line feed' \
    "$work/unterminated" "$work/unterminated/signatures.txt"

  make_case altered $'\n' $'\n'
  printf 'the archive changed after it was summed\n' >"$work/altered/kalareach.zip"
  expect 'an archive that does not match its sum is refused' refused 'sha256sum -c SHA256SUMS failed' \
    "$work/altered" "$work/altered/signatures.txt"

  make_case missing $'\n' $'\n'
  rm "${work:?}/missing/SHA256SUMS"
  expect 'a directory with no SHA256SUMS is refused' refused 'holds no SHA256SUMS' "$work/missing"

  echo "$passed passed, $failed failed"
  [ "$failed" -eq 0 ]
}

case ${1:-} in
  '')
    echo 'usage: check-release-sums.sh <directory> [<record>...] | self-test' >&2
    exit 2
    ;;
  self-test)
    self_test
    ;;
  *)
    check "$@"
    ;;
esac
