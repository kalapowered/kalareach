#!/bin/sh
# A marker helper for the restricted-profile fixture.
#
# Every execution-capable thing a project repository can name is planted as this program. If the
# host ever runs one of them, this writes a file named after the entry that invoked it, and the
# test that finds the file says which helper escaped. It exits zero so that a helper which ran does
# not also fail the command and hide itself behind an ordinary error.
#
# @SENTINELS@ is replaced with an absolute directory on the internal disk when the fixture is
# planted; the child process runs with an environment this host built from nothing, so the path
# cannot come from a variable.
set -u
sentinels='@SENTINELS@'
name="${1:-unknown}"
mkdir -p "$sentinels" 2>/dev/null || true
printf '%s\n' "$name" >>"$sentinels/$name" 2>/dev/null || true
# A filter, a textconv and a pager are all expected to pass content through, so content on the
# standard input is copied to the standard output unchanged. A helper that swallowed it would fail
# the command for the wrong reason.
cat 2>/dev/null || true
exit 0
