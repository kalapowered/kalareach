# shellcheck shell=bash
# The rule that a Mac run loads nothing into the account's own launchd unless it asks.
#
# A script that starts a daemon and sessions sources this file and calls `require_account_launchd`
# before it builds or starts anything. The system is a parameter (`uname -s`'s answer), so that the
# refusal can be shown on any host without a launch. A run asks by setting
# KR_ALLOW_ACCOUNT_LAUNCHD to exactly 1.

# require_account_launchd <system>: ends the script with status 1 and says why when <system> is
# Darwin and the run did not ask; on any other system, or when the run asked, it returns.
require_account_launchd() {
  local system="${1:?name the system}"
  if [ "$system" = Darwin ] && [ "${KR_ALLOW_ACCOUNT_LAUNCHD:-}" != 1 ]; then
    echo "${0##*/} starts a daemon and sessions, which load jobs into the account's own launchd, and this run did not ask for it: set KR_ALLOW_ACCOUNT_LAUNCHD=1 where that account is a test account or a hosted runner's" >&2
    exit 1
  fi
}
