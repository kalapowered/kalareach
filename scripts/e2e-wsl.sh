#!/usr/bin/env bash
# KR-ACC-011: WSL2 acceptance. Several distributions, independent operation, NAT and mirrored
# networking, and environment-specific paths.
#
# This runs on a Windows host with WSL2, in Git Bash or MSYS2. It is an acceptance run, so a
# prerequisite it cannot meet is a failure rather than a skip: a run that cannot establish these
# results has not established them.
#
# What it establishes, in order:
#
#   1. WSL 2 is installed, the default version is 2, and two distributions are registered. A second
#      one is made by exporting and importing the first when only one is there, and is removed
#      again at the end.
#   2. Each distribution runs KalaReach on its own: its own control daemon, its own worker, its own
#      Linux paths and process identifiers, with the native Windows installation taking no part. A
#      distribution this run imported is a copy, so the installation it inherited is removed before
#      anything starts in it and it becomes an installation of its own.
#   3. Argument vectors cross `wsl.exe --exec` unchanged, including values a shell would rewrite.
#   4. Windows reaches each distribution through the process bridge alone, learns that
#      distribution's own environment identity, and gets an answer to a real read across it.
#   5. A listing of stopped distributions comes from the cache and starts nothing. A refresh that
#      was told to start one does.
#   6. The bridge behaves the same in NAT and in mirrored networking mode, which is what decides
#      whether any automatic behaviour is needed.
#
# Every artefact is written under ${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}. The Windows
# daemon this starts keeps its keys in its own run directory (never the Credential Manager).
#
# Knobs, all optional:
#   KR_WSL_HELPER     absolute path of the helper inside a distribution (default /usr/local/bin/kr)
#   KR_WSL_USER       the Linux user the helper runs as (default root)
#   KR_WSL_SECOND     the name of the second distribution this script makes (default kr-acc-011)
#   KR_WSL_ROOT       where that distribution's image is written (default /c/kala/wsl)
#   KR_WSL_KEEP       1 to keep the second distribution and the daemons for inspection
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

artifacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
mkdir -p "$artifacts"
run_stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
run_dir="$artifacts/wsl-$run_stamp"
mkdir -p "$run_dir"
helper_path="${KR_WSL_HELPER:-/usr/local/bin/kr}"
# The bridge suite this acceptance installs beside the helper and runs in step 7, and the manifest
# that binds the whole installed set to the commit it was built from. Both are this acceptance's
# own artefacts rather than programs the product installs, so they live together outside the path.
suite_path=/usr/local/lib/kalareach-acc-bridge-suite
manifest_path=/usr/local/lib/kalareach-acc-commit
# The same set of paths relative to the root, which is the form the manifest carries so that both
# writing it and checking it work from one directory.
helper_relative="${helper_path#/}"
suite_relative="${suite_path#/}"
linux_user="${KR_WSL_USER:-root}"
second_name="${KR_WSL_SECOND:-kr-acc-011}"
wsl_root="${KR_WSL_ROOT:-/c/kala/wsl}"
keep="${KR_WSL_KEEP:-0}"

# MSYS2 rewrites an argument that looks like a POSIX path before it hands it to a native program,
# which is wrong for every argument here: `/bin/sh` is a path inside the distribution, not on this
# host, and so is the helper this run enrols. Every path that a native program should read as a
# Windows path is converted below, by name, so nothing is left for a heuristic to guess at.
export MSYS2_ARG_CONV_EXCL='*'
export MSYS_NO_PATHCONV=1

# The Windows form of a path in this shell. Every native program below is handed one of these: this
# shell's own form means nothing to them.
windows_path() { cygpath -w "$1" 2>/dev/null || printf '%s' "$1"; }

passed=0
fail() {
  # Standard error, so that a check inside a command substitution still says what went wrong
  # rather than handing its message to the variable being assigned.
  echo "FAIL: $*" >&2
  exit 1
}
pass() {
  passed=$((passed + 1))
  echo "PASS: $*"
}
step() { echo; echo "==> $*"; }

echo "kalareach wsl2 acceptance (KR-ACC-011)"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  artefacts: $artifacts"

# What this run made, and therefore what it may remove or end. Nothing else is touched: every
# process ended below is one this script started and recorded.
made_distribution=""
made_directory=""
wslconfig_path=""
wslconfig_saved=""
wslconfig_existed=0
daemons=""
windows_daemon=""

cleanup() {
  local status=$?
  if [ -n "$windows_daemon" ]; then
    kill "$windows_daemon" 2>/dev/null || true
  fi
  if [ "$keep" != "1" ]; then
    for distribution in $daemons; do
      # The identifier this script recorded when it started that daemon, and no pattern. The
      # substitution below runs inside the distribution, which is why it stays unexpanded here.
      # shellcheck disable=SC2016
      wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -c \
        'test -f /tmp/kr-acc-controller.pid && kill $(cat /tmp/kr-acc-controller.pid)' \
        >/dev/null 2>&1 || true
    done
    if [ -n "$made_distribution" ]; then
      echo "removing the distribution this run made: $made_distribution"
      wsl.exe --unregister "$made_distribution" >/dev/null 2>&1 || true
    fi
    # The image directory this run made, by the name this run gave it. Nothing else here is
    # this run's to remove.
    if [ -n "$made_directory" ] && [ -d "$made_directory" ]; then
      rm -rf "${made_directory:?}"
    fi
  fi
  # The networking mode is the operator's setting. It goes back exactly as it was.
  if [ -n "$wslconfig_saved" ] && [ -n "$wslconfig_path" ]; then
    if [ "$wslconfig_existed" = "1" ]; then
      cp "$wslconfig_saved" "$wslconfig_path"
    else
      rm -f "${wslconfig_path:?}"
    fi
    wsl.exe --shutdown >/dev/null 2>&1 || true
  fi
  echo "evidence kept under $run_dir"
  exit "$status"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------------------------
step "1. WSL 2, and the distributions this acceptance needs"

command -v wsl.exe >/dev/null 2>&1 ||
  fail "this acceptance runs on a Windows host with WSL2; wsl.exe is not on this machine"

# wsl.exe writes UTF-16LE. Dropping the null bytes is enough to read it as text here.
wsl_text() { wsl.exe "$@" 2>&1 | tr -d '\000\r'; }

version_text="$(wsl_text --version)"
echo "$version_text"
echo "$version_text" | grep -qi "WSL version" ||
  fail "wsl.exe --version did not report a WSL version; this needs WSL 2 from the Microsoft installer"

wsl_text --set-default-version 2 >/dev/null ||
  fail "the default WSL version could not be set to 2"

registered() { wsl_text -l -q | sed 's/[[:space:]]*$//' | grep -v '^$'; }
state_of() {
  # The state column of `wsl -l -v` for one distribution, matched on the whole name.
  wsl_text -l -v | sed 's/^[* ]*//' |
    awk -v want="$1" '{
      name = $0
      sub(/[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]*$/, "", name)
      if (name == want) { print $(NF - 1) }
    }'
}
version_of() {
  # The version column of the same listing. Setting the default version converts nothing that is
  # already registered, so a distribution this acceptance selected has to say for itself.
  wsl_text -l -v | sed 's/^[* ]*//' |
    awk -v want="$1" '{
      name = $0
      sub(/[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]*$/, "", name)
      if (name == want) { print $NF }
    }'
}

mapfile -t distributions < <(registered)
[ "${#distributions[@]}" -gt 0 ] ||
  fail "no WSL distribution is registered; install one before running this acceptance"
first="${distributions[0]}"
echo "registered: ${distributions[*]}"

if [ "${#distributions[@]}" -lt 2 ]; then
  echo "only one distribution is registered; making a second from it"
  tarball="$run_dir/$first.tar"
  # What wsl.exe said is kept, because a run that could not make its second distribution has to say
  # why rather than only that it could not.
  wsl.exe --export "$first" "$(windows_path "$tarball")" >"$run_dir/export.log" 2>&1 ||
    fail "$first could not be exported to make a second distribution: $(cat "$run_dir/export.log")"
  [ -s "$tarball" ] ||
    fail "exporting $first produced no image: $(cat "$run_dir/export.log")"
  echo "  exported $first: $(wc -c <"$tarball") bytes"
  # The directory this script imports into is this run's own, named after the distribution it
  # makes and the moment it made it. wsl.exe wants an empty directory, and a directory that is
  # already there belongs to something else: this run neither writes into it nor removes it.
  target_dir="$wsl_root/$second_name-$run_stamp"
  mkdir -p "$wsl_root" || fail "$wsl_root could not be made"
  # `mkdir` without `-p` is the ownership: it makes this directory or it fails because something
  # is already there, and only a directory this run made is one this run may remove.
  mkdir "$target_dir" ||
    fail "the image directory $target_dir could not be made by this run, so this run has none of its own to import into"
  made_directory="$target_dir"
  wsl.exe --import "$second_name" "$(windows_path "$target_dir")" \
    "$(windows_path "$tarball")" --version 2 >"$run_dir/import.log" 2>&1 ||
    fail "$second_name could not be imported into $target_dir: $(cat "$run_dir/import.log")"
  made_distribution="$second_name"
  # The one this run made, by the name it gave it. Reading a position out of the listing again
  # would take whichever name the registry happens to put second.
  second="$second_name"
  mapfile -t distributions < <(registered)
else
  second="${distributions[1]}"
fi
[ "${#distributions[@]}" -ge 2 ] || fail "this acceptance needs two distributions"
[ "$first" != "$second" ] || fail "the two distributions this acceptance needs are the same one"
for distribution in "$first" "$second"; do
  version="$(version_of "$distribution")"
  [ "$version" = "2" ] ||
    fail "$distribution is WSL version ${version:-unknown}, and this acceptance is about WSL 2"
done
pass "two WSL 2 distributions are registered: $first and $second"

# ---------------------------------------------------------------------------------------------
step "2. Argument vectors cross --exec unchanged"

# Every one of these would be rewritten by a shell. `--exec` hands the vector to the program named
# next, so each arrives as one element.
# The values below are meant to stay literal: the point is that nothing expands them.
# shellcheck disable=SC2016
awkward_out="$(wsl.exe -d "$first" -u "$linux_user" --exec /bin/sh -c 'printf "%s\n" "$@"' -- \
  "arg 1" "arg'2" 'arg"3' 'space and $HOME and `backtick`' 'semi;colon && ampersand' | tr -d '\r')"
# shellcheck disable=SC2016
awkward_expected="$(printf 'arg 1\narg'"'"'2\narg"3\nspace and $HOME and `backtick`\nsemi;colon && ampersand')"
[ "$awkward_out" = "$awkward_expected" ] ||
  fail "an argument vector was rewritten across the WSL boundary: $awkward_out"
pass "argument vectors cross --exec exactly as they were built"

# ---------------------------------------------------------------------------------------------
step "3. Each distribution runs KalaReach on its own"

# The helper and the daemon are built inside the distribution, from the same commit, into that
# distribution's own filesystem. Nothing here is a Windows binary, and nothing crosses /mnt.
commit="$(git rev-parse HEAD)"

build_inside() {
  local distribution="$1"
  # The whole installed set, from one commit: the helper, the daemon and worker it needs, and the
  # bridge suite step 7 runs. A set from another commit, or a set only half replaced, would prove
  # something about another candidate, so the manifest names the commit and the hash of every
  # installed file, and this reads all of it. A set built elsewhere and installed here carries the
  # manifest its builder wrote, so an incomplete copy fails this rather than passing it.
  if wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -c \
    "cd / && test \"\$(head -n 1 '$manifest_path' 2>/dev/null)\" = '$commit' && tail -n +2 '$manifest_path' | awk '{ print \$2 }' | sort >/tmp/kr-acc-manifest-carries && printf '%s\n' '$helper_relative' '$(dirname "$helper_relative")/kr-controller' '$(dirname "$helper_relative")/kr-worker' '$suite_relative' | sort >/tmp/kr-acc-manifest-wanted && cmp -s /tmp/kr-acc-manifest-carries /tmp/kr-acc-manifest-wanted && tail -n +2 '$manifest_path' | sha256sum -c --quiet" 2>/dev/null; then
    echo "  $distribution: the helper at $helper_path and its bridge suite were built from this commit"
    return 0
  fi
  echo "  $distribution: building the helper inside the distribution (this takes a few minutes)"
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "
    set -e
    command -v cargo >/dev/null 2>&1 || {
      echo 'cargo is not installed in this distribution, and no helper built from this commit is installed in it' >&2
      exit 1
    }
    rm -rf /tmp/kalareach-src
    cp -a /mnt/c/kala/kalareach /tmp/kalareach-src
    cd /tmp/kalareach-src
    cargo build -p kr-cli --bin kr -p kr-controller --bin kr-controller -p kr-worker --bin kr-worker
    install -m 0755 target/debug/kr '$helper_path'
    install -m 0755 target/debug/kr-controller '$(dirname "$helper_path")/kr-controller'
    install -m 0755 target/debug/kr-worker '$(dirname "$helper_path")/kr-worker'
    # The suite is installed like the rest of the set, so step 7 runs what this distribution
    # carries rather than a source tree that has to survive beside it. cargo names the executable
    # it built for each artefact; the one wanted here is the test target, and the command line
    # above selects exactly one of those.
    suite=\"\$(cargo test -p kr-cli --test bridge --no-run --message-format=json |
      sed -n 's/.*\"kind\":\\[\"test\"\\].*\"executable\":\"\\([^\"]*\\)\".*/\\1/p' | tail -n 1)\"
    test -n \"\$suite\" || {
      echo 'the build produced no bridge suite executable' >&2
      exit 1
    }
    mkdir -p /usr/local/lib
    install -m 0755 \"\$suite\" '$suite_path'
    # The manifest is written last and covers the whole set, so a half-installed set never looks
    # like a set built from this commit.
    cd /
    { echo '$commit'
      sha256sum '$helper_relative' '$(dirname "$helper_relative")/kr-controller' \
        '$(dirname "$helper_relative")/kr-worker' '$suite_relative'
    } >'$manifest_path.partial'
    mv '$manifest_path.partial' '$manifest_path'
  " || fail "$distribution could not build the Linux helper"
}

# A distribution this run imported is a copy of another one, and a copy of an installation is not a
# second installation: it carries the first one's environment identity, its registry and its
# staging area, and those name a device and an inode that are different here. The daemon in the
# copy is right to refuse them, so the copy is given none of it before anything starts in it.
#
# Two things have to be right, and neither is guessed at here.
#
# **Which directories.** The product derives its runtime and state roots from the directories this
# OS user's environment names. Every one of those inputs is mirrored into a directory of this run's
# own, the installed helper is asked where it then reads an account token (which lies directly in
# the runtime root) and where it publishes the identity it allocates on a first use (which lies
# directly in the state root), and each answer is mapped back through the input it came from. A
# root the product names outside every mirrored input is the same absolute path here as it is in
# the distribution this one was copied from, and is taken as it stands.
#
# **Which storage.** A directory that is not there was not inherited, and is left alone. A
# directory that is there is removed only when the whole of it -- the directory and everything
# under it -- is on the filesystem the image carries, which is the one the root of this
# distribution is on. Anything else -- a symbolic link out to storage shared between
# distributions, a bind mount of somewhere else at its top or at any directory inside it -- is not
# this copy's to remove and not something a copy can be made independent of, so the run stops
# before it removes anything and says which path it was.
#
# Only a distribution this run imported is ever handed to this.
clear_inherited_installation() {
  local distribution="$1"
  echo "  $distribution: removing the installation it inherited from the distribution it was copied from"
  # The script below runs inside the distribution, so it stays unexpanded here and takes the
  # helper's path as an argument rather than as text this shell substitutes into it.
  # shellcheck disable=SC2016
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc '
    set -e
    helper="$1"
    probe="$(mktemp -d /tmp/kr-acc-probe.XXXXXX)"
    # Each mirror is owner-only, because a mirror can become a root the product creates its files
    # in directly, and the product refuses a root anyone else can read.
    #
    # The real value of each input is held in a shell variable beside its mirror rather than in a
    # file of pairs. A path may carry a space, a tab or a trailing blank, and a line of text read
    # back as two fields would not return the value the product was given.
    index=0
    for name in HOME XDG_STATE_HOME XDG_RUNTIME_DIR KR_STATE_DIR KR_RUNTIME_DIR; do
      eval "value=\${$name-}"
      [ -n "$value" ] || continue
      index=$((index + 1))
      mkdir -m 0700 "$probe/$index"
      eval "configured_$index=\$value"
      eval "export $name=\"\$probe/\$index\""
    done
    token="$("$helper" --json account token show | tr -d " \n\r" |
      sed -n "s/.*\"path\":\"\([^\"]*\)\".*/\1/p")"
    [ -n "$token" ] || {
      echo "the helper did not say where it reads an account token, so its runtime root is not known" >&2
      exit 1
    }
    # This has no daemon to reach and fails once it has allocated the identity, which is the part
    # being read here.
    "$helper" list >/dev/null 2>&1 || true
    marker="$(find "$probe" -type f -printf "%d %p\n" | sort -n | head -n 1 | cut -d" " -f2-)"
    [ -n "$marker" ] || {
      echo "the helper published no identity of its own, so its state root is not known" >&2
      exit 1
    }
    image_device="$(stat -c %d /)"
    for named in "$(dirname "$token")" "$(dirname "$marker")"; do
      real="$named"
      mapped=0
      while [ "$mapped" -lt "$index" ]; do
        mapped=$((mapped + 1))
        mirror="$probe/$mapped"
        case "$named" in
          "$mirror" | "$mirror"/*)
            eval "value=\$configured_$mapped"
            real="$value${named#"$mirror"}"
            ;;
        esac
      done
      # What the path leads to, not what it says: a component of it may be a link somewhere else.
      resolved="$(readlink -m "$real")"
      if [ ! -e "$resolved" ]; then
        echo "  nothing of the product at $real"
        continue
      fi
      device="$(stat -c %d "$resolved")"
      [ "$device" = "$image_device" ] || {
        echo "$real leads to $resolved, which is on storage this image does not carry and may be \
shared with the distribution this one was copied from" >&2
        exit 1
      }
      # The whole tree, not only its top: a directory inside it can mount storage of its own, and
      # a removal that walked into one would take something this image does not carry with it.
      # Nothing is removed until the walk below has found none.
      find "$resolved" -xdev -printf "%D %p\n" >"$probe/crossings"
      crossing="$(grep -v "^$device " "$probe/crossings" | head -n 1 | cut -d" " -f2-)"
      [ -z "$crossing" ] || {
        echo "$real holds $crossing, which is on storage this image does not carry and may be \
shared with the distribution this one was copied from" >&2
        exit 1
      }
      # The same boundary again while removing, so this cannot leave the filesystem it measured
      # even if something is mounted between the two walks.
      find "$resolved" -xdev -depth -delete
      echo "  removed the inherited $real"
    done
    rm -rf "${probe:?}"
    # The leftovers this acceptance itself put in the distribution that was copied. The file it
    # writes a daemon identifier into would otherwise name a process in that other distribution.
    rm -f /tmp/kr-acc-controller.pid /tmp/kr-controller.log
  ' sh "$helper_path" ||
    fail "$distribution could not be given an installation of its own"
}

start_daemon_inside() {
  local distribution="$1"
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "
    set -e
    running=0
    if [ -f /tmp/kr-acc-controller.pid ] && kill -0 \$(cat /tmp/kr-acc-controller.pid) 2>/dev/null; then
      running=1
    fi
    if [ \$running -eq 0 ]; then
      nohup '$(dirname "$helper_path")/kr-controller' \
        --worker '$(dirname "$helper_path")/kr-worker' --secret-store file \
        >/tmp/kr-controller.log 2>&1 &
      echo \$! >/tmp/kr-acc-controller.pid
    fi
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if '$helper_path' list >/dev/null 2>&1; then
        exit 0
      fi
      sleep 1
    done
    echo 'the daemon inside the distribution did not answer' >&2
    tail -n 40 /tmp/kr-controller.log >&2 || true
    exit 1
  " || fail "$distribution did not start its own control daemon"
  daemons="$daemons $distribution"
}

inside() {
  local distribution="$1"
  shift
  # The distribution's own default paths, which is what the helper the Windows side starts will
  # discover. A directory of this run's own here would leave the two halves talking past each other.
  #
  # What the command answered is held before the carriage returns are taken out of it, because a
  # pipeline would answer for the last program in it: a read that failed inside the distribution
  # has to reach the caller as a failure rather than as an empty string.
  local answer
  answer="$(wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "$*")" || return $?
  printf '%s\n' "$answer" | tr -d '\r'
}

# One line of JSON with the spaces taken out, so an assertion can name a whole key path.
compact() { tr -d ' \n\r'; }

# The first value one named string key carries in a compacted document, or nothing. These are this
# product's own documents and the key is named in full, so the match is exact; and finding nothing
# is not a failure here, because the check that follows says what was missing.
json_string() {
  awk -v key="\"$1\":\"" '
    {
      start = index($0, key)
      if (start == 0) { exit }
      rest = substr($0, start + length(key))
      end = index(rest, "\"")
      if (end == 0) { exit }
      print substr(rest, 1, end - 1)
      exit
    }'
}

build_inside "$first"
start_daemon_inside "$first"
build_inside "$second"
# The set is installed before the inherited installation is removed, because removing it is done by
# asking the installed helper where the product keeps it. A second distribution that was already
# registered belongs to the machine, not to this run, and is started as it is.
if [ "$made_distribution" = "$second" ]; then
  clear_inherited_installation "$second"
fi
start_daemon_inside "$second"
pass "each distribution started its own KalaReach, from its own installed set, with no native Windows installation"

# Linux paths, binaries and process identifiers stay inside the distribution. Each assertion below
# names the process it is about and reads that process's own Linux paths out of /proc.
installed_dir="$(dirname "$helper_path")"
for distribution in "$first" "$second"; do
  # The daemon: the Linux binary this run installed in this distribution, running as the Linux user
  # the enrolment names.
  daemon_pid="$(inside "$distribution" 'cat /tmp/kr-acc-controller.pid')" ||
    fail "$distribution could not be asked for the daemon this run started in it"
  [[ "$daemon_pid" =~ ^[0-9]+$ ]] ||
    fail "$distribution did not report a Linux process identifier for its daemon"
  daemon_exe="$(inside "$distribution" "readlink -f /proc/$daemon_pid/exe | head -n 1")" ||
    fail "$distribution could not be asked what its daemon $daemon_pid runs"
  [ "$daemon_exe" = "$installed_dir/kr-controller" ] ||
    fail "$distribution's daemon $daemon_pid runs $daemon_exe, not the $installed_dir/kr-controller installed in it"
  daemon_user="$(inside "$distribution" "stat -c %U /proc/$daemon_pid | head -n 1")" ||
    fail "$distribution could not be asked who its daemon $daemon_pid runs as"
  [ "$daemon_user" = "$linux_user" ] ||
    fail "$distribution's daemon runs as $daemon_user and the enrolment names $linux_user"
  daemon_root="$(inside "$distribution" "readlink /proc/$daemon_pid/root | head -n 1")" ||
    fail "$distribution could not be asked what its daemon $daemon_pid has for a root"
  [ "$daemon_root" = "/" ] ||
    fail "$distribution's daemon has root $daemon_root rather than this distribution's own"

  # A session of the distribution's own, named by the identifier the create answered with.
  session="$(inside "$distribution" "'$helper_path' --json new --invisible --shell /bin/sh" | compact)" ||
    fail "$distribution could not be asked to create a session of its own"
  created="$(printf '%s' "$session" | json_string session_id)"
  [ -n "$created" ] ||
    fail "$distribution could not create a session of its own: $session"
  echo "  $distribution created session $created"
  listed="$(inside "$distribution" "'$helper_path' --json list" | compact)" ||
    fail "$distribution could not be asked what sessions it has"
  case "$listed" in
    *"\"session_id\":\"$created\""*) : ;;
    *) fail "$distribution does not list $created, the session it created: $listed" ;;
  esac

  # The worker serving it: this distribution's own Linux process, running the binary installed
  # here, as the same Linux user, with this distribution's filesystem as its root. Nothing on the
  # Windows side takes part in it, and nothing it opens comes through /mnt.
  #
  # This run created one session in this distribution and closes it below, so one worker is
  # running here and it is that session's. More than one would leave these checks unable to say
  # which process they are about, so the count is asserted rather than the newest one taken.
  workers="$(inside "$distribution" 'pgrep -x kr-worker')" ||
    fail "$distribution runs no worker for session $created"
  [ "$(printf '%s\n' "$workers" | grep -c .)" = "1" ] ||
    fail "$distribution runs more than one worker, so these checks cannot name the one serving $created: $workers"
  worker_pid="$(printf '%s\n' "$workers" | head -n 1)"
  [[ "$worker_pid" =~ ^[0-9]+$ ]] ||
    fail "$distribution did not report a Linux process identifier for the worker serving $created"
  worker_exe="$(inside "$distribution" "readlink -f /proc/$worker_pid/exe | head -n 1")" ||
    fail "$distribution could not be asked what its worker $worker_pid runs"
  [ "$worker_exe" = "$installed_dir/kr-worker" ] ||
    fail "$distribution's worker $worker_pid runs $worker_exe, not the $installed_dir/kr-worker installed in it"
  worker_user="$(inside "$distribution" "stat -c %U /proc/$worker_pid | head -n 1")" ||
    fail "$distribution could not be asked who its worker $worker_pid runs as"
  [ "$worker_user" = "$linux_user" ] ||
    fail "$distribution's worker runs as $worker_user and the enrolment names $linux_user"
  worker_root="$(inside "$distribution" "readlink /proc/$worker_pid/root | head -n 1")" ||
    fail "$distribution could not be asked what its worker $worker_pid has for a root"
  [ "$worker_root" = "/" ] ||
    fail "$distribution's worker has root $worker_root rather than this distribution's own"
  # The listing is made first and counted afterwards, so a listing that could not be made is a
  # failure here rather than a partial one counted as no crossings.
  crossing="$(inside "$distribution" "ls -l /proc/$worker_pid/fd >/tmp/kr-acc-worker-fds && awk '/ \\/mnt\\// { crossing++ } END { print crossing + 0 }' /tmp/kr-acc-worker-fds")" ||
    fail "$distribution could not be asked what its worker $worker_pid has open"
  [ "$crossing" = "0" ] ||
    fail "$distribution's worker has $crossing open files under /mnt, so it reaches out of the distribution"

  inside "$distribution" "'$helper_path' close $created" >/dev/null ||
    fail "$distribution could not close session $created"
done
pass "each distribution's daemon and worker are its own Linux processes, binaries, users and paths"

# ---------------------------------------------------------------------------------------------
step "4. Windows reaches each distribution through the process bridge"

kr_exe=""
for candidate in "C:/kala/target/debug/kr.exe" "target/debug/kr.exe" "C:/kala/target/release/kr.exe"; do
  if [ -f "$candidate" ]; then
    kr_exe="$candidate"
    break
  fi
done
[ -n "$kr_exe" ] || fail "no Windows kr.exe was found; build it with cargo build -p kr-cli --bin kr"
controller_exe="$(dirname "$kr_exe")/kr-controller.exe"
worker_exe="$(dirname "$kr_exe")/kr-worker.exe"
[ -f "$controller_exe" ] || fail "no Windows kr-controller.exe beside $kr_exe"

# The Windows daemon this run owns, with its keys in its own directory rather than the platform
# credential store. Every path handed to one of these native programs is a Windows path, including
# the two in the environment: this shell's own form means nothing to them.
windows_runtime="$run_dir/windows-run"
windows_state="$run_dir/windows-state"
mkdir -p "$windows_runtime" "$windows_state"
"$controller_exe" --runtime-dir "$(windows_path "$windows_runtime")" \
  --state-dir "$(windows_path "$windows_state")" \
  --worker "$(windows_path "$worker_exe")" \
  --secret-store file >"$run_dir/windows-controller.log" 2>&1 &
windows_daemon=$!
KR_RUNTIME_DIR="$(windows_path "$windows_runtime")"
KR_STATE_DIR="$(windows_path "$windows_state")"
export KR_RUNTIME_DIR KR_STATE_DIR
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if "$kr_exe" bridge list >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"$kr_exe" bridge list >/dev/null 2>&1 ||
  fail "the Windows daemon did not answer: $(tail -n 20 "$run_dir/windows-controller.log")"
pass "a Windows control daemon is running for this acceptance"

enrol_distribution() {
  local distribution="$1" label="$2" answer identity
  "$kr_exe" --json bridge enrol --access wsl --label "$label" --target "$distribution" \
    --user "$linux_user" --helper "$helper_path" --probe >"$run_dir/enrol-$label.json" 2>&1 ||
    fail "enrolling $distribution failed: $(cat "$run_dir/enrol-$label.json")"
  answer="$(compact <"$run_dir/enrol-$label.json")"
  identity="$(printf '%s' "$answer" | json_string environment_id)"
  [ -n "$identity" ] ||
    fail "enrolling $distribution recorded no environment identity: $answer"
  printf '%s' "$identity"
}

first_id="$(enrol_distribution "$first" "first")"
second_id="$(enrol_distribution "$second" "second")"
echo "  $first is environment $first_id"
echo "  $second is environment $second_id"
[ -n "$first_id" ] && [ -n "$second_id" ] ||
  fail "a distribution did not answer with an environment identity"
[ "$first_id" != "$second_id" ] ||
  fail "two distributions answered with the same environment identity"
pass "each distribution answered the bridge with its own environment identity"

# The identity the enrolment recorded is the one that distribution reports for itself.
for pair in "$first:$first_id" "$second:$second_id"; do
  distribution="${pair%%:*}"
  recorded="${pair##*:}"
  doctor="$(inside "$distribution" "'$helper_path' --json doctor" | compact)" ||
    fail "$distribution could not report on itself"
  reported="$(printf '%s' "$doctor" | json_string environment_id)"
  [ -n "$reported" ] ||
    fail "$distribution named no environment of its own: $doctor"
  [ "$reported" = "$recorded" ] ||
    fail "$distribution reports environment $reported and the enrolment recorded $recorded"
done
pass "the recorded identity is the one each distribution reports for itself"

refresh_and_check() {
  local label="$1" expect_id="$2" flags="${3:-}" text
  # shellcheck disable=SC2086
  "$kr_exe" --json bridge refresh "$label" $flags >"$run_dir/refresh-$label.json" 2>&1 ||
    fail "refreshing $label failed: $(cat "$run_dir/refresh-$label.json")"
  text="$(compact <"$run_dir/refresh-$label.json")"
  # The verification is what the destination answered. Matching the whole document would accept the
  # enrolment's own identity where the verification is absent, so the key path is named here.
  case "$text" in
    *"\"verification\":{\"environment_id\":\"$expect_id\""*) : ;;
    *) fail "the refresh of $label carried no verification from $expect_id: $text" ;;
  esac
  case "$text" in
    *'"role":"controller"'*) : ;;
    *) fail "the refresh of $label was not answered by a control daemon: $text" ;;
  esac
}

refresh_and_check first "$first_id"
refresh_and_check second "$second_id"
pass "a refresh opens a bridge to each distribution and carries a read to its own daemon"

# ---------------------------------------------------------------------------------------------
step "5. A listing reads the cache and starts nothing"

wsl.exe -t "$second" >/dev/null 2>&1 || fail "the second distribution could not be stopped"
sleep 2
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "$second is not stopped, so this check would prove nothing"

# A refresh observes, and observing starts nothing: this one was not told to start the environment.
"$kr_exe" --json bridge refresh second >"$run_dir/refresh-stopped.json" 2>&1 ||
  fail "the refresh of the stopped distribution failed: $(cat "$run_dir/refresh-stopped.json")"
observed="$(compact <"$run_dir/refresh-stopped.json")"
case "$observed" in
  *'"status":"environment_stopped"'*) : ;;
  *) fail "the refresh did not observe $second as stopped: $observed" ;;
esac
case "$observed" in
  *'"verification":null'*) : ;;
  *) fail "a stopped distribution answered a bridge: $observed" ;;
esac
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "the refresh started $second although it was not told to"
pass "a refresh observed the stopped distribution and started nothing"

"$kr_exe" --json bridge list >"$run_dir/list-while-stopped.json" 2>&1 ||
  fail "the listing failed: $(cat "$run_dir/list-while-stopped.json")"
listing="$(compact <"$run_dir/list-while-stopped.json")"
# The row for the stopped distribution alone: everything after its identity up to the end of that
# row. Another row's source or status cannot satisfy these.
row="${listing#*\"environment_id\":\""$second_id"\"}"
[ "$row" != "$listing" ] ||
  fail "the stopped distribution is missing from the listing: $listing"
row="${row%%\},\{\"enrolment\"*}"
case "$row" in
  *'"observation":"cache"'*) : ;;
  *) fail "the stopped distribution's row is not from the cache: $row" ;;
esac
case "$row" in
  *'"status":"environment_stopped"'*) : ;;
  *) fail "the listing does not repeat what was observed of $second: $row" ;;
esac
case "$row" in
  *'"last_observed_at_ms":'*) : ;;
  *) fail "the stopped distribution's row carries no observation time: $row" ;;
esac
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "the listing started $second, which a listing must never do"
pass "the listing reported the stopped distribution from the cache and started nothing"

# Starting the distribution again is one step; the daemon inside it is another, because stopping a
# distribution ends every process in it. The refresh below starts the distribution, and the bridge
# is checked once that distribution is serving again.
"$kr_exe" --json bridge refresh second --start >"$run_dir/refresh-start.json" 2>&1 ||
  fail "the refresh that was told to start failed: $(cat "$run_dir/refresh-start.json")"
[ "$(state_of "$second")" = "Running" ] ||
  fail "the refresh that was told to start did not start $second"
pass "a refresh that was told to start the distribution started it"

start_daemon_inside "$second"
refresh_and_check second "$second_id"
pass "the bridge reaches the distribution that was started again"

# ---------------------------------------------------------------------------------------------
step "6. NAT and mirrored networking"

# USERPROFILE is a Windows path. The redirection below is this shell's, so it needs the form this
# shell opens files by.
wslconfig_path="$(cygpath -u "${USERPROFILE:?the Windows profile directory}")/.wslconfig"
wslconfig_saved="$run_dir/wslconfig.saved"
if [ -f "$wslconfig_path" ]; then
  wslconfig_existed=1
  cp "$wslconfig_path" "$wslconfig_saved"
else
  : >"$wslconfig_saved"
fi

# What WSL said the first time it brought a distribution up under the mode being asked for. A host
# that cannot offer the mode says so there and falls back to another one.
mode_notice=""

networking_facts() {
  local mode="$1" distribution="$2" effective addresses
  # What WSL is actually doing, not what the file asks for.
  effective="$(inside "$distribution" 'wslinfo --networking-mode 2>/dev/null || true' | tr -d ' ')"
  echo "  $mode: $distribution reports networking mode: ${effective:-unknown}"
  [ -n "$effective" ] ||
    fail "$mode: this WSL build does not report its networking mode, so the mode cannot be established"
  # A mode that is not in effect is not a result about the bridge either way, so the failure names
  # what refused it. On a host that cannot offer the mode, what is missing is the host: the bridge
  # has simply not been measured there, and no automatic behaviour can be settled on one mode.
  [ "$effective" = "$mode" ] ||
    fail "$mode networking was asked for and $effective is in effect, so the bridge has not been \
measured in $mode on this machine. What this host said when it took the setting up: \
${mode_notice:-nothing}"
  addresses="$(inside "$distribution" 'ip -br addr')" ||
    fail "$mode: $distribution could not be asked what addresses it holds"
  echo "  $mode: $distribution addresses:"
  printf '    %s\n' "$addresses"
  inside "$distribution" 'ping -c 1 -W 2 127.0.0.1 >/dev/null 2>&1 && echo loopback-ok' |
    grep -q loopback-ok || fail "$mode: loopback is not reachable inside $distribution"
}

set_mode() {
  local mode="$1"
  printf '[wsl2]\nnetworkingMode=%s\n' "$mode" >"$wslconfig_path"
  wsl.exe --shutdown >/dev/null 2>&1 ||
    fail "the distributions could not be shut down to take up $mode networking"
  sleep 3
  # Bringing one distribution up is what makes WSL configure the network, and what makes it say so
  # when it cannot. The exit status is part of that answer rather than a failure of this run.
  if ! mode_notice="$(wsl.exe -d "$first" -u "$linux_user" --exec /bin/true 2>&1 | tr -d '\000\r')"; then
    mode_notice="${mode_notice:-wsl.exe exited non-zero and said nothing}"
  fi
  [ -z "$mode_notice" ] || echo "  $mode: this host said: $mode_notice"
  daemons=""
  for distribution in "$first" "$second"; do
    start_daemon_inside "$distribution"
  done
}

for mode in nat mirrored; do
  set_mode "$mode"
  networking_facts "$mode" "$first"
  # The bridge opens no socket, so it must behave the same in both modes. This is the measurement
  # that decides whether any automatic behaviour is needed, rather than assuming one.
  refresh_and_check first "$first_id"
  pass "$mode: the process bridge opened and carried a read unchanged"
done

# ---------------------------------------------------------------------------------------------
step "7. The helper refuses what may not cross"

# Input that is not a frame at all: the helper ends non-zero and says why.
malformed_code=0
malformed="$(printf 'not a bridge frame' |
  wsl.exe -d "$first" -u "$linux_user" --exec "$helper_path" bridge --stdio 2>&1)" || malformed_code=$?
[ "$malformed_code" -ne 0 ] ||
  fail "the helper served a stream that is not a bridge frame: $malformed"
echo "$malformed" | grep -qi "bridge" ||
  fail "the helper gave no diagnostic for input that is not a frame: $malformed"
pass "input that is not a bridge frame ends the helper non-zero with a diagnostic"

# A properly encoded handshake that declares a network origin has to be refused by protocol, not by
# a parse failure. The suite that builds those frames runs inside the distribution, against the
# Linux helper this run installed: it is told which command to drive, so it tests the installed
# helper rather than whichever build it was compiled beside.
inside "$first" "KR_TEST_COMMAND_BINARY='$helper_path' '$suite_path'" >"$run_dir/wsl-bridge-suite.log" 2>&1 ||
  fail "the bridge suite failed inside $first: $(tail -n 30 "$run_dir/wsl-bridge-suite.log")"
grep -q "test result: ok" "$run_dir/wsl-bridge-suite.log" ||
  fail "the bridge suite reported no result inside $first"
pass "the bridge suite passes inside the distribution, including the refusal of a network origin"

echo
echo "KR-ACC-011: $passed checks passed."
