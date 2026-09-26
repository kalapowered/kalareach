#!/usr/bin/env bash
# Takes every performance figure this host can take, in one run, and records each one beside the
# conditions it was taken under.
#
# Section 27 states its targets for a reference host: at least four processors and 8 GiB of memory,
# the operating system and architecture recorded beside every figure, and the host idle apart from
# the measurement. This script builds the release profile once, and then runs each measurement this
# host can take, one at a time:
#
#   performance   scripts/performance.sh                      KR-PERF-001 to KR-PERF-004
#   terminal      kr-term's output handling                   KR-PERF-007
#   transport     kr-transport's scheduling and reconnect     KR-PERF-005 and KR-PERF-006
#   reconnect     kr-client's half of a reconnect             KR-PERF-006
#   companion     the companion's semantic display            KR-PERF-008
#   stress        section 27's 50-session stress run          KR-PERF-001, KR-PERF-003 and
#                 (tests/perf)                                KR-PERF-007 under the stress
#   descriptions  scripts/bench-descriptions.sh               KR-PERF-009, where the host can hold
#                                                             its budget
#
# KR-PERF-010 is measured on a paired phone with a connected media path to the voice provider, so a
# run names it as not run here, with that reason.
#
# Every measurement writes its figures under KR_TEST_ARTIFACTS_DIR as Markdown sections headed by
# the identifier they measure (`## KR-PERF-007 ...`), each with a verdict. For each identifier this
# script adds a section of its own to bench-all.md there: the host, the conditions at the edges of
# each step that measured it, the outcome, and whether its figures are reference figures. A
# directory that already holds records is appended to, and only what this run added is read; a
# directory another run is writing to at the same time mixes the two runs' records. When
# KR_TEST_ARTIFACTS_DIR is not set, the run makes a directory of its own and says where it is.
#
# A step's outcome is its exit status and the verdicts its records give: a measurement can record a
# missed target without failing, where it does not assert the target on a host short of the
# reference host, and that still counts as a missed target here.
#
# The conditions read for each step are the other work on the machine over the ten seconds before
# it began and through the whole of it, the share of the step the hypervisor took from this machine
# (where the platform accounts for it), and the load average at both edges. Other work is read by
# tests/perf's kr-perf-watch, which reads the whole machine every two seconds: all processors' idle
# time, and every process with the processor time charged to it. This run is this script and every
# process descended from it, which includes the workers a measurement's daemon starts, and a
# process once of the run stays of it. The reader bounds the processor time the machine spent on
# anything but the run in any five seconds: the processors' time less their idle time, less the
# least the run's processes can have used. A figure is a reference figure only when the host has the
# reference host's processors and memory, that bound stayed under one processor's worth before and
# through each step, no step lost more than one part in a hundred of its time to a hypervisor, no
# measurement's own record names a shortfall, and the run kept all of its evidence; where a reading
# could not be taken, the figure is not a reference figure. The load average is recorded rather
# than judged: its one-minute average still carries the step before.
#
# Usage:
#   scripts/bench-all.sh [--reference-host] [--only <step>[,<step>...]]
#
#   --reference-host  the figures are to count as reference figures. The run waits up to ten minutes
#                     before each step for other work to stop, and fails naming every condition the
#                     host did not meet. Every figure is still taken and recorded.
#   --only            runs only the named steps.
#
# Exit status: 0 when every measurement that ran met its target and recorded its figures; 1 when a
# target was missed, a measurement failed or recorded no figure, the run could not keep its
# evidence, or, with --reference-host, the host did not meet a condition; 2 for a usage error.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 2

usage() {
  echo "usage: scripts/bench-all.sh [--reference-host] [--only <step>[,<step>...]]" >&2
  exit 2
}

all_steps="performance terminal transport reconnect companion stress descriptions"
reference=0
only=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --reference-host) reference=1 ;;
    --only)
      [ "$#" -ge 2 ] || usage
      only="$(printf '%s' "$2" | tr ',' ' ')"
      shift
      ;;
    *) usage ;;
  esac
  shift
done
for step in $only; do
  case " $all_steps " in
    *" $step "*) ;;
    *)
      echo "unknown step $step; the steps are: $all_steps" >&2
      exit 2
      ;;
  esac
done
steps="${only:-$all_steps}"

# The reference host section 27 states, and the two readings it leaves to the harness: how much of
# a step a hypervisor may take (the cutoff crates/kr-transport/tests/support/conditions.rs applies
# too) and how much other work may run beside a step, in processors' worth in any five seconds.
reference_processors=4
reference_memory_mib=8192
max_stolen_share=0.01
quiet_processors=1.0

# What the host is. `processors` is what the measurements can run on, which is what the reference
# host is held to.
os_name="$(uname -s)"
arch="$(uname -m)"
# A count that could not be read is left empty, and is a shortfall rather than a number.
count_or_empty() {
  case "$1" in
    "" | *[!0-9]*) ;;
    *) [ "$1" -gt 0 ] && printf '%s' "$1" ;;
  esac
}
# A count from a command, `$@`, taken only when the command succeeded.
count_from() {
  local text
  text="$("$@" 2>/dev/null)" && count_or_empty "$text"
}
case "$os_name" in
  Darwin)
    processors="$(count_from sysctl -n hw.logicalcpu)"
    memory_bytes="$(count_from sysctl -n hw.memsize)"
    memory_mib="$(count_or_empty "${memory_bytes:+$((memory_bytes / 1048576))}")"
    processor_name="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'not reported here')"
    os_release="macOS $(sw_vers -productVersion 2>/dev/null || uname -r)"
    ;;
  *)
    processors="$(count_from nproc)"
    # shellcheck disable=SC2016 # an awk program, which awk expands
    memory_mib="$(count_from awk '/^MemTotal:/ { printf "%d\n", $2 / 1024; found = 1 }
      END { exit !found }' /proc/meminfo)"
    processor_name="$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -1)"
    processor_name="${processor_name:-not reported here}"
    # shellcheck disable=SC1091 # the host's own description, read where it has one
    os_release="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}")"
    os_release="${os_release:-$os_name $(uname -r)}"
    ;;
esac
commit="$(git rev-parse HEAD 2>/dev/null || echo 'not a checkout')"

load_average() {
  if [ -r /proc/loadavg ]; then
    cut -d' ' -f1-3 /proc/loadavg
  else
    sysctl -n vm.loadavg 2>/dev/null | tr -d '{}' | awk '{ print $1, $2, $3 }'
  fi
}

# Where the kernel counts the time a hypervisor took from this machine: Linux's /proc/stat.
stolen_accounted=0
if [ -e /proc/stat ]; then
  stolen_accounted=1
fi

# The aggregate processor line's total and stolen ticks.
cpu_ticks() {
  awk '$1 == "cpu" {
    print $2 + $3 + $4 + $5 + $6 + $7 + $8 + $9, $9
    found = 1
    exit
  }
  END { exit !found }' /proc/stat
}

# The share of the span between two cpu_ticks readings that the hypervisor took.
stolen_share() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    split(a, x, " "); split(b, y, " "); t = y[1] - x[1]
    if (t <= 0 || y[2] < x[2]) { print "unread"; exit }
    printf "%.4f\n", (y[2] - x[2]) / t
  }'
}

# Whether `$1 < $2`, for decimal readings.
below() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 < b + 0) }'
}

percent() {
  awk -v s="$1" 'BEGIN { printf "%.2f%%", s * 100 }'
}

# The evidence directory, and a working directory of this run's own.
if [ -z "${KR_TEST_ARTIFACTS_DIR:-}" ]; then
  temporary="${TMPDIR:-/tmp}"
  KR_TEST_ARTIFACTS_DIR="$(mktemp -d "${temporary%/}/kalareach-bench.XXXXXX")" || exit 1
fi
if ! mkdir -p "$KR_TEST_ARTIFACTS_DIR" || [ ! -w "$KR_TEST_ARTIFACTS_DIR" ]; then
  echo "bench-all: the evidence directory $KR_TEST_ARTIFACTS_DIR cannot be written" >&2
  exit 1
fi
# Absolute, because each suite runs in its own package's directory and would read a relative path
# as a directory of its own.
evidence="$(cd "$KR_TEST_ARTIFACTS_DIR" && pwd)"
KR_TEST_ARTIFACTS_DIR="$evidence"
export KR_TEST_ARTIFACTS_DIR
record="$evidence/bench-all.md"
temporary="${TMPDIR:-/tmp}"
work="$(mktemp -d "${temporary%/}/kalareach-bench-work.XXXXXX")" || exit 1
trap 'rm -rf "${work:?}"' EXIT

# How long each record file was when the run began: what a file holds beyond that is this run's.
# What the run keeps about its own steps is kept in memory, in variables named after them, so no
# write or read of it can fail and be taken for an empty answer.
size_of() {
  if [ -f "$1" ]; then wc -c < "$1" | tr -d ' '; else echo 0; fi
}
start_sizes=""
for file in "$evidence"/*.md; do
  [ -f "$file" ] || continue
  if ! size="$(size_of "$file")" || [ -z "$size" ]; then
    echo "bench-all: the record $file cannot be read" >&2
    exit 1
  fi
  start_sizes="$start_sizes$(basename "$file") $size
"
done
started_at() {
  local line
  split_lines "$start_sizes"
  for line in ${found_lines[@]+"${found_lines[@]}"}; do
    if [ "${line% *}" = "$1" ]; then
      echo "${line##* }"
      return
    fi
  done
  echo 0
}

# Splits `$1` into the array `found_lines`, one element for each line that is not empty.
split_lines() {
  local IFS=$'\n'
  set -f
  # shellcheck disable=SC2206 # the split on newlines is the point, and globbing is off
  found_lines=($1)
  set +f
}

# A step's results.
put() { printf -v "result_${1}_$2" '%s' "$3"; }
get() {
  local name="result_${1}_$2"
  printf '%s' "${!name-}"
}
# A problem with a step, about one identifier it measures or, with "-", about the step itself.
add_problem() {
  local name="problems_$1"
  printf -v "$name" '%s%s %s\n' "${!name-}" "$2" "$3"
}
# The problems of a step that concern an identifier, or every one of them when it is "-".
problems_of() {
  local name="problems_$1" line joined=""
  split_lines "${!name-}"
  for line in ${found_lines[@]+"${found_lines[@]}"}; do
    if [ "$2" = - ] || [ "${line%% *}" = "$2" ] || [ "${line%% *}" = - ]; then
      joined="${joined:+$joined; }${line#* }"
    fi
  done
  printf '%s' "$joined"
}
# A reference-host condition a measurement's own record says it did not meet.
add_shortfall() {
  local name="shortfalls_$1"
  printf -v "$name" '%s%s\n' "${!name-}" "$2"
}
# The steps that ran, in order.
ran=""

echo "kalareach performance figures"
echo "  commit: $commit"
echo "  host: $os_release, $os_name $arch"
echo "  processor: $processor_name"
echo "  processors: ${processors:-unread} logical, against the reference host's $reference_processors"
echo "  memory: ${memory_mib:-unread} MiB, against the reference host's $reference_memory_mib MiB"
if [ "$reference" -eq 1 ]; then
  echo "  reference figures: asked for"
else
  echo "  reference figures: not asked for"
fi
echo "  steps: $steps"
echo "  evidence: $evidence"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# The host's own shortfalls, which hold for every step.
host_shortfalls=""
if [ -z "$processors" ]; then
  host_shortfalls="the number of processors could not be read"
elif [ "$processors" -lt "$reference_processors" ]; then
  host_shortfalls="$processors processors, below the reference host's $reference_processors"
fi
if [ -z "$memory_mib" ]; then
  host_shortfalls="${host_shortfalls:+$host_shortfalls; }the memory could not be read"
elif [ "$memory_mib" -lt "$reference_memory_mib" ]; then
  host_shortfalls="${host_shortfalls:+$host_shortfalls; }$memory_mib MiB of memory, below the reference host's $reference_memory_mib MiB"
fi

selected() {
  case " $steps " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# One release build of everything the steps run, before anything is measured, so that no figure is
# taken while a build is still running.
build_failed=0
build() {
  echo
  echo "== $(date '+%T') $*"
  "$@" || build_failed=1
}
build cargo build --locked --release --workspace
if selected performance; then
  build cargo test --locked --release --no-run -p kr-worker --test performance --bench input_latency
fi
if selected terminal; then
  build cargo test --locked --release --no-run -p kr-term --test perf
fi
if selected transport; then
  build cargo test --locked --release --no-run -p kr-transport --test perf
fi
if selected reconnect; then
  build cargo test --locked --release --no-run -p kr-client --test session
fi
if selected companion; then
  build pnpm install --frozen-lockfile
fi
if selected stress; then
  build cargo test --locked --release --no-run -p kr-perf --test stress
  # The fixture package the plugin host serves beside the stress run's sessions.
  build bash scripts/build-plugin-fixtures.sh
fi
if [ "$build_failed" -ne 0 ]; then
  echo "bench-all: the build failed, so nothing was measured"
  exit 1
fi

# The reader of other work, which the build above made: tests/perf's kr-perf-watch. It reads the
# whole machine every two seconds, all processors' idle time and every process with the processor
# time charged to it, and prints "<bound> <average>": the most processors' worth of processor time
# the machine can have spent on anything but this run in any five seconds it read, and over all of
# them. Where its readings cannot show that, it prints "unread: <why>". This run is this script and
# every process descended from it, and a process once of it stays of it.
watcher="$(cargo build --locked --release -p kr-perf --bin kr-perf-watch --message-format=json \
  2>/dev/null | sed -n 's/.*"executable":"\([^"]*kr-perf-watch\)".*/\1/p' | tail -1)"
if [ -z "$watcher" ] || [ ! -x "$watcher" ]; then
  echo "bench-all: the build left no reader of other work, so nothing was measured"
  exit 1
fi

# A reading of other work as the reader printed it, checked: from a reader that ended well, one line
# of two numbers or one that says why it is unread. Anything else is unread, with what the reader
# did. `$1` is the reader's exit status and `$2` what it printed.
checked_reading() {
  local form='^([0-9]+\.[0-9][0-9] [0-9]+\.[0-9][0-9]|unread: .+)$'
  if [ "$1" -ne 0 ]; then
    printf 'unread: the reader of other work ended with status %s' "$1"
    return
  fi
  case "$2" in
    *$'\n'*) ;;
    *)
      if [[ $2 =~ $form ]]; then
        printf '%s' "$2"
        return
      fi
      ;;
  esac
  printf 'unread: the reader of other work printed "%s"' "$(printf '%s' "$2" | tr '\n' ' ')"
}

# A checked reading of other work in words.
other_words() {
  case "$1" in
    "") printf 'unread' ;;
    unread*) printf '%s' "$1" ;;
    *) printf '%s in the busiest five seconds and %s on average' "${1%% *}" "${1#* }" ;;
  esac
}

# Whether a checked reading of other work stayed under one processor's worth in every five seconds.
quiet() {
  case "$1" in
    "" | unread*) return 1 ;;
    *) below "${1%% *}" "$quiet_processors" ;;
  esac
}

# Waits for reader `$1` to end, for at most `$2` seconds, and then stops it. Sets `reader_status` to
# its exit status, or leaves it empty when the reader had not ended; a reader that does not end even
# once stopped, as a process held in the kernel can, is left behind rather than waited for.
reader_status=""
finish_reader() {
  local waited=0
  reader_status=""
  while kill -0 "$1" 2>/dev/null && [ "$waited" -lt $(($2 * 20)) ]; do
    sleep 0.05
    waited=$((waited + 1))
  done
  if kill -0 "$1" 2>/dev/null; then
    kill -9 "$1" 2>/dev/null
    return
  fi
  wait "$1"
  reader_status=$?
}

# Other work over the next ten seconds, checked. The reader has a minute beyond its ten seconds.
other_work() {
  local text
  "$watcher" --run "$$" --for 10 > "$work/settle.out" 2>&1 &
  finish_reader "$!" 70
  if [ -z "$reader_status" ]; then
    echo "unread: the reader of other work had not ended a minute after its reading"
  elif ! text="$(cat "$work/settle.out")"; then
    echo "unread: what the reader of other work printed could not be read back"
  else
    checked_reading "$reader_status" "$text"
  fi
}

# Reads other work over the ten seconds before a step and, with --reference-host, reads again until
# it stays under one processor's worth, for at most ten minutes. Prints the last reading.
settle() {
  local reading attempts=0
  reading="$(other_work)"
  while [ "$reference" -eq 1 ] && [ "${reading#unread}" = "$reading" ] &&
    ! quiet "$reading" && [ "$attempts" -lt 59 ]; do
    attempts=$((attempts + 1))
    reading="$(other_work)"
  done
  echo "$reading"
}

# Evidence this run could not keep or read back, which fails the run.
evidence_lost=0
lost_places=""
lost() {
  evidence_lost=1
  lost_places="${lost_places:+$lost_places; }$1"
  echo "bench-all: this run could not keep or read back its evidence at $1" >&2
}

# What the sections of identifier `$3` that file `$1` gained beyond byte `$2` say against the target
# and the reference host: one "missed <heading>: <verdict>" line for each verdict that says the
# target was not met, and one "short <heading>: <condition>" line for each condition the
# measurement found missing. The whole of the gained text is read.
verdicts() {
  tail -c +"$(($2 + 1))" "$1" | awk -v id="$3" '
    /^## / { heading = substr($0, 4); inside = (heading == id || index(heading, id " ") == 1); next }
    !inside { next }
    { line = $0; sub(/^ +/, "", line) }
    line ~ /^verdict / {
      verdict = line; sub(/^verdict +/, "", verdict)
      if (verdict ~ /not met|below the target|outside the target|not valid/) print "missed " heading ": " verdict
    }
    line ~ /^condition missing / { sub(/^condition missing +/, "", line); print "short " heading ": " line }
    line ~ /^reference host +short: / { sub(/^reference host +short: +/, "", line); print "short " heading ": " line }'
}

# Runs one step and records its conditions, its exit status, whether each identifier it measures
# recorded a figure, and what those figures' own verdicts say. `$2` names each such identifier with
# the record file its figures land in.
run_step() {
  local step="$1" expected="$2" status logged load_in load_out other_in during ticks_in="" ticks_out
  local pair identifier file name gained found line watch reader waited began_read text
  shift 2
  echo
  echo "== $(date '+%T') step $step: $*"
  other_in="$(settle)"
  load_in="$(load_average)"
  if [ "$stolen_accounted" -eq 1 ]; then
    ticks_in="$(cpu_ticks)" || ticks_in=""
  fi
  echo "  other work in processors' worth over the ten seconds before the step:" \
    "$(other_words "$other_in"); load average entering: $load_in"
  # Other work through the step, from a reading taken before it begins to one taken after it ends.
  watch="$work/$step.watch"
  "$watcher" --run "$$" --until "$watch.stop" --ready "$watch.ready" > "$watch.out" 2>&1 &
  reader=$!
  waited=0
  while [ ! -e "$watch.ready" ] && kill -0 "$reader" 2>/dev/null && [ "$waited" -lt 600 ]; do
    sleep 0.05
    waited=$((waited + 1))
  done
  began_read=0
  if [ -e "$watch.ready" ]; then
    began_read=1
  fi
  "$@" 2>&1 | tee "$evidence/$step.log"
  # Both statuses in one statement: the next command replaces them.
  status=${PIPESTATUS[0]} logged=${PIPESTATUS[1]}
  # The reader takes its last reading and prints within a second of being asked; one that has not
  # ended within a minute is stopped, and its reading is unread.
  : > "$watch.stop" || lost "$watch.stop"
  finish_reader "$reader" 60
  if [ -z "$reader_status" ]; then
    during="unread: the reader of other work had not ended a minute after it was asked to"
  elif [ "$began_read" -eq 0 ]; then
    during="unread: the reader of other work had not read the machine when the step began"
  elif ! text="$(cat "$watch.out")"; then
    during="unread: what the reader of other work printed could not be read back"
  else
    during="$(checked_reading "$reader_status" "$text")"
  fi
  load_out="$(load_average)"
  ran="${ran:+$ran }$step"
  put "$step" status "$status"
  put "$step" load_in "${load_in:-unread}"
  put "$step" load_out "${load_out:-unread}"
  put "$step" other_in "$other_in"
  put "$step" other_during "$during"
  if [ "$stolen_accounted" -eq 0 ]; then
    put "$step" stolen "not accounted on this platform"
  elif [ -n "$ticks_in" ] && ticks_out="$(cpu_ticks)"; then
    put "$step" stolen "$(stolen_share "$ticks_in" "$ticks_out")"
  else
    put "$step" stolen unread
  fi
  if [ "$logged" -ne 0 ]; then
    lost "$evidence/$step.log"
  fi
  echo "  exit $status; other work in processors' worth through the step: $(other_words "$during");" \
    "load average leaving: $load_out; stolen share: $(get "$step" stolen)"
  for pair in $expected; do
    identifier="${pair%%:*}"
    name="${pair#*:}"
    file="$evidence/$name"
    # Counted rather than stopped at the first match, so the whole of the gained text is read. grep
    # exits with 1 when it counted none, and with more when it could not read.
    gained=0
    if [ -f "$file" ]; then
      gained="$(tail -c +"$(($(started_at "$name") + 1))" "$file" |
        grep -cE "^## $identifier( |\$)")"
      case $? in 0 | 1) ;; *) lost "$file" ;; esac
    fi
    if [ "${gained:-0}" -eq 0 ]; then
      add_problem "$step" "$identifier" "$identifier recorded no figure in $name"
      continue
    fi
    found="$(verdicts "$file" "$(started_at "$name")" "$identifier")" || lost "$file"
    split_lines "$found"
    for line in ${found_lines[@]+"${found_lines[@]}"}; do
      case "$line" in
        "missed "*) add_problem "$step" "$identifier" "$identifier's record says the target was missed: ${line#missed }" ;;
        "short "*) add_shortfall "$step" "${line#short }" ;;
      esac
    done
  done
}

# Puts one section of this run's own record together in `composed`: the heading, and each further
# argument as a line of its own.
compose() {
  local line
  composed="## $1"$'\n\n'
  shift
  for line in "$@"; do
    composed="$composed  $line"$'\n'
  done
  composed="$composed"$'\n'
}

# Appends one section to this run's own record, or says the run could not keep it. The section is
# put together first and written in one go, so that no part of it can fail unseen.
section() {
  compose "$@"
  printf '%s' "$composed" >> "$record" || lost "$record"
}

# Replaces this run's own record with what it held and `$1` after it, in one rename, so that anyone
# reading the record sees all of `$1` or none of it.
publish() {
  local next="$record.next.$$"
  if { [ ! -e "$record" ] || cat "$record"; } > "$next" && printf '%s' "$1" >> "$next" &&
    mv -f "$next" "$record"; then
    return 0
  fi
  rm -f "$next"
  lost "$record"
  return 1
}

outcome_of() {
  if [ "$(get "$1" status)" = 0 ]; then
    echo "passed"
  else
    echo "failed, exit $(get "$1" status)"
  fi
}

# Whether this host can hold KR-PERF-009's budget: four processors for the four-thread bound, mains
# power, and memory for the 4 GiB process ceiling above the reserve section 22 keeps free (the
# larger of 1 GiB and a fifth of the memory). Prints why not, when it cannot.
descriptions_refusal() {
  local available_mib reserve_mib need_mib
  if [ -z "$processors" ] || [ -z "$memory_mib" ]; then
    echo "the host's processors or memory could not be read"
    return
  fi
  if [ "$processors" -lt 4 ]; then
    echo "$processors processors, below the four the description budget runs on"
    return
  fi
  if [ "$os_name" = Darwin ] &&
    [ "$(pmset -g ps 2>/dev/null | grep -c "'AC Power'" || true)" = 0 ]; then
    echo "the host is not on mains power, and descriptions pause on battery"
    return
  fi
  # Available memory as the product itself reads it before it loads a model: on macOS the free,
  # speculative, inactive and purgeable pages less what the compressor holds.
  case "$os_name" in
    Darwin)
      available_mib="$(vm_stat | awk '
        NR == 1 { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) page = $i }
        /^Pages (free|inactive|speculative|purgeable):/ { gsub(/\./, "", $NF); pages += $NF }
        /^Pages occupied by compressor:/ { gsub(/\./, "", $NF); pages -= $NF }
        END { if (pages < 0) pages = 0; printf "%d\n", pages * page / 1048576 }')" ||
        available_mib=""
      ;;
    *)
      available_mib="$(awk '/^MemAvailable:/ { printf "%d\n", $2 / 1024; found = 1 }
        END { exit !found }' /proc/meminfo)" || available_mib=""
      ;;
  esac
  available_mib="$(count_or_empty "$available_mib")"
  reserve_mib=$((memory_mib / 5))
  [ "$reserve_mib" -lt 1024 ] && reserve_mib=1024
  need_mib=$((4096 + reserve_mib))
  if [ -z "$available_mib" ] || [ "$available_mib" -lt "$need_mib" ]; then
    echo "${available_mib:-no} MiB available, below the $need_mib MiB that the 4 GiB ceiling and the $reserve_mib MiB reserve need"
  fi
}

if selected performance; then
  run_step performance \
    "KR-PERF-001:kr-worker-input.md KR-PERF-002:kr-worker-input.md KR-PERF-003:kr-worker-performance.md KR-PERF-004:kr-worker-performance.md" \
    bash scripts/performance.sh
fi
if selected terminal; then
  run_step terminal "KR-PERF-007:kr-term-output-handling.md" \
    cargo test --locked --release -p kr-term --test perf -- --nocapture --test-threads=1
fi
if selected transport; then
  run_step transport "KR-PERF-005:kr-transport-scheduling.md KR-PERF-006:kr-transport-scheduling.md" \
    cargo test --locked --release -p kr-transport --test perf -- --nocapture --test-threads=1
fi
if selected reconnect; then
  run_step reconnect "" cargo test --locked --release -p kr-client --test session -- --exact \
    a_reconnect_reaches_a_screen_a_terminal_can_draw_inside_the_budget --nocapture
  if ! grep -q '^test result: ok\. 1 passed' "$evidence/reconnect.log"; then
    add_problem reconnect - "the reconnect check did not run"
  fi
  section "KR-PERF-006 the client's share of a reconnect" \
    "check             a restoration reaches a painted 120x40 screen inside the 2000 ms budget, once plainly and once after one refused read; the test asserts the budget and prints no figure" \
    "outcome           $(outcome_of reconnect)"
fi
if selected companion; then
  # The default reporter is named, because the runner otherwise picks a quieter one in some
  # environments and drops what a passing test printed.
  run_step companion "" env NO_COLOR=1 FORCE_COLOR=0 pnpm -C apps/companion exec vitest run \
    --reporter=default test/performance.test.tsx
  # The test prints each figure on a line of its own; any colour the runner still adds is taken off
  # before the line is read.
  escape="$(printf '\033')"
  if ! figures="$(sed "s/${escape}\[[0-9;]*[A-Za-z]//g" "$evidence/companion.log" |
    sed -n 's/^KR-PERF-008 //p')"; then
    lost "$evidence/companion.log"
    figures=""
  fi
  if [ -n "$figures" ]; then
    split_lines "$figures"
    section "KR-PERF-008 the companion's semantic display" ${found_lines[@]+"${found_lines[@]}"} \
      "outcome           $(outcome_of companion)"
    # Each figure line ends with its own verdict, "(met)" or "(missed)". grep exits with 1 when
    # every line met its target, and with more when it could not read or write.
    found="$(printf '%s\n' "$figures" | grep -v '(met)$')"
    case $? in 0 | 1) ;; *) lost "the verdicts of $evidence/companion.log" ;; esac
    split_lines "$found"
    for line in ${found_lines[@]+"${found_lines[@]}"}; do
      add_problem companion KR-PERF-008 "KR-PERF-008's record says the target was missed: $line"
    done
  else
    add_problem companion KR-PERF-008 "KR-PERF-008 recorded no figure"
  fi
fi
if selected stress; then
  run_step stress \
    "KR-PERF-001:kr-perf-stress.md KR-PERF-003:kr-perf-stress.md KR-PERF-007:kr-perf-stress.md" \
    env KR_REQUIRE_PLUGIN_FIXTURES=1 cargo test --locked --release -p kr-perf --test stress -- \
    --ignored --nocapture
fi
if selected descriptions; then
  refusal="$(descriptions_refusal)"
  if [ -n "$refusal" ]; then
    echo
    echo "== step descriptions: not run here: $refusal"
    section "KR-PERF-009 local session descriptions, not run here" "reason            $refusal"
  else
    run_step descriptions "" bash scripts/bench-descriptions.sh
    # The benchmark's own lines, which end with the hardware they were taken on, and not what the
    # model's runtime logs beside them; a line repeated for every job is given once, with a count.
    if ! machine="$(awk '/^hardware: / { sub(/^hardware: /, ""); print; exit }' \
      "$evidence/descriptions.log")" ||
      ! figures="$(sed -n '/^# KR-PERF-009/,$ p' "$evidence/descriptions.log" | sed '1d' |
        awk -v tag="[$machine]" '
          /^(hardware|profile|runtime|gpu_layers): / || /^--- / ||
            (length($0) >= length(tag) && substr($0, length($0) - length(tag) + 1) == tag)' |
        uniq -c | awk '{ count = $1; sub(/^ *[0-9]+ /, ""); print (count > 1 ? count " times: " : "") $0 }')"; then
      lost "$evidence/descriptions.log"
      figures=""
    fi
    if [ -n "$figures" ]; then
      split_lines "$figures"
      section "KR-PERF-009 local session descriptions" ${found_lines[@]+"${found_lines[@]}"} \
        "outcome           $(outcome_of descriptions)"
      # The benchmark names each qualification target it did not meet on a line of its own.
      found="$(printf '%s\n' "$figures" | grep 'qualification_target_not_met')"
      case $? in 0 | 1) ;; *) lost "the verdicts of $evidence/descriptions.log" ;; esac
      split_lines "$found"
      for line in ${found_lines[@]+"${found_lines[@]}"}; do
        add_problem descriptions KR-PERF-009 "KR-PERF-009's record says the target was missed: $line"
      done
    else
      add_problem descriptions KR-PERF-009 "KR-PERF-009 recorded no figure"
    fi
  fi
fi
if [ -z "$only" ]; then
  section "KR-PERF-010 voice, not run here" \
    "reason            first audio is taken on a paired phone with a connected media path to the voice provider, where the phone adds the remote audio track, and the voice service records what starting each call took; neither is taken on a host"
fi

# Which identifiers each step measures.
identifiers_of() {
  case "$1" in
    performance) echo "KR-PERF-001 KR-PERF-002 KR-PERF-003 KR-PERF-004" ;;
    terminal) echo "KR-PERF-007" ;;
    transport) echo "KR-PERF-005 KR-PERF-006" ;;
    reconnect) echo "KR-PERF-006" ;;
    companion) echo "KR-PERF-008" ;;
    stress) echo "KR-PERF-001 KR-PERF-003 KR-PERF-007" ;;
    descriptions) echo "KR-PERF-009" ;;
  esac
}

# Every condition of the reference host a step did not meet, the ones its own records name among
# them.
step_shortfalls() {
  local other during stolen name finding shortfalls="$host_shortfalls"
  # A step's figures stand for a quiet host only where other work was read before it and through
  # the whole of it.
  other="$(get "$1" other_in)"
  if ! quiet "$other"; then
    case "$other" in
      "" | unread*) finding="the other work before the step could not be read (${other#unread: })" ;;
      *) finding="${other%% *} processors' worth of other work in the busiest five seconds before the step, not under $quiet_processors" ;;
    esac
    shortfalls="${shortfalls:+$shortfalls; }$finding"
  fi
  during="$(get "$1" other_during)"
  if ! quiet "$during"; then
    case "$during" in
      "" | unread*) finding="the other work during the step could not be read (${during#unread: })" ;;
      *) finding="${during%% *} processors' worth of other work in the busiest five seconds of the step, not under $quiet_processors" ;;
    esac
    shortfalls="${shortfalls:+$shortfalls; }$finding"
  fi
  name="shortfalls_$1"
  split_lines "${!name-}"
  for finding in ${found_lines[@]+"${found_lines[@]}"}; do
    shortfalls="${shortfalls:+$shortfalls; }the record $finding"
  done
  stolen="$(get "$1" stolen)"
  case "$stolen" in
    "" | unread) shortfalls="${shortfalls:+$shortfalls; }the hypervisor's share could not be read" ;;
    not*) ;;
    *)
      if below "$max_stolen_share" "$stolen"; then
        shortfalls="${shortfalls:+$shortfalls; }the hypervisor took $(percent "$stolen") of the step, above $(percent "$max_stolen_share")"
      fi
      ;;
  esac
  printf '%s\n' "$shortfalls"
}

# What failed, and each identifier's conditions section.
failed=0
reasons=""
measured=""
for step in $ran; do
  for identifier in $(identifiers_of "$step"); do
    case " $measured " in *" $identifier "*) ;; *) measured="$measured $identifier" ;; esac
  done
  if [ "$(get "$step" status)" != 0 ]; then
    failed=1
    reasons="$reasons
  $step: exit $(get "$step" status)"
  fi
  if [ -n "$(problems_of "$step" -)" ]; then
    failed=1
    reasons="$reasons
  $step: $(problems_of "$step" -)"
  fi
done

# Everything this run added to the records, so that a log of the run carries its evidence even
# where the directory does not outlive it. It is read back before any figure is called a reference
# figure, since a record that cannot be read back is evidence the run did not keep.
echo
echo "== the records this run added under $evidence"
for file in "$evidence"/*.md; do
  [ -f "$file" ] || continue
  from="$(started_at "$(basename "$file")")"
  if ! size="$(size_of "$file")" || [ -z "$(count_or_empty "$size")" ]; then
    lost "$file"
    continue
  fi
  [ "$size" -gt "$from" ] || continue
  echo
  echo "--- $(basename "$file")"
  tail -c +"$((from + 1))" "$file" || lost "$file"
done

# Each identifier's conditions section, which says whether its figures are reference figures. They
# are the last evidence the run writes, and are published together in one rename once everything
# else is kept, so no later failure can leave a reference figure standing in the record.
short=0
conditions=""
for identifier in $measured; do
  lines=(
    "commit            $commit"
    "host              $os_release, $os_name $arch, $processor_name"
    "processors        ${processors:-unread} against the reference host's $reference_processors"
    "memory            ${memory_mib:-unread} MiB against the reference host's $reference_memory_mib MiB"
  )
  outcome="every step that measured it met its target and recorded its figures"
  shortfalls=""
  for step in $ran; do
    case " $(identifiers_of "$step") " in *" $identifier "*) ;; *) continue ;; esac
    stolen="$(get "$step" stolen)"
    case "$stolen" in
      "" | unread | not*) stolen="${stolen:-unread}" ;;
      *) stolen="$(percent "$stolen")" ;;
    esac
    lines+=("step $step  exit $(get "$step" status); load average (1, 5 and 15 minutes) $(get "$step" load_in) entering, $(get "$step" load_out) leaving; other work in processors' worth over the ten seconds before the step $(other_words "$(get "$step" other_in)"), and through the step $(other_words "$(get "$step" other_during)"); stolen share $stolen")
    problems="$(problems_of "$step" "$identifier")"
    if [ "$(get "$step" status)" != 0 ] || [ -n "$problems" ]; then
      outcome="not met: $step exit $(get "$step" status)${problems:+; $problems}"
    fi
    found="$(step_shortfalls "$step")"
    if [ -n "$found" ]; then
      shortfalls="${shortfalls:+$shortfalls; }$step: $found"
    fi
  done
  lines+=("outcome           $outcome")
  if [ "$reference" -ne 1 ]; then
    lines+=("reference figure  no: the run was not asked for reference figures${shortfalls:+; it would not have met: $shortfalls}")
  elif [ "$evidence_lost" -ne 0 ]; then
    lines+=("reference figure  no: the run could not keep or read back all of its evidence, at $lost_places${shortfalls:+; and $shortfalls}")
    short=1
    reasons="$reasons
  $identifier is not a reference figure: the run could not keep or read back all of its evidence"
  elif [ -n "$shortfalls" ]; then
    lines+=("reference figure  no: $shortfalls")
    short=1
    reasons="$reasons
  $identifier is not a reference figure: $shortfalls"
  else
    lines+=("reference figure  yes: the host met every condition this run read")
  fi
  compose "$identifier conditions of this run" "${lines[@]}"
  conditions="$conditions$composed"
done
if [ -n "$conditions" ]; then
  echo
  if publish "$conditions"; then
    echo "--- bench-all.md, this run's conditions"
  else
    echo "--- this run's conditions, which its record could not keep, so none of them stands"
  fi
  printf '%s' "$conditions"
fi

echo
if [ "$reference" -eq 1 ] && [ "$short" -ne 0 ]; then
  failed=1
fi
if [ "$evidence_lost" -ne 0 ]; then
  failed=1
  reasons="$reasons
  this run could not keep or read back its evidence at: $lost_places"
fi
if [ "$failed" -ne 0 ]; then
  echo "bench-all: not every figure stands:$reasons"
  exit 1
fi
echo "bench-all: every measurement that ran met its target and recorded its figures"
