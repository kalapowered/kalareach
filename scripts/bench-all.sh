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
# The conditions read at each step's edges are the load average, how much of the machine other work
# was using over the ten seconds before the step began and the ten seconds after it ended, and the
# share of the step the hypervisor took from this machine (where the platform accounts for it). A
# figure is a reference figure only when the host has the reference host's processors and memory,
# less than one processor's worth of other work was running at either edge of every step, no step
# lost more than one part in a hundred of its time to a hypervisor, and no measurement's own record
# names a shortfall. What runs between a step's edges is not read, because the measurement's own
# work cannot be told apart from anything else's there; the host's whole use over the step is kept
# beside the figure instead. The load average is recorded rather than judged: its one-minute average
# still carries the step before, whereas the ten-second readings say what is running now.
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

all_steps="performance terminal transport reconnect companion descriptions"
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
# too) and how much other work may be running as a step begins.
reference_processors=4
reference_memory_mib=8192
max_stolen_share=0.01
quiet_processors=1.0

# What the host is.
os_name="$(uname -s)"
arch="$(uname -m)"
# `processors` is what the measurements can run on, which is what the reference host is held to;
# `host_processors` is what the host's own counters cover, which is what other work is read over.
case "$os_name" in
  Darwin)
    processors="$(sysctl -n hw.logicalcpu)"
    host_processors="$processors"
    memory_mib="$(($(sysctl -n hw.memsize) / 1048576))"
    processor_name="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'not reported here')"
    os_release="macOS $(sw_vers -productVersion 2>/dev/null || uname -r)"
    ;;
  *)
    processors="$(nproc)"
    host_processors="$(grep -c '^cpu[0-9]' /proc/stat 2>/dev/null || echo "$processors")"
    memory_mib="$(awk '/^MemTotal:/ { printf "%d\n", $2 / 1024 }' /proc/meminfo)"
    processor_name="$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -1)"
    processor_name="${processor_name:-not reported here}"
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

# The aggregate processor line's busy, total and stolen ticks, where the kernel keeps them. Busy
# leaves out the time a hypervisor took, which is counted on its own.
cpu_ticks() {
  [ -r /proc/stat ] || return 1
  awk '$1 == "cpu" {
    print $2 + $3 + $4 + $7 + $8, $2 + $3 + $4 + $5 + $6 + $7 + $8 + $9, $9
    exit
  }' /proc/stat
}

# How many processors' worth of work the host ran between two cpu_ticks readings.
host_use() {
  awk -v a="$1" -v b="$2" -v n="$host_processors" 'BEGIN {
    split(a, x, " "); split(b, y, " "); t = y[2] - x[2]
    if (t <= 0) { print "unread"; exit }
    printf "%.2f\n", (y[1] - x[1]) / t * n
  }'
}

# How many processors' worth of work the host ran over the next ten seconds.
other_work() {
  local before after
  if before="$(cpu_ticks)"; then
    sleep 10
    after="$(cpu_ticks)" || { echo unread; return; }
    host_use "$before" "$after"
  elif command -v iostat > /dev/null 2>&1; then
    # The second report covers the interval, and its third column is the idle share.
    iostat -n 0 -c 2 -w 10 2>/dev/null | tail -1 |
      awk -v n="$host_processors" '$3 ~ /^[0-9.]+$/ { printf "%.2f\n", (100 - $3) / 100 * n; found = 1 }
        END { if (!found) print "unread" }'
  else
    echo unread
  fi
}

# The share of the span between two cpu_ticks readings that the hypervisor took.
stolen_share() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    split(a, x, " "); split(b, y, " "); t = y[2] - x[2]
    if (t <= 0 || y[3] < x[3]) { print "unread"; exit }
    printf "%.4f\n", (y[3] - x[3]) / t
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
size_of() {
  if [ -f "$1" ]; then wc -c < "$1" | tr -d ' '; else echo 0; fi
}
for file in "$evidence"/*.md; do
  [ -f "$file" ] && printf '%s %s\n' "$(basename "$file")" "$(size_of "$file")"
done > "$work/start"
started_at() {
  local length
  length="$(awk -v f="$1" '$1 == f { print $2 }' "$work/start")"
  echo "${length:-0}"
}

# A step's results, one file per field.
put() { printf '%s' "$3" > "$work/$1.$2"; }
get() { cat "$work/$1.$2" 2>/dev/null; }
# A problem with a step, about one identifier it measures or, with "-", about the step itself.
add_problem() {
  printf "%s %s\n" "$2" "$3" >> "$work/$1.problems"
}
# The problems of a step that concern an identifier, or every one of them when it is "-".
problems_of() {
  [ -f "$work/$1.problems" ] || return 0
  awk -v i="$2" 'i == "-" || $1 == i || $1 == "-" { $1 = ""; sub(/^ /, ""); print }' "$work/$1.problems" |
    paste -sd ";" - | sed "s/;/; /g"
}
: > "$work/ran"

echo "kalareach performance figures"
echo "  commit: $commit"
echo "  host: $os_release, $os_name $arch"
echo "  processor: $processor_name"
echo "  processors: $processors logical, against the reference host's $reference_processors"
echo "  memory: $memory_mib MiB, against the reference host's $reference_memory_mib MiB"
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
if [ "$processors" -lt "$reference_processors" ]; then
  host_shortfalls="$processors processors, below the reference host's $reference_processors"
fi
if [ "$memory_mib" -lt "$reference_memory_mib" ]; then
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
if [ "$build_failed" -ne 0 ]; then
  echo "bench-all: the build failed, so nothing was measured"
  exit 1
fi

# Reads how much other work is running and, with --reference-host, waits for it to fall under one
# processor's worth, for at most ten minutes. Prints the last reading.
settle() {
  local reading attempts=0
  reading="$(other_work)"
  while [ "$reference" -eq 1 ] && [ "$reading" != unread ] &&
    ! below "$reading" "$quiet_processors" && [ "$attempts" -lt 59 ]; do
    attempts=$((attempts + 1))
    reading="$(other_work)"
  done
  echo "$reading"
}

# Evidence this run could not keep, which fails the run.
lost() {
  echo "bench-all: this run could not keep its evidence at $1" >&2
  printf '%s\n' "$1" >> "$work/lost"
}

# A reference-host condition a measurement's own record says it did not meet.
add_shortfall() {
  printf '%s\n' "$2" >> "$work/$1.shortfalls"
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
  local step="$1" expected="$2" status logged load_in load_out other_in other_out ticks_in
  local ticks_out pair identifier file name gained kind finding
  shift 2
  echo
  echo "== $(date '+%T') step $step: $*"
  other_in="$(settle)"
  load_in="$(load_average)"
  ticks_in="$(cpu_ticks || true)"
  echo "  other work entering: $other_in processors; load average entering: $load_in"
  "$@" 2>&1 | tee "$evidence/$step.log"
  # Both statuses in one statement: the next command replaces them.
  status=${PIPESTATUS[0]} logged=${PIPESTATUS[1]}
  load_out="$(load_average)"
  ticks_out="$(cpu_ticks || true)"
  other_out="$(other_work)"
  echo "$step" >> "$work/ran"
  put "$step" status "$status"
  put "$step" load_in "${load_in:-unread}"
  put "$step" load_out "${load_out:-unread}"
  put "$step" other_in "$other_in"
  put "$step" other_out "$other_out"
  if [ -n "$ticks_in" ] && [ -n "$ticks_out" ]; then
    put "$step" stolen "$(stolen_share "$ticks_in" "$ticks_out")"
    put "$step" used "$(host_use "$ticks_in" "$ticks_out") processors' worth, the measurement's own work included"
  else
    put "$step" stolen "not accounted on this platform"
    put "$step" used "not read on this platform"
  fi
  if [ "$logged" -ne 0 ]; then
    lost "$evidence/$step.log"
  fi
  echo "  exit $status; other work leaving: $other_out processors; load average leaving:" \
    "$load_out; stolen share: $(get "$step" stolen)"
  for pair in $expected; do
    identifier="${pair%%:*}"
    name="${pair#*:}"
    file="$evidence/$name"
    # Counted rather than stopped at the first match, so the whole of the gained text is read.
    gained=0
    if [ -f "$file" ]; then
      gained="$(tail -c +"$(($(started_at "$name") + 1))" "$file" |
        grep -cE "^## $identifier( |\$)" || true)"
    fi
    if [ "${gained:-0}" -eq 0 ]; then
      add_problem "$step" "$identifier" "$identifier recorded no figure in $name"
      continue
    fi
    verdicts "$file" "$(started_at "$name")" "$identifier" > "$work/findings"
    while read -r kind finding; do
      case "$kind" in
        missed) add_problem "$step" "$identifier" "$identifier's record says the target was missed: $finding" ;;
        short) add_shortfall "$step" "$finding" ;;
      esac
    done < "$work/findings"
  done
}

# Appends one section to this run's own record, or says the run could not keep it.
#
# A redirection that fails is caught with `||`: bash does not apply `!` to a compound command whose
# redirection failed.
section() {
  local heading="$1" line
  shift
  {
    printf '## %s\n\n' "$heading"
    for line in "$@"; do
      printf '  %s\n' "$line"
    done
    printf '\n'
  } >> "$record" || lost "$record"
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
        END { if (pages < 0) pages = 0; printf "%d\n", pages * page / 1048576 }')"
      ;;
    *) available_mib="$(awk '/^MemAvailable:/ { printf "%d\n", $2 / 1024 }' /proc/meminfo)" ;;
  esac
  reserve_mib=$((memory_mib / 5))
  [ "$reserve_mib" -lt 1024 ] && reserve_mib=1024
  need_mib=$((4096 + reserve_mib))
  if [ "${available_mib:-0}" -lt "$need_mib" ]; then
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
  figures="$(sed "s/${escape}\[[0-9;]*[A-Za-z]//g" "$evidence/companion.log" |
    sed -n 's/^KR-PERF-008 //p')"
  if [ -n "$figures" ]; then
    {
      printf '## %s\n\n' "KR-PERF-008 the companion's semantic display"
      printf '%s\n' "$figures" | sed 's/^/  /'
      printf '  outcome           %s\n\n' "$(outcome_of companion)"
    } >> "$record" || lost "$record"
    # Each figure line ends with its own verdict, "(met)" or "(missed)".
    printf '%s\n' "$figures" | grep -v '(met)$' > "$work/findings" || true
    while read -r finding; do
      add_problem companion KR-PERF-008 "KR-PERF-008's record says the target was missed: $finding"
    done < "$work/findings"
  else
    add_problem companion KR-PERF-008 "KR-PERF-008 recorded no figure"
  fi
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
    machine="$(sed -n 's/^hardware: //p' "$evidence/descriptions.log" | head -1)"
    figures="$(sed -n '/^# KR-PERF-009/,$ p' "$evidence/descriptions.log" | sed '1d' |
      awk -v tag="[$machine]" '
        /^(hardware|profile|runtime|gpu_layers): / || /^--- / ||
          (length($0) >= length(tag) && substr($0, length($0) - length(tag) + 1) == tag)' |
      uniq -c | awk '{ count = $1; sub(/^ *[0-9]+ /, ""); print (count > 1 ? count " times: " : "") $0 }')"
    if [ -n "$figures" ]; then
      {
        printf '## KR-PERF-009 local session descriptions\n\n'
        printf '%s\n' "$figures" | sed 's/^/  /'
        printf '  outcome           %s\n\n' "$(outcome_of descriptions)"
      } >> "$record" || lost "$record"
      # The benchmark names each qualification target it did not meet on a line of its own.
      printf '%s\n' "$figures" | grep 'qualification_target_not_met' > "$work/findings" || true
      while read -r finding; do
        add_problem descriptions KR-PERF-009 "KR-PERF-009's record says the target was missed: $finding"
      done < "$work/findings"
    else
      add_problem descriptions KR-PERF-009 "KR-PERF-009 recorded no figure"
    fi
  fi
fi
if [ -z "$only" ]; then
  section "KR-PERF-010 voice, not run here" \
    "reason            first audio and delegation latency are measured on a paired phone with a connected media path to the voice provider, and the voice service records what starting each call took; neither is measured on a host"
fi

# Which identifiers each step measures.
identifiers_of() {
  case "$1" in
    performance) echo "KR-PERF-001 KR-PERF-002 KR-PERF-003 KR-PERF-004" ;;
    terminal) echo "KR-PERF-007" ;;
    transport) echo "KR-PERF-005 KR-PERF-006" ;;
    reconnect) echo "KR-PERF-006" ;;
    companion) echo "KR-PERF-008" ;;
    descriptions) echo "KR-PERF-009" ;;
  esac
}

# Every condition of the reference host a step did not meet, the ones its own records name among
# them.
step_shortfalls() {
  local other edge stolen finding shortfalls="$host_shortfalls"
  for edge in in out; do
    other="$(get "$1" "other_$edge")"
    if [ "$other" = unread ]; then
      shortfalls="${shortfalls:+$shortfalls; }how busy the host was could not be read"
    elif ! below "$other" "$quiet_processors"; then
      shortfalls="${shortfalls:+$shortfalls; }$other processors' worth of other work as the step $([ "$edge" = in ] && echo began || echo ended), not under $quiet_processors"
    fi
  done
  if [ -f "$work/$1.shortfalls" ]; then
    while read -r finding; do
      shortfalls="${shortfalls:+$shortfalls; }the record $finding"
    done < "$work/$1.shortfalls"
  fi
  stolen="$(get "$1" stolen)"
  case "$stolen" in
    unread) shortfalls="${shortfalls:+$shortfalls; }the hypervisor's share could not be read" ;;
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
while read -r step; do
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
done < "$work/ran"

short=0
for identifier in $measured; do
  lines=(
    "commit            $commit"
    "host              $os_release, $os_name $arch, $processor_name"
    "processors        $processors against the reference host's $reference_processors"
    "memory            $memory_mib MiB against the reference host's $reference_memory_mib MiB"
  )
  outcome="every step that measured it met its target and recorded its figures"
  shortfalls=""
  while read -r step; do
    case " $(identifiers_of "$step") " in *" $identifier "*) ;; *) continue ;; esac
    stolen="$(get "$step" stolen)"
    case "$stolen" in
      unread | not*) ;;
      *) stolen="$(percent "$stolen")" ;;
    esac
    lines+=("step $step  exit $(get "$step" status); load average (1, 5 and 15 minutes) $(get "$step" load_in) entering, $(get "$step" load_out) leaving; other work $(get "$step" other_in) processors entering, $(get "$step" other_out) leaving; the host's use over the step $(get "$step" used); stolen share $stolen")
    problems="$(problems_of "$step" "$identifier")"
    if [ "$(get "$step" status)" != 0 ] || [ -n "$problems" ]; then
      outcome="not met: $step exit $(get "$step" status)${problems:+; $problems}"
    fi
    found="$(step_shortfalls "$step")"
    if [ -n "$found" ]; then
      shortfalls="${shortfalls:+$shortfalls; }$step: $found"
    fi
  done < "$work/ran"
  lines+=("outcome           $outcome")
  if [ "$reference" -ne 1 ]; then
    lines+=("reference figure  no: the run was not asked for reference figures${shortfalls:+; it would not have met: $shortfalls}")
  elif [ -n "$shortfalls" ]; then
    lines+=("reference figure  no: $shortfalls")
    short=1
    reasons="$reasons
  $identifier is not a reference figure: $shortfalls"
  else
    lines+=("reference figure  yes: the host met every condition this run read")
  fi
  section "$identifier conditions of this run" "${lines[@]}"
done

# Everything this run added to the records, so that a log of the run carries its evidence even
# where the directory does not outlive it.
echo
echo "== the records this run added under $evidence"
for file in "$evidence"/*.md; do
  [ -f "$file" ] || continue
  from="$(started_at "$(basename "$file")")"
  [ "$(size_of "$file")" -gt "$from" ] || continue
  echo
  echo "--- $(basename "$file")"
  tail -c +"$((from + 1))" "$file"
done

echo
if [ "$reference" -eq 1 ] && [ "$short" -ne 0 ]; then
  failed=1
fi
if [ -s "$work/lost" ]; then
  failed=1
  reasons="$reasons
  this run could not keep its evidence at: $(sort -u "$work/lost" | paste -sd ' ' -)"
fi
if [ "$failed" -ne 0 ]; then
  echo "bench-all: not every figure stands:$reasons"
  exit 1
fi
echo "bench-all: every measurement that ran met its target and recorded its figures"
