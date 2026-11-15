#!/bin/bash
# Group F: what the step has, and the unit must not: a directory, variables (one of them made
# through the workflow's variable file), open descriptors 7 and 9, the runner's processes.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "F inheritance"
canary_dir="$RUNNER_TEMP/sbx-canary-dir"
mkdir -m 0700 -p "$canary_dir"
echo "canary" >"$canary_dir/file"
export SBX_CANARY_VAR=canary-from-the-step-shell
exec 7<"$canary_dir/file" 9>"$canary_dir/out"
cd "$canary_dir" || exit 1

# Process ids of the runner's: this shell, its parent, the worker.
worker=$(pgrep -f 'Runner.Worker' | head -1)
UNIT_MAX=60 unit_legs sbx-f1 -- /usr/bin/python3 "$TOOLS/inherit.py" "$$" "$PPID" "$worker"

has sbx-f1 '^RESULT cwd /home/kr-legs/work$' && ok F.1 "the unit's directory is its own, not the step's canary directory" || fail F.1 "the unit's directory: $(grep '^RESULT cwd' "$SBX_LOGS/sbx-f1.log")"
has sbx-f1 '^RESULT envbad none$' && ok F.2 "no variable named GITHUB_, ACTIONS_, RUNNER_, SBX_, CI or ImageOS/ImageVersion in the unit (canaries made by the shell, by the variable file and by the step's env are among them)" || fail F.2 "bad variable names: $(grep '^RESULT envbad' "$SBX_LOGS/sbx-f1.log")"
env_names=$(sed -n 's/^RESULT envnames //p' "$SBX_LOGS/sbx-f1.log")
ok F.3 "the unit's variable names are: $env_names"
has sbx-f1 '^RESULT fds 0 1 2$' && ok F.4 "only descriptors 0, 1 and 2 are open (the step's 7 and 9 are not)" || fail F.4 "descriptors: $(grep '^RESULT fds' "$SBX_LOGS/sbx-f1.log")"
has sbx-f1 '^RESULT CapEff 0*$' && ok F.5 "CapEff is zero" || fail F.5 "CapEff: $(grep '^RESULT CapEff' "$SBX_LOGS/sbx-f1.log")"
has sbx-f1 '^RESULT CapBnd 0*$' && ok F.6 "CapBnd is zero" || fail F.6 "CapBnd: $(grep '^RESULT CapBnd' "$SBX_LOGS/sbx-f1.log")"
has sbx-f1 '^RESULT ids uid=[1-9][0-9]* gid=[1-9][0-9]* groups=[0-9]*[^,]* ppid=1$' && ok F.7 "the unit's parent is PID 1, and it holds one group" || fail F.7 "ids: $(grep '^RESULT ids' "$SBX_LOGS/sbx-f1.log")"
if grep -q '^RESULT proc .* READABLE' "$SBX_LOGS/sbx-f1.log"; then
  fail F.8 "a runner process entry is readable: $(grep READABLE "$SBX_LOGS/sbx-f1.log" | sort | uniq -c | tr '\n' ';' | cut -c1-200)"
else
  ok F.8 "no /proc entry (environ, mem, fd, root, cmdline, maps) of the shell, its parent or the worker is readable: $(grep '^RESULT proc' "$SBX_LOGS/sbx-f1.log" | awk '{print $4}' | sort | uniq -c | tr '\n' ' ')"
fi
has sbx-f1 '^RESULT done$' && ok F.9 "the inheritance program ran to its end" || fail F.9 "the inheritance program did not finish"
# The step's descriptor 9 was not written by the unit.
[ ! -s "$canary_dir/out" ] && ok F.10 "descriptor 9 of the step received nothing from the unit" || fail F.10 "descriptor 9 of the step was written"
cd "$RUNNER_TEMP" || exit 1
exec 7<&- 9>&-
endgroup
finish F
