#!/bin/bash
# Group I: output. A unit prints every line that could act on the runner, in both command
# forms; the replay makes them inert. The checks here are on the replayed text; that none is
# an annotation is read back afterwards with the API. The runner's own controls, printed
# outside the bracket in both forms, must still act.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "I output"
link_target="$RUNNER_TEMP/sbx-link-target"
: >"$link_target"

# A previous unit plants links named like the next unit's log, in every folder it can write.
UNIT_MAX=60 unit_legs sbx-i0 -- /bin/sh -c "ln -s $link_target /home/kr-legs/tmp/sbx-i1.log; ln -s $link_target /tmp/sbx-i1.log; ln -s $link_target /home/kr-legs/work/sbx-i1.log"

UNIT_MAX=60 unit_legs sbx-i1 -- /usr/bin/python3 "$TOOLS/out.py" >"$RUNNER_TEMP/i1.out"
rc=$?
cat "$RUNNER_TEMP/i1.out"
[ "$rc" -eq 0 ] && ok I.1 "the canary unit ended 0" || fail I.1 "the canary unit exit $rc"

# The replayed text: a bracket around it, a prefix on every line, no control byte.
first=$(head -1 "$RUNNER_TEMP/i1.out")
token=${first#::stop-commands::}
if [ "$first" != "$token" ] && printf '%s' "$token" | grep -q -E '^[0-9a-f]{48}$'; then ok I.2 "the replay opens with ::stop-commands:: and a 48-hex-digit token"; else fail I.2 "no stop-commands opening"; fi
last=$(grep -n -F "::$token::" "$RUNNER_TEMP/i1.out" | tail -1)
total=$(wc -l <"$RUNNER_TEMP/i1.out")
if [ $((total - ${last%%:*})) -le 1 ]; then ok I.3 "the closing ::token:: ends the replay (only the launcher's own line follows)"; else fail I.3 "text follows the closing token"; fi
# Lines of the unit's own output are between the two. The launcher's own line follows the bracket.
inner=$(awk -v t="::$token::" 'NR==1{next} index($0,t)==1{exit} {print}' "$RUNNER_TEMP/i1.out")
if [ -n "$inner" ] && ! printf '%s\n' "$inner" | grep -v -E '^sbx-i1(\.systemd)? \| ' | grep -q .; then ok I.4 "every replayed line starts with the fixed prefix"; else fail I.4 "a replayed line lacks the prefix"; fi
if LC_ALL=C grep -q -P '[\x00-\x09\x0b-\x1f\x7f-\xff]' "$RUNNER_TEMP/i1.out"; then fail I.5 "a control or non-ASCII byte reached the replay"; else ok I.5 "no carriage return, escape or other control byte in the replay"; fi
grep -q 'sbx-i1 | ::notice::CANARY-NO-FINAL-NEWLINE$' "$RUNNER_TEMP/i1.out" && ok I.6 "a last line with no newline is ended before the closing token" || fail I.6 "the last line without newline is not whole"
n=$(grep -c 'CANARY-LATE-CHILD' "$SBX_LOGS/sbx-i1.log")
ok I.7 "the late child's line was captured $n time(s) (recorded: 0 means the unit ended first)"

# The runner's own controls, printed outside the bracket, in both forms. They must show as
# annotations; the canary lines above must not.
echo "::notice::RUNNER-CONTROL-COLON"
echo "##[notice]RUNNER-CONTROL-LEGACY"
# A mask made by the unit would hide this word below; it must appear as it is.
echo "word one: sbxmasklegacy"
echo "word two: sbxmaskcolon"

# A link planted by the earlier unit did not move this unit's log or write anything outside.
[ ! -s "$link_target" ] && ok I.8 "the planted links did not move the next unit's log: the link target is empty" || fail I.8 "the link target was written"
[ -s "$SBX_LOGS/sbx-i1.log" ] && [ ! -L "$SBX_LOGS/sbx-i1.log" ] && ok I.9 "the next unit's log is its own regular file in the log folder" || fail I.9 "the log file is not regular"
endgroup
finish I
