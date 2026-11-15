#!/bin/bash
# Group H: writes. Only the binds, /tmp, /dev/shm and the unit's own tmpfs mounts are writable;
# the unit does not share /tmp or /dev/shm with the host or another unit; the runner's and the
# other account's paths are absent; crontab and setuid fail; a hard link across binds fails;
# the hand-back check refuses what it must.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

group "H writes"
W="/usr/bin/python3 $TOOLS/writes.py"

# Fixtures of the runner's: a 0777 file in /usr/local/bin, a 1777 folder in /var, host canaries.
sudo -n install -m 0777 /dev/null /usr/local/bin/sbx-h-canary
sudo -n install -d -m 1777 /var/sbx-h-1777
echo host > /tmp/sbx-host-canary
echo host > /dev/shm/sbx-host-canary

UNIT_MAX=60 unit_legs sbx-h1 -- $W try /usr/local/bin/sbx-h-canary /var/sbx-h-1777 /usr/sbin /etc /usr /boot /home/kr-legs /home/kr-legs/tmp /opt/kr-legs/cargo /opt/kr-legs/target /tmp /dev/shm /var/tmp /run /opt /srv /mnt /media /home/kr-legs/.bashrc
for p in /usr/local/bin/sbx-h-canary /var/sbx-h-1777 /usr/sbin /etc /usr /boot; do
  if has sbx-h1 "^RESULT write $p \(EROFS\|ENOENT\|EACCES\|EPERM\)$"; then ok "H.1$p" "not writable from the unit: $p ($(grep "write $p " "$SBX_LOGS/sbx-h1.log" | awk '{print $4}'))"; else fail "H.1$p" "writable or odd: $(grep "write $p " "$SBX_LOGS/sbx-h1.log")"; fi
done
for p in /home/kr-legs /home/kr-legs/tmp /opt/kr-legs/cargo /opt/kr-legs/target /tmp /dev/shm; do
  if has sbx-h1 "^RESULT write $p ok$"; then ok "H.2$p" "writable from the unit, as intended: $p"; else fail "H.2$p" "not writable: $(grep "write $p " "$SBX_LOGS/sbx-h1.log")"; fi
done
# Printed: the unit's own tmpfs mounts that are writable and vanish with the unit.
ok H.3 "writable but unit-private tmpfs mounts: $(for p in /run /opt /srv /mnt /media /var/tmp; do printf '%s=%s ' "$p" "$(grep "write $p " "$SBX_LOGS/sbx-h1.log" | awk '{print $4}')"; done)"

# H.4: the full list of writable files and folders, by mount.
UNIT_MAX=120 unit_legs sbx-h2 -- $W list
bad=$(grep '^RESULT writable mount=' "$SBX_LOGS/sbx-h2.log" | grep -v -E 'mount=(/home/kr-legs|/opt/kr-legs/(cargo|target)|/tmp|/dev/shm|/run|/opt|/srv|/mnt|/media|/dev) ' || true)
if [ -z "$bad" ]; then ok H.4 "every writable file or folder lies on a bind or a unit-private tmpfs"; else fail H.4 "writable elsewhere: $(printf '%s' "$bad" | tr '\n' ';' | cut -c1-300)"; fi

# H.5: absent paths.
UNIT_MAX=60 unit_legs sbx-h3 -- $W absent /home/runner "$RUNNER_TEMP" "$GITHUB_WORKSPACE" /home/kr-svc "$SBX_LOGS" /run/netns /run/systemd/private /proc/1/root/etc
if [ "$(grep -c '^RESULT absent .* yes$' "$SBX_LOGS/sbx-h3.log")" -eq 8 ]; then
  ok H.5 "the runner's home, temp folder, workspace, the other account's home, the log folder, /run/netns and PID 1's root are absent in the unit"
else
  fail H.5 "present in the unit: $(grep '^RESULT absent .* no$' "$SBX_LOGS/sbx-h3.log" | tr '\n' ';' | cut -c1-200)"
fi

# H.6: /tmp and /dev/shm are the unit's own: not the host's, not another unit's.
UNIT_MAX=60 unit_legs sbx-h4 -- $W mark /tmp/sbx-unit-a-file
UNIT_MAX=60 unit_legs sbx-h5 -- $W see /tmp/sbx-host-canary /dev/shm/sbx-host-canary /tmp/sbx-unit-a-file
if [ "$(grep -c '^RESULT see .* absent$' "$SBX_LOGS/sbx-h5.log")" -eq 3 ]; then ok H.6 "/tmp and /dev/shm show neither the host's files nor another unit's"; else fail H.6 "shared: $(grep ' present$' "$SBX_LOGS/sbx-h5.log" | tr '\n' ';')"; fi

# H.7: crontab and setuid.
if [ -x /usr/bin/crontab ]; then
  UNIT_MAX=60 unit_legs sbx-h6 -- /bin/sh -c 'echo "* * * * * true" | /usr/bin/crontab -'
  rc=$?
  [ "$rc" -ne 0 ] && ok H.7 "crontab fails in the unit (exit $rc)" || fail H.7 "crontab succeeded in the unit"
else
  ok H.7 "crontab is not installed on this image (nothing to refuse)"
fi
UNIT_MAX=60 unit_legs sbx-h7 -- $W setuid /home/kr-legs/tmp
if has sbx-h7 '^RESULT setuid chmod-refused'; then ok H.8 "chmod u+s is refused in the unit ($(grep -o 'chmod-refused [A-Z]*' "$SBX_LOGS/sbx-h7.log"))"; else fail H.8 "setuid chmod: $(grep '^RESULT setuid' "$SBX_LOGS/sbx-h7.log")"; fi

# H.9: a hard link across two binds.
UNIT_MAX=60 unit_legs sbx-h8 -- $W hardlink /home/kr-legs/tmp /opt/kr-legs/cargo
if has sbx-h8 '^RESULT hardlink EXDEV$'; then ok H.9 "a hard link across two binds fails with EXDEV"; else fail H.9 "hard link across binds: $(grep '^RESULT hardlink' "$SBX_LOGS/sbx-h8.log")"; fi

# H.10: the hand-back check. A unit makes a tree with a link, a FIFO, a socket and a newline
# name (one folder each) and a clean folder; the runner's check refuses each of the four.
sudo -n /usr/bin/find /home/kr-legs/artifacts -mindepth 1 -delete
UNIT_MAX=60 unit_legs sbx-h9 -- $W fixtures /home/kr-legs/artifacts
sudo -n chown -hR runner:runner /home/kr-legs/artifacts 2>/dev/null
for kind in link fifo sock newline; do
  sudo -n bash "$PROBE_ROOT/tools/check-tree.sh" "/home/kr-legs/artifacts/$kind" runner >/dev/null 2>&1 && fail "H.10.$kind" "the hand-back check accepted a tree with a $kind" || ok "H.10.$kind" "the hand-back check refuses a tree with a $kind"
done
sudo -n bash "$PROBE_ROOT/tools/check-tree.sh" /home/kr-legs/artifacts/clean runner >/dev/null 2>&1 && ok H.11 "the hand-back check accepts a clean tree" || fail H.11 "the hand-back check refused a clean tree"
endgroup
finish H
