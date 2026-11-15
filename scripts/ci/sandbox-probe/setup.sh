#!/bin/bash
# The probe's setup, run once as the first step: installs the guard and the probe tools as root,
# makes the two accounts, their folders, the log folder and the two network namespaces, and
# hands the log folder's path and the canary variable to the later steps.
set -eu

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
sbx=$(cd "$here/../sandbox" && pwd)

sudo -n install -d -m 0755 -o root -g root /usr/local/lib/sandbox /usr/local/lib/sandbox-probe
sudo -n install -m 0755 -o root -g root "$sbx/guard.sh" /usr/local/lib/sandbox/guard.sh
for f in "$here"/tools/*.py; do
  sudo -n install -m 0755 -o root -g root "$f" "/usr/local/lib/sandbox-probe/$(basename "$f")"
done
if [ -f "$here/tools/ia32.c" ]; then
  gcc -O1 -o "${RUNNER_TEMP:?}/ia32" "$here/tools/ia32.c"
  sudo -n install -m 0755 -o root -g root "$RUNNER_TEMP/ia32" /usr/local/lib/sandbox-probe/ia32
fi

# The accounts: no login, no shell, no group of the runner's, no sudo entry.
for acct in kr-legs kr-svc; do
  sudo -n useradd --create-home --home-dir "/home/$acct" --shell /usr/sbin/nologin --user-group "$acct"
done
sudo -n install -d -o kr-legs -g kr-legs -m 0700 /home/kr-legs /home/kr-legs/work /home/kr-legs/tmp /home/kr-legs/artifacts
sudo -n install -d -o kr-legs -g kr-legs -m 0700 /opt/kr-legs /opt/kr-legs/cargo /opt/kr-legs/target
sudo -n install -d -o kr-svc -g kr-svc -m 0700 /home/kr-svc /home/kr-svc/work /home/kr-svc/tmp

# The log folder: the runner's, mode 0700, in the runner's temporary folder.
logs="$RUNNER_TEMP/sbx-logs"
install -d -m 0700 "$logs"

# The namespaces, made by the runner before the first unit.
bash "$sbx/make-netns.sh" add sbx-svc sbx-legs

# Canaries for the inheritance group: a variable made available to every later step.
{
  printf 'SBX_LOGS=%s\n' "$logs"
  printf 'SBX_CANARY_ENV=canary-through-github-env\n'
} >>"$GITHUB_ENV"
: >"$RUNNER_TEMP/probe-lines.txt"
echo "setup: done"
