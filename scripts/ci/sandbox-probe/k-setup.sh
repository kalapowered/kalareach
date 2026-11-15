#!/bin/bash
# The setup of the real-workload jobs: the phase 1 setup (accounts, folders, namespaces, guard),
# a plain core pattern so that a crash starts no helper, and the workload tools installed as
# root where no account can change them.
set -eu
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bash "$here/setup.sh"

sudo -n sysctl -w kernel.core_pattern=core >/dev/null
echo "k-setup: core_pattern is $(cat /proc/sys/kernel/core_pattern)"

sudo -n install -d -m 0755 -o root -g root /usr/local/lib/sandbox-probe/k
for f in "$here"/tools/fetch-core.sh "$here"/tools/fetch-trap.sh "$here"/tools/daemon-leg.sh "$here"/tools/start-worker.mjs; do
  sudo -n install -m 0755 -o root -g root "$f" "/usr/local/lib/sandbox-probe/k/$(basename "$f")"
done
echo "k-setup: nproc $(nproc), $(free -g | awk '/^Mem:/ {print $2}') GB memory"
df -h / | tail -1 | sed -e 's/^/k-setup: disk /'
