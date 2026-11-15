#!/bin/bash
# Group A: the image's facts. Print only; the one assertion is the cgroup file system.
# Prints no value of a variable but the two public image identifiers, and of the metadata
# services only the answer's status code and length.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

info() {
  local id=$1 what=$2 out
  shift 2
  out=$("$@" 2>&1 | tr '\n' ';' | cut -c1-700)
  ok "$id" "$what: $out"
}

group "A facts"
f_image() { printf 'ImageOS=%s ImageVersion=%s kernel=%s ' "${ImageOS:-unset}" "${ImageVersion:-unset}" "$(uname -r)"; systemctl --version | head -1; }
f_cgroup() { stat -f -c %T /sys/fs/cgroup; }
f_sysctl() { printf 'core_pattern=%s io_uring_disabled=%s ia32=%s' "$(cat /proc/sys/kernel/core_pattern)" "$(cat /proc/sys/kernel/io_uring_disabled 2>&1)" "$(cat /proc/sys/kernel/ia32_emulation 2>/dev/null || echo na)"; }
f_modules() { awk '{print $1}' /proc/modules | grep -E '^(vsock|hv_sock|vmw_vsock_virtio_transport_common|vsock_loopback|smc|rxrpc|tipc|rds|kcm|af_packet|algif_.*)$' | tr '\n' ' '; echo "|protocols:"; awk 'NR>1{print $1}' /proc/net/protocols | tr '\n' ' '; }
f_runner_paths() {
  local pid exe root p
  pid=$(pgrep -f 'Runner.Worker' | head -1)
  exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
  echo "worker_exe=$exe"
  root=$(dirname "$(dirname "$exe")")
  for p in "$root" "$root/_diag" "$root/.credentials" "$root/.credentials_rsaparams" "$root/.runner" /home/runner /home/runner/work "$RUNNER_TEMP" "$GITHUB_WORKSPACE"; do
    stat -c 'mode=%a owner=%U real=%N' "$(readlink -f "$p" 2>/dev/null || echo "$p")" 2>&1 | head -1
  done
  for p in GITHUB_ENV GITHUB_PATH GITHUB_OUTPUT GITHUB_STATE GITHUB_STEP_SUMMARY; do
    printf '%s real=%s\n' "$p" "$(readlink -f "${!p}")"
  done
}
f_top() { stat -c '%a %U:%G %n' /* 2>&1; }
f_manager_env() { systemctl show-environment | cut -d= -f1; }
f_account() { printf 'runner_groups=%s sudo=%s uid=%s' "$(id -Gn)" "$(sudo -n true && echo yes || echo no)" "$(id -u)"; }
f_machine() { printf 'nproc=%s mem_mb=%s ' "$(nproc)" "$(free -m | awk '/Mem:/{print $2}')"; df -h / | tail -1; }
f_tools() { printf 'python=%s gcc=%s ip=%s proxyd=%s node=%s ' "$(python3 --version 2>&1)" "$(gcc --version 2>&1 | head -1)" "$(ip -V 2>&1)" "$(ls /usr/lib/systemd/systemd-socket-proxyd 2>&1)" "$(node --version 2>&1)"; }
f_mgr() { printf 'state=%s ' "$(systemctl is-system-running 2>&1)"; systemctl show -p Version -p Architecture -p ControlGroupMode --no-pager 2>&1 | tr '\n' ' '; }
f_netns() { printf 'runner=%s pid1=%s\n' "$(readlink /proc/self/ns/net)" "$(sudo -n readlink /proc/1/ns/net)"; sudo -n ls -ld /run/netns /run/netns/* 2>&1; }
f_mounts() { findmnt -n -o TARGET,FSTYPE,PROPAGATION / /run /run/netns 2>&1 | head -5; }

# The metadata services: only the status code and the length of the answer.
f_metadata() {
  local name url
  for name in imds wireserver; do
    case $name in
      imds) url='http://169.254.169.254/metadata/instance?api-version=2021-02-01' ;;
      wireserver) url='http://168.63.129.16/machine/?comp=goalstate' ;;
    esac
    printf '%s=%s ' "$name" "$(curl -s -m 4 -H 'Metadata: true' -o /dev/null -w '%{http_code}/%{size_download}b' "$url" 2>&1 || true)"
  done
}
f_resolver() { printf 'getent=%s resolv=%s ' "$(getent hosts github.com | wc -l)" "$(readlink -f /etc/resolv.conf)"; ss -ltnH 2>/dev/null | awk '{print $4}' | sed -e 's/.*://' -e 's/^/port:/' | sort -u | tr '\n' ' '; }

info A.1 "image, kernel, systemd" f_image
info A.2 "cgroup file system" f_cgroup
info A.3 "core_pattern, io_uring_disabled, ia32_emulation" f_sysctl
info A.4 "modules loaded and registered protocols" f_modules
info A.5 "the runner's paths, modes and the command files' real paths" f_runner_paths
info A.6 "top-level folders" f_top
info A.7 "names in systemctl show-environment" f_manager_env
info A.8 "runner account" f_account
info A.9 "machine" f_machine
info A.10 "tools" f_tools
info A.11 "system manager" f_mgr
info A.12 "network namespaces of the runner and of PID 1" f_netns
info A.13 "mounts" f_mounts
info A.14 "metadata services answer the runner (status/length only)" f_metadata
info A.15 "resolver and local listening ports (numbers only)" f_resolver
if [ "$(stat -f -c %T /sys/fs/cgroup)" = cgroup2fs ]; then ok A.16 "cgroup v2 is mounted"; else fail A.16 "cgroup v2 is not mounted"; fi
endgroup
finish A
