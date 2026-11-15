#!/bin/bash
# Shared helpers of the real-workload groups (sourced after the phase 1 helpers).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

K_TOOLS=/usr/local/lib/sandbox-probe/k
CORE_URL=https://github.com/kalapowered/kalareach
NET="/usr/bin/python3 $TOOLS/net.py"
BASE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The addresses the fetch unit is refused: the metadata addresses (169.254.0.0/16, and Azure's
# 168.63.129.16 inside 168.0.0.0/8 is not private, so it is named), private ranges, and the whole
# loopback but the resolver's stub.
FETCH_DENY="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 168.63.129.16/32 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4 ::1/128 fc00::/7 fe80::/10"
FETCH_ALLOW="127.0.0.53/32"

# The fetch unit: the network, the address refusals, the resolver's folder read-only, the build
# account's folders. The caller names the unit and the command.
unit_fetch() {
  local n=$1
  shift
  bash "$SBX_DIR/run-unit.sh" --name "$n" --user kr-legs --group kr-legs --workdir /home/kr-legs/work \
    --log-dir "$SBX_LOGS" --host-network "${LEGS_BINDS[@]}" --bind-ro /run/systemd/resolve \
    --prop "IPAddressDeny=$FETCH_DENY" --prop "IPAddressAllow=$FETCH_ALLOW" \
    --runtime-max "${UNIT_MAX:-120}" "$@"
}

# The build account in the legs' namespace with the toolchain, offline, in the checkout.
build_env() {
  local chan=$1
  printf '%s\n' --env "CARGO_HOME=/opt/kr-legs/cargo" --env "RUSTUP_HOME=/home/kr-legs/rustup" \
    --env "CARGO_TARGET_DIR=/opt/kr-legs/target" --env "TMPDIR=/home/kr-legs/tmp" \
    --env "CARGO_PROFILE_DEV_DEBUG=0" --env "CARGO_PROFILE_TEST_DEBUG=0" --env "CARGO_INCREMENTAL=0" \
    --env "CARGO_NET_OFFLINE=true" --env "CARGO_TERM_COLOR=never" --env "RUSTUP_TOOLCHAIN=$chan" \
    --env "PATH=/opt/kr-legs/cargo/bin:$BASE_PATH"
}

# The toolchain version the fetch step wrote, validated before it is used as a value.
toolchain() {
  local chan
  chan=$(sudo -n cat /home/kr-legs/toolchain.txt 2>/dev/null | head -1)
  case $chan in [0-9]*.[0-9]*.[0-9]*) ;; *) return 1 ;; esac
  case $chan in *[!0-9.]*) return 1 ;; esac
  printf '%s\n' "$chan"
}

# unit_gone NAME: the unit is inactive or gone, and its control group holds no process.
unit_gone() {
  local state cg="/sys/fs/cgroup/system.slice/$1.service"
  state=$(sudo -n systemctl show -p ActiveState --value "$1.service" 2>/dev/null)
  case $state in inactive | failed | '') ;; *) return 1 ;; esac
  [ -d "$cg" ] && [ -n "$(cat "$cg/cgroup.procs" 2>/dev/null)" ] && return 1
  return 0
}

# no_processes ACCOUNT: the account has no process left.
no_processes() { ! pgrep -u "$1" >/dev/null 2>&1; }

# peak NAME: the manager's own memory-peak and runtime text for a unit that ended.
peak() {
  grep -i -E 'memory peak|service runtime|cpu time' "$SBX_LOGS/$1.systemd" 2>/dev/null | sed -e 's/^ *//' | tr '\n' ';' | cut -c1-200
}

# watch_mem NAME: samples the unit's control group once a second until the file NAME.done appears
# in the log folder, and leaves the highest memory.peak (bytes) in NAME.mem. The manager's own end
# text gave a few hundred KiB for a build that used 56 CPU seconds, so it is not the figure used.
# Start it in the background before the unit; call stop_mem NAME after the unit has ended.
watch_mem() {
  local name=$1 cg="/sys/fs/cgroup/system.slice/$1.service" max=0 v f
  while [ ! -e "$SBX_LOGS/$name.done" ]; do
    for f in memory.peak memory.current; do
      v=$(cat "$cg/$f" 2>/dev/null)
      case $v in '' | *[!0-9]*) ;; *) [ "$v" -gt "$max" ] && max=$v ;; esac
    done
    sleep 1
  done
  printf '%s\n' "$max" >"$SBX_LOGS/$name.mem"
}
stop_mem() {
  : >"$SBX_LOGS/$1.done"
  local i
  for i in $(seq 1 10); do [ -s "$SBX_LOGS/$1.mem" ] && break; sleep 0.5; done
}
# mem_peak NAME: the sampled peak in MiB.
mem_peak() { awk -v b="$(cat "$SBX_LOGS/$1.mem" 2>/dev/null || echo 0)" 'BEGIN { printf "%.0f MiB (sampled)", b / 1048576 }'; }

# The byte proxy: a socket in the legs' namespace and a proxy service in the service's namespace.
# (Form 1 of the reach group.) usage: start_proxy PORT SERVICE_NAMESPACE_INODE
start_proxy() {
  local port=$1 ino=$2
  sudo -n systemd-run --unit=sbx-k-proxy --collect \
    --socket-property=ListenStream=127.0.0.1:"$port" --socket-property=NetworkNamespacePath=/run/netns/sbx-legs \
    -p NetworkNamespacePath=/run/netns/sbx-svc -p DynamicUser=yes -p NoNewPrivileges=yes -p CapabilityBoundingSet= \
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateDevices=yes -p PrivateTmp=yes -p ProtectProc=invisible \
    -p 'RestrictAddressFamilies=AF_INET AF_UNIX' -p SystemCallArchitectures=native -p IPAddressDeny=any -p 'IPAddressAllow=127.0.0.1/32' \
    -p StandardOutput=null -p RuntimeMaxSec=1500 \
    "$GUARD" --netns-inode "$ino" -- /usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:"$port" 2>&1
}
stop_proxy() { sudo -n systemctl stop sbx-k-proxy.socket sbx-k-proxy.service 2>/dev/null || true; }

# secs: seconds with a fraction since an epoch given by `date +%s.%N`.
now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }
