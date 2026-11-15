#!/bin/bash
# guard.sh --netns-inode INODE -- COMMAND [ARGS...]
#
# The first command of every namespaced unit. It refuses, with exit status 97 and a line on
# standard error, unless the unit stands in the network namespace that the runner made (the
# inode of /proc/self/ns/net is INODE) with the loopback alone, up, holding 127.0.0.1 and ::1,
# no route, and with the properties that the launcher sets: no new privileges, a seccomp
# filter and no capability. Only then does it replace itself with COMMAND.
#
# A transient unit whose private network could not be made would otherwise run on, with a
# warning in the manager's log, in the host's namespace. This check is why that cannot pass.
#
# The file is installed by the runner as root, outside every account's reach.
set -u

refuse() {
  echo "guard: refused: $*" >&2
  exit 97
}

[ "$#" -ge 4 ] && [ "$1" = "--netns-inode" ] && [ "$3" = "--" ] || refuse "usage: guard.sh --netns-inode INODE -- COMMAND [ARGS...]"
want=$2
shift 3
case $want in
  '' | *[!0-9]*) refuse "the inode is not a number" ;;
esac

have=$(stat -L -c %i /proc/self/ns/net 2>/dev/null) || refuse "cannot read /proc/self/ns/net"
[ "$have" = "$want" ] || refuse "network namespace inode $have is not the runner's $want"

# The interfaces of this namespace (not sysfs: its view is the namespace it was mounted in). One
# command reads the file and drops its two header lines and each line's counters.
names=$(sed -e '1,2d' -e 's/^ *//' -e 's/:.*//' /proc/self/net/dev) || refuse "cannot read /proc/self/net/dev"
[ "$names" = "lo" ] || refuse "the interfaces are not the loopback alone"

# Both loopback addresses are present, which also shows that the loopback was brought up.
grep -q '^00000000000000000000000000000001 .* lo$' /proc/self/net/if_inet6 || refuse "no ::1 on lo"
awk '
  /\|-- 127\.0\.0\.1[ ]*$/ { want = 1; next }
  want && /\/32 host LOCAL/ { found = 1; exit }
  { want = 0 }
  END { exit found ? 0 : 1 }
' /proc/self/net/fib_trie || refuse "no 127.0.0.1 on lo"

# No route: the main table of IPv4 is only its header, and IPv6 has routes on lo alone.
route_lines=$(wc -l < /proc/self/net/route) || refuse "cannot read /proc/self/net/route"
[ "$route_lines" -le 1 ] || refuse "an IPv4 route exists"
bad_routes=$(awk 'NF && $NF != "lo" { n++ } END { print n + 0 }' /proc/self/net/ipv6_route) || refuse "cannot read /proc/self/net/ipv6_route"
[ "$bad_routes" = "0" ] || refuse "an IPv6 route outside lo exists"

status=$(cat /proc/self/status) || refuse "cannot read /proc/self/status"
grep -q '^NoNewPrivs:[[:space:]]*1$' <<<"$status" || refuse "NoNewPrivs is not 1"
grep -q '^Seccomp:[[:space:]]*2$' <<<"$status" || refuse "no seccomp filter"
grep -q '^CapEff:[[:space:]]*0*$' <<<"$status" || refuse "a capability is effective"
uid=$(id -u) || refuse "cannot read the account's id"
[ "$uid" != "0" ] || refuse "the unit runs as root"

case $1 in
  /*) ;;
  *) refuse "the command is not an absolute path" ;;
esac
exec "$@"
