#!/bin/bash
# Stand-in for one tool of the launcher's reads, chosen by the name it is called by: group L makes
# a link to this file for each tool name in a folder of its own and puts that folder first on the
# PATH of the one command it runs. Without L_AFTER a tool gives its real answer (sed, wc, id, od,
# awk, cat, stat) or a canned one (ip, systemctl: no namespace and no unit is made or asked
# about). L_AFTER names the one tool that, after it printed its answer, ends with a failure:
#   sed, wc, id, od, cat (a read of a cgroup.procs file), awk (a read of an ipv6_route file: no
#   answer, status 2), ip-link, ip-addr4, ip-addr6, systemctl, or sudo (every call fails at once).
# L_UNIT (gone, active, inactive) is the unit that the canned systemctl describes.
set -u
name=${0##*/}
after=${L_AFTER:-}
unit=${L_UNIT:-gone}

real() {
  local d
  for d in /usr/bin /bin; do
    if [ -x "$d/$name" ]; then
      "$d/$name" "$@"
      return
    fi
  done
  return 127
}

case $name in
  sed | wc | id | od)
    real "$@"
    rc=$?
    if [ "$after" = "$name" ]; then exit 7; fi
    exit "$rc"
    ;;
  awk)
    if [ "$after" = awk ]; then
      case ${!#} in *ipv6_route) exit 2 ;; esac
    fi
    real "$@"
    exit
    ;;
  cat)
    real "$@"
    rc=$?
    if [ "$after" = cat ]; then
      case ${!#} in *cgroup.procs) exit 7 ;; esac
    fi
    exit "$rc"
    ;;
  stat)
    case ${!#} in
      /run/netns/*) echo 4026531999; exit 0 ;;
    esac
    real "$@"
    exit
    ;;
  sleep)
    exit 0
    ;;
  sudo)
    if [ "$after" = sudo ]; then exit 1; fi
    if [ "${1:-}" = -n ]; then shift; fi
    exec "$@"
    ;;
  ip)
    args=" $* "
    case $args in
      *' netns add '* | *' netns delete '* | *' link set lo up '*)
        exit 0
        ;;
      *' -o link show '*)
        echo '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00'
        if [ "$after" = ip-link ]; then exit 7; fi
        exit 0
        ;;
      *' -o -6 addr show dev lo '*)
        echo '1: lo    inet6 ::1/128 scope host noprefixroute \       valid_lft forever preferred_lft forever'
        if [ "$after" = ip-addr6 ]; then exit 7; fi
        exit 0
        ;;
      *' -o addr show dev lo '*)
        echo '1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever'
        if [ "$after" = ip-addr4 ]; then exit 7; fi
        exit 0
        ;;
    esac
    ;;
  systemctl)
    args=" $* "
    case $args in
      *' stop '*)
        if [ "$unit" = gone ]; then exit 5; fi
        exit 0
        ;;
      *' show -p LoadState -p ActiveState '*)
        case $unit in
          gone) echo LoadState=not-found; echo ActiveState=inactive ;;
          active) echo LoadState=loaded; echo ActiveState=active ;;
          *) echo LoadState=loaded; echo ActiveState=inactive ;;
        esac
        if [ "$after" = systemctl ]; then exit 7; fi
        exit 0
        ;;
      *' show -p ActiveState --value '*)
        case $unit in
          active) echo active ;;
          *) echo inactive ;;
        esac
        if [ "$after" = systemctl ]; then exit 7; fi
        exit 0
        ;;
      *' cat '*)
        if [ "$unit" = gone ]; then exit 1; fi
        echo '[Unit]'
        echo 'Description=stand-in'
        if [ "$after" = systemctl ]; then exit 7; fi
        exit 0
        ;;
    esac
    ;;
esac
echo "l-stub: no answer for $name $*" >&2
exit 64
