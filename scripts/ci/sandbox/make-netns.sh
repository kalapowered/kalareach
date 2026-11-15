#!/bin/bash
# make-netns.sh add NAME...      makes each network namespace and brings its loopback up
# make-netns.sh delete NAME...   removes each one
# make-netns.sh inode NAME       prints the inode that the guard compares with
#
# The runner makes the namespaces before the first unit and every unit joins one by its path
# (/run/netns/NAME), never by another unit's name. A namespace holds the loopback alone: `ip
# netns add` leaves it down, so it is brought up here, and the check below fails the script when
# the namespace holds anything else or the loopback has no address.
set -eu

action=${1:-}
[ "$#" -ge 2 ] || { echo "usage: make-netns.sh add|delete NAME... | inode NAME" >&2; exit 2; }
shift

valid() {
  case $1 in
    '' | *[!A-Za-z0-9._-]*) echo "make-netns: bad namespace name" >&2; exit 2 ;;
  esac
}

case $action in
  add)
    for name in "$@"; do
      valid "$name"
      sudo -n ip netns add "$name"
      sudo -n ip -n "$name" link set lo up
      links=$(sudo -n ip -n "$name" -o link show | wc -l)
      [ "$links" -eq 1 ] || { echo "make-netns: $name holds $links interfaces, not one" >&2; exit 1; }
      sudo -n ip -n "$name" -o addr show dev lo | grep -q 'inet 127.0.0.1/8' || { echo "make-netns: $name: no 127.0.0.1" >&2; exit 1; }
      sudo -n ip -n "$name" -o -6 addr show dev lo | grep -q 'inet6 ::1/128' || { echo "make-netns: $name: no ::1" >&2; exit 1; }
      echo "make-netns: $name inode=$(sudo -n stat -L -c %i "/run/netns/$name")"
    done
    ;;
  delete)
    for name in "$@"; do
      valid "$name"
      sudo -n ip netns delete "$name"
    done
    ;;
  inode)
    [ "$#" -eq 1 ] || { echo "usage: make-netns.sh inode NAME" >&2; exit 2; }
    valid "$1"
    sudo -n stat -L -c %i "/run/netns/$1"
    ;;
  *)
    echo "usage: make-netns.sh add|delete NAME... | inode NAME" >&2
    exit 2
    ;;
esac
