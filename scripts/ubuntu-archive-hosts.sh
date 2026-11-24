#!/usr/bin/env bash
# Points apt on a hosted Ubuntu 24.04 runner at the Ubuntu archive and security hosts by name.
#
#   bash scripts/ubuntu-archive-hosts.sh [--root DIR]
#
# The image's apt sources name a mirror that it picks by the runner's region: the Azure mirror, or
# an EC2 region's. On the same day the first gave the package indexes at 10 to 12 MB/s and the
# second at 0.5 to 0.6 MB/s, and a download from the second ran at 79 kB/s; the archive and the
# security hosts gave 12 to 36 MB/s. `scripts/apt-install.sh` bounds a slow mirror and tries again;
# this script takes the cause away, and the bounds stay for the day an archive host is slow too.
#
# The image's file, /etc/apt/sources.list.d/ubuntu.sources, moves to /etc/apt/ubuntu.sources.runner,
# a place apt does not read, and /etc/apt/sources.list.d/ubuntu-archive.sources takes its place with
# the same suites and components: noble, noble-updates and noble-backports from archive.ubuntu.com,
# noble-security from security.ubuntu.com, both over http as the image's file is, and signed by the
# archive keyring. A second call finds that done and changes nothing. A runner that is not Ubuntu
# 24.04 on x86-64 (the ports host serves the others), or whose image does not hold the file where
# this expects it, fails the step: the cure is not applied and the run says so, instead of going on
# with the mirror that stalls.
#
# --root DIR reads and writes below DIR instead of /, for the script's own cases (and then the
# processor is not checked). Files are written through sudo unless the caller is root.
set -euo pipefail

root=
while [ $# -gt 0 ]; do
  case "$1" in
    --root)
      [ $# -ge 2 ] || { echo "usage: ubuntu-archive-hosts.sh [--root DIR]" >&2; exit 2; }
      root=${2%/}
      shift 2
      ;;
    *)
      echo "usage: ubuntu-archive-hosts.sh [--root DIR]" >&2
      exit 2
      ;;
  esac
done

if [ "$(id -u)" -eq 0 ]; then
  as_root() { "$@"; }
else
  as_root() { sudo "$@"; }
fi

fail() {
  echo "ubuntu-archive-hosts: $*" >&2
  exit 1
}

release_file=$root/etc/os-release
[ -f "$release_file" ] || fail "no $release_file"
# shellcheck disable=SC1090  # the file is the image's own, or a case's
id=$(. "$release_file" && echo "${ID-}")
# shellcheck disable=SC1090
codename=$(. "$release_file" && echo "${VERSION_CODENAME-}")
[ "$id" = ubuntu ] && [ "$codename" = noble ] || fail "this is $id $codename; only Ubuntu 24.04 (noble) is served here"
# A tree below --root is not the running system, so the processor says nothing about it.
if [ -z "$root" ]; then
  [ "$(uname -m)" = x86_64 ] || fail "this is $(uname -m); the archive host serves x86-64 only"
fi

sources_dir=$root/etc/apt/sources.list.d
runner_sources=$sources_dir/ubuntu.sources
archive_sources=$sources_dir/ubuntu-archive.sources
aside_sources=$root/etc/apt/ubuntu.sources.runner

wanted=$(cat <<'EOF'
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
)

if [ -f "$archive_sources" ] && [ ! -e "$runner_sources" ]; then
  [ "$(cat "$archive_sources")" = "$wanted" ] || fail "$archive_sources exists and is not the file this script writes"
  echo "ubuntu-archive-hosts: already in place: $archive_sources"
  exit 0
fi

[ -f "$runner_sources" ] || fail "the image's sources file is not at $runner_sources; $sources_dir holds: $(find "$sources_dir" -maxdepth 1 2>&1 | tr '\n' ' ')"
[ ! -e "$archive_sources" ] || fail "$archive_sources exists beside the image's file"

printf '%s\n' "$wanted" | as_root tee "$archive_sources" > /dev/null
as_root mv "$runner_sources" "$aside_sources"
echo "ubuntu-archive-hosts: new sources file: $archive_sources"
echo "ubuntu-archive-hosts: the image's file, moved aside: $aside_sources"
cat "$archive_sources"
