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
# noble-security from security.ubuntu.com, both over https (the image's own mirror list names the same
# two hosts over https as its fallbacks, so a runner reaches them that way), and signed by the
# archive keyring. A second call finds that done and changes nothing.
#
# A runner that is not Ubuntu 24.04 on x86-64 (the ports host serves the others) fails the step. The
# cure is a speed change and never a reason to turn a run red, so these three things print a
# `::warning::` line and leave the step green:
#   - the image does not hold its sources file where this expects it: nothing is changed;
#   - the image's file names other suites or components than the new file does: the new file is
#     still written, and the line says which differ;
#   - after the change, a source that apt still reads names the image's mirror list (mirror+file,
#     mirror) or a regional host (azure.archive.ubuntu.com, an EC2 region's, a country's): the line
#     names the file and the line, so "the regional mirror is no longer used" is checked at run time.
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

warn() {
  echo "::warning::ubuntu-archive-hosts: $*"
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
URIs: https://archive.ubuntu.com/ubuntu
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: https://security.ubuntu.com/ubuntu
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
)

# The sorted, distinct words of every `<field>:` line of the deb822 text on standard input.
words_of() {
  awk -v field="$1" 'tolower($1) == tolower(field ":") { for (i = 2; i <= NF; i++) print $i }' | sort -u | tr '\n' ' '
}

# After the change: no source that apt reads may still name the image's mirror list or a regional host.
check_sources() {
  local f hits=0 line
  for f in "$root/etc/apt/sources.list" "$sources_dir"/*.list "$sources_dir"/*.sources; do
    [ -f "$f" ] || continue
    while IFS= read -r line; do
      warn "$f still names the image's mirror list or a regional host, so apt may use it: $line"
      hits=$((hits + 1))
    done < <(grep -v -E '^[[:space:]]*#' "$f" | grep -E 'mirror\+file:|mirror\+https?:|mirror://|[a-z0-9-]+\.archive\.ubuntu\.com' || true)
  done
  if [ "$hits" -eq 0 ]; then
    echo "ubuntu-archive-hosts: no source that apt reads names a mirror list or a regional host"
  fi
}

if [ -f "$archive_sources" ] && [ ! -e "$runner_sources" ]; then
  [ "$(cat "$archive_sources")" = "$wanted" ] || fail "$archive_sources exists and is not the file this script writes"
  echo "ubuntu-archive-hosts: already in place: $archive_sources"
  check_sources
  exit 0
fi

if [ ! -f "$runner_sources" ]; then
  warn "the image's sources file is not at $runner_sources; nothing is changed and the image's own mirror stays in use (scripts/apt-install.sh still bounds a slow one); $sources_dir holds: $(find "$sources_dir" -maxdepth 1 2>&1 | tr '\n' ' ')"
  check_sources
  exit 0
fi
[ ! -e "$archive_sources" ] || fail "$archive_sources exists beside the image's file"

image_suites=$(words_of Suites < "$runner_sources")
image_components=$(words_of Components < "$runner_sources")
wanted_suites=$(printf '%s\n' "$wanted" | words_of Suites)
wanted_components=$(printf '%s\n' "$wanted" | words_of Components)
if [ "$image_suites" != "$wanted_suites" ]; then
  warn "the image's file names the suites [${image_suites% }] and the new file [${wanted_suites% }]: the new file is written as it is"
fi
if [ "$image_components" != "$wanted_components" ]; then
  warn "the image's file names the components [${image_components% }] and the new file [${wanted_components% }]: the new file is written as it is"
fi

printf '%s\n' "$wanted" | as_root tee "$archive_sources" > /dev/null
as_root mv "$runner_sources" "$aside_sources"
echo "ubuntu-archive-hosts: new sources file: $archive_sources"
echo "ubuntu-archive-hosts: the image's file, moved aside: $aside_sources"
cat "$archive_sources"
check_sources
