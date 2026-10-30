#!/usr/bin/env bash
# What the two store build scripts share: where the signing material is, how a build is numbered,
# where its output goes, and how a script that has read a secret keeps it out of every record.
#
# Source this file. Nothing here prints a secret, puts one on a command line, or keeps one in a
# variable: a secret is a file, and a tool that needs it is given the file's path.
#
# The signing material is read from `KR_SECRETS_DIR` (default `~/.config/kalareach-secrets`):
#
#   android-upload/kalareach-upload.p12      the Android upload key (PKCS12, alias `upload`)
#   android-upload/keystore-password         its password
#   android-upload/upload-certificate.pem    the upload key's public certificate
#   apple/asc-api-key.json                   the App Store Connect API key's identifiers and file
#   firebase-apps/google-services.json       the Android push configuration
#   firebase-apps/GoogleService-Info.plist   the iOS push configuration
#
# A build's output goes to `KR_STORE_ROOT` (default `~/Library/Caches/kalareach-store`), one
# directory for each version and build number, and one receipt file for each platform records the
# highest build number that platform has built and checked.

KR_SECRETS_DIR="${KR_SECRETS_DIR:-$HOME/.config/kalareach-secrets}"
KR_STORE_ROOT="${KR_STORE_ROOT:-$HOME/Library/Caches/kalareach-store}"
kr_store_checker="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/apps/companion/scripts/store-bundle.mjs"

# Build numbers count whole minutes from this instant (2026-10-01T00:00:00Z). A number rises with
# the clock, so no counter has to be stored, and each store's rule holds: Google Play wants every
# upload above all earlier ones (its limit is 2,100,000,000), and TestFlight wants a build number
# that is unique within a version and increasing.
KR_STORE_EPOCH=1790812800

kr_store_say() { printf '== [%s] %s\n' "${kr_store_tag:-store}" "$*"; }

# The version the companion declares (`version` in `tauri.conf.json`).
kr_store_version() {
    node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).version)' \
        "$1/apps/companion/src-tauri/tauri.conf.json"
}

# kr_store_number <platform> [override]: prints the build number, or says why there is none.
# The number must be above the platform's receipt, so a clock that was set back, a number given by
# hand and a rebuild of an old number all fail instead of reaching a store.
kr_store_number() {
    local platform=$1 given=${2:-} number receipt last=0
    if [ -n "$given" ]; then
        case "$given" in
            '' | *[!0-9]* | 0*) kr_store_say "the build number must be a whole number without a leading zero" >&2; return 2 ;;
        esac
        number=$given
    else
        number=$((($(date -u +%s) - KR_STORE_EPOCH) / 60))
    fi
    receipt="$KR_STORE_ROOT/receipts/$platform"
    if [ -f "$receipt" ]; then
        last="$(tr -d '[:space:]' <"$receipt")"
        case "$last" in '' | *[!0-9]*) kr_store_say "the receipt $receipt does not hold a number" >&2; return 2 ;; esac
        if [ "${#last}" -gt 10 ]; then kr_store_say "the receipt $receipt holds a number longer than ten digits" >&2; return 2; fi
    fi
    if [ "${#number}" -gt 10 ]; then
        kr_store_say "build number $number is longer than ten digits" >&2
        return 2
    fi
    if [ "$number" -le "$last" ]; then
        kr_store_say "build number $number is not above $last, the highest $platform has built; wait a minute or name a higher one" >&2
        return 2
    fi
    if [ "$number" -ge 2100000000 ]; then
        kr_store_say "build number $number is over the stores' limit" >&2
        return 2
    fi
    printf '%s\n' "$number"
}

# kr_store_receipt <platform> <number>: records a build that passed its checks. The receipt keeps
# the larger of the number it holds and this one, so two runs that overlap cannot lower it, and a
# failure to write it is the caller's failure. One writer at a time: the writer holds a kernel lock
# (`lockf` on a descriptor of `<receipt>.flock`) for the read and the write. The lock goes with the
# process that holds it, so no run can leave it held and none can take it from a run that is still
# working; a writer that cannot get it within `KR_STORE_LOCK_WAIT` seconds (default 60) fails.
kr_store_receipt() (
    platform=$1 number=$2
    receipt="$KR_STORE_ROOT/receipts/$platform"
    mkdir -p "$KR_STORE_ROOT/receipts" || exit 2
    exec 9>>"$receipt.flock" || exit 2
    limit="${KR_STORE_LOCK_WAIT:-60}"
    case "$limit" in
        *[!0-9]*) kr_store_say "KR_STORE_LOCK_WAIT must be a whole number of seconds, not '$limit'" >&2; exit 2 ;;
    esac
    lockf -s -t "$limit" 9
    locked=$?
    if [ "$locked" != 0 ]; then
        # 75 is lockf's answer when another process holds the lock.
        if [ "$locked" = 75 ]; then kr_store_say "the receipt for $platform is locked by another run" >&2
        else kr_store_say "lockf failed with status $locked, so the receipt for $platform cannot be written" >&2; fi
        exit 2
    fi
    old=0
    [ ! -f "$receipt" ] || old="$(tr -d '[:space:]' <"$receipt")"
    if [ "$old" -gt "$number" ] 2>/dev/null; then number=$old; fi
    if temporary="$(mktemp "$receipt.XXXXXX")" && printf '%s\n' "$number" >"$temporary" && mv -f "$temporary" "$receipt"; then
        exit 0
    fi
    rm -f -- "${temporary:-$receipt.none}"
    exit 2
)

# kr_store_claim_number <platform> <number>: reserves a build number for a platform, whatever the
# version, so that two builds of different versions made in one minute cannot both ship it (Google
# Play wants every version code to be unique). It fails when the number is already claimed.
kr_store_claim_number() {
    mkdir -p "$KR_STORE_ROOT/claims" || return 2
    if ! mkdir "$KR_STORE_ROOT/claims/$1-$2" 2>/dev/null; then
        kr_store_say "build number $2 is already claimed for $1; wait a minute" >&2
        return 2
    fi
}

# kr_store_claim <directory>: makes the output directory of one build, and fails when it exists, so
# that two builds of one number (two worktrees in the same minute) cannot share a directory.
kr_store_claim() {
    mkdir -p "$(dirname "$1")" || return 2
    if ! mkdir "$1" 2>/dev/null; then
        kr_store_say "$1 exists already, or cannot be made" >&2
        return 2
    fi
}

# kr_store_refuse_secret_in <secret file> <path>...: fails, naming nothing of the path, when a path
# that a message is about to print holds the secret in any form the checker searches for, or when
# the secret cannot be read. The checker refuses such a path itself, but only once the scripts have
# printed it in their own messages.
kr_store_refuse_secret_in() {
    local secret=$1 each shown
    shift
    for each in "$@"; do
        shown="$(printf '%s' "$each" | node "$kr_store_checker" --redact --secret-file "$secret")" \
            || { kr_store_say "a path could not be searched for the secret; nothing is built" >&2; return 2; }
        [ "$shown" = "$each" ] || { kr_store_say "a path holds the secret's text or a signed token; nothing is built" >&2; return 2; }
    done
}

# kr_store_show_tail <log> <secret file>: the last lines of a log, indented, for a person to read
# when a step has failed. The whole log goes through the checker first, so that a secret split across
# the first line of the tail is found: it leaves out all of the log when it holds the secret in any
# form (split across lines too) and each line that holds a signed token or a part of one; when it
# cannot read the secret it prints nothing.
kr_store_show_tail() {
    node "$kr_store_checker" --redact --secret-file "$2" <"$1" | tail -n 20 | sed 's/^/    /'
}

# kr_store_remove_token_logs <output directory>: Xcode keeps request tokens made from the API key in
# two places, `Packaging.log` beside the exported build and a log bundle in the temporary directory
# that the export log names. Neither is of use after the export, and a token is not a secret file a
# scan could match, so both go. It fails when a log cannot be removed, or is outside the temporary
# directory, which it does not clear, or when an export log exists and names no bundle. Xcode writes
# to the per-user temporary directory when `TMPDIR` is not set.
kr_store_remove_token_logs() {
    local named tmp parent
    rm -f -- "${1:?}/export/Packaging.log"
    named="$(sed -n 's/.*Created bundle at path "\(.*\.xcdistributionlogs\)".*/\1/p' "$1/export.log" 2>/dev/null | head -1)"
    if [ -z "$named" ]; then
        # An export log names its log bundle on its first line. One that does not may have left tokens
        # in a place this cannot find.
        [ ! -e "$1/export.log" ] || { kr_store_say "the export log $1/export.log names no Xcode log bundle; look for one in the temporary directory and remove it by hand" >&2; return 2; }
        return 0
    fi
    tmp="$(cd "${TMPDIR:-$(getconf DARWIN_USER_TEMP_DIR)}" 2>/dev/null && pwd -P)"
    parent="$(cd "$(dirname "$named")" 2>/dev/null && pwd -P)"
    if [ -z "$tmp" ] || [ "$parent" != "$tmp" ]; then
        kr_store_say "Xcode's export log $named is outside the temporary directory $tmp and was not removed; remove it by hand" >&2
        return 2
    fi
    [ ! -d "$named" ] || rm -rf -- "${named:?}"
    if [ -d "$named" ]; then
        kr_store_say "Xcode's export log $named could not be removed" >&2
        return 2
    fi
}

# kr_store_require_file <path> <what>: a regular file, and one that only its owner can read.
kr_store_require_file() {
    local path=$1 what=$2 mode
    [ -f "$path" ] || { kr_store_say "no $what at $path" >&2; return 2; }
    mode="$(stat -f '%Lp' "$path")"
    case "$mode" in
        400 | 600) ;;
        *) kr_store_say "$what at $path is readable by others (mode $mode); it must be 0600" >&2; return 2 ;;
    esac
}

# kr_store_json_field <file> <field>: one string field of a JSON file, printed without a newline.
# Used for the identifiers in the API key's record, which are not secrets.
kr_store_json_field() {
    node -e 'const v = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))[process.argv[2]]
if (typeof v !== "string" || v === "") process.exit(1)
process.stdout.write(v)' "$1" "$2"
}

# kr_store_clean_tree <repository>: the tracked files carry no uncommitted change, so a store build
# is of a commit. `KR_STORE_ALLOW_DIRTY=1` lifts it for a run that is only a trial.
kr_store_clean_tree() {
    local changes
    changes="$(git -C "$1" status --porcelain --untracked-files=no 2>/dev/null)" \
        || { kr_store_say "git could not read the state of $1" >&2; return 2; }
    [ "${KR_STORE_ALLOW_DIRTY:-}" = 1 ] && return 0
    if [ -n "$changes" ]; then
        kr_store_say "the tracked files have uncommitted changes; a store build is of a commit (KR_STORE_ALLOW_DIRTY=1 allows a trial)" >&2
        return 2
    fi
}

# kr_store_official_run <command...>: runs a build as the official one. A store bundle registers
# with the official push gateway, so a gateway the person running the script has named in the
# environment, for an independently signed build, is taken out of the build's environment, and the
# build is marked official. The companion's build step refuses a gateway input under the mark,
# whichever way the input reached the build; a Cargo configuration file's `[env]` table is one
# that the removal does not reach. `store-bundle.mjs` then reads the gateway back from the
# packaged library.
kr_store_official_run() {
    env -u KR_PUSH_GATEWAY_ORIGIN KR_OFFICIAL_BUILD=1 "$@"
}

# kr_store_cargo_target <repository>: the cargo target directory of this worktree, beside the
# worktrees, so no two worktrees share one.
kr_store_cargo_target() {
    local name
    name="$(basename "$1")"
    printf '%s\n' "$(dirname "$1")/.targets/$name"
}

# The iOS build rewrites tracked files under the Apple project (`Info.plist`, the entitlements
# files, the project itself) and reads one ignored file there, `Local.xcconfig`. These two
# functions put all of it back, and they never touch work a person has not committed:
#
#   kr_store_guard_begin <repository> <apple directory>   refuses unless the directory has no
#                          uncommitted change and no new file (the trial override of
#                          `kr_store_clean_tree` does not lift this one, because putting the
#                          directory back is a checkout), and keeps a copy of a `Local.xcconfig`
#                          that exists;
#   kr_store_guard_write_local <text>   writes `Local.xcconfig`, which `kr_store_guard_end` removes
#                          again (or replaces by the saved copy);
#   kr_store_guard_end     checks out the tracked files and restores `Local.xcconfig`. When it cannot
#                          put something back it keeps the saved copy and names where it is.
kr_store_guard_begin() {
    local relative=${2#"$1"/} changes
    changes="$(git -C "$1" status --porcelain -- "$relative" 2>/dev/null)" \
        || { kr_store_say "git could not read the state of $1" >&2; return 2; }
    if [ -n "$changes" ]; then
        kr_store_say "the Apple project has uncommitted or new files under $relative; the build puts that directory back when it ends, so commit or discard them first" >&2
        return 2
    fi
    kr_guard_kept="$(mktemp -d "${TMPDIR:-/tmp}/kr-store-guard.XXXXXX")" || return 2
    kr_guard_local="$2/Local.xcconfig"
    kr_guard_had=0
    kr_guard_wrote=0
    if [ -f "$kr_guard_local" ]; then
        if ! cp -p "$kr_guard_local" "$kr_guard_kept/Local.xcconfig"; then
            kr_store_say "could not keep $kr_guard_local; nothing was changed" >&2
            rm -rf -- "${kr_guard_kept:?}"
            return 2
        fi
        kr_guard_had=1
    fi
    # Only now does the guard hold anything to put back.
    kr_guard_relative=$relative
    kr_guard_repo=$1
}

kr_store_guard_write_local() {
    kr_guard_wrote=1
    printf '%s\n' "$1" >"$kr_guard_local"
}

kr_store_guard_end() {
    local failed=0
    [ -n "${kr_guard_repo:-}" ] || return 0
    git -C "$kr_guard_repo" checkout -- "$kr_guard_relative" 2>/dev/null || failed=1
    if [ "$kr_guard_wrote" = 1 ]; then
        if [ "$kr_guard_had" = 1 ]; then
            cp -p "$kr_guard_kept/Local.xcconfig" "$kr_guard_local" || failed=1
        else
            rm -f -- "${kr_guard_local:?}" || failed=1
        fi
    fi
    if [ "$failed" = 0 ]; then
        rm -rf -- "${kr_guard_kept:?}"
    else
        kr_store_say "could not put the Apple project back; check git status for $kr_guard_relative, and the copy of Local.xcconfig, if there was one, is in $kr_guard_kept" >&2
    fi
    kr_guard_repo=""
    return "$failed"
}
