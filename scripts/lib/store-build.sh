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
            '' | *[!0-9]*) kr_store_say "the build number must be a whole number, not '$given'" >&2; return 2 ;;
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
# failure to write it is the caller's failure.
kr_store_receipt() {
    local platform=$1 number=$2 receipt old=0 temporary
    receipt="$KR_STORE_ROOT/receipts/$platform"
    mkdir -p "$KR_STORE_ROOT/receipts" || return 2
    [ ! -f "$receipt" ] || old="$(tr -d '[:space:]' <"$receipt")"
    if [ "$old" -gt "$number" ] 2>/dev/null; then number=$old; fi
    temporary="$(mktemp "$receipt.XXXXXX")" || return 2
    if ! { printf '%s\n' "$number" >"$temporary" && mv -f "$temporary" "$receipt"; }; then
        rm -f -- "${temporary:?}"
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
    [ "${KR_STORE_ALLOW_DIRTY:-}" = 1 ] && return 0
    if [ -n "$(git -C "$1" status --porcelain --untracked-files=no)" ]; then
        kr_store_say "the tracked files have uncommitted changes; a store build is of a commit (KR_STORE_ALLOW_DIRTY=1 allows a trial)" >&2
        return 2
    fi
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
#   kr_store_guard_begin <repository> <apple directory>   refuses unless the tracked files under the
#                          directory are clean (the trial override of `kr_store_clean_tree` does not
#                          lift this one, because putting them back is a checkout), and keeps a copy
#                          of a `Local.xcconfig` that exists;
#   kr_store_guard_write_local <text>   writes `Local.xcconfig`, which `kr_store_guard_end` removes
#                          again (or replaces by the saved copy);
#   kr_store_guard_end     checks out the tracked files and restores `Local.xcconfig`. When it cannot
#                          put something back it keeps the saved copy and names where it is.
kr_store_guard_begin() {
    kr_guard_repo=$1
    kr_guard_relative=${2#"$1"/}
    kr_guard_local="$2/Local.xcconfig"
    kr_guard_kept=""
    kr_guard_had=0
    kr_guard_wrote=0
    if [ -n "$(git -C "$kr_guard_repo" status --porcelain -- "$kr_guard_relative")" ]; then
        kr_store_say "the Apple project has uncommitted changes under $kr_guard_relative; the build puts that directory back when it ends, so commit or discard them first" >&2
        return 2
    fi
    kr_guard_kept="$(mktemp -d "${TMPDIR:-/tmp}/kr-store-guard.XXXXXX")" || return 2
    if [ -f "$kr_guard_local" ]; then
        if ! cp -p "$kr_guard_local" "$kr_guard_kept/Local.xcconfig"; then
            kr_store_say "could not keep $kr_guard_local; nothing was changed" >&2
            rm -rf -- "${kr_guard_kept:?}"
            return 2
        fi
        kr_guard_had=1
    fi
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
