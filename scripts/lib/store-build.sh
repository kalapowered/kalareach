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

# kr_store_receipt <platform> <number>: records a build that passed its checks.
kr_store_receipt() {
    mkdir -p "$KR_STORE_ROOT/receipts"
    printf '%s\n' "$2" >"$KR_STORE_ROOT/receipts/$1"
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
