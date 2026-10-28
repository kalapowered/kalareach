#!/usr/bin/env bash
# Signs and notarises the two macOS release trees on the machine that holds the organisation's
# Developer ID, and stages them for the workflow that seals the release.
#
#   scripts/sign-macos-release.sh --build-run <run id> --commit <sha> [--no-stage]
#   scripts/sign-macos-release.sh --archive <kalareach-...tar.gz> [--archive <...>]
#   scripts/sign-macos-release.sh --remove-staging <release>
#
# The Developer ID key, its certificate and the notary key are files under $KR_APPLE_DIR
# (~/.config/kalareach-secrets/apple), mode 0600, read by path: none is imported into a keychain,
# none is sent to a service, and nothing here changes the person's keychains or their search list.
# The files are:
#
#   developer-id-application.key   the private key, PKCS #8 PEM
#   developer-id-application.pem   the certificate
#   DeveloperIDG2CA.cer            Apple's Developer ID intermediate certificate, DER
#   asc-api-key.json               key_id, issuer_id, team_id and key_file of the notary API key
#   the .p8 that key_file names    the notary API key
#
# With --build-run: the unsigned trees of the two macOS targets are taken from the named run of
# `release-tree.yml`, after the run is held to the commit and each artefact to the digest GitHub
# states for it and to the sum beside it; each tree is signed (`sign-macos-tree.sh developer-id`),
# held to what a Developer ID release is, notarised with `notarytool`, held to what a notarised
# release is, and packed. Unless --no-stage, the two packed trees, the notary submissions and the run
# and commit they were made from are put in a draft pre-release named host-staging/v<release>, with one
# file of sums over all four, and the command that starts the sealing is printed with the digest of
# that file, which the workflow holds the staging to. A draft is the place a command outside a
# workflow can leave files for one. A staged release is made only from a run on main; with --no-stage a
# run of any branch may be used, since nothing leaves this machine.
#
# With --archive: a release archive of an earlier run is unpacked and signed and notarised the same
# way, nothing is staged, and the signed trees are left in the work directory.
#
# Every Apple file is checked before use: its mode, the certificate's subject, team and remaining
# validity, and that the key is the certificate's.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
team="L775WGST9V"
repo="${KR_RELEASE_REPO:-kalapowered/kalareach}"
apple="${KR_APPLE_DIR:-$HOME/.config/kalareach-secrets/apple}"
work_root="${KR_RELEASE_WORK:-$HOME/Library/Caches/kalareach-release}"
targets=(aarch64-apple-darwin x86_64-apple-darwin)

run=""
commit=""
stage=1
remove=""
archives=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --build-run) run="${2:?--build-run needs a run id}"; shift 2 ;;
        --commit) commit="${2:?--commit needs a commit}"; shift 2 ;;
        --no-stage) stage=0; shift ;;
        --archive) archives+=("${2:?--archive needs a file}"); shift 2 ;;
        --remove-staging) remove="${2:?--remove-staging needs a release name}"; shift 2 ;;
        *) echo "sign-macos-release: unknown argument $1" >&2; exit 2 ;;
    esac
done

if [ "$(uname -s)" != Darwin ]; then
    echo "sign-macos-release: signing and notarising are done on macOS" >&2
    exit 1
fi

staging_tag() { printf 'host-staging/v%s' "$1"; }

# Whether `gh api <path>` finds something: 0 when it does, 1 on a 404, and the script stops on any
# other answer, since an error is not the same as nothing being there.
exists() {
    local answer
    if answer="$(gh api "$1" 2>&1)"; then
        return 0
    fi
    case "$answer" in
        *"HTTP 404"*) return 1 ;;
        *) echo "sign-macos-release: asking GitHub about $1 failed: $answer" >&2; exit 1 ;;
    esac
}

# The staging draft of a release, as "<id> <draft>" lines.
staging_of() {
    gh api "repos/$repo/releases" --paginate \
        --jq ".[] | select(.tag_name == \"$(staging_tag "$1")\") | \"\(.id) draft=\(.draft)\""
}

if [ -n "$remove" ]; then
    found="$(staging_of "$remove")"
    case "$found" in
        '') echo "sign-macos-release: no staging draft for $remove" ;;
        *draft=false*) echo "sign-macos-release: $(staging_tag "$remove") is published, and a published release is never removed" >&2; exit 1 ;;
        *)
            gh api --method DELETE "repos/$repo/releases/${found%% *}" --silent
            echo "sign-macos-release: removed the staging draft of $remove"
            ;;
    esac
    exit 0
fi

if [ -n "$run" ] && [ "${#archives[@]}" -gt 0 ]; then
    echo "sign-macos-release: give --build-run or --archive, not both" >&2
    exit 2
fi
if [ -z "$run" ] && [ "${#archives[@]}" -eq 0 ]; then
    echo "sign-macos-release: give --build-run and --commit, or --archive" >&2
    exit 2
fi
if [ -n "$run" ] && [ -z "$commit" ]; then
    echo "sign-macos-release: --build-run needs --commit" >&2
    exit 2
fi
if [ -n "$commit" ] && ! printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$'; then
    echo "sign-macos-release: --commit is a full commit hash" >&2
    exit 2
fi
if [ "${#archives[@]}" -gt 0 ]; then
    stage=0
fi

# ---- the Apple files ----------------------------------------------------------------------------

mode_of() { stat -f %Lp "$1"; }

for file in developer-id-application.key developer-id-application.pem DeveloperIDG2CA.cer asc-api-key.json; do
    if [ ! -f "$apple/$file" ]; then
        echo "sign-macos-release: $apple/$file is missing" >&2
        exit 1
    fi
    if [ "$(mode_of "$apple/$file")" != 600 ]; then
        echo "sign-macos-release: $apple/$file must be mode 0600" >&2
        exit 1
    fi
done

notary="$(python3 -I - "$apple/asc-api-key.json" "$apple" "$team" << 'PYTHON'
import json
import os
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
apple, team = sys.argv[2], sys.argv[3]
if document.get("team_id") != team:
    sys.exit(f"the notary key's team is not {team}")
key_file = document["key_file"]
if not os.path.isabs(key_file):
    key_file = os.path.join(apple, key_file)
for name in ("key_id", "issuer_id"):
    if not document.get(name):
        sys.exit(f"asc-api-key.json has no {name}")
print(key_file)
PYTHON
)"
if [ ! -f "$notary" ] || [ "$(mode_of "$notary")" != 600 ]; then
    echo "sign-macos-release: the notary key must be a file of mode 0600" >&2
    exit 1
fi
notary_id="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["key_id"])' "$apple/asc-api-key.json")"
notary_issuer="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["issuer_id"])' "$apple/asc-api-key.json")"

subject="$(openssl x509 -in "$apple/developer-id-application.pem" -noout -subject)"
case "$subject" in
    *"CN=Developer ID Application: "*"($team)"*"OU=$team"*) ;;
    *) echo "sign-macos-release: the certificate is not a Developer ID Application of the team $team" >&2; exit 1 ;;
esac
if ! openssl x509 -in "$apple/developer-id-application.pem" -noout -checkend $((30 * 86400)) > /dev/null; then
    echo "sign-macos-release: the certificate expires within 30 days, or has expired" >&2
    exit 1
fi
if [ "$(openssl x509 -in "$apple/developer-id-application.pem" -noout -pubkey)" != "$(openssl pkey -in "$apple/developer-id-application.key" -pubout)" ]; then
    echo "sign-macos-release: the private key is not the certificate's" >&2
    exit 1
fi
export KR_SIGN_KEY="$apple/developer-id-application.key"
export KR_SIGN_CERT="$apple/developer-id-application.pem"
export KR_SIGN_CHAIN="$apple/DeveloperIDG2CA.cer"

# ---- the unsigned trees ---------------------------------------------------------------------------

work=""
staged_release=""
staged_id=""
cleanup() {
    local status=$?
    if [ "$status" -ne 0 ] && [ -n "$staged_id" ]; then
        gh api --method DELETE "repos/$repo/releases/$staged_id" --silent 2> /dev/null \
            && echo "sign-macos-release: removed the staging draft this run made" >&2
    fi
}
trap cleanup EXIT

top_of() { basename "$1"; }

sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }

manifest_fact() { # <release.json> <member>
    python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["signed"][sys.argv[2]])' "$1" "$2"
}

trees=()
if [ -n "$run" ]; then
    facts="$(gh api "repos/$repo/actions/runs/$run" --jq '"\(.path) \(.conclusion) \(.head_sha) \(.head_branch)"')"
    wanted=".github/workflows/release-tree.yml success $commit"
    if [ "$stage" -eq 1 ]; then
        wanted="$wanted main"
    fi
    case "$facts" in
        "$wanted"*) ;;
        *) echo "sign-macos-release: run $run is not a successful release-tree run at $commit$([ "$stage" -eq 1 ] && echo ' on main'): $facts" >&2; exit 1 ;;
    esac
    gh api "repos/$repo/actions/runs/$run/artifacts" --paginate \
        --jq '.artifacts[] | "\(.id) \(.name) \(.expired) \(.digest)"' > "${TMPDIR:-/tmp}/kr-artifacts.$$"
fi

stamp="$(date +%Y%m%d-%H%M%S)"
work="$work_root/$stamp"
mkdir -p "$work"
chmod 700 "$work_root" "$work"

if [ -n "$run" ]; then
    for target in "${targets[@]}"; do
        line="$(awk -v t="unsigned-kalareach-$target-" 'index($2, t) == 1' "${TMPDIR:-/tmp}/kr-artifacts.$$")"
        if [ "$(printf '%s\n' "$line" | grep -c .)" -ne 1 ]; then
            echo "sign-macos-release: run $run holds not exactly one unsigned tree for $target" >&2
            exit 1
        fi
        read -r id name expired digest <<< "$line"
        if [ "$expired" != false ]; then
            echo "sign-macos-release: the artefact $name has expired" >&2
            exit 1
        fi
        gh api "repos/$repo/actions/artifacts/$id/zip" > "$work/$target.zip"
        if [ "sha256:$(sha256_of "$work/$target.zip")" != "$digest" ]; then
            echo "sign-macos-release: the artefact $name is not the one GitHub holds the digest of" >&2
            exit 1
        fi
        mkdir -p "$work/$target"
        unzip -q "$work/$target.zip" -d "$work/$target"
        rm -f "$work/$target.zip"
        tar_file="$(find "$work/$target" -maxdepth 1 -name 'kalareach-*.tar' | head -1)"
        if [ "$(cat "$tar_file.sha256" | cut -d' ' -f1)" != "$(sha256_of "$tar_file")" ]; then
            echo "sign-macos-release: $(basename "$tar_file") does not match the sum beside it" >&2
            exit 1
        fi
        tar -xf "$tar_file" -C "$work/$target"
        rm -f "$tar_file" "$tar_file.sha256"
        tree="$(find "$work/$target" -mindepth 1 -maxdepth 1 -type d -name 'kalareach-*' | head -1)"
        if [ "$(manifest_fact "$tree/release.json" commit)" != "$commit" ] || [ "$(manifest_fact "$tree/release.json" target)" != "$target" ]; then
            echo "sign-macos-release: the tree for $target does not name commit $commit and that target" >&2
            exit 1
        fi
        trees+=("$tree")
    done
    rm -f "${TMPDIR:-/tmp}/kr-artifacts.$$"
else
    index=0
    for archive in "${archives[@]}"; do
        index=$((index + 1))
        mkdir -p "$work/archive-$index"
        tar -xzf "$archive" -C "$work/archive-$index"
        trees+=("$(find "$work/archive-$index" -mindepth 1 -maxdepth 1 -type d -name 'kalareach-*' | head -1)")
    done
fi

release=""
for tree in "${trees[@]}"; do
    this="$(manifest_fact "$tree/release.json" release)"
    if [ -n "$release" ] && [ "$release" != "$this" ]; then
        echo "sign-macos-release: the trees are of two releases, $release and $this" >&2
        exit 1
    fi
    release="$this"
done

if [ "$stage" -eq 1 ]; then
    existing="$(staging_of "$release")"
    if [ -n "$existing" ]; then
        echo "sign-macos-release: $(staging_tag "$release") is already staged ($existing)." >&2
        echo "A staging draft that an earlier run left is removed with:" >&2
        echo "    scripts/sign-macos-release.sh --remove-staging $release" >&2
        exit 1
    fi
    if exists "repos/$repo/releases/tags/host/v$release" || exists "repos/$repo/git/ref/tags/host/v$release"; then
        echo "sign-macos-release: host/v$release already has a release or a tag" >&2
        exit 1
    fi
fi

# ---- sign, notarise, pack -------------------------------------------------------------------------

out="$work/staged"
mkdir -p "$out"
: > "$out/STAGED-SHA256SUMS"
: > "$out/STAGED-NOTARY.txt"
for tree in "${trees[@]}"; do
    top="$(top_of "$tree")"
    echo "sign-macos-release: signing $top"
    bash "$here/sign-macos-tree.sh" "$tree" developer-id
    bash "$here/check-macos-signatures.sh" "$tree" developer-id

    zip="$work/$top.zip"
    ditto -c -k --keepParent "$tree" "$zip"
    echo "sign-macos-release: submitting $top to the notary service"
    submitted="$work/$top.submit.json"
    set +e
    xcrun notarytool submit "$zip" --key "$notary" --key-id "$notary_id" --issuer "$notary_issuer" \
        --output-format json > "$submitted" 2> "$work/$top.submit.err"
    set -e
    id="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("id", ""))' "$submitted" 2> /dev/null || true)"
    if [ -z "$id" ]; then
        echo "sign-macos-release: the notary service did not accept the submission of $top:" >&2
        cat "$work/$top.submit.err" >&2
        exit 1
    fi
    echo "sign-macos-release: the notary submission of $top is $id; resume it with: xcrun notarytool wait $id --key <the notary key> --key-id <its id> --issuer <its issuer>"
    set +e
    xcrun notarytool wait "$id" --key "$notary" --key-id "$notary_id" --issuer "$notary_issuer" \
        --output-format json --timeout 60m > "$work/$top.wait.json" 2> "$work/$top.wait.err"
    set -e
    status="$(xcrun notarytool info "$id" --key "$notary" --key-id "$notary_id" --issuer "$notary_issuer" --output-format json 2> /dev/null \
        | python3 -I -c 'import json, sys; print(json.load(sys.stdin).get("status", ""))' 2> /dev/null || true)"
    xcrun notarytool log "$id" "$work/$top.notary-log.json" --key "$notary" --key-id "$notary_id" --issuer "$notary_issuer" > /dev/null 2>&1 || true
    if [ "$status" != Accepted ]; then
        echo "sign-macos-release: the submission $id of $top is ${status:-of unknown status}, not Accepted." >&2
        echo "Its log, if the service has one yet, is $work/$top.notary-log.json." >&2
        exit 1
    fi
    rm -f "$zip"
    printf '%s %s %s\n' "$top" "$id" "$status" >> "$out/STAGED-NOTARY.txt"

    # The service holds the ticket as soon as it says Accepted; the system's assessment can lag it.
    attempt=1
    until bash "$here/check-macos-signatures.sh" "$tree" notarized; do
        if [ "$attempt" -ge 10 ]; then
            echo "sign-macos-release: $top is not accepted as a Notarized Developer ID after $attempt tries" >&2
            exit 1
        fi
        attempt=$((attempt + 1))
        sleep 30
    done

    COPYFILE_DISABLE=1 tar --no-xattrs -C "$(dirname "$tree")" -cf "$out/signed-$top.tar" "$top"
    (cd "$out" && shasum -a 256 "signed-$top.tar") >> "$out/STAGED-SHA256SUMS"
done
printf 'run=%s\ncommit=%s\nrelease=%s\n' "${run:-none}" "${commit:-none}" "$release" > "$out/STAGED-RUN.txt"
(cd "$out" && shasum -a 256 STAGED-NOTARY.txt STAGED-RUN.txt) >> "$out/STAGED-SHA256SUMS"
sums_digest="$(sha256_of "$out/STAGED-SHA256SUMS")"
echo "sign-macos-release: signed and notarised $release; STAGED-SHA256SUMS sha256 $sums_digest"
cat "$out/STAGED-SHA256SUMS"

if [ "$stage" -eq 0 ]; then
    echo "sign-macos-release: nothing is staged; the signed trees and logs are under $work"
    exit 0
fi

# ---- staging ----------------------------------------------------------------------------------------

notes="$work/staging-notes.md"
{
    echo "Files left for the workflow that seals host release $release, from commit $commit."
    echo "This is not a release: it is deleted when the release is published."
} > "$notes"
created="$(gh api --method POST "repos/$repo/releases" \
    --raw-field "tag_name=$(staging_tag "$release")" \
    --raw-field "target_commitish=$commit" \
    --raw-field "name=Staging for host $release" \
    --field draft=true --field prerelease=true \
    --field "body=@$notes" \
    --jq '"\(.id) \(.upload_url)"')"
staged_id="${created%% *}"
upload="${created#* }"
upload="${upload%%\{*}"
case "$staged_id" in '' | *[!0-9]*) echo "sign-macos-release: creating the staging draft did not name one release: $created" >&2; staged_id=""; exit 1 ;; esac

for file in "$out"/signed-*.tar "$out/STAGED-SHA256SUMS" "$out/STAGED-NOTARY.txt" "$out/STAGED-RUN.txt"; do
    attempt=1
    until gh api --method POST "$upload" --raw-field "name=$(basename "$file")" \
        --header 'Content-Type: application/octet-stream' --input "$file" --silent; do
        if [ "$attempt" -ge 3 ]; then
            echo "sign-macos-release: uploading $(basename "$file") failed" >&2
            exit 1
        fi
        attempt=$((attempt + 1))
        sleep 5
    done
done

for file in "$out"/signed-*.tar "$out/STAGED-SHA256SUMS" "$out/STAGED-NOTARY.txt" "$out/STAGED-RUN.txt"; do
    printf '%s %s sha256:%s\n' "$(basename "$file")" "$(wc -c < "$file" | tr -d ' ')" "$(sha256_of "$file")"
done | sort > "$work/packed-assets"
attempt=1
while :; do
    if gh api "repos/$repo/releases/$staged_id" --jq '.assets[] | "\(.name) \(.size) \(.digest)"' | sort > "$work/stored-assets" \
        && cmp -s "$work/packed-assets" "$work/stored-assets"; then
        break
    fi
    if [ "$attempt" -ge 5 ]; then
        echo "sign-macos-release: the staging draft holds something other than what was packed:" >&2
        diff "$work/packed-assets" "$work/stored-assets" >&2 || true
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 3
done

staged_release="$release"
staged_id_kept="$staged_id"
staged_id=""
echo "sign-macos-release: staged $(staging_tag "$staged_release") (release $staged_id_kept) with:"
cat "$work/packed-assets"
echo
echo "Seal it with the user's approval at the update-signing environment:"
echo "    gh workflow run release-host.yml --repo $repo --ref main -f commit=$commit -f build_run=$run -f staged_sums_sha256=$sums_digest"
