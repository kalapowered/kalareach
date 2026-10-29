#!/usr/bin/env bash
# Publishes a host release: a pre-release of the four archives and their sums, made as a draft,
# held to what was packed, published, and then held to what it serves.
#
#   scripts/publish-host-release.sh --repo <owner/name> --release <name> --commit <sha> \
#       --archives <dir> --verified <dir> --root <root.json>
#   scripts/publish-host-release.sh self-test
#
# <dir of archives> holds the four archives `kalareach-<target>-<release>.tar.gz`, one for each of
# the macOS and Linux targets, and <dir of verified> holds `verified-<archive>.sha256` for each,
# the sum the check that installed that archive on its own platform recorded. An archive whose
# digest differs from the sum its check recorded is never uploaded.
#
# The release is the tag `host/v<release>`, made by publishing the draft at <sha>, so the tag names
# the commit that was built. The shape is the one the package releases settled: refuse before
# creating anything (including when nothing shows that the repository makes releases immutable), assemble
# as a draft, hold the stored assets and the bytes the draft serves to what was packed before publishing,
# and confirm afterwards that the tag resolves to this release at this commit and that nobody can
# replace what it serves. A failure before publication leaves a draft; a failure of the last
# confirmation leaves a published release, which is never deleted. The release is a pre-release and is never marked the latest,
# so the package release stays what the repository's page shows first. A draft the macOS signing
# staged under `host-staging/v<release>` is deleted once the release is published. A published
# release is never changed except in its notes, and a mistake is corrected by a release of a new
# commit under its own tag.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
targets=(aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu)

fail() {
    echo "publish-host-release: $1" >&2
    exit 1
}

scratch="$(mktemp -d "${TMPDIR:-/tmp}/kr-publish.XXXXXX")"
trap 'rm -rf "${scratch:?}"' EXIT

# Whether `gh api <path>` finds something: 0 when it does, 1 on a 404, and the script stops on any
# other answer, since an error is not the same as nothing being there.
exists() {
    local answer
    if answer="$(gh api "$1" 2>&1)"; then
        return 0
    fi
    case "$answer" in
        *"HTTP 404"* | *"Not Found"*) return 1 ;;
        *) fail "asking GitHub about $1 failed: $answer" ;;
    esac
}

publish() {
    local repo="" release="" commit="" archives="" verified="" root=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --repo) repo="${2:?}"; shift 2 ;;
            --release) release="${2:?}"; shift 2 ;;
            --commit) commit="${2:?}"; shift 2 ;;
            --archives) archives="${2:?}"; shift 2 ;;
            --verified) verified="${2:?}"; shift 2 ;;
            --root) root="${2:?}"; shift 2 ;;
            *) fail "unknown argument $1" ;;
        esac
    done
    for need in repo release commit archives verified root; do
        [ -n "${!need}" ] || fail "--$need is needed"
    done
    printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$' || fail "--commit is a full commit hash"
    printf '%s' "$release" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\+[0-9a-f]{12}$' || fail "$release is not a release name"
    [ "${commit:0:12}" = "${release#*+}" ] || fail "the release $release does not name the commit $commit"

    local tag="host/v$release" staging="host-staging/v$release" work="$scratch/publish"
    rm -rf "${work:?}"
    mkdir -p "$work"

    # The four archives, each at the digest its check recorded.
    local target archive name want have
    : > "$work/packed-sums"
    for target in "${targets[@]}"; do
        name="kalareach-$target-$release.tar.gz"
        archive="$archives/$name"
        [ -f "$archive" ] || fail "$name is missing from $archives"
        [ -f "$verified/verified-$name.sha256" ] || fail "the check of $name recorded no sum"
        want="$(cut -d' ' -f1 < "$verified/verified-$name.sha256")"
        have="$(shasum -a 256 "$archive" | cut -d' ' -f1)"
        [ "$want" = "$have" ] || fail "$name has the digest $have, and the check recorded $want"
        printf '%s  %s\n' "$have" "$name" >> "$work/packed-sums"
    done
    [ "$(find "$archives" -maxdepth 1 -type f | wc -l | tr -d ' ')" -eq 4 ] || fail "$archives holds something besides the four archives"
    LC_ALL=C sort -k2 "$work/packed-sums" > "$work/SHA256SUMS"
    # The sums are held to what their checkers read: line feeds only, and every archive at its digest.
    mkdir -p "$work/sumcheck"
    cp "$work/SHA256SUMS" "$work/sumcheck/SHA256SUMS"
    for target in "${targets[@]}"; do ln -s "$archives/kalareach-$target-$release.tar.gz" "$work/sumcheck/"; done
    bash "$here/check-release-sums.sh" "$work/sumcheck" > /dev/null || fail "the sums are not what their checkers read"

    # One tag is one release, and a release is never assembled twice. The listing is read once: it
    # names the release of this tag when there is one, and the newest published release when nothing
    # can read the repository's setting. The token sees drafts too, and the staging draft is the
    # newest release at this point, so a draft is never taken for evidence.
    local existing listing="$work/releases.json" newest
    gh api "repos/$repo/releases" --paginate > "$listing" || fail "GitHub did not list the releases of $repo"
    existing="$(python3 -I -c '
import json, sys
text = open(sys.argv[2], encoding="utf-8").read()
decoder = json.JSONDecoder()
index = 0
while index < len(text):
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        break
    page, index = decoder.raw_decode(text, index)
    for release in page:
        if release["tag_name"] == sys.argv[1]:
            print(release["id"], "draft=" + str(release["draft"]).lower())
' "$tag" "$listing")"
    if [ -n "$existing" ]; then
        echo "$tag already has a release: $existing" >&2
        echo 'A draft left by a run that failed: delete the draft and run this again. A published release:' >&2
        echo 'leave it where it is and release the corrected commit under its own tag.' >&2
        exit 1
    fi
    if exists "repos/$repo/git/ref/tags/$tag"; then
        fail "$tag is already a tag of this repository"
    fi
    # A release published where releases are not immutable has assets that can be replaced, which
    # cannot be undone, so nothing is made unless something shows they are immutable. The setting
    # itself needs a token that can administer the repository, which a workflow's token never is:
    # when the token can read it, it has to say enabled. When it cannot, the most recently published
    # release of the repository has to report itself immutable, which a release published while the
    # setting is off does not. That shows the setting as it was at that release, so whoever
    # dispatches the release reads the setting with their own login first.
    local setting
    setting="$(gh api "repos/$repo/immutable-releases" 2> /dev/null | python3 -I -c 'import json, sys; print(json.load(sys.stdin).get("enabled"))' 2> /dev/null || true)"
    case "$setting" in
        True) ;;
        False) fail "this repository does not make releases immutable, so nothing is published" ;;
        *)
            newest="$(python3 -I -c '
import json, sys
text = open(sys.argv[1], encoding="utf-8").read()
decoder = json.JSONDecoder()
index = 0
published = []
while index < len(text):
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        break
    page, index = decoder.raw_decode(text, index)
    published += [r for r in page if not r["draft"] and r.get("published_at")]
newest = max(published, key=lambda r: r["published_at"]) if published else None
print(str(newest["immutable"]).lower() if newest else "none")' "$listing" 2> /dev/null || true)"
            [ "$newest" = true ] || fail "nothing shows that this repository makes releases immutable (the setting cannot be read, and the most recently published release answers '${newest:-nothing}'), so nothing is published"
            ;;
    esac

    local key_ids
    key_ids="$(python3 -I -c '
import json, sys
signed = json.load(open(sys.argv[1], encoding="utf-8"))["signed"]
print(", ".join(signed["roles"]["targets"]["keyids"]))
' "$root")"

    # shellcheck disable=SC2016
    {
        echo
        echo "Check an archive after it is downloaded, with the one sum file for all four:"
        echo
        echo '    shasum -a 256 --ignore-missing -c SHA256SUMS'
        echo
        echo 'Unpack it and put the release in this user'"'"'s store of releases:'
        echo
        echo "    tar -xzf kalareach-<target>-$release.tar.gz"
        echo "    kalareach-<target>-$release/bin/kr host install"
        echo
        echo 'A host that has an earlier release takes this one with'
        # shellcheck disable=SC2016
        echo '`kr host update --archive <archive>`. `kr host install` checks the release'"'"'s manifest against'
        echo 'the update channel root the release carries, and `kr host update` against the root the host'
        echo "already trusts. The targets key identifiers of that root are: $key_ids."
        echo
        echo 'SHA256SUMS:'
        echo
        sed 's/^/    /' "$work/SHA256SUMS"
        echo
        echo 'Every program in the macOS archives is signed by Kala Holdings Inc. (team L775WGST9V) and'
        echo 'notarised by Apple. The Linux archives carry no platform signature; their manifest,'
        echo 'release.json, is signed by the update channel as the macOS ones are.'
    } > "$work/notes-tail.md"
    {
        echo "The KalaReach host $release for macOS and Linux, built from commit $commit."
        cat "$work/notes-tail.md"
    } > "$work/notes-draft.md"

    local created id upload
    created="$(gh api --method POST "repos/$repo/releases" \
        --raw-field "tag_name=$tag" --raw-field "target_commitish=$commit" \
        --raw-field "name=Host $release for macOS and Linux" \
        --field draft=true --field prerelease=true --raw-field make_latest=false \
        --field "body=@$work/notes-draft.md" | python3 -I -c 'import json, sys; d = json.load(sys.stdin); print(d["id"], d["upload_url"])')"
    id="${created%% *}"
    upload="${created#* }"
    upload="${upload%%\{*}"
    case "$id" in '' | *[!0-9]*) fail "creating the draft did not name one release: $created" ;; esac

    local file attempt
    for file in "$archives"/*.tar.gz "$work/SHA256SUMS"; do
        attempt=1
        until gh api --method POST "$upload" --raw-field "name=$(basename "$file")" \
            --header 'Content-Type: application/octet-stream' --input "$file" --silent; do
            [ "$attempt" -lt 3 ] || fail "uploading $(basename "$file") to draft release $id failed; delete the draft and run this again"
            attempt=$((attempt + 1))
            sleep 5
        done
    done

    # The asset set is held to what was packed while nothing can install it: every archive and the
    # sums, at their lengths, with the sha256 GitHub computed over the bytes it stored.
    for file in "$archives"/*.tar.gz "$work/SHA256SUMS"; do
        printf '%s %s sha256:%s\n' "$(basename "$file")" "$(wc -c < "$file" | tr -d ' ')" "$(shasum -a 256 "$file" | cut -d' ' -f1)"
    done | sort > "$work/packed-assets"
    attempt=1
    while :; do
        if gh api "repos/$repo/releases/$id" | python3 -I -c '
import json, sys
for asset in json.load(sys.stdin)["assets"]:
    print(asset["name"], asset["size"], asset["digest"])
' | sort > "$work/stored-assets" && cmp -s "$work/packed-assets" "$work/stored-assets"; then
            break
        fi
        if [ "$attempt" -ge 5 ]; then
            echo "The release holds something other than what was packed; it stays a draft." >&2
            diff "$work/packed-assets" "$work/stored-assets" >&2 || true
            exit 1
        fi
        attempt=$((attempt + 1))
        sleep 3
    done

    # The bytes the draft serves, by the identifier of each asset, are the bytes that were packed.
    mkdir -p "$work/served"
    gh api "repos/$repo/releases/$id" | python3 -I -c '
import json, sys
for asset in json.load(sys.stdin)["assets"]:
    print(asset["id"], asset["name"])
' > "$work/draft-assets"
    local asset_id asset_name
    while read -r asset_id asset_name; do
        gh api "repos/$repo/releases/assets/$asset_id" --header 'Accept: application/octet-stream' > "$work/served/$asset_name"
        case "$asset_name" in
            SHA256SUMS) cmp -s "$work/SHA256SUMS" "$work/served/$asset_name" || fail "the draft serves other sums than were packed" ;;
            *) cmp -s "$archives/$asset_name" "$work/served/$asset_name" || fail "the draft serves other bytes than were packed for $asset_name" ;;
        esac
    done < "$work/draft-assets"

    gh api --method PATCH "repos/$repo/releases/$id" -F draft=false --silent

    # What a tester pins is a URL and a digest, so the release behind them has to be one nobody can
    # point somewhere else, at the commit that was built.
    attempt=1
    local published tagged
    while :; do
        published="$(gh api "repos/$repo/releases/tags/$tag" 2> /dev/null | python3 -I -c 'import json, sys; d = json.load(sys.stdin); print(d["id"], str(d["immutable"]).lower(), str(d["prerelease"]).lower())' 2> /dev/null || true)"
        tagged="$(gh api "repos/$repo/git/ref/tags/$tag" 2> /dev/null | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["object"]["sha"])' 2> /dev/null || true)"
        [ "$published" = "$id true true" ] && [ "$tagged" = "$commit" ] && break
        if [ "$attempt" -ge 5 ]; then
            echo "$tag was published, and it is not the immutable pre-release of $id at $commit: it answers '$published' and the tag is at '$tagged'." >&2
            echo "Turn on immutable releases for this repository if it answers false, and release the next commit." >&2
            exit 1
        fi
        attempt=$((attempt + 1))
        sleep 3
    done

    # The public release holds what the draft held when it was checked.
    gh api "repos/$repo/releases/$id" | python3 -I -c '
import json, sys
for asset in json.load(sys.stdin)["assets"]:
    print(asset["name"], asset["size"], asset["digest"])
' | sort > "$work/public-assets"
    cmp -s "$work/packed-assets" "$work/public-assets" || fail "the published release holds other assets than were checked"

    # Where each asset is served, for the notes.
    gh api "repos/$repo/releases/$id" | python3 -I -c '
import json, sys
for asset in json.load(sys.stdin)["assets"]:
    print(asset["id"], asset["name"], asset["browser_download_url"])
' > "$work/served-assets"
    local asset_url

    {
        echo "The KalaReach host $release for macOS and Linux, built from commit $commit."
        echo
        while read -r asset_id asset_name asset_url; do
            case "$asset_name" in *.tar.gz) echo "- $asset_url" ;; esac
        done < "$work/served-assets"
        cat "$work/notes-tail.md"
    } > "$work/notes.md"
    attempt=1
    until gh api --method PATCH "repos/$repo/releases/$id" --field "body=@$work/notes.md" --silent; do
        if [ "$attempt" -ge 5 ]; then
            echo "Writing the served URLs into the notes of release $id failed; the release itself is published" >&2
            echo "and carries what was packed. Put the URLs into its notes by hand." >&2
            cat "$work/notes.md" >&2
            exit 1
        fi
        attempt=$((attempt + 1))
        sleep 3
    done

    # The draft the macOS signing staged is not part of the release.
    local staged
    staged="$(gh api "repos/$repo/releases" --paginate | python3 -I -c '
import json, sys
text = sys.stdin.read()
decoder = json.JSONDecoder()
index = 0
while index < len(text):
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        break
    page, index = decoder.raw_decode(text, index)
    for release in page:
        if release["tag_name"] == sys.argv[1] and release["draft"]:
            print(release["id"])
' "$staging")"
    if [ -n "$staged" ]; then
        gh api --method DELETE "repos/$repo/releases/$staged" --silent || echo "publish-host-release: the staging draft $staged was not deleted; delete it by hand" >&2
    fi
    echo "publish-host-release: $tag is published at $commit"
}

# ---- the self-test --------------------------------------------------------------------------------
#
# A stand-in for `gh api` that keeps releases in a directory, so that the script is driven against
# the answers it must act on: a control that publishes, and a release or a draft already there, an
# archive that differs from the sum its check recorded, an archive missing, a store that keeps other
# bytes than were uploaded, and a release that can be replaced.

write_stub() {
    local directory="$1"
    cat > "$directory/gh" << 'PYTHON'
#!/usr/bin/env python3
import hashlib
import json
import os
import sys

state_path = os.path.join(os.environ["STUB_STATE"], "state.json")
state = json.load(open(state_path)) if os.path.exists(state_path) else {"releases": [], "next": 1}


def save():
    json.dump(state, open(state_path, "w"))


args = sys.argv[1:]
assert args[0] == "api", args
args = args[1:]
method = "GET"
fields = {}
input_file = None
paths = []
index = 0
while index < len(args):
    arg = args[index]
    if arg == "--method":
        method = args[index + 1]; index += 2
    elif arg in ("--raw-field", "--field", "-F", "-f"):
        key, _, value = args[index + 1].partition("="); fields[key] = value; index += 2
    elif arg == "--input":
        input_file = args[index + 1]; index += 2
    elif arg == "--header":
        index += 2
    else:
        paths.append(arg); index += 1
path = paths[0]
repo = "o/r"


def release_json(release):
    return {
        "id": release["id"], "tag_name": release["tag_name"], "draft": release["draft"],
        "prerelease": release["prerelease"], "immutable": release["immutable"],
        # A draft has a date of its own, later than every published release, so that taking it for the
        # newest release is a mistake a case can see.
        "published_at": "2026-01-01T00:59:00Z" if release["draft"] else f"2026-01-01T00:{release['published']:02d}:00Z",
        "upload_url": f"upload://{release['id']}{{?name,label}}",
        "assets": [{"id": a["id"], "name": a["name"], "size": a["size"], "digest": a["digest"],
                    "browser_download_url": f"https://example.invalid/{a['name']}"} for a in release["assets"]],
    }


def find(identifier):
    return next(r for r in state["releases"] if r["id"] == identifier)


if method == "POST" and path.endswith("/releases"):
    release = {"id": state["next"], "tag_name": fields["tag_name"], "draft": True, "prerelease": fields.get("prerelease") == "true",
               "immutable": os.environ.get("STUB_PUBLISH_MUTABLE") != "1", "assets": [], "target": fields["target_commitish"], "published": 40, "next_asset": 1}
    state["next"] += 1
    state["releases"].append(release)
    save()
    print(json.dumps(release_json(release)))
elif method == "POST" and path.startswith("upload://"):
    release = find(int(path[len("upload://"):]))
    data = open(input_file, "rb").read()
    if os.environ.get("STUB_CORRUPT") == fields["name"]:
        data = data + b"x"
    asset = {"id": release["id"] * 100 + release["next_asset"], "name": fields["name"], "size": len(data),
             "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
             "path": os.path.join(os.environ["STUB_STATE"], f"{release['id']}-{fields['name']}")}
    open(asset["path"], "wb").write(data)
    release["assets"].append(asset)
    release["next_asset"] += 1
    save()
elif method == "GET" and path == f"repos/{repo}/releases":
    # Drafts are listed to a token with push access. The order is the order the releases were made in
    # here, oldest first, which is not the order they were published in (each carries a date of its
    # own), so taking the first or the last of the list is a mistake a case can see. A real answer is
    # paged, so the stand-in gives one page per release to show that every page is read.
    print("\n".join(json.dumps([release_json(r)]) for r in sorted(state["releases"], key=lambda r: r["id"])))
elif method == "GET" and path == f"repos/{repo}/immutable-releases":
    # A token that cannot administer the repository is answered 404; STUB_SETTING stands for one that can.
    if os.environ.get("STUB_SETTING") in ("true", "false"):
        print(json.dumps({"enabled": os.environ["STUB_SETTING"] == "true", "enforced_by_owner": False}))
    else:
        sys.exit("gh: Not Found (HTTP 404)")
elif method == "GET" and path.startswith(f"repos/{repo}/releases/tags/"):
    tag = path[len(f"repos/{repo}/releases/tags/"):]
    matches = [r for r in state["releases"] if r["tag_name"] == tag and not r["draft"]]
    if not matches:
        sys.exit(1)
    print(json.dumps(release_json(matches[0])))
elif method == "GET" and path.startswith(f"repos/{repo}/git/ref/tags/"):
    tag = path[len(f"repos/{repo}/git/ref/tags/"):]
    matches = [r for r in state["releases"] if r["tag_name"] == tag and not r["draft"]]
    if not matches:
        sys.exit("gh: Not Found (HTTP 404)")
    print(json.dumps({"object": {"sha": matches[0]["target"]}}))
elif method == "GET" and path.startswith(f"repos/{repo}/releases/assets/"):
    identifier = int(path.rsplit("/", 1)[1])
    for release in state["releases"]:
        for asset in release["assets"]:
            if asset["id"] == identifier:
                sys.stdout.flush()
                data = open(asset["path"], "rb").read()
                if os.environ.get("STUB_SERVE_OTHER") == asset["name"]:
                    data = data + b"x"
                sys.stdout.buffer.write(data)
                sys.exit(0)
    sys.exit(1)
elif method == "GET" and path.startswith(f"repos/{repo}/releases/"):
    print(json.dumps(release_json(find(int(path.rsplit("/", 1)[1])))))
elif method == "PATCH":
    release = find(int(path.rsplit("/", 1)[1]))
    if fields.get("draft") == "false":
        release["draft"] = False
    save()
elif method == "DELETE":
    identifier = int(path.rsplit("/", 1)[1])
    state["releases"] = [r for r in state["releases"] if r["id"] != identifier]
    save()
else:
    sys.exit(f"the stand-in has no answer for {method} {path}")
PYTHON
    chmod +x "$directory/gh"
}

# What the stand-in holds after a case, asked of its state file.
state_has() { # published | draft | staging
    python3 -I - "$STUB_STATE/state.json" "$1" "$2" << 'PYTHON'
import json
import os
import sys

path, what, tag = sys.argv[1:4]
state = json.load(open(path)) if os.path.exists(path) else {"releases": []}
releases = [r for r in state["releases"] if r["tag_name"] == tag]
sys.exit(0 if any((what == "published" and not r["draft"]) or (what == "draft" and r["draft"]) for r in releases) else 1)
PYTHON
}

# The state every case starts from: one published release of the repository, immutable unless BASE says
# otherwise (mutable, or none), and a copy of it to compare the end state with.
seed_base() {
    python3 -I - "$STUB_STATE" "${BASE:-immutable}" "$commit" << 'PYTHON'
import json
import os
import shutil
import sys

directory, base, commit = sys.argv[1:4]
releases = []
if base != "none":
    releases.append({"id": 1, "tag_name": "packages/v0.0.0+000000000000", "draft": False, "prerelease": False,
                     "immutable": base == "immutable", "published": int(os.environ.get("BASE_PUBLISHED", "10")),
                     "assets": [], "target": commit, "next_asset": 1})
json.dump({"releases": releases, "next": 2}, open(os.path.join(directory, "state.json"), "w"))
shutil.copy(os.path.join(directory, "state.json"), os.path.join(directory, "initial.json"))
PYTHON
}

seed_release() { # <tag> <draft: true|false> [<immutable: true|false> [<published: minute, later is newer>]]: another release, part of the state a case starts from
    python3 -I - "$STUB_STATE" "$1" "$2" "$commit" "${3:-true}" "${4:-30}" << 'PYTHON'
import json
import os
import shutil
import sys

directory, tag, draft, commit, immutable, published = sys.argv[1:7]
path = os.path.join(directory, "state.json")
state = json.load(open(path))
state["releases"].append({"id": state["next"], "tag_name": tag, "draft": draft == "true", "prerelease": True,
                          "immutable": immutable == "true", "published": int(published), "assets": [], "target": commit, "next_asset": 1})
state["next"] += 1
json.dump(state, open(path, "w"))
shutil.copy(path, os.path.join(directory, "initial.json"))
PYTHON
}

go() { publish --repo o/r --release "$release" --commit "$commit" --archives "$work/archives" --verified "$work/verified" --root "$work/root.json"; }

case_control() { go && state_has published "host/v$release" && ! state_has draft "host/v$release"; }
case_published() { seed_release "host/v$release" false; ( go ) && return 1; [ "$(nothing_created)" = yes ]; }
case_draft() { seed_release "host/v$release" true; ( go ) && return 1; [ "$(nothing_created)" = yes ]; }
case_staging_removed() { seed_release "host-staging/v$release" true; go && ! state_has draft "host-staging/v$release"; }
case_corrupt() { ( STUB_CORRUPT=SHA256SUMS go ) && return 1; state_has draft "host/v$release" && ! state_has published "host/v$release"; }
case_serves_other() { ( STUB_SERVE_OTHER="kalareach-${targets[0]}-$release.tar.gz" go ) && return 1; state_has draft "host/v$release" && ! state_has published "host/v$release"; }
case_setting_off() { ( STUB_SETTING=false go ) && return 1; [ "$(nothing_created)" = yes ]; }
case_setting_on() { STUB_SETTING=true go && state_has published "host/v$release"; }
case_published_mutable() { ( STUB_PUBLISH_MUTABLE=1 go ) && return 1; state_has published "host/v$release"; }
case_no_proof() { ( go ) && return 1; [ "$(nothing_created)" = yes ]; }
case_no_proof_beside_draft() { seed_release "host-staging/v$release" true; ( go ) && return 1; [ "$(nothing_created)" = yes ]; }
case_newer_immutable() { seed_release "host/v0.0.1+000000000001" false true; go && state_has published "host/v$release"; }
case_newer_mutable() { seed_release "host/v0.0.1+000000000001" false false; ( go ) && return 1; [ "$(nothing_created)" = yes ]; }
# The release made later in the stand-in is published earlier, so the date decides and not the order of the list.
case_list_last_is_older() { seed_release "host/v0.0.1+000000000001" false true 5; ( go ) && return 1; [ "$(nothing_created)" = yes ]; }
case_list_first_is_older() { seed_release "host/v0.0.1+000000000001" false false 20; ( go ) && return 1; [ "$(nothing_created)" = yes ]; }
case_digest_differs() { ( go ) && return 1; [ "$(nothing_created)" = yes ]; }
case_missing_archive() { ( go ) && return 1; [ "$(nothing_created)" = yes ]; }

# "yes" when the stand-in holds exactly the releases and assets it started the case with.
nothing_created() {
    python3 -I - "$STUB_STATE" << 'PYTHON'
import json
import os
import sys

def shape(path):
    state = json.load(open(path))
    return sorted((r["id"], r["tag_name"], r["draft"], len(r["assets"])) for r in state["releases"])

directory = sys.argv[1]
print("yes" if shape(os.path.join(directory, "state.json")) == shape(os.path.join(directory, "initial.json")) else "no")
PYTHON
}

self_test() {
    failures=0
    release="0.1.0+0123456789ab"
    commit="0123456789abcdef0123456789abcdef01234567"
    work="$scratch/selftest"
    mkdir -p "$work/bin" "$work/archives" "$work/verified"
    write_stub "$work/bin"
    python3 -I -c '
import json
json.dump({"signed": {"roles": {"targets": {"keyids": ["aa", "bb"]}}}}, open("'"$work"'/root.json", "w"))'
    local target name
    for target in "${targets[@]}"; do
        name="kalareach-$target-$release.tar.gz"
        printf 'archive of %s\n' "$target" > "$work/archives/$name"
        printf '%s  %s\n' "$(shasum -a 256 "$work/archives/$name" | cut -d' ' -f1)" "$name" > "$work/verified/verified-$name.sha256"
    done

    run() { # <name> <wanted: pass|refuse> <function>
        local rc=0
        rm -rf "${work:?}/state"
        mkdir -p "$work/state"
        ( export STUB_STATE="$work/state" PATH="$work/bin:$PATH"; seed_base; "$3" ) > "$work/out.txt" 2>&1 || rc=$?
        if { [ "$2" = pass ] && [ "$rc" -ne 0 ]; } || { [ "$2" = refuse ] && [ "$rc" -eq 0 ]; }; then
            echo "self-test FAILED: $1 (exit $rc)"
            sed 's/^/    /' "$work/out.txt"
            failures=$((failures + 1))
        else
            echo "self-test ok: $1"
            [ "${KR_SELFTEST_VERBOSE:-}" != 1 ] || sed 's/^/        /' "$work/out.txt" | tail -4
        fi
    }

    run "the control: four archives at their recorded digests are published as an immutable pre-release at the commit" pass case_control
    run "a staging draft of the release is deleted once it is published" pass case_staging_removed
    run "a published release of the tag is refused, and nothing is created beside it" pass case_published
    run "a draft of the tag is refused, and nothing is created beside it" pass case_draft
    run "a store that keeps other bytes than were uploaded leaves a draft and no release" pass case_corrupt
    run "a repository setting that reads as off is refused before a draft is made" pass case_setting_off
    run "a setting that can be read and is on is enough" pass case_setting_on
    BASE=mutable run "no readable setting and a newest release that is not immutable is refused before a draft is made" pass case_no_proof
    BASE=none run "no readable setting and no published release is refused before a draft is made" pass case_no_proof
    BASE=mutable run "a staging draft is not evidence: the newest published release behind it is what counts, and it is not immutable" pass case_no_proof_beside_draft
    BASE=mutable run "no readable setting and a mutable release followed by an immutable one is enough: the most recent counts" pass case_newer_immutable
    run "no readable setting and an immutable release followed by a mutable one is refused: the most recent counts" pass case_newer_mutable
    BASE=mutable BASE_PUBLISHED=20 run "a mutable release published after an immutable one that the list shows last is refused: the date counts, not the order of the list" pass case_list_last_is_older
    BASE_PUBLISHED=5 run "an immutable release published before a mutable one that the list shows last is refused: the date counts, not the order of the list" pass case_list_first_is_older
    run "a draft that serves other bytes than were packed is not published" pass case_serves_other
    run "a release that turns out to be replaceable after it is published ends the run with an error" pass case_published_mutable

    printf 'changed\n' >> "$work/archives/kalareach-${targets[0]}-$release.tar.gz"
    run "an archive that differs from the sum its check recorded is refused before anything is created" pass case_digest_differs
    printf 'archive of %s\n' "${targets[0]}" > "$work/archives/kalareach-${targets[0]}-$release.tar.gz"
    rm -f "$work/archives/kalareach-${targets[3]}-$release.tar.gz"
    run "a missing archive is refused before anything is created" pass case_missing_archive

    if [ "$failures" -ne 0 ]; then
        echo "publish-host-release: $failures self-test case(s) failed" >&2
        return 1
    fi
    echo "publish-host-release: the self-test passed"
}

if [ "${1:-}" = self-test ]; then
    self_test
    exit $?
fi
publish "$@"
