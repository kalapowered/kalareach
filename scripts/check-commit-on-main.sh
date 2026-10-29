#!/usr/bin/env bash
# Holds a commit to the history of `main`.
#
#   scripts/check-commit-on-main.sh <full commit hash>
#   scripts/check-commit-on-main.sh self-test
#
# The branch is named by its full reference, `refs/remotes/origin/main`, which `origin` fetches into
# here. The short name `origin/main` is looked up among the tags first, and a checkout that fetches
# every tag has one, so a tag that someone with the right to push tags named `origin/main` would stand
# in for the branch.

set -euo pipefail

# A failed fetch is a failure of its own: this runs on the left of `||`, where `set -e` does not
# apply, and the reference that is already there would otherwise decide.
on_main() { # <commit>
    git fetch --quiet origin '+refs/heads/main:refs/remotes/origin/main' || return 2
    git merge-base --is-ancestor "$1" refs/remotes/origin/main
}

self_test() {
    local work status=0
    work="$(mktemp -d "${TMPDIR:-/tmp}/kr-on-main.XXXXXX")"
    trap 'rm -rf "${work:?}"' RETURN
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
    git init -q --bare -b main "$work/origin.git"
    git init -q -b main "$work/seed"
    (
        cd "$work/seed"
        git commit -q --allow-empty -m one
        git commit -q --allow-empty -m two
        git remote add origin "$work/origin.git"
        git push -q origin main
        git switch -q -c side HEAD~1
        git commit -q --allow-empty -m side
        git push -q origin side
    )
    git clone -q "$work/origin.git" "$work/clone"
    (
        cd "$work/clone"
        local main_commit side_commit
        main_commit="$(git rev-parse origin/main)"
        side_commit="$(git rev-parse origin/side)"
        # A tag called origin/main, on a commit that has the side commit in its history.
        git tag origin/main "$side_commit"
        git fetch -q --tags
        if git merge-base --is-ancestor "$side_commit" origin/main 2> /dev/null; then
            echo "self-test ok: the short name origin/main is the tag, so it takes the side commit for one of main's"
        else
            echo "self-test FAILED: the short name did not resolve to the tag, so the case does not show what it should"
            exit 1
        fi
        if on_main "$main_commit"; then
            echo "self-test ok: a commit of main's history is accepted"
        else
            echo "self-test FAILED: a commit of main's history was refused"
            exit 1
        fi
        if on_main "$side_commit"; then
            echo "self-test FAILED: a commit that is not in main's history was accepted"
            exit 1
        fi
        echo "self-test ok: a commit that is not in main's history is refused, with a tag called origin/main in place"
        # The reference the clone already holds says main has the side commit; the fetch that would
        # correct it fails.
        git update-ref refs/remotes/origin/main "$side_commit"
        git remote set-url origin "$work/gone.git"
        if on_main "$side_commit" 2> /dev/null; then
            echo "self-test FAILED: a fetch that failed was ignored, and the reference already held decided"
            exit 1
        fi
        echo "self-test ok: a fetch that fails is a refusal, whatever reference is already held"
    ) || status=1
    [ "$status" -eq 0 ] && echo "check-commit-on-main: the self-test passed"
    return "$status"
}

case "${1:-}" in
    self-test) self_test ;;
    *)
        printf '%s' "${1:-}" | grep -Eq '^[0-9a-f]{40}$' || { echo "check-commit-on-main: name the commit in full" >&2; exit 2; }
        on_main "$1" && exit 0
        code=$?
        if [ "$code" -eq 2 ]; then echo "::error::main could not be fetched, so $1 is not held to it" >&2; else echo "::error::$1 is not on main" >&2; fi
        exit 1
        ;;
esac
