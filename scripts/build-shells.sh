#!/usr/bin/env bash
# Builds the managed shell packages from pinned upstream releases and the reader patch sets in
# shells/.
#
#   scripts/build-shells.sh --zsh --bash     build both
#   scripts/build-shells.sh --zsh            build one
#   scripts/build-shells.sh --zsh --bash --check-patches
#                                            apply the patches to a scratch tree and stop
#
# Upstream is never vendored. Each package's manifest pins one release tarball by URL and SHA-256;
# this script fetches it, verifies the digest, applies the ordered patches in shells/<shell>/patches
# and copies the bridge sources from shells/<shell>/src into the tree.
#
# The identity is a digest of the inputs: the upstream archive, this script, the manifest with the
# flags it pins, every patch, every added source, the startup entry and the compiler. The same inputs give the same identity, so a rebuild
# lands in the same place and reports that nothing changed. The identity record written beside the
# binary is what the package declares in its handshake.
#
# Built binaries live outside the repository, under the platform's cache directory, because a
# process started from a service manager that opens a path on a removable volume makes the
# operating system ask the person for permission first.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

build_zsh=0
build_bash=0
build_fish=0
force=0
run_upstream_tests=1
require_upstream_tests=0
check_patches_only=0
jobs="${KR_SHELL_BUILD_JOBS:-4}"
# A shell's own test suite is worth running and is not worth waiting on for ever: some of these
# suites drive a terminal and can stall on a loaded machine. The outcome is recorded either way.
test_timeout="${KR_SHELL_TEST_TIMEOUT:-900}"

if [ "$(uname -s)" = "Darwin" ]; then
    default_prefix="$HOME/Library/Caches/kalareach/shells"
else
    default_prefix="${XDG_CACHE_HOME:-$HOME/.cache}/kalareach/shells"
fi
prefix="${KR_SHELL_PREFIX:-$default_prefix}"

usage() {
    cat >&2 <<'USAGE'
usage: build-shells.sh [--zsh] [--bash] [--fish] [--all] [options]

  --zsh, --bash, --fish, --all   which packages to build
  --force                rebuild even when the identity is already installed
  --no-upstream-tests    skip the shell's own test suite
  --require-upstream-tests  fail the build unless the shell's own test suite passes
  --check-patches        apply the patches to a scratch tree, report, and stop
  --jobs N               parallel compilation jobs (default 4)
  --test-timeout N       seconds to allow the shell's own test suite (default 900)
  --prefix DIR           where packages are installed (default: the platform cache directory)
USAGE
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --zsh) build_zsh=1 ;;
        --bash) build_bash=1 ;;
        --fish) build_fish=1 ;;
        --all) build_zsh=1; build_bash=1; build_fish=1 ;;
        --force) force=1 ;;
        --no-upstream-tests) run_upstream_tests=0 ;;
        --require-upstream-tests) require_upstream_tests=1 ;;
        --check-patches) check_patches_only=1 ;;
        --jobs) shift; jobs="${1:-4}" ;;
        --test-timeout) shift; test_timeout="${1:-900}" ;;
        --prefix) shift; prefix="${1:?--prefix needs a directory}" ;;
        -h|--help) usage ;;
        *) echo "build-shells: unknown argument $1" >&2; usage ;;
    esac
    shift
done

if [ "$build_zsh" -eq 0 ] && [ "$build_bash" -eq 0 ] && [ "$build_fish" -eq 0 ]; then
    echo "build-shells: name at least one package" >&2
    usage
fi

needed="curl make patch tar python3"
if [ "$build_fish" -eq 1 ]; then
    # The fish package is a Rust shell built through CMake, so it needs both.
    needed="$needed cmake cargo rustc"
fi
for tool in $needed; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "build-shells: $tool is needed and is not installed" >&2
        exit 1
    fi
done

digest() {
    # One digest command, whichever the platform ships.
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

digest_string() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | cut -d' ' -f1
    else
        printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
    fi
}

# Reads one manifest and prints shell assignments for it.
manifest_env() {
    python3 - "$1" <<'PYTHON'
import json
import shlex
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)

def put(name, value):
    print("%s=%s" % (name, shlex.quote(str(value))))

put("m_shell", manifest["shell"])
put("m_build_system", manifest.get("build_system", "autotools"))
put("m_environment", " ".join("%s=%s" % item
                              for item in sorted(manifest.get("environment", {}).items())))
put("m_integration_version", manifest["integration_version"])
put("m_editor_abi", manifest["editor_abi"])
put("m_mailbox", manifest["mailbox_mechanism"])
put("m_pre_eof", manifest["pre_eof_mechanism"])
put("m_upstream_version", manifest["upstream"]["version"])
put("m_archive", manifest["upstream"]["archive"])
put("m_url", manifest["upstream"]["url"])
put("m_sha256", manifest["upstream"]["sha256"])
put("m_directory", manifest["upstream"]["directory"])
put("m_revision", manifest["upstream"]["revision"])
put("m_binary", manifest["binary"])
put("m_module_directory", manifest["module_directory"])
put("m_source_directory", manifest["source_directory"])
put("m_test_command", manifest["upstream_tests"]["command"])
put("m_test_reason", manifest["upstream_tests"].get("reason", ""))
put("m_configure", " ".join(manifest["configure"]))
put("m_cflags", " ".join(manifest["cflags"]))
put("m_patches", " ".join(patch["file"] for patch in manifest["patches"]))
put("m_patch_names", " ".join(patch["name"] for patch in manifest["patches"]))
put("m_patch_revisions", " ".join(patch["revision"] for patch in manifest["patches"]))
put("m_sources", " ".join("%s:%s" % (source["file"], source["install"])
                          for source in manifest["sources"]))
put("m_modules", " ".join(module for module in manifest["modules"]))
put("m_startup", manifest["startup"]["file"])
PYTHON
}

# Writes the identity header the bridge is compiled with.
write_identity_header() {
    local destination="$1"
    local package="$2"
    python3 - "$package/manifest.json" "$destination" "$3" "$4" <<'PYTHON'
import json
import sys

manifest_path, destination, executable, module_directory = sys.argv[1:5]
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)

patches = manifest["patches"]
modules = manifest["modules"]

def quote(text):
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"')

lines = [
    "/* Generated by scripts/build-shells.sh from %s. Do not edit. */" % manifest_path.split("/")[-2:][0],
    "#ifndef KR_BRIDGE_IDENTITY_H",
    "#define KR_BRIDGE_IDENTITY_H",
    "",
    "#define KR_SHELL_KIND %s" % quote(manifest["shell"]),
    "#define KR_SHELL_EXECUTABLE %s" % quote(executable),
    "#define KR_UPSTREAM_VERSION %s" % quote(manifest["upstream"]["version"]),
    "#define KR_EDITOR_ABI %s" % quote(manifest["editor_abi"]),
    "#define KR_INTEGRATION_VERSION %s" % quote(manifest["integration_version"]),
    "#define KR_MAILBOX_MECHANISM %s" % quote(manifest["mailbox_mechanism"]),
    "#define KR_PRE_EOF_MECHANISM %s" % quote(manifest["pre_eof_mechanism"]),
    "",
    "typedef struct {",
    "    const char *name;",
    "    const char *upstream_revision;",
    "    const char *revision;",
    "} kr_patch_entry;",
    "",
    "typedef struct {",
    "    const char *name;",
    "    const char *search_path;",
    "    const char *editor_abi;",
    "} kr_module_entry;",
    "",
    "#define KR_PATCH_COUNT %d" % len(patches),
    "static const kr_patch_entry kr_patches[KR_PATCH_COUNT] = {",
]
lines += [
    "    { %s, %s, %s }%s"
    % (quote(patch["name"]), quote(manifest["upstream"]["revision"]), quote(patch["revision"]),
       "," if index + 1 < len(patches) else "")
    for index, patch in enumerate(patches)
]
lines += [
    "};",
    "",
    "#define KR_MODULE_COUNT %d" % len(modules),
]
if modules:
    lines.append("static const kr_module_entry kr_modules[KR_MODULE_COUNT] = {")
    lines += [
        "    { %s, %s, %s }%s"
        % (quote(module), quote(module_directory), quote(manifest["editor_abi"]),
           "," if index + 1 < len(modules) else "")
        for index, module in enumerate(modules)
    ]
    lines.append("};")
else:
    # A package with no loadable reader modules still declares an empty tree rather than nothing.
    lines.append("static const kr_module_entry kr_modules[1] = { { \"\", \"\", \"\" } };")
lines += ["", "#endif /* KR_BRIDGE_IDENTITY_H */", ""]

with open(destination, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines))
PYTHON
}

write_identity_record() {
    python3 - "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" <<'PYTHON'
import json
import sys

manifest_path, destination, identity, executable, module_directory, inputs, tests, toolchain = (
    sys.argv[1:9]
)
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)

record = {
    "identity": identity,
    "shell": {
        "kind": manifest["shell"],
        "executable": executable,
        "upstream_version": manifest["upstream"]["version"],
        "editor_abi": manifest["editor_abi"],
        "integration_version": manifest["integration_version"],
        "patches": [
            {
                "name": patch["name"],
                "upstream_revision": manifest["upstream"]["revision"],
                "revision": patch["revision"],
            }
            for patch in manifest["patches"]
        ],
        "modules": [
            {
                "name": module,
                "search_path": module_directory,
                "editor_abi": manifest["editor_abi"],
            }
            for module in manifest["modules"]
        ],
    },
    "abi": {
        "mailbox": manifest["mailbox_mechanism"],
        "pre_eof": manifest["pre_eof_mechanism"],
        "fence_proof": "atomic_reader_state",
        "cancellation": "non_destructive_key_wait",
        "launch_delivery": "reader_mailbox",
    },
    "build": {
        "upstream": {
            "archive": manifest["upstream"]["archive"],
            "url": manifest["upstream"]["url"],
            "sha256": manifest["upstream"]["sha256"],
        },
        "configure": manifest["configure"],
        "cflags": manifest["cflags"],
        "inputs_sha256": inputs,
        "toolchain": toolchain,
        "upstream_tests": tests,
    },
    "startup_entry": manifest["startup"],
}

with open(destination, "w", encoding="utf-8") as handle:
    json.dump(record, handle, indent=2, sort_keys=True)
    handle.write("\n")
PYTHON
}

build_package() {
    local shell_name="$1"
    local package="$root/shells/$shell_name"
    local cache="$prefix/sources"
    local m_shell m_integration_version m_editor_abi m_mailbox m_pre_eof
    local m_build_system m_environment
    local m_upstream_version m_archive m_url m_sha256 m_directory m_revision
    local m_binary m_module_directory m_source_directory m_test_command m_test_reason
    local m_configure m_cflags m_patches m_patch_names m_patch_revisions m_sources
    local m_modules m_startup

    eval "$(manifest_env "$package/manifest.json")"

    mkdir -p "$cache"
    local archive="$cache/$m_archive"
    if [ ! -f "$archive" ]; then
        echo "build-shells: fetching $m_archive"
        curl --fail --location --silent --show-error --output "$archive.part" "$m_url"
        mv "$archive.part" "$archive"
    fi
    local actual
    actual="$(digest "$archive")"
    if [ "$actual" != "$m_sha256" ]; then
        echo "build-shells: $m_archive has digest $actual and the manifest pins $m_sha256" >&2
        exit 1
    fi

    # The identity covers everything that goes into the binary, so the same inputs land in the same
    # place and a second run has nothing to do.
    local inputs
    # The toolchain and the environment the build honours are part of what produced the binary, so
    # they are part of what names it: a different compiler is a different package.
    local toolchain
    toolchain="$(${CC:-cc} --version 2>/dev/null | head -1)"
    inputs="kr-shell-package/1
shell=$m_shell
manifest=$(digest "$package/manifest.json")
script=$(digest "$root/scripts/build-shells.sh")
upstream=$m_sha256 $m_archive
cc=${CC:-cc} $toolchain
cppflags=${CPPFLAGS:-}
ldflags=${LDFLAGS:-}
"
    if [ "$m_build_system" = "cmake" ]; then
        # A shell whose own source is Rust is the compiler that produced it as much as the C one,
        # so a different toolchain is a different package here too. The toolchain is pinned by
        # name as well as recorded, because the build runs in a temporary directory where this
        # repository's own choice of toolchain does not reach.
        local rust_toolchain
        rust_toolchain="${RUSTUP_TOOLCHAIN:-$(rustup show active-toolchain 2>/dev/null | cut -d' ' -f1)}"
        export RUSTUP_TOOLCHAIN="${rust_toolchain:-stable}"
        inputs="$inputs
rustc=$(rustc --version 2>/dev/null)
toolchain=$RUSTUP_TOOLCHAIN
rustflags=${RUSTFLAGS:-}
env=$m_environment
"
    fi
    local patch_file
    for patch_file in $m_patches; do
        inputs="$inputs
patch=$(digest "$package/$patch_file") $patch_file"
    done
    local entry
    for entry in $m_sources; do
        inputs="$inputs
source=$(digest "$package/${entry%%:*}") ${entry#*:}"
    done
    inputs="$inputs
startup=$(digest "$package/$m_startup") $m_startup"

    local inputs_digest identity
    inputs_digest="$(digest_string "$inputs")"
    identity="${inputs_digest:0:16}"

    local destination="$prefix/$shell_name/$identity"
    local record="$destination/kr-shell-identity.json"
    local executable="$destination/$m_binary"
    local module_directory="$destination/$m_module_directory"

    if [ "$check_patches_only" -eq 0 ] && [ "$force" -eq 0 ] && [ -f "$record" ] && [ -x "$executable" ]; then
        if [ "$require_upstream_tests" -eq 1 ]; then
            # A cached package satisfies the requirement only if the suite passed when it was built.
            local recorded
            recorded="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["build"]["upstream_tests"])' "$record")"
            if [ "$recorded" != "passed" ]; then
                echo "build-shells: $shell_name $identity was built with upstream tests \"$recorded\"" >&2
                exit 1
            fi
        fi
        echo "build-shells: $shell_name $identity is current, nothing changed"
        printf '%s\n' "$identity" > "$prefix/$shell_name/current"
        return 0
    fi

    local work
    work="$(mktemp -d "${TMPDIR:-/tmp}/kr-shell-$shell_name.XXXXXX")"
    trap 'rm -rf "$work"' RETURN

    echo "build-shells: unpacking $m_archive"
    tar -x -f "$archive" -C "$work"
    local source_tree="$work/$m_directory"
    if [ ! -d "$source_tree" ]; then
        echo "build-shells: $m_archive does not hold $m_directory" >&2
        exit 1
    fi

    for patch_file in $m_patches; do
        echo "build-shells: applying $patch_file"
        # --forward and no fuzz: a patch that does not apply exactly to the pinned release is a
        # failure to report, never something to reconcile by hand.
        if ! patch -p1 --forward --batch --fuzz=0 -d "$source_tree" < "$package/$patch_file"; then
            echo "build-shells: $patch_file does not apply cleanly to $m_directory" >&2
            exit 1
        fi
    done

    for entry in $m_sources; do
        local from="${entry%%:*}"
        local into="${entry#*:}"
        mkdir -p "$source_tree/$(dirname "$into")"
        cp "$package/$from" "$source_tree/$into"
    done

    if [ "$check_patches_only" -eq 1 ]; then
        echo "build-shells: $shell_name patches apply cleanly to $m_directory ($identity)"
        return 0
    fi

    write_identity_header "$source_tree/$m_source_directory/kr_bridge_identity.h" \
        "$package" "$executable" "$module_directory"

    echo "build-shells: configuring $shell_name $m_upstream_version"
    if [ "$m_build_system" = "cmake" ]; then
        (
            # shellcheck disable=SC2086
            env $m_environment CFLAGS="$m_cflags" \
                cmake -S "$source_tree" -B "$source_tree/build" \
                    -DCMAKE_INSTALL_PREFIX="$destination" $m_configure
        ) > "$work/configure.log" 2>&1 || {
            tail -40 "$work/configure.log" >&2
            echo "build-shells: configuring $shell_name failed" >&2
            exit 1
        }
    else
    (
        cd "$source_tree"
        # A release from 2022 writes some of its configure probes in pre-C99 style, and a compiler
        # that defaults to C23 rejects them: the probe then reports the feature missing rather than
        # broken, and the shell is built around a working call it believes it does not have. The
        # manifest's compilation flags keep those probes compiling, so the answers are about the
        # platform rather than about the compiler's default standard.
        # shellcheck disable=SC2086
        CFLAGS="$m_cflags" ./configure --prefix="$destination" $m_configure
    ) > "$work/configure.log" 2>&1 || {
        tail -40 "$work/configure.log" >&2
        echo "build-shells: configuring $shell_name failed" >&2
        exit 1
    }
    fi

    echo "build-shells: compiling $shell_name"
    if [ "$m_build_system" = "cmake" ]; then
        # shellcheck disable=SC2086
        env $m_environment CFLAGS="$m_cflags" \
            cmake --build "$source_tree/build" -j"$jobs" > "$work/make.log" 2>&1 || {
            tail -40 "$work/make.log" >&2
            echo "build-shells: compiling $shell_name failed" >&2
            exit 1
        }
    else
    make -C "$source_tree" -j"$jobs" > "$work/make.log" 2>&1 || {
        tail -40 "$work/make.log" >&2
        echo "build-shells: compiling $shell_name failed" >&2
        exit 1
    }
    fi

    local tests_result="skipped"
    local summary=
    local -a test_argv
    if [ "$m_build_system" = "cmake" ]; then
        test_argv=(env $m_environment cmake --build "$source_tree/build" --target "$m_test_command")
    else
        test_argv=(make -C "$source_tree" "$m_test_command")
    fi
    if [ "$run_upstream_tests" -eq 1 ] && [ -n "$m_test_command" ]; then
        echo "build-shells: running the $shell_name test suite"
        # The suite runs in its own process group so a stall can be ended without reaching any
        # other build on this machine.
        set -m
        (
            "${test_argv[@]}" > "$work/tests.log" 2>&1
            echo "$?" > "$work/tests.status"
        ) &
        local runner=$!
        set +m
        local waited=0
        while [ "$waited" -lt "$test_timeout" ] && kill -0 "$runner" 2>/dev/null; do
            sleep 5
            waited=$((waited + 5))
        done
        if kill -0 "$runner" 2>/dev/null; then
            kill -- -"$runner" 2>/dev/null || true
            local grace=0
            while [ "$grace" -lt 10 ] && kill -0 "$runner" 2>/dev/null; do
                sleep 1
                grace=$((grace + 1))
            done
            kill -9 -- -"$runner" 2>/dev/null || true
            wait "$runner" 2>/dev/null || true
            tests_result="did not finish within ${test_timeout}s"
            echo "build-shells: the $shell_name test suite did not finish within ${test_timeout}s" >&2
            if [ "$require_upstream_tests" -eq 1 ]; then
                exit 1
            fi
            echo "build-shells: the identity record says so; the package is still built" >&2
        else
            wait "$runner" 2>/dev/null || true
            if [ "$(cat "$work/tests.status" 2>/dev/null || echo 1)" = "0" ]; then
                tests_result="passed"
            else
                # A release's own suite can fail on a platform for reasons that have nothing to do
                # with these patches, so the outcome is recorded rather than guessed at. The
                # summary goes into the identity beside the binary, and a run that wants the suite
                # to pass says so with --require-upstream-tests.
                summary="$(grep -E 'successful test scripts|tests failed|of the tests failed' \
                    "$work/tests.log" | tail -1 | tr -s ' ')"
                tests_result="failed${summary:+: $summary}"
                tail -40 "$work/tests.log" >&2
                echo "build-shells: the $shell_name test suite failed" >&2
                if [ "$require_upstream_tests" -eq 1 ]; then
                    exit 1
                fi
                echo "build-shells: the identity record says so; the package is still built" >&2
            fi
        fi
    elif [ -z "$m_test_command" ]; then
        tests_result="not run: $m_test_reason"
    fi
    if [ "$require_upstream_tests" -eq 1 ] && [ "$tests_result" != "passed" ]; then
        echo "build-shells: $shell_name upstream tests were \"$tests_result\"" >&2
        exit 1
    fi

    rm -rf "$destination"
    mkdir -p "$destination"
    if [ "$m_build_system" = "cmake" ]; then
        # shellcheck disable=SC2086
        env $m_environment cmake --install "$source_tree/build" > "$work/install.log" 2>&1 || {
            tail -40 "$work/install.log" >&2
            echo "build-shells: installing $shell_name failed" >&2
            exit 1
        }
    else
    make -C "$source_tree" install > "$work/install.log" 2>&1 || {
        tail -40 "$work/install.log" >&2
        echo "build-shells: installing $shell_name failed" >&2
        exit 1
    }
    fi

    if [ ! -x "$executable" ]; then
        echo "build-shells: $executable was not installed" >&2
        exit 1
    fi

    install -d "$destination/startup"
    cp "$package/$m_startup" "$destination/startup/$(basename "$m_startup")"

    write_identity_record "$package/manifest.json" "$record" "$identity" "$executable" \
        "$module_directory" "$inputs_digest" "$tests_result" "${CC:-cc} $toolchain"
    printf '%s\n' "$identity" > "$prefix/$shell_name/current"

    echo "build-shells: built $shell_name $m_upstream_version as $identity"
    echo "build-shells:   executable   $executable"
    echo "build-shells:   identity     $record"
    echo "build-shells:   upstream tests $tests_result"
}

mkdir -p "$prefix"

if [ "$build_zsh" -eq 1 ]; then
    build_package zsh
fi
if [ "$build_bash" -eq 1 ]; then
    build_package bash
fi
if [ "$build_fish" -eq 1 ]; then
    build_package fish
fi
