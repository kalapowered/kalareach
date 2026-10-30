# kalareach

This repository holds the KalaReach host, controller, workers, CLI, shared protocol and transport,
Tauri desktop and mobile apps, plugin runtime and SDK, contact skill and conformance fixtures.

KalaReach is licensed under the BSD 3-Clause License, in [LICENSE](LICENSE). Every crate of the
Cargo workspace and every package of the pnpm workspace declares it with the SPDX identifier
`BSD-3-Clause`. The website and catalogue repositories carry the same licence in the same way.

The managed shell packages under `shells/` are the exception, because they are built from other
people's shells. `shells/zsh/` carries the Zsh licence, `shells/bash/` the GNU General Public
Licence, version 3 or later, and `shells/fish/` version 2 of that licence, each with its own
`LICENSE` file that keeps the upstream licence text. `shells/psreadline/` copies nothing from
upstream and stays BSD 3-Clause. Every crate, script and document written for KalaReach stays BSD
3-Clause, and no code under any of those licences is compiled into a crate. The Gradle wrapper
under `apps/companion/src-tauri/gen/android/`, its scripts and `gradle-wrapper.jar`, is Gradle's own
code under the Apache License 2.0, and the scripts keep their headers.

## Repository layout

This is both a Cargo and a pnpm workspace.

| Path | What it holds |
| --- | --- |
| `crates/kr-cbor` | The KR-CBOR-1 codec: canonical encoding, strict decoding, digests and signing input |
| `crates/kr-protocol` | Wire types, the method authority table, error codes and the JSON Schema generator |
| `crates/kr-ipc` | Local typed-frame inter-process communication: directories, peer credentials, descriptors and identity proofs |
| `crates/kr-worker` | The session worker: pseudo-terminal, canonical grid, lifecycle, attachments, input lease and receipt journal |
| `crates/kr-controller` | The control daemon: registry, create admission, worker supervision, the local service and the network |
| `crates/kr-cli` | The `kr` command line and its terminal restoration guard |
| `crates/kr-hook` | The forwarder: the native bridge an application starts beside its unchanged terminal, and the relay a launched agent reaches its worker through |
| `crates/kr-crypto` | Cryptography: a narrow libsodium wrapper, purpose-separated device keys, encrypted objects and secret storage |
| `crates/kr-pairing` | Pairing: the short-code SPAKE2 and direct QR state machines, their budgets and their transcripts |
| `crates/kr-transport` | Transport: iroh endpoints, the connection handshake, stream kinds, actor envelopes, action windows and dispatch leases |
| `crates/kr-client` | The native client library: network and local connections, typed calls, cursors, receipts and replaceable service clients |
| `crates/kr-plugin-sdk` | The plugin package contract: manifests, the WIT package, effect classes, the catalogue index and the package validator |
| `crates/kr-plugin-catalogue` | The plugin catalogue client: repository enrolment and budgets, the signed metadata snapshot and its verification, offline search, package activation and what an installed package may do |
| `crates/kr-plugin-runtime` | Component hosting: the engine, the per-instance limits, the compiled-code cache and the binding lifecycle |
| `crates/kr-plugin-service` | Reaching the plugin host without the engine: its protocol, the worker's client and the launcher |
| `crates/kr-plugin-host` | The plugin-runtime service: one lazily started per-environment process that owns component instances |
| `crates/kr-term` | The terminal engine: the kr-vt/1 profile, sequence classes, canonical grid, query broker and snapshots |
| `crates/kr-shell-integration` | The root-editor bridge contract: the handshake, the reader events, the fence and detach state machine and the cross-shell scenarios |
| `shells/` | The managed shell packages: the reader patch sets, the bridge sources, the guarded startup entries and the build manifests |
| `crates/kr-transfer` | The transfer service: uploads, verified downloads, handle-based filesystem authority and bounded previews |
| `crates/kr-project` | The project service: repositories, workspaces, the restricted Git execution profile and staged publish |
| `crates/kr-changeset` | The change-set service: immutable captured versions, their content store, independent materialisations and the apply outcome classes |
| `crates/kr-attention` | The attention engine: the rule set, quiet hours and escalation, review and visit acknowledgements, and the feature store they are rebuilt from |
| `crates/kr-automation` | The automation engine: workflow definitions, runs, causal budgets and admission |
| `crates/kr-delivery` | The delivery producer: the delivery journal, notification previews, the push outbox and external notification destinations |
| `crates/kr-describe` | The description service: deterministic session titles, the scheduler and resource policy for one shared CPU-only inference process per environment, its signed model profiles and inference seam, and the names, pins and provenance store, with no model runtime |
| `crates/kr-describe-model` | The description model: the CPU-only llama.cpp runtime behind that seam, the check that a downloaded model file is the one its profile records, the `kr-describe-inference` process and the `kr-describe-bench` benchmark |
| `crates/kr-voice` | The voice coordinator: context selection, delegation, the voice grant and the unlocked-screen confirmation |
| `skills/kalareach-contact` | The installable contact skill: what an agent reads, its tool reference and its installation manifest |
| `apps/companion` | The Tauri companion application for desktops and phones: the React interface, its native backend in `src-tauri`, the native platform services in `native/platform`, and the iOS and Android sources beside them |
| `packages/protocol` | The generated TypeScript package: types, a byte-compatible codec and the JSON adapter |
| `packages/plugin-sdk` | The generated plugin SDK package: types, the package contract as data and the published WIT file |
| `bundled-plugins/` | The signed catalogue generation that ships with the host, with its packages, and the lock that names every byte of it |
| `fixtures/` | Cross-language conformance vectors and fixture packages that both languages test against |
| `tests/` | Suites that span crates: the cross-boundary checkpoint in `tests/e2e/m1b`, the legs against a deployment in `tests/integration`, and the shell qualification corpus in `tests/shells` |
| `scripts/` | Builds and checks that span crates: the test components, the shell packages, the bundled generation, the end-to-end, performance and device runs, the package release and the clean-checkout check |
| `docs/` | The documentation; [docs/README.md](docs/README.md) lists every document |

Rust is canonical. The JSON Schema in `packages/protocol/schema/` and `packages/plugin-sdk/schema/`
comes from the Rust types, and the TypeScript types come from those schemas. Every step has a check
mode that CI runs, so a change on one side that is not carried to the other fails the build.

The generated schema carries the shape of each document, not every rule. Rules a schema cannot
express, such as Windows device names, case-folded path collisions, predicate depth and whether a
control names a registered action, are checked by the host and by `kr-plugin-sandbox`.
[docs/plugins/README.md](docs/plugins/README.md) lists them as finding codes.

## Build and test

Requirements for building the project:

- the toolchain `rust-toolchain.toml` pins, which rustup installs on first use, with its
  `wasm32-wasip2` target for the plugin runtime's test components;
- Node version 22 and the version of pnpm specified in `package.json`
- a C and a C++ compiler, CMake and libclang, which the description service's model runtime is
  built with, and Git and Python 3;
- on Linux, the headers of the system WebView the companion application's backend links: WebKitGTK
  4.1, GTK 3, libayatana-appindicator, librsvg and libsoup 3;
- On macOS, fish, which the Fish test in `crates/kr-worker/tests/shells.rs` starts as a session's
  root shell (macOS ships the Bash and Zsh that the file's other two tests start)
- curl, make, patch, and tar, as well as the headers for ncurses, and gettext (for the managed shell
  packages), and PowerShell >= 7.4 with PSReadLine >= 2.3.4 < 3.0.0, at or above the fixed release of each advisory in
  `docs/shell-integration/upstream.md` (for the PSReadLine package)

The lists below hold every step, in order.
[`scripts/check-clean-checkout.sh`](scripts/check-clean-checkout.sh) runs them in a fresh clone of
one commit, with a home directory, a Cargo home, a pnpm store and a temporary directory of its own,
and with a PATH reduced to the system directories and those of the programs the list uses, whose
paths and digests it prints first; on macOS the fresh home directory has a keychain of its own.
`--help` says how to choose groups. Before it runs a step it refuses a tree that names a working
record kept outside the repository, a commit message longer than one line, and a link in a Markdown
file, read as text, that names a relative path the tree does not have or that it cannot read;
`--self-test` shows each refusal on a fixture with its defect planted. Each step is one line of the
lists below.

Setup prepares the target, the JavaScript dependencies, the test components the plugin runtime's
tests load, and the managed shell packages with the PSReadLine qualification. The packages build
from upstream sources that `scripts/place-shell-sources.sh` puts in place first: the archives, from the
URL each manifest names or from a listed mirror, and, for fish, the crates and git repositories its
build would otherwise download. `--no-upstream-tests` leaves out the shells' own test
suites, which continuous integration runs for Bash and Zsh.

<!-- clean-checkout: setup -->

```bash
rustup target add wasm32-wasip2
pnpm install --frozen-lockfile
bash scripts/build-plugin-fixtures.sh
bash scripts/place-shell-sources.sh --zsh --bash --fish
bash scripts/build-shells.sh --zsh --bash --fish --no-upstream-tests
pwsh -NoProfile -Command 'Import-Module ./shells/psreadline/module/KalaReach.ShellBridge.psd1; Publish-KalaReachQualification | Out-Null'
```

In the checks, `KR_REQUIRE_PLUGIN_FIXTURES=1` makes a missing test component fail the plugin
runtime's tests rather than skip them.

<!-- clean-checkout: check -->

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
KR_REQUIRE_PLUGIN_FIXTURES=1 cargo test --locked --workspace
bash scripts/sync-bundled-plugins.sh --verify
cargo run --locked -p kr-protocol --bin kr-protocol-gen -- --check
cargo run --locked -p kr-crypto --bin kr-crypto-vectors -- --check
cargo run --locked -p kr-pairing --bin kr-pairing-vectors -- --check
cargo run --locked -p kr-plugin-sdk --bin kr-plugin-sdk-gen -- --check
for package in fixtures/plugins/valid/*/; do cargo run --locked -p kr-plugin-sdk --bin kr-plugin-sandbox -- "$package" || exit 1; done
cargo run --locked -p kr-term --bin kr-term-fixtures -- --check
cargo run --locked -p kr-shell-integration --bin kr-shell-fixtures -- --check
pnpm -r generate:check
pnpm -r test
```

The cases that drive a managed shell package are left out of an ordinary test run, because they
need the packages the setup built. This group runs them, then qualifies the packages against the
startup customisations people run: `fetch-shell-stacks.sh` fetches the pinned customisations, a
second Zsh build made with the qualification define stands for an installation that holds two
builds, and the pinned build is put back before the qualification cases run.

<!-- clean-checkout: shells -->

```bash
cargo test --locked -p kr-shell-integration --test zsh --test bash --test fish --test pwsh -- --test-threads=1 --include-ignored
bash scripts/fetch-shell-stacks.sh
CPPFLAGS=-DKR_QUALIFICATION_BUILD=1 bash scripts/build-shells.sh --zsh --no-upstream-tests
bash scripts/build-shells.sh --zsh --no-upstream-tests
cargo test --locked -p kr-shell-integration --test qualification -- --test-threads=1 --include-ignored
```

The last group is separate because of what it costs. `scripts/end-to-end.sh` runs the host's
end-to-end demonstrations one at a time, with real daemons, workers, shells and terminals, and takes
about a minute. `scripts/performance.sh` builds a release profile and takes four measurements, each
against its requirement's bound: the latency forwarding ordinary input adds (KR-PERF-001), the paste
recogniser's deadline for every prefix length and for a delimiter split across frames (KR-PERF-002),
the processor time twenty idle sessions with thirty-two views use, averaged over five minutes, and
the memory they hold, read once at the end of those five minutes (KR-PERF-003), and the time from
attaching to a usable screen (KR-PERF-004). The five-minute window makes it take more than five
minutes. Both take an optional log path, and both exit non-zero when anything they were meant to
demonstrate did not happen. The terminal engine's output handling (KR-PERF-007) and the transport's
scheduling and reconnection (KR-PERF-005 and KR-PERF-006) are measured by their own suites in an
optimised build, one test at a time.

<!-- clean-checkout: demonstrations -->

```bash
bash scripts/end-to-end.sh
bash scripts/performance.sh
cargo test --locked --release -p kr-term --test perf -- --nocapture --test-threads=1
cargo test --locked --release -p kr-transport --test perf -- --nocapture --test-threads=1
```

After changing a wire type or a method, regenerate what the Rust types generate, which is the
schema, the method table and index and the service and push vectors, and the TypeScript types, and
commit them with the change:

```bash
cargo run -p kr-protocol --bin kr-protocol-gen
pnpm -C packages/protocol generate
```

After changing anything the cryptography vectors cover, regenerate them and commit them too:

```bash
cargo run -p kr-crypto --bin kr-crypto-vectors
cargo run -p kr-pairing --bin kr-pairing-vectors
```

After changing a manifest type, do the same for the plugin SDK, and after changing terminal
behaviour, for the terminal fixtures:

```bash
cargo run -p kr-plugin-sdk --bin kr-plugin-sdk-gen
pnpm -C packages/plugin-sdk generate
cargo run -p kr-term --bin kr-term-fixtures
```

After changing the shell-bridge contract, rewrite its scenarios and commit them with the change:

```bash
cargo run -p kr-shell-integration --bin kr-shell-fixtures
```

## Releases

There are two kinds of release. A package release is initiated by creating a tag, and a host release by running a workflow.

- A tag `packages/v<version>+<commit>` releases the generated `@kalareach/protocol` and
  `@kalareach/plugin-sdk` packages as immutable archives on a GitHub release, through
  `.github/workflows/package-release.yml`. [docs/releases/packages.md](docs/releases/packages.md)
  says what a release carries, how a consumer pins one and how to reproduce it, and sets the
  managed shell packages' update target.
- A macOS and Linux host release is built by `.github/workflows/release-tree.yml`, signed and
  notarised on the machine that holds the Developer ID, and sealed and published as a pre-release
  `host/v<version>+<commit>` by `.github/workflows/release-host.yml`.
  [docs/releases/macos-signing.md](docs/releases/macos-signing.md) says what each step does and checks.
- A tag that starts with `host/v`, pushed to the repository, builds the Windows host executables and
  PowerShell packages through `.github/workflows/release-windows.yml`, whose `release` job signs the
  files that carry a signature and runs only when the repository variable `WINDOWS_HOST_RELEASE` is
  `true`. That job ends with an error at its manifest step, so the workflow publishes no release.
  [docs/releases/windows-signing.md](docs/releases/windows-signing.md) says what signs, what the
  release carries and how the signing identity is kept.

To see what a package release will include, without creating a tag:

```bash
bash scripts/release-packages.sh --output /tmp/kalareach-packages
```

## Install a host

Every release of the host for macOS and Linux is tagged on GitHub with a tag beginning with `host/v` and published as a pre-release. It contains an archive for each target, named `kalareach-<target>-<release>.tar.gz`, as well as a file named `SHA256SUMS`, which covers all four archives. The target should be selected according to your host's architecture: `aarch64-apple-darwin` or `x86_64-apple-darwin` if you run macOS 14 or above, `aarch64-unknown-linux-gnu` or `x86_64-unknown-linux-gnu` if you run Linux with glibc 2.35 or above. You can download the archive and `SHA256SUMS` with `curl`, using the links on the release page and naming each file as `SHA256SUMS` lists it:

```sh
curl -fL -o kalareach-<target>-<release>.tar.gz <the archive's link>
curl -fL -o SHA256SUMS <the link of SHA256SUMS>
```

The links use `%2B` to encode the `+` in the release name, so you should not use `curl -O`: it keeps that spelling in the file name, and the check below will not find the archive. Also, if you use your browser to download the archive instead of `curl`, on macOS 26.6.2 Safari with its default settings decompresses it, leaving the `.tar` file but not the `.tar.gz` file, which leaves nothing to check. Once you have both files, the following commands check the archive's integrity and, only if the check passes, unpack it and run the install command:

```sh
shasum -a 256 --ignore-missing -c SHA256SUMS &&
tar -xzf kalareach-<target>-<release>.tar.gz &&
kalareach-<target>-<release>/bin/kr host install
```

On Linux, run `sha256sum --ignore-missing -c SHA256SUMS` instead of the first command. The check has to print `kalareach-<target>-<release>.tar.gz: OK`, and the two commands after it run only if it does. If it ends with a line ending in `FAILED`, the archive you downloaded is not the one that was released. If it says `no file was verified` and there is no line ending in `FAILED`, you do not have an archive with the name `SHA256SUMS` lists. In both cases the block stops there, and nothing is unpacked or installed.

The command `kr host install` verifies the signed manifest of the release and checks every file against it before making the release current. It then prints the directory to add to your `PATH`. A first install can check the manifest only against the update channel root that the archive carries, so `SHA256SUMS` and the address you downloaded from are what vouch for the archive; the release notes list the key identifiers of that root. On macOS, every program in the archive is signed by Kala Holdings Inc. and notarised by Apple. If you downloaded the archive with `curl`, the programs carry no quarantine flag, and on macOS 26.6.2 `kr` ran with no network. A download from a browser carries the flag, and so does every file that Archive Utility or `tar` unpacks from it. On macOS 26.6.2, the first flagged `kr` you run asks Apple's service about it, so it needs a network. Without one, the system refused it: a window titled "“kr” Not Opened" said "Apple could not verify “kr” is free of malware that may harm your Mac or compromise your privacy", and the command waited behind that window. A copy refused this way kept refusing when the network came back. Run the first command with the network on, and unpack the archive again if it was refused. The copies that `kr host install` puts in the store carry no flag.

If `kr` refuses `~/Library/Application Support/KalaReach` as open to others, as a macOS install of release 0.1.0+8cd1adf5c8bf leaves it, run `chmod 700 "$HOME/Library/Application Support/KalaReach"`.

The host will not join any network unless instructed to via the configuration document. Run `kr host startup --set standalone`, which writes the configuration document and prints the path to it. If your network requires the use of a proxy, now is the time to set the `network.proxy_url` field of the configuration document, as the following command makes its request through it. See [docs/host/README.md](docs/host/README.md#the-network-and-the-voice-broker) for more details.

Then run `kr host network --join`. This will retrieve the KalaReach service's self-description, verify that it has been signed using the key embedded in this version of the software, and write the relay, discovery and service settings into the configuration document according to the description (`level` is set to match). If any of these settings are already set to different values, the command will name those settings and will not write any of them; use the `--replace` option to force the settings to be taken from the service regardless. To join a self-run service instead, see [docs/cli/README.md](docs/cli/README.md#kr-host-network) for more information.

These settings will come into effect when the control daemon starts. Also run `kr shell install`, so that the shells you start under KalaReach open their bridge to it.

Open a second terminal window before you create the first session. Create the session in the first window with `kr new`, which starts the control daemon, and pair your first phone from the second. `kr pair invite --owner` asks you to type `pair`, then shows a pairing code, a QR code and an invitation identifier; `kr pair confirm <invitation>` takes the value the phone shows. `kr new` attaches the terminal it runs in, and the first pairing is refused inside a KalaReach session; on macOS it is also refused in a window opened after a session started. If, when running `kr new`, it replies that the control daemon did not respond, and the last lines in `controller.log` contain a line mentioning `the secret store failed`, the secret-store error is given at the end of that line. If it is `Couldn't access platform storage` on a Linux login that uses a desktop keyring, it usually means that the keyring answers but cannot be opened, and the control daemon stops when it starts. Unlock the keyring, for example by signing in to the desktop session on that machine, and run `kr new` again. A host that has started on the keyring keeps using it, and does not move to the file store by itself. Any other secret-store error has a different cause, and its text says what failed. On macOS, `kr new` over SSH can stop with `User interaction is not allowed` in `controller.log`, because that login could not reach the login Keychain; run it in a terminal on the Mac's own desktop.

To update to a new release, download the archive for the new release and run `kr host update --archive <archive>`. `kr host rollback` goes back to the release before it. [docs/host/updates.md](docs/host/updates.md) says what an update does to a running session, and [docs/releases/macos-signing.md](docs/releases/macos-signing.md) says how the releases are signed.

## Recovering a host

A host keeps what it knows in two owner-only directories for each operating-system user, with one
directory per environment beneath each. `KR_RUNTIME_DIR` and `KR_STATE_DIR` override them.

| Directory | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Runtime: the local endpoints and each worker's published descriptor | `$TMPDIR/kalareach`, else `/tmp/kalareach-<uid>` | `$XDG_RUNTIME_DIR/kalareach`, else `~/.cache/kalareach/run` | `%LOCALAPPDATA%\KalaReach\run` |
| State: the registry, the worker journals, the output spools, the secret-store fallback, the transfer and backup stores, and the daemon's log | `~/Library/Application Support/KalaReach` | `$XDG_STATE_HOME/kalareach`, else `~/.local/state/kalareach` | `%LOCALAPPDATA%\KalaReach` |

On Windows the endpoints are named pipes rather than files.
[Directories](docs/host/README.md#directories) says what each directory holds and how it is
protected.

- **The control daemon restarts, is upgraded or crashes.** No session ends. The replacement takes
  the environment's lock, advances its generation, rebuilds its view of the sessions from the
  registry and the published descriptors, and verifies each worker with a fresh challenge. A
  descriptor that fails is quarantined, and no worker is stopped because the daemon changed. `kr
  attach` reaches a worker without the daemon, so attaching works while it restarts. See
  [Recovery](docs/host/README.md#recovery).
- **A worker crashes.** Its session has ended. The daemon records the closure as abnormal once the
  operating system agrees the worker has gone; a daemon that only cannot reach a worker records
  nothing. See [Closure](docs/host/README.md#closure).
- **The machine reboots.** Every session ends: a desktop-bound session with its login, a headless
  one with the machine. As the daemon starts, it closes every session recorded in an earlier boot,
  and the record says the host restarted. A logout ends the desktop-bound sessions of that login,
  and whether a headless session outlives it depends on the platform. See [What a reboot
  does](docs/host/platforms.md#what-a-reboot-does) and [What logout
  does](docs/host/platforms.md#what-logout-does).

[docs/README.md](docs/README.md) indexes the documentation: the protocol reference and its method
index, and one reference for each part of the host, the clients and the plugins.
