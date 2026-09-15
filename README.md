# kalareach

KalaReach host, controller, workers, CLI, shared protocol and transport, Tauri desktop and mobile apps, plugin runtime and SDK, contact skill and conformance fixtures.

Licensed under the BSD 3-Clause License. See [LICENSE](LICENSE).

## Repository layout

A Cargo workspace and a pnpm workspace share one tree.

| Path | What it holds |
| --- | --- |
| `crates/kr-cbor` | The KR-CBOR-1 codec: canonical encoding, strict decoding, digests and signing input |
| `crates/kr-protocol` | Wire types, the method authority table, error codes and the JSON Schema generator |
| `crates/kr-ipc` | Local typed-frame inter-process communication: directories, peer credentials, descriptors and identity proofs |
| `crates/kr-worker` | The session worker: pseudo-terminal, lifecycle, attachments, input lease and receipt journal |
| `crates/kr-controller` | The control daemon: registry, create admission, worker supervision and the local service |
| `crates/kr-cli` | The `kr` command line and its terminal restoration guard |
| `crates/kr-crypto` | Cryptography: a narrow libsodium wrapper, purpose-separated device keys, encrypted objects and secret storage |
| `crates/kr-pairing` | Pairing: the short-code SPAKE2 and direct QR state machines, their budgets and their transcripts |
| `crates/kr-transport` | Transport: iroh endpoints, the connection handshake, stream kinds, actor envelopes, action windows and dispatch leases |
| `crates/kr-client` | The native client library: connections, typed calls, cursors, receipts and replaceable service clients |
| `crates/kr-plugin-sdk` | The plugin package contract: manifests, the WIT package, effect classes, the catalogue index and the package validator |
| `crates/kr-term` | The terminal engine: the kr-vt/1 profile, sequence classes, canonical grid, query broker and snapshots |
| `packages/protocol` | The generated TypeScript package: types, a byte-compatible codec and the JSON adapter |
| `packages/plugin-sdk` | The generated plugin SDK package: types, the package contract as data and the published WIT file |
| `fixtures/` | Cross-language conformance vectors and fixture packages that both languages test against |
| `docs/protocol/` | The protocol reference |
| `docs/host/` | The host: process topology, directories, descriptors, supervision, journals and recovery |
| `docs/cli/` | The command line: commands, exit codes and the `--json` shapes |
| `docs/crypto/` | The cryptography reference |
| `docs/pairing/` | The pairing reference |
| `docs/transport/` | The transport reference |
| `docs/plugins/` | The plugin reference |
| `docs/terminal/` | The terminal reference |

Rust is canonical. The JSON Schema in `packages/protocol/schema/` and `packages/plugin-sdk/schema/`
comes from the Rust types, and the TypeScript types come from those schemas. Every step has a check
mode that CI runs, so a change on one side that is not carried to the other fails the build.

The generated schema carries the shape of each document, not every rule. Rules a schema cannot
express, such as Windows device names, case-folded path collisions, predicate depth and whether a
control names a registered action, are checked by the host and by `kr-plugin-sandbox`.
[docs/plugins/README.md](docs/plugins/README.md) lists them as finding codes.

## Build and test

Requirements: the toolchain pinned in `rust-toolchain.toml` (rustup installs it on first use),
Node 22 and pnpm 11.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p kr-protocol --bin kr-protocol-gen -- --check
cargo run -p kr-crypto --bin kr-crypto-vectors -- --check
cargo run -p kr-pairing --bin kr-pairing-vectors -- --check
cargo run -p kr-plugin-sdk --bin kr-plugin-sdk-gen -- --check
cargo run -p kr-plugin-sdk --bin kr-plugin-sandbox -- fixtures/plugins/valid/example-declarative
cargo run -p kr-term --bin kr-term-fixtures -- --check

pnpm install --frozen-lockfile
pnpm -r test
```

After changing a wire type, regenerate both artefacts and commit them with the change:

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

[docs/protocol/README.md](docs/protocol/README.md) explains the encoding, the framing, the
envelopes, the receipt contract, the error codes and the authority table.
[docs/host/README.md](docs/host/README.md) explains how the host runs sessions, and
[docs/cli/README.md](docs/cli/README.md) is the command-line reference.
[docs/crypto/README.md](docs/crypto/README.md) explains the cryptographic boundary: the key
purposes, the domains, the encrypted object formats and the secret store.
[docs/pairing/README.md](docs/pairing/README.md) explains the two pairing flows, their budgets, the
PAKE profile and the review gate it carries.
[docs/transport/README.md](docs/transport/README.md) explains the network layer: endpoint
configuration, the connection handshake, stream kinds and limits, reconnect behaviour, actor
envelopes, action windows, the dispatch lease and the self-hosting fields.
[docs/plugins/README.md](docs/plugins/README.md) explains the package contract, the manifests, the
effect classes, the node union, the predicate grammar and the limits.
[docs/terminal/README.md](docs/terminal/README.md) explains the kr-vt/1 profile, the sequence class
table, the byte policy, the query broker, snapshots and the probe contract.
