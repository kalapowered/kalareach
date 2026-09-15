# kalareach

KalaReach host, controller, workers, CLI, shared protocol and transport, Tauri desktop and mobile apps, plugin runtime and SDK, contact skill and conformance fixtures.

Licensed under the BSD 3-Clause License. See [LICENSE](LICENSE).

## Repository layout

A Cargo workspace and a pnpm workspace share one tree.

| Path | What it holds |
| --- | --- |
| `crates/kr-cbor` | The KR-CBOR-1 codec: canonical encoding, strict decoding, digests and signing input |
| `crates/kr-protocol` | Wire types, the method authority table, error codes and the JSON Schema generator |
| `crates/kr-crypto` | Cryptography: a narrow libsodium wrapper, purpose-separated device keys, encrypted objects and secret storage |
| `crates/kr-plugin-sdk` | The plugin package contract: manifests, the WIT package, effect classes, the catalogue index and the package validator |
| `packages/protocol` | The generated TypeScript package: types, a byte-compatible codec and the JSON adapter |
| `packages/plugin-sdk` | The generated plugin SDK package: types, the package contract as data and the published WIT file |
| `fixtures/` | Cross-language conformance vectors and fixture packages that both languages test against |
| `docs/protocol/` | The protocol reference |
| `docs/crypto/` | The cryptography reference |
| `docs/plugins/` | The plugin reference |

Rust is canonical. The JSON Schema in `packages/protocol/schema/` and `packages/plugin-sdk/schema/`
comes from the Rust types, and the TypeScript types come from those schemas. Every step is checked
in CI, so the two languages cannot drift.

## Build and test

Requirements: the toolchain pinned in `rust-toolchain.toml` (rustup installs it on first use),
Node 22 and pnpm 11.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p kr-protocol --bin kr-protocol-gen -- --check
cargo run -p kr-crypto --bin kr-crypto-vectors -- --check
cargo run -p kr-plugin-sdk --bin kr-plugin-sdk-gen -- --check

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
After changing a manifest type, do the same for the plugin SDK:

```bash
cargo run -p kr-plugin-sdk --bin kr-plugin-sdk-gen
pnpm -C packages/plugin-sdk generate
```

[docs/protocol/README.md](docs/protocol/README.md) explains the encoding, the framing, the
envelopes, the receipt contract, the error codes and the authority table.
[docs/crypto/README.md](docs/crypto/README.md) explains the cryptographic boundary: the key
purposes, the domains, the encrypted object formats and the secret store.
[docs/plugins/README.md](docs/plugins/README.md) explains the package contract, the manifests, the
effect classes, the node union, the predicate grammar and the limits.
