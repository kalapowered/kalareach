# kalareach

KalaReach host, controller, workers, CLI, shared protocol and transport, Tauri desktop and mobile apps, plugin runtime and SDK, contact skill and conformance fixtures.

Licensed under the BSD 3-Clause License. See [LICENSE](LICENSE).

## Repository layout

A Cargo workspace and a pnpm workspace share one tree.

| Path | What it holds |
| --- | --- |
| `crates/kr-cbor` | The KR-CBOR-1 codec: canonical encoding, strict decoding, digests and signing input |
| `crates/kr-protocol` | Wire types, the method authority table, error codes and the JSON Schema generator |
| `packages/protocol` | The generated TypeScript package: types, a byte-compatible codec and the JSON adapter |
| `fixtures/` | Cross-language conformance vectors that both languages test against |
| `docs/protocol/` | The protocol reference |

Rust is canonical. The JSON Schema in `packages/protocol/schema/` comes from the Rust types, and the
TypeScript types come from that schema. Both steps are checked in CI, so the two languages cannot
drift.

## Build and test

Requirements: the toolchain pinned in `rust-toolchain.toml` (rustup installs it on first use),
Node 22 and pnpm 11.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p kr-protocol --bin kr-protocol-gen -- --check

pnpm install --frozen-lockfile
pnpm -r test
```

After changing a wire type, regenerate both artefacts and commit them with the change:

```bash
cargo run -p kr-protocol --bin kr-protocol-gen
pnpm -C packages/protocol generate
```

[docs/protocol/README.md](docs/protocol/README.md) explains the encoding, the framing, the
envelopes, the receipt contract, the error codes and the authority table.
