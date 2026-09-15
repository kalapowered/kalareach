/**
 * `@kalareach/protocol`
 *
 * Generated TypeScript types for the KalaReach wire contract, a KR-CBOR-1 codec that produces the
 * same bytes as the Rust implementation, and the JSON representation adapter.
 *
 * Rust is canonical. The types in `./generated/protocol.js` come from
 * `schema/kalareach-protocol.schema.json`, which the Rust crate generates. Both steps are checked,
 * so this package cannot drift from the host implementation.
 */

export * from './cbor/errors.js'
export * from './cbor/limits.js'
export * from './cbor/value.js'
export * from './cbor/decode.js'
export * from './cbor/encode.js'
export * from './json.js'
export type * from './generated/protocol.js'
