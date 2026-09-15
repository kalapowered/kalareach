/**
 * Resource limits checked before any allocation.
 *
 * The fields and defaults match `kr_cbor::Limits` in Rust, so a fixture that names a limit means
 * the same thing in both languages.
 */

/** Configured bounds for one decode. */
export interface Limits {
  /** Maximum length of the complete encoded message. */
  maxMessageLen: number
  /** Maximum nesting depth. A top-level scalar has depth 1. */
  maxDepth: number
  /** Maximum number of values in the whole message. */
  maxItems: number
  /** Maximum number of members in one array or map. */
  maxCollectionLen: number
  /** Maximum length in bytes of one byte string. */
  maxBytesLen: number
  /** Maximum length in bytes of one text string. */
  maxTextLen: number
}

/** Default bounds: 1 MiB message, depth 32, 65 536 items, 4 096 members, 1 MiB strings. */
export const DEFAULT_LIMITS: Limits = Object.freeze({
  maxMessageLen: 1 << 20,
  maxDepth: 32,
  maxItems: 65_536,
  maxCollectionLen: 4_096,
  maxBytesLen: 1 << 20,
  maxTextLen: 1 << 20
})

/** The snake_case names the shared fixtures use for each limit. */
const FIXTURE_NAMES: Record<string, keyof Limits> = {
  max_message_len: 'maxMessageLen',
  max_depth: 'maxDepth',
  max_items: 'maxItems',
  max_collection_len: 'maxCollectionLen',
  max_bytes_len: 'maxBytesLen',
  max_text_len: 'maxTextLen'
}

/** Merges fixture limit overrides, named as they are in the fixture files, over the defaults. */
export function limitsFromFixture (overrides?: Record<string, number>): Limits {
  const limits: Limits = { ...DEFAULT_LIMITS }
  for (const [name, value] of Object.entries(overrides ?? {})) {
    const field = FIXTURE_NAMES[name]
    if (field === undefined) {
      throw new Error(`unknown limit ${name}`)
    }
    limits[field] = value
  }
  return limits
}
