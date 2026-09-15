/**
 * The canonical encoder.
 *
 * `cborg` does the encoding, with its RFC 8949 section 4.2.1 map ordering: keys sort by the
 * bytewise order of their complete encoded key, which is the rule KR-CBOR-1 uses. This module is
 * the adaptation layer around it: it converts a validated {@link CanonicalValue} into the shapes
 * `cborg` encodes (bigint, `Uint8Array`, `Map`), so no float, tag, indefinite length or
 * non-text key can reach the encoder.
 */

import { encode as cborgEncode, rfc8949EncodeOptions } from 'cborg'

import { fail } from './errors.js'
import { validateCanonical, type CanonicalValue } from './value.js'

/** Converts a canonical value into the representation `cborg` encodes. */
function toNative (value: CanonicalValue): unknown {
  switch (value.kind) {
    case 'null':
      return null
    case 'bool':
      return value.value
    case 'int':
      // A bigint always encodes as a CBOR integer in its shortest form. A JavaScript number would
      // encode as a float once it left the safe-integer range.
      return value.value
    case 'bytes':
      return value.value
    case 'text':
      return value.value
    case 'array':
      return value.items.map(toNative)
    case 'map':
      return new Map(value.entries.map(([key, entry]) => [key, toNative(entry)] as const))
  }
}

/**
 * Encodes one value as canonical KR-CBOR-1 bytes.
 *
 * The value is validated first, because a caller can build a tree with an object literal rather
 * than through the constructors. Without that step a duplicate or misordered key would be
 * flattened by `Map` instead of rejected.
 */
export function encodeCanonical (value: CanonicalValue): Uint8Array {
  validateCanonical(value)
  try {
    return cborgEncode(toNative(value), rfc8949EncodeOptions)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    fail('unrepresentable', `value cannot be encoded as KR-CBOR-1: ${message}`)
  }
}

/** Returns the SHA-256 digest of `bytes`. */
export async function sha256 (bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes as BufferSource)
  return new Uint8Array(digest)
}

/** Returns the SHA-256 digest of the canonical encoding of `value`. */
export async function sha256OfCanonical (value: CanonicalValue): Promise<Uint8Array> {
  return await sha256(encodeCanonical(value))
}

/**
 * Builds the canonical signing input `CBOR([domain, element, ...])`.
 *
 * Every signature in the protocol covers one of these, never a fragment of a message and never a
 * re-serialised diagnostic document.
 */
export function signingInput (domain: string, elements: readonly CanonicalValue[]): Uint8Array {
  return encodeCanonical({
    kind: 'array',
    items: [{ kind: 'text', value: domain }, ...elements]
  })
}

/** Builds the signing input and returns its SHA-256 digest. */
export async function signingDigest (
  domain: string,
  elements: readonly CanonicalValue[]
): Promise<Uint8Array> {
  return await sha256(signingInput(domain, elements))
}
