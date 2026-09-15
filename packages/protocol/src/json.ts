/**
 * The JSON representation adapter.
 *
 * JSON is the managed HTTP representation. Opaque bytes are unpadded base64url and unsigned
 * 64-bit counters are decimal strings, because a JavaScript number cannot carry a `u64` exactly.
 * Identifiers use their canonical hyphenated text form.
 *
 * JSON is never a signing representation. Signatures and digests cover canonical KR-CBOR-1 bytes.
 */

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

/** Encodes bytes as unpadded base64url. */
export function bytesToBase64Url (bytes: Uint8Array): string {
  let out = ''
  for (let index = 0; index < bytes.length; index += 3) {
    const remaining = bytes.length - index
    const first = bytes[index]
    const second = remaining > 1 ? bytes[index + 1] : 0
    const third = remaining > 2 ? bytes[index + 2] : 0
    out += BASE64URL[first >> 2]
    out += BASE64URL[((first & 0x03) << 4) | (second >> 4)]
    if (remaining > 1) {
      out += BASE64URL[((second & 0x0f) << 2) | (third >> 6)]
    }
    if (remaining > 2) {
      out += BASE64URL[third & 0x3f]
    }
  }
  return out
}

/** Decodes unpadded base64url. Padding and non-alphabet characters are rejected. */
export function base64UrlToBytes (text: string): Uint8Array {
  const out: number[] = []
  let accumulator = 0
  let bits = 0
  for (const character of text) {
    const value = BASE64URL.indexOf(character)
    if (value < 0) {
      throw new Error(`invalid base64url character ${JSON.stringify(character)}`)
    }
    accumulator = (accumulator << 6) | value
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out.push((accumulator >> bits) & 0xff)
    }
  }
  if (bits >= 6 || (accumulator & ((1 << bits) - 1)) !== 0) {
    throw new Error('invalid base64url length or padding bits')
  }
  return new Uint8Array(out)
}

/** Renders an unsigned 64-bit counter the way JSON carries it. */
export function u64ToJson (value: bigint): string {
  if (value < 0n || value > 2n ** 64n - 1n) {
    throw new Error(`${value} is not an unsigned 64-bit counter`)
  }
  return value.toString(10)
}

/**
 * Reads an unsigned 64-bit counter.
 *
 * A decimal string is the representation this package emits. A JSON number is accepted so a
 * hand-written diagnostic document parses, and is rejected when it cannot be represented exactly.
 */
export function jsonToU64 (value: string | number): bigint {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${value} is not an exact unsigned counter`)
    }
    return BigInt(value)
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${JSON.stringify(value)} is not a decimal counter`)
  }
  const parsed = BigInt(value)
  if (parsed > 2n ** 64n - 1n) {
    throw new Error(`${value} is above the unsigned 64-bit range`)
  }
  return parsed
}

/** Renders a 16-byte identifier as canonical hyphenated lower-case text. */
export function uuidToJson (bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new Error(`a UUID is 16 bytes, not ${bytes.length}`)
  }
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/** Reads a canonical hyphenated identifier into its 16 bytes. */
export function jsonToUuid (text: string): Uint8Array {
  if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(text)) {
    throw new Error(`${JSON.stringify(text)} is not a hyphenated UUID`)
  }
  const hex = text.replace(/-/g, '')
  const bytes = new Uint8Array(16)
  for (let index = 0; index < 16; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}
