import { describe, expect, it } from 'vitest'

import {
  base64UrlToBytes,
  bytesToBase64Url,
  jsonToU64,
  jsonToUuid,
  u64ToJson,
  uuidToJson
} from '../src/index.js'
import { bytesToHex, hexToBytes } from './fixtures.js'

describe('the JSON representation', () => {
  it('renders opaque bytes as unpadded base64url', () => {
    expect(bytesToBase64Url(new Uint8Array(32).fill(0xff))).toBe(
      '__________________________________________8'
    )
    expect(bytesToBase64Url(new Uint8Array([]))).toBe('')
    expect(bytesToBase64Url(new Uint8Array([0]))).toBe('AA')
    expect(bytesToBase64Url(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe('-_-_')
  })

  it('reads back exactly what it wrote', () => {
    for (let length = 0; length < 40; length += 1) {
      const bytes = new Uint8Array(length).map((_, index) => (index * 37 + 11) & 0xff)
      expect(bytesToHex(base64UrlToBytes(bytesToBase64Url(bytes)))).toBe(bytesToHex(bytes))
    }
  })

  it('rejects padded, non-canonical or malformed base64url', () => {
    // Padding is not part of the representation.
    expect(() => base64UrlToBytes('AA==')).toThrowError()
    // Standard base64 characters are not base64url characters.
    expect(() => base64UrlToBytes('A+/A')).toThrowError()
    // Non-zero trailing bits are a second encoding of the same bytes; Rust rejects them too.
    expect(() => base64UrlToBytes('AB')).toThrowError()
    expect(bytesToHex(base64UrlToBytes('AA'))).toBe('00')
  })

  it('renders unsigned 64-bit counters as decimal strings', () => {
    expect(u64ToJson(0n)).toBe('0')
    expect(u64ToJson(2n ** 64n - 1n)).toBe('18446744073709551615')
    expect(() => u64ToJson(2n ** 64n)).toThrowError()
    expect(() => u64ToJson(-1n)).toThrowError()
  })

  it('reads a counter from a decimal string, and from a number for diagnostics', () => {
    expect(jsonToU64('18446744073709551615')).toBe(2n ** 64n - 1n)
    expect(jsonToU64(41)).toBe(41n)
    expect(() => jsonToU64('041')).toThrowError()
    expect(() => jsonToU64('-1')).toThrowError()
    expect(() => jsonToU64(1.5)).toThrowError()
    expect(() => jsonToU64(Number.MAX_SAFE_INTEGER + 2)).toThrowError()
  })

  it('renders identifiers as canonical hyphenated text', () => {
    const bytes = hexToBytes('b4a1bc38157d4e84bf521137b15b462b')
    expect(uuidToJson(bytes)).toBe('b4a1bc38-157d-4e84-bf52-1137b15b462b')
    expect(bytesToHex(jsonToUuid('b4a1bc38-157d-4e84-bf52-1137b15b462b'))).toBe(
      'b4a1bc38157d4e84bf521137b15b462b'
    )
    expect(() => uuidToJson(new Uint8Array(15))).toThrowError()
    expect(() => jsonToUuid('not-a-uuid')).toThrowError()
  })
})
