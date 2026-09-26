import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { base64UrlToBytes } from '../src/index.js'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

/**
 * How many bytes each fixed-width definition carries, and `null` for a byte string of any length.
 *
 * Every definition the schema encodes as base64url is named here, so a new one fails the test
 * below until its width is stated rather than being passed over.
 */
const WIDTHS: Readonly<Record<string, number | null>> = {
  AuthorisationKey: 32,
  Bytes: null,
  Digest256: 32,
  EndpointKey: 32,
  KeyId: 32,
  Mac256: 32,
  Nonce192: 24,
  Nonce256: 32,
  NotificationPreviewKey: 32,
  RelayInstanceKey: 32,
  SecretBytes32: 32,
  ServiceAdmissionKey: 32,
  Signature64: 64,
  StoredEnvelopeKey: 32
}

/** The bytes a text decodes to, or `null` when the decoder refuses it. */
function decoded (text: string): Uint8Array | null {
  try {
    return base64UrlToBytes(text)
  } catch {
    return null
  }
}

/** A text of `length` symbols: a body that uses the whole alphabet, then `last`. */
function textOf (length: number, last: string): string {
  let body = ''
  for (let index = 0; index + 1 < length; index += 1) {
    body += ALPHABET[(index * 7) % ALPHABET.length]
  }
  return length === 0 ? '' : body + last
}

describe('the base64url patterns the schema publishes', () => {
  it('admit exactly the text the decoder reads, at every length and with every last symbol', () => {
    // KR-REQ-04.08 and KR-REQ-04.19: bytes travel in JSON as unpadded base64url, and the schema
    // generated from the Rust types admits exactly the canonical encodings the runtime decoders
    // read: the right length, and a last symbol whose bits past the last byte are zero.
    const schema = JSON.parse(
      readFileSync(join(packageRoot, 'schema', 'kalareach-protocol.schema.json'), 'utf8')
    ) as { $defs: Record<string, { contentEncoding?: string, pattern?: string }> }
    const encoded = Object.entries(schema.$defs).filter(
      ([, definition]) => definition.contentEncoding === 'base64url'
    )
    expect(encoded.map(([name]) => name).sort()).toEqual(Object.keys(WIDTHS).sort())

    const lastSymbols = [...ALPHABET, '=', '+', '/', '.']
    for (const [name, definition] of encoded) {
      expect(definition.pattern, name).toBeDefined()
      const pattern = new RegExp(definition.pattern ?? '')
      const width = WIDTHS[name]
      // Every residue of the length several times over, and past the longest fixed width.
      for (let length = 0; length <= 90; length += 1) {
        for (const last of lastSymbols) {
          const text = textOf(length, last)
          const bytes = decoded(text)
          const reads = bytes !== null && (width === null || bytes.length === width)
          expect(pattern.test(text), `${name}: ${length} symbols ending in ${last}`).toBe(reads)
        }
      }
    }
  })

  it('refuse a last symbol that carries bits past the last byte', () => {
    const schema = JSON.parse(
      readFileSync(join(packageRoot, 'schema', 'kalareach-protocol.schema.json'), 'utf8')
    ) as { $defs: Record<string, { pattern: string }> }
    // Two encodings of one key: the canonical one and one whose last symbol sets an unused bit.
    const key = new RegExp(schema.$defs.AuthorisationKey.pattern)
    expect(key.test('A'.repeat(43))).toBe(true)
    expect(key.test('A'.repeat(42) + 'B')).toBe(false)
    expect(() => base64UrlToBytes('A'.repeat(42) + 'B')).toThrowError()
    // And a length no encoding has, which a byte string of any length refuses as well.
    const bytes = new RegExp(schema.$defs.Bytes.pattern)
    expect(bytes.test('AAAAA')).toBe(false)
    expect(bytes.test('AAAAAA')).toBe(true)
  })
})

describe('a refused base64url text', () => {
  /** What the decoder says of `text`, which it refuses. */
  function refusal (text: string): string {
    try {
      base64UrlToBytes(text)
    } catch (error) {
      return (error as Error).message
    }
    throw new Error('the text decodes')
  }

  it('names the rule and the offset, never the symbol it refused', () => {
    for (const planted of ['~', '§', '€', '"kr-marker-7c1e"', '\u0000']) {
      const said = refusal(`AAAA${planted}AAA`)
      expect(said).toBe('the symbol at offset 4 is not a base64url symbol')
      expect(said.includes(planted)).toBe(false)
      expect(said.includes(JSON.stringify(planted))).toBe(false)
    }
  })

  it('names a length no encoding has, a last symbol that sets bits past the last byte, and padding', () => {
    expect(refusal('AAAAA')).toBe('5 symbols is not the length of any base64url encoding')
    expect(refusal('AB')).toBe('the last symbol, at offset 1, sets bits past the last byte')
    expect(refusal('AA==')).toBe('unpadded base64url carries no padding')
  })

  it('decodes a valid text as before', () => {
    expect(Array.from(base64UrlToBytes('a3ItbWFya2VyLTdjMWU'))).toEqual(
      Array.from(new TextEncoder().encode('kr-marker-7c1e'))
    )
    expect(base64UrlToBytes('').length).toBe(0)
  })
})
