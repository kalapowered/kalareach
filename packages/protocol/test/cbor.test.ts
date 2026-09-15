import { describe, expect, it } from 'vitest'

import {
  CBOR_RULES,
  DEFAULT_LIMITS,
  KrCborError,
  compareKeys,
  decodeCanonical,
  encodeCanonical,
  krInt,
  krMap,
  krText,
  limitsFromFixture,
  sha256,
  signingDigest,
  signingInput,
  valuesEqual
} from '../src/index.js'
import { bytesToHex, findCase, hexToBytes, loadFixture, parseValue } from './fixtures.js'

const VALID_FILES = [
  'integers.json',
  'strings.json',
  'map-ordering.json',
  'null-and-absent.json',
  'structures.json'
] as const

describe.each(VALID_FILES)('%s', (name) => {
  const document = loadFixture('cbor', name)
  const cases = document.cases ?? []

  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(3)
  })

  it.each(cases.map((entry) => [entry.id, entry] as const))(
    '%s encodes to the fixture bytes and decodes back',
    (_id, entry) => {
      const value = parseValue(entry.value)
      expect(bytesToHex(encodeCanonical(value))).toBe(entry.hex)

      const decoded = decodeCanonical(hexToBytes(entry.hex as string))
      expect(valuesEqual(decoded, value)).toBe(true)
      expect(bytesToHex(encodeCanonical(decoded))).toBe(entry.hex)
    }
  )
})

describe('invalid.json', () => {
  const document = loadFixture('cbor', 'invalid.json')
  const cases = document.cases ?? []

  it('covers every rule the Rust decoder can report', () => {
    expect(cases.length).toBeGreaterThanOrEqual(50)
    const covered = new Set(cases.map((entry) => entry.rule))
    for (const rule of CBOR_RULES) {
      // These two are internal invariants with no reachable input.
      if (rule === 'integer_out_of_range' || rule === 'non_canonical' || rule === 'unrepresentable') {
        continue
      }
      expect(covered.has(rule), `no fixture covers ${rule}`).toBe(true)
    }
  })

  it.each(cases.map((entry) => [entry.id, entry] as const))(
    '%s is rejected with the named rule',
    (id, entry) => {
      const limits = limitsFromFixture(entry.limits)
      let thrown: unknown
      try {
        decodeCanonical(hexToBytes(entry.hex as string), limits)
      } catch (error) {
        thrown = error
      }
      expect(thrown, `${id} was accepted`).toBeInstanceOf(KrCborError)
      expect((thrown as KrCborError).rule).toBe(entry.rule)
    }
  )
})

describe('key ordering', () => {
  it('orders by the encoded key, not by the key text', () => {
    expect('aa' < 'z').toBe(true)
    expect(compareKeys('z', 'aa')).toBeLessThan(0)
    const encoded = encodeCanonical(
      krMap([
        ['aa', krInt(2n)],
        ['z', krInt(1n)]
      ])
    )
    expect(bytesToHex(encoded)).toBe('a2617a0162616102')
  })

  it('rejects a duplicate key', () => {
    expect(() =>
      krMap([
        ['a', krInt(1n)],
        ['a', krInt(2n)]
      ])
    ).toThrowError(/duplicate_key/)
  })

  it('agrees with the encoded key bytes across every length boundary', () => {
    const keys = ['', 'a', 'b', 'A', 'z', 'aa', 'ab', 'é', 'a'.repeat(23), 'z'.repeat(23),
      'a'.repeat(24), 'a'.repeat(255), 'a'.repeat(256)]
    for (const left of keys) {
      for (const right of keys) {
        const a = encodeCanonical(krText(left))
        const b = encodeCanonical(krText(right))
        const expected = compareBytes(a, b)
        expect(Math.sign(compareKeys(left, right))).toBe(expected)
      }
    }
  })
})

function compareBytes (a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length)
  for (let index = 0; index < length; index += 1) {
    if (a[index] !== b[index]) {
      return a[index] < b[index] ? -1 : 1
    }
  }
  return Math.sign(a.length - b.length)
}

describe('digests', () => {
  const document = loadFixture('cbor', 'digests.json')

  it.each((document.digest_cases ?? []).map((entry) => [entry.id, entry] as const))(
    '%s produces the fixture bytes and digest',
    async (_id, entry) => {
      const value = parseValue(entry.value)
      const encoded = encodeCanonical(value)
      expect(bytesToHex(encoded)).toBe(entry.hex)
      expect(bytesToHex(await sha256(encoded))).toBe(entry.sha256)
    }
  )

  it.each((document.signing_input_cases ?? []).map((entry) => [entry.id, entry] as const))(
    '%s builds the same domain-separated signing input',
    async (_id, entry) => {
      const elements = (entry.elements ?? []).map(parseValue)
      const input = signingInput(entry.domain as string, elements)
      expect(bytesToHex(input)).toBe(entry.hex)
      expect(bytesToHex(await signingDigest(entry.domain as string, elements))).toBe(entry.sha256)
    }
  )
})

describe('absent versus null', () => {
  it('produces different bytes and different digests', async () => {
    const document = loadFixture('cbor', 'null-and-absent.json')
    const absent = encodeCanonical(parseValue(findCase(document, 'field_absent').value))
    const explicit = encodeCanonical(parseValue(findCase(document, 'field_null').value))
    expect(bytesToHex(absent)).not.toBe(bytesToHex(explicit))
    expect(bytesToHex(await sha256(absent))).toBe(document.digests?.field_absent_sha256)
    expect(bytesToHex(await sha256(explicit))).toBe(document.digests?.field_null_sha256)
  })
})

describe('non-ASCII text', () => {
  it('is never normalised or case folded', () => {
    const document = loadFixture('cbor', 'strings.json')
    const bytesFor = (id: string): string =>
      bytesToHex(encodeCanonical(parseValue(findCase(document, id).value)))
    expect(bytesFor('text_nfc')).not.toBe(bytesFor('text_nfd'))
    expect(bytesFor('text_sharp_s')).not.toBe(bytesFor('text_upper'))
  })
})

describe('value construction', () => {
  it('rejects a JavaScript number that is not an exact integer', () => {
    expect(() => krInt(9007199254740993)).toThrowError(/integer_out_of_range/)
    expect(() => krInt(1.5)).toThrowError(/integer_out_of_range/)
    expect(krInt(9007199254740993n)).toEqual({ kind: 'int', value: 9007199254740993n })
  })

  it('rejects an integer outside the 64-bit argument range', () => {
    expect(() => krInt(2n ** 64n)).toThrowError(/integer_out_of_range/)
    expect(() => krInt(-(2n ** 64n) - 1n)).toThrowError(/integer_out_of_range/)
    expect(bytesToHex(encodeCanonical(krInt(-(2n ** 64n))))).toBe('3bffffffffffffffff')
  })

  it('rejects text with an unpaired surrogate', () => {
    expect(() => krText('\ud800')).toThrowError(/invalid_utf8/)
    expect(() => krText('\udc00')).toThrowError(/invalid_utf8/)
    expect(krText('\ud83d\ude00').kind).toBe('text')
  })

  it('rejects a hand-built map that is unsorted or has duplicate keys', () => {
    expect(() =>
      encodeCanonical({
        kind: 'map',
        entries: [
          ['aa', krInt(1n)],
          ['z', krInt(2n)]
        ]
      })
    ).toThrowError(/unsorted_map_keys/)
    expect(() =>
      encodeCanonical({
        kind: 'map',
        entries: [
          ['a', krInt(1n)],
          ['a', krInt(2n)]
        ]
      })
    ).toThrowError(/duplicate_key/)
  })

  it('preserves a byte order mark as an ordinary character', () => {
    const withMark = encodeCanonical(krText('\ufeffkalareach'))
    const without = encodeCanonical(krText('kalareach'))
    expect(bytesToHex(withMark)).not.toBe(bytesToHex(without))
    const decoded = decodeCanonical(withMark)
    expect(decoded).toEqual({ kind: 'text', value: '\ufeffkalareach' })
  })
})

describe('limits', () => {
  it('rejects a message above the configured bound before decoding', () => {
    expect(() => decodeCanonical(hexToBytes('820102'), limitsFromFixture({ max_message_len: 2 })))
      .toThrowError(/input_too_large/)
  })

  it('uses the same defaults as the Rust crate', () => {
    expect(DEFAULT_LIMITS).toEqual({
      maxMessageLen: 1048576,
      maxDepth: 32,
      maxItems: 65536,
      maxCollectionLen: 4096,
      maxBytesLen: 1048576,
      maxTextLen: 1048576
    })
  })
})
