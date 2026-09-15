/**
 * The validated KR-CBOR-1 value tree.
 *
 * The shape mirrors `kr_cbor::CanonicalValue` in Rust: integers inside CBOR's 64-bit argument
 * range, byte strings, valid UTF-8 text, arrays, text-keyed maps, booleans and null. A map keeps
 * its entries in canonical key order, so encoding a value cannot produce non-canonical bytes.
 */

import { fail } from './errors.js'

/** Smallest integer the profile admits, -2^64. */
export const INTEGER_MIN = -(2n ** 64n)

/** Largest integer the profile admits, 2^64 - 1. */
export const INTEGER_MAX = 2n ** 64n - 1n

/** A value in the KR-CBOR-1 profile. */
export type CanonicalValue =
  | { readonly kind: 'null' }
  | { readonly kind: 'bool', readonly value: boolean }
  | { readonly kind: 'int', readonly value: bigint }
  | { readonly kind: 'bytes', readonly value: Uint8Array }
  | { readonly kind: 'text', readonly value: string }
  | { readonly kind: 'array', readonly items: readonly CanonicalValue[] }
  | { readonly kind: 'map', readonly entries: ReadonlyArray<readonly [string, CanonicalValue]> }

const encoder = new TextEncoder()

/** Schema-declared null. Null is a value, never an omitted field. */
export function krNull (): CanonicalValue {
  return { kind: 'null' }
}

/** A boolean. */
export function krBool (value: boolean): CanonicalValue {
  return { kind: 'bool', value }
}

/**
 * An integer, rejected when it falls outside the 64-bit argument range.
 *
 * A JavaScript number is accepted only when it is an exact integer. Above 2^53 a number has
 * already lost digits, so converting it would silently encode a different value.
 */
export function krInt (value: bigint | number): CanonicalValue {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    fail('integer_out_of_range', `${value} is not an exact integer; pass a bigint`)
  }
  const big = typeof value === 'bigint' ? value : BigInt(value)
  if (big < INTEGER_MIN || big > INTEGER_MAX) {
    fail('integer_out_of_range', `${big} is outside the 64-bit argument range`)
  }
  return { kind: 'int', value: big }
}

/** A byte string. Raw terminal bytes need not be valid UTF-8 and travel here. */
export function krBytes (value: Uint8Array): CanonicalValue {
  return { kind: 'bytes', value }
}

/** Matches a surrogate code unit that has no partner, which cannot be encoded as UTF-8. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

/**
 * A text string. Never normalised or case folded.
 *
 * A JavaScript string can hold an unpaired surrogate, which has no UTF-8 encoding. `TextEncoder`
 * would replace it with U+FFFD, so two different strings could encode to the same bytes. Such a
 * string is rejected rather than silently repaired.
 */
export function krText (value: string): CanonicalValue {
  if (LONE_SURROGATE.test(value)) {
    fail('invalid_utf8', 'text contains an unpaired surrogate and has no UTF-8 encoding')
  }
  return { kind: 'text', value }
}

/** An array. */
export function krArray (items: readonly CanonicalValue[]): CanonicalValue {
  return { kind: 'array', items }
}

/**
 * A map, sorted into canonical key order.
 *
 * Duplicate keys are rejected: byte-distinct keys are distinct, and no normalisation happens here.
 */
export function krMap (
  entries: Iterable<readonly [string, CanonicalValue]>
): CanonicalValue {
  const sorted = [...entries].sort((left, right) => compareKeys(left[0], right[0]))
  for (let index = 1; index < sorted.length; index += 1) {
    if (sorted[index - 1][0] === sorted[index][0]) {
      fail('duplicate_key', `duplicate map key ${JSON.stringify(sorted[index][0])}`)
    }
  }
  return { kind: 'map', entries: sorted }
}

/** Builds a map from already sorted entries, rejecting a wrong wire order. */
export function krMapFromSorted (
  entries: ReadonlyArray<readonly [string, CanonicalValue]>
): CanonicalValue {
  for (let index = 1; index < entries.length; index += 1) {
    const previous = entries[index - 1][0]
    const current = entries[index][0]
    const order = compareKeys(previous, current)
    if (order === 0) {
      fail('duplicate_key', `duplicate map key ${JSON.stringify(current)}`)
    }
    if (order > 0) {
      fail(
        'unsorted_map_keys',
        `map keys ${JSON.stringify(previous)} and ${JSON.stringify(current)} are not in canonical order`
      )
    }
  }
  return { kind: 'map', entries }
}

/**
 * Orders two map keys the way section 23 requires.
 *
 * The rule is the bytewise order of the complete encoded key. For a text key the head encodes the
 * length and rises strictly with it, so this is the length of the UTF-8 bytes first and then those
 * bytes. It is not the order of the key text: "z" sorts before "aa".
 */
export function compareKeys (left: string, right: string): number {
  const a = encoder.encode(left)
  const b = encoder.encode(right)
  if (a.length !== b.length) {
    return a.length < b.length ? -1 : 1
  }
  for (let index = 0; index < a.length; index += 1) {
    if (a[index] !== b[index]) {
      return a[index] < b[index] ? -1 : 1
    }
  }
  return 0
}

/** Structural equality, used by the conformance tests. */
export function valuesEqual (left: CanonicalValue, right: CanonicalValue): boolean {
  if (left.kind !== right.kind) {
    return false
  }
  switch (left.kind) {
    case 'null':
      return true
    case 'bool':
      return left.value === (right as { value: boolean }).value
    case 'int':
      return left.value === (right as { value: bigint }).value
    case 'text':
      return left.value === (right as { value: string }).value
    case 'bytes': {
      const other = (right as { value: Uint8Array }).value
      return (
        left.value.length === other.length &&
        left.value.every((byte, index) => byte === other[index])
      )
    }
    case 'array': {
      const other = (right as { items: readonly CanonicalValue[] }).items
      return (
        left.items.length === other.length &&
        left.items.every((item, index) => valuesEqual(item, other[index]))
      )
    }
    case 'map': {
      const other = (right as {
        entries: ReadonlyArray<readonly [string, CanonicalValue]>
      }).entries
      return (
        left.entries.length === other.length &&
        left.entries.every(
          ([key, value], index) =>
            key === other[index][0] && valuesEqual(value, other[index][1])
        )
      )
    }
  }
}

/** Looks one key up in a map value. */
export function mapGet (value: CanonicalValue, key: string): CanonicalValue | undefined {
  if (value.kind !== 'map') {
    return undefined
  }
  return value.entries.find((entry) => entry[0] === key)?.[1]
}

/**
 * Checks a value that was built by hand rather than decoded.
 *
 * The constructors above enforce their own rules, but a caller can also write an object literal,
 * so the encoder validates the whole tree before handing it over. It checks integer range, text
 * that has a UTF-8 encoding, and map entries that are in canonical order with no duplicates.
 */
export function validateCanonical (value: CanonicalValue): void {
  switch (value.kind) {
    case 'null':
    case 'bool':
    case 'bytes':
      return
    case 'int':
      if (value.value < INTEGER_MIN || value.value > INTEGER_MAX) {
        fail('integer_out_of_range', `${value.value} is outside the 64-bit argument range`)
      }
      return
    case 'text':
      if (LONE_SURROGATE.test(value.value)) {
        fail('invalid_utf8', 'text contains an unpaired surrogate and has no UTF-8 encoding')
      }
      return
    case 'array':
      for (const item of value.items) {
        validateCanonical(item)
      }
      return
    case 'map':
      for (let index = 0; index < value.entries.length; index += 1) {
        const [key, entry] = value.entries[index]
        if (LONE_SURROGATE.test(key)) {
          fail('invalid_utf8', 'a map key contains an unpaired surrogate')
        }
        if (index > 0) {
          const order = compareKeys(value.entries[index - 1][0], key)
          if (order === 0) {
            fail('duplicate_key', `duplicate map key ${JSON.stringify(key)}`)
          }
          if (order > 0) {
            fail('unsorted_map_keys', `map key ${JSON.stringify(key)} is out of canonical order`)
          }
        }
        validateCanonical(entry)
      }
  }
}
