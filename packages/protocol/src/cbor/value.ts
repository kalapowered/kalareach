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

/** An integer, rejected when it falls outside the 64-bit argument range. */
export function krInt (value: bigint | number): CanonicalValue {
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

/** A text string. Never normalised or case folded. */
export function krText (value: string): CanonicalValue {
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
