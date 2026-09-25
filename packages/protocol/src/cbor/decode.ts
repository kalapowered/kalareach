/**
 * The strict decoder.
 *
 * The reader walks the bytes itself because every forbidden representation has to be rejected by
 * its own rule, and a decoded value cannot answer those questions: it cannot say whether a length
 * was indefinite, whether an argument used a longer head than necessary, whether two keys
 * collided, what order the keys arrived in or whether bytes followed the object.
 *
 * `cborg` is still the library that decides what canonical bytes look like: once the byte rules
 * pass, the decoded value goes back through `cborg`'s encoder and the result has to equal the
 * input. That closes the loop, because a reader that quietly normalised something would produce
 * different bytes on the way out.
 *
 * `cborg`'s own decoder is not used for that check. It strips a leading U+FEFF from text strings,
 * so it reads `"\uFEFF"` and `""` as the same key, which is a different interpretation rather than
 * a stricter one.
 */

import { fail } from './errors.js'

import { encodeCanonical } from './encode.js'
import { DEFAULT_LIMITS, type Limits } from './limits.js'
import {
  type CanonicalValue,
  krBool,
  krBytes,
  krInt,
  krNull,
  krText,
  compareKeys,
  krMapFromSorted
} from './value.js'

/**
 * A strict profile for a consumer that calls `cborg.decode` directly.
 *
 * It is not sufficient on its own: it does not check canonical key order, and `cborg` strips a
 * leading U+FEFF from text strings. Use {@link decodeCanonical} for anything that is signed,
 * hashed or framed.
 */
export const STRICT_CBORG_OPTIONS = Object.freeze({
  strict: true,
  allowIndefinite: false,
  allowUndefined: false,
  allowNaN: false,
  allowInfinity: false,
  allowBigInt: true,
  useMaps: true,
  rejectDuplicateMapKeys: true,
  tags: Object.freeze({})
})

// ignoreBOM keeps U+FEFF as an ordinary character. Without it TextDecoder removes a leading byte
// order mark, which would change the string, its length and its position in key order, and would
// make this decoder disagree with the Rust one.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

class Reader {
  private offset = 0
  private items = 0

  constructor (
    private readonly input: Uint8Array,
    private readonly limits: Limits
  ) {}

  position (): number {
    return this.offset
  }

  private remaining (): number {
    return this.input.length - this.offset
  }

  private take (count: number): Uint8Array {
    if (this.remaining() < count) {
      fail('unexpected_end', 'input ended inside a value', this.input.length)
    }
    const slice = this.input.subarray(this.offset, this.offset + count)
    this.offset += count
    return slice
  }

  private countItem (): void {
    this.items += 1
    if (this.items > this.limits.maxItems) {
      fail('count_limit', `item count exceeds the limit of ${this.limits.maxItems}`)
    }
  }

  private readArgument (additional: number, forLength: boolean, headOffset: number): bigint {
    const rule = forLength ? 'non_shortest_length' : 'non_shortest_integer'
    const nonShortest = (): never =>
      fail(rule, 'argument is not encoded in the shortest form', headOffset)
    if (additional <= 23) {
      return BigInt(additional)
    }
    if (additional === 24) {
      const value = BigInt(this.take(1)[0])
      if (value < 24n) {
        nonShortest()
      }
      return value
    }
    const width = additional === 25 ? 2 : additional === 26 ? 4 : 8
    const bytes = this.take(width)
    let value = 0n
    for (const byte of bytes) {
      value = (value << 8n) | BigInt(byte)
    }
    const boundary = additional === 25 ? 0xffn : additional === 26 ? 0xffffn : 0xffff_ffffn
    if (value <= boundary) {
      nonShortest()
    }
    return value
  }

  private checkStringLen (declared: bigint, limit: number): number {
    if (declared > BigInt(limit)) {
      fail('length_limit', `string of ${declared} bytes exceeds the limit of ${limit}`)
    }
    // Reject a declared length the remaining input cannot supply before allocating.
    if (declared > BigInt(this.remaining())) {
      fail('unexpected_end', 'declared length exceeds the remaining input', this.input.length)
    }
    return Number(declared)
  }

  private checkCollectionLen (declared: bigint, bytesPerMember: number): number {
    const limit = this.limits.maxCollectionLen
    if (declared > BigInt(limit)) {
      fail('collection_limit', `collection of ${declared} members exceeds the limit of ${limit}`)
    }
    if (declared * BigInt(bytesPerMember) > BigInt(this.remaining())) {
      fail('unexpected_end', 'declared member count exceeds the remaining input', this.input.length)
    }
    return Number(declared)
  }

  /**
   * Checks the depth and item budgets a collection is about to consume, before it is built.
   */
  private reserveItems (members: number, memberDepth: number): void {
    // An empty collection has no children, so it does not consume the depth its members would.
    if (members > 0 && memberDepth > this.limits.maxDepth) {
      fail('depth_limit', `nesting depth exceeds the limit of ${this.limits.maxDepth}`)
    }
    if (this.items + members > this.limits.maxItems) {
      fail('count_limit', `item count exceeds the limit of ${this.limits.maxItems}`)
    }
  }

  readValue (depth: number): CanonicalValue {
    if (depth > this.limits.maxDepth) {
      fail('depth_limit', `nesting depth exceeds the limit of ${this.limits.maxDepth}`)
    }
    this.countItem()
    const headOffset = this.offset
    const initial = this.take(1)[0]
    const major = initial >> 5
    const additional = initial & 0x1f

    if (additional >= 28) {
      if (additional === 31 && major >= 2 && major <= 5) {
        fail('indefinite_length', 'indefinite lengths are forbidden', headOffset)
      }
      if (additional === 31 && major === 7) {
        fail('break_outside_indefinite', 'break code outside an indefinite item', headOffset)
      }
      fail(
        'reserved_additional_info',
        `additional information ${additional} is reserved`,
        headOffset
      )
    }

    switch (major) {
      case 0:
        return krInt(this.readArgument(additional, false, headOffset))
      case 1:
        return krInt(-1n - this.readArgument(additional, false, headOffset))
      case 2: {
        const declared = this.readArgument(additional, true, headOffset)
        const length = this.checkStringLen(declared, this.limits.maxBytesLen)
        return krBytes(this.take(length).slice())
      }
      case 3:
        return krText(this.readText(additional, headOffset))
      case 4: {
        const declared = this.readArgument(additional, true, headOffset)
        const length = this.checkCollectionLen(declared, 1)
        this.reserveItems(length, depth + 1)
        const items: CanonicalValue[] = []
        for (let index = 0; index < length; index += 1) {
          items.push(this.readValue(depth + 1))
        }
        return { kind: 'array', items }
      }
      case 5:
        return this.readMap(additional, headOffset, depth)
      case 6: {
        const tag = this.readArgument(additional, false, headOffset)
        fail('tag', `tag ${tag} is forbidden`, headOffset)
        break
      }
      default:
        return this.readSimple(additional, headOffset)
    }
    /* c8 ignore next */
    throw new Error('unreachable')
  }

  private readText (additional: number, headOffset: number): string {
    const declared = this.readArgument(additional, true, headOffset)
    const length = this.checkStringLen(declared, this.limits.maxTextLen)
    const bodyOffset = this.offset
    const body = this.take(length)
    try {
      return decoder.decode(body)
    } catch {
      fail('invalid_utf8', 'text string is not valid UTF-8', bodyOffset)
    }
  }

  private readMap (additional: number, headOffset: number, depth: number): CanonicalValue {
    const declared = this.readArgument(additional, true, headOffset)
    const length = this.checkCollectionLen(declared, 2)
    // Two items per entry: the key and its value.
    this.reserveItems(length * 2, depth + 1)
    const entries: Array<readonly [string, CanonicalValue]> = []
    for (let index = 0; index < length; index += 1) {
      this.countItem()
      const keyOffset = this.offset
      if (this.remaining() < 1) {
        fail('unexpected_end', 'input ended before a map key', this.input.length)
      }
      const keyInitial = this.input[keyOffset]
      if (keyInitial >> 5 !== 3) {
        fail('non_text_map_key', 'map keys must be text strings', keyOffset)
      }
      const keyAdditional = keyInitial & 0x1f
      // A key head carries the same reserved and indefinite rules as any other head, and it has to
      // be checked here: readText would otherwise be handed an argument it cannot read.
      if (keyAdditional >= 28) {
        if (keyAdditional === 31) {
          fail('indefinite_length', 'indefinite lengths are forbidden', keyOffset)
        }
        fail(
          'reserved_additional_info',
          `additional information ${keyAdditional} is reserved`,
          keyOffset
        )
      }
      this.offset += 1
      const key = this.readText(keyAdditional, keyOffset)
      if (entries.length > 0) {
        const previous = entries[entries.length - 1][0]
        const order = compareKeys(previous, key)
        if (order === 0) {
          fail('duplicate_key', 'duplicate map key', keyOffset)
        }
        if (order > 0) {
          fail('unsorted_map_keys', 'map keys are not in canonical order', keyOffset)
        }
      }
      entries.push([key, this.readValue(depth + 1)] as const)
    }
    return krMapFromSorted(entries)
  }

  private readSimple (additional: number, headOffset: number): CanonicalValue {
    switch (additional) {
      case 20:
        return krBool(false)
      case 21:
        return krBool(true)
      case 22:
        return krNull()
      case 23:
        fail('undefined', 'undefined is forbidden', headOffset)
        break
      case 24: {
        const value = this.take(1)[0]
        fail('simple_value', `simple value ${value} is forbidden`, headOffset)
        break
      }
      case 25:
      case 26:
      case 27:
        fail('float', 'floats are forbidden', headOffset)
        break
      default:
        fail('simple_value', `simple value ${additional} is forbidden`, headOffset)
    }
    /* c8 ignore next */
    throw new Error('unreachable')
  }
}

/**
 * Decodes exactly one canonical object.
 *
 * Throws a {@link KrCborError} naming the first rule the input breaks.
 */
export function decodeCanonical (bytes: Uint8Array, limits: Limits = DEFAULT_LIMITS): CanonicalValue {
  if (bytes.length > limits.maxMessageLen) {
    fail('input_too_large', `input of ${bytes.length} bytes exceeds ${limits.maxMessageLen}`)
  }
  if (bytes.length === 0) {
    fail('empty_input', 'a KR-CBOR-1 message is exactly one object')
  }
  const reader = new Reader(bytes, limits)
  const value = reader.readValue(1)
  const remaining = bytes.length - reader.position()
  if (remaining > 0) {
    fail('trailing_bytes', `${remaining} trailing byte(s) after the top-level object`)
  }
  assertCanonical(bytes, value)
  return value
}

/**
 * Re-encodes the decoded value and requires the bytes back.
 *
 * Every rule is already checked while reading, so this should be unreachable. It is here because
 * canonicity is what signatures depend on: a reader that normalised something instead of rejecting
 * it would show up here as different bytes rather than as a valid signature over the wrong value.
 */
function assertCanonical (bytes: Uint8Array, value: CanonicalValue): void {
  const reencoded = encodeCanonical(value)
  if (reencoded.length !== bytes.length || reencoded.some((byte, index) => byte !== bytes[index])) {
    fail('non_canonical', 'the decoded value does not re-encode to the input bytes')
  }
}
