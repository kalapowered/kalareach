/**
 * The strict decoder.
 *
 * The reader walks the bytes itself because every forbidden representation has to be rejected by
 * its own rule, and a decoded value cannot answer those questions: it cannot say whether a length
 * was indefinite, whether an argument used a longer head than necessary, whether two keys
 * collided, what order the keys arrived in or whether bytes followed the object.
 *
 * `cborg` is still the library that reads the wire format: after the byte rules pass, the same
 * bytes go through `cborg.decode` with its strict profile as an independent check. Two readers
 * that disagree mean the input is rejected rather than interpreted.
 */

import { decode as cborgDecode } from 'cborg'

import { fail, KrCborError } from './errors.js'
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

/** The decode profile handed to `cborg`: definite lengths, shortest forms, no tags, no floats. */
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

const decoder = new TextDecoder('utf-8', { fatal: true })

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
      this.offset += 1
      const key = this.readText(keyInitial & 0x1f, keyOffset)
      if (entries.length > 0) {
        const previous = entries[entries.length - 1][0]
        const order = compareKeys(previous, key)
        if (order === 0) {
          fail('duplicate_key', `duplicate map key ${JSON.stringify(key)}`, keyOffset)
        }
        if (order > 0) {
          fail(
            'unsorted_map_keys',
            `map keys ${JSON.stringify(previous)} and ${JSON.stringify(key)} are not in canonical order`,
            keyOffset
          )
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
  crossCheck(bytes)
  return value
}

/**
 * Runs the maintained library over bytes the byte rules already accepted.
 *
 * It cannot report our rule names, so it never decides which rule failed. It is here so that an
 * input only one of the two readers accepts is rejected instead of interpreted.
 */
function crossCheck (bytes: Uint8Array): void {
  try {
    cborgDecode(bytes, STRICT_CBORG_OPTIONS)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new KrCborError('unrepresentable', `the maintained decoder rejected these bytes: ${message}`)
  }
}
