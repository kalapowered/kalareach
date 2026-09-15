/**
 * Typed KR-CBOR-1 failures.
 *
 * Every rule name matches `CborError::rule` in the Rust crate, so the shared fixtures assert the
 * same error class in both languages.
 */

/** The stable rule identifiers a decoder can report. */
export const CBOR_RULES = [
  'empty_input',
  'unexpected_end',
  'trailing_bytes',
  'input_too_large',
  'non_shortest_integer',
  'non_shortest_length',
  'indefinite_length',
  'break_outside_indefinite',
  'reserved_additional_info',
  'tag',
  'float',
  'undefined',
  'simple_value',
  'non_text_map_key',
  'duplicate_key',
  'unsorted_map_keys',
  'invalid_utf8',
  'depth_limit',
  'count_limit',
  'collection_limit',
  'length_limit',
  'integer_out_of_range',
  'non_canonical',
  'unrepresentable'
] as const

/** One stable rule identifier. */
export type CborRule = (typeof CBOR_RULES)[number]

/** A KR-CBOR-1 validation, encoding or decoding failure. */
export class KrCborError extends Error {
  /** The rule the input broke. */
  readonly rule: CborRule

  /** Byte offset the failure was found at, where one applies. */
  readonly offset?: number

  constructor (rule: CborRule, message: string, offset?: number) {
    super(`${rule}: ${message}`)
    this.name = 'KrCborError'
    this.rule = rule
    this.offset = offset
  }
}

/** Throws a typed failure. */
export function fail (rule: CborRule, message: string, offset?: number): never {
  throw new KrCborError(rule, message, offset)
}
