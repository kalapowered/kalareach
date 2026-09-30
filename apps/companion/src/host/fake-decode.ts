/**
 * A method's parameters, read the way native code reads them before anything is sent.
 *
 * Every command that performs a method parses the page's JSON into that method's own Rust type:
 * the fields it declares and no other, each in the form the protocol's JSON gives it. An identifier
 * is a hyphenated UUID, a counter is a decimal string without leading zeros or a whole number, and
 * prompt text is one to 65,536 bytes of UTF-8. A map native code would not read is refused with
 * `INVALID_ARGUMENT` before anything is asked of a host. The scripted host reads with the same rules,
 * so a page that passes against it sends what a real host takes.
 */

import { FakeHostError } from './fake'

/** One value's shape, as the method's type declares it. */
export type Shape =
  | { readonly kind: 'string' }
  | { readonly kind: 'opaque' }
  | { readonly kind: 'uuid' }
  | { readonly kind: 'u64' }
  | { readonly kind: 'bool' }
  | { readonly kind: 'prompt' }
  | { readonly kind: 'nullable'; readonly of: Shape }
  | { readonly kind: 'enum'; readonly values: readonly string[] }
  | { readonly kind: 'array'; readonly of: Shape }
  | { readonly kind: 'object'; readonly fields: Readonly<Record<string, Shape>> }
  | { readonly kind: 'variant'; readonly variants: Readonly<Record<string, Shape>> }

export const text: Shape = { kind: 'string' }
/** An opaque identifier: one to 256 bytes with no control character. */
export const opaque: Shape = { kind: 'opaque' }
export const uuid: Shape = { kind: 'uuid' }
export const u64: Shape = { kind: 'u64' }
export const bool: Shape = { kind: 'bool' }
/** Prompt or steering text: one to 65,536 bytes of UTF-8. */
export const prompt: Shape = { kind: 'prompt' }
export const nullable = (of: Shape): Shape => ({ kind: 'nullable', of })
export const oneOf = (...values: string[]): Shape => ({ kind: 'enum', values })
export const arrayOf = (of: Shape): Shape => ({ kind: 'array', of })
export const object = (fields: Readonly<Record<string, Shape>>): Shape => ({
  kind: 'object',
  fields
})
/** An externally tagged union: exactly one of the named keys, holding its own shape. */
export const variant = (variants: Readonly<Record<string, Shape>>): Shape => ({
  kind: 'variant',
  variants
})

/** The greatest value of an unsigned 64-bit counter. */
const U64_GREATEST = 2n ** 64n - 1n

/** The most bytes an opaque identifier holds. */
const MAX_OPAQUE_BYTES = 256

/** The most bytes of prompt or steering text one call carries. */
export const MAX_PROMPT_BYTES = 65_536

function bytesOf(value: string): number {
  return new TextEncoder().encode(value).length
}

/** Why `value` is not `shape`, naming where, or null when it is. */
export function problemOf(value: unknown, shape: Shape, at: string): string | null {
  switch (shape.kind) {
    case 'string':
      return typeof value === 'string' ? null : `\`${at}\` is text`
    case 'opaque':
      return typeof value === 'string' &&
        value.length > 0 &&
        bytesOf(value) <= MAX_OPAQUE_BYTES &&
        !/\p{Cc}/u.test(value)
        ? null
        : `\`${at}\` is an identifier of 1 to ${MAX_OPAQUE_BYTES} bytes`
    case 'uuid':
      return typeof value === 'string' &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)
        ? null
        : `\`${at}\` is not an identifier`
    case 'u64': {
      if (typeof value === 'number') {
        return Number.isSafeInteger(value) && value >= 0 ? null : `\`${at}\` is not a counter`
      }
      if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
        return `\`${at}\` is not a counter as a decimal string without leading zeros`
      }
      return BigInt(value) <= U64_GREATEST ? null : `\`${at}\` is past a counter's range`
    }
    case 'bool':
      return typeof value === 'boolean' ? null : `\`${at}\` is true or false`
    case 'prompt':
      return typeof value === 'string' && value.length > 0 && bytesOf(value) <= MAX_PROMPT_BYTES
        ? null
        : `\`${at}\` is 1 to ${MAX_PROMPT_BYTES} bytes of text; longer content belongs in a draft`
    case 'nullable':
      return value === null ? null : problemOf(value, shape.of, at)
    case 'enum':
      return typeof value === 'string' && shape.values.includes(value)
        ? null
        : `\`${at}\` is one of ${shape.values.join(', ')}`
    case 'array': {
      if (!Array.isArray(value)) return `\`${at}\` is a list`
      for (const [index, each] of value.entries()) {
        const problem = problemOf(each, shape.of, `${at}[${index}]`)
        if (problem !== null) return problem
      }
      return null
    }
    case 'object': {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return `\`${at}\` is a map`
      }
      const fields = value as Record<string, unknown>
      const unknown = Object.keys(fields).find((key) => !(key in shape.fields))
      if (unknown !== undefined) return `unknown field \`${unknown}\``
      for (const [key, each] of Object.entries(shape.fields)) {
        if (!(key in fields)) return `missing field \`${key}\``
        const problem = problemOf(fields[key], each, at.length > 0 ? `${at}.${key}` : key)
        if (problem !== null) return problem
      }
      return null
    }
    case 'variant': {
      if (typeof value === 'string' && value in shape.variants) return null
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return `\`${at}\` is one of ${Object.keys(shape.variants).join(', ')}`
      }
      const keys = Object.keys(value)
      const [key] = keys
      if (keys.length !== 1 || key === undefined || !(key in shape.variants)) {
        return `\`${at}\` is one of ${Object.keys(shape.variants).join(', ')}`
      }
      const inner = shape.variants[key]
      return inner === undefined
        ? null
        : problemOf((value as Record<string, unknown>)[key], inner, `${at}.${key}`)
    }
  }
}

/**
 * Reads a method's parameters as native code does, or refuses them with `INVALID_ARGUMENT` in the
 * form a command's refusal arrives: data rather than an Error.
 */
export function decodeParams<T>(params: unknown, shape: Shape): T {
  const problem = problemOf(params, shape, '')
  if (problem !== null) {
    // A command's failure arrives as data rather than as an Error, because that is what crosses
    // the boundary from the native backend.
    // eslint-disable-next-line @typescript-eslint/only-throw-error -- see above
    throw new FakeHostError(
      'INVALID_ARGUMENT',
      `those are not this operation's parameters: ${problem}`
    ).toPayload()
  }
  return params as T
}

/* ---- The shapes of the methods the page calls ------------------------------------------------- */

const subject = object({ session_id: uuid, application_instance_id: uuid })
const target = object({ subject, binding_revision: u64 })

export const AGENT_SUBJECT_PARAMS = object({ subject })
export const AGENT_SNAPSHOT_PARAMS = object({ subject, from_node: nullable(u64) })
export const AGENT_INSPECT_PARAMS = object({ subject, resource_id: uuid })
export const AGENT_PROMPT_PARAMS = object({
  target,
  draft_id: nullable(uuid),
  text: nullable(prompt)
})
export const AGENT_STEER_PARAMS = object({ target, turn_id: opaque, text: prompt })
export const AGENT_CANCEL_PARAMS = object({ target, turn_id: opaque })
export const AGENT_RESPOND_PARAMS = object({ target, resource_id: uuid, option_id: text })

export const ATTENTION_READ_PARAMS = object({
  session_id: nullable(uuid),
  include_acknowledged: bool,
  max_items: u64,
  after: nullable(opaque)
})
export const ATTENTION_ACKNOWLEDGE_PARAMS = object({
  items: arrayOf(object({ key: opaque, revision: u64 }))
})

const reviewSubject = variant({
  completed_turn: object({ session_id: uuid, turn_id: opaque }),
  change_set: object({ session_id: uuid, change_set_id: uuid })
})
export const REVIEW_READ_PARAMS = object({
  session_id: nullable(uuid),
  subject: nullable(reviewSubject),
  max_reviews: u64,
  after: nullable(reviewSubject)
})
export const REVIEW_ACKNOWLEDGE_PARAMS = object({
  session_id: uuid,
  subject: reviewSubject,
  version: u64
})
export const CHANGESET_READ_PARAMS = object({ change_set_id: uuid, version: nullable(u64) })

export const DEVICE_LIST_PARAMS = object({ include_revoked: bool })
export const ROLE_SELECTION = object({
  role: oneOf('viewer', 'reviewer', 'controller', 'owner'),
  history_from_cursor_ms: nullable(u64),
  include_live_screen: bool,
  include_question_respond: bool,
  named_questions: arrayOf(uuid),
  named_approvals: arrayOf(uuid)
})
export const GRANT_CREATE_PARAMS = object({
  session_id: uuid,
  recipient_device_id: uuid,
  parent_grant_id: nullable(uuid),
  selection: ROLE_SELECTION,
  lifetime_ms: nullable(u64),
  accepted_notices: arrayOf(
    oneOf('account_access', 'agent_permissions', 'environment_writes', 'delegation')
  ),
  owner_confirmation: { kind: 'nullable', of: { kind: 'object', fields: {} } }
})
export const GRANT_LIST_PARAMS = object({ session_id: nullable(uuid), include_resolved: bool })

export const ENVIRONMENT_PARAMS = object({ environment_id: uuid })

/** A retained artefact's deletion names the artefact and nothing else. */
export const STORAGE_OBJECT_DELETE_PARAMS = object({ object_id: opaque })

export const HISTORY_PAGE_PARAMS = object({ session_id: uuid, from_cursor: u64, max_bytes: u64 })

export const AGENT_DRAFT_ADD_ATTACHMENT_PARAMS = object({
  draft_id: uuid,
  expected_revision: u64,
  transfer_id: uuid,
  contribution: object({
    operation_id: text,
    accepted_media_types: arrayOf(text),
    max_byte_len: u64,
    max_count: u64,
    insertion_method: oneOf('typed_submission', 'verified_composer_insertion', 'manual_terminal_workflow'),
    external_destination: nullable(text),
    model_media_capability: bool
  })
})
