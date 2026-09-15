/**
 * The exact bytes an organisation's policy-signing key covers.
 *
 * A signature is over bytes, never over JSON. Two encoders that agree on a document can still
 * disagree on its text, and a verifier that re-serialises what it received is checking its own
 * encoder rather than the issuer's statement. So each payload is built here, once, from the JSON
 * representation the managed service carries, and both the issuer and a verifier cover identical
 * bytes. The Rust host builds the same payloads from `kr_protocol::account`; `fixtures/accounts`
 * publishes the bytes both languages must produce.
 *
 * Each schema is closed. A payload with a field nobody agreed on, a counter that is not an exact
 * unsigned integer, or a right outside the vocabulary is refused rather than narrowed to the part
 * this version understands: signing what is left of a document after discarding what a verifier
 * did not recognise is exactly the strip-and-verify behaviour section 23 forbids.
 */

import { encodeCanonical } from './cbor/encode.js'
import {
  krArray,
  krBytes,
  krInt,
  krMap,
  krNull,
  krText,
  type CanonicalValue
} from './cbor/value.js'
import { base64UrlToBytes, jsonToU64, jsonToUuid } from './json.js'
import type {
  ActionRight,
  MembershipLeasePayload,
  PolicyAuthorityHeadPayload,
  PolicyAuthorityLinkPayload
} from './generated/protocol.js'

/** The domain a membership lease signature covers. */
export const MEMBERSHIP_LEASE_DOMAIN = 'kr-membership-lease/1'

/** The domain one policy-signing authority link covers. */
export const POLICY_AUTHORITY_DOMAIN = 'kr-policy-authority/1'

/** The domain the statement of the current revision covers. */
export const POLICY_AUTHORITY_HEAD_DOMAIN = 'kr-policy-authority-head/1'

/** The longest a membership lease may last, in milliseconds. */
export const MEMBERSHIP_LEASE_MAX_LIFETIME_MS = 15 * 60 * 1000

/** How often a holder asks for the next lease, in milliseconds. */
export const MEMBERSHIP_LEASE_REFRESH_INTERVAL_MS = 5 * 60 * 1000

/** The longest a head statement may last, in milliseconds. */
export const POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS = MEMBERSHIP_LEASE_MAX_LIFETIME_MS

/** Raw bytes in an Ed25519 public key. */
export const ED25519_PUBLIC_KEY_BYTES = 32

/** Raw bytes in an Ed25519 signature. */
export const ED25519_SIGNATURE_BYTES = 64

/** An organisation role, from the least to the most authority. */
export type TeamRole = MembershipLeasePayload['role']

/** The roles, from the least to the most authority. */
export const TEAM_ROLES: readonly TeamRole[] = ['viewer', 'reviewer', 'controller', 'owner']

/**
 * The most each role may ever carry.
 *
 * A role is a label for a ceiling; a host authorises from the rights a lease names, never from the
 * label. Answering a question is inside a viewer's and a reviewer's ceiling because an organisation
 * may invite one to answer, which is not the same as carrying it by default.
 */
export const ROLE_MAXIMUM_GRANTS: Readonly<Record<TeamRole, readonly ActionRight[]>> = {
  viewer: ['question.respond', 'session.view'],
  reviewer: ['files.read', 'question.respond', 'session.view'],
  controller: ['files.read', 'question.respond', 'session.view', 'terminal.input'],
  owner: [
    'files.read',
    'question.respond',
    'session.close',
    'session.share',
    'session.view',
    'terminal.input'
  ]
}

/** Raised when a payload does not match the closed schema its signature covers. */
export class AccountSchemaError extends Error {
  constructor (message: string) {
    super(message)
    this.name = 'AccountSchemaError'
  }
}

function refuse (message: string): never {
  throw new AccountSchemaError(message)
}

/** The fields of a closed schema, with nothing else beside them. */
function closed (what: string, value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    refuse(`${what} is an object`)
  }
  const record = value as Record<string, unknown>
  for (const key of Object.keys(record)) {
    if (!fields.includes(key)) {
      refuse(`${what} has no field ${JSON.stringify(key)}`)
    }
  }
  for (const field of fields) {
    if (!Object.hasOwn(record, field)) {
      refuse(`${what} is missing ${JSON.stringify(field)}`)
    }
  }
  return record
}

/** An identifier the protocol carries as 16 bytes, from its hyphenated text. */
function identifier (what: string, value: unknown): CanonicalValue {
  if (typeof value !== 'string') {
    refuse(`${what} is a hyphenated identifier`)
  }
  try {
    return krBytes(jsonToUuid(value))
  } catch (error) {
    refuse(`${what} is a hyphenated identifier: ${error instanceof Error ? error.message : 'invalid'}`)
  }
}

/** Longest an opaque identifier may be, in bytes, as `kr_protocol::ids` bounds one. */
const MAX_OPAQUE_ID_BYTES = 256

/**
 * An identifier the service mints and the protocol carries verbatim.
 *
 * A host never resolves it: it names a person to an organisation. It is bounded
 * and free of control characters, so a peer cannot force an unbounded
 * allocation, or a line break, through an identifier field.
 */
function opaqueIdentifier (what: string, value: unknown): CanonicalValue {
  if (typeof value !== 'string' || value === '') {
    refuse(`${what} is a non-empty identifier`)
  }
  if (new TextEncoder().encode(value).length > MAX_OPAQUE_ID_BYTES) {
    refuse(`${what} is at most ${String(MAX_OPAQUE_ID_BYTES)} bytes`)
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    refuse(`${what} carries no control characters`)
  }
  return krText(value)
}

/**
 * A counter that travelled as a decimal string, as a canonical integer.
 *
 * JSON carries an unsigned 64-bit value as text because a JSON number cannot hold one exactly. A
 * number is refused here rather than converted, even one a reader could convert exactly: `2`, `2.0`
 * and `2e0` are one JavaScript value and three documents, and the host refuses all three. Two
 * producers that disagreed about which of them to send would otherwise sign identical bytes from
 * documents a strict reader treats as different.
 */
function counter (what: string, value: unknown): CanonicalValue {
  if (typeof value !== 'string') {
    refuse(`${what} is an unsigned counter written as a decimal string`)
  }
  try {
    return krInt(jsonToU64(value))
  } catch (error) {
    refuse(`${what} is an unsigned counter: ${error instanceof Error ? error.message : 'invalid'}`)
  }
}

/** A fixed-width scalar read from its base64url text. */
function scalar (what: string, value: unknown, width: number): Uint8Array {
  if (typeof value !== 'string') {
    refuse(`${what} is unpadded base64url`)
  }
  let bytes: Uint8Array
  try {
    bytes = base64UrlToBytes(value)
  } catch (error) {
    refuse(`${what} is unpadded base64url: ${error instanceof Error ? error.message : 'invalid'}`)
  }
  if (bytes.length !== width) {
    refuse(`${what} is ${String(width)} bytes, not ${String(bytes.length)}`)
  }
  return bytes
}

/** An Ed25519 public key read from the base64url text a response carries. */
export function publicKeyBytes (value: unknown): Uint8Array {
  return scalar('an Ed25519 public key', value, ED25519_PUBLIC_KEY_BYTES)
}

/** An Ed25519 signature read from the base64url text a response carries. */
export function signatureBytes (value: unknown): Uint8Array {
  return scalar('an Ed25519 signature', value, ED25519_SIGNATURE_BYTES)
}

function signingInput (domain: string, payload: CanonicalValue): Uint8Array {
  return encodeCanonical(krArray([krText(domain), payload]))
}

const LEASE_FIELDS = [
  'account_id',
  'expires_at_ms',
  'issued_at_ms',
  'key_revision',
  'maximum_grants',
  'organisation_id',
  'role'
] as const

/**
 * The closed action-right vocabulary, in the order the protocol declares it.
 *
 * A lease names rights from this vocabulary and no others, so a host intersects what a lease says
 * with the grants it already understands rather than with a second set of names.
 */
export const ACTION_RIGHTS: readonly ActionRight[] = [
  'session.view',
  'terminal.input',
  'terminal.geometry',
  'terminal.geometry.transfer',
  'terminal.palette',
  'agent.prompt',
  'agent.cancel',
  'agent.approval.respond',
  'question.respond',
  'files.read',
  'files.upload',
  'files.apply_diff',
  'project.create',
  'workspace.manage',
  'changeset.create',
  'session.create',
  'session.rename',
  'session.close',
  'session.share',
  'automation.manage',
  'host.manage'
]

/**
 * The rights a set carries, in the one order the wire form admits.
 *
 * Rights are ordered by their wire string and carry no duplicates, so a set encodes to the same
 * bytes whatever order an issuer holds it in. A set that is not already in that order is refused
 * rather than sorted: a verifier checks the bytes it received, so re-ordering them here would cover
 * bytes the issuer never sent. An issuer calls {@link canonicalRights} once, before it signs.
 */
function rights (what: string, value: unknown): CanonicalValue {
  if (!Array.isArray(value)) {
    refuse(`${what} is an array`)
  }
  const members: ActionRight[] = []
  for (const member of value as unknown[]) {
    if (typeof member !== 'string' || !(ACTION_RIGHTS as readonly string[]).includes(member)) {
      refuse(`${JSON.stringify(member)} is not an action right`)
    }
    members.push(member as ActionRight)
  }
  for (let index = 1; index < members.length; index += 1) {
    if ((members[index - 1] as string) >= (members[index] as string)) {
      refuse(`${what} is in ascending order without duplicates`)
    }
  }
  return krArray(members.map((right) => krText(right)))
}

/**
 * Sorts and de-duplicates a set of rights into the order a lease states them in.
 *
 * An issuer holding a role's ceiling calls this once and stores the result; the lease it signs
 * then carries the same bytes as a lease any other issuer of the same set would sign.
 */
export function canonicalRights (value: readonly ActionRight[]): ActionRight[] {
  return [...new Set(value)].sort() as ActionRight[]
}

/**
 * The bytes a membership lease is signed over.
 *
 * `CBOR(["kr-membership-lease/1", the payload as a canonical map])`.
 *
 * Everything a standalone authorisation object must cover is here: the type through the domain,
 * the issuing organisation and the key revision that signed it, the account it names, the authority
 * it carries, and when it ends.
 */
export function membershipLeaseSigningInput (payload: MembershipLeasePayload): Uint8Array {
  const record = closed('a membership lease', payload, LEASE_FIELDS)
  const role = record['role']
  if (typeof role !== 'string' || !(TEAM_ROLES as readonly string[]).includes(role)) {
    refuse(`${JSON.stringify(role)} is not a team role`)
  }
  return signingInput(
    MEMBERSHIP_LEASE_DOMAIN,
    krMap([
      ['account_id', opaqueIdentifier('an account identifier', record['account_id'])],
      ['expires_at_ms', counter('a lease expiry', record['expires_at_ms'])],
      ['issued_at_ms', counter('a lease issue time', record['issued_at_ms'])],
      ['key_revision', counter('a key revision', record['key_revision'])],
      ['maximum_grants', rights('a grant ceiling', record['maximum_grants'])],
      ['organisation_id', identifier('an organisation identifier', record['organisation_id'])],
      ['role', krText(role)]
    ])
  )
}

const LINK_FIELDS = [
  'key_revision',
  'not_before_ms',
  'organisation_id',
  'previous_key_revision',
  'public_key'
] as const

/**
 * The bytes one authority-chain link is signed over.
 *
 * `CBOR(["kr-policy-authority/1", the payload as a canonical map])`.
 *
 * The first revision signs its own link and names no predecessor, which is what a host pins. Every
 * later revision is signed by the key of the revision it names, so a host that pinned the first can
 * walk forward to the current key without being told which key to trust, and a link cannot be
 * re-parented under a revision it was not issued against.
 */
export function policyAuthorityLinkSigningInput (payload: PolicyAuthorityLinkPayload): Uint8Array {
  const record = closed('an authority link', payload, LINK_FIELDS)
  const previous = record['previous_key_revision']
  return signingInput(
    POLICY_AUTHORITY_DOMAIN,
    krMap([
      ['key_revision', counter('a key revision', record['key_revision'])],
      ['not_before_ms', counter('an activation time', record['not_before_ms'])],
      ['organisation_id', identifier('an organisation identifier', record['organisation_id'])],
      [
        'previous_key_revision',
        previous === null ? krNull() : counter('a predecessor revision', previous)
      ],
      ['public_key', krBytes(publicKeyBytes(record['public_key']))]
    ])
  )
}

const HEAD_FIELDS = ['expires_at_ms', 'issued_at_ms', 'key_revision', 'organisation_id'] as const

/**
 * The bytes the statement naming the current revision is signed over.
 *
 * `CBOR(["kr-policy-authority-head/1", the payload as a canonical map])`.
 *
 * Any prefix of a chain verifies on its own, so a host handed the first few links cannot tell from
 * the links alone that a later revision exists. This statement is what tells it: it is signed by
 * the key that signs leases now, and it expires, so a captured statement stops being usable and a
 * host that has accepted a later revision refuses one naming an earlier revision. A retained
 * private key of a retired revision can still sign statements naming that revision, which is why
 * rotation destroys it.
 */
export function policyAuthorityHeadSigningInput (payload: PolicyAuthorityHeadPayload): Uint8Array {
  const record = closed('an authority head', payload, HEAD_FIELDS)
  return signingInput(
    POLICY_AUTHORITY_HEAD_DOMAIN,
    krMap([
      ['expires_at_ms', counter('a head expiry', record['expires_at_ms'])],
      ['issued_at_ms', counter('a head issue time', record['issued_at_ms'])],
      ['key_revision', counter('a key revision', record['key_revision'])],
      ['organisation_id', identifier('an organisation identifier', record['organisation_id'])]
    ])
  )
}
