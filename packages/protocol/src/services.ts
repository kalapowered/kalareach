/**
 * The mailbox, the authority feed, settings sync, backup manifests and host policy.
 *
 * A managed service meets all five as JSON over HTTPS and holds them to rules it can check without
 * a key: the shape of a sealed item, the bucket its ciphertext was padded to, how long it may live,
 * and — for the four records somebody other than the service verifies — the exact bytes a
 * signature covers. This module is the TypeScript half of `kr_protocol::mailbox`,
 * `kr_protocol::sync`, `kr_protocol::archive` and `kr_protocol::account`: the same domains, the
 * same field names, the same encoding, checked against `fixtures/service/services.json`.
 *
 * Each schema is closed. A record carrying a field nobody agreed on, a counter that is not an exact
 * unsigned integer, or a payload kind outside the vocabulary is refused rather than narrowed to the
 * part this version understands.
 *
 * What is not here is as deliberate as what is. There is no signing input for a mailbox item,
 * because what authenticates one is the box around it; and none for a synchronised object, because
 * what decides a write is a revision comparison rather than a signature.
 */

import { encodeCanonical } from './cbor/encode.js'
import {
  krArray,
  krBool,
  krBytes,
  krInt,
  krMap,
  krNull,
  krText,
  type CanonicalValue
} from './cbor/value.js'
import { base64UrlToBytes, bytesToBase64Url, jsonToU64, jsonToUuid, uuidToJson } from './json.js'
import type {
  ArchiveDescriptor,
  AuthorityRevisionRecord,
  BackupWriterRecordPayload,
  BackupGenerationPublicationPayload,
  EnvelopePlaintext,
  EnvelopeRouting,
  OrganisationPolicyPayload,
  RevocationRequest,
  SealedEnvelope,
  SealedSyncObject,
  SyncObjectRecord
} from './generated/protocol.js'

/** What a mailbox item carries. The set is closed; none of its kinds is an action. */
export type MailboxPayloadType = EnvelopeRouting['payload_type']

/** What a synchronised object is. */
export type SyncObjectKind = SyncObjectRecord['kind']

/** The domain a key identifier is derived under. */
export const KEY_ID_DOMAIN = 'kr-key-id/1'

/** The domain a remote owner's revocation request covers. */
export const REVOCATION_DOMAIN = 'kr-revocation/1'

/** The domain a host's authority revision record covers. */
export const AUTHORITY_REVISION_DOMAIN = 'kr-authority/1'

/** The domain one collection's writer enrolment covers. */
export const BACKUP_WRITER_DOMAIN = 'kr-backup-writer/1'

/** The domain one published backup generation covers. */
export const BACKUP_PUBLICATION_DOMAIN = 'kr-backup-publication/1'

/** The domain one organisation's signed policy covers. */
export const ORGANISATION_POLICY_DOMAIN = 'kr-organisation-policy/1'

/** Bytes `crypto_box_easy` adds to the plaintext it seals. */
export const SEAL_OVERHEAD_BYTES = 16

/** One kibibyte. */
const KIB = 1024

/** The longest a mailbox item may live, in milliseconds. */
export const MAX_MAILBOX_ITEM_LIFETIME_MS = 24 * 60 * 60 * 1000

/** How long a replay identifier is retained past its envelope's expiry, in milliseconds. */
export const REPLAY_ID_RETENTION_MS = 24 * 60 * 60 * 1000

/**
 * The most one stored item may occupy, in bytes.
 *
 * A mailbox item travels as a control message, and section 9 bounds one at 1 MiB. The bound is on
 * the whole stored item, so a producer cannot reach past it by declaring a larger bucket.
 */
export const MAX_MAILBOX_ITEM_BYTES = 1024 * 1024

/** The most items one device's mailbox holds. */
export const MAX_MAILBOX_ITEMS = 1_000

/** The most stored ciphertext one device's mailbox holds, in bytes. */
export const MAX_MAILBOX_BYTES = 32 * 1024 * 1024

/** What a routing record and an item's bookkeeping cost in a mailbox, in bytes. */
export const ROUTING_RECORD_BYTES = 256

/** What one synchronised object's record costs, in bytes. */
export const SYNC_RECORD_BYTES = 256

/** The most plaintext one synchronised object may carry before padding, in bytes. */
export const MAX_SYNC_OBJECT_PLAINTEXT_BYTES = 64 * 1024

/** The most objects one collection may hold. */
export const MAX_SYNC_OBJECTS_PER_COLLECTION = 256

/** The most conflict copies one object retains. */
export const MAX_SYNC_CONFLICT_COPIES = 8

/** The most recipients a public archive descriptor may name. */
export const MAX_ARCHIVE_RECIPIENTS = 128

/** The most bytes a public archive descriptor may be. */
export const MAX_ARCHIVE_DESCRIPTOR_LEN = 64 * 1024

/** Every mailbox payload kind, in the order the protocol declares them. */
export const MAILBOX_PAYLOAD_TYPES: readonly MailboxPayloadType[] = [
  'authority_feed_change',
  'action_receipt',
  'state_reference',
  'signed_authority_object',
  'notification_preview',
  'sync_change'
]

/**
 * The payload kinds that carry authority of their own.
 *
 * A forwarded signed object is authority rather than a state notification, so it is never
 * coalesced and never names a thread: section 10 keeps revocation records outside notification
 * coalescing.
 */
export const AUTHORITY_BEARING_PAYLOAD_TYPES: readonly MailboxPayloadType[] = [
  'signed_authority_object'
]

/** Every synchronised object kind, in the order the protocol declares them. */
export const SYNC_OBJECT_KINDS: readonly SyncObjectKind[] = [
  'settings',
  'draft',
  'client_selection'
]

/** What an organisation permits its members' clients to reach outside KalaReach. */
export const EXTERNAL_PROVIDER_POLICIES: readonly OrganisationPolicyPayload['external_providers'][] =
  ['forbidden', 'organisation_only', 'any']

/** The shortest audit retention an organisation may set, in days. */
export const MIN_AUDIT_RETENTION_DAYS = 30

/** The longest audit retention an organisation may set, in days. */
export const MAX_AUDIT_RETENTION_DAYS = 3_650

/** The most adapters an allowlist may name. */
export const MAX_ADAPTER_ALLOWLIST = 64

/** The longest grant lifetime an organisation policy may permit, in milliseconds. */
export const MAX_POLICY_GRANT_LIFETIME_MS = 90 * 24 * 60 * 60 * 1000

/** The longest a client version string may be, in bytes. */
export const MAX_CLIENT_VERSION_LEN = 64

/** Raised when a record does not match the closed schema its signature or its rules cover. */
export class ServicesSchemaError extends Error {
  constructor (message: string) {
    super(message)
    this.name = 'ServicesSchemaError'
  }
}

function refuse (message: string): never {
  throw new ServicesSchemaError(message)
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
function uuid (what: string, value: unknown): CanonicalValue {
  if (typeof value !== 'string') {
    refuse(`${what} is a hyphenated identifier`)
  }
  try {
    return krBytes(jsonToUuid(value))
  } catch (error) {
    refuse(`${what} is a hyphenated identifier: ${error instanceof Error ? error.message : 'invalid'}`)
  }
}

/** A counter that travelled as a decimal string, as a canonical integer. */
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

/** Opaque bytes read from their unpadded base64url form. */
function opaqueBytes (what: string, value: unknown): Uint8Array {
  if (typeof value !== 'string') {
    refuse(`${what} is unpadded base64url`)
  }
  try {
    return base64UrlToBytes(value)
  } catch (error) {
    refuse(`${what} is unpadded base64url: ${error instanceof Error ? error.message : 'invalid'}`)
  }
}

/** A fixed-width scalar read from its base64url text. */
function fixedBytes (what: string, value: unknown, width: number): Uint8Array {
  const bytes = opaqueBytes(what, value)
  if (bytes.length !== width) {
    refuse(`${what} is ${String(width)} bytes, not ${String(bytes.length)}`)
  }
  return bytes
}

/** A member of a closed vocabulary. */
function member<T extends string> (what: string, value: unknown, values: readonly T[]): T {
  if (typeof value !== 'string' || !(values as readonly string[]).includes(value)) {
    refuse(`${what} is one of ${values.join(', ')}`)
  }
  return value as T
}

/** Bytes in a key identifier, a public key and a signature. */
const KEY_ID_BYTES = 32
const KEY_BYTES = 32
const ENVELOPE_NONCE_BYTES = 24

function signingInput (domain: string, elements: readonly CanonicalValue[]): Uint8Array {
  return encodeCanonical(krArray([krText(domain), ...elements]))
}

/**
 * The identifier of one purpose-separated public key.
 *
 * `SHA256(CBOR(["kr-key-id/1", purpose, key]))`, which is what `kr_crypto::keys::key_id` produces.
 * The purpose is inside the hash, so the same 32 bytes declared under two purposes name two
 * different keys and a service can never confuse them.
 *
 * A service derives an identifier rather than accepting one: a caller that presents a key has
 * already said which identifier it names, and believing a claimed identifier instead would let a
 * caller point at somebody else's records.
 */
export async function keyId (
  purpose: 'transport' | 'authorisation' | 'stored_envelope' | 'notification_preview',
  publicKey: Uint8Array
): Promise<Uint8Array> {
  if (publicKey.length !== KEY_BYTES) {
    refuse(`a public key is ${String(KEY_BYTES)} bytes, not ${String(publicKey.length)}`)
  }
  const encoded = encodeCanonical(
    krArray([krText(KEY_ID_DOMAIN), krText(purpose), krBytes(publicKey)])
  )
  const digest = await crypto.subtle.digest('SHA-256', encoded as unknown as BufferSource)
  return new Uint8Array(digest)
}

/** The identifier of one device authorisation key. */
export async function authorisationKeyId (publicKey: Uint8Array): Promise<Uint8Array> {
  return await keyId('authorisation', publicKey)
}

/** The identifier of one stored-envelope key, which is what a mailbox is addressed by. */
export async function storedEnvelopeKeyId (publicKey: Uint8Array): Promise<Uint8Array> {
  return await keyId('stored_envelope', publicKey)
}

/**
 * The granularity a padded plaintext of `bucket` bytes was padded to, or null.
 *
 * The three bands do not overlap, so a reader recovers the granularity from the padded length
 * alone. Null means the length is not one any of section 20's rules produces, which is what a
 * service refuses.
 */
export function granularityForBucket (bucket: number | bigint): number | null {
  const value = BigInt(bucket)
  const granularity =
    value <= BigInt(16 * KIB + KIB)
      ? KIB
      : value <= BigInt(64 * KIB + 4 * KIB)
        ? 4 * KIB
        : 64 * KIB
  if (value <= 0n || value % BigInt(granularity) !== 0n) {
    return null
  }
  return granularity
}

/** The granularity a mailbox item's plaintext of `length` bytes is padded to, in bytes. */
export function mailboxGranularity (length: number): number {
  if (length <= 16 * KIB) {
    return KIB
  }
  return length <= 64 * KIB ? 4 * KIB : 64 * KIB
}

/**
 * The declared size bucket of a mailbox item, in bytes.
 *
 * The padding always adds at least one byte so that it can be removed unambiguously, so a plaintext
 * that is already an exact multiple rounds to the next multiple rather than to itself.
 */
export function mailboxSizeBucket (length: number): number {
  const granularity = mailboxGranularity(length)
  return (Math.floor(length / granularity) + 1) * granularity
}

/** The domain the value that claims a mailbox is derived under. */
export const MAILBOX_CLAIM_DOMAIN = 'kr-mailbox-claim/1'

/** How long a claim challenge stays answerable, in milliseconds. */
export const MAILBOX_CLAIM_LIFETIME_MS = 5 * 60 * 1000

/**
 * The value that answers one mailbox claim challenge.
 *
 * `SHA256(CBOR(["kr-mailbox-claim/1", ephemeral_key, recipient_key, shared_secret]))`, where the
 * shared secret is the X25519 agreement of the two keys. A mailbox is addressed by the identifier
 * of the recipient's stored-envelope key, which every paired peer of that recipient knows, so what
 * distinguishes the recipient from everybody who knows its public key is the private half. This is
 * how a service asks for it without the private key leaving the device and without the service
 * keeping anything that could open an envelope: the secret is discarded with the challenge.
 *
 * Both public keys are inside the hash, so an answer derived for one challenge cannot answer
 * another.
 */
export async function mailboxClaimValue (
  ephemeralKey: Uint8Array,
  recipientKey: Uint8Array,
  sharedSecret: Uint8Array
): Promise<Uint8Array> {
  for (const [what, bytes] of [
    ['an ephemeral key', ephemeralKey],
    ['a recipient key', recipientKey],
    ['a shared secret', sharedSecret]
  ] as const) {
    if (bytes.length !== KEY_BYTES) {
      refuse(`${what} is ${String(KEY_BYTES)} bytes, not ${String(bytes.length)}`)
    }
  }

  const encoded = encodeCanonical(
    krArray([
      krText(MAILBOX_CLAIM_DOMAIN),
      krBytes(ephemeralKey),
      krBytes(recipientKey),
      krBytes(sharedSecret)
    ])
  )
  const digest = await crypto.subtle.digest('SHA-256', encoded as unknown as BufferSource)
  return new Uint8Array(digest)
}

/**
 * The canonical bytes of one request body.
 *
 * The bodies of the mailbox, authority-feed, settings-sync and backup-manifest methods are JSON
 * documents rather than protocol objects, and a signature covers bytes rather than a document. So
 * the document is encoded in KR-CBOR-1 — text keys in canonical order, text as text, an exact
 * count as an unsigned integer — and the digest of those bytes is the `body_digest` a service
 * request carries. Both halves of the contract build it from the document they hold, so a caller
 * signs what a service recomputes and nothing depends on how either wrote its JSON.
 *
 * Numbers are the one place this is strict: every counter these bodies carry travels as a decimal
 * string, so a JSON number is either a small exact count or a value nobody agreed on. A float, a
 * negative or anything past the exact-integer range is refused rather than rounded into one.
 */
export function canonicalBody (body: unknown): Uint8Array {
  return encodeCanonical(canonicalBodyValue(body))
}

/** The SHA-256 of {@link canonicalBody}, which is what a signature's `body_digest` carries. */
export async function canonicalBodyDigest (body: unknown): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', canonicalBody(body) as unknown as BufferSource)
  return new Uint8Array(digest)
}

function canonicalBodyValue (body: unknown): CanonicalValue {
  if (body === null) {
    return krNull()
  }
  if (typeof body === 'boolean') {
    return krBool(body)
  }
  if (typeof body === 'number') {
    if (!Number.isSafeInteger(body) || body < 0) {
      refuse('a request body carries no number that is not an exact unsigned integer')
    }
    return krInt(BigInt(body))
  }
  if (typeof body === 'string') {
    return krText(body)
  }
  if (Array.isArray(body)) {
    return krArray((body as unknown[]).map(canonicalBodyValue))
  }
  if (typeof body === 'object') {
    return krMap(
      Object.entries(body as Record<string, unknown>).map(
        ([key, value]) => [key, canonicalBodyValue(value)] as const
      )
    )
  }
  refuse('a request body carries objects, arrays, text, exact counts, booleans and null')
}

const SEALED_ENVELOPE_FIELDS = ['ciphertext', 'nonce', 'routing'] as const

const ENVELOPE_ROUTING_FIELDS = [
  'envelope_id',
  'expires_at_ms',
  'payload_type',
  'recipient_key_id',
  'sender_key_id',
  'size_bucket_bytes',
  'thread_id'
] as const

/**
 * One sealed envelope, read against its closed schema.
 *
 * A service stores what a caller sends, so what it stores has to be exactly the record and nothing
 * beside it: a field nobody agreed on would be stored, served back and counted against nobody's
 * quota. Every scalar is checked for its own width and shape here, and the value returned is built
 * from the checked fields, so a caller cannot smuggle anything through by adding to the document.
 *
 * @throws {ServicesSchemaError} naming the rule the envelope breaks.
 */
export function readSealedEnvelope (value: unknown): SealedEnvelope {
  const envelope = closed('a sealed envelope', value, SEALED_ENVELOPE_FIELDS)
  const routing = closed('a routing record', envelope['routing'], ENVELOPE_ROUTING_FIELDS)
  const thread = routing['thread_id']

  return {
    // Every field is re-encoded from what was checked, so the value is canonical text whatever
    // spelling arrived: a key that decodes to the same bytes is the same key.
    ciphertext: bytesToBase64Url(opaqueBytes('a ciphertext', envelope['ciphertext'])),
    nonce: bytesToBase64Url(
      fixedBytes('an envelope nonce', envelope['nonce'], ENVELOPE_NONCE_BYTES)
    ),
    routing: {
      envelope_id: uuidToJson(identifierBytes('an envelope identifier', routing['envelope_id'])),
      expires_at_ms: counterText('an envelope expiry', routing['expires_at_ms']),
      payload_type: member('a mailbox payload kind', routing['payload_type'], MAILBOX_PAYLOAD_TYPES),
      recipient_key_id: bytesToBase64Url(
        fixedBytes('a recipient key identifier', routing['recipient_key_id'], KEY_ID_BYTES)
      ),
      sender_key_id: bytesToBase64Url(
        fixedBytes('a sender key identifier', routing['sender_key_id'], KEY_ID_BYTES)
      ),
      size_bucket_bytes: counterText('a declared size bucket', routing['size_bucket_bytes']),
      thread_id:
        thread === null
          ? null
          : uuidToJson(identifierBytes('a coalescing thread identifier', thread))
    }
  }
}

const SEALED_SYNC_OBJECT_FIELDS = ['ciphertext', 'nonce', 'size_bucket_bytes'] as const

/**
 * One sealed synchronised object, read against its closed schema.
 *
 * For the reason {@link readSealedEnvelope} states: a service stores this, so it stores the record
 * and nothing beside it.
 *
 * @throws {ServicesSchemaError} naming the rule the object breaks.
 */
export function readSealedSyncObject (value: unknown): SealedSyncObject {
  const object = closed('a sealed object', value, SEALED_SYNC_OBJECT_FIELDS)

  return {
    ciphertext: bytesToBase64Url(opaqueBytes('a ciphertext', object['ciphertext'])),
    nonce: bytesToBase64Url(fixedBytes('an object nonce', object['nonce'], ENVELOPE_NONCE_BYTES)),
    size_bucket_bytes: counterText('a declared size bucket', object['size_bucket_bytes'])
  }
}

/** A 16-byte identifier from its hyphenated text. */
function identifierBytes (what: string, value: unknown): Uint8Array {
  if (typeof value !== 'string') {
    refuse(`${what} is a hyphenated identifier`)
  }
  try {
    return jsonToUuid(value)
  } catch (error) {
    refuse(`${what} is a hyphenated identifier: ${error instanceof Error ? error.message : 'invalid'}`)
  }
}

/** A counter that travelled as a decimal string, as the exact text it means. */
function counterText (what: string, value: unknown): string {
  if (typeof value !== 'string') {
    refuse(`${what} is an unsigned counter written as a decimal string`)
  }
  try {
    return jsonToU64(value).toString()
  } catch (error) {
    refuse(`${what} is an unsigned counter: ${error instanceof Error ? error.message : 'invalid'}`)
  }
}

/** Why a sealed record is not one this contract admits. */
export type StructureRefusal =
  | { readonly reason: 'unknown_payload_type'; readonly declared: string }
  | { readonly reason: 'item_too_large'; readonly stored: number; readonly limit: number }
  | { readonly reason: 'undeclared_bucket'; readonly bucket: bigint }
  | { readonly reason: 'ciphertext_length'; readonly length: bigint; readonly expected: bigint }
  | { readonly reason: 'too_large'; readonly bucket: bigint; readonly limit: number }
  | { readonly reason: 'lifetime_too_long'; readonly ahead: bigint; readonly limit: number }
  | { readonly reason: 'already_expired'; readonly behind: bigint }
  | { readonly reason: 'authority_coalesced' }

/**
 * Everything about a sealed mailbox item a service can check without a key, or null.
 *
 * Five rules: the payload kind is one of the closed set, the declared bucket is a length the
 * padding rules produce, the ciphertext is exactly that bucket plus the seal's overhead, the item
 * expires inside the day section 9 gives it and not in the past, and a payload that carries
 * authority names no coalescing thread.
 *
 * The first is what keeps an action out of a mailbox. Section 9 queues no keystroke, no shell
 * command, no approval decision and no closure, and the way that holds is that the kinds are a
 * closed set with no member any of them could arrive under: a kind outside it is refused here
 * rather than stored under a name nobody reads.
 */
export function checkSealedEnvelope (
  envelope: SealedEnvelope,
  nowMs: number
): StructureRefusal | null {
  const routing = envelope.routing
  if (!(MAILBOX_PAYLOAD_TYPES as readonly string[]).includes(routing.payload_type)) {
    return { reason: 'unknown_payload_type', declared: String(routing.payload_type) }
  }
  const bucket = jsonToU64(routing.size_bucket_bytes)
  if (granularityForBucket(bucket) === null) {
    return { reason: 'undeclared_bucket', bucket }
  }
  const expected = bucket + BigInt(SEAL_OVERHEAD_BYTES)
  const length = BigInt(base64UrlToBytes(envelope.ciphertext).length)
  if (length !== expected) {
    return { reason: 'ciphertext_length', length, expected }
  }
  const expires = jsonToU64(routing.expires_at_ms)
  const now = BigInt(nowMs)
  if (expires <= now) {
    return { reason: 'already_expired', behind: now - expires }
  }
  const ahead = expires - now
  if (ahead > BigInt(MAX_MAILBOX_ITEM_LIFETIME_MS)) {
    return { reason: 'lifetime_too_long', ahead, limit: MAX_MAILBOX_ITEM_LIFETIME_MS }
  }
  const stored = envelopeStoredBytes(envelope)
  if (stored > MAX_MAILBOX_ITEM_BYTES) {
    return { reason: 'item_too_large', stored, limit: MAX_MAILBOX_ITEM_BYTES }
  }
  if (
    (AUTHORITY_BEARING_PAYLOAD_TYPES as readonly string[]).includes(routing.payload_type) &&
    routing.thread_id !== null
  ) {
    return { reason: 'authority_coalesced' }
  }
  return null
}

/** The bytes one sealed item occupies in a mailbox: the ciphertext, the nonce and the routing. */
export function envelopeStoredBytes (envelope: SealedEnvelope): number {
  return (
    base64UrlToBytes(envelope.ciphertext).length + ENVELOPE_NONCE_BYTES + ROUTING_RECORD_BYTES
  )
}

/** Everything about a sealed synchronised object a service can check without a key, or null. */
export function checkSealedSyncObject (object: SealedSyncObject): StructureRefusal | null {
  const bucket = jsonToU64(object.size_bucket_bytes)
  if (granularityForBucket(bucket) === null) {
    return { reason: 'undeclared_bucket', bucket }
  }
  if (bucket > BigInt(MAX_SYNC_OBJECT_PLAINTEXT_BYTES)) {
    return { reason: 'too_large', bucket, limit: MAX_SYNC_OBJECT_PLAINTEXT_BYTES }
  }
  const expected = bucket + BigInt(SEAL_OVERHEAD_BYTES)
  const length = BigInt(base64UrlToBytes(object.ciphertext).length)
  if (length !== expected) {
    return { reason: 'ciphertext_length', length, expected }
  }
  return null
}

/** The bytes one synchronised object occupies: the ciphertext, the nonce and the record. */
export function syncObjectStoredBytes (object: SealedSyncObject): number {
  return base64UrlToBytes(object.ciphertext).length + ENVELOPE_NONCE_BYTES + SYNC_RECORD_BYTES
}

/**
 * True when the routing record declares what the plaintext authenticated.
 *
 * A service may rewrite routing, so a reader that acted on it would be acting on the service's
 * word. Every field it declares is checked against the field the box authenticated, the payload
 * kind and the coalescing thread among them: a service that relabelled an item or coalesced by
 * another thread is caught here rather than believed.
 */
export function routingMatchesPlaintext (
  envelope: SealedEnvelope,
  plaintext: EnvelopePlaintext
): boolean {
  const routing = envelope.routing
  return (
    routing.envelope_id === plaintext.envelope_id &&
    routing.recipient_key_id === plaintext.recipient_key_id &&
    routing.sender_key_id === plaintext.sender_key_id &&
    routing.expires_at_ms === plaintext.expires_at_ms &&
    routing.payload_type === plaintext.payload_type &&
    routing.thread_id === plaintext.thread_id
  )
}

const REVOCATION_TARGET_KINDS = ['devices', 'grants'] as const

/** The canonical value of what a revocation removes. */
function revocationTarget (value: unknown): CanonicalValue {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    refuse('a revocation target is an object')
  }
  const record = value as Record<string, unknown>
  const keys = Object.keys(record)
  if (keys.length !== 1) {
    refuse('a revocation target names devices or grants, and nothing else')
  }
  const kind = member('a revocation target', keys[0], REVOCATION_TARGET_KINDS)
  const field = kind === 'devices' ? 'device_ids' : 'grant_ids'
  const inner = closed(`a ${kind} revocation target`, record[kind], [field])
  const listed = inner[field]
  if (!Array.isArray(listed)) {
    refuse(`${field} is an array`)
  }
  const text: string[] = []
  for (const entry of listed as unknown[]) {
    if (typeof entry !== 'string') {
      refuse(`${field} holds hyphenated identifiers`)
    }
    text.push(entry)
  }
  // A canonical set is in ascending order of its members and carries no duplicates. The members
  // are compared as the bytes they encode to rather than as the text they arrived as, because one
  // identifier has two spellings: a verifier that compared the text would admit an upper-case
  // duplicate of a lower-case member and cover bytes the host's own decoder refuses. The order is
  // checked rather than imposed, because a verifier checks the bytes it received.
  const encoded = text.map((entry) => uuidToJson(jsonToUuid(entry)))
  for (let index = 1; index < encoded.length; index += 1) {
    if ((encoded[index - 1] as string) >= (encoded[index] as string)) {
      refuse(`${field} is in ascending order without duplicates`)
    }
  }
  return krMap([[kind, krMap([[field, krArray(text.map((entry) => krBytes(jsonToUuid(entry))))]])]])
}

const REVOCATION_FIELDS = [
  'host_device_id',
  'issued_at_ms',
  'issuer_device_id',
  'issuer_key_id',
  'request_id',
  'signature',
  'target'
] as const

/**
 * The bytes a remote owner's revocation request is signed over.
 *
 * `CBOR(["kr-revocation/1", request_id, issuer_device_id, host_device_id, target, issued_at_ms,
 * issuer_key_id])`: the fields in declaration order, with the signature left out. The elements are
 * positional rather than a map because that is what the host signs.
 *
 * There is no host revision in it, which is the point. Only the target host issues its ordered
 * authority revisions, so a device cannot assign one to its own request.
 */
export function revocationRequestSigningInput (request: RevocationRequest): Uint8Array {
  const record = closed('a revocation request', request, REVOCATION_FIELDS)
  return signingInput(REVOCATION_DOMAIN, [
    uuid('a request identifier', record['request_id']),
    uuid('an issuer device identifier', record['issuer_device_id']),
    uuid('a host device identifier', record['host_device_id']),
    revocationTarget(record['target']),
    counter('a revocation issue time', record['issued_at_ms']),
    krBytes(fixedBytes('an issuer key identifier', record['issuer_key_id'], KEY_ID_BYTES))
  ])
}

const REVISION_FIELDS = [
  'applied_requests',
  'authority_revision',
  'host_device_id',
  'host_key_id',
  'issued_at_ms',
  'previous_revision',
  'signature'
] as const

/**
 * The bytes a host's authority revision record is signed over.
 *
 * `CBOR(["kr-authority/1", host_device_id, authority_revision, previous_revision,
 * applied_requests, issued_at_ms, host_key_id])`.
 *
 * The revision it follows is inside the signature, so a record cannot be re-parented on to another
 * revision, and a feed that has accepted revision twelve refuses one that claims to follow ten.
 */
export function authorityRevisionSigningInput (record_: AuthorityRevisionRecord): Uint8Array {
  const record = closed('an authority revision record', record_, REVISION_FIELDS)
  const applied = record['applied_requests']
  if (!Array.isArray(applied)) {
    refuse('applied_requests is an array')
  }
  const requests: string[] = []
  for (const entry of applied as unknown[]) {
    if (typeof entry !== 'string') {
      refuse('applied_requests holds hyphenated identifiers')
    }
    requests.push(entry)
  }
  // Compared as the bytes they encode to, for the reason `revocationTarget` states: one identifier
  // has two spellings, and the host's own set refuses the duplicate a text comparison would admit.
  const appliedBytes = requests.map((entry) => uuidToJson(jsonToUuid(entry)))
  for (let index = 1; index < appliedBytes.length; index += 1) {
    if ((appliedBytes[index - 1] as string) >= (appliedBytes[index] as string)) {
      refuse('applied_requests is in ascending order without duplicates')
    }
  }
  return signingInput(AUTHORITY_REVISION_DOMAIN, [
    uuid('a host device identifier', record['host_device_id']),
    counter('an authority revision', record['authority_revision']),
    counter('a previous revision', record['previous_revision']),
    krArray(requests.map((entry) => krBytes(jsonToUuid(entry)))),
    counter('a revision issue time', record['issued_at_ms']),
    krBytes(fixedBytes('a host key identifier', record['host_key_id'], KEY_ID_BYTES))
  ])
}

const TRUSTED_WRITER_FIELDS = ['enrolled_at_ms', 'signing_key', 'writer_key_id'] as const

const WRITER_RECORD_FIELDS = [
  'archive_id',
  'enrolled_at_ms',
  'owner_key_id',
  'writer',
  'writer_revision'
] as const

/**
 * The bytes a collection's writer enrolment is signed over.
 *
 * `CBOR(["kr-backup-writer/1", the payload as a canonical map])`, signed by the collection owner's
 * authorisation key. A service cannot read a manifest, so what it can hold a publisher to is this:
 * the writer the owner enrolled, at the revision the owner last advanced.
 */
export function backupWriterRecordSigningInput (payload: BackupWriterRecordPayload): Uint8Array {
  const record = closed('a writer enrolment', payload, WRITER_RECORD_FIELDS)
  const writer = closed('an enrolled writer', record['writer'], TRUSTED_WRITER_FIELDS)
  return signingInput(BACKUP_WRITER_DOMAIN, [
    krMap([
      ['archive_id', uuid('an archive identifier', record['archive_id'])],
      ['enrolled_at_ms', counter('an enrolment time', record['enrolled_at_ms'])],
      [
        'owner_key_id',
        krBytes(fixedBytes('an owner key identifier', record['owner_key_id'], KEY_ID_BYTES))
      ],
      [
        'writer',
        krMap([
          ['enrolled_at_ms', counter("a writer's enrolment time", writer['enrolled_at_ms'])],
          ['signing_key', krBytes(fixedBytes('a writer signing key', writer['signing_key'], KEY_BYTES))],
          [
            'writer_key_id',
            krBytes(fixedBytes('a writer key identifier', writer['writer_key_id'], KEY_ID_BYTES))
          ]
        ])
      ],
      ['writer_revision', counter('a writer revision', record['writer_revision'])]
    ])
  ])
}

const OBJECT_REF_FIELDS = ['encrypted_len', 'encrypted_object_hash', 'object_id'] as const

const WRAP_CONTEXT_FIELDS = [
  'archive_id',
  'backup_generation',
  'encrypted_object_hash',
  'format',
  'object_id',
  'purpose',
  'recipient_key_id',
  'sender_key_id'
] as const

const WRAP_FIELDS = ['ciphertext', 'context', 'nonce'] as const

const DESCRIPTOR_FIELDS = [
  'archive_id',
  'backup_generation',
  'encrypted_manifest',
  'manifest_key_wraps',
  'version'
] as const

const PUBLICATION_FIELDS = ['descriptor', 'published_at_ms', 'writer_key_id'] as const

const DIGEST_BYTES = 32

function objectRef (what: string, value: unknown): CanonicalValue {
  const record = closed(what, value, OBJECT_REF_FIELDS)
  return krMap([
    ['encrypted_len', counter(`${what} length`, record['encrypted_len'])],
    [
      'encrypted_object_hash',
      krBytes(fixedBytes(`${what} hash`, record['encrypted_object_hash'], DIGEST_BYTES))
    ],
    ['object_id', uuid(`${what} identifier`, record['object_id'])]
  ])
}

function keyWrap (value: unknown): CanonicalValue {
  const wrap = closed('a manifest key wrap', value, WRAP_FIELDS)
  const context = closed('a key wrap context', wrap['context'], WRAP_CONTEXT_FIELDS)
  return krMap([
    ['ciphertext', krBytes(opaqueBytes('a key wrap ciphertext', wrap['ciphertext']))],
    [
      'context',
      krMap([
        ['archive_id', uuid('an archive identifier', context['archive_id'])],
        ['backup_generation', counter('a backup generation', context['backup_generation'])],
        [
          'encrypted_object_hash',
          krBytes(fixedBytes('a wrapped object hash', context['encrypted_object_hash'], DIGEST_BYTES))
        ],
        [
          'format',
          krText(member('a key wrap format', context['format'], ['kr-keywrap/1'] as const))
        ],
        ['object_id', uuid('a wrapped object identifier', context['object_id'])],
        [
          'purpose',
          krText(
            member('a key wrap purpose', context['purpose'], [
              'object_key',
              'manifest_key',
              'recovery_bundle_key'
            ] as const)
          )
        ],
        [
          'recipient_key_id',
          krBytes(fixedBytes('a recipient key identifier', context['recipient_key_id'], KEY_ID_BYTES))
        ],
        [
          'sender_key_id',
          krBytes(fixedBytes('a sender key identifier', context['sender_key_id'], KEY_ID_BYTES))
        ]
      ])
    ],
    ['nonce', krBytes(fixedBytes('a key wrap nonce', wrap['nonce'], ENVELOPE_NONCE_BYTES))]
  ])
}

function descriptorValue (value: unknown): CanonicalValue {
  const descriptor = closed('an archive descriptor', value, DESCRIPTOR_FIELDS)
  const wraps = descriptor['manifest_key_wraps']
  if (!Array.isArray(wraps)) {
    refuse('manifest_key_wraps is an array')
  }
  if (wraps.length > MAX_ARCHIVE_RECIPIENTS) {
    refuse(`an archive descriptor names at most ${String(MAX_ARCHIVE_RECIPIENTS)} recipients`)
  }
  return krMap([
    ['archive_id', uuid('an archive identifier', descriptor['archive_id'])],
    ['backup_generation', counter('a backup generation', descriptor['backup_generation'])],
    ['encrypted_manifest', objectRef('an encrypted manifest', descriptor['encrypted_manifest'])],
    ['manifest_key_wraps', krArray((wraps as unknown[]).map(keyWrap))],
    ['version', counter('a descriptor version', descriptor['version'])]
  ])
}

/**
 * The bytes one published backup generation is signed over.
 *
 * `CBOR(["kr-backup-publication/1", the payload as a canonical map])`, signed by the enrolled
 * writer. A device that fetches a generation verifies the writer's own statement rather than the
 * service's word about what was published.
 */
export function backupGenerationPublicationSigningInput (
  payload: BackupGenerationPublicationPayload
): Uint8Array {
  const record = closed('a generation publication', payload, PUBLICATION_FIELDS)
  return signingInput(BACKUP_PUBLICATION_DOMAIN, [
    krMap([
      ['descriptor', descriptorValue(record['descriptor'])],
      ['published_at_ms', counter('a publication time', record['published_at_ms'])],
      [
        'writer_key_id',
        krBytes(fixedBytes('a writer key identifier', record['writer_key_id'], KEY_ID_BYTES))
      ]
    ])
  ])
}

/** The descriptor as it is measured against the 64 KiB bound, in bytes. */
export function descriptorEncodedLength (descriptor: ArchiveDescriptor): number {
  return encodeCanonical(descriptorValue(descriptor)).length
}

/** The descriptor version this contract publishes and accepts. */
export const ARCHIVE_DESCRIPTOR_VERSION = 1n

/** Why an archive descriptor is not one this contract admits. */
export type DescriptorRefusal =
  | { readonly reason: 'too_large'; readonly len: number; readonly limit: number }
  | { readonly reason: 'unsupported_version'; readonly version: bigint }
  | { readonly reason: 'too_many_recipients'; readonly count: number; readonly limit: number }
  | { readonly reason: 'wrap_purpose'; readonly purpose: string }
  | { readonly reason: 'wrap_archive' }
  | { readonly reason: 'wrap_object'; readonly named: string }
  | { readonly reason: 'wrap_hash' }
  | { readonly reason: 'duplicate_recipient' }

/**
 * Every check one archive descriptor passes, or null.
 *
 * The twin of `ArchiveDescriptor::validate`, in the same order and with the same rules. Section 20
 * bounds a descriptor to 64 KiB and 128 recipients and refuses an invalid one before anything is
 * allocated for it, and what makes a descriptor invalid is more than its size: a wrap that names
 * another archive, another generation, another object or another hash is a wrap for something else,
 * and a second wrap for one recipient says nothing the first did not.
 *
 * Call it on a descriptor read through {@link readArchiveDescriptor}, whose fields are canonical
 * text: a comparison of two spellings of one value would otherwise be a comparison of two texts.
 *
 * @throws {ServicesSchemaError} when the descriptor is not one this contract can encode at all.
 */
export function checkArchiveDescriptor (descriptor: ArchiveDescriptor): DescriptorRefusal | null {
  // The byte limit first, so an oversized descriptor costs nothing beyond the bytes that were
  // already received.
  const len = descriptorEncodedLength(descriptor)
  if (len > MAX_ARCHIVE_DESCRIPTOR_LEN) {
    return { reason: 'too_large', len, limit: MAX_ARCHIVE_DESCRIPTOR_LEN }
  }

  const version = jsonToU64(descriptor.version)
  if (version !== ARCHIVE_DESCRIPTOR_VERSION) {
    return { reason: 'unsupported_version', version }
  }
  if (descriptor.manifest_key_wraps.length > MAX_ARCHIVE_RECIPIENTS) {
    return {
      reason: 'too_many_recipients',
      count: descriptor.manifest_key_wraps.length,
      limit: MAX_ARCHIVE_RECIPIENTS
    }
  }

  const generation = jsonToU64(descriptor.backup_generation)
  const recipients = new Set<string>()
  for (const wrap of descriptor.manifest_key_wraps) {
    const context = wrap.context
    if (context.purpose !== 'manifest_key') {
      return { reason: 'wrap_purpose', purpose: context.purpose }
    }
    if (
      context.archive_id !== descriptor.archive_id ||
      jsonToU64(context.backup_generation) !== generation
    ) {
      return { reason: 'wrap_archive' }
    }
    if (context.object_id !== descriptor.encrypted_manifest.object_id) {
      return { reason: 'wrap_object', named: context.object_id }
    }
    if (context.encrypted_object_hash !== descriptor.encrypted_manifest.encrypted_object_hash) {
      return { reason: 'wrap_hash' }
    }
    if (recipients.has(context.recipient_key_id)) {
      return { reason: 'duplicate_recipient' }
    }
    recipients.add(context.recipient_key_id)
  }

  return null
}

/**
 * One archive descriptor, read against its closed schema.
 *
 * For the reason {@link readSealedEnvelope} states: a service stores this and serves it back, so it
 * stores the descriptor and nothing beside it, in one spelling.
 *
 * @throws {ServicesSchemaError} naming the rule the descriptor breaks.
 */
export function readArchiveDescriptor (value: unknown): ArchiveDescriptor {
  const descriptor = closed('an archive descriptor', value, DESCRIPTOR_FIELDS)
  const wraps = descriptor['manifest_key_wraps']
  if (!Array.isArray(wraps)) {
    refuse('manifest_key_wraps is an array')
  }
  if (wraps.length > MAX_ARCHIVE_RECIPIENTS) {
    refuse(`an archive descriptor names at most ${String(MAX_ARCHIVE_RECIPIENTS)} recipients`)
  }

  return {
    archive_id: uuidToJson(identifierBytes('an archive identifier', descriptor['archive_id'])),
    backup_generation: counterText('a backup generation', descriptor['backup_generation']),
    encrypted_manifest: readObjectRef('an encrypted manifest', descriptor['encrypted_manifest']),
    manifest_key_wraps: (wraps as unknown[]).map(readKeyWrap),
    version: counterText('a descriptor version', descriptor['version'])
  }
}

function readObjectRef (what: string, value: unknown): ArchiveDescriptor['encrypted_manifest'] {
  const record = closed(what, value, OBJECT_REF_FIELDS)
  return {
    encrypted_len: counterText(`${what} length`, record['encrypted_len']),
    encrypted_object_hash: bytesToBase64Url(
      fixedBytes(`${what} hash`, record['encrypted_object_hash'], DIGEST_BYTES)
    ),
    object_id: uuidToJson(identifierBytes(`${what} identifier`, record['object_id']))
  }
}

function readKeyWrap (value: unknown): ArchiveDescriptor['manifest_key_wraps'][number] {
  const wrap = closed('a manifest key wrap', value, WRAP_FIELDS)
  const context = closed('a key wrap context', wrap['context'], WRAP_CONTEXT_FIELDS)

  return {
    ciphertext: bytesToBase64Url(opaqueBytes('a key wrap ciphertext', wrap['ciphertext'])),
    context: {
      archive_id: uuidToJson(identifierBytes('an archive identifier', context['archive_id'])),
      backup_generation: counterText('a backup generation', context['backup_generation']),
      encrypted_object_hash: bytesToBase64Url(
        fixedBytes('a wrapped object hash', context['encrypted_object_hash'], DIGEST_BYTES)
      ),
      format: member('a key wrap format', context['format'], ['kr-keywrap/1'] as const),
      object_id: uuidToJson(identifierBytes('a wrapped object identifier', context['object_id'])),
      purpose: member('a key wrap purpose', context['purpose'], [
        'manifest_key',
        'object_key'
      ] as const),
      recipient_key_id: bytesToBase64Url(
        fixedBytes('a recipient key identifier', context['recipient_key_id'], KEY_ID_BYTES)
      ),
      sender_key_id: bytesToBase64Url(
        fixedBytes('a sender key identifier', context['sender_key_id'], KEY_ID_BYTES)
      )
    },
    nonce: bytesToBase64Url(fixedBytes('a key wrap nonce', wrap['nonce'], ENVELOPE_NONCE_BYTES))
  }
}

const SIGNED_RECORD_FIELDS = ['payload', 'signature'] as const

const SIGNATURE_BYTES = 64

/** A signature read back in one spelling. */
function signature (what: string, value: unknown): string {
  return bytesToBase64Url(fixedBytes(what, value, SIGNATURE_BYTES))
}

/**
 * One owner's writer enrolment, read against its closed schema.
 *
 * A service stores the record so a later publication can be checked against it, so it stores the
 * record and nothing beside it: a field nobody agreed on would be stored, served back and covered
 * by no signature.
 *
 * @throws {ServicesSchemaError} naming the rule the record breaks.
 */
export function readBackupWriterRecord (value: unknown): {
  readonly payload: BackupWriterRecordPayload
  readonly signature: string
} {
  const record = closed('a writer enrolment', value, SIGNED_RECORD_FIELDS)
  const payload = closed('a writer enrolment payload', record['payload'], WRITER_RECORD_FIELDS)
  const writer = closed('an enrolled writer', payload['writer'], TRUSTED_WRITER_FIELDS)

  return {
    payload: {
      archive_id: uuidToJson(identifierBytes('an archive identifier', payload['archive_id'])),
      enrolled_at_ms: counterText("an owner's enrolment time", payload['enrolled_at_ms']),
      owner_key_id: bytesToBase64Url(
        fixedBytes('an owner key identifier', payload['owner_key_id'], KEY_ID_BYTES)
      ),
      writer: {
        enrolled_at_ms: counterText("a writer's enrolment time", writer['enrolled_at_ms']),
        signing_key: bytesToBase64Url(
          fixedBytes('a writer signing key', writer['signing_key'], KEY_BYTES)
        ),
        writer_key_id: bytesToBase64Url(
          fixedBytes('a writer key identifier', writer['writer_key_id'], KEY_ID_BYTES)
        )
      },
      writer_revision: counterText('a writer revision', payload['writer_revision'])
    },
    signature: signature("an owner's signature", record['signature'])
  }
}

/**
 * One writer's generation publication, read against its closed schema.
 *
 * For the reason {@link readBackupWriterRecord} states. The descriptor inside it is read the same
 * way, so what a service stores and serves back is the descriptor the writer signed.
 *
 * @throws {ServicesSchemaError} naming the rule the publication breaks.
 */
export function readBackupGenerationPublication (value: unknown): {
  readonly payload: BackupGenerationPublicationPayload
  readonly signature: string
} {
  const record = closed('a generation publication', value, SIGNED_RECORD_FIELDS)
  const payload = closed('a generation publication payload', record['payload'], PUBLICATION_FIELDS)

  return {
    payload: {
      descriptor: readArchiveDescriptor(payload['descriptor']),
      published_at_ms: counterText('a publication time', payload['published_at_ms']),
      writer_key_id: bytesToBase64Url(
        fixedBytes('a writer key identifier', payload['writer_key_id'], KEY_ID_BYTES)
      )
    },
    signature: signature("a writer's signature", record['signature'])
  }
}

const RECOVERY_RECIPIENT_FIELDS = [
  'name',
  'named_at_ms',
  'recipient_key',
  'recipient_key_id'
] as const

const BACKUP_POLICY_FIELDS = ['recovery_recipient', 'required'] as const

const POLICY_FIELDS = [
  'adapter_allowlist',
  'audit_retention_days',
  'backup',
  'external_providers',
  'issued_at_ms',
  'key_revision',
  'maximum_grant_lifetime_ms',
  'minimum_client_version',
  'organisation_id',
  'policy_revision'
] as const

/** The longest an adapter identifier may be, in bytes, as `kr_protocol::ids` bounds one. */
const MAX_OPAQUE_ID_BYTES = 256

function adapterAllowlist (value: unknown): CanonicalValue {
  if (value === null) {
    return krNull()
  }
  if (!Array.isArray(value)) {
    refuse('an adapter allowlist is an array or null')
  }
  const adapters: string[] = []
  for (const entry of value as unknown[]) {
    if (typeof entry !== 'string' || entry === '') {
      refuse('an adapter allowlist names non-empty identifiers')
    }
    if (new TextEncoder().encode(entry).length > MAX_OPAQUE_ID_BYTES) {
      refuse(`an adapter identifier is at most ${String(MAX_OPAQUE_ID_BYTES)} bytes`)
    }
    // eslint-disable-next-line no-control-regex
    if (/[ --]/.test(entry)) {
      refuse('an adapter identifier carries no control characters')
    }
    adapters.push(entry)
  }
  for (let index = 1; index < adapters.length; index += 1) {
    // A canonical set is in ascending order of its members and carries no duplicates. The order is
    // checked rather than imposed: a verifier checks the bytes it received, so sorting them here
    // would cover bytes the issuer never sent.
    if ((adapters[index - 1] as string) >= (adapters[index] as string)) {
      refuse('an adapter allowlist is in ascending order without duplicates')
    }
  }
  return krArray(adapters.map((entry) => krText(entry)))
}

function clientVersion (value: unknown): CanonicalValue {
  if (value === null) {
    return krNull()
  }
  if (typeof value !== 'string' || value === '') {
    refuse('a client version is a non-empty string or null')
  }
  if (value.length > MAX_CLIENT_VERSION_LEN) {
    refuse(`a client version is at most ${String(MAX_CLIENT_VERSION_LEN)} bytes`)
  }
  if (!/^[0-9A-Za-z.+-]+$/.test(value)) {
    refuse('a client version is alphanumeric with dots, hyphens and plus signs')
  }
  return krText(value)
}

/**
 * The bytes one organisation's policy is signed over.
 *
 * `CBOR(["kr-organisation-policy/1", the payload as a canonical map])`, signed by the revision of
 * the organisation's policy-signing key that a host follows its pinned chain to. What the policy
 * carries narrows what a host allows and includes no content key of any kind.
 */
export function organisationPolicySigningInput (payload: OrganisationPolicyPayload): Uint8Array {
  const record = closed('an organisation policy', payload, POLICY_FIELDS)
  const backup = closed('a backup policy', record['backup'], BACKUP_POLICY_FIELDS)
  const recipient = backup['recovery_recipient']
  const lifetime = record['maximum_grant_lifetime_ms']
  return signingInput(ORGANISATION_POLICY_DOMAIN, [
    krMap([
      ['adapter_allowlist', adapterAllowlist(record['adapter_allowlist'])],
      ['audit_retention_days', counter('an audit retention', record['audit_retention_days'])],
      [
        'backup',
        krMap([
          [
            'recovery_recipient',
            recipient === null
              ? krNull()
              : (() => {
                  const named = closed(
                    'an organisation recovery recipient',
                    recipient,
                    RECOVERY_RECIPIENT_FIELDS
                  )
                  const name = named['name']
                  if (typeof name !== 'string') {
                    refuse('a recovery recipient name is a string')
                  }
                  return krMap([
                    ['name', krText(name)],
                    ['named_at_ms', counter('a naming time', named['named_at_ms'])],
                    [
                      'recipient_key',
                      krBytes(fixedBytes('a recipient key', named['recipient_key'], KEY_BYTES))
                    ],
                    [
                      'recipient_key_id',
                      krBytes(
                        fixedBytes(
                          'a recipient key identifier',
                          named['recipient_key_id'],
                          KEY_ID_BYTES
                        )
                      )
                    ]
                  ])
                })()
          ],
          [
            'required',
            typeof backup['required'] === 'boolean'
              ? krBool(backup['required'])
              : refuse('a backup requirement is a boolean')
          ]
        ])
      ],
      [
        'external_providers',
        krText(
          member(
            'an external provider policy',
            record['external_providers'],
            EXTERNAL_PROVIDER_POLICIES
          )
        )
      ],
      ['issued_at_ms', counter('a policy issue time', record['issued_at_ms'])],
      ['key_revision', counter('a key revision', record['key_revision'])],
      [
        'maximum_grant_lifetime_ms',
        lifetime === null ? krNull() : counter('a grant lifetime', lifetime)
      ],
      ['minimum_client_version', clientVersion(record['minimum_client_version'])],
      ['organisation_id', uuid('an organisation identifier', record['organisation_id'])],
      ['policy_revision', counter('a policy revision', record['policy_revision'])]
    ])
  ])
}

/** Why a policy is not one this contract admits. */
export type PolicyRefusal =
  | { readonly reason: 'audit_retention'; readonly days: bigint }
  | { readonly reason: 'grant_lifetime'; readonly lifetime: bigint }
  | { readonly reason: 'empty_allowlist' }
  | { readonly reason: 'allowlist_too_long'; readonly count: number }

/**
 * Every check a policy passes before it is signed or accepted, or null.
 *
 * These need neither a signature nor the clock, so the service that signs a policy and the host
 * that accepts one both make them, and a policy that fails one is refused rather than narrowed to
 * the part that reads.
 */
export function checkOrganisationPolicy (payload: OrganisationPolicyPayload): PolicyRefusal | null {
  const days = jsonToU64(payload.audit_retention_days)
  if (days < BigInt(MIN_AUDIT_RETENTION_DAYS) || days > BigInt(MAX_AUDIT_RETENTION_DAYS)) {
    return { reason: 'audit_retention', days }
  }
  if (payload.maximum_grant_lifetime_ms !== null) {
    const lifetime = jsonToU64(payload.maximum_grant_lifetime_ms)
    if (lifetime === 0n || lifetime > BigInt(MAX_POLICY_GRANT_LIFETIME_MS)) {
      return { reason: 'grant_lifetime', lifetime }
    }
  }
  if (payload.adapter_allowlist !== null) {
    if (payload.adapter_allowlist.length === 0) {
      return { reason: 'empty_allowlist' }
    }
    if (payload.adapter_allowlist.length > MAX_ADAPTER_ALLOWLIST) {
      return { reason: 'allowlist_too_long', count: payload.adapter_allowlist.length }
    }
  }
  // Nothing here couples the two backup fields. An organisation that requires backups and names
  // no recipient requires an archive it cannot read, which is the ordinary case; recovery is what
  // naming a recipient establishes, and a host enrols visibly for it.
  return null
}
