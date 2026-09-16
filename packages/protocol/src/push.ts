/**
 * The exact bytes the push objects are signed and digested over.
 *
 * The gateway meets these as JSON: a device answers a registration challenge, a host renews or
 * revokes an authorisation, a host delivers a notification. None of those signatures cover JSON, so
 * the gateway rebuilds the canonical KR-CBOR-1 payload before it verifies anything. This module is
 * the TypeScript half of `kr_protocol::push`: the same domains, the same field names, the same
 * encoding, checked against `fixtures/push/push.json`.
 *
 * It also holds the limits section 16 fixes, so the gateway and a host agree on them without either
 * copying a number out of prose: the challenge lifetime, the credential lifetime and renewal
 * window, the payload bounds, and the free rate policy.
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
import { DIGEST_BYTES, NONCE_BYTES, fixedBytes, gatewayOrigin } from './service.js'
import type {
  PushDeliveryAck,
  PushDeliveryRequest,
  PushRequest,
  PushInstallationBinding,
  PushPlatformHints,
  PushRatePolicy,
  PushRegistrationAnswerPayload,
  PushSenderBinding,
  PushSenderRecord,
  PushSuppression,
  PushSenderRenewalPayload,
  PushSenderRevocationPayload
} from './generated/protocol.js'

/** The generic alert a device shows before anything is decrypted. */
export type PushAlert = PushPlatformHints['alert']

/** How urgently a provider is asked to deliver. */
export type PushUrgency = PushPlatformHints['urgency']

/** A push platform, as the gateway builds a payload for it. */
export type PushPlatform = PushInstallationBinding['platform']

/** What became of one delivery request. */
export type PushDeliveryState = PushDeliveryAck['state']

/** Why a notification was suppressed, when it was. */
export type PushSuppressionReason = PushSuppression['reason']

/** Whether a bound token is still usable. */
export type PushTokenState = PushInstallationBinding['state']

/** Whether a sender authorisation still stands. */
export type PushSenderState = PushSenderRecord['state']

/** The domain a registration answer's signature covers. */
export const PUSH_REGISTRATION_ANSWER_DOMAIN = 'kr-push-registration/1'

/** The domain the immutable half of a sender record is digested under. */
export const PUSH_SENDER_BINDING_DOMAIN = 'kr-push-sender/1'

/** The domain a renewal proof's signature covers. */
export const PUSH_SENDER_RENEWAL_DOMAIN = 'kr-push-sender-renewal/1'

/** The domain a revocation's signature covers. */
export const PUSH_SENDER_REVOCATION_DOMAIN = 'kr-push-sender-revocation/1'

/** The domain a delivery request is digested under. */
export const PUSH_DELIVERY_DOMAIN = 'kr-push-delivery/1'

/** The domain a provider token is digested under. */
export const PUSH_TOKEN_DOMAIN = 'kr-push-token/1'

/** The domain a delivery credential's bearer is digested under. */
export const PUSH_CREDENTIAL_DOMAIN = 'kr-push-credential/1'

/** How long a registration challenge stays answerable, in milliseconds. */
export const REGISTRATION_CHALLENGE_LIFETIME_MS = 5 * 60 * 1000

/** How long a delivery credential lasts, in milliseconds. */
export const DELIVERY_CREDENTIAL_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000

/** How long before expiry a host may renew its delivery credential, in milliseconds. */
export const SENDER_RENEWAL_WINDOW_MS = 7 * 24 * 60 * 60 * 1000

/** The most preview text plus inner metadata may be before encryption, in bytes. */
export const MAX_PREVIEW_PLAINTEXT_BYTES = 1_800

/** The most the complete provider payload may be after encryption and base64, in bytes. */
export const MAX_PROVIDER_PAYLOAD_BYTES = 3_500

/** Notifications a free destination may receive in a burst. */
export const FREE_PUSH_BURST = 20

/** Notifications a free destination may receive in an hour. */
export const FREE_PUSH_PER_HOUR = 60

/** How often suppressed notifications collapse into one attention update, in milliseconds. */
export const PUSH_COLLAPSE_WINDOW_MS = 5 * 60 * 1000

/** Bytes `crypto_box_easy` adds to the plaintext it seals. */
export const SEAL_OVERHEAD_BYTES = 16

/** The granularity a notification's plaintext is padded to, in bytes. */
export const NOTIFICATION_GRANULARITY_BYTES = 1024

/**
 * The largest declared size bucket a notification preview may carry, in bytes.
 *
 * Section 20's padding rounds plaintext up to 16 KiB to the next kibibyte, so 17 KiB is the largest
 * bucket that rule produces at notification granularity. Anything larger was padded under a
 * different rule and is not a notification.
 */
export const MAX_NOTIFICATION_BUCKET_BYTES = 17 * 1024

/** The free allowance of section 16, as a rate policy. */
export const FREE_RATE_POLICY: PushRatePolicy = {
  burst: String(FREE_PUSH_BURST),
  collapse_window_ms: String(PUSH_COLLAPSE_WINDOW_MS),
  sustained_per_hour: String(FREE_PUSH_PER_HOUR)
}

/** Bytes in an Ed25519 public key. */
const KEY_BYTES = 32

/** Bytes in an Ed25519 detached signature. */
const SIGNATURE_BYTES = 64

/** The platforms the gateway builds a payload for. */
export const PUSH_PLATFORMS: readonly PushPlatform[] = ['android', 'ios']

/**
 * The generic alert text each alert shows before anything is decrypted.
 *
 * A sender chooses an alert; it never supplies text. There is no field anywhere in a delivery
 * request for sender-supplied text, so command text and approval arguments cannot reach a lock
 * screen by mistake or by a host that decided to.
 */
export const PUSH_ALERT_TEXT: Readonly<Record<PushAlert, string>> = {
  session_needs_attention: 'A KalaReach session needs attention.',
  approval_waiting: 'A KalaReach session is waiting for an approval.',
  question_waiting: 'A KalaReach session is waiting for an answer.',
  work_complete: 'A KalaReach session has work to review.',
  host_unreachable: 'A KalaReach host stopped responding.',
  attention_update: 'Several KalaReach sessions need attention.'
}

/** The FCM Android message priority each urgency asks for. */
export const FCM_PRIORITY: Readonly<Record<PushUrgency, string>> = {
  attention: 'high',
  deferred: 'normal'
}

/** The `apns-priority` header value each urgency asks for. */
export const APNS_PRIORITY: Readonly<Record<PushUrgency, string>> = {
  attention: '10',
  deferred: '5'
}

/** Raised when a payload does not match the closed schema its signature covers. */
export class PushSchemaError extends Error {
  constructor (message: string) {
    super(message)
    this.name = 'PushSchemaError'
  }
}

function refuse (message: string): never {
  throw new PushSchemaError(message)
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

/** An identifier the protocol carries as sixteen bytes, from its hyphenated text. */
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

/** A bounded opaque identifier, exactly as `kr_protocol::ids` admits one. */
const MAX_OPAQUE_ID_BYTES = 256

function opaqueIdentifier (what: string, value: unknown): CanonicalValue {
  if (typeof value !== 'string' || value === '') {
    refuse(`${what} is a non-empty identifier`)
  }
  if (new TextEncoder().encode(value).length > MAX_OPAQUE_ID_BYTES) {
    refuse(`${what} is at most ${String(MAX_OPAQUE_ID_BYTES)} bytes`)
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(value)) {
    refuse(`${what} carries no control characters`)
  }
  return krText(value)
}

/** One of a closed set of wire strings. */
function member<T extends string> (what: string, value: unknown, permitted: readonly T[]): T {
  if (typeof value !== 'string' || !(permitted as readonly string[]).includes(value)) {
    refuse(`${JSON.stringify(value)} is not ${what}`)
  }
  return value as T
}

/** A 32-byte public key in its unpadded base64url form. */
function key (what: string, value: unknown): CanonicalValue {
  return krBytes(fixedBytes(what, value, KEY_BYTES))
}

function signingInput (domain: string, payload: CanonicalValue): Uint8Array {
  return encodeCanonical(krArray([krText(domain), payload]))
}

/** The longest a provider registration token may be, in bytes. */
export const MAX_REGISTRATION_TOKEN_LEN = 1024

/** A provider registration token: printable ASCII without spaces, bounded. */
export function registrationToken (value: unknown): string {
  if (typeof value !== 'string' || value === '') {
    refuse('a registration token is not empty')
  }
  if (new TextEncoder().encode(value).length > MAX_REGISTRATION_TOKEN_LEN) {
    refuse(`a registration token is at most ${String(MAX_REGISTRATION_TOKEN_LEN)} bytes`)
  }
  for (const character of value) {
    const code = character.codePointAt(0) as number
    if (code < 0x21 || code > 0x7e) {
      refuse('a registration token is printable ASCII without spaces')
    }
  }
  return value
}

/**
 * The digest one provider token is indexed by.
 *
 * `SHA-256(CBOR(["kr-push-token/1", token]))`. Nothing about the caller goes into it, the platform
 * label least of all: receiving the challenge proves the token reaches this device and proves
 * nothing about the label beside it, so a digest that included the label would let one device
 * register one token twice and start its rate history again.
 *
 * The gateway indexes and counts by this. The token itself is a delivery capability, so it is held
 * where the gateway keeps its own secrets and never travels in a record.
 */
export async function tokenDigest (token: string): Promise<Uint8Array> {
  const encoded = encodeCanonical(
    krArray([krText(PUSH_TOKEN_DOMAIN), krText(registrationToken(token))])
  )
  const digest = await crypto.subtle.digest('SHA-256', encoded as unknown as BufferSource)
  return new Uint8Array(digest)
}

/** The digest a delivery credential's bearer is stored and matched under. */
export async function credentialDigest (secret: Uint8Array): Promise<Uint8Array> {
  if (secret.length !== 32) {
    refuse(`a delivery credential is 32 bytes, not ${String(secret.length)}`)
  }
  const encoded = encodeCanonical(krArray([krText(PUSH_CREDENTIAL_DOMAIN), krBytes(secret)]))
  const digest = await crypto.subtle.digest('SHA-256', encoded as unknown as BufferSource)
  return new Uint8Array(digest)
}

const ANSWER_FIELDS = [
  'challenge',
  'expires_at_ms',
  'gateway_origin',
  'installation_id',
  'platform',
  'registration_id',
  'token_digest'
] as const

/**
 * The bytes a registration answer is signed over.
 *
 * `CBOR(["kr-push-registration/1", the payload as a canonical map])`.
 *
 * Every field of the challenge is covered, so an answer is a statement about one attempt, one token
 * and one gateway. Without the token digest an answer would activate a token nobody proved receipt
 * of; without the origin it would answer another deployment's challenge; without the registration
 * identifier it would complete whichever attempt happened to be pending.
 */
export function registrationAnswerSigningInput (
  payload: PushRegistrationAnswerPayload
): Uint8Array {
  return signingInput(PUSH_REGISTRATION_ANSWER_DOMAIN, registrationAnswerPayloadValue(payload))
}

/** The canonical value of a registration answer's payload. */
function registrationAnswerPayloadValue (payload: unknown): CanonicalValue {
  const record = closed('a registration answer', payload, ANSWER_FIELDS)
  return krMap([
      ['challenge', krBytes(fixedBytes('a challenge', record['challenge'], NONCE_BYTES))],
      ['expires_at_ms', counter('a challenge expiry', record['expires_at_ms'])],
      ['gateway_origin', krText(gatewayOrigin('a gateway origin', record['gateway_origin']))],
      ['installation_id', uuid('an installation identifier', record['installation_id'])],
      ['platform', krText(member('a push platform', record['platform'], PUSH_PLATFORMS))],
      ['registration_id', uuid('a registration identifier', record['registration_id'])],
      ['token_digest', krBytes(fixedBytes('a token digest', record['token_digest'], DIGEST_BYTES))]
  ])
}

const RATE_POLICY_FIELDS = ['burst', 'collapse_window_ms', 'sustained_per_hour'] as const

function ratePolicyValue (value: unknown): CanonicalValue {
  const record = closed('a rate policy', value, RATE_POLICY_FIELDS)
  return krMap([
    ['burst', counter('a burst allowance', record['burst'])],
    ['collapse_window_ms', counter('a collapse window', record['collapse_window_ms'])],
    ['sustained_per_hour', counter('an hourly allowance', record['sustained_per_hour'])]
  ])
}

const SENDER_BINDING_FIELDS = [
  'gateway_origin',
  'host_endpoint_key',
  'host_signing_key',
  'installation_id',
  'rate_policy',
  'sender_record_id'
] as const

/**
 * The bytes one sender authorisation is digested from.
 *
 * `CBOR(["kr-push-sender/1", the binding as a canonical map])`.
 *
 * It holds everything a renewal must not change, and nothing else, so comparing two digests is the
 * whole of the check rather than a list of fields somebody has to remember to extend.
 */
export function senderBindingSigningInput (binding: PushSenderBinding): Uint8Array {
  const record = closed('a sender binding', binding, SENDER_BINDING_FIELDS)
  return signingInput(
    PUSH_SENDER_BINDING_DOMAIN,
    krMap([
      ['gateway_origin', krText(gatewayOrigin('a gateway origin', record['gateway_origin']))],
      ['host_endpoint_key', key('a host endpoint key', record['host_endpoint_key'])],
      ['host_signing_key', key('a host signing key', record['host_signing_key'])],
      ['installation_id', uuid('an installation identifier', record['installation_id'])],
      ['rate_policy', ratePolicyValue(record['rate_policy'])],
      ['sender_record_id', uuid('a sender record identifier', record['sender_record_id'])]
    ])
  )
}

/** The digest of one sender authorisation. A renewal preserves it or it is not a renewal. */
export async function senderBindingDigest (binding: PushSenderBinding): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    senderBindingSigningInput(binding) as unknown as BufferSource
  )
  return new Uint8Array(digest)
}

const RENEWAL_FIELDS = [
  'gateway_nonce',
  'gateway_origin',
  'requested_at_ms',
  'sender_record_id'
] as const

/**
 * The bytes a renewal proof is signed over.
 *
 * `CBOR(["kr-push-sender-renewal/1", the payload as a canonical map])`.
 *
 * The nonce is the gateway's, handed out for this renewal and accepted once, so a renewal is a
 * reply to a question the gateway asked a moment ago rather than a statement usable for as long as
 * the host key lives.
 */
export function senderRenewalSigningInput (payload: PushSenderRenewalPayload): Uint8Array {
  return signingInput(PUSH_SENDER_RENEWAL_DOMAIN, renewalPayloadValue(payload))
}

/** The canonical value of a renewal proof's payload. */
function renewalPayloadValue (payload: unknown): CanonicalValue {
  const record = closed('a renewal proof', payload, RENEWAL_FIELDS)
  return krMap([
      ['gateway_nonce', krBytes(fixedBytes('a gateway nonce', record['gateway_nonce'], NONCE_BYTES))],
      ['gateway_origin', krText(gatewayOrigin('a gateway origin', record['gateway_origin']))],
    ['requested_at_ms', counter('a renewal time', record['requested_at_ms'])],
    ['sender_record_id', uuid('a sender record identifier', record['sender_record_id'])]
  ])
}

const REVOCATION_FIELDS = [
  'gateway_nonce',
  'gateway_origin',
  'reason',
  'requested_at_ms',
  'sender_record_id'
] as const

/** Why a sender authorisation ended. */
export const PUSH_REVOCATION_REASONS: readonly PushSenderRevocationPayload['reason'][] = [
  'unpaired',
  'host_key_replaced',
  'installation_key_replaced'
]

/**
 * The bytes a revocation is signed over.
 *
 * `CBOR(["kr-push-sender-revocation/1", the payload as a canonical map])`.
 */
export function senderRevocationSigningInput (payload: PushSenderRevocationPayload): Uint8Array {
  return signingInput(PUSH_SENDER_REVOCATION_DOMAIN, revocationPayloadValue(payload))
}

/** The canonical value of a revocation's payload. */
function revocationPayloadValue (payload: unknown): CanonicalValue {
  const record = closed('a revocation', payload, REVOCATION_FIELDS)
  return krMap([
      ['gateway_nonce', krBytes(fixedBytes('a gateway nonce', record['gateway_nonce'], NONCE_BYTES))],
      ['gateway_origin', krText(gatewayOrigin('a gateway origin', record['gateway_origin']))],
    ['reason', krText(member('a revocation reason', record['reason'], PUSH_REVOCATION_REASONS))],
    ['requested_at_ms', counter('a revocation time', record['requested_at_ms'])],
    ['sender_record_id', uuid('a sender record identifier', record['sender_record_id'])]
  ])
}

const HINTS_FIELDS = ['alert', 'urgency'] as const

/** The closed alert vocabulary, in the order the protocol declares it. */
export const PUSH_ALERTS: readonly PushAlert[] = [
  'session_needs_attention',
  'approval_waiting',
  'question_waiting',
  'work_complete',
  'host_unreachable',
  'attention_update'
]

/** The urgencies, in the order the protocol declares them. */
export const PUSH_URGENCIES: readonly PushUrgency[] = ['attention', 'deferred']

function hintsValue (value: unknown): CanonicalValue {
  const record = closed('platform hints', value, HINTS_FIELDS)
  return krMap([
    ['alert', krText(member('a push alert', record['alert'], PUSH_ALERTS))],
    ['urgency', krText(member('a push urgency', record['urgency'], PUSH_URGENCIES))]
  ])
}

const ENVELOPE_ROUTING_FIELDS = [
  'envelope_id',
  'expires_at_ms',
  'recipient_key_id',
  'sender_key_id',
  'size_bucket_bytes'
] as const

const SEALED_ENVELOPE_FIELDS = ['ciphertext', 'nonce', 'routing'] as const

/** Bytes in the nonce a sealed envelope carries. */
const ENVELOPE_NONCE_BYTES = 24

/** Bytes in a key identifier. */
const KEY_ID_BYTES = 32

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

/** The canonical value of a sealed envelope, as `kr_protocol::mailbox` encodes one. */
function sealedEnvelopeValue (value: unknown): CanonicalValue {
  const envelope = closed('a sealed preview', value, SEALED_ENVELOPE_FIELDS)
  const routing = closed('a sealed preview routing record', envelope['routing'], ENVELOPE_ROUTING_FIELDS)
  return krMap([
    ['ciphertext', krBytes(opaqueBytes('a sealed preview ciphertext', envelope['ciphertext']))],
    ['nonce', krBytes(fixedBytes('a sealed preview nonce', envelope['nonce'], ENVELOPE_NONCE_BYTES))],
    [
      'routing',
      krMap([
        ['envelope_id', uuid('an envelope identifier', routing['envelope_id'])],
        ['expires_at_ms', counter('an envelope expiry', routing['expires_at_ms'])],
        [
          'recipient_key_id',
          krBytes(fixedBytes('a recipient key identifier', routing['recipient_key_id'], KEY_ID_BYTES))
        ],
        [
          'sender_key_id',
          krBytes(fixedBytes('a sender key identifier', routing['sender_key_id'], KEY_ID_BYTES))
        ],
        ['size_bucket_bytes', counter('a declared size bucket', routing['size_bucket_bytes'])]
      ])
    ]
  ])
}

const DELIVERY_FIELDS = [
  'collapse_id',
  'expires_at_ms',
  'hints',
  'notification_id',
  'preview',
  'sender_record_id'
] as const

/**
 * The bytes a delivery request is digested from.
 *
 * `CBOR(["kr-push-delivery/1", the request as a canonical map])`.
 *
 * The schema is the structural guarantee section 16 asks for: there is no field here for text a
 * sender supplies. The notification and collapse identifiers are 128 opaque bits rather than text,
 * the alert comes from a closed vocabulary whose words live in this module, and the preview is a
 * sealed envelope rather than arbitrary bytes.
 */
export function deliveryRequestSigningInput (request: PushDeliveryRequest): Uint8Array {
  const record = closed('a delivery request', request, DELIVERY_FIELDS)
  const preview = record['preview']
  return signingInput(
    PUSH_DELIVERY_DOMAIN,
    krMap([
      ['collapse_id', uuid('a collapse identifier', record['collapse_id'])],
      ['expires_at_ms', counter('a notification expiry', record['expires_at_ms'])],
      ['hints', hintsValue(record['hints'])],
      ['notification_id', uuid('a notification identifier', record['notification_id'])],
      ['preview', preview === null ? krNull() : sealedEnvelopeValue(preview)],
      ['sender_record_id', uuid('a sender record identifier', record['sender_record_id'])]
    ])
  )
}

/**
 * True when the sealed preview is shaped the way a notification preview is shaped.
 *
 * Three things a gateway can check about a ciphertext it cannot read: that the envelope expires
 * when the notification does, that the declared size bucket is a notification bucket, and that the
 * ciphertext is exactly that bucket plus the seal's overhead. Together they bound what a host can
 * put in front of a provider; they do not prove the plaintext was encrypted correctly, which only
 * the destination can tell.
 */
export function previewIsWellFormed (request: PushDeliveryRequest): boolean {
  const preview = request.preview
  if (preview === null) {
    return true
  }
  const bucket = jsonToU64(preview.routing.size_bucket_bytes)
  const ciphertext = BigInt(base64UrlToBytes(preview.ciphertext).length)
  return (
    preview.routing.expires_at_ms === request.expires_at_ms &&
    bucket > 0n &&
    bucket % BigInt(NOTIFICATION_GRANULARITY_BYTES) === 0n &&
    bucket <= BigInt(MAX_NOTIFICATION_BUCKET_BYTES) &&
    ciphertext === bucket + BigInt(SEAL_OVERHEAD_BYTES)
  )
}

/**
 * The digest the gateway recognises a notification by.
 *
 * Delivery carries the bearer credential the host was issued rather than a signature, so this is not
 * a signing input. It is how a retry of the same notification is recognised as the same request,
 * and how a second request reusing a notification identifier with anything else changed is
 * recognised as a conflict rather than a retry.
 */
export async function deliveryRequestDigest (request: PushDeliveryRequest): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    deliveryRequestSigningInput(request) as unknown as BufferSource
  )
  return new Uint8Array(digest)
}

/**
 * True when a built provider payload is inside the section 16 bound.
 *
 * The argument is the length of the complete request body about to be sent, after encryption and
 * after base64, because that is the figure section 16 names and the only one a provider sees. The
 * bound is exclusive, as section 16 words it: below 3,500 bytes.
 */
export function providerPayloadWithinPolicy (payloadLength: number): boolean {
  return payloadLength < MAX_PROVIDER_PAYLOAD_BYTES
}

/**
 * When a host may start renewing: seven days before the credential expires.
 *
 * The arithmetic is in `bigint` and saturates at zero, as the host does, so an expiry inside the
 * window does not produce a negative instant that every clock is already past.
 */
export function renewalOpensAtMs (credentialExpiresAtMs: number | bigint): bigint {
  const expires = BigInt(credentialExpiresAtMs)
  const window = BigInt(SENDER_RENEWAL_WINDOW_MS)
  return expires > window ? expires - window : 0n
}

// ----- Request bodies -------------------------------------------------------------------------

/** The domain a signed push request body is digested under. */
export const PUSH_REQUEST_DOMAIN = 'kr-push-request/1'

const PROPOSAL_FIELDS = [
  'installation_key',
  'platform',
  'registration_id',
  'registration_token'
] as const

const ISSUE_FIELDS = ['host_endpoint_key', 'host_signing_key', 'sender_record_id'] as const

const NONCE_REQUEST_FIELDS = ['sender_record_id'] as const

/** The method each request body belongs to, and who must have signed it. */
export const PUSH_REQUEST_METHODS = {
  installation_register: { method: 'push.installation.register', signer: 'installation' },
  sender_issue: { method: 'push.sender.issue', signer: 'installation' },
  sender_renew: { method: 'push.sender.renew', signer: 'host' },
  sender_revoke: { method: 'push.sender.revoke', signer: 'host' }
} as const

/** The one variant of a tagged union, refusing a body that carries two or none. */
function variant<T extends string> (
  what: string,
  value: unknown,
  permitted: readonly T[]
): [T, unknown] {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    refuse(`${what} is an object`)
  }
  const entries = Object.entries(value as Record<string, unknown>)
  if (entries.length !== 1) {
    refuse(`${what} names exactly one of ${permitted.join(', ')}`)
  }
  const [tag, payload] = entries[0] as [string, unknown]
  if (!(permitted as readonly string[]).includes(tag)) {
    refuse(`${JSON.stringify(tag)} is not ${what}`)
  }
  return [tag as T, payload]
}

function proposalValue (value: unknown): CanonicalValue {
  const record = closed('a registration proposal', value, PROPOSAL_FIELDS)
  return krMap([
    ['installation_key', key('an installation key', record['installation_key'])],
    ['platform', krText(member('a push platform', record['platform'], PUSH_PLATFORMS))],
    ['registration_id', uuid('a registration identifier', record['registration_id'])],
    ['registration_token', krText(registrationToken(record['registration_token']))]
  ])
}

function registrationRequestValue (value: unknown): CanonicalValue {
  const [tag, payload] = variant('a registration request', value, ['propose', 'answer'] as const)
  if (tag === 'propose') {
    const wrapper = closed('a registration proposal request', payload, ['proposal'] as const)
    return krMap([['propose', krMap([['proposal', proposalValue(wrapper['proposal'])]])]])
  }
  const wrapper = closed('a registration answer request', payload, ['answer'] as const)
  const answer = closed('a registration answer', wrapper['answer'], [
    'installation_key',
    'payload',
    'signature'
  ] as const)
  return krMap([
    [
      'answer',
      krMap([
        [
          'answer',
          krMap([
            ['installation_key', key('an installation key', answer['installation_key'])],
            ['payload', registrationAnswerPayloadValue(answer['payload'])],
            ['signature', krBytes(fixedBytes('a signature', answer['signature'], SIGNATURE_BYTES))]
          ])
        ]
      ])
    ]
  ])
}

function issueRequestValue (value: unknown): CanonicalValue {
  const wrapper = closed('a sender issue request', value, ['request'] as const)
  const record = closed('a sender issue body', wrapper['request'], ISSUE_FIELDS)
  return krMap([
    [
      'request',
      krMap([
        ['host_endpoint_key', key('a host endpoint key', record['host_endpoint_key'])],
        ['host_signing_key', key('a host signing key', record['host_signing_key'])],
        ['sender_record_id', uuid('a sender record identifier', record['sender_record_id'])]
      ])
    ]
  ])
}

function nonceRequestValue (value: unknown): CanonicalValue {
  const record = closed('a nonce request', value, NONCE_REQUEST_FIELDS)
  return krMap([['sender_record_id', uuid('a sender record identifier', record['sender_record_id'])]])
}

function renewRequestValue (value: unknown): CanonicalValue {
  const [tag, payload] = variant('a renewal request', value, ['begin', 'complete'] as const)
  if (tag === 'begin') {
    const wrapper = closed('a renewal nonce request', payload, ['request'] as const)
    return krMap([['begin', krMap([['request', nonceRequestValue(wrapper['request'])]])]])
  }
  const wrapper = closed('a renewal proof request', payload, ['renewal'] as const)
  const renewal = closed('a renewal proof', wrapper['renewal'], ['payload', 'signature'] as const)
  return krMap([
    [
      'complete',
      krMap([
        [
          'renewal',
          krMap([
            ['payload', renewalPayloadValue(renewal['payload'])],
            ['signature', krBytes(fixedBytes('a signature', renewal['signature'], SIGNATURE_BYTES))]
          ])
        ]
      ])
    ]
  ])
}

function revokeRequestValue (value: unknown): CanonicalValue {
  const [tag, payload] = variant('a revocation request', value, ['begin', 'complete'] as const)
  if (tag === 'begin') {
    const wrapper = closed('a revocation nonce request', payload, ['request'] as const)
    return krMap([['begin', krMap([['request', nonceRequestValue(wrapper['request'])]])]])
  }
  const wrapper = closed('a revocation request body', payload, ['revocation'] as const)
  const revocation = closed('a revocation', wrapper['revocation'], ['payload', 'signature'] as const)
  return krMap([
    [
      'complete',
      krMap([
        [
          'revocation',
          krMap([
            ['payload', revocationPayloadValue(revocation['payload'])],
            [
              'signature',
              krBytes(fixedBytes('a signature', revocation['signature'], SIGNATURE_BYTES))
            ]
          ])
        ]
      ])
    ]
  ])
}

/**
 * The bytes a signed push request body is digested from.
 *
 * `CBOR(["kr-push-request/1", the body as a canonical map])`. The digest is what a service-request
 * signature carries as its `body_digest`, and {@link pushRequestMethod} is the method that signature
 * must name, so a body built for one method cannot be presented under another.
 */
export function pushRequestSigningInput (request: PushRequest): Uint8Array {
  const [tag, payload] = variant(
    'a push request',
    request,
    Object.keys(PUSH_REQUEST_METHODS) as Array<keyof typeof PUSH_REQUEST_METHODS>
  )
  const body =
    tag === 'installation_register'
      ? krMap([
          [
            'installation_register',
            krMap([
              [
                'request',
                registrationRequestValue(
                  closed('a registration request body', payload, ['request'] as const)['request']
                )
              ]
            ])
          ]
        ])
      : tag === 'sender_issue'
        ? krMap([['sender_issue', issueRequestValue(payload)]])
        : tag === 'sender_renew'
          ? krMap([
              [
                'sender_renew',
                krMap([
                  [
                    'request',
                    renewRequestValue(
                      closed('a renewal request body', payload, ['request'] as const)['request']
                    )
                  ]
                ])
              ]
            ])
          : krMap([
              [
                'sender_revoke',
                krMap([
                  [
                    'request',
                    revokeRequestValue(
                      closed('a revocation request body', payload, ['request'] as const)['request']
                    )
                  ]
                ])
              ]
            ])
  return signingInput(PUSH_REQUEST_DOMAIN, body)
}

/** The digest a service-request signature carries as its `body_digest`. */
export async function pushRequestDigest (request: PushRequest): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    pushRequestSigningInput(request) as unknown as BufferSource
  )
  return new Uint8Array(digest)
}

/** The method a signature over this body must name. */
export function pushRequestMethod (request: PushRequest): string {
  const [tag] = variant(
    'a push request',
    request,
    Object.keys(PUSH_REQUEST_METHODS) as Array<keyof typeof PUSH_REQUEST_METHODS>
  )
  return PUSH_REQUEST_METHODS[tag].method
}

/** Who must have signed the request carrying this body. */
export function pushRequestSigner (request: PushRequest): string {
  const [tag] = variant(
    'a push request',
    request,
    Object.keys(PUSH_REQUEST_METHODS) as Array<keyof typeof PUSH_REQUEST_METHODS>
  )
  return PUSH_REQUEST_METHODS[tag].signer
}
