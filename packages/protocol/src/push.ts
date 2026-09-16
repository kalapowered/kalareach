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
import { krArray, krBytes, krInt, krMap, krText, type CanonicalValue } from './cbor/value.js'
import { base64UrlToBytes, jsonToU64, jsonToUuid } from './json.js'
import { DIGEST_BYTES, NONCE_BYTES, fixedBytes, gatewayOrigin } from './service.js'
import type {
  PushDeliveryRequest,
  PushInstallationBinding,
  PushPlatformHints,
  PushRatePolicy,
  PushRegistrationAnswerPayload,
  PushSenderBinding,
  PushSenderRenewalPayload,
  PushSenderRevocationPayload
} from './generated/protocol.js'

/** The generic alert a device shows before anything is decrypted. */
export type PushAlert = PushPlatformHints['alert']

/** How urgently a provider is asked to deliver. */
export type PushUrgency = PushPlatformHints['urgency']

/** A push platform, as the gateway builds a payload for it. */
export type PushPlatform = PushInstallationBinding['platform']

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

/** The free allowance of section 16, as a rate policy. */
export const FREE_RATE_POLICY: PushRatePolicy = {
  burst: String(FREE_PUSH_BURST),
  collapse_window_ms: String(PUSH_COLLAPSE_WINDOW_MS),
  sustained_per_hour: String(FREE_PUSH_PER_HOUR)
}

/** Bytes in an Ed25519 public key. */
const KEY_BYTES = 32

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

/**
 * The digest a provider token is recorded under.
 *
 * `SHA-256(CBOR(["kr-push-token/1", platform, token]))`. The gateway stores this rather than the
 * token, because a registration token is a delivery capability: anything holding one can be sent to
 * through the provider. The platform is inside the digest, so one token registered on two platforms
 * is two destinations rather than one.
 */
export async function tokenDigest (platform: PushPlatform, token: string): Promise<Uint8Array> {
  const encoded = encodeCanonical(
    krArray([
      krText(PUSH_TOKEN_DOMAIN),
      krText(member('a push platform', platform, PUSH_PLATFORMS)),
      krText(token)
    ])
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
  const record = closed('a registration answer', payload, ANSWER_FIELDS)
  return signingInput(
    PUSH_REGISTRATION_ANSWER_DOMAIN,
    krMap([
      ['challenge', krBytes(fixedBytes('a challenge', record['challenge'], NONCE_BYTES))],
      ['expires_at_ms', counter('a challenge expiry', record['expires_at_ms'])],
      ['gateway_origin', krText(gatewayOrigin('a gateway origin', record['gateway_origin']))],
      ['installation_id', uuid('an installation identifier', record['installation_id'])],
      ['platform', krText(member('a push platform', record['platform'], PUSH_PLATFORMS))],
      ['registration_id', uuid('a registration identifier', record['registration_id'])],
      ['token_digest', krBytes(fixedBytes('a token digest', record['token_digest'], DIGEST_BYTES))]
    ])
  )
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
  const record = closed('a renewal proof', payload, RENEWAL_FIELDS)
  return signingInput(
    PUSH_SENDER_RENEWAL_DOMAIN,
    krMap([
      ['gateway_nonce', krBytes(fixedBytes('a gateway nonce', record['gateway_nonce'], NONCE_BYTES))],
      ['gateway_origin', krText(gatewayOrigin('a gateway origin', record['gateway_origin']))],
      ['requested_at_ms', counter('a renewal time', record['requested_at_ms'])],
      ['sender_record_id', uuid('a sender record identifier', record['sender_record_id'])]
    ])
  )
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
  const record = closed('a revocation', payload, REVOCATION_FIELDS)
  return signingInput(
    PUSH_SENDER_REVOCATION_DOMAIN,
    krMap([
      ['gateway_nonce', krBytes(fixedBytes('a gateway nonce', record['gateway_nonce'], NONCE_BYTES))],
      ['gateway_origin', krText(gatewayOrigin('a gateway origin', record['gateway_origin']))],
      ['reason', krText(member('a revocation reason', record['reason'], PUSH_REVOCATION_REASONS))],
      ['requested_at_ms', counter('a revocation time', record['requested_at_ms'])],
      ['sender_record_id', uuid('a sender record identifier', record['sender_record_id'])]
    ])
  )
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
 * The schema is the structural guarantee section 16 asks for: there is no field here for plaintext
 * that describes the work. The identifier is opaque, the collapse label names no project, the alert
 * comes from a closed vocabulary, and the preview is sealed to the device.
 */
export function deliveryRequestSigningInput (request: PushDeliveryRequest): Uint8Array {
  const record = closed('a delivery request', request, DELIVERY_FIELDS)
  const preview = record['preview']
  return signingInput(
    PUSH_DELIVERY_DOMAIN,
    krMap([
      ['collapse_id', opaqueIdentifier('a collapse identifier', record['collapse_id'])],
      ['expires_at_ms', counter('a notification expiry', record['expires_at_ms'])],
      ['hints', hintsValue(record['hints'])],
      ['notification_id', opaqueIdentifier('a notification identifier', record['notification_id'])],
      [
        'preview',
        preview === null
          ? { kind: 'null' }
          : krBytes(previewBytes(preview))
      ],
      ['sender_record_id', uuid('a sender record identifier', record['sender_record_id'])]
    ])
  )
}

/** Reads the sealed preview envelope from its unpadded base64url form. */
function previewBytes (value: unknown): Uint8Array {
  if (typeof value !== 'string') {
    refuse('a sealed preview is unpadded base64url')
  }
  try {
    return base64UrlToBytes(value)
  } catch (error) {
    refuse(`a sealed preview is unpadded base64url: ${error instanceof Error ? error.message : 'invalid'}`)
  }
}

/** The digest a delivery credential's request signature covers as its body. */
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
 * after base64, because that is the figure section 16 names and the only one a provider sees.
 */
export function providerPayloadWithinPolicy (payloadLength: number): boolean {
  return payloadLength <= MAX_PROVIDER_PAYLOAD_BYTES
}

/** When a host may start renewing: seven days before the credential expires. */
export function renewalOpensAtMs (credentialExpiresAtMs: number): number {
  return credentialExpiresAtMs - SENDER_RENEWAL_WINDOW_MS
}
