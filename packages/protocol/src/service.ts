/**
 * The exact bytes a managed-service request is authenticated over.
 *
 * Every method in the `Services` group reaches the web service as JSON over HTTPS, and JSON is
 * never what a signature covers. Before the service can believe a request it has to rebuild the
 * canonical KR-CBOR-1 payload the caller signed, field by field, from the representation that
 * arrived. That is what this module does, and it is the TypeScript half of
 * `kr_protocol::service`: the same two domains, the same field names, the same encoding, checked
 * against `fixtures/service/requests.json`.
 *
 * The schema is closed. A payload carrying a field nobody agreed on, a counter that is not an exact
 * unsigned integer, or a method outside the registry is refused rather than narrowed to the part
 * this version understands.
 *
 * {@link installationId} derives the caller's identity from the key that signed, so a caller never
 * asserts who it is. A service that trusted an identifier in the body would be trusting the
 * caller's word about the one thing the signature already proves.
 */

import { encodeCanonical } from './cbor/encode.js'
import { krArray, krBytes, krInt, krMap, krText, type CanonicalValue } from './cbor/value.js'
import { base64UrlToBytes, jsonToU64, uuidToJson } from './json.js'
import {
  HTTP_DEFAULT_PORT,
  HTTPS_DEFAULT_PORT,
  OriginError,
  isLoopbackAuthority,
  validateAuthority
} from './origin.js'
import type { ServiceRequestPayload, ServiceRequestSignature } from './generated/protocol.js'

/** A method name, as the registry spells it. */
export type Method = ServiceRequestPayload['method']

/** Which key signed a service request, and therefore which domain it is checked under. */
export type ServiceRequestSigner = ServiceRequestSignature['signer']

/** The domain an installation's service-request signature covers. */
export const SERVICE_REQUEST_DOMAIN = 'kr-service-request/1'

/** The domain a host's service-request signature covers. */
export const SERVICE_REQUEST_HOST_DOMAIN = 'kr-service-request/1/host'

/** How far a signature's stated time may be from the service's own, in milliseconds. */
export const SERVICE_REQUEST_FRESHNESS_MS = 5 * 60 * 1000

/** The longest a gateway origin may be, in bytes. */
export const MAX_GATEWAY_ORIGIN_LEN = 128

/** Bytes in a SHA-256 digest. */
export const DIGEST_BYTES = 32

/** Bytes in a nonce. */
export const NONCE_BYTES = 32

/** Raised when a payload does not match the closed schema its signature covers. */
export class ServiceSchemaError extends Error {
  constructor (message: string) {
    super(message)
    this.name = 'ServiceSchemaError'
  }
}

function refuse (message: string): never {
  throw new ServiceSchemaError(message)
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

/** A fixed-width scalar read from its base64url text. */
export function fixedBytes (what: string, value: unknown, width: number): Uint8Array {
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

/**
 * An origin exactly as `kr_protocol::service::GatewayOrigin` admits one.
 *
 * The grammar is the shared one in `./origin.js`: a scheme, a canonically spelled host, an optional
 * non-default port, and nothing else. The one difference from a rendezvous origin is the scheme:
 * `http://` is admitted for a loopback host, which is what a development deployment serves on, and
 * refused for anything else.
 */
export function gatewayOrigin (what: string, value: unknown): string {
  if (typeof value !== 'string' || value === '') {
    refuse(`${what} is a non-empty origin`)
  }
  if (new TextEncoder().encode(value).length > MAX_GATEWAY_ORIGIN_LEN) {
    refuse(`${what} is at most ${String(MAX_GATEWAY_ORIGIN_LEN)} bytes`)
  }

  let authority: string
  let defaultPort: number
  if (value.startsWith('https://')) {
    authority = value.slice('https://'.length)
    defaultPort = HTTPS_DEFAULT_PORT
  } else if (value.startsWith('http://')) {
    authority = value.slice('http://'.length)
    if (!isLoopbackAuthority(authority)) {
      refuse('only a loopback gateway origin may use http')
    }
    defaultPort = HTTP_DEFAULT_PORT
  } else {
    refuse(`${what} names its scheme`)
  }

  try {
    validateAuthority(authority, defaultPort)
  } catch (error) {
    refuse(error instanceof OriginError ? error.message : `${what} is an origin`)
  }
  return value
}

/** The domain a signer's signatures are separated by. */
export function signerDomain (signer: ServiceRequestSigner): string {
  switch (signer) {
    case 'installation':
      return SERVICE_REQUEST_DOMAIN
    case 'host':
      return SERVICE_REQUEST_HOST_DOMAIN
    default:
      return refuse(`${JSON.stringify(signer)} is not a service request signer`)
  }
}

const PAYLOAD_FIELDS = [
  'body_digest',
  'gateway_origin',
  'method',
  'nonce',
  'signed_at_ms'
] as const

/**
 * The method names a service credential may name.
 *
 * It is the `Services` group of the registry and nothing else. A signature naming a host method is
 * refused rather than checked: no managed service holds the authority to run one, so a credential
 * that could name one would be a credential a caller could aim somewhere it was never meant to go.
 */
export const SERVICE_METHODS: readonly Method[] = [
  'push.installation.register',
  'push.sender.issue',
  'push.sender.renew',
  'push.sender.revoke',
  'mailbox.read',
  'authority.sync',
  'sync.compare_exchange',
  'backup.manifest'
]

/** True when `method` is one a service credential may name. */
export function isServiceMethod (method: unknown): method is Method {
  return typeof method === 'string' && (SERVICE_METHODS as readonly string[]).includes(method)
}

/**
 * The bytes a service request is signed over.
 *
 * `CBOR([domain, the payload as a canonical map])`, where the domain is the signer's.
 *
 * Five fields, each one load bearing. The origin stops a signature made for one deployment being
 * replayed against another; the method stops a signature for a read authorising a write; the nonce
 * stops the same request being accepted twice; the time bounds how long a captured request stays
 * usable; the body digest stops the body being swapped under a signature that still verifies.
 */
export function serviceRequestSigningInput (
  payload: ServiceRequestPayload,
  signer: ServiceRequestSigner
): Uint8Array {
  const record = closed('a service request', payload, PAYLOAD_FIELDS)
  if (!isServiceMethod(record['method'])) {
    refuse(`${JSON.stringify(record['method'])} is not a managed-service method`)
  }
  return encodeCanonical(
    krArray([
      krText(signerDomain(signer)),
      krMap([
        ['body_digest', krBytes(fixedBytes('a body digest', record['body_digest'], DIGEST_BYTES))],
        ['gateway_origin', krText(gatewayOrigin('a gateway origin', record['gateway_origin']))],
        ['method', krText(record['method'] as string)],
        ['nonce', krBytes(fixedBytes('a nonce', record['nonce'], NONCE_BYTES))],
        ['signed_at_ms', counter('a signing time', record['signed_at_ms'])]
      ])
    ])
  )
}

/**
 * True when `nowMs` is inside the freshness window either side of the signing time.
 *
 * The arithmetic is in `bigint`, because a signing time is an unsigned 64-bit counter and a
 * `number` cannot hold every one of them exactly. A comparison that rounded would admit a signature
 * the host refuses, or refuse one it admits.
 */
export function isFreshAt (payload: ServiceRequestPayload, nowMs: number | bigint): boolean {
  const signed = jsonToU64(payload.signed_at_ms)
  const now = BigInt(nowMs)
  const distance = now >= signed ? now - signed : signed - now
  return distance <= BigInt(SERVICE_REQUEST_FRESHNESS_MS)
}

/**
 * The instant a nonce may be forgotten: the signing time plus twice the window.
 *
 * It saturates at the largest unsigned 64-bit value, as the host does, so a signature dated at the
 * end of time does not wrap round to a nonce that may be forgotten at once.
 */
export function nonceRetainedUntilMs (signedAtMs: number | bigint): bigint {
  const signed = BigInt(signedAtMs)
  const retained = signed + BigInt(2 * SERVICE_REQUEST_FRESHNESS_MS)
  const ceiling = (1n << 64n) - 1n
  return retained > ceiling ? ceiling : retained
}

/**
 * The installation a device authorisation key names.
 *
 * The first sixteen bytes of the key's SHA-256, in hyphenated form. It is derived rather than
 * asserted, so a caller that signs with a key has already proved which installation it is and
 * cannot choose to be another.
 */
export async function installationId (publicKey: Uint8Array): Promise<string> {
  if (publicKey.length !== 32) {
    refuse(`an authorisation key is 32 bytes, not ${String(publicKey.length)}`)
  }
  const digest = await crypto.subtle.digest('SHA-256', publicKey as unknown as BufferSource)
  return uuidToJson(new Uint8Array(digest).subarray(0, 16))
}

/** The SHA-256 of a canonical request body, as the payload carries it. */
export async function bodyDigest (canonicalBody: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', canonicalBody as unknown as BufferSource)
  return new Uint8Array(digest)
}
