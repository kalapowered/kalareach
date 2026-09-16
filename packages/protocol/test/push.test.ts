/**
 * The service-credential and push vectors, recomputed in TypeScript.
 *
 * Nothing here calls the Rust implementation. The payloads come from the JSON representation the
 * gateway carries, the bytes come from this package's own codec, and the expected bytes come from
 * the fixtures the Rust tests verify. Agreement is therefore real cross-language agreement over the
 * exact input a device authorisation key, a host signing key and a delivery credential cover.
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
  APNS_PRIORITY,
  DELIVERY_CREDENTIAL_LIFETIME_MS,
  FCM_PRIORITY,
  FREE_PUSH_BURST,
  FREE_PUSH_PER_HOUR,
  FREE_RATE_POLICY,
  MAX_PREVIEW_PLAINTEXT_BYTES,
  MAX_PROVIDER_PAYLOAD_BYTES,
  PUSH_ALERTS,
  PUSH_ALERT_TEXT,
  PUSH_COLLAPSE_WINDOW_MS,
  PUSH_DELIVERY_DOMAIN,
  PUSH_REGISTRATION_ANSWER_DOMAIN,
  PUSH_SENDER_BINDING_DOMAIN,
  PUSH_SENDER_RENEWAL_DOMAIN,
  PUSH_SENDER_REVOCATION_DOMAIN,
  PUSH_URGENCIES,
  PushSchemaError,
  REGISTRATION_CHALLENGE_LIFETIME_MS,
  SENDER_RENEWAL_WINDOW_MS,
  SERVICE_METHODS,
  SERVICE_REQUEST_DOMAIN,
  SERVICE_REQUEST_FRESHNESS_MS,
  SERVICE_REQUEST_HOST_DOMAIN,
  ServiceSchemaError,
  base64UrlToBytes,
  credentialDigest,
  decodeCanonical,
  deliveryRequestDigest,
  deliveryRequestSigningInput,
  encodeCanonical,
  installationId,
  isFreshAt,
  nonceRetainedUntilMs,
  previewIsWellFormed,
  providerPayloadWithinPolicy,
  pushRequestDigest,
  pushRequestMethod,
  pushRequestSigner,
  pushRequestSigningInput,
  registrationAnswerSigningInput,
  renewalOpensAtMs,
  senderBindingDigest,
  senderBindingSigningInput,
  senderRenewalSigningInput,
  senderRevocationSigningInput,
  serviceRequestSigningInput,
  tokenDigest,
  type PushDeliveryCredential,
  type PushDeliveryRequest,
  type PushInstallationBinding,
  type PushRegistrationAnswer,
  type PushRequest,
  type PushSenderBinding,
  type PushSenderRecord,
  type PushSenderRenewal,
  type PushSenderRevocation,
  type ServiceRequestSignature
} from '../src/index.js'
import { bytesToHex, parseValue } from './fixtures.js'

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

interface VectorCase {
  id: string
  description: string
  domain: string
  json?: unknown
  value: unknown
  cbor_hex: string
  sha256: string
}

interface ServiceFixture {
  freshness_ms: string
  installation_identity: { public_key: string, installation_id: string }
  origins: { accepted: string[], refused: string[] }
  cases: VectorCase[]
}

interface PushFixture {
  limits: Record<string, string>
  token: { platform: 'android' | 'ios', registration_token: string, token_digest: string }
  alerts: Array<{ alert: string, text: string }>
  request_methods: Array<{ body: string, method: string, signer: string }>
  records: {
    installation_binding: PushInstallationBinding
    sender_record: PushSenderRecord
    delivery_credential: PushDeliveryCredential
    credential_digest: string
  }
  cases: VectorCase[]
}

const services = JSON.parse(
  readFileSync(join(repositoryRoot, 'fixtures', 'service', 'requests.json'), 'utf8')
) as ServiceFixture

const push = JSON.parse(
  readFileSync(join(repositoryRoot, 'fixtures', 'push', 'push.json'), 'utf8')
) as PushFixture

function findCase (cases: VectorCase[], id: string): VectorCase {
  const found = cases.find((entry) => entry.id === id)
  if (found === undefined) {
    throw new Error(`no case ${id}`)
  }
  return found
}

function sha256 (bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function assertVector (cases: VectorCase[], id: string, bytes: Uint8Array): VectorCase {
  const entry = findCase(cases, id)
  expect(bytesToHex(bytes), `${id}: bytes`).toBe(entry.cbor_hex)
  expect(sha256(bytes), `${id}: digest`).toBe(entry.sha256)
  // The description grammar and the hex are two renderings of one value: a fixture that disagreed
  // with itself would let both languages agree on the wrong bytes.
  expect(bytesToHex(encodeCanonical(parseValue(entry.value))), `${id}: description`).toBe(
    entry.cbor_hex
  )
  expect(bytesToHex(encodeCanonical(decodeCanonical(bytes))), `${id}: round trip`).toBe(
    entry.cbor_hex
  )
  return entry
}

describe('the service credential', () => {
  /** KR-REQ-16.05: a registration request is proven by the installation's own key. */
  it('signs the bytes the Rust vectors publish', () => {
    const installation = findCase(services.cases, 'installation_request')
      .json as ServiceRequestSignature
    const entry = assertVector(
      services.cases,
      'installation_request',
      serviceRequestSigningInput(installation.payload, installation.signer)
    )
    expect(entry.domain).toBe(SERVICE_REQUEST_DOMAIN)
    expect(installation.signer).toBe('installation')

    const host = findCase(services.cases, 'host_request').json as ServiceRequestSignature
    const hostEntry = assertVector(
      services.cases,
      'host_request',
      serviceRequestSigningInput(host.payload, host.signer)
    )
    expect(hostEntry.domain).toBe(SERVICE_REQUEST_HOST_DOMAIN)
    expect(host.signer).toBe('host')
  })

  /** KR-REQ-16.09, KR-REQ-16.10: a host proof and an installation proof cannot be exchanged. */
  it('covers different bytes for the two signers', () => {
    const installation = findCase(services.cases, 'installation_request')
      .json as ServiceRequestSignature
    assertVector(
      services.cases,
      'same_payload_other_domain',
      serviceRequestSigningInput(installation.payload, 'host')
    )
    expect(
      bytesToHex(serviceRequestSigningInput(installation.payload, 'installation'))
    ).not.toBe(bytesToHex(serviceRequestSigningInput(installation.payload, 'host')))
  })

  it('derives the installation identity from the key that signs', async () => {
    const key = base64UrlToBytes(services.installation_identity.public_key)
    await expect(installationId(key)).resolves.toBe(services.installation_identity.installation_id)
  })

  it('admits a signature inside the window in either direction', () => {
    const installation = findCase(services.cases, 'installation_request')
      .json as ServiceRequestSignature
    const signed = Number(installation.payload.signed_at_ms)
    expect(services.freshness_ms).toBe(String(SERVICE_REQUEST_FRESHNESS_MS))
    expect(isFreshAt(installation.payload, signed)).toBe(true)
    expect(isFreshAt(installation.payload, signed + SERVICE_REQUEST_FRESHNESS_MS)).toBe(true)
    expect(isFreshAt(installation.payload, signed - SERVICE_REQUEST_FRESHNESS_MS)).toBe(true)
    expect(isFreshAt(installation.payload, signed + SERVICE_REQUEST_FRESHNESS_MS + 1)).toBe(false)
    expect(isFreshAt(installation.payload, signed - SERVICE_REQUEST_FRESHNESS_MS - 1)).toBe(false)
    // A nonce outlives the whole window a forward-dated signature could still be presented in.
    expect(nonceRetainedUntilMs(signed)).toBe(BigInt(signed + 2 * SERVICE_REQUEST_FRESHNESS_MS))
    // It saturates rather than wrapping at the end of the counter's range.
    expect(nonceRetainedUntilMs((1n << 64n) - 1n)).toBe((1n << 64n) - 1n)
  })

  it('refuses a payload the host would refuse', () => {
    const installation = findCase(services.cases, 'installation_request')
      .json as ServiceRequestSignature

    // A method outside the Services group is not something a service credential may name.
    expect(() =>
      serviceRequestSigningInput(
        { ...installation.payload, method: 'session.read' as never },
        'installation'
      )
    ).toThrow(ServiceSchemaError)

    // A field nobody agreed on is refused rather than dropped before signing.
    expect(() =>
      serviceRequestSigningInput(
        { ...installation.payload, extra: 1 } as never,
        'installation'
      )
    ).toThrow(ServiceSchemaError)

    // An origin with a path is a second spelling of one address.
    expect(() =>
      serviceRequestSigningInput(
        { ...installation.payload, gateway_origin: 'https://reach.kala.to/' },
        'installation'
      )
    ).toThrow(ServiceSchemaError)

    // A counter that arrived as a number rather than as a decimal string.
    expect(() =>
      serviceRequestSigningInput(
        { ...installation.payload, signed_at_ms: 1_767_225_600_000 as never },
        'installation'
      )
    ).toThrow(ServiceSchemaError)
  })

  /** KR-REQ-16.05: one origin, spelled one way, in both languages. */
  it('agrees with the host about which origins are origins', () => {
    const installation = findCase(services.cases, 'installation_request')
      .json as ServiceRequestSignature

    for (const origin of services.origins.accepted) {
      expect(
        () => serviceRequestSigningInput({ ...installation.payload, gateway_origin: origin }, 'installation'),
        `a published accepted origin is refused: ${origin}`
      ).not.toThrow()
    }
    for (const origin of services.origins.refused) {
      expect(
        () => serviceRequestSigningInput({ ...installation.payload, gateway_origin: origin }, 'installation'),
        `a published refused origin is accepted: ${origin}`
      ).toThrow(ServiceSchemaError)
    }
  })

  it('names every managed-service method and no other', () => {
    expect([...SERVICE_METHODS].sort()).toEqual(
      [
        'authority.sync',
        'backup.manifest',
        'mailbox.read',
        'push.installation.register',
        'push.sender.issue',
        'push.sender.renew',
        'push.sender.revoke',
        'sync.compare_exchange'
      ].sort()
    )
  })
})

describe('push registration', () => {
  /** KR-REQ-16.06: the answer is bound to token hash, registration, origin and expiry. */
  it('signs the bytes the Rust vectors publish', () => {
    const answer = findCase(push.cases, 'registration_answer').json as PushRegistrationAnswer
    const entry = assertVector(
      push.cases,
      'registration_answer',
      registrationAnswerSigningInput(answer.payload)
    )
    expect(entry.domain).toBe(PUSH_REGISTRATION_ANSWER_DOMAIN)
  })

  /** KR-REQ-16.07: a token is one destination, recorded by a digest and never in the clear. */
  it('digests a token and nothing about the caller', async () => {
    const digest = await tokenDigest(push.token.registration_token)
    expect(bytesToHex(digest)).toBe(bytesToHex(base64UrlToBytes(push.token.token_digest)))

    // The label beside a token changes nothing, so one device cannot hold two rate histories by
    // registering once as Android and once as iOS.
    expect(bytesToHex(await tokenDigest(push.token.registration_token))).toBe(bytesToHex(digest))
    expect(bytesToHex(await tokenDigest(`${push.token.registration_token}x`))).not.toBe(
      bytesToHex(digest)
    )
  })

  it('refuses an answer that changes what the challenge asked', () => {
    const answer = findCase(push.cases, 'registration_answer').json as PushRegistrationAnswer
    const moved = {
      ...answer.payload,
      gateway_origin: 'https://someone-else.invalid'
    }
    expect(bytesToHex(registrationAnswerSigningInput(moved))).not.toBe(
      findCase(push.cases, 'registration_answer').cbor_hex
    )
    expect(() =>
      registrationAnswerSigningInput({ ...answer.payload, platform: 'web' as never })
    ).toThrow(PushSchemaError)
  })
})

describe('sender authorisation', () => {
  /** KR-REQ-16.08: what an authorisation fixes is one digest. */
  it('digests what a renewal may not change', async () => {
    const binding = findCase(push.cases, 'sender_binding').json as PushSenderBinding
    const entry = assertVector(
      push.cases,
      'sender_binding',
      senderBindingSigningInput(binding)
    )
    expect(entry.domain).toBe(PUSH_SENDER_BINDING_DOMAIN)
    expect(bytesToHex(await senderBindingDigest(binding))).toBe(entry.sha256)

    for (const changed of [
      { ...binding, host_signing_key: binding.host_endpoint_key },
      { ...binding, rate_policy: { ...binding.rate_policy, burst: '200' } },
      { ...binding, installation_id: '00000000-0000-0000-0000-000000000000' }
    ]) {
      expect(bytesToHex(await senderBindingDigest(changed)), 'a renewal preserves the binding')
        .not.toBe(entry.sha256)
    }
  })

  /** KR-REQ-16.09: a renewal answers a nonce the gateway issued. */
  it('signs a renewal over the gateway nonce and the record', () => {
    const renewal = findCase(push.cases, 'sender_renewal').json as PushSenderRenewal
    const entry = assertVector(
      push.cases,
      'sender_renewal',
      senderRenewalSigningInput(renewal.payload)
    )
    expect(entry.domain).toBe(PUSH_SENDER_RENEWAL_DOMAIN)

    const record = push.records.sender_record
    const expires = BigInt(record.credential_expires_at_ms)
    expect(renewalOpensAtMs(expires)).toBe(expires - BigInt(SENDER_RENEWAL_WINDOW_MS))
    expect(BigInt(renewal.payload.requested_at_ms)).toBe(renewalOpensAtMs(expires))
    // An expiry inside the window opens renewal now rather than at a negative instant.
    expect(renewalOpensAtMs(1_000)).toBe(0n)
  })

  /** KR-REQ-16.10: a revocation names why, and a revoked record never renews. */
  it('signs a revocation over its reason', () => {
    const revocation = findCase(push.cases, 'sender_revocation').json as PushSenderRevocation
    const entry = assertVector(
      push.cases,
      'sender_revocation',
      senderRevocationSigningInput(revocation.payload)
    )
    expect(entry.domain).toBe(PUSH_SENDER_REVOCATION_DOMAIN)
    expect(() =>
      senderRevocationSigningInput({ ...revocation.payload, reason: 'because' as never })
    ).toThrow(PushSchemaError)
  })

  /** KR-REQ-16.08: the gateway stores a digest of the bearer, never the bearer. */
  it('digests a delivery credential', async () => {
    const credential = push.records.delivery_credential
    const digest = await credentialDigest(base64UrlToBytes(credential.secret))
    expect(bytesToHex(digest)).toBe(bytesToHex(base64UrlToBytes(push.records.credential_digest)))

    const lifetime = Number(credential.expires_at_ms) - Number(credential.issued_at_ms)
    expect(lifetime).toBe(DELIVERY_CREDENTIAL_LIFETIME_MS)
  })
})

describe('delivery', () => {
  /** KR-REQ-16.01, KR-REQ-16.03: one request shape for both platforms. */
  it('digests the delivery request the gateway deduplicates by', async () => {
    const request = findCase(push.cases, 'delivery_request').json as PushDeliveryRequest
    const entry = assertVector(
      push.cases,
      'delivery_request',
      deliveryRequestSigningInput(request)
    )
    expect(entry.domain).toBe(PUSH_DELIVERY_DOMAIN)
    expect(bytesToHex(await deliveryRequestDigest(request))).toBe(entry.sha256)

    const withoutPreview = findCase(push.cases, 'delivery_request_without_preview')
      .json as PushDeliveryRequest
    assertVector(
      push.cases,
      'delivery_request_without_preview',
      deliveryRequestSigningInput(withoutPreview)
    )
    expect(withoutPreview.preview).toBeNull()

    // A preview is a sealed envelope, padded to a notification bucket. The gateway can check that
    // much about a ciphertext it cannot read, and refuses anything else.
    expect(previewIsWellFormed(request)).toBe(true)
    expect(previewIsWellFormed(withoutPreview)).toBe(true)
    const preview = request.preview as NonNullable<PushDeliveryRequest['preview']>
    expect(
      previewIsWellFormed({
        ...request,
        preview: { ...preview, routing: { ...preview.routing, expires_at_ms: '99999999999' } }
      })
    ).toBe(false)
    expect(
      previewIsWellFormed({
        ...request,
        preview: { ...preview, routing: { ...preview.routing, size_bucket_bytes: '1500' } }
      })
    ).toBe(false)
  })

  /** KR-REQ-16.05, KR-REQ-16.09: one body digest, under the method its signature names. */
  it('digests each request body the way the signature covers it', async () => {
    for (const entry of push.request_methods) {
      const body = findCase(push.cases, entry.body).json as PushRequest
      const bytes = pushRequestSigningInput(body)
      assertVector(push.cases, entry.body, bytes)
      expect(pushRequestMethod(body)).toBe(entry.method)
      expect(pushRequestSigner(body)).toBe(entry.signer)

      const digest = await pushRequestDigest(body)
      expect(bytesToHex(digest)).toBe(findCase(push.cases, entry.body).sha256)
    }

    // The signature over a body carries that body's digest and names that body's method, so a body
    // built for one method cannot be presented under another.
    for (const [caseId, bodyId] of [
      ['signed_registration_propose', 'body_registration_propose'],
      ['signed_sender_renew', 'body_sender_renew']
    ] as const) {
      const signed = findCase(push.cases, caseId).json as ServiceRequestSignature
      const body = findCase(push.cases, bodyId).json as PushRequest
      assertVector(
        push.cases,
        caseId,
        serviceRequestSigningInput(signed.payload, signed.signer)
      )
      expect(bytesToHex(base64UrlToBytes(signed.payload.body_digest))).toBe(
        bytesToHex(await pushRequestDigest(body))
      )
      expect(signed.payload.method).toBe(pushRequestMethod(body))
      expect(signed.signer).toBe(pushRequestSigner(body))
    }
  })

  /** KR-REQ-16.16: nothing a sender supplies reaches a lock screen as text. */
  it('carries no field for sender-supplied text', () => {
    const request = findCase(push.cases, 'delivery_request').json as PushDeliveryRequest
    expect(Object.keys(request).sort()).toEqual([
      'collapse_id',
      'expires_at_ms',
      'hints',
      'notification_id',
      'preview',
      'sender_record_id'
    ])
    expect(() =>
      deliveryRequestSigningInput({ ...request, body: 'rm -rf /' } as never)
    ).toThrow(PushSchemaError)

    // The two identifiers are 128 opaque bits, so neither can carry a project or session name.
    expect(() =>
      deliveryRequestSigningInput({ ...request, collapse_id: 'acme-payments:deploy' } as never)
    ).toThrow(PushSchemaError)
    expect(() =>
      deliveryRequestSigningInput({ ...request, notification_id: 'rm -rf /' } as never)
    ).toThrow(PushSchemaError)

    // Every alert's text comes from the protocol, and names no session, project or command.
    expect(push.alerts.map((entry) => entry.alert)).toEqual([...PUSH_ALERTS])
    for (const entry of push.alerts) {
      expect(PUSH_ALERT_TEXT[entry.alert as keyof typeof PUSH_ALERT_TEXT]).toBe(entry.text)
      expect(entry.text).toMatch(/^[A-Z].*\.$/)
    }
    for (const urgency of PUSH_URGENCIES) {
      expect(FCM_PRIORITY[urgency]).toBeTruthy()
      expect(APNS_PRIORITY[urgency]).toBeTruthy()
    }
  })

  /** KR-REQ-16.17: the free allowance and the payload bounds are the section 16 figures. */
  it('holds the limits section 16 fixes', () => {
    expect(push.limits).toEqual({
      registration_challenge_lifetime_ms: String(REGISTRATION_CHALLENGE_LIFETIME_MS),
      delivery_credential_lifetime_ms: String(DELIVERY_CREDENTIAL_LIFETIME_MS),
      sender_renewal_window_ms: String(SENDER_RENEWAL_WINDOW_MS),
      max_preview_plaintext_bytes: String(MAX_PREVIEW_PLAINTEXT_BYTES),
      max_provider_payload_bytes: String(MAX_PROVIDER_PAYLOAD_BYTES),
      free_burst: String(FREE_PUSH_BURST),
      free_per_hour: String(FREE_PUSH_PER_HOUR),
      collapse_window_ms: String(PUSH_COLLAPSE_WINDOW_MS)
    })
    expect(push.records.sender_record.binding.rate_policy).toEqual(FREE_RATE_POLICY)
    // Section 16 says below 3,500 bytes, so 3,500 is one too many.
    expect(providerPayloadWithinPolicy(MAX_PROVIDER_PAYLOAD_BYTES - 1)).toBe(true)
    expect(providerPayloadWithinPolicy(MAX_PROVIDER_PAYLOAD_BYTES)).toBe(false)
  })
})
