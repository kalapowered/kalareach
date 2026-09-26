/**
 * The mailbox, authority-feed, sync, backup and policy vectors, recomputed in TypeScript.
 *
 * Nothing here calls the Rust implementation. The records come from the JSON representation the
 * managed service carries, the bytes come from this package's own codec, and the expected bytes
 * come from `fixtures/service/services.json`, which the Rust tests verify against the types. So
 * agreement here is real cross-language agreement over the exact input a remote owner's key, a
 * host's key, a backup writer's key and an organisation's policy key cover.
 */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
  AUTHORITY_REVISION_DOMAIN,
  AUTHORITY_BEARING_PAYLOAD_TYPES,
  BACKUP_PUBLICATION_DOMAIN,
  BACKUP_WRITER_DOMAIN,
  KEY_ID_DOMAIN,
  MAILBOX_CLAIM_DOMAIN,
  MAILBOX_CLAIM_LIFETIME_MS,
  MAILBOX_PAYLOAD_TYPES,
  MAX_ADAPTER_ALLOWLIST,
  MAX_MAILBOX_BYTES,
  MAX_MAILBOX_ITEMS,
  MAX_MAILBOX_ITEM_LIFETIME_MS,
  MAX_SEALED_RECOVERY_BUNDLE_BYTES,
  MAX_SYNC_CONFLICT_COPIES,
  MAX_SYNC_OBJECTS_PER_COLLECTION,
  MAX_SYNC_OBJECT_PLAINTEXT_BYTES,
  MIN_SEALED_RECOVERY_BUNDLE_BYTES,
  ORGANISATION_POLICY_DOMAIN,
  REVOCATION_DOMAIN,
  SEALED_SYNC_OBJECT_KINDS,
  SEAL_OVERHEAD_BYTES,
  SYNC_OBJECT_KINDS,
  SYNC_RECORD_BYTES,
  ServicesSchemaError,
  authorisationKeyId,
  authorityRevisionSigningInput,
  backupGenerationPublicationSigningInput,
  backupWriterRecordSigningInput,
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalBody,
  canonicalBodyDigest,
  checkArchiveDescriptor,
  checkOrganisationPolicy,
  readArchiveDescriptor,
  readBackupGenerationPublication,
  readBackupWriterRecord,
  readRevocationAcknowledgement,
  checkSealedEnvelope,
  checkSealedRecoveryBundle,
  checkSealedSyncObject,
  envelopeStoredBytes,
  granularityForBucket,
  keyId,
  mailboxClaimValue,
  mailboxSizeBucket,
  organisationPolicySigningInput,
  readSealedEnvelope,
  readSealedRecoveryBundle,
  readSealedSyncObject,
  recoveryBundleStoredBytes,
  revocationRequestSigningInput,
  routingMatchesPlaintext,
  storedEnvelopeKeyId,
  syncObjectStoredBytes,
  type AuthorityRevisionRecord,
  type BackupGenerationPublication,
  type BackupWriterRecord,
  type EnvelopePlaintext,
  type OrganisationPolicy,
  type RevocationRequest,
  type SealedEnvelope,
  type SealedRecoveryBundle,
  type SyncConflictCopy,
  type SyncObjectRecord
} from '../src/index.js'

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

interface Case {
  readonly id: string
  readonly cbor_hex: string
  readonly sha256: string
  readonly domain: string | null
  readonly json: unknown
  readonly stored_bytes?: string
}

interface Document {
  readonly cases: readonly Case[]
  readonly key_identifiers: {
    readonly domain: string
    readonly public_key: string
    readonly identifiers: ReadonlyArray<{
      readonly purpose: 'transport' | 'authorisation' | 'stored_envelope' | 'notification_preview'
      readonly key_id: string
      readonly key_id_hex: string
    }>
  }
  readonly mailbox_limits: Record<string, unknown>
  readonly sync_limits: Record<string, unknown>
  readonly canonical_bodies: {
    readonly cases: ReadonlyArray<{
      readonly id: string
      readonly json: unknown
      readonly cbor_hex: string
      readonly sha256: string
    }>
    readonly refused: readonly string[]
  }
  readonly sync_requests: {
    readonly method: string
    readonly cases: ReadonlyArray<{
      readonly id: string
      readonly json: Readonly<Record<string, Readonly<Record<string, unknown>>>>
      readonly cbor_hex: string
      readonly sha256: string
    }>
  }
  readonly mailbox_claim: {
    readonly domain: string
    readonly lifetime_ms: string
    readonly ephemeral_key: string
    readonly recipient_key: string
    readonly shared_secret: string
    readonly claim_value_hex: string
  }
}

const document = JSON.parse(
  readFileSync(join(repositoryRoot, 'fixtures', 'service', 'services.json'), 'utf8')
) as Document

function vector (id: string): Case {
  const found = document.cases.find((entry) => entry.id === id)
  if (found === undefined) {
    throw new Error(`no case ${id}`)
  }
  return found
}

function hex (bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

describe('key identifiers', () => {
  it('derives the identifier the host derives, per purpose', async () => {
    expect(document.key_identifiers.domain).toBe(KEY_ID_DOMAIN)
    const key = base64UrlToBytes(document.key_identifiers.public_key)
    for (const entry of document.key_identifiers.identifiers) {
      expect(hex(await keyId(entry.purpose, key))).toBe(entry.key_id_hex)
    }
  })

  it('names two different keys for one key declared under two purposes', async () => {
    const key = base64UrlToBytes(document.key_identifiers.public_key)
    expect(hex(await authorisationKeyId(key))).not.toBe(hex(await storedEnvelopeKeyId(key)))
  })

  it('refuses anything that is not a 32-byte key', async () => {
    await expect(authorisationKeyId(new Uint8Array(31))).rejects.toThrow(ServicesSchemaError)
  })
})

describe('the canonical body a signature covers', () => {
  it('encodes each published document to the bytes the host produces', async () => {
    for (const entry of document.canonical_bodies.cases) {
      expect(hex(canonicalBody(entry.json)), entry.id).toBe(entry.cbor_hex)
      expect(hex(await canonicalBodyDigest(entry.json)), entry.id).toBe(entry.sha256)
    }
  })

  it('digests two spellings of one document to one value', async () => {
    const one = document.canonical_bodies.cases.find((entry) => entry.id === 'mailbox_read')
    const other = document.canonical_bodies.cases.find(
      (entry) => entry.id === 'mailbox_read_reordered'
    )
    expect(one?.sha256).toBe(other?.sha256)
    expect(hex(await canonicalBodyDigest(one?.json))).toBe(
      hex(await canonicalBodyDigest(other?.json))
    )
  })

  it('refuses every document the host refuses', () => {
    for (const text of document.canonical_bodies.refused) {
      // The text is parsed the way a gateway parses a request body, and then refused for the
      // number it carries rather than for how it was written.
      const body = JSON.parse(text) as unknown
      expect(() => canonicalBody(body), text).toThrow(ServicesSchemaError)
    }
  })
})

describe('the settings-sync requests a client sends', () => {
  const requests = document.sync_requests

  it('publishes one request for each member, and the recovery bundle\'s four beside them', () => {
    expect(requests.method).toBe('sync.compare_exchange')
    expect(
      Object.fromEntries(requests.cases.map((entry) => [entry.id, Object.keys(entry.json)]))
    ).toEqual({
      exchange: ['exchange'],
      compare: ['compare'],
      resolve: ['resolve'],
      status: ['status'],
      fence: ['fence'],
      keys: ['keys'],
      rekey: ['rekey'],
      memberships: ['memberships'],
      bundle_exchange: ['exchange'],
      bundle_compare: ['compare'],
      bundle_status: ['status'],
      bundle_fence: ['fence']
    })
  })

  it('encodes each request to the bytes the host produces and digests it as its signature does', async () => {
    for (const entry of requests.cases) {
      expect(hex(canonicalBody(entry.json)), entry.id).toBe(entry.cbor_hex)
      expect(hex(await canonicalBodyDigest(entry.json)), entry.id).toBe(entry.sha256)
    }
  })

  it('carries in each write an object this package admits', () => {
    const write = (id: string): Readonly<Record<string, unknown>> => {
      const found = requests.cases.find((entry) => entry.id === id)?.json['exchange']
      if (found === undefined) {
        throw new Error(`no request ${id}`)
      }
      return found
    }
    expect(checkSealedSyncObject(readSealedSyncObject(write('exchange')['object']))).toBeNull()
    expect(
      checkSealedRecoveryBundle(readSealedRecoveryBundle(write('bundle_exchange')['object']))
    ).toBeNull()
  })
})

describe('the value that claims a mailbox', () => {
  it('derives the value the host derives', async () => {
    const claim = document.mailbox_claim
    expect(claim.domain).toBe(MAILBOX_CLAIM_DOMAIN)
    expect(claim.lifetime_ms).toBe(String(MAILBOX_CLAIM_LIFETIME_MS))
    expect(
      hex(
        await mailboxClaimValue(
          base64UrlToBytes(claim.ephemeral_key),
          base64UrlToBytes(claim.recipient_key),
          base64UrlToBytes(claim.shared_secret)
        )
      )
    ).toBe(claim.claim_value_hex)
  })

  it('answers one challenge and no other', async () => {
    const claim = document.mailbox_claim
    const ephemeral = base64UrlToBytes(claim.ephemeral_key)
    const recipient = base64UrlToBytes(claim.recipient_key)
    const secret = base64UrlToBytes(claim.shared_secret)
    const elsewhere = new Uint8Array(32).fill(9)

    expect(hex(await mailboxClaimValue(elsewhere, recipient, secret))).not.toBe(
      claim.claim_value_hex
    )
    expect(hex(await mailboxClaimValue(ephemeral, elsewhere, secret))).not.toBe(
      claim.claim_value_hex
    )
    expect(hex(await mailboxClaimValue(ephemeral, recipient, elsewhere))).not.toBe(
      claim.claim_value_hex
    )
    await expect(mailboxClaimValue(new Uint8Array(31), recipient, secret)).rejects.toThrow(
      ServicesSchemaError
    )
  })
})

describe('reading a sealed record against its closed schema', () => {
  it('returns the record it was given, in canonical spelling', () => {
    const item = vector('mailbox_item')
    const { sealed } = item.json as { sealed: SealedEnvelope }
    expect(readSealedEnvelope(sealed)).toEqual(sealed)
  })

  it('refuses a field nobody agreed on, in the envelope and in the routing record', () => {
    const item = vector('mailbox_item')
    const { sealed } = item.json as { sealed: SealedEnvelope }
    expect(() => readSealedEnvelope({ ...sealed, nickname: 'extra' })).toThrow(ServicesSchemaError)
    expect(() =>
      readSealedEnvelope({
        ...sealed,
        routing: { ...sealed.routing, nickname: 'extra' }
      })
    ).toThrow(ServicesSchemaError)
  })

  it('refuses a scalar of the wrong width or shape', () => {
    const item = vector('mailbox_item')
    const { sealed } = item.json as { sealed: SealedEnvelope }
    expect(() => readSealedEnvelope({ ...sealed, nonce: sealed.nonce.slice(0, 8) })).toThrow(
      ServicesSchemaError
    )
    expect(() =>
      readSealedEnvelope({
        ...sealed,
        routing: { ...sealed.routing, recipient_key_id: 'AAAA' }
      })
    ).toThrow(ServicesSchemaError)
    expect(() =>
      readSealedEnvelope({ ...sealed, routing: { ...sealed.routing, envelope_id: 'not-a-uuid' } })
    ).toThrow(ServicesSchemaError)
    expect(() =>
      readSealedEnvelope({ ...sealed, routing: { ...sealed.routing, expires_at_ms: 12 } })
    ).toThrow(ServicesSchemaError)
    expect(() =>
      readSealedEnvelope({ ...sealed, routing: { ...sealed.routing, payload_type: 'keystroke' } })
    ).toThrow(ServicesSchemaError)
  })

  it('reads a sealed synchronised object the same way', () => {
    const record = vector('sync_object_record').json as SyncObjectRecord
    expect(readSealedSyncObject(record.object)).toEqual(record.object)
    expect(() => readSealedSyncObject({ ...record.object, nickname: 'extra' })).toThrow(
      ServicesSchemaError
    )
  })
})

describe('the mailbox', () => {
  const item = vector('mailbox_item')
  const { plaintext, sealed } = item.json as {
    plaintext: EnvelopePlaintext
    sealed: SealedEnvelope
  }

  it('publishes the limits of section 9', () => {
    expect(document.mailbox_limits['item_lifetime_ms']).toBe(String(MAX_MAILBOX_ITEM_LIFETIME_MS))
    expect(document.mailbox_limits['items_per_device']).toBe(String(MAX_MAILBOX_ITEMS))
    expect(document.mailbox_limits['bytes_per_device']).toBe(String(MAX_MAILBOX_BYTES))
    expect(document.mailbox_limits['seal_overhead_bytes']).toBe(String(SEAL_OVERHEAD_BYTES))
    expect(document.mailbox_limits['payload_types']).toEqual(MAILBOX_PAYLOAD_TYPES)
    expect(document.mailbox_limits['coalesced_payload_types']).toEqual(
      MAILBOX_PAYLOAD_TYPES.filter(
        (kind) => !(AUTHORITY_BEARING_PAYLOAD_TYPES as readonly string[]).includes(kind)
      )
    )
  })

  it('admits the published item and measures what it stores', () => {
    const created = Number(plaintext.created_at_ms)
    expect(checkSealedEnvelope(sealed, created)).toBeNull()
    expect(String(envelopeStoredBytes(sealed))).toBe(item.stored_bytes)
    expect(routingMatchesPlaintext(sealed, plaintext)).toBe(true)
  })

  it('refuses a bucket no padding rule produces, and a ciphertext that is not its bucket sealed', () => {
    const created = Number(plaintext.created_at_ms)
    const relabelled: SealedEnvelope = {
      ...sealed,
      routing: { ...sealed.routing, size_bucket_bytes: String(18 * 1024) }
    }
    expect(checkSealedEnvelope(relabelled, created)?.reason).toBe('undeclared_bucket')

    const truncated: SealedEnvelope = {
      ...sealed,
      ciphertext: bytesToBase64Url(base64UrlToBytes(sealed.ciphertext).subarray(0, -3))
    }
    expect(checkSealedEnvelope(truncated, created)?.reason).toBe('ciphertext_length')
  })

  it('refuses an item that outlives the day section 9 gives it, or has already expired', () => {
    const created = Number(plaintext.created_at_ms)
    const expires = Number(sealed.routing.expires_at_ms)
    expect(checkSealedEnvelope(sealed, created - 1)?.reason).toBe('lifetime_too_long')
    expect(checkSealedEnvelope(sealed, expires)?.reason).toBe('already_expired')
  })

  it('refuses a payload kind that is not one of the closed set', () => {
    const created = Number(plaintext.created_at_ms)
    // There is no kind an action could arrive under: a keystroke, a command, an approval decision
    // and a closure are all refused by the same rule.
    for (const kind of ['keystroke', 'shell_command', 'approval_decision', 'session_closure']) {
      const declared: SealedEnvelope = {
        ...sealed,
        routing: { ...sealed.routing, payload_type: kind as never }
      }
      expect(checkSealedEnvelope(declared, created)?.reason).toBe('unknown_payload_type')
    }
  })

  it('refuses a payload that carries authority and asks to be coalesced', () => {
    const created = Number(plaintext.created_at_ms)
    const authority: SealedEnvelope = {
      ...sealed,
      routing: { ...sealed.routing, payload_type: 'signed_authority_object' }
    }
    expect(checkSealedEnvelope(authority, created)?.reason).toBe('authority_coalesced')
    expect(
      checkSealedEnvelope(
        { ...authority, routing: { ...authority.routing, thread_id: null } },
        created
      )
    ).toBeNull()
  })

  it('catches a service that relabelled or re-threaded an item', () => {
    expect(
      routingMatchesPlaintext(
        { ...sealed, routing: { ...sealed.routing, payload_type: 'notification_preview' } },
        plaintext
      )
    ).toBe(false)
    expect(
      routingMatchesPlaintext(
        { ...sealed, routing: { ...sealed.routing, thread_id: null } },
        plaintext
      )
    ).toBe(false)
  })

  it('rounds a plaintext up to the next bucket, and recovers the granularity from one', () => {
    expect(mailboxSizeBucket(1)).toBe(1024)
    expect(mailboxSizeBucket(16 * 1024)).toBe(17 * 1024)
    expect(mailboxSizeBucket(16 * 1024 + 1)).toBe(20 * 1024)
    expect(mailboxSizeBucket(64 * 1024)).toBe(68 * 1024)
    expect(mailboxSizeBucket(64 * 1024 + 1)).toBe(128 * 1024)
    expect(granularityForBucket(1024)).toBe(1024)
    expect(granularityForBucket(20 * 1024)).toBe(4 * 1024)
    expect(granularityForBucket(128 * 1024)).toBe(64 * 1024)
    expect(granularityForBucket(18 * 1024)).toBeNull()
    expect(granularityForBucket(0)).toBeNull()
  })
})

describe('the authority feed', () => {
  it('covers the bytes a revocation request is signed over', () => {
    const request = vector('revocation_request')
    expect(request.domain).toBe(REVOCATION_DOMAIN)
    expect(hex(revocationRequestSigningInput(request.json as RevocationRequest))).toBe(
      request.cbor_hex
    )
  })

  it('covers the bytes a host authority revision is signed over', () => {
    const revision = vector('authority_revision_record')
    expect(revision.domain).toBe(AUTHORITY_REVISION_DOMAIN)
    expect(hex(authorityRevisionSigningInput(revision.json as AuthorityRevisionRecord))).toBe(
      revision.cbor_hex
    )
  })

  it('refuses a request with a field nobody agreed on', () => {
    const request = vector('revocation_request').json as RevocationRequest
    expect(() =>
      revocationRequestSigningInput({ ...request, host_revision: '9' } as never)
    ).toThrow(ServicesSchemaError)
  })

  it('refuses a target that is neither devices nor grants', () => {
    const request = vector('revocation_request').json as RevocationRequest
    expect(() =>
      revocationRequestSigningInput({ ...request, target: { hosts: { host_ids: [] } } } as never)
    ).toThrow(ServicesSchemaError)
  })
})

describe("a host's acknowledgement, which carries no signature", () => {
  const acknowledgement = {
    request_id: '2f1c7a10-0000-4000-8000-000000000001',
    host_device_id: '2f1c7a10-0000-4000-8000-000000000002',
    authority_revision: '4',
    completion: 'complete',
    acknowledged_at_ms: '1774000000000'
  } as const

  it('reads the two completions the protocol declares and nothing else', () => {
    expect(readRevocationAcknowledgement(acknowledgement)).toEqual(acknowledgement)

    const pending = {
      ...acknowledgement,
      completion: { pending: { pending_workers: '2' } }
    }
    expect(readRevocationAcknowledgement(pending)).toEqual(pending)

    for (const completion of [
      {},
      'finished',
      { pending: {} },
      { pending: { pending_workers: 2 } },
      { pending: { pending_workers: '007' } },
      { pending: { pending_workers: '1' }, complete: null }
    ]) {
      expect(() =>
        readRevocationAcknowledgement({ ...acknowledgement, completion })
      ).toThrow(ServicesSchemaError)
    }
  })

  it('refuses a field nobody agreed on, and a counter that is not one', () => {
    // A service stores this and serves it back to the publisher, so a field nobody agreed on would
    // be stored, served back and covered by nothing at all.
    expect(() =>
      readRevocationAcknowledgement({ ...acknowledgement, prompt: 'explain this failure' })
    ).toThrow(ServicesSchemaError)
    expect(() =>
      readRevocationAcknowledgement({ ...acknowledgement, authority_revision: 'soon' })
    ).toThrow(ServicesSchemaError)
    expect(() =>
      readRevocationAcknowledgement({ ...acknowledgement, acknowledged_at_ms: '-1' })
    ).toThrow(ServicesSchemaError)
    const { request_id: _omitted, ...missing } = acknowledgement
    expect(() => readRevocationAcknowledgement(missing)).toThrow(ServicesSchemaError)
  })
})

describe('settings sync', () => {
  const record = vector('sync_object_record')
  const conflict = vector('sync_conflict_copy')

  it('reads the conflict copy the service keeps for a rejected write', () => {
    const copy = conflict.json as SyncConflictCopy
    // The rejected content is kept as it arrived, and both revisions are recorded: the one the
    // writer expected and the one the object actually held. Nothing here chooses between them.
    expect(copy.expected_revision).not.toBe(copy.current_revision)
    expect(checkSealedSyncObject(copy.object)).toBeNull()
  })

  it('publishes the closed set of kinds and the limits', () => {
    expect(document.sync_limits['object_kinds']).toEqual(SYNC_OBJECT_KINDS)
    expect(document.sync_limits['object_plaintext_bytes']).toBe(
      String(MAX_SYNC_OBJECT_PLAINTEXT_BYTES)
    )
    expect(document.sync_limits['objects_per_collection']).toBe(
      String(MAX_SYNC_OBJECTS_PER_COLLECTION)
    )
    expect(document.sync_limits['conflict_copies_per_object']).toBe(
      String(MAX_SYNC_CONFLICT_COPIES)
    )
    // Host grants and revocation state have one host authority, so no kind names them.
    expect(SYNC_OBJECT_KINDS).not.toContain('grant')
    expect(SYNC_OBJECT_KINDS).not.toContain('revocation')
    // The recovery bundle is key material, stored as a stream of its own rather than a sealed
    // object, so it is a kind and not one of the kinds a sealed object is read for.
    expect(SYNC_OBJECT_KINDS).toEqual(['settings', 'draft', 'client_selection', 'recovery_bundle'])
    expect(document.sync_limits['sealed_object_kinds']).toEqual(SEALED_SYNC_OBJECT_KINDS)
    expect(SEALED_SYNC_OBJECT_KINDS).toEqual(['settings', 'draft', 'client_selection'])
    expect(document.sync_limits['recovery_bundle_bytes']).toEqual({
      min: String(MIN_SEALED_RECOVERY_BUNDLE_BYTES),
      max: String(MAX_SEALED_RECOVERY_BUNDLE_BYTES)
    })
  })

  const bundleOf = (length: number): SealedRecoveryBundle => ({
    ciphertext: bytesToBase64Url(new Uint8Array(length).fill(0xcd))
  })

  it('reads a sealed recovery bundle as its stream and nothing beside it', () => {
    const bundle = bundleOf(64)
    expect(readSealedRecoveryBundle(bundle)).toEqual(bundle)
    // The stream carries its own header: a nonce or a bucket beside it is a member nobody agreed
    // on, and it would be stored and counted as something it is not.
    for (const extra of [{ nonce: 'AAAA' }, { size_bucket_bytes: '64' }]) {
      expect(() => readSealedRecoveryBundle({ ...bundle, ...extra })).toThrow(ServicesSchemaError)
    }
    expect(() => readSealedRecoveryBundle({})).toThrow(ServicesSchemaError)
    expect(() => readSealedRecoveryBundle({ ciphertext: 'not base64url!' })).toThrow(
      ServicesSchemaError
    )
    expect(recoveryBundleStoredBytes(bundle)).toBe(64 + SYNC_RECORD_BYTES)
  })

  it('admits a recovery bundle from an empty stream to its bound, and nothing outside it', () => {
    for (const length of [
      MIN_SEALED_RECOVERY_BUNDLE_BYTES,
      4096,
      MAX_SEALED_RECOVERY_BUNDLE_BYTES
    ]) {
      expect(checkSealedRecoveryBundle(bundleOf(length))).toBeNull()
    }
    for (const length of [MIN_SEALED_RECOVERY_BUNDLE_BYTES - 1, MAX_SEALED_RECOVERY_BUNDLE_BYTES + 1]) {
      expect(checkSealedRecoveryBundle(bundleOf(length))).toEqual({
        reason: 'bundle_length',
        length,
        min: MIN_SEALED_RECOVERY_BUNDLE_BYTES,
        max: MAX_SEALED_RECOVERY_BUNDLE_BYTES
      })
    }
  })

  it('admits the published object and measures what it stores', () => {
    const object = (record.json as SyncObjectRecord).object
    expect(checkSealedSyncObject(object)).toBeNull()
    expect(String(syncObjectStoredBytes(object))).toBe(record.stored_bytes)
  })

  it('refuses an object over the size one may be, and a ciphertext that is not its bucket sealed', () => {
    const object = (record.json as SyncObjectRecord).object
    expect(
      checkSealedSyncObject({ ...object, size_bucket_bytes: String(128 * 1024) })?.reason
    ).toBe('too_large')
    expect(
      checkSealedSyncObject({
        ...object,
        ciphertext: bytesToBase64Url(base64UrlToBytes(object.ciphertext).subarray(0, -3))
      })?.reason
    ).toBe('ciphertext_length')
  })
})

/** An identifier no vector uses, for a field that is meant to name something else. */
const OTHER_IDENTIFIER = '2f1c7a10-0000-4000-8000-000000000001'

describe('backup manifests', () => {
  it('covers the bytes a writer enrolment is signed over', () => {
    const enrolment = vector('backup_writer_record')
    expect(enrolment.domain).toBe(BACKUP_WRITER_DOMAIN)
    expect(
      hex(backupWriterRecordSigningInput((enrolment.json as BackupWriterRecord).payload))
    ).toBe(enrolment.cbor_hex)
  })

  it('covers the bytes a published generation is signed over', () => {
    const publication = vector('backup_generation_publication')
    expect(publication.domain).toBe(BACKUP_PUBLICATION_DOMAIN)
    expect(
      hex(
        backupGenerationPublicationSigningInput(
          (publication.json as BackupGenerationPublication).payload
        )
      )
    ).toBe(publication.cbor_hex)
  })

  it('admits the published descriptor and refuses every wrap that is for something else', () => {
    const publication = readBackupGenerationPublication(
      vector('backup_generation_publication').json
    )
    const descriptor = publication.payload.descriptor
    const wrap = descriptor.manifest_key_wraps[0]
    if (wrap === undefined) {
      throw new Error('the published descriptor names a recipient')
    }

    expect(checkArchiveDescriptor(descriptor)).toBeNull()

    // A signed descriptor says who signed it and nothing about what it is for. Each of these is a
    // descriptor a writer could sign and a service must not store: section 20 refuses an invalid
    // descriptor before anything is allocated for it.
    const refusals = [
      [{ ...descriptor, version: '2' }, 'unsupported_version'],
      [
        {
          ...descriptor,
          manifest_key_wraps: [{ ...wrap, context: { ...wrap.context, purpose: 'object_key' } }]
        },
        'wrap_purpose'
      ],
      [
        {
          ...descriptor,
          manifest_key_wraps: [
            { ...wrap, context: { ...wrap.context, archive_id: OTHER_IDENTIFIER } }
          ]
        },
        'wrap_archive'
      ],
      [
        {
          ...descriptor,
          manifest_key_wraps: [
            { ...wrap, context: { ...wrap.context, backup_generation: '99' } }
          ]
        },
        'wrap_archive'
      ],
      [
        {
          ...descriptor,
          manifest_key_wraps: [
            { ...wrap, context: { ...wrap.context, object_id: OTHER_IDENTIFIER } }
          ]
        },
        'wrap_object'
      ],
      [
        {
          ...descriptor,
          manifest_key_wraps: [
            {
              ...wrap,
              context: { ...wrap.context, encrypted_object_hash: bytesToBase64Url(new Uint8Array(32)) }
            }
          ]
        },
        'wrap_hash'
      ],
      [{ ...descriptor, manifest_key_wraps: [wrap, wrap] }, 'duplicate_recipient']
    ] as const

    for (const [tampered, reason] of refusals) {
      expect(checkArchiveDescriptor(tampered as never)?.reason, reason).toBe(reason)
    }
  })

  it('refuses a descriptor above the bound before it is read for anything else', () => {
    const descriptor = readBackupGenerationPublication(
      vector('backup_generation_publication').json
    ).payload.descriptor
    const wrap = descriptor.manifest_key_wraps[0]
    if (wrap === undefined) {
      throw new Error('the published descriptor names a recipient')
    }

    // One wrap per recipient, each with a recipient of its own, until the encoding passes 64 KiB.
    const wraps = Array.from({ length: 96 }, (_, index) => ({
      ...wrap,
      ciphertext: bytesToBase64Url(new Uint8Array(700).fill(index + 1)),
      context: {
        ...wrap.context,
        recipient_key_id: bytesToBase64Url(new Uint8Array(32).fill(index + 1))
      }
    }))
    const refusal = checkArchiveDescriptor({ ...descriptor, manifest_key_wraps: wraps })
    expect(refusal?.reason).toBe('too_large')
  })

  it('reads a writer enrolment and a publication against their closed schemas', () => {
    const enrolment = vector('backup_writer_record').json as BackupWriterRecord
    expect(readBackupWriterRecord(enrolment)).toEqual(enrolment)

    const publication = vector('backup_generation_publication').json as BackupGenerationPublication
    expect(readBackupGenerationPublication(publication)).toEqual(publication)
    expect(readArchiveDescriptor(publication.payload.descriptor)).toEqual(
      publication.payload.descriptor
    )

    // What a service stores is the record and nothing beside it, at every level of it.
    expect(() =>
      readBackupWriterRecord({ ...enrolment, stored_at: '1' })
    ).toThrow(ServicesSchemaError)
    expect(() =>
      readBackupWriterRecord({
        ...enrolment,
        payload: { ...enrolment.payload, writer: { ...enrolment.payload.writer, label: 'x' } }
      })
    ).toThrow(ServicesSchemaError)
    expect(() =>
      readBackupGenerationPublication({
        ...publication,
        payload: {
          ...publication.payload,
          descriptor: {
            ...publication.payload.descriptor,
            encrypted_manifest: {
              ...publication.payload.descriptor.encrypted_manifest,
              filename: 'notes.txt'
            }
          }
        }
      })
    ).toThrow(ServicesSchemaError)
  })

  it('refuses a publication carrying a descriptor field nobody agreed on', () => {
    const publication = (vector('backup_generation_publication').json as BackupGenerationPublication)
      .payload
    expect(() =>
      backupGenerationPublicationSigningInput({
        ...publication,
        descriptor: { ...publication.descriptor, owner_device_id: 'x' }
      } as never)
    ).toThrow(ServicesSchemaError)
  })
})

describe('organisation policy', () => {
  const policy = vector('organisation_policy')

  it('covers the bytes a policy is signed over', () => {
    expect(policy.domain).toBe(ORGANISATION_POLICY_DOMAIN)
    expect(hex(organisationPolicySigningInput((policy.json as OrganisationPolicy).payload))).toBe(
      policy.cbor_hex
    )
  })

  it('admits the published policy', () => {
    expect(checkOrganisationPolicy((policy.json as OrganisationPolicy).payload)).toBeNull()
  })

  it('refuses a retention, a lifetime and an allowlist outside the rules', () => {
    const payload = (policy.json as OrganisationPolicy).payload
    expect(checkOrganisationPolicy({ ...payload, audit_retention_days: '29' })?.reason).toBe(
      'audit_retention'
    )
    expect(checkOrganisationPolicy({ ...payload, audit_retention_days: '3651' })?.reason).toBe(
      'audit_retention'
    )
    expect(checkOrganisationPolicy({ ...payload, maximum_grant_lifetime_ms: '0' })?.reason).toBe(
      'grant_lifetime'
    )
    expect(checkOrganisationPolicy({ ...payload, adapter_allowlist: [] })?.reason).toBe(
      'empty_allowlist'
    )
    expect(
      checkOrganisationPolicy({
        ...payload,
        adapter_allowlist: Array.from(
          { length: MAX_ADAPTER_ALLOWLIST + 1 },
          (_, index) => `adapter-${String(index)}`
        )
      })?.reason
    ).toBe('allowlist_too_long')
  })

  it('lets an organisation require backups it cannot read', () => {
    const payload = (policy.json as OrganisationPolicy).payload
    // Section 17 keeps the two apart: requiring a backup is a rule about whether an archive
    // exists, and organisation recovery is a recipient an archive is also wrapped for.
    // Administering billing or membership gives nobody a content key, so an organisation that
    // names no recipient requires an archive it cannot decrypt, which is the ordinary case.
    expect(
      checkOrganisationPolicy({
        ...payload,
        backup: { required: true, recovery_recipient: null }
      })
    ).toBeNull()
    expect(
      checkOrganisationPolicy({
        ...payload,
        backup: { required: false, recovery_recipient: null }
      })
    ).toBeNull()
  })

  it('refuses an allowlist that is not in the order a canonical set encodes', () => {
    const payload = (policy.json as OrganisationPolicy).payload
    expect(() =>
      organisationPolicySigningInput({
        ...payload,
        adapter_allowlist: ['kalareach.codex', 'kalareach.claude-code']
      })
    ).toThrow(ServicesSchemaError)
  })

  it('refuses a client version that is not one', () => {
    const payload = (policy.json as OrganisationPolicy).payload
    expect(() =>
      organisationPolicySigningInput({ ...payload, minimum_client_version: '1.0 (beta)' })
    ).toThrow(ServicesSchemaError)
  })
})
