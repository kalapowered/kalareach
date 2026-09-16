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
  MAILBOX_PAYLOAD_TYPES,
  MAX_ADAPTER_ALLOWLIST,
  MAX_MAILBOX_BYTES,
  MAX_MAILBOX_ITEMS,
  MAX_MAILBOX_ITEM_LIFETIME_MS,
  MAX_SYNC_CONFLICT_COPIES,
  MAX_SYNC_OBJECTS_PER_COLLECTION,
  MAX_SYNC_OBJECT_PLAINTEXT_BYTES,
  ORGANISATION_POLICY_DOMAIN,
  REVOCATION_DOMAIN,
  SEAL_OVERHEAD_BYTES,
  SYNC_OBJECT_KINDS,
  ServicesSchemaError,
  authorisationKeyId,
  authorityRevisionSigningInput,
  backupGenerationPublicationSigningInput,
  backupWriterRecordSigningInput,
  base64UrlToBytes,
  bytesToBase64Url,
  checkOrganisationPolicy,
  checkSealedEnvelope,
  checkSealedSyncObject,
  envelopeStoredBytes,
  granularityForBucket,
  keyId,
  mailboxSizeBucket,
  organisationPolicySigningInput,
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

  it('refuses a required backup with no organisation recipient named', () => {
    const payload = (policy.json as OrganisationPolicy).payload
    expect(
      checkOrganisationPolicy({
        ...payload,
        backup: { required: true, recovery_recipient: null }
      })?.reason
    ).toBe('recovery_recipient_missing')
    // Administering an organisation gives nobody a content key: with no recipient named, the
    // organisation simply requires nothing it cannot read.
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
