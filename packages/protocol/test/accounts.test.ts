/**
 * The account vectors under `fixtures/accounts/`, recomputed in TypeScript.
 *
 * Nothing here calls the Rust implementation. The payloads come from the JSON representation the
 * managed service carries, the bytes come from this package's own codec, and the expected bytes
 * come from the fixture the Rust tests verify. Agreement is therefore real cross-language
 * agreement over the exact input a policy-signing key covers.
 */

import { createHash, createPublicKey, verify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
  ACTION_RIGHTS,
  AccountSchemaError,
  MEMBERSHIP_LEASE_DOMAIN,
  MEMBERSHIP_LEASE_MAX_LIFETIME_MS,
  MEMBERSHIP_LEASE_REFRESH_INTERVAL_MS,
  POLICY_AUTHORITY_DOMAIN,
  POLICY_AUTHORITY_HEAD_DOMAIN,
  POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS,
  ROLE_MAXIMUM_GRANTS,
  TEAM_ROLES,
  canonicalRights,
  decodeCanonical,
  encodeCanonical,
  membershipLeaseSigningInput,
  policyAuthorityHeadSigningInput,
  policyAuthorityLinkSigningInput,
  publicKeyBytes,
  signatureBytes,
  type MembershipLease,
  type MembershipLeasePayload,
  type PolicyAuthority,
  type PolicyAuthorityHead,
  type PolicyAuthorityHeadPayload,
  type PolicyAuthorityLink,
  type PolicyAuthorityLinkPayload
} from '../src/index.js'

import { bytesToHex, hexToBytes, parseValue } from './fixtures.js'

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

interface AccountCase {
  id: string
  description: string
  domain: string
  json: unknown
  value: unknown
  cbor_hex: string
  sha256: string
}

interface AccountFixture {
  name: string
  description: string
  roles: Array<{ role: string, maximum_grants: string[] }>
  lifetimes_ms: Record<string, string>
  published_authority: PolicyAuthority
  cases: AccountCase[]
}

const document = JSON.parse(
  readFileSync(join(repositoryRoot, 'fixtures', 'accounts', 'leases.json'), 'utf8')
) as AccountFixture

const schema = JSON.parse(
  readFileSync(
    join(repositoryRoot, 'packages', 'protocol', 'schema', 'kalareach-protocol.schema.json'),
    'utf8'
  )
) as { $defs: Record<string, { oneOf?: Array<{ const: string }> }> }

function findCase (id: string): AccountCase {
  const found = document.cases.find((entry) => entry.id === id)
  if (found === undefined) {
    throw new Error(`no case ${id}`)
  }
  return found
}

function sha256 (bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

/** Wraps a raw 32-byte Ed25519 public key in the SPKI encoding Node reads. */
function ed25519PublicKey (raw: Uint8Array): ReturnType<typeof createPublicKey> {
  const spki = new Uint8Array([
    // SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING { key } }
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ...raw
  ])
  return createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' })
}

interface SignedCase {
  id: string
  description: string
  domain: string
  signer: string
  json: { payload: unknown, signature: string }
  message_hex: string
  message_sha256: string
  signature_hex: string
}

interface NegativeCase {
  id: string
  description: string
  domain: string
  message_hex: string
  public_key_hex: string
  signature_hex: string
}

interface OrganisationFixture {
  signers: Record<string, { seed_hex: string, public_key_hex: string }>
  devices: Record<string, { seed_hex: string, public_key_hex: string }>
  authority: PolicyAuthority
  cases: SignedCase[]
  negative_cases: NegativeCase[]
}

const organisation = JSON.parse(
  readFileSync(join(repositoryRoot, 'fixtures', 'crypto', 'organisation.json'), 'utf8')
) as OrganisationFixture

/** The bytes this package builds for one signed object, by the domain it is signed under. */
function rebuilt (domain: string, payload: unknown): Uint8Array {
  switch (domain) {
    case MEMBERSHIP_LEASE_DOMAIN:
      return membershipLeaseSigningInput(payload as MembershipLeasePayload)
    case POLICY_AUTHORITY_DOMAIN:
      return policyAuthorityLinkSigningInput(payload as PolicyAuthorityLinkPayload)
    case POLICY_AUTHORITY_HEAD_DOMAIN:
      return policyAuthorityHeadSigningInput(payload as PolicyAuthorityHeadPayload)
    default:
      throw new Error(`no builder signs under ${domain}`)
  }
}

function verifies (message: Uint8Array, publicKeyHex: string, signature: Uint8Array): boolean {
  return verify(null, Buffer.from(message), ed25519PublicKey(hexToBytes(publicKeyHex)), Buffer.from(signature))
}

function assertVector (id: string, bytes: Uint8Array): void {
  const entry = findCase(id)
  expect(bytesToHex(bytes), `${id}: bytes`).toBe(entry.cbor_hex)
  expect(sha256(bytes), `${id}: digest`).toBe(entry.sha256)
  // The description grammar and the hex are two renderings of one value: a fixture that disagreed
  // with itself would let both languages agree on the wrong bytes.
  expect(bytesToHex(encodeCanonical(parseValue(entry.value))), `${id}: description`).toBe(entry.cbor_hex)
  expect(bytesToHex(encodeCanonical(decodeCanonical(bytes))), `${id}: round trip`).toBe(entry.cbor_hex)
}

describe('membership leases', () => {
  it('signs the bytes the Rust vectors publish', () => {
    for (const id of ['membership_lease', 'membership_lease_narrowed']) {
      const lease = findCase(id).json as MembershipLease
      assertVector(id, membershipLeaseSigningInput(lease.payload))
      expect(findCase(id).domain).toBe(MEMBERSHIP_LEASE_DOMAIN)
      expect(signatureBytes(lease.signature)).toHaveLength(64)
    }
  })

  it('refuses an identifier the host would refuse', () => {
    const lease = findCase('membership_lease').json as MembershipLease
    // `kr_protocol::ids` bounds an opaque identifier and rejects every control
    // character, in both blocks. An identifier one side admits and the other
    // refuses is an identifier the two disagree about.
    for (const account of ['', 'a\u0000b', 'a\u001fb', 'a\u007fb', 'a\u0085b', 'a\u009fb', 'a'.repeat(257)]) {
      expect(() => membershipLeaseSigningInput({ ...lease.payload, account_id: account }))
        .toThrow(AccountSchemaError)
    }

    expect(() => membershipLeaseSigningInput({ ...lease.payload, account_id: 'a'.repeat(256) }))
      .not.toThrow()
  })

  it('refuses a payload that is not the closed schema', () => {
    const lease = findCase('membership_lease').json as MembershipLease
    expect(() => membershipLeaseSigningInput({ ...lease.payload, scope: 'everything' } as never))
      .toThrow(AccountSchemaError)
    const { role, ...withoutRole } = lease.payload
    expect(role).toBe('owner')
    expect(() => membershipLeaseSigningInput(withoutRole as never)).toThrow(AccountSchemaError)
    // A lease that names no device, or a key that is not one, is not the closed schema.
    const { device_key: deviceKey, ...withoutDevice } = lease.payload
    expect(publicKeyBytes(deviceKey)).toHaveLength(32)
    expect(() => membershipLeaseSigningInput(withoutDevice as never)).toThrow(AccountSchemaError)
    expect(() => membershipLeaseSigningInput({ ...lease.payload, device_key: 'AAAA' }))
      .toThrow(AccountSchemaError)
    expect(() => membershipLeaseSigningInput({ ...lease.payload, role: 'admin' } as never))
      .toThrow(AccountSchemaError)
    expect(() => membershipLeaseSigningInput({ ...lease.payload, key_revision: '01' } as never))
      .toThrow(AccountSchemaError)
    expect(() => membershipLeaseSigningInput({ ...lease.payload, organisation_id: 'org-1' } as never))
      .toThrow(AccountSchemaError)
    expect(() => membershipLeaseSigningInput({ ...lease.payload, maximum_grants: ['everything'] } as never))
      .toThrow(AccountSchemaError)
  })

  it('refuses a counter that did not arrive as a decimal string', () => {
    const lease = findCase('membership_lease').json as MembershipLease
    // `2`, `2.0` and `2e0` are one JavaScript value and three documents. The host refuses all
    // three, so accepting any of them here would let two producers sign identical bytes from
    // documents a strict reader treats as different.
    for (const revision of [2, 2.0, 2e0, -0, '2.0', '02', ' 2']) {
      expect(() => membershipLeaseSigningInput({ ...lease.payload, key_revision: revision } as never))
        .toThrow(AccountSchemaError)
    }
  })

  it('refuses a ceiling that arrived out of order rather than sorting it', () => {
    const lease = findCase('membership_lease').json as MembershipLease
    const reversed = [...lease.payload.maximum_grants].reverse()
    expect(() => membershipLeaseSigningInput({ ...lease.payload, maximum_grants: reversed }))
      .toThrow(AccountSchemaError)
    expect(() => membershipLeaseSigningInput({
      ...lease.payload,
      maximum_grants: ['session.view', 'session.view']
    })).toThrow(AccountSchemaError)
    expect(canonicalRights(reversed)).toEqual(lease.payload.maximum_grants)
  })

  it('publishes the same role ceilings as the host', () => {
    expect(document.roles.map((entry) => entry.role)).toEqual([...TEAM_ROLES])
    for (const entry of document.roles) {
      expect(ROLE_MAXIMUM_GRANTS[entry.role as (typeof TEAM_ROLES)[number]]).toEqual(entry.maximum_grants)
    }
    expect(document.lifetimes_ms.membership_lease_maximum).toBe(String(MEMBERSHIP_LEASE_MAX_LIFETIME_MS))
    expect(document.lifetimes_ms.membership_lease_refresh).toBe(String(MEMBERSHIP_LEASE_REFRESH_INTERVAL_MS))
    expect(document.lifetimes_ms.policy_authority_head_maximum)
      .toBe(String(POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS))
  })

  it('names every right the generated vocabulary names', () => {
    expect(ACTION_RIGHTS).toEqual(schema.$defs.ActionRight?.oneOf?.map((entry) => entry.const))
  })
})

describe('the policy-signing authority', () => {
  it('signs each link over the bytes the Rust vectors publish', () => {
    for (const id of ['policy_authority_first_revision', 'policy_authority_rotation']) {
      const link = findCase(id).json as PolicyAuthorityLink
      assertVector(id, policyAuthorityLinkSigningInput(link.payload))
      expect(findCase(id).domain).toBe(POLICY_AUTHORITY_DOMAIN)
      expect(publicKeyBytes(link.payload.public_key)).toHaveLength(32)
    }
  })

  it('signs the head over the bytes the Rust vectors publish', () => {
    const head = findCase('policy_authority_head').json as PolicyAuthorityHead
    assertVector('policy_authority_head', policyAuthorityHeadSigningInput(head.payload))
    expect(findCase('policy_authority_head').domain).toBe(POLICY_AUTHORITY_HEAD_DOMAIN)
  })

  it('carries the first revision without a predecessor and the next one with it', () => {
    const [first, rotation] = document.published_authority.chain
    expect(first?.payload.previous_key_revision).toBeNull()
    expect(rotation?.payload.previous_key_revision).toBe(first?.payload.key_revision)
    expect(document.published_authority.head.payload.key_revision)
      .toBe(rotation?.payload.key_revision)
  })

  it('separates a head from a lease by its domain', () => {
    const lease = findCase('membership_lease').json as MembershipLease
    const head = findCase('policy_authority_head').json as PolicyAuthorityHead
    expect(bytesToHex(membershipLeaseSigningInput(lease.payload)))
      .not.toBe(bytesToHex(policyAuthorityHeadSigningInput(head.payload)))
  })

  it('refuses a link that is not the closed schema', () => {
    const link = findCase('policy_authority_rotation').json as PolicyAuthorityLink
    expect(() => policyAuthorityLinkSigningInput({ ...link.payload, retired: true } as never))
      .toThrow(AccountSchemaError)
    expect(() => policyAuthorityLinkSigningInput({ ...link.payload, public_key: 'AAAA' }))
      .toThrow(AccountSchemaError)
    const head = findCase('policy_authority_head').json as PolicyAuthorityHead
    expect(() => policyAuthorityHeadSigningInput({ ...head.payload, expires_at_ms: -1 } as never))
      .toThrow(AccountSchemaError)
  })
})

// The organisation vectors under `fixtures/crypto/organisation.json`: a chain of three revisions, a
// head, and leases signed by the second and third revisions for one device. Each signing input is
// rebuilt here by this package's own builders and each signature verified by the Node runtime.
describe('the organisation signature vectors', () => {
  it('verifies every signed object over the bytes this package builds', () => {
    expect(organisation.cases.length).toBeGreaterThan(0)
    for (const entry of organisation.cases) {
      const message = rebuilt(entry.domain, entry.json.payload)
      expect(bytesToHex(message), `${entry.id}: bytes`).toBe(entry.message_hex)
      expect(sha256(message), `${entry.id}: digest`).toBe(entry.message_sha256)
      const signature = signatureBytes(entry.json.signature)
      expect(bytesToHex(signature), `${entry.id}: signature`).toBe(entry.signature_hex)
      const signer = organisation.signers[entry.signer]
      expect(signer, `${entry.id}: signer`).toBeDefined()
      expect(verifies(message, signer?.public_key_hex ?? '', signature), entry.id).toBe(true)
    }
  })

  it('fails every signed object whose payload has one field changed', () => {
    for (const entry of organisation.cases) {
      const changed = {
        ...(entry.json.payload as Record<string, unknown>),
        organisation_id: '00000000-0000-4000-8000-000000000000'
      }
      const message = rebuilt(entry.domain, changed)
      expect(bytesToHex(message), `${entry.id}: bytes`).not.toBe(entry.message_hex)
      const signer = organisation.signers[entry.signer]
      expect(verifies(message, signer?.public_key_hex ?? '', signatureBytes(entry.json.signature)), entry.id)
        .toBe(false)
    }
  })

  it('rejects every negative case', () => {
    expect(organisation.negative_cases.length).toBeGreaterThan(0)
    for (const entry of organisation.negative_cases) {
      expect(verifies(hexToBytes(entry.message_hex), entry.public_key_hex, hexToBytes(entry.signature_hex)), entry.id)
        .toBe(false)
    }
  })

  it('binds both leases to the member device and the chain they belong to', () => {
    const member = organisation.devices.member?.public_key_hex
    const leases = organisation.cases.filter((entry) => entry.domain === MEMBERSHIP_LEASE_DOMAIN)
    expect(leases).toHaveLength(2)
    for (const entry of leases) {
      const payload = entry.json.payload as MembershipLeasePayload
      expect(bytesToHex(publicKeyBytes(payload.device_key)), entry.id).toBe(member)
    }
    const links = organisation.cases.filter((entry) => entry.domain === POLICY_AUTHORITY_DOMAIN)
    expect(organisation.authority.chain.map((link) => link.payload)).toEqual(links.map((entry) => entry.json.payload))
    const head = organisation.cases.find((entry) => entry.domain === POLICY_AUTHORITY_HEAD_DOMAIN)
    expect(organisation.authority.head.payload).toEqual(head?.json.payload)
  })
})
