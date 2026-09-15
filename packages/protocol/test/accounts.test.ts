/**
 * The account vectors under `fixtures/accounts/`, recomputed in TypeScript.
 *
 * Nothing here calls the Rust implementation. The payloads come from the JSON representation the
 * managed service carries, the bytes come from this package's own codec, and the expected bytes
 * come from the fixture the Rust tests verify. Agreement is therefore real cross-language
 * agreement over the exact input a policy-signing key covers.
 */

import { createHash } from 'node:crypto'
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
  type PolicyAuthority,
  type PolicyAuthorityHead,
  type PolicyAuthorityLink
} from '../src/index.js'

import { bytesToHex, parseValue } from './fixtures.js'

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

  it('refuses a payload that is not the closed schema', () => {
    const lease = findCase('membership_lease').json as MembershipLease
    expect(() => membershipLeaseSigningInput({ ...lease.payload, scope: 'everything' } as never))
      .toThrow(AccountSchemaError)
    const { role, ...withoutRole } = lease.payload
    expect(role).toBe('owner')
    expect(() => membershipLeaseSigningInput(withoutRole as never)).toThrow(AccountSchemaError)
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
