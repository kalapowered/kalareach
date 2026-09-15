/**
 * The relay vectors under `fixtures/relay/`, recomputed in TypeScript.
 *
 * Nothing here calls the Rust implementation. The canonical encodings come from this package's own
 * codec and SHA-256 comes from the Node runtime, so agreement with the Rust vectors is real
 * cross-language agreement: the managed service verifies a relay's receipts against the same bytes
 * the relay signed, and issues leases the relay will accept.
 */

import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import {
  base64UrlToBytes,
  decodeCanonical,
  encodeCanonical,
  krArray,
  krText,
  relayConsumptionReceiptSigningInput,
  relayInstanceRegistrationSigningInput,
  relayLeaseRevocationSigningInput,
  relayLeaseSigningInput,
  RELAY_INSTANCE_DOMAIN,
  RELAY_LEASE_DOMAIN,
  RELAY_RECEIPT_DOMAIN,
  RELAY_REVOKE_DOMAIN,
  type CanonicalValue,
  type RelayConsumptionReceipt,
  type RelayInstanceRegistration,
  type RelayLease,
  type RelayLeaseRevocation
} from '../src/index.js'

import {
  bytesToHex,
  findCase,
  hexToBytes,
  loadFixture,
  parseValue,
  type FixtureCase
} from './fixtures.js'

const leases = loadFixture('relay', 'leases.json')
const receipts = loadFixture('relay', 'receipts.json')
const instances = loadFixture('relay', 'instances.json')

/** Builds the signing input the way `kr-cbor` does: `CBOR([domain, object])`. */
function signingInput (domain: string, object: CanonicalValue): Uint8Array {
  return encodeCanonical(krArray([krText(domain), object]))
}

function sha256 (bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

/** Every case of every relay document, so no vector can be added without being checked. */
function allCases (): Array<[string, FixtureCase]> {
  return [leases, receipts, instances].flatMap((document) =>
    (document.cases ?? []).map((entry) => [document.name, entry] as [string, FixtureCase])
  )
}

describe('relay vectors', () => {
  it.each(allCases())('%s/%s encodes to the bytes the vector states', (_document, entry) => {
    const value = parseValue(entry['value'])
    expect(bytesToHex(encodeCanonical(value))).toBe(entry.cbor_hex)
  })

  it.each(allCases())('%s/%s decodes back to the same value', (_document, entry) => {
    const decoded = decodeCanonical(hexToBytes(entry.cbor_hex as string))
    expect(decoded).toEqual(parseValue(entry['value']))
    // Re-encoding a decoded object reproduces it byte for byte, so a receiver that stores the
    // decoded form can still verify the signature it arrived with.
    expect(bytesToHex(encodeCanonical(decoded))).toBe(entry.cbor_hex)
  })

  it.each(allCases())('%s/%s signs under its own domain', (_document, entry) => {
    const input = signingInput(entry.domain as string, parseValue(entry['value']))
    expect(bytesToHex(input)).toBe(entry['signing_input_hex'])
    expect(sha256(input)).toBe(entry.sha256)
  })

  it('separates the four domains', () => {
    const domains = new Set(allCases().map(([, entry]) => entry.domain as string))
    expect([...domains].sort()).toEqual([
      RELAY_INSTANCE_DOMAIN,
      RELAY_LEASE_DOMAIN,
      RELAY_RECEIPT_DOMAIN,
      RELAY_REVOKE_DOMAIN
    ].sort())
  })

  it.each(allCases())(
    '%s/%s signs the same bytes when rebuilt from the managed representation',
    (_document, entry) => {
      // This is the path the managed service actually takes: a receipt arrives as JSON over
      // HTTPS and has to become the canonical object its signature covers before anything can
      // be verified. Nothing here reads `value` or `cbor_hex`; it converts every field of
      // `json` through the package's own adapters.
      const rebuilt = signingInputFromJson(entry.domain as string, entry['json'])
      expect(bytesToHex(rebuilt)).toBe(entry['signing_input_hex'])
      expect(sha256(rebuilt)).toBe(entry.sha256)
    }
  )

  it('refuses a representation whose key is the wrong width', () => {
    const lease = structuredClone(
      findCase(leases, 'lease_bidirectional')['json']
    ) as RelayLease
    const truncated: RelayLease = { ...lease, issuer_key: lease.issuer_key.slice(0, 10) }

    expect(() => relayLeaseSigningInput(truncated)).toThrow()
  })

  it('refuses a counter that is not a decimal string', () => {
    const receipt = structuredClone(
      findCase(receipts, 'receipt_first')['json']
    ) as RelayConsumptionReceipt
    const wrong: RelayConsumptionReceipt = { ...receipt, bytes_consumed: '0x400' }

    expect(() => relayConsumptionReceiptSigningInput(wrong)).toThrow()
  })

  it('carries a counter above the exact range of a JSON number', () => {
    const receipt = structuredClone(
      findCase(receipts, 'receipt_first')['json']
    ) as RelayConsumptionReceipt
    const huge: RelayConsumptionReceipt = {
      ...receipt,
      bytes_consumed: '18446744073709551615'
    }

    // 2^64 - 1 survives the conversion, which a JSON number could not have carried.
    const encoded = bytesToHex(relayConsumptionReceiptSigningInput(huge))
    expect(encoded).toContain('ffffffffffffffff')
    expect(() =>
      relayConsumptionReceiptSigningInput({ ...receipt, bytes_consumed: '18446744073709551616' })
    ).toThrow()
  })

  it('signs the same object differently under two domains', () => {
    const value = parseValue((leases.cases ?? [])[0]['value'])
    expect(bytesToHex(signingInput('kr-relay/lease/1', value))).not.toBe(
      bytesToHex(signingInput('kr-relay/revoke/1', value))
    )
  })
})

describe('the managed representation', () => {
  function jsonOf<T> (document: typeof leases, id: string): T {
    const entry = (document.cases ?? []).find((candidate) => candidate.id === id)
    if (entry === undefined) throw new Error(`no case ${id}`)
    return entry['json'] as T
  }

  it('writes byte counts and timestamps as decimal strings', () => {
    const lease = jsonOf<RelayLease>(leases, 'lease_bidirectional')

    expect(lease.byte_ceiling).toBe('4194304')
    expect(lease.expires_at_ms).toBe('1800000060000')
    expect(lease.revision).toBe('1')
  })

  it('writes keys and identifiers in the form each type declares', () => {
    const lease = jsonOf<RelayLease>(leases, 'lease_bidirectional')

    // Endpoint keys are opaque bytes, so base64url; identifiers are UUIDs, so hyphenated text.
    expect(base64UrlToBytes(lease.source_endpoint_key)).toHaveLength(32)
    expect(lease.lease_id).toMatch(/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/)
    expect(lease.issuer_key).not.toContain('=')
  })

  it('names the payer and the authority that made them the payer', () => {
    const paid = jsonOf<RelayLease>(leases, 'lease_bidirectional')
    const sponsored = jsonOf<RelayLease>(leases, 'lease_in_grace')

    expect(paid.payer).toEqual({ account: { account_id: 'acct_2f8c1d' } })
    expect(paid.payer_authorisation).toBe('host_selected')
    expect(sponsored.payer_authorisation).toEqual({
      sponsored: { authorisation_id: 'payauth_9b3e' }
    })
  })

  it('bounds the grace it reports at fifteen minutes and 100 MiB above the reservation', () => {
    const lease = jsonOf<RelayLease>(leases, 'lease_in_grace')
    const grace = lease.grace
    if (grace === null) throw new Error('the grace vector carries a grace')

    expect(Number(grace.ends_at_ms) - Number(grace.started_at_ms)).toBe(15 * 60 * 1000)
    // The grace raises the reservation's cumulative ceiling; it does not open a second one.
    expect(Number(grace.byte_ceiling) - Number(lease.byte_ceiling)).toBe(100 * 1024 * 1024)
    expect(lease.direction).toBe('source_to_destination')
  })

  it('names the two positions of the route the lease is valid at', () => {
    const twoRelay = jsonOf<RelayLease>(leases, 'lease_bidirectional')
    const oneRelay = jsonOf<RelayLease>(leases, 'lease_in_grace')

    expect(twoRelay.relay_scope.ingress_relay_instance_id).not.toBe(
      twoRelay.relay_scope.egress_relay_instance_id
    )
    expect(twoRelay.metering_relay_instance_id).toBe(
      twoRelay.relay_scope.ingress_relay_instance_id
    )
    expect(oneRelay.relay_scope.ingress_relay_instance_id).toBe(
      oneRelay.relay_scope.egress_relay_instance_id
    )
  })

  it('counts consumption cumulatively, so a lost receipt loses no bytes', () => {
    const first = jsonOf<RelayConsumptionReceipt>(receipts, 'receipt_first')
    const second = jsonOf<RelayConsumptionReceipt>(receipts, 'receipt_second')

    expect(Number(first.sequence)).toBe(1)
    expect(Number(second.sequence)).toBe(2)
    expect(Number(second.bytes_consumed)).toBeGreaterThan(Number(first.bytes_consumed))
    expect(second.reservation_id).toBe(first.reservation_id)
    expect(second.relay_instance_id).toBe(first.relay_instance_id)
  })

  it('revokes at a revision above the one it fences', () => {
    const lease = jsonOf<RelayLease>(leases, 'lease_bidirectional')
    const revocation = jsonOf<RelayLeaseRevocation>(leases, 'lease_revocation')

    expect(revocation.lease_id).toBe(lease.lease_id)
    expect(Number(revocation.revision)).toBeGreaterThan(Number(lease.revision))
  })

  it('announces a rotation as an overlap window inside the registration', () => {
    const registration = jsonOf<RelayInstanceRegistration>(instances, 'instance_registration')
    const rotation = jsonOf<RelayInstanceRegistration>(instances, 'instance_rotation')
    const successor = rotation.successor
    if (successor === null) throw new Error('the rotation vector carries a successor')

    expect(registration.successor).toBeNull()
    expect(successor.instance_key).not.toBe(rotation.instance_key)
    expect(Number(successor.overlap_from_ms)).toBeLessThan(
      Number(successor.predecessor_retires_at_ms)
    )
    expect(Number(successor.predecessor_retires_at_ms)).toBeLessThanOrEqual(
      Number(rotation.valid_until_ms)
    )
  })
})

/** Rebuilds a signing input from the managed representation of whichever object the domain names. */
function signingInputFromJson (domain: string, json: unknown): Uint8Array {
  switch (domain) {
    case RELAY_LEASE_DOMAIN:
      return relayLeaseSigningInput(json as RelayLease)
    case RELAY_REVOKE_DOMAIN:
      return relayLeaseRevocationSigningInput(json as RelayLeaseRevocation)
    case RELAY_RECEIPT_DOMAIN:
      return relayConsumptionReceiptSigningInput(json as RelayConsumptionReceipt)
    case RELAY_INSTANCE_DOMAIN:
      return relayInstanceRegistrationSigningInput(json as RelayInstanceRegistration)
    default:
      throw new Error(`no relay object signs under ${domain}`)
  }
}

describe('the envelopes that carry them', () => {
  const envelopes = loadFixture('relay', 'envelopes.json')

  it.each((envelopes.cases ?? []).map((entry) => [entry.id, entry] as const))(
    '%s encodes to the bytes the vector states and decodes back',
    (_id, entry) => {
      const value = parseValue(entry['value'])
      expect(bytesToHex(encodeCanonical(value))).toBe(entry.cbor_hex)

      const decoded = decodeCanonical(hexToBytes(entry.cbor_hex as string))
      expect(decoded).toEqual(value)
      expect(bytesToHex(encodeCanonical(decoded))).toBe(entry.cbor_hex)
    }
  )

  it('adds nothing to what the signatures inside it cover', () => {
    const install = findCase(envelopes, 'lease_install')['json'] as {
      install: { lease: { lease: RelayLease; signature: string } }
    }
    const lease = findCase(leases, 'lease_bidirectional')

    // The lease inside the envelope signs exactly what the lease vector says, so a relay handed an
    // envelope verifies the same bytes as one handed the lease on its own.
    expect(bytesToHex(relayLeaseSigningInput(install.install.lease.lease))).toBe(
      lease['signing_input_hex']
    )
  })

  it('carries the receipts of one reservation in order', () => {
    const report = findCase(envelopes, 'consumption_report')['json'] as {
      reservation_id: string
      receipts: Array<{ receipt: RelayConsumptionReceipt; signature: string }>
    }

    expect(report.receipts).toHaveLength(2)
    for (const [position, signed] of report.receipts.entries()) {
      expect(signed.receipt.reservation_id).toBe(report.reservation_id)
      expect(Number(signed.receipt.sequence)).toBe(position + 1)
      expect(bytesToHex(relayConsumptionReceiptSigningInput(signed.receipt))).toBe(
        findCase(receipts, position === 0 ? 'receipt_first' : 'receipt_second')[
          'signing_input_hex'
        ]
      )
    }
  })
})
