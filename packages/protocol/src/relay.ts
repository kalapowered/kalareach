/**
 * What a relay lease, a revocation, a consumption receipt and an instance registration sign.
 *
 * The managed service meets these objects as JSON: a relay posts receipts over HTTPS, an operator
 * submits a registration, a client asks for a lease. JSON is never what a signature covers, so
 * before the service can verify any of them it has to rebuild the canonical KR-CBOR-1 object the
 * signer actually signed. That rebuilding is what this module does, and it is the TypeScript half
 * of `signing_input` in the Rust crate: the same four domains, the same field names, the same
 * canonical encoding, checked against the vectors under `fixtures/relay/`.
 *
 * Every field is converted through the adapters in `./json.js` rather than copied. A counter
 * arrives as a decimal string and becomes an integer; an identifier arrives as hyphenated text and
 * becomes its sixteen bytes; a key arrives as unpadded base64url and becomes its thirty-two. A
 * field that is not in the representation, or is in it twice, or carries the wrong width, is an
 * error here rather than a signature that silently fails to verify later.
 */

import {
  krArray,
  krBytes,
  krInt,
  krMap,
  krNull,
  krText,
  type CanonicalValue
} from './cbor/value.js'
import { encodeCanonical } from './cbor/encode.js'
import { base64UrlToBytes, jsonToU64, jsonToUuid } from './json.js'
import type {
  RelayConsumptionReceipt,
  RelayGrace,
  RelayInstanceRegistration,
  RelayKeySuccession,
  RelayLease,
  RelayLeaseRevocation,
  RelayScope
} from './generated/protocol.js'

/** The domain a relay lease signature covers. */
export const RELAY_LEASE_DOMAIN = 'kr-relay/lease/1'

/** The domain a relay lease revocation signature covers. */
export const RELAY_REVOKE_DOMAIN = 'kr-relay/revoke/1'

/** The domain a relay consumption receipt signature covers. */
export const RELAY_RECEIPT_DOMAIN = 'kr-relay/receipt/1'

/** The domain a relay instance registration signature covers. */
export const RELAY_INSTANCE_DOMAIN = 'kr-relay/instance/1'

/** Bytes in an Ed25519 public key. */
const KEY_BYTES = 32

/** Reads an identifier in its hyphenated text form. */
function uuid (value: string): CanonicalValue {
  return krBytes(jsonToUuid(value))
}

/** Reads an unsigned 64-bit counter in its decimal-string form. */
function counter (value: string): CanonicalValue {
  return krInt(jsonToU64(value))
}

/** Reads a 32-byte public key in its unpadded base64url form. */
function key (value: string): CanonicalValue {
  const bytes = base64UrlToBytes(value)
  if (bytes.length !== KEY_BYTES) {
    throw new Error(`a key is ${String(KEY_BYTES)} bytes, not ${String(bytes.length)}`)
  }
  return krBytes(bytes)
}

/** Builds the canonical value of a relay scope. */
function scopeValue (scope: RelayScope): CanonicalValue {
  return krMap([
    ['ingress_relay_instance_id', uuid(scope.ingress_relay_instance_id)],
    ['egress_relay_instance_id', uuid(scope.egress_relay_instance_id)]
  ])
}

/** Builds the canonical value of a grace remainder. */
function graceValue (grace: RelayGrace | null): CanonicalValue {
  if (grace === null) {
    return krNull()
  }
  return krMap([
    ['started_at_ms', counter(grace.started_at_ms)],
    ['ends_at_ms', counter(grace.ends_at_ms)],
    ['byte_ceiling', counter(grace.byte_ceiling)]
  ])
}

/** Builds the canonical value of a payer principal. */
function payerValue (payer: RelayLease['payer']): CanonicalValue {
  if ('account' in payer) {
    return krMap([['account', krMap([['account_id', krText(payer.account.account_id)]])]])
  }
  return krMap([
    [
      'installation',
      krMap([['installation_id', uuid(payer.installation.installation_id)]])
    ]
  ])
}

/** Builds the canonical value of a payer authorisation. */
function authorisationValue (
  authorisation: RelayLease['payer_authorisation']
): CanonicalValue {
  if (authorisation === 'host_selected') {
    return krText(authorisation)
  }
  return krMap([
    [
      'sponsored',
      krMap([['authorisation_id', krText(authorisation.sponsored.authorisation_id)]])
    ]
  ])
}

/** Builds the canonical value of an announced key rotation. */
function successorValue (successor: RelayKeySuccession | null): CanonicalValue {
  if (successor === null) {
    return krNull()
  }
  return krMap([
    ['instance_key', key(successor.instance_key)],
    ['overlap_from_ms', counter(successor.overlap_from_ms)],
    ['predecessor_retires_at_ms', counter(successor.predecessor_retires_at_ms)]
  ])
}

/** Builds the canonical value of a lease. */
export function relayLeaseValue (lease: RelayLease): CanonicalValue {
  return krMap([
    ['lease_id', uuid(lease.lease_id)],
    ['revision', counter(lease.revision)],
    ['reservation_id', uuid(lease.reservation_id)],
    ['source_endpoint_key', key(lease.source_endpoint_key)],
    ['destination_endpoint_key', key(lease.destination_endpoint_key)],
    ['direction', krText(lease.direction)],
    ['payer', payerValue(lease.payer)],
    ['payer_authorisation', authorisationValue(lease.payer_authorisation)],
    ['byte_ceiling', counter(lease.byte_ceiling)],
    ['expires_at_ms', counter(lease.expires_at_ms)],
    ['relay_scope', scopeValue(lease.relay_scope)],
    ['metering_relay_instance_id', uuid(lease.metering_relay_instance_id)],
    ['metering_role', krText(lease.metering_role)],
    ['grace', graceValue(lease.grace)],
    ['issuer_key', key(lease.issuer_key)]
  ])
}

/** Builds the canonical value of a lease revocation. */
export function relayLeaseRevocationValue (revocation: RelayLeaseRevocation): CanonicalValue {
  return krMap([
    ['lease_id', uuid(revocation.lease_id)],
    ['revision', counter(revocation.revision)],
    ['relay_instance_id', uuid(revocation.relay_instance_id)],
    ['issued_at_ms', counter(revocation.issued_at_ms)],
    ['issuer_key', key(revocation.issuer_key)]
  ])
}

/** Builds the canonical value of a consumption receipt. */
export function relayConsumptionReceiptValue (
  receipt: RelayConsumptionReceipt
): CanonicalValue {
  return krMap([
    ['relay_instance_id', uuid(receipt.relay_instance_id)],
    ['reservation_id', uuid(receipt.reservation_id)],
    ['sequence', counter(receipt.sequence)],
    ['bytes_consumed', counter(receipt.bytes_consumed)],
    ['lease_revision', counter(receipt.lease_revision)],
    ['observed_at_ms', counter(receipt.observed_at_ms)]
  ])
}

/** Builds the canonical value of an instance registration. */
export function relayInstanceRegistrationValue (
  registration: RelayInstanceRegistration
): CanonicalValue {
  return krMap([
    ['relay_instance_id', uuid(registration.relay_instance_id)],
    ['instance_key', key(registration.instance_key)],
    ['relay_url', krText(registration.relay_url)],
    ['region', krText(registration.region)],
    ['valid_from_ms', counter(registration.valid_from_ms)],
    ['valid_until_ms', counter(registration.valid_until_ms)],
    ['successor', successorValue(registration.successor)]
  ])
}

/** Wraps a canonical object in its domain and encodes the bytes a signature covers. */
export function relaySigningInput (domain: string, object: CanonicalValue): Uint8Array {
  return encodeCanonical(krArray([krText(domain), object]))
}

/** The bytes a lease signature covers. */
export function relayLeaseSigningInput (lease: RelayLease): Uint8Array {
  return relaySigningInput(RELAY_LEASE_DOMAIN, relayLeaseValue(lease))
}

/** The bytes a lease revocation signature covers. */
export function relayLeaseRevocationSigningInput (
  revocation: RelayLeaseRevocation
): Uint8Array {
  return relaySigningInput(RELAY_REVOKE_DOMAIN, relayLeaseRevocationValue(revocation))
}

/** The bytes a consumption receipt signature covers. */
export function relayConsumptionReceiptSigningInput (
  receipt: RelayConsumptionReceipt
): Uint8Array {
  return relaySigningInput(RELAY_RECEIPT_DOMAIN, relayConsumptionReceiptValue(receipt))
}

/** The bytes an instance registration signature covers. */
export function relayInstanceRegistrationSigningInput (
  registration: RelayInstanceRegistration
): Uint8Array {
  return relaySigningInput(
    RELAY_INSTANCE_DOMAIN,
    relayInstanceRegistrationValue(registration)
  )
}
