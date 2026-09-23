/**
 * The pairing vectors under `fixtures/pairing/`, recomputed in TypeScript.
 *
 * Nothing here calls the Rust implementation. SHA-256, HMAC-SHA256 and HKDF-SHA256 come from the
 * Node runtime, and the canonical encodings come from this package's own codec, so agreement with
 * the Rust vectors is real cross-language agreement.
 *
 * This is the TypeScript half of KR-ACC-015: the ten-character entry rules, the PAKE derivations,
 * the confirmation tags, the key-bundle and iroh binding, and both QR payload encodings.
 */

import { createHash, createHmac, hkdfSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import { decodeCanonical, encodeCanonical, krText } from '../src/index.js'

import { bytesToHex, hexToBytes } from './fixtures.js'

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

function loadPairingFixture (name: string): Record<string, any> {
  return JSON.parse(
    readFileSync(join(repositoryRoot, 'fixtures', 'pairing', name), 'utf8')
  ) as Record<string, any>
}

function sha256 (bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function hmac (keyHex: string, message: Uint8Array): string {
  return createHmac('sha256', Buffer.from(hexToBytes(keyHex))).update(message).digest('hex')
}

function hkdf (ikmHex: string, saltHex: string, info: string): string {
  return bytesToHex(
    new Uint8Array(
      hkdfSync(
        'sha256',
        Buffer.from(hexToBytes(ikmHex)),
        Buffer.from(hexToBytes(saltHex)),
        Buffer.from(info, 'utf8'),
        32
      )
    )
  )
}

/** The Bitcoin Base58 alphabet, as section 10 gives it. */
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/** Parses an entered code the way section 10 specifies: strip spaces and hyphens, keep case. */
function parseCode (entered: string): string | undefined {
  let normalised = ''
  for (const character of entered) {
    if (character === ' ' || character === '-') continue
    if (!BASE58.includes(character)) return undefined
    if (normalised.length === 10) return undefined
    normalised += character
  }
  return normalised.length === 10 ? normalised : undefined
}

describe('short-code entry', () => {
  const document = loadPairingFixture('codes.json')

// KR-REQ-10.11: the code alphabet is Bitcoin Base58.
  it('uses the Bitcoin Base58 alphabet', () => {
    expect(document.alphabet).toBe(BASE58)
    expect(document.display_form).toBe('XXXX-XXX-XXX')
    for (const excluded of ['0', 'O', 'I', 'l']) {
      expect(BASE58.includes(excluded)).toBe(false)
    }
  })

  it('accepts every spelling the vector accepts, with the same normalisation', () => {
    for (const entry of document.parsing.accepted) {
      expect(parseCode(entry.entered), entry.entered).toBe(entry.normalised)
      expect(entry.normalised.slice(0, 4)).toBe(entry.locator)
    }
  })

  it('rejects every case the vector rejects', () => {
    for (const entry of document.parsing.rejected) {
      expect(parseCode(entry.entered), entry.id).toBeUndefined()
    }
  })

// KR-REQ-10.11: parsing preserves case.
  it('preserves case, because folding it would throw away entropy', () => {
    expect(parseCode('aB3x-Yz7-9Qw')).not.toBe(parseCode('Ab3x-Yz7-9Qw'))
  })
})

describe('QR payloads', () => {
  const document = loadPairingFixture('codes.json')

// KR-REQ-10.38: both QR payloads round trip in their canonical encodings.
  it('round-trips both published encodings', () => {
    for (const mode of ['code', 'direct'] as const) {
      const canonical = hexToBytes(document.qr[mode].canonical_hex)
      const value = decodeCanonical(canonical)
      expect(value.kind).toBe('map')
      expect(bytesToHex(encodeCanonical(value))).toBe(document.qr[mode].canonical_hex)

      const entries = value.kind === 'map' ? new Map(value.entries) : new Map()
      expect(entries.get('mode')).toEqual(krText(mode))
      expect(entries.get('version')).toEqual({ kind: 'int', value: BigInt(document.qr.version) })
    }
  })

// KR-REQ-10.38: the two published payloads name different explicit modes, and a code payload
// carries four members to a direct payload's eight.
  it('requires an explicit supported mode', () => {
    const direct = decodeCanonical(hexToBytes(document.qr.direct.canonical_hex))
    const code = decodeCanonical(hexToBytes(document.qr.code.canonical_hex))
    const modeOf = (value: ReturnType<typeof decodeCanonical>): unknown =>
      value.kind === 'map' ? new Map(value.entries).get('mode') : undefined
    expect(modeOf(direct)).not.toEqual(modeOf(code))
    // A code payload has four members and a direct one has eight: a code QR carries no secret and
    // no endpoint, so it is not an offline invitation.
    expect(code.kind === 'map' ? code.entries.length : 0).toBe(4)
    expect(direct.kind === 'map' ? direct.entries.length : 0).toBe(8)
  })

  it('matches the base64url text form of the same bytes', () => {
    for (const mode of ['code', 'direct'] as const) {
      const canonical = hexToBytes(document.qr[mode].canonical_hex)
      expect(Buffer.from(canonical).toString('base64url')).toBe(document.qr[mode].text)
    }
  })
})

describe('short-code transcript', () => {
  const document = loadPairingFixture('transcript.json')

// KR-REQ-10.20: `C` built here from its seven published members, in the order section 10 writes
// them, is byte for byte the published encoding, and its SHA-256 is the published context hash.
  it('builds C as the array section 10 writes', () => {
    const context = document.context
    const built = encodeCanonical({
      kind: 'array',
      items: [
        krText(document.domain),
        krText(context.rendezvous_origin),
        krText(context.locator),
        { kind: 'bytes', value: hexToBytes(context.invitation_id_hex) },
        { kind: 'bytes', value: hexToBytes(context.attempt_id_hex) },
        { kind: 'bytes', value: hexToBytes(context.host_nonce_hex) },
        { kind: 'bytes', value: hexToBytes(context.client_nonce_hex) }
      ]
    })
    expect(bytesToHex(built)).toBe(context.canonical_hex)
    expect(sha256(built)).toBe(context.context_hash_hex)
  })

// KR-REQ-10.20: the host is role A and the client role B, each identified from `CH`.
  it('builds the two role identities from CH', () => {
    for (const [side, domainKey] of [
      ['host', 'host_domain'],
      ['client', 'client_domain']
    ] as const) {
      const identity = hexToBytes(document.identities[`${side}_hex`])
      const value = decodeCanonical(identity)
      expect(value.kind).toBe('array')
      if (value.kind !== 'array') throw new Error('unreachable')
      expect(value.items).toHaveLength(2)
      expect(value.items[0]).toEqual(krText(document.identities[domainKey]))
      const hash = value.items[1]
      expect(hash.kind).toBe('bytes')
      if (hash.kind !== 'bytes') throw new Error('unreachable')
      expect(bytesToHex(hash.value)).toBe(document.context.context_hash_hex)
    }
    expect(document.identities.host_hex).not.toBe(document.identities.client_hex)
  })

// KR-REQ-10.22: an independent computation of `T` gives the published value.
  it('computes T over the context and both messages in order', () => {
    const transcript = hexToBytes(document.exchange.transcript_hex)
    expect(sha256(transcript)).toBe(document.exchange.transcript_sha256_hex)
    const value = decodeCanonical(transcript)
    if (value.kind !== 'array') throw new Error('unreachable')
    expect(value.items).toHaveLength(3)
    const [context, messageA, messageB] = value.items
    expect(bytesToHex(encodeCanonical(context))).toBe(document.context.canonical_hex)
    if (messageA.kind !== 'bytes' || messageB.kind !== 'bytes') throw new Error('unreachable')
    expect(bytesToHex(messageA.value)).toBe(document.exchange.message_a_hex)
    expect(bytesToHex(messageB.value)).toBe(document.exchange.message_b_hex)
  })

// KR-REQ-10.22: Node's own HKDF-SHA256, with `K` and salt `T`, derives the five published keys.
  it('derives the five keys with the five literal information strings', () => {
    const salt = document.exchange.transcript_sha256_hex
    const ikm = document.exchange.shared_key_hex
    const expected: Array<[string, string]> = [
      ['kr-pair/1/client-confirm', document.hkdf.client_confirm_key_hex],
      ['kr-pair/1/host-confirm', document.hkdf.host_confirm_key_hex],
      ['kr-pair/1/client-to-host', document.hkdf.client_to_host_key_hex],
      ['kr-pair/1/host-to-client', document.hkdf.host_to_client_key_hex],
      ['kr-pair/1/iroh-bind', document.hkdf.iroh_bind_key_hex]
    ]
    expect(document.hkdf.info_strings).toEqual(expected.map(([info]) => info))
    for (const [info, key] of expected) {
      expect(hkdf(ikm, salt, info), info).toBe(key)
    }
    expect(new Set(expected.map(([, key]) => key)).size).toBe(expected.length)
  })

// KR-REQ-10.23: both confirmation tags are HMAC-SHA256 over `T` under their own keys.
  it('computes both confirmation tags over T', () => {
    const transcript = hexToBytes(document.exchange.transcript_sha256_hex)
    expect(hmac(document.hkdf.client_confirm_key_hex, transcript)).toBe(
      document.confirmation.client_tag_hex
    )
    expect(hmac(document.hkdf.host_confirm_key_hex, transcript)).toBe(
      document.confirmation.host_tag_hex
    )
    expect(document.confirmation.client_tag_hex).not.toBe(document.confirmation.host_tag_hex)
  })

// KR-REQ-10.27: the `pair.finish` tag covers both endpoint identities and both bundle hashes.
  it('binds pair.finish to both endpoints and both bundle hashes', () => {
    const message = hexToBytes(document.finish.message_hex)
    expect(hmac(document.hkdf.iroh_bind_key_hex, message)).toBe(document.finish.tag_hex)

    const value = decodeCanonical(message)
    if (value.kind !== 'array') throw new Error('unreachable')
    expect(value.items[0]).toEqual(krText('kr-pair/finish/1'))
    const hexOf = (index: number): string => {
      const item = value.items[index]
      if (item.kind !== 'bytes') throw new Error('unreachable')
      return bytesToHex(item.value)
    }
    expect(hexOf(3)).toBe(document.exchange.transcript_sha256_hex)
    expect(hexOf(4)).toBe(document.finish.host_endpoint_hex)
    expect(hexOf(5)).toBe(document.finish.client_endpoint_hex)
    expect(hexOf(6)).toBe(document.finish.host_bundle_hash_hex)
    expect(hexOf(7)).toBe(document.finish.client_bundle_hash_hex)
  })

// KR-REQ-10.24: the bundle additional data separates direction, sequence and type.
  it('separates every bundle additional-data case', () => {
    const seen = new Set<string>()
    for (const entry of document.bundle_additional_data) {
      expect(seen.has(entry.aad_hex)).toBe(false)
      seen.add(entry.aad_hex)
      const value = decodeCanonical(hexToBytes(entry.aad_hex))
      if (value.kind !== 'array') throw new Error('unreachable')
      expect(value.items).toHaveLength(5)
      expect(value.items[0]).toEqual(krText(document.domain))
      expect(value.items[2]).toEqual(krText(entry.direction))
      expect(value.items[3]).toEqual({ kind: 'int', value: BigInt(entry.sequence) })
      expect(value.items[4]).toEqual(krText(entry.message_type))
    }
    expect(seen.size).toBe(4)
  })

// KR-REQ-10.28: the verification value is the first eight hex characters of its digest.
  it('takes the verification value from the first eight hexadecimal characters', () => {
    const input = encodeCanonical({
      kind: 'array',
      items: [
        krText(document.verification_value.domain),
        { kind: 'bytes', value: hexToBytes(document.exchange.transcript_sha256_hex) },
        { kind: 'bytes', value: hexToBytes(document.finish.host_bundle_hash_hex) },
        { kind: 'bytes', value: hexToBytes(document.finish.client_bundle_hash_hex) }
      ]
    })
    expect(sha256(input).slice(0, 8)).toBe(document.verification_value.value)
  })
})

describe('direct transcript', () => {
  const document = loadPairingFixture('direct.json')

// KR-REQ-10.36: `D` built here from its members, in the order section 10 writes them, is byte for
// byte the published encoding. The fixed inputs give each device a complete purpose-key bundle
// whose transport key is its endpoint and whose other three keys are the next three byte values,
// and the proposed-grant digest is taken here from the grant the published direct QR carries.
  it('builds D as the array section 10 writes', () => {
    const transcript = document.transcript
    const fill = (byte: number): Uint8Array => new Uint8Array(32).fill(byte)
    const bundle = (endpointHex: string): ReturnType<typeof decodeCanonical> => {
      const first = hexToBytes(endpointHex)[0]
      return {
        kind: 'array',
        items: [0, 1, 2, 3].map((offset) => ({ kind: 'bytes', value: fill(first + offset) }))
      }
    }
    const qr = decodeCanonical(hexToBytes(loadPairingFixture('codes.json').qr.direct.canonical_hex))
    if (qr.kind !== 'map') throw new Error('unreachable')
    const grant = new Map(qr.entries).get('proposed_grant')
    if (grant === undefined) throw new Error('the direct QR carries a proposed grant')
    const grantDigest = sha256(encodeCanonical(grant))
    expect(grantDigest).toBe(transcript.proposed_grant_digest_hex)

    const built = encodeCanonical({
      kind: 'array',
      items: [
        krText(document.domain),
        { kind: 'bytes', value: hexToBytes(transcript.invitation_id_hex) },
        { kind: 'bytes', value: hexToBytes(transcript.host_endpoint_hex) },
        { kind: 'bytes', value: hexToBytes(transcript.client_endpoint_hex) },
        bundle(transcript.host_endpoint_hex),
        bundle(transcript.client_endpoint_hex),
        { kind: 'bytes', value: hexToBytes(grantDigest) },
        { kind: 'bytes', value: hexToBytes(transcript.host_nonce_hex) },
        { kind: 'bytes', value: hexToBytes(transcript.client_nonce_hex) },
        { kind: 'int', value: BigInt(transcript.expires_at) }
      ]
    })
    expect(bytesToHex(built)).toBe(transcript.canonical_hex)
    expect(sha256(built)).toBe(transcript.canonical_sha256_hex)
  })

// KR-REQ-10.36: the redemption proof is HMAC-SHA256 of the invitation secret over `D`.
  it('computes the secret proof over D', () => {
    expect(
      hmac(document.secret_proof.secret_hex, hexToBytes(document.transcript.canonical_hex))
    ).toBe(document.secret_proof.tag_hex)
  })

// KR-REQ-10.37: the direct verification value comes from its own domain over `D`.
  it('takes its verification value from its own domain', () => {
    expect(document.domain).not.toBe('kr-pair/spake2-ed25519/1')
    expect(document.verification_value.domain).toBe('kr-pair/direct-verify/1')
    const input = encodeCanonical({
      kind: 'array',
      items: [
        krText(document.verification_value.domain),
        decodeCanonical(hexToBytes(document.transcript.canonical_hex))
      ]
    })
    expect(sha256(input).slice(0, 8)).toBe(document.verification_value.value)
  })
})
