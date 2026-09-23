/**
 * The cryptography vectors under `fixtures/crypto/`, recomputed in TypeScript.
 *
 * Nothing here calls the Rust implementation. SHA-256, HMAC-SHA256, HKDF-SHA256 and Ed25519
 * verification come from the Node runtime, and the canonical encodings come from this package's
 * own codec, so agreement with the Rust vectors is real cross-language agreement rather than two
 * readings of one library.
 *
 * This is the TypeScript half of KR-ACC-015 and of the section 23 signature conformance the
 * protocol package deferred.
 */

import { createHash, createHmac, createPrivateKey, createPublicKey, hkdfSync, sign, verify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
  decodeCanonical, encodeCanonical, krArray, krBytes, krMap, krNull, krText, signingInput,
  type CanonicalValue
} from '../src/index.js'

import { bytesToHex, hexToBytes, loadFixture, parseValue } from './fixtures.js'

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

function loadCryptoFixture (name: string): Record<string, any> {
  return JSON.parse(
    readFileSync(join(repositoryRoot, 'fixtures', 'crypto', name), 'utf8')
  ) as Record<string, any>
}

/** Decodes the sixteen bytes a hyphenated UUID names. */
function uuidToBytes (text: string): Uint8Array {
  return hexToBytes(text.replace(/-/g, ''))
}

/** Decodes the unpadded base64url the JSON representation uses for opaque bytes. */
function fromBase64url (text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'base64url'))
}

function sha256 (bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex')
}

/** Wraps a raw 32-byte Ed25519 public key in the SPKI encoding Node reads. */
function ed25519PublicKey (raw: Uint8Array) {
  const spki = new Uint8Array([
    // SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING { key } }
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ...raw
  ])
  return createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' })
}

/** Wraps a 32-byte Ed25519 seed in the PKCS #8 encoding Node reads. */
function ed25519PrivateKey (seed: Uint8Array) {
  const pkcs8 = new Uint8Array([
    // SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING { seed } } }
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ...seed
  ])
  return createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' })
}

// KR-REQ-23.08: the TypeScript half of signature parity for the edge cases section 23 lists. Every
// boundary integer, non-ASCII string, map ordering, absent/null and structure case under
// fixtures/cbor is encoded by this package's own codec into CBOR([domain, value]); the published
// signature verifies over those bytes, and signing them with the host test seed reproduces it.
describe('KR-CBOR-1 edge case signatures', () => {
  const host = loadCryptoFixture('signatures.json').keys.host
  const privateKey = ed25519PrivateKey(hexToBytes(host.seed_hex))
  const publicKey = ed25519PublicKey(hexToBytes(host.public_key_hex))
  const files = [
    'integers.json',
    'strings.json',
    'map-ordering.json',
    'null-and-absent.json',
    'structures.json'
  ] as const

  it.each(files)('%s is signed alike in both languages', (name) => {
    const document = loadFixture('cbor', name)
    const signing = document.signing as { domain: string, public_key_hex: string }
    expect(signing.public_key_hex).toBe(host.public_key_hex)
    const cases = document.cases ?? []
    expect(cases.length).toBeGreaterThan(3)
    for (const entry of cases) {
      const transcript = signingInput(signing.domain, [parseValue(entry.value)])
      expect(bytesToHex(transcript).endsWith(entry.hex as string), entry.id).toBe(true)
      const published = Buffer.from(hexToBytes(entry.signature_hex as string))
      expect(verify(null, Buffer.from(transcript), publicKey, published), entry.id).toBe(true)
      expect(
        bytesToHex(new Uint8Array(sign(null, Buffer.from(transcript), privateKey))),
        entry.id
      ).toBe(entry.signature_hex)
    }
  })
})

// KR-REQ-23.08: the TypeScript half of signature parity: every published signature verifies and
// every negative case fails.
describe('signature vectors', () => {
  const document = loadCryptoFixture('signatures.json')

  it('verifies every published signature', () => {
    const publicKey = ed25519PublicKey(hexToBytes(document.keys.host.public_key_hex))
    expect(document.cases.length).toBeGreaterThan(0)
    for (const testCase of document.cases) {
      const message = hexToBytes(testCase.message_hex)
      expect(sha256(message), testCase.id).toBe(testCase.message_sha256)
      const ok = verify(
        null,
        Buffer.from(message),
        publicKey,
        Buffer.from(hexToBytes(testCase.signature_hex))
      )
      expect(ok, testCase.id).toBe(true)
    }
  })

  it('confirms the message is a domain-separated canonical transcript', () => {
    for (const testCase of document.cases) {
      const value = decodeCanonical(hexToBytes(testCase.message_hex))
      expect(value.kind, testCase.id).toBe('array')
      if (value.kind !== 'array') throw new Error('unreachable')
      expect(value.items[0]).toEqual(krText(testCase.domain))
      // Re-encoding the decoded value gives the bytes it arrived in.
      expect(bytesToHex(encodeCanonical(value))).toBe(testCase.message_hex)
    }
  })

  it('rejects every negative case', () => {
    for (const testCase of document.negative_cases) {
      const ok = verify(
        null,
        Buffer.from(hexToBytes(testCase.message_hex)),
        ed25519PublicKey(hexToBytes(testCase.public_key_hex)),
        Buffer.from(hexToBytes(testCase.signature_hex))
      )
      expect(ok, testCase.id).toBe(false)
    }
  })

  it('reproduces the RFC 8032 test vector', () => {
    const vector = document.rfc_8032_test_vector_1
    expect(vector.public_key_hex).toBe(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
    )
    const ok = verify(
      null,
      Buffer.alloc(0),
      ed25519PublicKey(hexToBytes(vector.public_key_hex)),
      Buffer.from(hexToBytes(vector.signature_hex))
    )
    expect(ok).toBe(true)
  })

  it('requires both connection proofs', () => {
    const proofs = document.connect_proofs
    const transcript = hexToBytes(proofs.transcript_hex)
    expect(sha256(transcript)).toBe(proofs.transcript_sha256)

    const value = decodeCanonical(transcript)
    expect(value.kind).toBe('array')
    if (value.kind !== 'array') throw new Error('unreachable')
    expect(value.items[0]).toEqual(krText(proofs.domain))

    const hostKey = ed25519PublicKey(hexToBytes(document.keys.host.public_key_hex))
    const clientKey = ed25519PublicKey(hexToBytes(document.keys.client.public_key_hex))
    const hostProof = Buffer.from(hexToBytes(proofs.host_signature_hex))
    const clientProof = Buffer.from(hexToBytes(proofs.client_signature_hex))
    const message = Buffer.from(transcript)

    expect(verify(null, message, hostKey, hostProof)).toBe(true)
    expect(verify(null, message, clientKey, clientProof)).toBe(true)
    // Neither proof stands in for the other.
    expect(verify(null, message, hostKey, clientProof)).toBe(false)
    expect(verify(null, message, clientKey, hostProof)).toBe(false)
  })

  it('derives the same key identifier', () => {
    const raw = hexToBytes(document.keys.host.public_key_hex)
    const input = signingInput(document.key_id_domain, [krText('authorisation'), krBytes(raw)])
    expect(sha256(input)).toBe(document.keys.host.key_id_hex)
  })
})

describe('envelope vectors', () => {
  const document = loadCryptoFixture('envelopes.json')

  it('reproduces the canonical envelope bytes and their digest', () => {
    const canonical = hexToBytes(document.envelope.canonical_hex)
    expect(sha256(canonical)).toBe(document.envelope.canonical_sha256)
    const value = decodeCanonical(canonical)
    expect(value.kind).toBe('map')
    expect(bytesToHex(encodeCanonical(value))).toBe(document.envelope.canonical_hex)
  })

  it('seals the padded plaintext, not the plaintext', () => {
    const canonical = hexToBytes(document.envelope.canonical_hex)
    const bucket: number = document.envelope.padded_len
    expect(bucket).toBeGreaterThan(canonical.length)
    // The ciphertext is the bucket plus the crypto_box MAC, so the stored size says nothing about
    // the plaintext beyond its bucket.
    const ciphertext = fromBase64url(document.envelope.sealed_json.ciphertext)
    expect(ciphertext.length).toBe(bucket + 16)
    expect(Number(document.envelope.sealed_json.routing.size_bucket_bytes)).toBe(bucket)
  })

  it('reproduces the key wrap plaintext from its context', () => {
    const canonical = hexToBytes(document.key_wrap.canonical_hex)
    const value = decodeCanonical(canonical)
    expect(value.kind).toBe('array')
    if (value.kind !== 'array') throw new Error('unreachable')
    expect(value.items).toHaveLength(2)
    const key = value.items[1]
    expect(key.kind).toBe('bytes')
    if (key.kind !== 'bytes') throw new Error('unreachable')
    expect(bytesToHex(key.value)).toBe(document.key_wrap.object_key_hex)
    expect(bytesToHex(encodeCanonical(value))).toBe(document.key_wrap.canonical_hex)
  })

  it('verifies the forwarded authority object under the issuer key it names', () => {
    const section = document.authority_object
    const request = section.object_json.revocation_request
    // The signature covers a domain-separated transcript of the object's own fields, and the
    // issuer key is named by its identifier rather than carried by the envelope. Both are rebuilt
    // here from the published object rather than taken on trust from the transcript bytes.
    const signingInputBytes = hexToBytes(section.signing_input_hex)
    const transcript = decodeCanonical(signingInputBytes)
    expect(transcript.kind).toBe('array')
    if (transcript.kind !== 'array') throw new Error('unreachable')
    expect(transcript.items[0]).toEqual(krText(section.signing_domain))
    // Element by element against the object's own fields: the request, both devices, the instant
    // and the issuer's key identifier. A transcript that covered other values than the ones the
    // object publishes would fail here rather than verify.
    expect(transcript.items[1]).toEqual(krBytes(uuidToBytes(request.request_id)))
    expect(transcript.items[2]).toEqual(krBytes(uuidToBytes(request.issuer_device_id)))
    expect(transcript.items[3]).toEqual(krBytes(uuidToBytes(request.host_device_id)))
    // The target is rebuilt from the object's own JSON, so a changed target cannot pass this test
    // without changing the transcript the signature covers.
    expect(transcript.items[4]).toEqual(krMap([
      ['grants', krMap([[
        'grant_ids',
        krArray(request.target.grants.grant_ids.map((id: string) => krBytes(uuidToBytes(id))))
      ]])]
    ]))
    expect(transcript.items[5]).toEqual({ kind: 'int', value: BigInt(request.issued_at_ms) })
    expect(transcript.items[6]).toEqual(krBytes(fromBase64url(request.issuer_key_id)))
    expect(bytesToHex(encodeCanonical(transcript))).toBe(section.signing_input_hex)

    // The identifier the object names is the identifier of the key it is verified under, derived
    // the way every key identifier in this protocol is.
    const rawKey = hexToBytes(section.issuer.public_key_hex)
    expect(sha256(signingInput('kr-key-id/1', [krText('authorisation'), krBytes(rawKey)]))).toBe(
      bytesToHex(fromBase64url(request.issuer_key_id))
    )
    expect(section.issuer.key_id_hex).toBe(bytesToHex(fromBase64url(request.issuer_key_id)))

    const publicKey = ed25519PublicKey(hexToBytes(section.issuer.public_key_hex))
    const signature = fromBase64url(section.object_json.revocation_request.signature)
    expect(verify(null, Buffer.from(signingInputBytes), publicKey, Buffer.from(signature))).toBe(
      true
    )

    // A single flipped byte of the transcript is refused, so the check is the signature's and not
    // the encoding's.
    const altered = new Uint8Array(signingInputBytes)
    altered[altered.length - 1] ^= 0x01
    expect(verify(null, Buffer.from(altered), publicKey, Buffer.from(signature))).toBe(false)

    // The envelope's payload is this very object's canonical encoding and nothing else, which is
    // what makes the envelope a delivery rather than an authorisation. It is rebuilt field by
    // field, so a payload carrying a different object cannot pass while the transcript above does.
    const payload = hexToBytes(section.payload_canonical_hex)
    const rebuilt = krMap([['revocation_request', krMap([
      ['request_id', krBytes(uuidToBytes(request.request_id))],
      ['issuer_device_id', krBytes(uuidToBytes(request.issuer_device_id))],
      ['host_device_id', krBytes(uuidToBytes(request.host_device_id))],
      ['target', transcript.items[4]],
      ['issued_at_ms', { kind: 'int', value: BigInt(request.issued_at_ms) }],
      ['issuer_key_id', krBytes(fromBase64url(request.issuer_key_id))],
      ['signature', krBytes(signature)]
    ])]])
    expect(bytesToHex(encodeCanonical(rebuilt))).toBe(section.payload_canonical_hex)
    expect(decodeCanonical(payload)).toEqual(rebuilt)
    expect(section.envelope.plaintext_json.payload).toBe(
      Buffer.from(payload).toString('base64url')
    )
    expect(section.envelope.plaintext_json.payload_type).toBe('signed_authority_object')
    // A payload that carries authority is never coalesced, so it names no thread.
    expect(section.envelope.plaintext_json.thread_id).toBeNull()
  })

  it('applies the published size bucket rule', () => {
    const kib = 1024
    const granularity = (plaintext: number): number =>
      plaintext <= 16 * kib ? kib : plaintext <= 64 * kib ? 4 * kib : 64 * kib
    const bucket = (plaintext: number, step: number): number =>
      (Math.floor(plaintext / step) + 1) * step

    for (const entry of document.size_buckets.mailbox) {
      expect(bucket(entry.plaintext_bytes, granularity(entry.plaintext_bytes))).toBe(
        entry.bucket_bytes
      )
      expect(entry.bucket_bytes).toBeGreaterThan(entry.plaintext_bytes)
    }
    for (const entry of document.size_buckets.notification) {
      expect(bucket(entry.plaintext_bytes, kib)).toBe(entry.bucket_bytes)
    }
  })
})

describe('derivation vectors', () => {
  const document = loadCryptoFixture('kdf.json')

  it('reproduces the HKDF-SHA256 output', () => {
    const okm = new Uint8Array(
      hkdfSync(
        'sha256',
        Buffer.from(hexToBytes(document.hkdf_sha256.ikm_hex)),
        Buffer.from(hexToBytes(document.hkdf_sha256.salt_hex)),
        Buffer.from(hexToBytes(document.hkdf_sha256.info_hex)),
        32
      )
    )
    expect(bytesToHex(okm)).toBe(document.hkdf_sha256.okm_hex)
    // RFC 5869 appendix A.1.
    expect(document.hkdf_sha256.okm_hex).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
    )
  })

  it('reproduces the HMAC-SHA256 tag', () => {
    const tag = createHmac('sha256', Buffer.from(hexToBytes(document.hmac_sha256.key_hex)))
      .update(document.hmac_sha256.message_utf8, 'utf8')
      .digest('hex')
    expect(tag).toBe(document.hmac_sha256.tag_hex)
  })

  it('binds the recovery bundle key to its retrieval context', () => {
    const binding = document.recovery.context_binding
    const salt = signingInput('kr-recovery-bundle/1', [
      krText(binding.context_json.service_origin),
      krText(binding.context_json.bundle_locator)
    ])
    expect(bytesToHex(salt)).toBe(binding.context_salt_hex)

    const bound = new Uint8Array(
      hkdfSync(
        'sha256',
        Buffer.from(hexToBytes(document.recovery.bundle_key_hex)),
        Buffer.from(salt),
        Buffer.from('kr-recovery-bundle/1', 'utf8'),
        32
      )
    )
    expect(bytesToHex(bound)).toBe(binding.bundle_key_hex)
    expect(binding.bundle_key_hex).not.toBe(document.recovery.bundle_key_hex)
  })

  it('names the specified crypto_kdf context', () => {
    expect(document.recovery.context).toBe('KRRECOV1')
    expect(document.recovery.bundle_subkey_id).toBe(1)
    expect(document.recovery.recipient_subkey_id).toBe(2)
  })
})

describe('collection key vectors', () => {
  const document = loadCryptoFixture('collection-keys.json')

  /** An unsigned integer the JSON carries as a decimal string. */
  function int (text: string): CanonicalValue {
    return { kind: 'int', value: BigInt(text) }
  }

  /** Rebuilds a wrap's context from its JSON, field by field. */
  function contextValue (context: Record<string, string>): CanonicalValue {
    return krMap([
      ['format', krText(context.format)],
      ['collection_id', krBytes(uuidToBytes(context.collection_id))],
      ['key_epoch', int(context.key_epoch)],
      ['sender_key_id', krBytes(fromBase64url(context.sender_key_id))],
      ['recipient_key_id', krBytes(fromBase64url(context.recipient_key_id))]
    ])
  }

  /** Rebuilds one record's payload from its JSON, field by field. */
  function payloadValue (payload: Record<string, any>): CanonicalValue {
    return krMap([
      ['collection_id', krBytes(uuidToBytes(payload.collection_id))],
      ['home', krBytes(uuidToBytes(payload.home))],
      ['key_epoch', int(payload.key_epoch)],
      ['revision', int(payload.revision)],
      ['previous', payload.previous === null ? krNull() : krBytes(fromBase64url(payload.previous))],
      ['issuer_key_id', krBytes(fromBase64url(payload.issuer_key_id))],
      ['issued_at_ms', int(payload.issued_at_ms)],
      ['members', krArray(payload.members.map((member: Record<string, any>) => krMap([
        ['authorisation', krBytes(fromBase64url(member.authorisation))],
        ['stored_envelope', krBytes(fromBase64url(member.stored_envelope))],
        ['wrap', krMap([
          ['context', contextValue(member.wrap.context)],
          ['nonce', krBytes(fromBase64url(member.wrap.nonce))],
          ['ciphertext', krBytes(fromBase64url(member.wrap.ciphertext))]
        ])]
      ])))]
    ])
  }

  /** The identifier of an authorisation key, derived the way every key identifier is. */
  function authorisationKeyId (raw: Uint8Array): string {
    return sha256(signingInput('kr-key-id/1', [krText('authorisation'), krBytes(raw)]))
  }

  it('rebuilds the wrap plaintext from the context its JSON declares', () => {
    const declared = document.wrap.context_json
    const rebuilt = encodeCanonical(krArray([
      contextValue(declared),
      krBytes(hexToBytes(document.collection_key_hex))
    ]))
    expect(bytesToHex(rebuilt)).toBe(document.wrap.canonical_hex)
    expect(declared.format).toBe('kr-collection-key-wrap/1')
    expect(declared.sender_key_id).toBe(
      Buffer.from(hexToBytes(document.members.a.stored_envelope_key_id_hex)).toString('base64url')
    )
    expect(declared.recipient_key_id).toBe(
      Buffer.from(hexToBytes(document.members.b.stored_envelope_key_id_hex)).toString('base64url')
    )
    // crypto_box_easy adds its sixteen-byte tag and nothing else.
    expect(fromBase64url(document.wrap.sealed_json.ciphertext).length).toBe(rebuilt.length + 16)
  })

  it('rebuilds each record from its JSON, verifies it under its issuer and chains them', () => {
    for (const record of document.records) {
      const payload = record.record_json.payload
      // The bytes the signature covers are rebuilt from the record's own fields under the literal
      // domain, not taken from the published transcript.
      const input = signingInput('kr-collection-keys/1', [payloadValue(payload)])
      expect(bytesToHex(input)).toBe(record.signing_input_hex)

      // The issuer is found among the members by the key identifier the record names, and the
      // signature verifies under that member's authorisation key over the rebuilt bytes.
      const issuerKeyId = bytesToHex(fromBase64url(payload.issuer_key_id))
      const issuer = payload.members.find(
        (member: { authorisation: string }) =>
          authorisationKeyId(fromBase64url(member.authorisation)) === issuerKeyId
      )
      expect(issuer).toBeDefined()
      const signature = fromBase64url(record.record_json.signature)
      const publicKey = ed25519PublicKey(fromBase64url(issuer.authorisation))
      expect(verify(null, Buffer.from(input), publicKey, Buffer.from(signature))).toBe(true)
      const altered = new Uint8Array(input)
      altered[altered.length - 1] ^= 0x01
      expect(verify(null, Buffer.from(altered), publicKey, Buffer.from(signature))).toBe(false)

      // The whole record, rebuilt, is the published encoding, and its digest is what the next
      // record names.
      const whole = encodeCanonical(krMap([
        ['payload', payloadValue(payload)],
        ['signature', krBytes(signature)]
      ]))
      expect(bytesToHex(whole)).toBe(record.canonical_hex)
      expect(sha256(whole)).toBe(record.digest_hex)
    }

    const [first, second] = document.records
    expect(first.record_json.payload.previous).toBeNull()
    expect(bytesToHex(fromBase64url(second.record_json.payload.previous))).toBe(first.digest_hex)
    expect(second.record_json.payload.key_epoch).toBe(first.record_json.payload.key_epoch)
    expect(second.record_json.payload.members).toHaveLength(2)
  })
})
