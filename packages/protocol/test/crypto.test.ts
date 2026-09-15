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

import { createHash, createHmac, createPublicKey, hkdfSync, verify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import { decodeCanonical, encodeCanonical, krBytes, krText, signingInput } from '../src/index.js'

import { bytesToHex, hexToBytes } from './fixtures.js'

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

function loadCryptoFixture (name: string): Record<string, any> {
  return JSON.parse(
    readFileSync(join(repositoryRoot, 'fixtures', 'crypto', name), 'utf8')
  ) as Record<string, any>
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
