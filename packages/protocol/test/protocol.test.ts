import { describe, expect, it } from 'vitest'

import {
  decodeCanonical,
  encodeCanonical,
  mapGet,
  sha256,
  signingDigest,
  signingInput,
  valuesEqual
} from '../src/index.js'
import type { MutationRequest, Receipt } from '../src/generated/protocol.js'
import { bytesToHex, findCase, hexToBytes, loadFixture, parseValue } from './fixtures.js'

const frames = loadFixture('protocol', 'frames.json')
const transcripts = loadFixture('protocol', 'transcripts.json')

const FRAME_LENGTH_PREFIX_LEN = 4

/** Complete frame bounds, prefix included, matching kr_protocol::limits. */
const MAX_FRAME_LEN: Record<string, number> = {
  control: 1024 * 1024,
  terminal_output: 1024 * 1024,
  semantic_updates: 1024 * 1024,
  terminal_input: 64 * 1024,
  attachment_chunks: 1024 * 1024 + 4 * 1024
}

/** Frames one payload: a four-byte big-endian length followed by one KR-CBOR-1 object. */
function frame (payload: Uint8Array, streamKind: string): Uint8Array {
  const frameLimit = MAX_FRAME_LEN[streamKind]
  if (frameLimit === undefined) {
    throw new Error(`unknown stream kind ${streamKind}`)
  }
  // The stated bound covers the bytes that go on the wire, so the payload is that less its prefix.
  const limit = frameLimit - FRAME_LENGTH_PREFIX_LEN
  if (payload.length === 0) {
    throw new Error('a frame payload cannot be empty')
  }
  if (payload.length > limit) {
    throw new Error(`frame of ${payload.length} bytes exceeds the ${limit}-byte limit`)
  }
  const out = new Uint8Array(FRAME_LENGTH_PREFIX_LEN + payload.length)
  new DataView(out.buffer).setUint32(0, payload.length, false)
  out.set(payload, FRAME_LENGTH_PREFIX_LEN)
  return out
}

describe('frames.json', () => {
  const cases = frames.cases ?? []

  it('covers the envelope types', () => {
    expect(cases.length).toBeGreaterThanOrEqual(7)
  })

  it.each(cases.map((entry) => [entry.id, entry] as const))(
    '%s round trips byte for byte',
    (_id, entry) => {
      const value = parseValue(entry.value)
      const encoded = encodeCanonical(value)
      expect(bytesToHex(encoded)).toBe(entry.cbor_hex)
      expect(valuesEqual(decodeCanonical(encoded), value)).toBe(true)
      expect(bytesToHex(frame(encoded, entry.stream_kind as string))).toBe(entry.frame_hex)
    }
  )

  it('rejects a frame above its stream bound before any payload is built', () => {
    for (const [kind, frameLimit] of Object.entries(MAX_FRAME_LEN)) {
      const payloadLimit = frameLimit - FRAME_LENGTH_PREFIX_LEN
      expect(frame(new Uint8Array(payloadLimit), kind).length).toBe(frameLimit)
      expect(() => frame(new Uint8Array(payloadLimit + 1), kind)).toThrowError(/exceeds/)
    }
    expect(() => frame(new Uint8Array(0), 'control')).toThrowError(/cannot be empty/)
  })
})

describe('the mutation from the specification example', () => {
  const entry = findCase(frames, 'mutation_request')
  const decoded = decodeCanonical(hexToBytes(entry.cbor_hex as string))

  it('carries every field a mutation requires', () => {
    for (const field of [
      'request_id',
      'method',
      'method_version',
      'action_id',
      'grant_id',
      'target',
      'expected',
      'action_window_id',
      'requested_ttl_ms',
      'params'
    ]) {
      expect(mapGet(decoded, field), `${field} is missing`).toBeDefined()
    }
  })

  it('puts identifiers on the wire as 16-byte strings', () => {
    const actionId = mapGet(decoded, 'action_id')
    expect(actionId?.kind).toBe('bytes')
    expect((actionId as { value: Uint8Array }).value.length).toBe(16)
  })

  it('puts counters on the wire as unsigned integers', () => {
    const ttl = mapGet(decoded, 'requested_ttl_ms')
    expect(ttl?.kind).toBe('int')
    expect((ttl as { value: bigint }).value).toBe(120000n)
  })

  it('types as the generated MutationRequest shape', () => {
    // A compile-time check that the generated interface covers the example's fields.
    const typed: Pick<MutationRequest, 'method' | 'method_version'> = {
      method: 'agent.approval.respond',
      method_version: 1
    }
    expect(typed.method).toBe('agent.approval.respond')
  })
})

describe('the receipt', () => {
  it('names a state from the transition contract', () => {
    const entry = findCase(frames, 'receipt_response')
    const decoded = decodeCanonical(hexToBytes(entry.cbor_hex as string))
    const receipt = mapGet(decoded, 'receipt')
    expect(receipt).toBeDefined()
    const state = mapGet(receipt as never, 'state')
    const permitted: Array<Receipt['state']> = [
      'received',
      'accepted',
      'dispatching',
      'applied',
      'refused',
      'rejected',
      'unknown'
    ]
    expect(permitted).toContain((state as { value: string }).value)
    // A receipt that has not been rejected carries an explicit null reason, never an omitted one.
    expect(mapGet(receipt as never, 'reason')?.kind).toBe('null')
  })
})

describe('transcripts.json', () => {
  it.each((transcripts.cases ?? []).map((entry) => [entry.id, entry] as const))(
    '%s produces the same bytes and digest',
    async (_id, entry) => {
      const value = parseValue(entry.value)
      const encoded = encodeCanonical(value)
      expect(bytesToHex(encoded)).toBe(entry.hex)
      expect(bytesToHex(await sha256(encoded))).toBe(entry.sha256)
    }
  )

  it('builds the connect transcript from its parts', async () => {
    const entry = (transcripts.cases ?? []).find((item) => item.id === 'connect_transcript')
    if (entry === undefined) {
      throw new Error('missing connect_transcript')
    }
    const built = signingInput('kr-connect/1', [
      parseValue(entry.client_offer),
      parseValue(entry.host_selection),
      parseValue({ bytes: entry.client_endpoint_id }),
      parseValue({ bytes: entry.host_endpoint_id })
    ])
    expect(bytesToHex(built)).toBe(entry.hex)
    expect(
      bytesToHex(
        await signingDigest('kr-connect/1', [
          parseValue(entry.client_offer),
          parseValue(entry.host_selection),
          parseValue({ bytes: entry.client_endpoint_id }),
          parseValue({ bytes: entry.host_endpoint_id })
        ])
      )
    ).toBe(entry.sha256)
  })
})
