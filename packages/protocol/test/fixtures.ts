/** Loads the cross-language fixtures and parses their value description grammar. */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  type CanonicalValue,
  krArray,
  krBool,
  krBytes,
  krInt,
  krMap,
  krNull,
  krText
} from '../src/index.js'

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

export interface FixtureCase {
  id: string
  description: string
  value?: unknown
  hex?: string
  rule?: string
  limits?: Record<string, number>
  cbor_hex?: string
  frame_hex?: string
  stream_kind?: string
  sha256?: string
  domain?: string
  elements?: unknown[]
  [key: string]: unknown
}

export interface FixtureFile {
  name: string
  description: string
  cases?: FixtureCase[]
  digest_cases?: FixtureCase[]
  signing_input_cases?: FixtureCase[]
  digests?: Record<string, string>
  [key: string]: unknown
}

/** Loads one fixture document from `fixtures/<area>/<name>`. */
export function loadFixture (area: 'cbor' | 'protocol' | 'relay', name: string): FixtureFile {
  const path = join(repositoryRoot, 'fixtures', area, name)
  return JSON.parse(readFileSync(path, 'utf8')) as FixtureFile
}

/** Parses the fixture value grammar into a canonical value. */
export function parseValue (description: unknown): CanonicalValue {
  if (typeof description !== 'object' || description === null) {
    throw new Error(`a value description is an object: ${JSON.stringify(description)}`)
  }
  const entries = Object.entries(description as Record<string, unknown>)
  if (entries.length !== 1) {
    throw new Error('a value description has exactly one key')
  }
  const [kind, payload] = entries[0]
  switch (kind) {
    case 'int':
      return krInt(BigInt(payload as string))
    case 'bytes':
      return krBytes(hexToBytes(payload as string))
    case 'text':
      return krText(payload as string)
    case 'bool':
      return krBool(payload as boolean)
    case 'null':
      return krNull()
    case 'array':
      return krArray((payload as unknown[]).map(parseValue))
    case 'map':
      return krMap(
        (payload as Array<[string, unknown]>).map(
          ([key, value]) => [key, parseValue(value)] as const
        )
      )
    default:
      throw new Error(`unknown value kind ${kind}`)
  }
}

/** Finds one case by identifier. */
export function findCase (document: FixtureFile, id: string): FixtureCase {
  const found = (document.cases ?? []).find((entry) => entry.id === id)
  if (found === undefined) {
    throw new Error(`no case ${id}`)
  }
  return found
}

/** Decodes a hex string. */
export function hexToBytes (hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('hex has an odd length')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

/** Encodes bytes as hex. */
export function bytesToHex (bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}
