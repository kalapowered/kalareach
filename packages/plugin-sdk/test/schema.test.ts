import { describe, expect, it } from 'vitest'

import {
  componentExports,
  defaultRepositoryCeiling,
  documentNodeKinds,
  instanceLimits,
  isMutation,
  packageContract,
  repositoryBudgets,
  requiredRights,
  sdkVersion,
  validateCatalogueIndex,
  validateConnectorManifest,
  validatePluginManifest,
  validatePresentationManifest,
  witVersion
} from '../src/index.js'
import { fixtureNames, readJson, readJsonIfPresent } from './fixtures.js'

describe('the package contract', () => {
  it('carries the section 11 execution limits as exact decimal strings', () => {
    expect(instanceLimits.memory_bytes).toBe('67108864')
    expect(instanceLimits.observation_deadline_ms).toBe('10')
    expect(instanceLimits.interpretation_deadline_ms).toBe('50')
    expect(instanceLimits.snapshot_deadline_ms).toBe('100')
    expect(instanceLimits.output_bytes_per_call).toBe('1048576')
    expect(instanceLimits.observation_queue_bytes).toBe('4194304')
    expect(instanceLimits.faults_before_disable).toBe(3)
    expect(repositoryBudgets.metadata_bytes).toBe('67108864')
    expect(repositoryBudgets.metadata_entries).toBe('100000')
    expect(repositoryBudgets.payload_cache_bytes).toBe('1073741824')
    expect(BigInt(instanceLimits.memory_bytes)).toBe(64n * 1024n * 1024n)
  })

  it('names the eight component exports and the four host imports', () => {
    expect(componentExports).toEqual([
      'bind',
      'observe',
      'snapshot',
      'prepare-action',
      'decode-request',
      'encode-response',
      'checkpoint',
      'restore'
    ])
    expect(packageContract.wit_package.imports.map((entry) => entry.interface)).toEqual([
      'source-events',
      'upstream',
      'attachments',
      'document'
    ])
    expect(sdkVersion).toBe('0.1.0')
    expect(witVersion).toBe('0.1.0')
  })

  it('holds the thirteen document node kinds', () => {
    expect(documentNodeKinds).toHaveLength(13)
    expect(documentNodeKinds).toContain('approval_ref')
    expect(documentNodeKinds).not.toContain('html')
  })

  it('permits only metadata, presentation and authorised events by default', () => {
    expect(defaultRepositoryCeiling).toEqual([
      'metadata.match',
      'presentation.declarative',
      'broker.semantic_events'
    ])
  })

  it('resolves each effect class to the rights the broker intersects', () => {
    expect(requiredRights('terminal.input')).toEqual(['terminal.input'])
    expect(requiredRights('observe')).toEqual(['session.view'])
    expect(isMutation('observe')).toBe(false)
    expect(isMutation('terminal.input')).toBe(true)
  })

  it('treats an effect class it does not know as a mutation', () => {
    expect(requiredRights('shell.exec')).toBeUndefined()
    expect(isMutation('shell.exec')).toBe(true)
  })
})

describe('manifest validation', () => {
  it('accepts every valid fixture package', () => {
    const names = fixtureNames('valid')
    expect(names.length).toBeGreaterThan(0)
    for (const name of names) {
      const manifest = validatePluginManifest(readJson('valid', name, 'plugin.json'))
      expect(manifest.ok ? [] : manifest.problems).toEqual([])

      const presentation = validatePresentationManifest(
        readJson('valid', name, 'presentation.json')
      )
      expect(presentation.ok ? [] : presentation.problems).toEqual([])

      const connector = readJsonIfPresent('valid', name, 'connector.json')
      if (connector !== undefined) {
        const checked = validateConnectorManifest(connector)
        expect(checked.ok ? [] : checked.problems).toEqual([])
      }
    }
  })

  it('rejects the manifest defects the invalid fixtures carry', () => {
    const rejected = ['unsafe-extraction-path', 'unknown-effect-class', 'unbounded-sdk-range']
    for (const name of rejected) {
      const manifest = readJson('invalid', name, 'package', 'plugin.json')
      const result = validatePluginManifest(manifest)
      if (name === 'unbounded-sdk-range') {
        // A wildcard range is a well-formed string; the host rejects it, not the schema.
        expect(result.ok).toBe(true)
      } else {
        expect(result.ok).toBe(false)
      }
    }
  })

  it('rejects a count no host would accept', () => {
    const manifest = readJson('valid', 'example-declarative', 'plugin.json') as Record<
      string,
      unknown
    >
    // 2^32 is one past what a uint32 holds. The schema says uint32 through a format, and the
    // loader teaches the validator what that format means.
    const overflowed = JSON.parse(JSON.stringify(manifest)) as Record<string, unknown>
    ;(overflowed as { manifest_version: number }).manifest_version = 4294967296
    expect(validatePluginManifest(overflowed).ok).toBe(false)
  })

  it('rejects a counter past the 64-bit range', () => {
    const presentation = readJson('valid', 'example-declarative', 'presentation.json') as {
      nodes: Array<{ body: Record<string, unknown> }>
    }
    const progress = presentation.nodes.find((node) => node.body.kind === 'progress')
    expect(progress).toBeDefined()
    if (!progress) return
    progress.body.state = { kind: 'determinate', completed: '0', total: '18446744073709551616' }
    expect(validatePresentationManifest(presentation).ok).toBe(false)

    progress.body.state = { kind: 'determinate', completed: '0', total: '18446744073709551615' }
    expect(validatePresentationManifest(presentation).ok).toBe(true)
  })

  it('keeps a 64-bit byte count exact', () => {
    const manifest = readJson('valid', 'example-connector', 'plugin.json') as {
      payloads: Array<{ size_bytes: string }>
    }
    for (const payload of manifest.payloads) {
      expect(typeof payload.size_bytes).toBe('string')
      expect(BigInt(payload.size_bytes) > 0n).toBe(true)
    }
  })

  it('reports where a document breaks the schema', () => {
    const manifest = readJson('valid', 'example-declarative', 'plugin.json') as Record<
      string,
      unknown
    >
    const result = validatePluginManifest({ ...manifest, escalate: true })
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.problems.length).toBeGreaterThan(0)
      expect(result.problems[0]?.message).toBeTruthy()
    }
  })

  it('rejects a catalogue index that is not one', () => {
    expect(validateCatalogueIndex({ index_version: 1 }).ok).toBe(false)
  })
})
