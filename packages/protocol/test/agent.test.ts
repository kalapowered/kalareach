import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import { MAX_INLINE_PROMPT_BYTES, assertPromptText, promptTextProblem } from '../src/agent.js'
import type { PluginActionInvokeParams } from '../src/index.js'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

describe('prompt text', () => {
  it('bounds the text in bytes rather than characters', () => {
    expect(promptTextProblem('hello')).toBeUndefined()
    expect(promptTextProblem('')).toBe('empty')
    expect(promptTextProblem('a'.repeat(MAX_INLINE_PROMPT_BYTES))).toBeUndefined()
    expect(promptTextProblem('a'.repeat(MAX_INLINE_PROMPT_BYTES + 1))).toBe('too-long')
  })

  it('refuses what the generated schema would admit', () => {
    // Two bytes per character: half the characters, the same bytes. `maxLength` counts characters
    // and would admit twice this; the contract counts bytes and does not.
    const atTheBound = 'é'.repeat(MAX_INLINE_PROMPT_BYTES / 2)
    expect(new TextEncoder().encode(atTheBound).length).toBe(MAX_INLINE_PROMPT_BYTES)
    expect(atTheBound.length).toBe(MAX_INLINE_PROMPT_BYTES / 2)
    expect(promptTextProblem(atTheBound)).toBeUndefined()
    expect(promptTextProblem(`${atTheBound}é`)).toBe('too-long')
  })

  it('says what is wrong when it throws', () => {
    expect(() => assertPromptText('hello')).not.toThrow()
    expect(() => assertPromptText('')).toThrow(RangeError)
    expect(() => assertPromptText('a'.repeat(MAX_INLINE_PROMPT_BYTES + 1))).toThrow(
      /65536 bytes of UTF-8/,
    )
  })
})

describe('plugin action call', () => {
  // KR-REQ-12.18: a plugin action call names the pending resource it answers, or null. The member
  // is required, so a call that says nothing about it does not type-check and the schema refuses
  // it, rather than reading as a call that answers nothing.
  it('always says which pending resource it answers', () => {
    const answering: PluginActionInvokeParams = {
      target: {
        subject: {
          session_id: '01010101-0101-0101-0101-010101010101',
          application_instance_id: '02020202-0202-0202-0202-020202020202'
        },
        binding_revision: '7'
      },
      plugin_id: 'kalareach/claude-code',
      action: 'approval.answer',
      draft_id: null,
      resource_id: '09090909-0909-0909-0909-090909090909',
      parameters: 'eyJkZWNpc2lvbiI6ImFsbG93In0'
    }
    const answeringNothing: PluginActionInvokeParams = { ...answering, resource_id: null }
    expect(answeringNothing.resource_id).toBeNull()
    const { resource_id: _omitted, ...withoutResource } = answering
    // @ts-expect-error the resource is always stated, as null when the action answers nothing
    const silent: PluginActionInvokeParams = withoutResource
    expect(silent).not.toHaveProperty('resource_id')

    const schema = JSON.parse(
      readFileSync(join(packageRoot, 'schema', 'kalareach-protocol.schema.json'), 'utf8')
    ) as {
      $defs: Record<string, { required?: string[]; properties?: Record<string, { anyOf?: unknown[] }> }>
    }
    const params = schema.$defs.PluginActionInvokeParams
    expect(params?.required).toContain('resource_id')
    expect(params?.properties?.resource_id?.anyOf).toEqual([
      { $ref: '#/$defs/PendingResourceId' },
      { type: 'null' }
    ])
  })
})
