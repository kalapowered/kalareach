import { describe, expect, it } from 'vitest'

import { MAX_INLINE_PROMPT_BYTES, assertPromptText, promptTextProblem } from '../src/agent.js'

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
