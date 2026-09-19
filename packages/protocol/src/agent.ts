/**
 * Bounds a client has to enforce before it sends an agent mutation.
 *
 * The normative limits are the Rust types', and every host decoder applies them. A client that
 * sends an over-long prompt therefore gets a refusal rather than a truncation, which is correct
 * and unhelpful: the schema's own `maxLength` counts Unicode characters, and the contract counts
 * UTF-8 bytes, so the schema admits values the host refuses. These are those checks, so a client
 * can tell a person before the request leaves.
 */

/** Maximum bytes of UTF-8 that prompt or steering text may carry inline. */
export const MAX_INLINE_PROMPT_BYTES = 65536

/** Why one piece of prompt text is not one this host will accept. */
export type PromptTextProblem = 'empty' | 'too-long'

/**
 * Returns what is wrong with prompt or steering text, or `undefined` when nothing is.
 *
 * The length is measured in UTF-8 bytes, which is what the contract bounds. A string of 40,000
 * accented characters satisfies the generated schema's `maxLength` of 65536 and is 80,000 bytes,
 * and this is what says so.
 */
export function promptTextProblem(text: string): PromptTextProblem | undefined {
  if (text.length === 0) {
    return 'empty'
  }
  if (new TextEncoder().encode(text).length > MAX_INLINE_PROMPT_BYTES) {
    return 'too-long'
  }
  return undefined
}

/**
 * Throws when prompt or steering text is not one this host will accept.
 *
 * @throws {RangeError} when the text is empty or longer than {@link MAX_INLINE_PROMPT_BYTES}
 * bytes of UTF-8.
 */
export function assertPromptText(text: string): void {
  const problem = promptTextProblem(text)
  if (problem === 'empty') {
    throw new RangeError('prompt text is at least one byte')
  }
  if (problem === 'too-long') {
    throw new RangeError(
      `prompt text is at most ${MAX_INLINE_PROMPT_BYTES} bytes of UTF-8; longer content belongs in a draft`,
    )
  }
}
