/**
 * A sentence that holds technical words, as its pieces in order: plain text, and the words that the
 * page draws as technical words (an address, an identifier, a host name). A model that says such a
 * sentence returns this, so that what it says stays in one place and the page decides how a word is
 * drawn. Joined, the pieces are the sentence.
 */

export interface Technical {
  readonly technical: string
}

export type Wording = ReadonlyArray<string | Technical>

/** A technical word inside a sentence. */
export function technical(text: string): Technical {
  return { technical: text }
}

/** The sentence as plain text, as a person reads it aloud or copies it. */
export function wordingText(wording: Wording): string {
  return wording.map((piece) => (typeof piece === 'string' ? piece : piece.technical)).join('')
}
