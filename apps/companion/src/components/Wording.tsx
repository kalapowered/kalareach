/**
 * A sentence that holds technical words, drawn with each word as a technical word and the rest as it
 * is written. See `model/wording.ts`.
 */

import { Fragment, type ReactNode } from 'react'

import type { Wording as WordingPieces } from '../model/wording'
import { TechnicalWord } from './TechnicalWord'

export function Wording({ of }: { readonly of: WordingPieces }): ReactNode {
  return of.map((piece, index) => (
    // The pieces are positions in one sentence, and never reorder.
    <Fragment key={index}>{typeof piece === 'string' ? piece : <TechnicalWord text={piece.technical} />}</Fragment>
  ))
}
