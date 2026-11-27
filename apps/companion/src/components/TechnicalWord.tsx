/**
 * Technical words, drawn so that they break where a person would break them.
 *
 * An application identifier, a path, a command's option, a host name: the engine ends a line in the
 * middle of such a word, after `com.kala` and before `reach`. Here each word, a run of text between
 * spaces, is one box that stays on a line while it fits there. When it does not, it breaks at its
 * separators first (see `breakParts`), and inside a part only when that one part alone is wider than
 * the line, where the page's last rule, that a word may break anywhere, takes over. Nothing is cut
 * off. Spaces are left as they are, so a command line breaks between its words as it always did.
 *
 * What a person copies and what a screen reader reads is the source text. A place a line may end is
 * a `<wbr>` element, which adds no character; it is hidden from a screen reader because a visible
 * one makes Chromium's accessibility tree put a space at it in the name of the heading or the button
 * that holds the word. The last hyphen of a run and the letter after it are one box that cannot end
 * a line, so that the engine's own break after a hyphen does not open between the hyphens and the
 * option's name. The hyphens before it are text like any other: a run wider than its line breaks
 * inside, as the last step, and nothing is cut off.
 */

import { Fragment, type ReactNode } from 'react'

import { breakParts } from '../model/technical-word'

/**
 * A part, with the last hyphen of each run and the character after it in a box that does not break.
 * The hyphens before it stay text, so that a run wider than its line still breaks, as the last step.
 */
function Hyphens({ part }: { readonly part: string }): ReactNode {
  // Splitting on a group keeps the heads, which sit at the odd places.
  return part.split(/(-[^-])/u).map((piece, index) =>
    index % 2 === 1 ? (
      // The pieces are positions in one part, and never reorder.
      <span key={index} className="technical-head">
        {piece}
      </span>
    ) : (
      piece
    )
  )
}

function Word({ word }: { readonly word: string }): ReactNode {
  return (
    <span className="technical-word">
      {breakParts(word).map((part, index) => (
        // The parts are positions in one word, and never reorder.
        <Fragment key={index}>
          {index > 0 ? <wbr aria-hidden="true" /> : null}
          <Hyphens part={part} />
        </Fragment>
      ))}
    </span>
  )
}

export function TechnicalWord({ text }: { readonly text: string }): ReactNode {
  // Splitting on a group keeps the spaces, which sit at the odd places.
  return text.split(/(\s+)/u).map((piece, index) =>
    index % 2 === 1 || piece === '' ? (
      piece
    ) : (
      // The words are positions in one text, and never reorder.
      <Word key={index} word={piece} />
    )
  )
}
