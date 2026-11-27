/**
 * A technical word is drawn with the characters it was given and nothing more.
 *
 * A place a line may end is a break element that a screen reader skips, so the text a person copies
 * and the text a screen reader reads are the source text, and the words of a command line keep the
 * spaces that separate them.
 */

import { render } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { TechnicalWord } from '../src/components/TechnicalWord'

describe('TechnicalWord', () => {
  it('draws each word whole, with a place to end a line between its parts, and the same characters', () => {
    const { container } = render(
      <p>
        Stock shell, <TechnicalWord text="/usr/local/bin/my-shell --login" />
      </p>
    )
    expect(container.textContent).toBe('Stock shell, /usr/local/bin/my-shell --login')
    // Two words, joined by the space they had; four places a line may end inside the first.
    expect(container.querySelectorAll('.technical-word')).toHaveLength(2)
    const places = Array.from(container.querySelectorAll('wbr'))
    expect(places).toHaveLength(4)
    // A place is hidden from a screen reader, which reads the words as they were.
    for (const place of places) expect(place.getAttribute('aria-hidden')).toBe('true')
    // The last hyphen of a run and the letter after it are one box that cannot end a line.
    expect(Array.from(container.querySelectorAll('.technical-head')).map((head) => head.textContent)).toEqual([
      '-s',
      '-l'
    ])
  })

  it('keeps the hyphens of a long run before its last one as text that can break', () => {
    const { container } = render(
      <p>
        <TechnicalWord text="a------b" />
      </p>
    )
    expect(container.textContent).toBe('a------b')
    expect(Array.from(container.querySelectorAll('.technical-head')).map((head) => head.textContent)).toEqual(['-b'])
  })

  it('draws a word with no separator as one box with no place to end a line', () => {
    const { container } = render(
      <p>
        <TechnicalWord text="companion" />
      </p>
    )
    expect(container.textContent).toBe('companion')
    expect(container.querySelectorAll('wbr')).toHaveLength(0)
  })

  it('draws nothing for no text', () => {
    const { container } = render(
      <p>
        <TechnicalWord text="" />
      </p>
    )
    expect(container.textContent).toBe('')
    expect(container.querySelectorAll('.technical-word')).toHaveLength(0)
  })
})
