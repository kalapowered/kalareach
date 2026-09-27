/**
 * Retained output, read a page at a time: the text it printed, and a window that moves both ways
 * within its bound.
 */

import { describe, expect, it } from 'vitest'

import {
  atEnd,
  atOldest,
  emptyOutput,
  OutputReader,
  placed,
  textOfPages,
  withNewer,
  withOlder,
  type OutputPage
} from '../src/model/output'

const bytes = (text: string) => new TextEncoder().encode(text)

function page(from: number, text: string | Uint8Array): OutputPage {
  const content = typeof text === 'string' ? bytes(text) : text
  return { from: String(from), next: String(from + content.length), bytes: content }
}

describe('reading retained output as the text it printed (KR-REQ-13.15)', () => {
  it('keeps text, tabs and line ends, and leaves out what a terminal would act on', () => {
    const reader = new OutputReader()
    const read = reader.read(
      bytes(
        '\u001b]0;kalareach — zsh\u0007$ cargo test\r\ntest one ... \u001b[32mok\u001b[0m\r\n\ttabbed\u0007\u0008\r\n'
      )
    )
    expect(read).toBe('$ cargo test\ntest one ... ok\n\ttabbed\n')
  })

  it('leaves out a clipboard write and a device control string, however they end', () => {
    const reader = new OutputReader()
    expect(reader.read(bytes('a\u001b]52;c;c2VjcmV0\u001b\\b\u001bPq#0;2;0;0;0\u001b\\c'))).toBe('abc')
  })

  it('reads a line written over itself as each version of it', () => {
    const reader = new OutputReader()
    expect(reader.read(bytes('10%\r\u001b[K20%\r\u001b[Kdone\r\n'))).toBe('10%\n20%\ndone\n')
  })

  it('finishes a character and an escape sequence a page boundary cut in two', () => {
    const whole = bytes('é \u001b[31mred\u001b[0m\r\n')
    const reader = new OutputReader()
    // é is two bytes; the colour sequence is cut after its bracket; the line end after its return.
    const cuts = [1, 5, whole.length - 1]
    let read = ''
    let at = 0
    for (const cut of [...cuts, whole.length]) {
      read += reader.read(whole.subarray(at, cut))
      at = cut
    }
    expect(read).toBe('é red\n')
  })

  it('leaves out the bytes of a character the window begins partway through', () => {
    const encoded = bytes('éa')
    const [text] = textOfPages([page(10, encoded.subarray(1))])
    expect(text).toBe('a')
  })
})

describe('the window over retained output (KR-REQ-13.15)', () => {
  const answer = { oldest: '100', end: '400', gap: null }

  it('moves towards newer and older output, and only to the next page along', () => {
    let window = withNewer(emptyOutput(), page(200, 'b'.repeat(100)), answer)
    window = withOlder(window, page(100, 'a'.repeat(100)), answer)
    expect(window.pages.map((each) => each.from)).toEqual(['100', '200'])
    expect(atOldest(window)).toBe(true)
    // A page that does not end where the first begins is not the next one along.
    expect(withOlder(window, page(0, 'x'.repeat(50)), answer)).toBe(window)
    window = withNewer(window, page(300, 'c'.repeat(100)), answer)
    expect(atEnd(window)).toBe(true)
    expect(withNewer(window, page(450, 'd'), answer)).toBe(window)
  })

  it('lets pages go from the far end to stay inside its bound', () => {
    let window = withNewer(emptyOutput(), page(100, 'a'.repeat(100)), answer, 250)
    window = withNewer(window, page(200, 'b'.repeat(100)), answer, 250)
    window = withNewer(window, page(300, 'c'.repeat(100)), answer, 250)
    expect(window.pages.map((each) => each.from)).toEqual(['200', '300'])
    // Going back, the newest page goes, so the reader there is no longer at the live end.
    window = withOlder(window, page(100, 'a'.repeat(100)), answer, 250)
    expect(window.pages.map((each) => each.from)).toEqual(['100', '200'])
    expect(window.following).toBe(false)
  })

  it('keeps what the host said it no longer keeps, and where the output ends', () => {
    const gap = { from_cursor: '0', to_cursor: '100', cause: 'retention' as const }
    const window = withOlder(
      withNewer(emptyOutput(), page(100, 'a'), { oldest: '100', end: '101', gap: null }),
      page(100, ''),
      { oldest: '100', gap }
    )
    expect(window.gap).toEqual(gap)
    expect(window.end).toBe('101')
  })

  it('starts again where the host now begins when it let go of what came after the window', () => {
    let window = withNewer(emptyOutput(), page(100, 'a'.repeat(100)), answer)
    window = placed(window, false, { from: '100', offset: 4 })
    const gap = { from_cursor: '200', to_cursor: '260', cause: 'retention' as const }
    const again = withNewer(window, page(260, 'c'.repeat(40)), { oldest: '260', end: '300', gap })
    expect(again.pages.map((each) => each.from)).toEqual(['260'])
    expect(again.gap).toEqual(gap)
    expect(again.anchor).toBeNull()
    // Without the host saying why, a page from elsewhere is not the next one along.
    expect(withNewer(window, page(260, 'c'), { oldest: '100', end: '300', gap: null })).toBe(window)
  })

  it('is at the live end when it holds nothing and the host has said where the output ends', () => {
    expect(atEnd(emptyOutput())).toBe(false)
    expect(atEnd({ ...emptyOutput(), end: '300' })).toBe(true)
  })

  it('records where the reader is, and nothing at the live end', () => {
    const window = withNewer(emptyOutput(), page(100, 'a'), answer)
    expect(placed(window, false, { from: '100', offset: 12 }).anchor).toEqual({ from: '100', offset: 12 })
    expect(placed(window, true, { from: '100', offset: 12 }).anchor).toBeNull()
  })
})
