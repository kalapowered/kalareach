/**
 * What a click on plain text near a link does, over made rectangles and made records.
 *
 * `decide` never stops a click and never redirects one: its result is "stand" (the click goes where
 * the browser sent it) or "open this link" (the link also gets a click of its own). Each case below
 * is one condition of the rule, with every other condition held, so a case fails when its condition
 * is dropped.
 */

import { describe, expect, it } from 'vitest'

import { CLICK_WITHIN, decide, type Click, type Layout, type PaneLink, type Press, type Rect } from '../src/markdown/link-target'

/** Links are named by strings here: the decision only compares them. */
type Id = string

const PANE: Rect = { left: 0, top: 0, right: 390, bottom: 844 }
const IOS = { least: 44, beside: 22 }

function words(left: number, top: number, width: number, height = 17): Rect {
  return { left, top, right: left + width, bottom: top + height }
}

function link(id: Id, rect: Rect, destination = `https://example.org/${id}`): PaneLink<Id> {
  return { id, destination, words: [rect], box: [] }
}

/** Two links, one above the other, 40 px apart: the click's point decides between them. */
const UPPER = link('upper', words(16, 100, 120))
const LOWER = link('lower', words(16, 140, 120))

function layoutOf(...links: PaneLink<Id>[]): () => Layout<Id> {
  return () => ({ links, reach: IOS, bounds: PANE })
}

/** A press of a finger on the upper link that has ended 300 ms before the click. */
function press(over: Partial<Press<Id>> = {}): Press<Id> {
  return { pointerType: 'touch', moved: false, upAt: 1000, start: { link: 'upper', destination: UPPER.destination }, ...over }
}

/** A trusted click with a detail of 1 on plain text, 8 px under the upper link's words. */
function click(over: Partial<Click> = {}): Click {
  return { trusted: true, detail: 1, at: 1300, names: 'neither', point: { x: 60, y: 125 }, ...over }
}

const STAND = { kind: 'stand' }
const OPEN_UPPER = { kind: 'open', link: 'upper' }

describe('a click on plain text near the link a touch pressed', () => {
  it('opens that link', () => {
    expect(decide(press(), click(), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
  })

  it('opens it for a pen, as for a finger', () => {
    expect(decide(press({ pointerType: 'pen' }), click(), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
  })

  it('opens it at the least time and at the last time that a click may come after the pointer up', () => {
    expect(decide(press(), click({ at: 1000 }), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
    expect(decide(press(), click({ at: 1000 + CLICK_WITHIN }), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
  })
})

describe('a click that names a link or a control', () => {
  it('stands: the browser’s own hit test decides', () => {
    expect(decide(press(), click({ names: 'link' }), layoutOf(UPPER, LOWER))).toEqual(STAND)
    expect(decide(press(), click({ names: 'control' }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })
})

describe('a click that is not a trusted click of one tap', () => {
  it('stands when it is not the browser’s own', () => {
    expect(decide(press(), click({ trusted: false }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when its detail is 0, as a keyboard’s and a screen reader’s is', () => {
    expect(decide(press(), click({ detail: 0 }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when its detail is 2 or more, as the second tap of a double tap’s is', () => {
    expect(decide(press(), click({ detail: 2 }), layoutOf(UPPER, LOWER))).toEqual(STAND)
    expect(decide(press(), click({ detail: 3 }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })
})

describe('a click with no usable press before it', () => {
  it('stands when there is no record', () => {
    expect(decide(null, click(), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when the record is a mouse’s', () => {
    expect(decide(press({ pointerType: 'mouse' }), click(), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when the press moved beyond the slop', () => {
    expect(decide(press({ moved: true }), click(), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when the pointer has not come up', () => {
    expect(decide(press({ upAt: null }), click(), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when the click comes before the pointer up', () => {
    expect(decide(press(), click({ at: 999 }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when the click comes more than three seconds after the pointer up', () => {
    expect(decide(press(), click({ at: 1000 + CLICK_WITHIN + 1 }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when the press named no link at its start', () => {
    expect(decide(press({ start: null }), click(), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })
})

describe('the nearest-words rule at the click’s point', () => {
  it('stands when it names no link', () => {
    expect(decide(press(), click({ point: { x: 60, y: 400 } }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when it names another link than the press’s', () => {
    expect(decide(press(), click({ point: { x: 60, y: 150 } }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when the press’s link is no longer in the pane', () => {
    expect(decide(press(), click({ point: { x: 60, y: 125 } }), layoutOf(LOWER))).toEqual(STAND)
  })

  it('stands when the pane holds another link in the place of the press’s, as another element', () => {
    expect(decide(press(), click(), layoutOf(link('replacement', words(16, 100, 120), UPPER.destination), LOWER))).toEqual(STAND)
  })

  it('stands when the link’s destination changed during the press', () => {
    expect(decide(press(), click(), layoutOf(link('upper', words(16, 100, 120), 'https://example.org/elsewhere'), LOWER))).toEqual(STAND)
  })

  it('opens the link that has moved, where its words are still the nearest at the click’s point', () => {
    const moved = link('upper', words(16, 112, 120))
    expect(decide(press(), click(), layoutOf(moved, LOWER))).toEqual(OPEN_UPPER)
  })
})
