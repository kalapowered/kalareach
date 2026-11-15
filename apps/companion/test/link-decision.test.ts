/**
 * What a click on plain text near a link does, over made rectangles and made records.
 *
 * `decide` never stops a click and never redirects one: its result is "stand" (the click goes where
 * the browser sent it) or "open this link" (the link also gets a click of its own). Each case below
 * is one condition of the rule, with every other condition held, so a case fails when its condition
 * is dropped.
 */

import { describe, expect, it } from 'vitest'

import { CLICK_AWAY, decide, keepsPress, lookAt, type Click, type Decision, type Layout, type NamedLink, type PaneLink, type Press, type Rect } from '../src/markdown/link-target'

/** Links are named by strings here: the decision only compares them. */
type Id = string

const PANE: Rect = { left: 0, top: 0, right: 390, bottom: 844 }
const IOS = { least: 44, beside: 22 }

function words(left: number, top: number, width: number, height = 17): Rect {
  return { left, top, right: left + width, bottom: top + height }
}

function link(id: Id, rect: Rect, destination = `https://example.org/${id}`): PaneLink<Id> {
  return { id, destination, words: [rect], view: PANE }
}

/** Two links, one above the other, 40 px apart: the press's point decides between them. */
const UPPER = link('upper', words(16, 100, 120))
const LOWER = link('lower', words(16, 140, 120))

function layoutOf(...links: PaneLink<Id>[]): () => Layout<Id> {
  return () => ({ links, reach: IOS })
}

/** A press of a finger 8 px under the upper link's words that has ended 300 ms before the click. */
function press(over: Partial<Press<Id>> = {}): Press<Id> {
  return { pointerType: 'touch', at: { x: 60, y: 125 }, moved: false, upAt: 1000, start: { link: 'upper', destination: UPPER.destination }, ...over }
}

/** A trusted click with a detail of 1 on plain text, 8 px under the upper link's words. */
function click(over: Partial<Click> = {}): Click {
  return { trusted: true, detail: 1, at: 1300, names: 'neither', point: { x: 60, y: 125 }, ...over }
}

const STAND = { kind: 'stand' } as const
const OPEN_UPPER = { kind: 'open', link: 'upper' }

describe('a click on plain text near the link a touch pressed', () => {
  it('opens that link', () => {
    expect(decide(press(), click(), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
  })

  it('opens the link that the press named, whichever place it has among the links', () => {
    const second = press({ at: { x: 60, y: 150 }, start: { link: 'lower', destination: LOWER.destination } })
    expect(decide(second, click({ point: { x: 60, y: 150 } }), layoutOf(UPPER, LOWER))).toEqual({ kind: 'open', link: 'lower' })
  })

  it('opens it for a pen, as for a finger', () => {
    expect(decide(press({ pointerType: 'pen' }), click(), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
  })

  it('opens it at the least time and at the last time that a click may come after the pointer up', () => {
    expect(decide(press(), click({ at: 1000 }), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
    expect(decide(press(), click({ at: 4000 }), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
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
    expect(decide(press(), click({ at: 4001 }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when the press named no link at its start', () => {
    expect(decide(press({ start: null }), click(), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })
})

describe('the nearest-words rule at the press’s point, run again at the click', () => {
  it('stands when it names no link there now', () => {
    expect(decide(press({ at: { x: 60, y: 400 } }), click({ point: { x: 60, y: 400 } }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when it names another link than the press’s there now', () => {
    expect(decide(press({ at: { x: 60, y: 150 } }), click({ point: { x: 60, y: 150 } }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('stands when the press’s link is no longer in the pane', () => {
    expect(decide(press(), click(), layoutOf(LOWER))).toEqual(STAND)
  })

  it('stands when the pane holds another link in the place of the press’s, as another element', () => {
    expect(decide(press(), click(), layoutOf(link('replacement', words(16, 100, 120), UPPER.destination), LOWER))).toEqual(STAND)
  })

  it('stands when the link’s destination changed during the press', () => {
    expect(decide(press(), click(), layoutOf(link('upper', words(16, 100, 120), 'https://example.org/elsewhere'), LOWER))).toEqual(STAND)
  })

  it('opens the link that has moved, where its words are still the nearest at the press’s point', () => {
    const moved = link('upper', words(16, 112, 120))
    expect(decide(press(), click(), layoutOf(moved, LOWER))).toEqual(OPEN_UPPER)
  })

  it('stands when the pane scrolled between the press and the click so that the link’s words are out of view', () => {
    // The pane's view now starts 40 px below the link's words: a link out of view never opens.
    const scrolled = () => ({ links: [{ ...UPPER, view: { left: 0, top: 140, right: 390, bottom: 984 } }], reach: IOS })
    expect(decide(press({ at: { x: 60, y: 145 } }), click({ point: { x: 60, y: 145 } }), scrolled)).toEqual(STAND)
  })

  it('stands when an arriving message moved the link away from the press’s point', () => {
    const moved = link('upper', words(16, 180, 120))
    expect(decide(press(), click(), layoutOf(moved, LOWER))).toEqual(STAND)
  })

  it('reads the layout at the press’s point', () => {
    const at: { x: number; y: number }[] = []
    decide(press(), click({ point: { x: 64, y: 130 } }), (point) => {
      at.push(point)
      return { links: [UPPER, LOWER], reach: IOS }
    })
    expect(at).toEqual([{ x: 60, y: 125 }])
  })
})

describe('what keeps a press', () => {
  it('is nothing for a press that lit no link', () => {
    expect(keepsPress(press({ start: null }), layoutOf(UPPER))).toBe(false)
  })
})

describe('where the click lies against the press', () => {
  it('allows the finger’s 10 px and an engine’s adjustment of up to 22.6 px more, and no farther: 32 px opens, 33 px stands', () => {
    expect(decide(press(), click({ point: { x: 60 + 32, y: 125 } }), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
    expect(decide(press(), click({ point: { x: 60 + 33, y: 125 } }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })

  it('opens the link at the edge of its area, where the engine reports the click a pixel off the point that lit it', () => {
    // The upper link's area ends 22 px under its words' middle (y 108.5): 130.5. The press was at 130.5, the click is reported at 131.
    expect(decide(press({ at: { x: 60, y: 130.5 } }), click({ point: { x: 60, y: 131 } }), layoutOf(UPPER))).toEqual(OPEN_UPPER)
  })

  it('opens it for a click at the allowed distance from the press, and stands for a click farther', () => {
    expect(decide(press(), click({ point: { x: 60 + CLICK_AWAY, y: 125 } }), layoutOf(UPPER, LOWER))).toEqual(OPEN_UPPER)
    expect(decide(press(), click({ point: { x: 60 + CLICK_AWAY + 0.5, y: 125 } }), layoutOf(UPPER, LOWER))).toEqual(STAND)
  })
})

/** The link a click names, as the handler measures it. */
const NAMED: NamedLink<Id> = { id: 'lower', measurable: true }

/** What `decide` says of a click at `names`, held to the layout of the two links. */
function decision(names: Click['names'], over: Partial<Click> = {}, record: Press<Id> | null = press()): Decision<Id> {
  return decide(record, click({ names, ...over }), layoutOf(UPPER, LOWER))
}

describe('the link that has the look at a click', () => {
  it('is the link that the click names, for a touch and for a pen', () => {
    expect(lookAt('touch', click({ names: 'link' }), NAMED, decision('link'))).toBe('lower')
    expect(lookAt('pen', click({ names: 'link' }), NAMED, decision('link'))).toBe('lower')
  })

  it('is the link that the click names whatever the handler’s own tests of the click say: a detail of 2, a late click, a press that moved, no press at all', () => {
    const two = click({ names: 'link', detail: 2 })
    expect(decision('link', { detail: 2 })).toEqual(STAND)
    expect(lookAt('touch', two, NAMED, decision('link', { detail: 2 }))).toBe('lower')
    const late = click({ names: 'link', at: 1000 + 3200 })
    expect(lookAt('touch', late, NAMED, decision('link', { at: 1000 + 3200 }))).toBe('lower')
    const far = click({ names: 'link', point: { x: 60 + CLICK_AWAY + 40, y: 125 } })
    expect(lookAt('touch', far, NAMED, decision('link', { point: far.point }))).toBe('lower')
    expect(lookAt('touch', click({ names: 'link' }), NAMED, decision('link', {}, press({ moved: true })))).toBe('lower')
    expect(lookAt('touch', click({ names: 'link' }), NAMED, decision('link', {}, null))).toBe('lower')
  })

  it('is the link that the handler opens from plain text, and none where the handler stands', () => {
    expect(lookAt('touch', click(), null, decision('neither'))).toBe('upper')
    expect(lookAt('pen', click(), null, decision('neither'))).toBe('upper')
    expect(decision('neither', { at: 1000 + 3200 })).toEqual(STAND)
    expect(lookAt('touch', click({ at: 1000 + 3200 }), null, decision('neither', { at: 1000 + 3200 }))).toBeNull()
    expect(lookAt('touch', click({ detail: 2 }), null, decision('neither', { detail: 2 }))).toBeNull()
    expect(lookAt('touch', click(), null, decision('neither', {}, press({ moved: true })))).toBeNull()
    expect(lookAt('touch', click(), null, decision('neither', {}, null))).toBeNull()
  })

  it('is none for a click that names a control, which opens no link', () => {
    expect(lookAt('touch', click({ names: 'control' }), null, decision('control'))).toBeNull()
  })

  it('is none where the last press was a mouse’s or where no press in the pane came before the click', () => {
    expect(lookAt('mouse', click({ names: 'link' }), NAMED, decision('link'))).toBeNull()
    expect(lookAt('mouse', click(), null, STAND)).toBeNull()
    expect(lookAt(null, click({ names: 'link' }), NAMED, decision('link'))).toBeNull()
    expect(lookAt('', click({ names: 'link' }), NAMED, decision('link'))).toBeNull()
  })

  it('is none for a click with a detail of 0, which nothing pressed, and for an untrusted click', () => {
    expect(lookAt('touch', click({ names: 'link', detail: 0 }), NAMED, decision('link', { detail: 0 }))).toBeNull()
    expect(lookAt('touch', click({ names: 'link', trusted: false }), NAMED, decision('link', { trusted: false }))).toBeNull()
    expect(lookAt('touch', click({ trusted: false }), null, decision('neither', { trusted: false }))).toBeNull()
  })

  it('is none for a link that cannot be measured, as at the press', () => {
    expect(lookAt('touch', click({ names: 'link' }), { id: 'lower', measurable: false }, decision('link'))).toBeNull()
  })

  it('is none for a click that names a link the handler has no name for', () => {
    expect(lookAt('touch', click({ names: 'link' }), null, decision('link'))).toBeNull()
  })
})
