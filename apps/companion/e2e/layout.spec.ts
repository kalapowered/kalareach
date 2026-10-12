/**
 * The measure of text that runs out of its box, on pages made for it.
 *
 * Every case that uses the measure carries a control that keeps its text from wrapping. These say,
 * on small pages with one fault each, what the measure reports and what it does not, so that the
 * controls mean what they claim.
 */

import { expect, test } from '@playwright/test'

import { overrunning } from './layout'

test.describe('the measure of text that runs out of its box', () => {
  test.use({ viewport: { width: 800, height: 600 } })

  test('reports a line that runs out of its root and stays on the screen', async ({ page }) => {
    await page.setContent(
      '<div id="card" style="width:100px"><button style="white-space:nowrap">a-label-that-is-longer-than-the-card</button></div>'
    )
    const found = await overrunning(page, '#card')
    expect(found.some((each) => each.endsWith('past its box'))).toBe(true)
  })

  test('reports a line that runs out of the button that holds it inside a root that is wide enough', async ({
    page
  }) => {
    await page.setContent(
      '<div id="card" style="width:600px"><button style="width:60px;white-space:nowrap;overflow:visible">a-label-that-is-longer-than-the-button</button></div>'
    )
    const found = await overrunning(page, '#card')
    expect(found.some((each) => each.endsWith('past the box that holds it'))).toBe(true)
    expect(found.some((each) => each.endsWith('past its box'))).toBe(false)
  })

  test('reports a line that runs past the screen', async ({ page }) => {
    await page.setContent('<div id="card"><p style="white-space:nowrap">' + 'word '.repeat(300) + '</p></div>')
    expect((await overrunning(page, '#card')).some((each) => each.endsWith('past the screen'))).toBe(true)
  })

  test('reports text that a box clips sideways while it scrolls only vertically', async ({ page }) => {
    // Words that cannot wrap are cut off by the box: nothing scrolls there, so they are not drawn
    // where a person can reach them.
    await page.setContent(
      '<div id="card" style="width:600px"><span style="display:block;width:80px;max-height:60px;overflow-x:hidden;overflow-y:auto;white-space:nowrap">a-label-that-is-longer-than-the-box</span></div>'
    )
    expect((await overrunning(page, '#card')).length).toBeGreaterThan(0)
  })

  test('reports a box drawn past its root inside a box that sets only its vertical overflow', async ({ page }) => {
    // Setting only the vertical overflow makes the horizontal one auto as well, but the box has
    // nothing to scroll across: what lies past its root is not drawn where it can be reached. The
    // positioned box adds nothing to what the scroller could scroll, so only a measure that asks
    // whether it really scrolls sideways sees it.
    await page.setContent(
      '<div id="card" style="width:300px"><div style="max-height:60px;overflow-y:auto"><span style="position:absolute;left:500px;top:0;width:50px;height:20px">x</span></div></div>'
    )
    expect((await overrunning(page, '#card')).some((each) => each.endsWith('past its box'))).toBe(true)
  })

  test('reports a line a button cuts off inside a row that really scrolls sideways', async ({ page }) => {
    // The row is meant to run on past its edge, but a button in it still has to hold its own label.
    await page.setContent(
      '<div id="card" style="width:200px"><div style="display:flex;gap:8px;overflow-x:auto"><button style="flex:none;width:60px;white-space:nowrap;overflow:visible">a-label-that-is-longer-than-the-button</button><span style="flex:none;width:400px">a wide chip</span></div></div>'
    )
    const found = await overrunning(page, '#card')
    expect(found.some((each) => each.endsWith('past the box that holds it'))).toBe(true)
    expect(found.some((each) => each.endsWith('past its box') || each.endsWith('past the screen'))).toBe(false)
  })

  test('reports nothing for text that wraps inside its card, for text kept for a screen reader, or for text scrolled inside a scroller', async ({
    page
  }) => {
    await page.setContent(
      `<div id="card" style="width:100px">
         <p>${'a-long-word-that-breaks-'.repeat(6)}</p>
         <span style="position:absolute;width:1px;height:1px;margin:-1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap">${'hidden '.repeat(40)}</span>
         <div style="overflow-x:auto;width:100px"><span style="white-space:nowrap">${'scrolled '.repeat(20)}</span></div>
       </div>`
    )
    // The long word is allowed to break anywhere, as the product's text does.
    await page.addStyleTag({ content: '#card p { overflow-wrap: anywhere }' })
    expect(await overrunning(page, '#card')).toEqual([])
  })
})
