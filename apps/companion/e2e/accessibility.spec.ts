/**
 * What assistive technology finds on the phone's screens, in both engines the page runs in.
 *
 * The role and name locators and the accessibility snapshot are computed from the page by the test
 * runner, the same way in each engine; the browser's own tree is read as well where the engine
 * offers it.
 */

import { Buffer } from 'node:buffer'

import { expect, test, type Page } from '@playwright/test'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** Opens the phone's session on `surface`, on a screen the size of a current phone's. */
async function openSession(page: Page, surface: 'ios' | 'android'): Promise<void> {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(`/harness.html?surface=${surface}&session=${SESSION}`)
  await expect(page.getByRole('group', { name: 'Add an attachment' })).toBeVisible()
}

// KR-REQ-13.19, KR-REQ-13.17: each of the three ways to attach is one control to assistive
// technology, named for what it does and with the role of a button. The file input under it is not
// a second control: it is out of the accessibility tree and out of the focus order, and the control
// still opens the platform's picker with a touch, with Enter and with Space.
test.describe('the attachment controls', () => {
  const NAMES = ['Take a photo', 'Photo library', 'Files'] as const

  for (const surface of ['ios', 'android'] as const) {
    test(`are one named button each in the accessibility tree on ${surface}`, async ({ page }) => {
      await openSession(page, surface)
      const group = page.getByRole('group', { name: 'Add an attachment' })
      expect(await group.ariaSnapshot()).toBe(
        [
          '- group "Add an attachment":',
          '  - button "Take a photo"',
          '  - button "Photo library"',
          '  - button "Files"'
        ].join('\n')
      )
      for (const name of NAMES) {
        await expect(page.getByRole('button', { name, exact: true })).toHaveCount(1)
      }
      // The three inputs are still in the page, so the platform can open its pickers from them.
      const inputs = page.locator('input[type="file"]')
      await expect(inputs).toHaveCount(3)
      for (const input of await inputs.all()) await expect(input).toBeHidden()
    })

    test(`leave the file inputs out of the browser's own accessibility tree on ${surface}`, async ({
      page,
      browserName
    }) => {
      test.skip(browserName !== 'chromium', 'only this engine hands the page its own tree')
      await openSession(page, surface)
      const session = await page.context().newCDPSession(page)
      const { nodes } = (await session.send('Accessibility.getFullAXTree')) as {
        nodes: {
          ignored?: boolean
          role?: { value: string }
          name?: { value: string }
          backendDOMNodeId?: number
        }[]
      }
      // What each of the page's file inputs is, in that tree: no node, or one it ignores.
      const shown: string[] = []
      for (const node of nodes) {
        if (node.ignored === true || node.backendDOMNodeId === undefined) continue
        const described = await session.send('DOM.describeNode', { backendNodeId: node.backendDOMNodeId })
        const element = described.node
        if (element.nodeName === 'INPUT' && element.attributes?.includes('file')) {
          shown.push(`${node.role?.value ?? '?'} ${node.name?.value ?? ''}`.trim())
        }
      }
      expect(shown, 'file inputs the browser lists as controls').toEqual([])
      const buttons = nodes.filter(
        (node) =>
          node.ignored !== true &&
          node.role?.value === 'button' &&
          (NAMES as readonly string[]).includes(node.name?.value ?? '')
      )
      expect(buttons.map((node) => node.name?.value).sort()).toEqual([...NAMES].sort())
    })

    test(`keep the file inputs out of the focus order and open the picker from each control on ${surface}`, async ({
      page
    }) => {
      await openSession(page, surface)
      // An input the page hides cannot take the focus, so it is no stop for a keyboard or a switch.
      for (const input of await page.locator('input[type="file"]').all()) {
        expect(await input.evaluate((element) => {
          element.focus()
          return document.activeElement === element
        }), 'a file input that takes the focus').toBe(false)
      }

      // The platform's picker, each way a control is used: a touch or click, Enter and Space.
      for (const [name, accept, capture, multiple] of [
        ['Take a photo', 'image/*', 'environment', false],
        ['Photo library', 'image/*,video/*', null, true],
        ['Files', '*/*', null, true]
      ] as const) {
        const control = page.getByRole('button', { name, exact: true })
        for (const press of ['click', 'Enter', 'Space'] as const) {
          const opened = page.waitForEvent('filechooser')
          if (press === 'click') await control.click()
          else {
            await control.focus()
            await page.keyboard.press(press === 'Space' ? ' ' : press)
          }
          const chooser = await opened
          expect(chooser.isMultiple(), `${name} by ${press}: more than one file`).toBe(multiple)
          const input = chooser.element()
          expect(await input.getAttribute('accept'), `${name}: what it accepts`).toBe(accept)
          expect(await input.getAttribute('capture'), `${name}: the camera`).toBe(capture)
        }
      }
    })
  }

  test('hand the picked file to the draft', async ({ page }) => {
    await openSession(page, 'ios')
    const opened = page.waitForEvent('filechooser')
    await page.getByRole('button', { name: 'Files', exact: true }).click()
    const chooser = await opened
    await chooser.setFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('a picked file') })
    await expect(page.getByTestId('draft-attachments')).toContainText('notes.txt')
  })
})
