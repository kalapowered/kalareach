/**
 * The bundle the desktop window actually loads.
 *
 * Every other test drives the harness bundle, whose entry substitutes a scripted host. That covers
 * the interface and covers nothing about the entry the shell ships: its imports, its port, and
 * whether the application mounts at all. A window that comes up empty is the one failure a person
 * cannot work around, so this loads `dist` in a browser engine with the desktop bridge stubbed at
 * the boundary and asks for the first screen.
 */

import { expect, test } from '@playwright/test'

/** Where the production bundle is served for this run. */
const BUNDLE = 'http://localhost:4189/'

/**
 * The bridge the shell injects, reduced to what the page may use.
 *
 * The page reaches the backend through `invoke` and through events, and nothing else, so a stub of
 * those two is the whole boundary. It answers the connection query and refuses the rest the way a
 * host does, which is the state the window has to render on a machine with nothing running.
 */
function bridge(): void {
  const refusal = {
    code: 'RESOURCE_UNAVAILABLE',
    message: 'no host on this machine',
    user_action: 'retry'
  }
  let nextListener = 0
  // Removing a listener goes through the event plugin's own internals before it reaches a command,
  // so a stub without them turns an ordinary unmount into a type error.
  Object.defineProperty(window, '__TAURI_EVENT_PLUGIN_INTERNALS__', {
    value: { unregisterListener: () => undefined },
    configurable: true
  })
  Object.defineProperty(window, '__TAURI_INTERNALS__', {
    value: {
      metadata: {
        currentWindow: { label: 'main' },
        currentWebview: { label: 'main' }
      },
      plugins: {},
      transformCallback(callback: (payload: unknown) => void) {
        const id = Math.floor(Math.random() * 1_000_000_000)
        Object.defineProperty(window, `_${id}`, { value: callback, configurable: true })
        return id
      },
      invoke(command: string) {
        // Each listener gets its own identifier, because two listeners that share one are one
        // listener as far as removing them is concerned.
        if (command === 'plugin:event|listen') return Promise.resolve(++nextListener)
        if (command === 'plugin:event|unlisten') return Promise.resolve(null)
        if (command === 'connection_state') {
          return Promise.resolve({
            connected: false,
            environment_id: null,
            reason: 'no host on this machine'
          })
        }
        // A refusal arrives from the shell as the value the backend serialised, not as an Error,
        // and the page reads it by its shape. Rejecting with anything else would test a boundary
        // the application does not have.
        // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
        return Promise.reject(refusal)
      }
    },
    configurable: true
  })
}

test.describe('the bundle the desktop window loads', () => {
  test('mounts, shows the first screen, and raises nothing uncaught', async ({ page }) => {
    const uncaught: string[] = []
    page.on('pageerror', (error) => uncaught.push(error.message))

    await page.addInitScript(bridge)
    await page.goto(BUNDLE)

    await expect(page.getByRole('heading', { name: 'What needs you' })).toBeVisible()
    // The host is not there, and the window says so in its own words.
    await expect(page.getByText('no host on this machine').first()).toBeVisible()

    // A second screen renders for the first time here, and the first one renders again. The
    // subscription is the shell's and outlives both, so this is not a test of releasing one: it is
    // the shipped entry being asked for something other than the screen it opens on.
    const sessions = page.getByRole('button', { name: 'Sessions' })
    await sessions.click()
    await expect(sessions).toHaveAttribute('aria-current', 'page')
    const attention = page.getByRole('button', { name: 'Attention' })
    await attention.click()
    await expect(page.getByRole('heading', { name: 'What needs you' })).toBeVisible()

    expect(uncaught).toEqual([])
  })

  test('shows one product mark, and the one the mode calls for', async ({ page }) => {
    await page.addInitScript(bridge)
    await page.goto(BUNDLE)

    const marks = page.locator('.brand img')
    await expect(marks).toHaveCount(2)
    await expect(marks.filter({ visible: true })).toHaveCount(1)

    await page.emulateMedia({ colorScheme: 'dark' })
    await expect(page.locator('.mark-dark')).toBeVisible()
    await expect(page.locator('.mark-light')).toBeHidden()

    await page.emulateMedia({ colorScheme: 'light' })
    await expect(page.locator('.mark-light')).toBeVisible()
    await expect(page.locator('.mark-dark')).toBeHidden()
  })
})
