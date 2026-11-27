/**
 * What a slow try to reach the host changes, and what it leaves alone.
 *
 * The connection line says the app is still trying to reach the host while a try runs long. The
 * banners of a session screen say the contact is lost, the inbox counts the time, and a reader is
 * told a change once through the announcement scope. None of them reads the mark: each run below
 * drives the same outage with the mark and without it, and the screens and the announcements of the
 * two runs are the same.
 */

import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { MobileApp } from '../src/mobile/MobileApp'

import { addedTo, regionsOf, watched } from './live-regions'

const MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** What both session screens say when the connection is lost. */
const LOST = 'Not in contact with this host'

/** The last failure's words, and the words of a host that then refused. */
const UNREACHED = 'the host did not answer in time'
const REFUSED = 'the host refused the connection: PERMISSION_DENIED: this device is not paired'

/** What a run shows beside the connection line, step by step, and what it announced. */
interface Run {
  readonly screens: readonly string[]
  readonly heard: readonly string[]
}

/** The two shells, each with the part of the screen that is not the connection line. */
const SHELLS = {
  desktop: {
    open: (port: HostPort) =>
      render(
        <AppProvider port={port} initialPlace={{ view: 'session', sessionId: MAIN, pane: 'semantic' }}>
          <App />
        </AppProvider>
      ),
    line: () => document.querySelector('.topbar .connection'),
    beside: () => document.querySelector('main')?.textContent ?? '',
    live: 'Connected to this machine'
  },
  phone: {
    open: (port: HostPort) => {
      window.history.replaceState(null, '', `/?session=${MAIN}`)
      try {
        return render(
          <AppProvider port={port}>
            <MobileApp surface="ios" storage={null} />
          </AppProvider>
        )
      } finally {
        window.history.replaceState(null, '', '/')
      }
    },
    line: () => document.querySelector('.m-connection'),
    beside: () => document.querySelector('.m-main')?.textContent ?? '',
    live: 'In contact with this host'
  }
} as const

/**
 * One outage, as native code tells it: a loss, a try that goes slow and ends with the same words,
 * a try that goes slow and succeeds, and a try that goes slow and is refused. With `marked` the
 * mark is published and cleared at each slow try; without it nothing is.
 */
async function outage(shell: keyof typeof SHELLS, marked: boolean): Promise<Run> {
  const { port, controls } = fakeHost()
  const { open, line, beside, live } = SHELLS[shell]
  open(port)
  await waitFor(() => {
    expect(line()?.textContent).toBe(live)
  })
  await waitFor(() => {
    expect(beside().length).toBeGreaterThan(0)
  })
  const watching = watched(document.body)
  const screens: string[] = []
  const settle = async (): Promise<void> => {
    await act(async () => {
      await Promise.resolve()
    })
    screens.push(beside())
  }
  const slow = (): void => {
    if (marked) controls.setStillReaching('paired')
  }
  const over = (): void => {
    if (marked) controls.setStillReaching(null)
  }

  act(() => {
    controls.setConnected(false, UNREACHED)
  })
  await settle()
  act(slow)
  await settle()
  // The try ends with the same words.
  act(over)
  await settle()
  // The next try goes slow and works.
  act(slow)
  await settle()
  act(() => {
    over()
    controls.setConnected(true)
  })
  await settle()
  // A later one goes slow and is refused, in the host's words.
  act(() => {
    controls.setConnected(false, UNREACHED)
  })
  act(slow)
  await settle()
  act(() => {
    over()
    controls.setConnected(false, REFUSED)
  })
  await settle()

  const heard = regionsOf(document.body).flatMap((region) => addedTo(region, watching.records()))
  watching.stop()
  cleanup()
  return { screens, heard }
}

for (const shell of ['desktop', 'phone'] as const) {
  describe(`the ${shell}'s session screen, through an outage with slow tries`, () => {
    // A guard: the banners say the contact is lost, in the same words, with the mark and without.
    it('shows the same banners with the mark as without it', async () => {
      const plain = await outage(shell, false)
      const marked = await outage(shell, true)
      expect(marked.screens).toEqual(plain.screens)
      // The run did say that contact was lost and that it came back: the comparison has something to hold.
      expect(plain.screens[0]).toContain(LOST)
      expect(plain.screens[4]).not.toContain(LOST)
      expect(plain.screens.at(-1)).toContain(LOST)
      // The banners say it in their own words and never in the line's.
      for (const text of marked.screens) expect(text).not.toContain('still trying to reach')
    })

    // A guard: a reader hears what it heard without the mark, and no more.
    it('announces the same with the mark as without it', async () => {
      const plain = await outage(shell, false)
      const marked = await outage(shell, true)
      // The outage is told to a reader: the comparison has something to hold.
      expect(plain.heard.length).toBeGreaterThan(0)
      expect(marked.heard).toEqual(plain.heard)
    })

    // A guard: the line has no live region of its own and sits in none, so a reader meets it by
    // navigation and is not spoken to when it changes.
    it('keeps the connection line out of every live region while the mark shows', async () => {
      const { port, controls } = fakeHost()
      const { open, line, live } = SHELLS[shell]
      open(port)
      await waitFor(() => {
        expect(line()?.textContent).toBe(live)
      })
      act(() => {
        controls.setConnected(false, UNREACHED)
        controls.setStillReaching('paired')
      })
      await screen.findAllByText(LOST)
      const marked = line()
      expect(marked?.textContent).toContain('still trying to reach the host you chose')
      expect(marked?.closest('[aria-live], [role="status"], [role="alert"], [data-announcements]')).toBeNull()
      expect(marked?.querySelector('[aria-live], [role="status"], [role="alert"], [data-announcements]')).toBeNull()
      expect(marked?.hasAttribute('aria-live')).toBe(false)
      expect(marked?.hasAttribute('role')).toBe(false)
    })
  })
}
