/**
 * Session descriptions on the session rows.
 *
 * The rows show what the host says each session is called and doing, and say where it came from:
 * a title the host made from the session's metadata carries no label, a pinned name says so, and a
 * line a local model wrote is labelled generated and says when the session has moved on since. A
 * row the host has not answered yet shows what every host knows, the directory the session is in.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { MobileSessions } from '../src/mobile/views/Places'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
const SESSION_OFFLINE = '8a7b6c50-22bb-4c3d-8e4f-000000000103'

function open(port: HostPort, initialPlace: Place): void {
  render(
    <AppProvider port={port} initialPlace={initialPlace}>
      <App />
    </AppProvider>
  )
}

/** The host says session 1 was described by a model, session 2 has its metadata title, session 3 is pinned. */
function describedHost() {
  const host = fakeHost()
  host.controls.describe(SESSION_MAIN, {
    title: 'KalaReach pairing',
    source: 'generated',
    activity_text: 'Checks the code-entry flow and host approval screen',
    freshness: 'current'
  })
  host.controls.describe(SESSION_OFFLINE, { title: 'Release 1.0', source: 'pinned' })
  return host
}

afterEach(() => {
  vi.useRealTimers()
})

// KR-REQ-13.10: a session row shows the description the host gives it.
describe("the desktop session list shows each session's description", () => {
  it('shows a generated title labelled, its activity, and a metadata title with no label', async () => {
    const { port } = describedHost()
    open(port, { view: 'sessions' })

    const generated = await screen.findByTestId('session-row-1')
    await waitFor(() => {
      expect(within(generated).getByRole('heading', { level: 3 })).toHaveTextContent(
        'KalaReach pairing'
      )
    })
    expect(within(generated).getByTestId('description-source')).toHaveTextContent('Generated')
    expect(within(generated).getByTestId('description-activity')).toHaveTextContent(
      'Checks the code-entry flow and host approval screen'
    )
    expect(within(generated).queryByTestId('description-freshness')).toBeNull()

    // Session 2 has only the title the host made from its directory: no label, no activity line.
    const metadata = screen.getByTestId('session-row-2')
    expect(within(metadata).getByRole('heading', { level: 3 })).toHaveTextContent('kalareach-web')
    expect(within(metadata).queryByTestId('description-source')).toBeNull()
    expect(within(metadata).queryByTestId('description-activity')).toBeNull()

    // A pinned name is a person's, and says so.
    expect(
      within(await screen.findByTestId('session-row-3')).getByTestId('description-source')
    ).toHaveTextContent('Pinned')
  })

  it('says when a generated line is out of date or a newer one is waiting, and nothing when it is current', async () => {
    const { port, controls } = describedHost()
    controls.describe(SESSION_BUILD, {
      title: 'Web release',
      source: 'generated',
      activity_text: 'Runs the website checks',
      freshness: 'stale'
    })
    controls.describe(SESSION_MAIN, { freshness: 'delayed' })
    open(port, { view: 'sessions' })

    const delayed = await screen.findByTestId('session-row-1')
    await waitFor(() => {
      expect(within(delayed).getByTestId('description-freshness')).toHaveTextContent(
        'A newer description is waiting'
      )
    })
    expect(
      within(await screen.findByTestId('session-row-2')).getByTestId('description-freshness')
    ).toHaveTextContent('Out of date')
  })

  it('shows no line the host sent beside a title that is not generated', async () => {
    const { port, controls } = fakeHost()
    controls.describe(SESSION_MAIN, {
      title: 'Release 1.0',
      source: 'pinned',
      activity_text: 'Runs the website checks',
      freshness: 'current'
    })
    open(port, { view: 'sessions' })
    const row = await screen.findByTestId('session-row-1')
    await waitFor(() => {
      expect(within(row).getByRole('heading', { level: 3 })).toHaveTextContent('Release 1.0')
    })
    expect(within(row).queryByTestId('description-activity')).toBeNull()
  })

  it('shows the directory until the host has answered, and keeps it when the host refuses', async () => {
    const { port, controls } = describedHost()
    const held = controls.hold('sessionDescribe')
    open(port, { view: 'sessions' })
    const row = await screen.findByTestId('session-row-1')
    expect(within(row).getByRole('heading', { level: 3 })).toHaveTextContent('kalareach')
    expect(within(row).queryByTestId('description-source')).toBeNull()

    // The host answers the first read with a title; a later answer replaces nothing it refused.
    await act(async () => {
      held.release()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    await waitFor(() => {
      expect(within(row).getByRole('heading', { level: 3 })).toHaveTextContent('KalaReach pairing')
    })

    const refused = fakeHost()
    refused.controls.describe(SESSION_BUILD, { title: 'Web release', source: 'generated' })
    const failing: HostPort = {
      ...refused.port,
      sessionDescribe: () => Promise.reject(new Error('the host did not answer'))
    }
    document.body.replaceChildren()
    open(failing, { view: 'sessions' })
    const kept = await screen.findByTestId('session-row-2')
    await new Promise((resolve) => {
      setTimeout(resolve, 20)
    })
    expect(within(kept).getByRole('heading', { level: 3 })).toHaveTextContent('kalareach-web')
  })

  // Section 22: a description that has aged is shown as aged. A screen left open is read again at
  // the host's cooldown, so the note appears without the person leaving and coming back.
  it('reads a row again once the host’s cooldown has passed on a screen left open, and says when its line has aged', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const { port, controls } = describedHost()
    open(port, { view: 'sessions' })
    const row = await screen.findByTestId('session-row-1')
    await waitFor(() => {
      expect(within(row).getByTestId('description-activity')).toBeInTheDocument()
    })
    expect(within(row).queryByTestId('description-freshness')).toBeNull()

    controls.describe(SESSION_MAIN, { freshness: 'stale' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    await waitFor(() => {
      expect(within(row).getByTestId('description-freshness')).toHaveTextContent('Out of date')
    })
  })

  it('finds a session by the title the host gave it', async () => {
    const person = userEvent.setup()
    const { port } = describedHost()
    open(port, { view: 'sessions' })
    await waitFor(() => {
      expect(
        within(screen.getByTestId('session-row-1')).getByRole('heading', { level: 3 })
      ).toHaveTextContent('KalaReach pairing')
    })
    await person.type(screen.getByRole('searchbox'), 'pairing')
    expect(screen.getByTestId('session-row-1')).toBeInTheDocument()
    expect(screen.queryByTestId('session-row-2')).toBeNull()
  })

  it('reads one session at a time from the host, and asks for nothing else about it', async () => {
    const { port, controls } = describedHost()
    open(port, { view: 'sessions' })
    await waitFor(() => {
      expect([...controls.described].sort()).toEqual([SESSION_MAIN, SESSION_BUILD, SESSION_OFFLINE].sort())
    })
  })
})

describe("the phone's session list shows each session's description", () => {
  it('shows the host’s title, labelled where a model wrote it, and its activity', async () => {
    const { port, controls } = describedHost()
    controls.describe(SESSION_BUILD, {
      title: 'Web release',
      source: 'generated',
      activity_text: 'Runs the website checks',
      freshness: 'stale'
    })
    render(
      <AppProvider port={port}>
        <MobileSessions surface="ios" onOpen={() => undefined} />
      </AppProvider>
    )
    await waitFor(() => {
      expect(screen.getAllByTestId('description-title').map((row) => row.textContent?.trim())).toEqual([
        'KalaReach pairing Generated',
        'Web release Generated',
        'Release 1.0 Pinned'
      ])
    })
    expect(screen.getAllByTestId('description-activity')[0]).toHaveTextContent(
      'Checks the code-entry flow and host approval screen'
    )
    expect(screen.getByTestId('description-freshness')).toHaveTextContent('Out of date')
  })
})
