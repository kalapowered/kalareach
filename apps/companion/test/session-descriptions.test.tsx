/**
 * Session descriptions on the session rows.
 *
 * The rows show what the host says each session is called and doing, and say where it came from:
 * a title the host made from the session's metadata carries no label, a pinned name says so, and a
 * line a local model wrote is labelled generated and says when the session has moved on since. A
 * row the host has not answered yet shows what every host knows, the directory the session is in.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
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

  // The host is asked about few sessions at a time and each once, however long it takes to answer:
  // a round of reads that is not done is not started again, and a slow answer is shown when it comes.
  it('asks about at most four sessions at once and none twice across rounds, and shows an answer that is slow', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const { port, controls } = describedHost()
    controls.addSessions(8)
    const held = controls.hold('sessionDescribe')
    open(port, { view: 'sessions' })
    await waitFor(() => {
      expect(held.count).toBe(4)
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(95_000)
    })
    expect(held.count, 'no read begun beside the four on their way').toBe(4)
    expect(controls.described.length).toBe(new Set(controls.described).size)

    held.release()
    const row = await screen.findByTestId('session-row-1')
    await waitFor(() => {
      expect(within(row).getByRole('heading', { level: 3 })).toHaveTextContent('KalaReach pairing')
    })
    await waitFor(() => {
      expect(controls.described.length, 'every session, in the first round').toBe(11)
    })
    expect(controls.described.length).toBe(new Set(controls.described).size)
  })

  // One read the host never answers holds back its own row and no other: the rounds go on, and a
  // line that has aged beside it is shown as aged.
  it('goes on reading the other rows when the host never answers one', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const { port, controls } = describedHost()
    const held = controls.hold('sessionDescribe')
    open(port, { view: 'sessions' })
    await waitFor(() => {
      expect(held.count).toBe(3)
    })
    // The first session's read is never answered; the other two are.
    held.answer(1)
    held.answer(2)
    controls.describe(SESSION_BUILD, {
      title: 'Web release',
      source: 'generated',
      activity_text: 'Runs the website checks',
      freshness: 'stale'
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(31_000)
    })
    await waitFor(() => {
      expect(held.count, 'the next round asked about the two that answered, and not the third').toBe(5)
    })
    held.answer(3)
    held.answer(4)
    await waitFor(() => {
      expect(
        within(screen.getByTestId('session-row-2')).getByTestId('description-freshness')
      ).toHaveTextContent('Out of date')
    })

    // And the round after that one, with the first read still unanswered.
    controls.describe(SESSION_BUILD, { freshness: 'delayed' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(31_000)
    })
    await waitFor(() => {
      expect(held.count, 'a third round, with the first session still unanswered').toBe(7)
    })
    held.answer(5)
    held.answer(6)
    await waitFor(() => {
      expect(
        within(screen.getByTestId('session-row-2')).getByTestId('description-freshness')
      ).toHaveTextContent('A newer description is waiting')
    })
  })

  // A page that is hidden, as a minimised window is, starts no read, and the reads that were
  // waiting start when it is shown again.
  it('starts no read while the page is hidden and the waiting ones when it is shown', async () => {
    const visibility = vi.spyOn(document, 'visibilityState', 'get')
    visibility.mockReturnValue('visible')
    const { port, controls } = describedHost()
    controls.addSessions(8)
    const held = controls.hold('sessionDescribe')
    open(port, { view: 'sessions' })
    await waitFor(() => {
      expect(held.count).toBe(4)
    })
    visibility.mockReturnValue('hidden')
    held.release()
    await act(async () => {
      await new Promise((resolve) => {
        setTimeout(resolve, 50)
      })
    })
    expect(controls.described.length, 'no read begun while hidden').toBe(4)

    visibility.mockReturnValue('visible')
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
    // Shown again, the rows that were waiting are read, and the rows already read are read again,
    // as a page shown again reads what may have changed while it was away.
    await waitFor(() => {
      expect(new Set(controls.described).size).toBe(11)
    })
    visibility.mockRestore()
  })

  // A search keeps the row a person is on, even when a fresh answer from the host no longer matches.
  it('keeps the row a person is on in the results of a search when the host’s words about it change', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const person = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    const { port, controls } = describedHost()
    open(port, { view: 'sessions' })
    await waitFor(() => {
      expect(
        within(screen.getByTestId('session-row-1')).getByTestId('description-activity')
      ).toBeInTheDocument()
    })
    await person.type(screen.getByRole('searchbox'), 'host approval')
    const row = screen.getByTestId('session-row-1')
    expect(screen.queryByTestId('session-row-2')).toBeNull()
    act(() => {
      row.focus()
    })
    expect(row).toHaveFocus()

    controls.describe(SESSION_MAIN, { title: 'Release notes', activity_text: 'Edits the changelog' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(31_000)
    })
    await waitFor(() => {
      expect(within(row).getByRole('heading', { level: 3 })).toHaveTextContent('Release notes')
    })
    expect(row, 'the row stays and keeps focus').toBeInTheDocument()
    expect(row).toHaveFocus()
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

// KR-REQ-13.10: the session's own screen names it as the list does.
describe("the session's header names the session as the list does", () => {
  it("shows the generated title with its label, and the pinned name with its own", async () => {
    const { port } = describedHost()
    open(port, { view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const header = await screen.findByRole('heading', { level: 1 })
    await waitFor(() => {
      expect(header).toHaveTextContent('KalaReach pairing')
    })
    expect(within(header).getByTestId('description-source')).toHaveTextContent('Generated')
    cleanup()

    open(port, { view: 'session', sessionId: SESSION_OFFLINE, pane: 'semantic' })
    const pinned = await screen.findByRole('heading', { level: 1 })
    await waitFor(() => {
      expect(pinned).toHaveTextContent('Release 1.0')
    })
    expect(within(pinned).getByTestId('description-source')).toHaveTextContent('Pinned')
  })

  it("shows the directory until the host has answered, and for a session the host only knows by its metadata", async () => {
    const { port, controls } = describedHost()
    const held = controls.hold('sessionDescribe')
    open(port, { view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    const header = await screen.findByRole('heading', { level: 1 })
    await waitFor(() => {
      expect(header).toHaveTextContent('kalareach')
    })
    expect(within(header).queryByTestId('description-source')).toBeNull()
    await act(async () => {
      held.release()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    await waitFor(() => {
      expect(header).toHaveTextContent('KalaReach pairing')
    })
    cleanup()

    // The title the host made from the session's metadata carries no label.
    open(port, { view: 'session', sessionId: SESSION_BUILD, pane: 'semantic' })
    const metadata = await screen.findByRole('heading', { level: 1 })
    await waitFor(() => {
      expect(metadata).toHaveTextContent('kalareach-web')
    })
    expect(within(metadata).queryByTestId('description-source')).toBeNull()
  })
})
