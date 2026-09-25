/**
 * Each screen shows its newest read, and nothing a read answers after the screen moved on.
 *
 * A screen that reads again, on a retry, a refresh or an action, can have two reads on their way at
 * once, and they answer in whatever order the host answers them. The one that answers last is not
 * the newer: a screen shows the answer of the newest read it started, and nothing a read answers
 * for a session the screen has left.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost, type HeldReads } from '../src/host/fake'
import type { HostPort } from '../src/host/port'

function open(port: HostPort, initialPlace: Place): void {
  render(
    <AppProvider port={port} initialPlace={initialPlace}>
      <App />
    </AppProvider>
  )
}

/**
 * Answers the held read at `index`, and lets everything that answer sets off run: whatever the
 * screen does with it has been done when this returns.
 */
async function answer(held: HeldReads, index: number): Promise<void> {
  await act(async () => {
    held.answer(index)
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
  })
}

/** Waits until `count` reads of a kind have been made. */
async function made(held: HeldReads, count: number): Promise<void> {
  await waitFor(() => {
    expect(held.count).toBe(count)
  })
}

describe('the attention inbox shows its newest read', () => {
  const shows = (kind: string) => document.querySelector(`[data-testid="attention-${kind}"]`) !== null

  it('keeps the newer inbox when two reads answer in reverse order', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = controls.hold('attentionRead')
    open(port, { view: 'attention' })
    await made(held, 1)
    await answer(held, 0)
    expect(shows('failed_action')).toBe(true)

    // Each decision reads the inbox again. Between the two, another device clears the failure.
    const allow = () =>
      within(screen.getByTestId('attention-pending_decision')).getByRole('button', { name: 'Allow' })
    await person.click(allow())
    await made(held, 2)
    await act(async () => {
      await port.attentionAcknowledge({ attention_id: 'a-2' }, {})
    })
    await person.click(allow())
    await made(held, 3)

    await answer(held, 2)
    expect(shows('failed_action')).toBe(false)
    await answer(held, 1)
    expect(shows('failed_action')).toBe(false)
  })

  it('lets a retry give way to a later one', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = controls.hold('attentionRead')
    controls.setConnected(false)
    open(port, { view: 'attention' })
    await made(held, 1)
    await answer(held, 0)
    const again = () => screen.getByRole('button', { name: 'Try again' })

    act(() => {
      controls.setConnected(true)
    })
    await person.click(again())
    await made(held, 2)
    await act(async () => {
      await port.attentionAcknowledge({ attention_id: 'a-2' }, {})
    })
    await person.click(again())
    await made(held, 3)

    await answer(held, 2)
    await answer(held, 1)
    expect(shows('pending_decision')).toBe(true)
    expect(shows('failed_action')).toBe(false)
    expect(screen.queryByText('This list could not be read')).toBeNull()
  })

  it('shows the inbox it read when nothing changed in between', async () => {
    const { port } = fakeHost()
    open(port, { view: 'attention' })
    await waitFor(() => {
      expect(shows('failed_action')).toBe(true)
    })
    expect(shows('pending_decision')).toBe(true)
  })
})

describe('change sets and retained artefacts show their newest read', () => {
  const shows = (id: string) => screen.queryByTestId(`delete-${id}`) !== null

  it('keeps the newer artefacts when two reads answer in reverse order', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = controls.hold('storageStatus')
    open(port, { view: 'changesets' })
    await made(held, 1)
    await answer(held, 0)
    expect(shows('obj-2')).toBe(true)

    // Each deletion reads the list again.
    await person.click(screen.getByTestId('delete-obj-1'))
    await made(held, 2)
    await person.click(screen.getByTestId('delete-obj-2'))
    await made(held, 3)

    await answer(held, 2)
    expect(shows('obj-2')).toBe(false)
    await answer(held, 1)
    expect(shows('obj-2')).toBe(false)
    expect(shows('obj-1')).toBe(false)
  })

  it('lets a retry give way to a later one', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = controls.hold('storageStatus')
    controls.setConnected(false)
    open(port, { view: 'changesets' })
    await screen.findByText('This could not be read')
    const again = () => screen.getByRole('button', { name: 'Try again' })

    act(() => {
      controls.setConnected(true)
    })
    const before = held.count
    await person.click(again())
    await made(held, before + 1)
    await act(async () => {
      await port.storageObjectDelete({ object_id: 'obj-2' }, {})
    })
    await person.click(again())
    await made(held, before + 2)

    await answer(held, before + 1)
    await answer(held, before)
    expect(shows('obj-1')).toBe(true)
    expect(shows('obj-2')).toBe(false)
    expect(screen.queryByText('This could not be read')).toBeNull()
  })

  it('shows what it read when nothing changed in between', async () => {
    const { port } = fakeHost()
    open(port, { view: 'changesets' })
    await waitFor(() => {
      expect(shows('obj-2')).toBe(true)
    })
  })
})

describe('the hosts show their newest read', () => {
  it('keeps the newer answer when two reads answer in reverse order', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const info = controls.hold('hostInfo')
    const list = controls.hold('environmentList')
    open(port, { view: 'hosts' })
    await made(info, 1)

    act(() => {
      controls.setConnected(false)
    })
    await person.click(screen.getByRole('button', { name: 'Refresh' }))
    await made(info, 2)

    await answer(info, 1)
    await answer(list, 1)
    expect(screen.getByText('Disconnected', { selector: '.banner strong' })).toBeInTheDocument()
    await answer(info, 0)
    await answer(list, 0)
    expect(screen.getByText('Disconnected', { selector: '.banner strong' })).toBeInTheDocument()
    expect(screen.queryAllByText('studio · macOS')).toEqual([])
  })

  it('lets a refresh give way to a later one', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const info = controls.hold('hostInfo')
    const list = controls.hold('environmentList')
    controls.setConnected(false)
    open(port, { view: 'hosts' })
    await made(info, 1)
    await answer(info, 0)
    await answer(list, 0)

    await person.click(screen.getByRole('button', { name: 'Refresh' }))
    await made(info, 2)
    act(() => {
      controls.setConnected(true)
    })
    await person.click(screen.getByRole('button', { name: 'Refresh' }))
    await made(info, 3)

    await answer(info, 2)
    await answer(list, 2)
    await answer(info, 1)
    await answer(list, 1)
    expect(screen.getAllByText('studio · macOS').length).toBeGreaterThan(0)
    expect(screen.queryByText('Disconnected', { selector: '.banner strong' })).toBeNull()
  })

  it('shows what it read when nothing changed in between', async () => {
    const { port } = fakeHost()
    open(port, { view: 'hosts' })
    expect((await screen.findAllByText('studio · macOS')).length).toBeGreaterThan(0)
  })
})

describe('the session list shows its newest read', () => {
  it('lets a retry give way to a later one', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = controls.hold('sessionList')
    controls.setConnected(false)
    open(port, { view: 'sessions' })
    await made(held, 1)
    await answer(held, 0)
    const again = () => screen.getByRole('button', { name: 'Try again' })

    act(() => {
      controls.setConnected(true)
    })
    await person.click(again())
    await made(held, 2)
    act(() => {
      controls.setConnected(false)
    })
    await person.click(again())
    await made(held, 3)

    await answer(held, 2)
    await answer(held, 1)
    expect(screen.getByText('This host is not answering')).toBeInTheDocument()
    expect(screen.queryByTestId('session-row-1')).toBeNull()
  })

  it('shows what it read when nothing changed in between', async () => {
    const { port } = fakeHost()
    open(port, { view: 'sessions' })
    expect(await screen.findByTestId('session-row-1')).toBeInTheDocument()
  })
})

describe('the packages show their newest read', () => {
  it('lets a retry give way to a later one', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = controls.hold('pluginList')
    controls.setConnected(false)
    open(port, { view: 'plugins' })
    await made(held, 1)
    await answer(held, 0)
    const again = () => screen.getByRole('button', { name: 'Try again' })

    act(() => {
      controls.setConnected(true)
    })
    await person.click(again())
    await made(held, 2)
    act(() => {
      controls.setConnected(false)
    })
    await person.click(again())
    await made(held, 3)

    await answer(held, 2)
    await answer(held, 1)
    expect(screen.getByText('This host is not answering')).toBeInTheDocument()
    expect(screen.queryAllByText('Codex presentation')).toEqual([])
  })

  it('shows what it read when nothing changed in between', async () => {
    const { port } = fakeHost()
    open(port, { view: 'plugins' })
    expect((await screen.findAllByText('Codex presentation')).length).toBeGreaterThan(0)
  })
})

describe('the raw terminal shows its newest read, and only for its own session', () => {
  const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  /** Where the view says its window is. */
  const position = () => screen.getByText(/^(At the live end\.|Showing history from row)/).textContent

  /** One turn of the wheel over the terminal, in view mode. */
  function wheel(deltaY: number): void {
    act(() => {
      screen
        .getByTestId('terminal-surface')
        .dispatchEvent(new WheelEvent('wheel', { deltaY, bubbles: true, cancelable: true }))
    })
  }

  it('keeps the newer window when two reads answer in reverse order', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = controls.hold('terminalProjection')
    open(port, { view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' })
    await made(held, 1)
    await answer(held, 0)
    expect(position()).toBe('At the live end.')

    // Each move of the window reads the screen again.
    await person.click(screen.getByRole('tab', { name: 'View' }))
    wheel(120)
    await made(held, 2)
    wheel(240)
    await made(held, 3)

    await answer(held, 2)
    expect(position()).toContain('from row 86')
    await answer(held, 1)
    expect(position()).toContain('from row 86')
  })

  it('shows nothing a read answers for a session it has left', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, { view: 'sessions' })
    await person.click(await screen.findByTestId('session-row-1'))
    await screen.findByText('Session 1 · Waiting for you')
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-2'))
    await screen.findByText('Session 2 · Working')

    const held = controls.hold('terminalProjection')
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await made(held, 1)
    await person.click(screen.getByRole('tab', { name: 'Session 01' }))
    await made(held, 2)

    await answer(held, 1)
    expect(screen.getByText('80×8')).toBeInTheDocument()
    // Session 2's screen answers after the view has moved to session 1.
    await answer(held, 0)
    expect(screen.getByText('80×8')).toBeInTheDocument()
    expect(screen.queryByText('100×4')).toBeNull()
  })

  it('claims no size, palette or window before its first answer', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('terminalProjection')
    open(port, { view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' })
    await made(held, 1)

    expect(screen.queryByTestId('palette-provenance')).toBeNull()
    expect(screen.queryByText(/^\d+×\d+$/)).toBeNull()
    expect(screen.queryByText(/^(At the live end\.|Showing history from row)/)).toBeNull()
  })

  it('shows the screen it read when nothing changed in between', async () => {
    const { port } = fakeHost()
    open(port, { view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' })
    expect(await screen.findByText('80×8')).toBeInTheDocument()
    expect(position()).toBe('At the live end.')
  })
})
