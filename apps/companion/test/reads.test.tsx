/**
 * Each screen shows its newest read, and nothing a read answers after the screen moved on.
 *
 * A screen that reads again, on a retry, a refresh or an action, can have two reads on their way at
 * once, and they answer in whatever order the host answers them. The one that answers last is not
 * the newer: a screen shows the answer of the newest read it started, and nothing a read answers
 * for a session the screen has left.
 */

import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Terminal } from '@xterm/xterm'

import type { EnvironmentListResult, SessionListResult } from '@kalareach/protocol'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost, type HeldReads } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { MobileHosts, MobileSessions } from '../src/mobile/views/Places'
import { paint } from '../src/terminal/RawTerminal'

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

  /**
   * Opens session 2 and then session 1 in tabs, and shows session 1's conversation: the view the
   * person has in front of them when they change session in the same panel.
   */
  async function twoSessions(person: ReturnType<typeof userEvent.setup>): Promise<void> {
    await person.click(await screen.findByTestId('session-row-2'))
    await screen.findByText('Session 2 · Working')
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-1'))
    await screen.findByText('Session 1 · Waiting for you')
  }

  /** Everything a renderer holds, row by row, once everything written to it has been processed. */
  async function drawn(terminal: Terminal): Promise<string> {
    await new Promise<void>((resolve) => {
      terminal.write('', resolve)
    })
    const buffer = terminal.buffer.active
    const rows: string[] = []
    for (let row = 0; row < buffer.length; row += 1) {
      rows.push(buffer.getLine(row)?.translateToString(true) ?? '')
    }
    return rows.join('\n')
  }

  it('reads nothing for a session it has left when a window move answers late', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, { view: 'sessions' })
    await twoSessions(person)
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    expect(await screen.findByText('80×8')).toBeInTheDocument()
    await person.click(screen.getByRole('tab', { name: 'View' }))

    const moved = controls.hold('attachmentViewport')
    const reads = controls.hold('terminalProjection')
    wheel(120)
    await made(moved, 1)
    await person.click(screen.getByRole('tab', { name: 'Session 02' }))
    await made(reads, 1)

    // Session 1's window move answers after the view changed session, and session 2's read after it.
    await answer(moved, 0)
    await answer(reads, 0)
    expect(screen.getByTestId('terminal-size').textContent).toBe('100×4')
    expect(reads.count).toBe(1)
  })

  it('shows nothing it read before on a return to a session, until it has read it again', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, { view: 'sessions' })
    await twoSessions(person)
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    expect(await screen.findByText('80×8')).toBeInTheDocument()

    const reads = controls.hold('terminalProjection')
    await person.click(screen.getByRole('tab', { name: 'Session 02' }))
    await made(reads, 1)
    await person.click(screen.getByRole('tab', { name: 'Session 01' }))
    await made(reads, 2)
    expect(screen.queryByTestId('terminal-size')).toBeNull()
    expect(screen.queryByTestId('palette-provenance')).toBeNull()

    await answer(reads, 1)
    expect(screen.getByTestId('terminal-size').textContent).toBe('80×8')
  })

  /**
   * Holds what every renderer is given until the test lets it through, as a busy renderer does:
   * a renderer processes what it is written later than it is written. Returns the function that
   * lets everything held through, in the order it was written; a renderer the view has disposed
   * of by then takes nothing.
   */
  function holdRendering(): () => void {
    const waiting: {
      readonly terminal: Terminal
      readonly data: string | Uint8Array
      readonly callback?: () => void
    }[] = []
    const holding = vi
      .spyOn(Terminal.prototype, 'write')
      .mockImplementation(function (this: Terminal, data: string | Uint8Array, callback?: () => void) {
        waiting.push({ terminal: this, data, callback })
      })
    return () => {
      holding.mockRestore()
      for (const { terminal, data, callback } of waiting.splice(0)) {
        try {
          terminal.write(data, callback)
        } catch {
          // A disposed renderer refuses what it is given, which is what disposing of it is for.
        }
      }
    }
  }

  it('shows no failure from before on a return to a session, until it has read it again', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    let refusing = true
    open(
      {
        ...port,
        terminalProjection: (params) =>
          refusing && (params as { session_id?: string }).session_id === SESSION_MAIN
            ? Promise.reject({
                code: 'RESOURCE_UNAVAILABLE',
                message: 'The screen could not be read.',
                user_action: 'retry'
              })
            : port.terminalProjection(params)
      },
      { view: 'sessions' }
    )
    await twoSessions(person)
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    expect(await screen.findByText('The screen could not be read.')).toBeInTheDocument()

    refusing = false
    const reads = controls.hold('terminalProjection')
    await person.click(screen.getByRole('tab', { name: 'Session 02' }))
    await made(reads, 1)
    await person.click(screen.getByRole('tab', { name: 'Session 01' }))
    await made(reads, 2)
    expect(screen.queryByText('The screen could not be read.')).toBeNull()
  })

  it('draws nothing of a session it has left, however far its renderer had got', async () => {
    const person = userEvent.setup()
    const opened = vi.spyOn(Terminal.prototype, 'open')
    const { port, controls } = fakeHost()
    open(port, { view: 'sessions' })
    await twoSessions(person)

    const reads = controls.hold('terminalProjection')
    const release = holdRendering()
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await made(reads, 1)
    // Session 1's screen is painted, and the view changes session before the renderer has
    // processed any of it.
    await answer(reads, 0)
    act(() => {
      fireEvent.click(screen.getByRole('tab', { name: 'Session 02' }))
    })
    await made(reads, 2)
    release()

    // Session 2's screen has not been read, so the renderer in the view holds nothing at all.
    const showing = opened.mock.contexts.at(-1) as Terminal
    expect((await drawn(showing)).trim()).toBe('')
  })

  it('shows the screen it read when nothing changed in between', async () => {
    const { port } = fakeHost()
    open(port, { view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' })
    expect(await screen.findByText('80×8')).toBeInTheDocument()
    expect(position()).toBe('At the live end.')
  })
})

describe('painting a screen', () => {
  /** What a renderer holds once it has processed everything written to it. */
  async function held(terminal: Terminal): Promise<string[]> {
    await new Promise<void>((resolve) => {
      terminal.write('', resolve)
    })
    const buffer = terminal.buffer.active
    const rows: string[] = []
    for (let row = 0; row < buffer.length; row += 1) {
      const text = buffer.getLine(row)?.translateToString(true) ?? ''
      if (text.length > 0) rows.push(text)
    }
    return rows
  }

  it('replaces the screen it painted before, even one the renderer has not processed yet', async () => {
    const terminal = new Terminal({ scrollback: 0, allowProposedApi: true })
    paint(terminal, ['first screen, row 1', 'first screen, row 2'])
    paint(terminal, ['second screen'])
    expect(await held(terminal)).toEqual(['second screen'])
    terminal.dispose()
  })

  it('clears the renderer when there is nothing to paint', async () => {
    const terminal = new Terminal({ scrollback: 0, allowProposedApi: true })
    paint(terminal, ['a screen'])
    paint(terminal, [])
    expect(await held(terminal)).toEqual([])
    terminal.dispose()
  })
})

describe("the phone's lists show their newest read", () => {
  // A phone list reads once for each port it is given. A list given a new port reads again, and
  // the read through the port it replaced can still answer after that: the list shows the newer
  // read's answer or failure, and takes nothing in from a read that answers once it has gone.

  function sessionsThrough(port: HostPort): ReactNode {
    return (
      <AppProvider port={port}>
        <MobileSessions surface="ios" onOpen={() => undefined} />
      </AppProvider>
    )
  }

  function hostsThrough(port: HostPort): ReactNode {
    return (
      <AppProvider port={port}>
        <MobileHosts surface="android" />
      </AppProvider>
    )
  }

  /** The scripted host, whose session list answers only its first `count` sessions. */
  function firstSessions(port: HostPort, count: number): HostPort {
    return {
      ...port,
      sessionList: (params) =>
        port.sessionList(params).then((list) => ({ ...list, sessions: list.sessions.slice(0, count) }))
    }
  }

  /** The scripted host, whose environment list calls every environment `label`. */
  function labelled(port: HostPort, label: string): HostPort {
    return {
      ...port,
      environmentList: () =>
        port.environmentList().then((list) => ({
          environments: list.environments.map((each) => ({ ...each, label }))
        }))
    }
  }

  /** The titles of the rows the list shows, in order. */
  const titles = () =>
    Array.from(document.querySelectorAll('.m-row-title'), (title) => title.textContent)

  /**
   * A value that records whether anything read it. A promise asks what it settles with for `then`
   * before any handler runs, so that one question is not counted.
   */
  function watched<T extends object>(value: T): { readonly value: T; readonly read: () => boolean } {
    let read = false
    const recording = new Proxy(value, {
      get(target, key, receiver) {
        if (key !== 'then') read = true
        return Reflect.get(target, key, receiver) as unknown
      }
    })
    return { value: recording, read: () => read }
  }

  /** A read the test settles by hand, and whether the list has asked for it yet. */
  function settledByHand<T>(): {
    readonly read: () => Promise<T>
    readonly asked: () => boolean
    readonly resolve: (value: T) => void
    readonly reject: (failure: unknown) => void
  } {
    let resolve: ((value: T) => void) | null = null
    let reject: ((failure: unknown) => void) | null = null
    return {
      read: () =>
        new Promise<T>((settle, refuse) => {
          resolve = settle
          reject = refuse
        }),
      asked: () => resolve !== null,
      resolve: (value) => {
        resolve?.(value)
      },
      reject: (failure) => {
        reject?.(failure)
      }
    }
  }

  /** Lets everything a settled read sets off run. */
  async function settle(settling: () => void): Promise<void> {
    await act(async () => {
      settling()
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
  }

  it('keeps the newer session list when two reads answer in reverse order', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('sessionList')
    const { rerender } = render(sessionsThrough(firstSessions(port, 3)))
    await made(held, 1)
    rerender(sessionsThrough(firstSessions(port, 1)))
    await made(held, 2)

    await answer(held, 1)
    expect(titles()).toEqual(['Session 1'])
    await answer(held, 0)
    expect(titles()).toEqual(['Session 1'])
  })

  it('shows no failure of an older session read that answers after the newer list', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('sessionList')
    controls.setConnected(false)
    const { rerender } = render(sessionsThrough(port))
    await made(held, 1)
    act(() => {
      controls.setConnected(true)
    })
    rerender(sessionsThrough({ ...port }))
    await made(held, 2)

    await answer(held, 1)
    await answer(held, 0)
    expect(titles()).toEqual(['Session 1', 'Session 2', 'Session 3'])
    expect(screen.queryByText('The sessions could not be read')).toBeNull()
  })

  it('takes nothing in from a session read that answers after the list has gone', async () => {
    for (const ending of ['answer', 'failure'] as const) {
      const { port } = fakeHost()
      const late = settledByHand<SessionListResult>()
      const { unmount } = render(sessionsThrough({ ...port, sessionList: late.read }))
      await waitFor(() => {
        expect(late.asked()).toBe(true)
      })
      unmount()

      const answered = watched<SessionListResult>({ sessions: [] })
      const refused = watched({ code: 'RESOURCE_UNAVAILABLE', message: 'Gone.', user_action: 'retry' })
      await settle(() => {
        if (ending === 'answer') late.resolve(answered.value)
        else late.reject(refused.value)
      })
      expect(answered.read() || refused.read()).toBe(false)
    }
  })

  it('shows the sessions it read when nothing overtook the read', async () => {
    const { port } = fakeHost()
    render(sessionsThrough(port))
    await waitFor(() => {
      expect(titles()).toEqual(['Session 1', 'Session 2', 'Session 3'])
    })
    expect(screen.getByText('Live · 2 views attached')).toBeInTheDocument()
  })

  it('keeps the newer host list when two reads answer in reverse order', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('environmentList')
    const { rerender } = render(hostsThrough(labelled(port, 'studio before')))
    await made(held, 1)
    rerender(hostsThrough(labelled(port, 'studio after')))
    await made(held, 2)

    await answer(held, 1)
    expect(titles()).toEqual(['studio after'])
    await answer(held, 0)
    expect(titles()).toEqual(['studio after'])
  })

  it('shows no failure of an older host read that answers after the newer list', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('environmentList')
    controls.setConnected(false)
    const { rerender } = render(hostsThrough(port))
    await made(held, 1)
    act(() => {
      controls.setConnected(true)
    })
    rerender(hostsThrough({ ...port }))
    await made(held, 2)

    await answer(held, 1)
    await answer(held, 0)
    expect(titles()).toEqual(['studio · macOS'])
    expect(screen.queryByText('The hosts could not be read')).toBeNull()
  })

  it('takes nothing in from a host read that answers after the list has gone', async () => {
    for (const ending of ['answer', 'failure'] as const) {
      const { port } = fakeHost()
      const late = settledByHand<EnvironmentListResult>()
      const { unmount } = render(hostsThrough({ ...port, environmentList: late.read }))
      await waitFor(() => {
        expect(late.asked()).toBe(true)
      })
      unmount()

      const answered = watched<EnvironmentListResult>({ environments: [] })
      const refused = watched({ code: 'RESOURCE_UNAVAILABLE', message: 'Gone.', user_action: 'retry' })
      await settle(() => {
        if (ending === 'answer') late.resolve(answered.value)
        else late.reject(refused.value)
      })
      expect(answered.read() || refused.read()).toBe(false)
    }
  })

  it('shows the hosts it read when nothing overtook the read', async () => {
    const { port } = fakeHost()
    render(hostsThrough(port))
    await waitFor(() => {
      expect(titles()).toEqual(['studio · macOS'])
    })
    expect(screen.getByText('3 live sessions')).toBeInTheDocument()
  })
})
