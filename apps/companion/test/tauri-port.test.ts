/**
 * What the desktop port sends for a raw terminal view, and how it takes in the connection state
 * native code reports.
 *
 * A view is opened with the session and the grid the command takes, and a channel of its own that
 * native code publishes that view's states on; its size and its close go to their own commands with
 * the handle the open answered. A connection state's reason that is blank is no reason, so the port
 * hands it on as none, from a read and from a change alike.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'

import type { ConnectionState } from '../src/host/port'
import { CONNECTION_EVENT, tauriPort } from '../src/host/tauri'

const shell = vi.hoisted(() => ({
  invoked: [] as { command: string; args: unknown }[],
  /** What a command answers, by its name; one not named here answers a session snapshot. */
  answers: new Map<string, unknown>(),
  /** The handler native code publishes each event to, by the event's name. */
  handlers: new Map<string, (published: { payload: unknown }) => void>()
}))

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (command: string, args: unknown) => {
    shell.invoked.push({ command, args })
    return Promise.resolve(shell.answers.has(command) ? shell.answers.get(command) : null)
  },
  // The page's end of a channel: native code calls `onmessage` with each message.
  Channel: class {
    onmessage: (message: unknown) => void = () => undefined
  }
}))

vi.mock('@tauri-apps/api/event', () => ({
  listen: (event: string, handler: (published: { payload: unknown }) => void) => {
    shell.handlers.set(event, handler)
    return Promise.resolve(() => undefined)
  }
}))

afterEach(() => {
  shell.invoked.length = 0
  shell.answers.clear()
  shell.handlers.clear()
})

describe('the desktop port and a raw terminal view', () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  it('opens a view with the session, the grid and a channel of its own', async () => {
    shell.answers.set('terminal_view_open', '7')
    const heard: unknown[] = []
    await tauriPort().openTerminalView(SESSION, { columns: 80, rows: 24 }, (state) => {
      heard.push(state)
    })
    expect(shell.invoked).toHaveLength(1)
    const [opened] = shell.invoked
    expect(opened?.command).toBe('terminal_view_open')
    const args = opened?.args as {
      sessionId: string
      columns: number
      rows: number
      onState: { onmessage: (message: unknown) => void }
    }
    expect({ sessionId: args.sessionId, columns: args.columns, rows: args.rows }).toEqual({
      sessionId: SESSION,
      columns: 80,
      rows: 24
    })
    // What native code publishes on the view's channel reaches the view's listener, and only it.
    const ended = { state: 'ended', reason: 'This session has closed.' }
    args.onState.onmessage(ended)
    expect(heard).toEqual([ended])
  })

  it('sends the size, the moves and the close to their own commands, with the handle the open answered', async () => {
    shell.answers.set('terminal_view_open', '7')
    const view = await tauriPort().openTerminalView(SESSION, { columns: 80, rows: 24 }, () => undefined)
    await view.resize({ columns: 100, rows: 30 })
    await view.move({ number: 1, across: -2, down: 3 })
    await view.move({ number: 2, live: true })
    await view.close()
    expect(shell.invoked.slice(1)).toEqual([
      { command: 'terminal_view_resize', args: { view: '7', columns: 100, rows: 30 } },
      {
        command: 'terminal_view_move',
        args: { view: '7', number: 1, across: -2, down: 3, live: false }
      },
      { command: 'terminal_view_move', args: { view: '7', number: 2, across: 0, down: 0, live: true } },
      { command: 'terminal_view_close', args: { view: '7' } }
    ])
  })
})

describe('the desktop port and the connection state', () => {
  const lost = (reason: string | null): ConnectionState => ({
    connected: false,
    environment_id: null,
    reason
  })

  /** What a listener registered through the port hears when native code publishes `state`. */
  async function heard(state: ConnectionState): Promise<ConnectionState[]> {
    const states: ConnectionState[] = []
    await tauriPort().onConnection((each) => {
      states.push(each)
    })
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: state })
    return states
  }

  it('takes a blank reason in as no reason when it reads the state', async () => {
    for (const blank of ['', '   ', '\n\t ']) {
      shell.answers.set('connection_state', lost(blank))
      expect(await tauriPort().connectionState()).toEqual(lost(null))
    }
  })

  it('takes a blank reason in as no reason when it hears a change', async () => {
    for (const blank of ['', '   ', '\n\t ']) {
      expect(await heard(lost(blank))).toEqual([lost(null)])
    }
  })

  it('hands on a reason with words, and a live connection, as native code sent them', async () => {
    const said = lost('  the relay closed this connection ')
    shell.answers.set('connection_state', said)
    expect(await tauriPort().connectionState()).toEqual(said)
    expect(await heard(said)).toEqual([said])

    const live: ConnectionState = {
      connected: true,
      environment_id: '3f1a2c40-11aa-4b2c-9d3e-000000000001',
      reason: null
    }
    shell.answers.set('connection_state', live)
    expect(await tauriPort().connectionState()).toEqual(live)
    expect(await heard(live)).toEqual([live])
  })
})
