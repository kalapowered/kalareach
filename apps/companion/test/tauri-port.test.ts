/**
 * What the desktop port sends for a session's snapshot, the read it refuses, and how it takes in the
 * connection state native code reports.
 *
 * The snapshot command answers a session's state and carries no screen, so the port types it as
 * that and sends it there, and it refuses the projected screen, which no command answers, rather
 * than reading a screen out of an answer that has none. A connection state's reason that is blank
 * is no reason, so the port hands it on as none, from a read and from a change alike.
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
    return Promise.resolve(shell.answers.has(command) ? shell.answers.get(command) : { attachments: [] })
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

describe('the desktop port and a session snapshot', () => {
  it('sends the snapshot read to the snapshot command, with the parameters the host decodes', async () => {
    const params = { session_id: '8a7b6c50-22bb-4c3d-8e4f-000000000101', agent_resources_from: null }
    await tauriPort().eventsSnapshot(params)
    expect(shell.invoked).toEqual([{ command: 'events_snapshot', args: { params } }])
  })

  it('refuses the projected screen, which no command answers, and sends nothing', async () => {
    await expect(
      tauriPort().terminalProjection({ session_id: '8a7b6c50-22bb-4c3d-8e4f-000000000101' })
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_SCHEMA' })
    expect(shell.invoked).toEqual([])
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

  it('takes a blank reason in as no reason, from a read and from a change', async () => {
    for (const blank of ['', '   ', '\n\t ']) {
      shell.answers.set('connection_state', lost(blank))
      expect(await tauriPort().connectionState()).toEqual(lost(null))
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
