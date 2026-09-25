/**
 * What the desktop port sends for a session's snapshot, and the read it refuses.
 *
 * The snapshot command answers a session's state and carries no screen, so the port types it as
 * that and sends it there, and it refuses the projected screen, which no command answers, rather
 * than reading a screen out of an answer that has none.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'

import { tauriPort } from '../src/host/tauri'

const shell = vi.hoisted(() => ({ invoked: [] as { command: string; args: unknown }[] }))

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (command: string, args: unknown) => {
    shell.invoked.push({ command, args })
    return Promise.resolve({ attachments: [] })
  }
}))

vi.mock('@tauri-apps/api/event', () => ({
  listen: () => Promise.resolve(() => undefined)
}))

afterEach(() => {
  shell.invoked.length = 0
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
