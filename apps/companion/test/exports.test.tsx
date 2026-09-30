/**
 * The two exports a session offers, as the page asks native code to write them.
 *
 * The recording carries each screen the raw terminal view drew, when it drew it, at the size it
 * drew it; the semantic archive carries each entry of the agent's history as the session's worker
 * gave it, at the session's own size, and declares what it leaves out.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { readSemanticArchive } from '../src/model/exports'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

function open(port: HostPort, place: Place): void {
  render(
    <AppProvider port={port} initialPlace={place}>
      <App />
    </AppProvider>
  )
}

/** Opens the session's settings at its exports. */
async function openExports(person: ReturnType<typeof userEvent.setup>): Promise<void> {
  await person.click(screen.getByTestId('open-settings'))
  await person.click(await screen.findByRole('button', { name: 'Export' }))
}

describe("a session's exports (KR-REQ-25.25)", () => {
  it('exports each screen the terminal view drew, when it drew it, at the size it drew it', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, { view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' })
    await screen.findByTestId('palette-provenance')
    act(() => {
      controls.terminalViews[0]?.show({ cursor: { line: 1, column: 4, style: 1, visible: true } })
    })

    await openExports(person)
    expect(screen.getByTestId('recording-held')).toHaveTextContent('2 screens at 80×8.')
    await person.click(screen.getByRole('button', { name: 'Export recording' }))
    await waitFor(() => {
      expect(controls.exportedCasts).toHaveLength(1)
    })
    const cast = controls.exportedCasts[0]
    const session = await port.sessionRead({ session_id: SESSION_MAIN })
    expect(cast?.path).toBe(`/tmp/session-${SESSION_MAIN}.cast`)
    expect(cast?.title).toBe(`Session ${session.session.display_number}`)
    expect(cast?.dimensions).toEqual({ columns: 80, rows: 8 })
    expect(cast?.frames).toHaveLength(2)
    expect(cast?.frames[0]?.at_ms).toBe(0)
    expect(cast?.frames[1]?.at_ms).toBeGreaterThanOrEqual(0)
    // The first screen's text, drawn at its cells; the second moved only the cursor.
    expect(cast?.frames[0]?.text).toContain('$ cargo test -p kr-client')
    expect(cast?.frames[0]?.text).toContain('\u001b[6;3H\u001b[?25h')
    expect(cast?.frames[1]?.text).toContain('\u001b[2;5H\u001b[?25h')
    // The view drew the cursor on both screens, in a shape and colour a player draws in its own.
    expect(cast?.omissions).toEqual([
      {
        kind: 'cursor_style',
        detail: "The cursor's shape and colour, which a player draws in its own",
        count: 2
      }
    ])
    expect(
      await screen.findByText(`Written to /tmp/session-${SESSION_MAIN}.cast, with 1 declared omission.`)
    ).toBeInTheDocument()
  })

  it('offers no recording until the terminal view has drawn', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    open(port, { view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await screen.findByTestId('open-settings')
    await openExports(person)
    expect(screen.getByTestId('recording-held')).toHaveTextContent(
      'The terminal view has drawn nothing yet. Open the terminal, and what it shows is recorded.'
    )
    expect(screen.getByRole('button', { name: 'Export recording' })).toBeDisabled()
    expect(controls.exportedCasts).toHaveLength(0)
  })

  it("archives each entry of the agent's history at the session's size, and declares what it withheld", async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    // This device's filter withholds the second entry.
    controls.records.withholdEntry(SESSION_MAIN, 2)
    open(port, { view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' })
    await screen.findByTestId('open-settings')
    await openExports(person)
    const button = screen.getByRole('button', { name: 'Export JSON' })
    await waitFor(() => {
      expect(button).toBeEnabled()
    })
    await person.click(button)
    await waitFor(() => {
      expect(controls.exportedArchives).toHaveLength(1)
    })
    const archive = controls.exportedArchives[0]
    const session = await port.sessionRead({ session_id: SESSION_MAIN })
    expect(archive?.path).toBe(`/tmp/session-${SESSION_MAIN}.json`)
    expect(archive?.dimensions).toEqual({
      columns: Number(session.session.dimensions.columns),
      rows: Number(session.session.dimensions.rows)
    })
    expect(archive?.nodes.map((node) => (node.body as { text: string }).text)).toEqual([
      'Codex started a conversation in /Users/rs/work/kalareach.',
      expect.stringContaining('The test waits on a **timer**'),
      'read_file tests/reconnect.rs',
      'Codex asks to run scripts/release.sh --publish'
    ])
    for (const node of archive?.nodes ?? []) expect(node.at_ms).toBeGreaterThan(0)
    expect(archive?.omissions).toEqual([
      {
        kind: 'withheld_entries',
        detail: "Entries outside what this device's authority lets it read",
        count: 1
      }
    ])
    expect(
      await screen.findByText(`Written to /tmp/session-${SESSION_MAIN}.json, with 1 declared omission.`)
    ).toBeInTheDocument()
  })

  it('archives the binding revision and the turn each entry was observed under', async () => {
    const entry = (node: string, revision: string, turn: string | null) => ({
      node,
      kind: 'message',
      text: `entry ${node}`,
      omitted_text_bytes: '0',
      observed_at: '10',
      binding_revision: revision,
      turn_id: turn
    })
    // The history of an agent whose owner changed after its first entry: the read is made under the
    // second revision, and each entry names the one it was observed under.
    const port = {
      sessionAgents: () =>
        Promise.resolve({
          instances: {
            sequence: '1',
            instances: [{ application_instance_id: 'i-1', ended_at: null }]
          },
          resources: []
        }),
      agentSnapshot: () =>
        Promise.resolve({
          entries: [entry('1', '1', 'turn-1'), entry('2', '2', null)],
          continuation: null,
          history_gap: false,
          withheld_entries: '0'
        })
    } as unknown as HostPort
    const archive = await readSemanticArchive(port, SESSION_MAIN)
    expect(
      archive.nodes.map((node) => {
        const body = node.body as { binding_revision: string; turn_id: string | null }
        return [body.binding_revision, body.turn_id]
      })
    ).toEqual([
      ['1', 'turn-1'],
      ['2', null]
    ])
  })
})
