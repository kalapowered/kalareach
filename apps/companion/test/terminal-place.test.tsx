/**
 * The desktop's raw terminal view keeps its own place across a pane change: the place the last view
 * showed is what the next one for the same session is opened with, native code puts the window
 * there before anything is drawn, and says so when it could not.
 *
 * The scripted host stands for native code: a view opened with a place restores it, the moves made
 * before its first screen go behind the restore, and its states carry the anchor of its window.
 */

import { describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { Receipt } from '@kalareach/protocol'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { MOVES_LATER } from '../src/terminal/modes'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const ACTION = '00000000-0000-4000-8000-00000000abcd'

type Controls = ReturnType<typeof fakeHost>['controls']

/** The host's record of a prompt's action when it cannot establish the outcome either. */
function unknownReceipt(action: string): Receipt {
  return {
    action_id: action,
    actor_id: 'owner:local',
    error: null,
    method: 'agent.prompt.submit',
    method_version: 1,
    payload_digest: '0'.repeat(64),
    reason: null,
    revision: '1',
    state: 'unknown',
    updated_at_ms: '0',
    accepted_deadline_ms: null
  }
}

function open(
  port: HostPort,
  place: Place = { view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' }
): ReturnType<typeof render> {
  return render(
    <AppProvider port={port} initialPlace={place}>
      <App />
    </AppProvider>
  )
}

/** The first line the grid draws, as a person reads it. */
function firstRow(): string {
  const grid = screen.queryByTestId('terminal-grid')
  if (grid === null) return ''
  return Array.from(grid.querySelectorAll<HTMLElement>('[data-testid="terminal-piece"]'))
    .filter((box) => box.dataset.line === '0')
    .map((box) => box.textContent ?? '')
    .join('')
}

/** Lays the view out as a browser would: cells of 8 by 16 pixels, the surface at (12, 12). */
function laidOut(): () => void {
  const rects = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (this: Element) {
    const element = this as HTMLElement
    const text = element.textContent ?? ''
    const size = parseFloat(element.parentElement?.style.fontSize ?? '')
    if (element.getAttribute('aria-hidden') === 'true' && /^M+$/.test(text) && size > 0) {
      return DOMRect.fromRect({ x: 0, y: 0, width: (text.length * size * 2) / 3, height: (size * 4) / 3 })
    }
    if (element.dataset.testid === 'terminal-grid') {
      return DOMRect.fromRect({
        x: 12,
        y: 12,
        width: parseFloat(element.style.width) || 0,
        height: parseFloat(element.style.height) || 0
      })
    }
    if (element.parentElement?.dataset.testid === 'terminal-surface') {
      return DOMRect.fromRect({ x: 12, y: 12, width: 640, height: 384 })
    }
    return new DOMRect()
  })
  return () => {
    rects.mockRestore()
  }
}

/** Turns the wheel over the terminal, `deltaY` pixels. */
function wheel(deltaY: number): void {
  act(() => {
    screen
      .getByTestId('terminal-surface')
      .firstElementChild?.dispatchEvent(new WheelEvent('wheel', { bubbles: true, cancelable: true, deltaY }))
  })
}

/** The pane tabs: the person goes to the conversation and back to the terminal. */
async function awayAndBack(person: ReturnType<typeof userEvent.setup>): Promise<void> {
  await person.click(screen.getByRole('tab', { name: 'Conversation' }))
  await person.click(await screen.findByRole('tab', { name: 'Terminal' }))
}

/** A desktop whose terminal shows the main session and has been scrolled up two rows. */
async function scrolledUp(controls: Controls): Promise<void> {
  await screen.findByTestId('palette-provenance')
  expect(firstRow()).toBe('$ cargo test -p kr-client')
  wheel(-32)
  await waitFor(() => {
    expect(firstRow()).toBe('$ echo earlier 11')
  })
  expect(controls.terminalViews).toHaveLength(1)
}

describe('a terminal view keeps its place across a pane change', () => {
  it('opens the next view for the place the last one showed, and draws that place', async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port)
      await scrolledUp(controls)
      await awayAndBack(person)
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      expect(controls.terminalViews[0]?.closed).toBe(true)
      expect(controls.terminalViews[1]?.anchor).toMatchObject({ row: '10', line: 0, column: 0 })
      await waitFor(() => {
        expect(firstRow()).toBe('$ echo earlier 11')
      })
    } finally {
      restore()
    }
  })

  it('opens a view that followed the tail with no place', async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port)
      await screen.findByTestId('palette-provenance')
      await awayAndBack(person)
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      expect(controls.terminalViews[1]?.anchor).toBeNull()
      wheel(-32)
      await waitFor(() => {
        expect(firstRow()).toBe('$ echo earlier 11')
      })
      wheel(32)
      await waitFor(() => {
        expect(firstRow()).toBe('$ cargo test -p kr-client')
      })
      await awayAndBack(person)
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(3)
      })
      expect(controls.terminalViews[2]?.anchor).toBeNull()
    } finally {
      restore()
    }
  })

  it('draws nothing of the new opening while the restore waits', async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port)
      await scrolledUp(controls)
      controls.holdTerminalViews()
      await awayAndBack(person)
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      act(() => {
        controls.terminalViews[1]?.attach()
      })
      expect(screen.queryByTestId('terminal-grid')).toBeNull()
      expect(screen.getByTestId('terminal-surface').getAttribute('aria-busy')).toBe('true')
      act(() => {
        controls.terminalViews[1]?.show()
      })
      expect(firstRow()).toBe('$ echo earlier 11')
    } finally {
      restore()
    }
  })

  it('shows a note with its kind from the first screen and ends it with the next move', async () => {
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      controls.holdTerminalViews()
      open(port)
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(1)
      })
      const slot = document.querySelector('.terminal-place-note')
      expect(slot).not.toBeNull()
      expect(slot?.textContent).toBe('')
      act(() => {
        controls.terminalViews[0]?.attach()
        controls.terminalViews[0]?.show(undefined, undefined, 'gone')
      })
      expect(screen.getByTestId('terminal-place-note').getAttribute('data-kind')).toBe('gone')
      for (const kind of ['unavailable', 'different'] as const) {
        act(() => {
          controls.terminalViews[0]?.show(undefined, undefined, kind)
        })
        expect(screen.getByTestId('terminal-place-note').getAttribute('data-kind')).toBe(kind)
      }
      wheel(-16)
      await waitFor(() => {
        expect(screen.queryByTestId('terminal-place-note')).toBeNull()
      })
      expect(document.querySelector('.terminal-place-note')).toBe(slot)
    } finally {
      restore()
    }
  })

  it("does not take one session's place for another's", async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port, { view: 'sessions' })
      await person.click(await screen.findByTestId('session-row-2'))
      await screen.findByText('Session 2 · Working')
      await person.click(screen.getByRole('button', { name: 'Sessions' }))
      await person.click(await screen.findByTestId('session-row-1'))
      await screen.findByText('Session 1 · Waiting for you')
      await person.click(screen.getByRole('tab', { name: 'Terminal' }))
      await scrolledUp(controls)
      // The switch is made with the Terminal pane showing: the old view's cleanup runs after the new
      // render, and must keep the place under the old session.
      act(() => {
        fireEvent.click(screen.getByRole('tab', { name: 'Session 02' }))
      })
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      expect(controls.terminalViews[1]?.sessionId).not.toBe(SESSION_MAIN)
      expect(controls.terminalViews[1]?.anchor).toBeNull()
      act(() => {
        fireEvent.click(screen.getByRole('tab', { name: 'Session 01' }))
      })
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(3)
      })
      expect(controls.terminalViews[2]?.sessionId).toBe(SESSION_MAIN)
      expect(controls.terminalViews[2]?.anchor).toMatchObject({ row: '10' })
    } finally {
      restore()
    }
  })

  it('keeps the place when the view is left before its restore settles', async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port)
      await scrolledUp(controls)
      controls.holdTerminalViews()
      await awayAndBack(person)
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      await awayAndBack(person)
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(3)
      })
      expect(controls.terminalViews[2]?.anchor).toEqual(controls.terminalViews[1]?.anchor)
      expect(controls.terminalViews[2]?.anchor).toMatchObject({ row: '10' })
    } finally {
      restore()
    }
  })

  it('keeps the live landing when a return to the live screen is not settled at the leave', async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port)
      await scrolledUp(controls)
      controls.holdTerminalMoves()
      await person.click(screen.getByRole('button', { name: 'Take control' }))
      await waitFor(() => {
        expect(controls.terminalViews[0]?.moves.at(-1)).toEqual({ number: 2, live: true })
      })
      await awayAndBack(person)
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      expect(controls.terminalViews[1]?.anchor).toBeNull()
    } finally {
      restore()
    }
  })

  it('keeps the live landing when the view ends after a return to the live screen', async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port)
      await scrolledUp(controls)
      controls.holdTerminalMoves()
      await person.click(screen.getByRole('button', { name: 'Take control' }))
      act(() => {
        controls.terminalViews[0]?.end('The session closed.')
      })
      await person.click(await screen.findByRole('button', { name: /Attach again/ }))
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      expect(controls.terminalViews[1]?.anchor).toBeNull()
    } finally {
      restore()
    }
  })

  it('opens a view attached again for the place it last showed', async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port)
      await scrolledUp(controls)
      act(() => {
        controls.terminalViews[0]?.end('The session closed.')
      })
      await person.click(await screen.findByRole('button', { name: /Attach again/ }))
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      expect(controls.terminalViews[1]?.anchor).toMatchObject({ row: '10' })
    } finally {
      restore()
    }
  })

  it('says it cannot move before the first screen, and a take sends the return and the take', async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port)
      await scrolledUp(controls)
      controls.holdTerminalViews()
      await awayAndBack(person)
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      const view = controls.terminalViews[1]
      act(() => {
        view?.attach()
      })
      const sentence = screen.getByTestId('terminal-mode-sentence')
      expect(sentence.getAttribute('data-moves')).toBe('later')
      expect(sentence.textContent).toBe(MOVES_LATER)
      for (const button of within(screen.getByRole('group', { name: 'Move the window' })).getAllByRole('button')) {
        expect(button).toBeDisabled()
      }
      // A wheel turn has no window to move either: nothing is sent.
      wheel(-32)
      expect(view?.moves).toEqual([])
      await person.click(screen.getByRole('button', { name: 'Take control' }))
      await waitFor(() => {
        expect(view?.moves).toEqual([{ number: 1, live: true }])
      })
      expect(view?.inputs).toMatchObject([{ kind: 'take' }])
      act(() => {
        view?.show()
      })
      expect(screen.getByTestId('terminal-mode-sentence').getAttribute('data-moves')).toBeNull()
    } finally {
      restore()
    }
  })

  it('does not say it waits for a place when the view attaches again with its frame kept', async () => {
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      open(port)
      await scrolledUp(controls)
      controls.holdTerminalViews()
      act(() => {
        controls.terminalViews[0]?.end('The session closed.')
      })
      await userEvent.setup().click(await screen.findByRole('button', { name: /Attach again/ }))
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      const view = controls.terminalViews[1]
      act(() => {
        view?.attach()
      })
      // The opening asks for the place it was left at, and the kept frame can move: the window
      // moves, and native code queues the move behind the restore.
      expect(view?.anchor).toMatchObject({ row: '10' })
      const sentence = screen.getByTestId('terminal-mode-sentence')
      expect(sentence.getAttribute('data-moves')).toBeNull()
      expect(sentence.textContent).not.toBe(MOVES_LATER)
      wheel(-16)
      await waitFor(() => {
        expect(view?.moves).toHaveLength(1)
      })
    } finally {
      restore()
    }
  })

  it('stops waiting for a place when the open itself is refused', async () => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      let opens = 0
      const refusing: HostPort = {
        ...port,
        openTerminalView: (sessionId, grid, listener, opening, anchor) => {
          opens += 1
          if (opens === 1) return port.openTerminalView(sessionId, grid, listener, opening, anchor)
          return Promise.reject(new Error('This session could not be reached'))
        }
      }
      open(refusing)
      await scrolledUp(controls)
      await awayAndBack(person)
      expect(await screen.findByTestId('terminal-ended')).toHaveTextContent(
        'This session could not be reached'
      )
      const sentence = screen.getByTestId('terminal-mode-sentence')
      expect(sentence.getAttribute('data-moves')).toBeNull()
      expect(sentence.textContent).not.toBe(MOVES_LATER)
      expect(screen.getByRole('button', { name: /Attach again/ })).toBeInTheDocument()
    } finally {
      restore()
    }
  })

  it.each([
    { owed: false, title: "forgets a closed tab's place: the session opens again with none" },
    {
      owed: true,
      title: "forgets a closed tab's place though a prompt with no outcome keeps its state: the session opens again with none"
    }
  ])('$title', async ({ owed }) => {
    const person = userEvent.setup()
    const restore = laidOut()
    try {
      const { port, controls } = fakeHost()
      // A prompt whose outcome nobody knows: closing the tab keeps what is owed for it.
      const unconfirmed: HostPort = {
        ...port,
        composerSubmit: () => Promise.resolve({ receipt: null, value: null, action_id: ACTION }),
        actionRead: (params) =>
          Promise.resolve({ receipt: unknownReceipt(params.action_id), result: null })
      }
      open(owed ? unconfirmed : port, { view: 'sessions' })
      await person.click(await screen.findByTestId('session-row-2'))
      await screen.findByText('Session 2 · Working')
      await person.click(screen.getByRole('button', { name: 'Sessions' }))
      await person.click(await screen.findByTestId('session-row-1'))
      await screen.findByText('Session 1 · Waiting for you')
      if (owed) {
        await person.type(await screen.findByTestId('composer-input'), 'run the migration')
        await waitFor(() => {
          expect(screen.getByTestId('composer-send')).toBeEnabled()
        })
        await person.click(screen.getByTestId('composer-send'))
        await waitFor(() => {
          expect(screen.getByTestId('composer-reason')).toHaveTextContent(/no confirmed outcome yet/)
        })
      }
      await person.click(screen.getByRole('tab', { name: 'Terminal' }))
      await scrolledUp(controls)
      // The tab closes with the view still open: the view's cleanup runs after the session was
      // forgotten, and must not make its place again, though the state is held for the prompt.
      await person.click(screen.getByRole('button', { name: /Close the tab for session 01/ }))
      await person.click(await screen.findByTestId('session-row-1'))
      await screen.findByText('Session 1 · Waiting for you')
      await person.click(screen.getByRole('tab', { name: 'Terminal' }))
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      expect(controls.terminalViews[1]?.sessionId).toBe(SESSION_MAIN)
      expect(controls.terminalViews[1]?.anchor).toBeNull()
      if (owed) {
        // What is owed stays: the prompt is still held, and the draft is still the person's.
        await person.click(screen.getByRole('tab', { name: 'Conversation' }))
        await waitFor(() => {
          expect(screen.getByTestId('composer-input')).toHaveValue('run the migration')
        })
        expect(screen.getByTestId('composer-send')).toBeDisabled()
        expect(screen.getByTestId('composer-reason')).toHaveTextContent(/no confirmed outcome yet/)
      }
    } finally {
      restore()
    }
  })
})
