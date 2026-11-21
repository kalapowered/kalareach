/**
 * What output does to the launch buttons, and what a change that draws nothing does (KR-REQ-13.11).
 *
 * The scripted host answers each read of the launch surface when the test says, and the scripted
 * view publishes the states the test chooses, so each case decides by the host's recorded calls and
 * a clock the test moves: output on the screen wakes a read but darkens nothing, the editor's own
 * silent change is found by the next read, and a press that comes before that read is refused by the
 * host.
 */

import { describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider, type Place } from '../src/app/state'
import { LAUNCH_SURFACE_CADENCE_MS, LAUNCH_SURFACE_WAKE_GAP_MS } from '../src/app/launch-surface'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

const SAVED = [
  { label: 'Claude Code', program: '/usr/local/bin/claude', arguments: ['--resume'] },
  { label: 'Codex CLI', program: 'codex', arguments: [] }
]

function open(port: HostPort): void {
  const place: Place = { view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' }
  render(
    <AppProvider port={port} initialPlace={place}>
      <App />
    </AppProvider>
  )
}

/** The raw view, with the person's press on "Take control" and the session's grant of it. */
async function takeControl(person: ReturnType<typeof userEvent.setup>): Promise<void> {
  await screen.findByTestId('palette-provenance')
  await person.click(screen.getByRole('button', { name: 'Take control' }))
  await waitFor(() => {
    expect(screen.getByTestId('terminal-mode')).toHaveTextContent('Control')
  })
}

/** The installed agents' buttons, by what they start. */
function profile(): HTMLElement[] {
  return within(screen.getByTestId('launch-surface'))
    .getAllByRole('button')
    .filter((each) => each.dataset.offer !== undefined)
}

/** The saved commands' buttons. */
function named(): HTMLElement[] {
  return within(screen.getByTestId('launch-saved')).getAllByRole('button')
}

/** Every button that starts something, an installed agent's or a saved command's. */
function everyButton(): HTMLElement[] {
  return [...profile(), ...named()]
}

function everyLit(): void {
  expect(everyButton()).toHaveLength(5)
  for (const each of everyButton()) expect(each).toBeEnabled()
}

function everyDark(): void {
  expect(everyButton()).toHaveLength(5)
  for (const each of everyButton()) expect(each).toBeDisabled()
}

/** The view's controlled terminal with every button lit, and the clock the test moves. */
async function lit() {
  vi.useFakeTimers({ shouldAdvanceTime: true })
  const person = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
  const { port, controls } = fakeHost()
  controls.launchCommands.changeElsewhere(SAVED)
  open(port)
  await takeControl(person)
  await waitFor(() => {
    everyLit()
  })
  const view = controls.terminalViews[0]
  if (view === undefined) throw new Error('the page opened no view')
  // The states that took control have woken reads of their own: let each start and answer, so that
  // the reads a case counts are the ones it caused.
  let seen = -1
  while (view.launchReads !== seen) {
    seen = view.launchReads
    await act(async () => {
      vi.advanceTimersByTime(LAUNCH_SURFACE_WAKE_GAP_MS)
      await Promise.resolve()
    })
  }
  everyLit()
  return { person, controls, view }
}

describe('what output and a silent change do to the launch buttons', () => {
  it('output_alone_does_not_darken_profile_or_named_buttons_and_a_new_generation_still_needs_the_look', async () => {
    try {
      const { person, controls, view } = await lit()
      const listReads = controls.launchCommands.reads
      const reads = controls.hold('launchSurface')

      // Output streams. Each state the view publishes wakes a read of the surface, at most one in
      // each wake gap; no button is dark in the frame the output is drawn in, while the wake read
      // is on its way, or after it has answered the same prompt.
      for (let round = 1; round <= 3; round += 1) {
        act(() => {
          view.show()
        })
        everyLit()
        act(() => {
          vi.advanceTimersByTime(LAUNCH_SURFACE_WAKE_GAP_MS)
        })
        await waitFor(() => {
          expect(reads.count).toBe(round)
        })
        everyLit()
        await act(async () => {
          reads.answer(round - 1)
          await Promise.resolve()
        })
        everyLit()
      }
      // A wake round reads the surface only: output never reads the saved commands.
      expect(controls.launchCommands.reads).toBe(listReads)

      // The prompt moves on and its output is drawn. The read it wakes is on its way, and the
      // buttons are lit until it has answered: output alone says nothing of the prompt.
      act(() => {
        controls.changePromptGeneration()
        view.show()
      })
      everyLit()
      act(() => {
        vi.advanceTimersByTime(LAUNCH_SURFACE_WAKE_GAP_MS)
      })
      await waitFor(() => {
        expect(reads.count).toBe(4)
      })
      everyLit()

      // The answer names a prompt the buttons were not drawn at: every button, an agent's and a
      // saved command's, stays dark until the person has looked at it.
      await act(async () => {
        reads.answer(3)
        await Promise.resolve()
      })
      await waitFor(() => {
        expect(screen.getByTestId('launch-stale')).toHaveTextContent('The prompt changed')
      })
      everyDark()
      act(() => {
        vi.advanceTimersByTime(LAUNCH_SURFACE_WAKE_GAP_MS)
        view.show()
        vi.advanceTimersByTime(LAUNCH_SURFACE_WAKE_GAP_MS)
      })
      everyDark()
      expect(screen.getByTestId('launch-refresh')).toHaveTextContent('I have looked at the prompt')

      await person.click(screen.getByTestId('launch-refresh'))
      everyLit()
    } finally {
      vi.useRealTimers()
    }
  })

  it('a_silent_editor_change_is_seen_at_the_next_read_and_the_press_is_refused_before_it', async () => {
    try {
      const { person, controls } = await lit()
      const reads = controls.hold('launchSurface')

      // The editor changes and nothing the page sees says so: no output, no input, no read. The
      // buttons are lit for as long as it takes the next read to start.
      act(() => {
        controls.changePromptGeneration()
        vi.advanceTimersByTime(LAUNCH_SURFACE_WAKE_GAP_MS)
      })
      expect(reads.count).toBe(0)
      everyLit()
      expect(screen.queryByTestId('launch-stale')).toBeNull()

      // The next read, a cadence after the last, finds the change; until it answers the page knows
      // nothing, and after it every button is dark until the person has looked.
      act(() => {
        vi.advanceTimersByTime(LAUNCH_SURFACE_CADENCE_MS)
      })
      await waitFor(() => {
        expect(reads.count).toBe(1)
      })
      everyLit()
      await act(async () => {
        reads.answer(0)
        await Promise.resolve()
      })
      await waitFor(() => {
        expect(screen.getByTestId('launch-stale')).toHaveTextContent('The prompt changed')
      })
      everyDark()
      await person.click(screen.getByTestId('launch-refresh'))
      everyLit()

      // The editor changes silently again, and this time the person presses before any read: the
      // host refuses the quote and nothing is typed. The buttons then wait for a read that began
      // after the refusal, and stay dark while it is on its way.
      act(() => {
        controls.changePromptGeneration()
      })
      expect(reads.count).toBe(1)
      await person.click(profile()[0])
      expect(await screen.findByText(/The prompt changed before the launch was installed/)).toBeInTheDocument()
      expect(controls.launches).toEqual([])
      expect(screen.queryByText(/Submitted the command/)).toBeNull()
      await waitFor(() => {
        expect(reads.count).toBe(2)
      })
      everyDark()
      expect(screen.getByTestId('launch-stale')).toHaveTextContent('The last launch was refused')
      await act(async () => {
        reads.answer(1)
        await Promise.resolve()
      })
      await waitFor(() => {
        expect(screen.getByTestId('launch-stale')).toHaveTextContent('The prompt changed')
      })
      everyDark()
    } finally {
      vi.useRealTimers()
    }
  })
})
