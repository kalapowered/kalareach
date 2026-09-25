/**
 * How the host presents each raw terminal view, and why, on the desktop and on the phone.
 *
 * Each view reads the session's snapshot and takes the summary of its own attachment and no other:
 * a viewport is shown with the host's reason in the host's words, a viewport whose worker gave no
 * reason says so and is never taken for a direct presentation, and a direct one shows no reason.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { PresentationReason } from '@kalareach/protocol'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost, type HeldReads } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { MobileApp } from '../src/mobile/MobileApp'
import { terminalAttachment } from '../src/terminal/modes'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const VIEW = terminalAttachment(SESSION_MAIN)

/** Each reason, with the sentence the host gives it. */
const HOST_WORDS: readonly (readonly [PresentationReason, string])[] = [
  [
    'no_terminal_profile',
    "its client declared no terminal profile, so what the session's output would do on its terminal is not known"
  ],
  [
    'unqualified_terminal_profile',
    'the terminal profile its client declared is not one this build has qualified'
  ],
  ['size_mismatch', "its size is not the session's"],
  ['history_window', 'its window is above the live screen'],
  [
    'stream_not_carryable',
    "the session's output is no longer something a terminal can be handed as it is"
  ],
  [
    'restoration_incomplete',
    'the screen it was last given could not carry everything the application addresses'
  ],
  [
    'awaiting_parser_boundary',
    "forwarding waits for the session's output to reach the end of a sequence"
  ]
]

const DIRECT = "This view is shown the session's output directly."
const NO_REASON = 'This view is shown a viewport. The host reported no reason for it.'
const NOT_REPORTED = 'The host reports no presentation for this view.'
const viewport = (words: string) => `This view is shown a viewport because ${words}.`

/** What the view says about how it is presented, once it says anything. */
async function presented(): Promise<string> {
  return (await screen.findByTestId('terminal-presentation')).textContent ?? ''
}

/** Whether any reason's words are anywhere on the page. */
function anyReasonShown(): boolean {
  const text = document.body.textContent ?? ''
  return HOST_WORDS.some(([, words]) => text.includes(words))
}

/** Answers the held read at `index`, and lets everything that answer sets off run. */
async function answer(held: HeldReads, index: number): Promise<void> {
  await act(async () => {
    held.answer(index)
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
  })
}

async function made(held: HeldReads, count: number): Promise<void> {
  await waitFor(() => {
    expect(held.count).toBe(count)
  })
}

describe('the desktop raw view says how the host presents it, and why (KR-REQ-08.02)', () => {
  function openTerminal(port: HostPort): void {
    render(
      <AppProvider
        port={port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'terminal' }}
      >
        <App />
      </AppProvider>
    )
  }

  for (const [reason, words] of HOST_WORDS) {
    it(`gives a viewport's reason in the host's words: ${reason}`, async () => {
      const { port, controls } = fakeHost()
      controls.presentAttachment(VIEW, 'viewport', reason)
      openTerminal(port)
      expect(await presented()).toBe(viewport(words))
    })
  }

  it('shows a direct presentation with no reason', async () => {
    const { port } = fakeHost()
    openTerminal(port)
    expect(await presented()).toBe(DIRECT)
    expect(anyReasonShown()).toBe(false)
  })

  it('never shows a viewport whose worker gave no reason as direct', async () => {
    const { port, controls } = fakeHost()
    controls.presentAttachment(VIEW, 'viewport')
    openTerminal(port)
    expect(await presented()).toBe(NO_REASON)
    expect(document.body.textContent).not.toContain('directly')
  })

  it("never takes another attachment's summary for its own", async () => {
    const { port, controls } = fakeHost()
    // What is left is another client's viewport, for a reason of its own, and a semantic view.
    controls.detachAttachment(VIEW)
    openTerminal(port)
    expect(await presented()).toBe(NOT_REPORTED)
    expect(anyReasonShown()).toBe(false)
  })

  it('reads the snapshot again when its window moves, and shows the reason then in force', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    openTerminal(port)
    expect(await presented()).toBe(DIRECT)

    await person.click(screen.getByRole('tab', { name: 'View' }))
    act(() => {
      screen
        .getByTestId('terminal-surface')
        .dispatchEvent(new WheelEvent('wheel', { deltaY: 120, bubbles: true, cancelable: true }))
    })
    await waitFor(() => {
      expect(screen.getByTestId('terminal-presentation').textContent).toBe(
        viewport('its window is above the live screen')
      )
    })
  })

  it('says nothing of its presentation before the snapshot answers', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('eventsSnapshot')
    openTerminal(port)
    await made(held, 1)
    expect(screen.queryByTestId('terminal-presentation')).toBeNull()

    await answer(held, 0)
    expect(await presented()).toBe(DIRECT)
  })
})

describe("the phone's raw view says the same (KR-REQ-08.02)", () => {
  /** Opens the phone on the main session's terminal. */
  async function openTerminal(port: HostPort): Promise<ReturnType<typeof userEvent.setup>> {
    const person = userEvent.setup()
    window.history.replaceState(null, '', `/?session=${SESSION_MAIN}`)
    try {
      render(
        <AppProvider port={port}>
          <MobileApp surface="ios" storage={null} />
        </AppProvider>
      )
    } finally {
      window.history.replaceState(null, '', '/')
    }
    await person.click(await screen.findByRole('tab', { name: 'Terminal' }))
    return person
  }

  for (const [reason, words] of HOST_WORDS) {
    it(`gives a viewport's reason in the host's words: ${reason}`, async () => {
      const { port, controls } = fakeHost()
      controls.presentAttachment(VIEW, 'viewport', reason)
      await openTerminal(port)
      expect(await presented()).toBe(viewport(words))
    })
  }

  it('shows a direct presentation with no reason', async () => {
    const { port } = fakeHost()
    await openTerminal(port)
    expect(await presented()).toBe(DIRECT)
    expect(anyReasonShown()).toBe(false)
  })

  it('never shows a viewport whose worker gave no reason as direct', async () => {
    const { port, controls } = fakeHost()
    controls.presentAttachment(VIEW, 'viewport')
    await openTerminal(port)
    expect(await presented()).toBe(NO_REASON)
  })

  it("never takes another attachment's summary for its own", async () => {
    const { port, controls } = fakeHost()
    controls.detachAttachment(VIEW)
    await openTerminal(port)
    expect(await presented()).toBe(NOT_REPORTED)
    expect(anyReasonShown()).toBe(false)
  })

  it('shows only its newest read when it is left and opened again', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('eventsSnapshot')
    const person = await openTerminal(port)
    await made(held, 1)

    // The presentation changes, and the person leaves the terminal and comes back to it.
    controls.presentAttachment(VIEW, 'viewport', 'size_mismatch')
    await person.click(screen.getByRole('tab', { name: 'Conversation' }))
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await made(held, 2)

    await answer(held, 1)
    expect(await presented()).toBe(viewport("its size is not the session's"))
    // The first read, made before the change, answers last.
    await answer(held, 0)
    expect(await presented()).toBe(viewport("its size is not the session's"))
  })
})
