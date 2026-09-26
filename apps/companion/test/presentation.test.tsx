/**
 * How the host presents each raw terminal view, and why, on the desktop and on the phone.
 *
 * Each view says what its own attachment's summary says, which native code sends with the view's
 * states from the moment it attaches: a viewport is shown with the host's reason in the host's
 * words, a viewport whose worker gave no reason says so and is never taken for a direct
 * presentation, and a direct one shows no reason. A view declares no terminal profile, so the host
 * presents it as a viewport for that reason unless it says otherwise.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { PresentationReason } from '@kalareach/protocol'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { MobileApp } from '../src/mobile/MobileApp'
import { ATTACHING } from '../src/terminal/modes'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

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
      controls.presentTerminal('viewport', reason)
      openTerminal(port)
      await screen.findByTestId('palette-provenance')
      expect(await presented()).toBe(viewport(words))
    })
  }

  it('says, as the host does for a view with no terminal profile, why it is a viewport', async () => {
    const { port } = fakeHost()
    openTerminal(port)
    await screen.findByTestId('palette-provenance')
    expect(await presented()).toBe(viewport(HOST_WORDS[0]?.[1] ?? ''))
  })

  it('shows a direct presentation with no reason', async () => {
    const { port, controls } = fakeHost()
    controls.presentTerminal('direct')
    openTerminal(port)
    await screen.findByTestId('palette-provenance')
    expect(await presented()).toBe(DIRECT)
    expect(anyReasonShown()).toBe(false)
  })

  it('never shows a viewport whose worker gave no reason as direct', async () => {
    const { port, controls } = fakeHost()
    controls.presentTerminal('viewport')
    openTerminal(port)
    await screen.findByTestId('palette-provenance')
    expect(await presented()).toBe(NO_REASON)
    expect(document.body.textContent).not.toContain('directly')
  })

  it('says the host reported nothing when its own summary has no presentation', async () => {
    const { port, controls } = fakeHost()
    controls.presentTerminal(null)
    openTerminal(port)
    await screen.findByTestId('palette-provenance')
    expect(await presented()).toBe(NOT_REPORTED)
    expect(anyReasonShown()).toBe(false)
  })

  it('says it is attaching, and nothing of a presentation, before the view has attached', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    openTerminal(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    expect(await presented()).toBe(ATTACHING)
    expect(anyReasonShown()).toBe(false)

    act(() => {
      controls.terminalViews[0]?.attach()
    })
    expect(await presented()).toBe(viewport(HOST_WORDS[0]?.[1] ?? ''))
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
      controls.presentTerminal('viewport', reason)
      await openTerminal(port)
      expect(await presented()).toBe(viewport(words))
    })
  }

  it('shows a direct presentation with no reason', async () => {
    const { port, controls } = fakeHost()
    controls.presentTerminal('direct')
    await openTerminal(port)
    expect(await presented()).toBe(DIRECT)
    expect(anyReasonShown()).toBe(false)
  })

  it('never shows a viewport whose worker gave no reason as direct', async () => {
    const { port, controls } = fakeHost()
    controls.presentTerminal('viewport')
    await openTerminal(port)
    expect(await presented()).toBe(NO_REASON)
  })

  it('says the host reported nothing when its own summary has no presentation', async () => {
    const { port, controls } = fakeHost()
    controls.presentTerminal(null)
    await openTerminal(port)
    expect(await presented()).toBe(NOT_REPORTED)
    expect(anyReasonShown()).toBe(false)
  })

  it('shows what its newest view attached with when it is left and opened again', async () => {
    const { port, controls } = fakeHost()
    const person = await openTerminal(port)
    expect(await presented()).toBe(viewport(HOST_WORDS[0]?.[1] ?? ''))

    // The presentation changes, and the person leaves the terminal and comes back to it: a new
    // view attaches, and says what it attached with.
    controls.presentTerminal('viewport', 'size_mismatch')
    await person.click(screen.getByRole('tab', { name: 'Conversation' }))
    await waitFor(() => {
      expect(controls.terminalViews[0]?.closed).toBe(true)
    })
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(2)
    })
    await waitFor(() => {
      expect(screen.getByTestId('terminal-presentation').textContent).toBe(
        viewport("its size is not the session's")
      )
    })
  })
})
