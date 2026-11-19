import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { VoiceRoute } from '../../src/voice/VoiceRoute'

/**
 * The page's half of a call on the host owner's own key: what a person reads before the call
 * starts, what the start names, and what a refusal leaves on the screen. The words of the
 * disclosure are the host's, carried through; these cases read them back from what the fake host
 * answered, and decide none of them.
 *
 * Each case waits for a thing that is on the screen whatever the page does with the provider (the
 * choice screen's own heading), and then asserts with queries that return nothing rather than
 * throw, so that what the page got wrong shows as a failed expectation and not as a query that gave
 * up.
 */

/** The host's own disclosure for the own-key provider, as the fake host answers it. */
async function disclosureOf(port: HostPort): Promise<readonly string[]> {
  const prepared = await port.voicePrepare({ session_ids: [], selected: [] })
  return 'own_key' in prepared.provider ? prepared.provider.own_key.disclosure : []
}

function mount(
  terms: 'own_key' | 'own_key_unheld' | 'published',
  wrap?: (port: HostPort) => void
): { port: HostPort; controls: FakeHostControls; start: ReturnType<typeof vi.fn> } {
  const { port, controls } = fakeHost()
  controls.setVoiceTerms(terms)
  const answered = port.voiceStart.bind(port)
  const start = vi.fn((...args: Parameters<HostPort['voiceStart']>) => answered(...args))
  Object.assign(port, { voiceStart: start })
  wrap?.(port)
  render(
    <AppProvider port={port}>
      <VoiceRoute surface="desktop" />
    </AppProvider>
  )
  return { port, controls, start }
}

/** Waits for the choice screen, which every provider's preparation draws. */
async function choiceScreen(): Promise<void> {
  await screen.findByRole('heading', { name: 'Start a voice session' })
}

function startControl(): HTMLElement | null {
  return screen.queryByRole('button', { name: 'Start voice session' })
}

describe('a call on the host owner’s own key, before it starts', () => {
  // KR-REQ-15.09, KR-REQ-15.19: the provider and what it sees are shown before voice starts, and
  // the host's own disclosure is shown above the control that starts the call.
  it('shows the host’s disclosure above the start control, and no rate, balance or sign-in', async () => {
    const { port } = mount('own_key')
    const lines = await disclosureOf(port)
    await choiceScreen()

    expect(lines.length).toBeGreaterThan(0)
    const access = screen.queryByRole('region', { name: 'What this gives access to' })
    expect(access).not.toBeNull()
    if (access === null) return
    for (const line of lines) {
      expect(within(access).queryByText(line)).not.toBeNull()
    }
    const start = startControl()
    expect(start).not.toBeNull()
    if (start === null) return
    // Above the control that acts on it: a disclosure below the button has already been skipped.
    expect(
      (access.compareDocumentPosition(start) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0
    ).toBe(true)

    expect(screen.queryByText('gpt-live-1')).not.toBeNull()
    expect(screen.queryByText(/Brokered by/)).toBeNull()
    expect(screen.queryByRole('region', { name: 'What it costs' })).toBeNull()
    expect(screen.queryByText(/a second/)).toBeNull()
    expect(screen.queryByText(/balance|sign in|signed in/i)).toBeNull()
  })

  it('names the own-key provider in its start, with no rate and the length of a call on that key', async () => {
    const person = userEvent.setup()
    const { start } = mount('own_key')
    await choiceScreen()
    const control = startControl()
    expect(control).not.toBeNull()
    if (control === null) return
    await person.click(control)

    await waitFor(() => {
      expect(start).toHaveBeenCalledTimes(1)
    })
    const [request] = start.mock.calls[0] as Parameters<HostPort['voiceStart']>
    expect(request.provider).toBe('own_key')
    expect(request.expectedRateVersion).toBeNull()
    expect(request.durationSeconds).toBe(1800)
  })

  it('offers no start while the host holds no key, and says why', async () => {
    mount('own_key_unheld')
    await choiceScreen()
    expect(
      screen.queryByText('This host holds no OpenAI key, so it cannot start this call.')
    ).not.toBeNull()
    expect(startControl()).toBeNull()
  })

  it('still starts a managed call under the rate on screen', async () => {
    const person = userEvent.setup()
    const { start } = mount('published')
    await choiceScreen()
    const control = startControl()
    expect(control).not.toBeNull()
    if (control === null) return
    await person.click(control)
    await waitFor(() => {
      expect(start).toHaveBeenCalledTimes(1)
    })
    const [request] = start.mock.calls[0] as Parameters<HostPort['voiceStart']>
    expect(request.provider).toBe('managed')
    expect(request.expectedRateVersion).not.toBeNull()
  })

  // C-10. The host refuses a second own-key start while an earlier call is not confirmed closed, in
  // its own words naming the earlier action. The page shows that sentence and offers no control
  // that starts the call again over it: an own-key row is not one a "Start again" can act on yet.
  it('shows a conflict on an own-key call in the host’s words and offers no start again', async () => {
    const person = userEvent.setup()
    const conflict =
      'This host holds an earlier voice call on your OpenAI key that is not confirmed closed (action a-1, device d-1, begun at 2026-11-19 09:00, UTC), so a second call could be charged beside it.'
    mount('own_key', (port) => {
      Object.assign(port, {
        voiceStart: vi.fn(() =>
          Promise.reject(
            Object.assign(new Error(`DRAFT_CONFLICT: ${conflict}`), {
              code: 'DRAFT_CONFLICT'
            })
          )
        )
      })
    })
    await choiceScreen()
    const control = startControl()
    expect(control).not.toBeNull()
    if (control === null) return
    await person.click(control)

    await waitFor(() => {
      expect(screen.queryByText(conflict)).not.toBeNull()
    })
    expect(screen.queryByRole('button', { name: /start again/i })).toBeNull()
    expect(screen.queryByText(/start again/i)).toBeNull()
    expect(screen.queryByRole('heading', { name: 'Voice session' })).toBeNull()
  })
})
