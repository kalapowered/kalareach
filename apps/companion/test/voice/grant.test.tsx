/**
 * The first-use step of the voice screen: what allowing voice permits, and for which sessions.
 *
 * A host that holds no voice grant for this device refuses to say what a call would be, and the
 * screen turns that refusal into the question it is: it shows the host's words, every action the
 * grant permits in the sentence the protocol states it in, and the sessions to choose from. Nothing
 * is allowed until the person presses the control, and the preparation is asked again only when the
 * host has granted what was allowed.
 */

import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import { VoiceRoute } from '../../src/voice/VoiceRoute'

afterEach(() => {
  cleanup()
})

function start(setup?: (controls: FakeHostControls) => void): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  controls.requireVoiceGrant('PERMISSION_DENIED: name the sessions this voice session may reach')
  setup?.(controls)
  render(
    <AppProvider port={port}>
      <VoiceRoute surface="ios" />
    </AppProvider>
  )
  return { controls }
}

describe('allowing voice for the first time', () => {
  // KR-REQ-15.21: the default scope is stated action by action before anything is granted, and the
  // host's own words for why it asks are shown with it.
  it('asks instead of showing a call that cannot start, and states every action', async () => {
    start()
    expect(await screen.findByRole('heading', { name: 'Allow voice on this phone' })).toBeInTheDocument()
    expect(screen.getByTestId('voice-grant-refusal')).toHaveTextContent(
      'name the sessions this voice session may reach'
    )
    const scope = await screen.findByTestId('voice-scope')
    for (const sentence of [
      'Move between the sessions this grant covers.',
      'Read what a session is doing.',
      'Hear a briefing built from the selected context.',
      'Compose a prompt without submitting it.'
    ]) {
      expect(within(scope).getByText(sentence)).toBeInTheDocument()
    }
    expect(screen.queryByRole('button', { name: 'Start voice session' })).toBeNull()
  })

  // KR-REQ-15.21: allowing sends the sessions the person kept and the default scope, and only then
  // does the screen show the call the host describes.
  it('allows the sessions the person kept, and then shows what a call would be', async () => {
    const { controls } = start()
    const sessions = await screen.findAllByRole('checkbox')
    expect(sessions.length).toBeGreaterThan(1)
    expect(sessions.every((box) => (box as HTMLInputElement).checked)).toBe(true)
    await userEvent.click(sessions[0])
    await userEvent.click(screen.getByTestId('voice-allow'))
    await waitFor(() => {
      expect(controls.voiceAllows).toHaveLength(1)
    })
    const asked = controls.voiceAllows[0]
    expect(asked.actions).toBeNull()
    expect(asked.sessionIds).toHaveLength(sessions.length - 1)
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
  })

  it('allows nothing until a session is chosen', async () => {
    const { controls } = start()
    const sessions = await screen.findAllByRole('checkbox')
    for (const box of sessions) await userEvent.click(box)
    expect(screen.getByTestId('voice-allow')).toBeDisabled()
    expect(controls.voiceAllows).toEqual([])
  })

  it('says what the host said when it would not allow it, and stays on the question', async () => {
    const { controls } = start((fake) => {
      fake.failNextVoiceAllow('PERMISSION_DENIED: this phone may not widen its own access')
    })
    await screen.findAllByRole('checkbox')
    await userEvent.click(screen.getByTestId('voice-allow'))
    expect((await screen.findByTestId('voice-grant-failure')).textContent).toContain(
      'may not widen its own access'
    )
    expect(screen.queryByRole('button', { name: 'Start voice session' })).toBeNull()
    expect(controls.voiceAllows).toHaveLength(1)
    await userEvent.click(screen.getByTestId('voice-allow'))
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
  })

  it('shows no question to a device the host already allowed', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port}>
        <VoiceRoute surface="ios" />
      </AppProvider>
    )
    expect(await screen.findByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
    expect(controls.voiceAllows).toEqual([])
    expect(screen.queryByRole('heading', { name: 'Allow voice on this phone' })).toBeNull()
  })
})
