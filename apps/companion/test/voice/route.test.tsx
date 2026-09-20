/**
 * The voice screen against a host.
 *
 * The point of every test here is the same one: the screen shows what an answer said. It is the
 * property the rest of section 15 rests on, because a screen that drew a running call from its own
 * state would tell a person their microphone was live while nothing was listening, and would keep
 * saying so after the service stopped answering.
 */

import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { VoiceRoute } from '../../src/voice/VoiceRoute'

function start(): { controls: FakeHostControls; port: HostPort } {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port}>
      <VoiceRoute surface="desktop" />
    </AppProvider>
  )
  return { controls, port }
}

/** Waits for the choice screen, which only appears once a host has answered the preparation. */
async function waitForChoice(): Promise<void> {
  await waitFor(() => {
    expect(screen.getByRole('button', { name: 'Start voice session' })).toBeInTheDocument()
  })
}

describe('before a call exists', () => {
  // KR-REQ-15.19, KR-REQ-15.09: the provider, the scope and the managed access are read from the
  // host before voice starts. None of them is written into this screen.
  it('shows the provider and the scope the host answered, and nothing before it answers', async () => {
    const { port } = start()
    const prepare = vi.spyOn(port, 'voicePrepare')
    expect(screen.queryByText('gpt-live-1')).not.toBeInTheDocument()

    await waitForChoice()
    expect(screen.getByText('gpt-live-1')).toBeInTheDocument()
    expect(screen.getByText('https://reach.kala.to')).toBeInTheDocument()

    const access = screen.getByRole('region', { name: 'What this gives access to' })
    expect(
      within(access).getByText(/receives transcripts and copies of the audio/)
    ).toBeInTheDocument()

    const scope = screen.getByRole('region', { name: 'What will be sent' })
    expect(within(scope).getByText('the contents of files')).toBeInTheDocument()
    expect(within(scope).getByText(/at most 8,000 tokens/)).toBeInTheDocument()

    // Asking created nothing: the preparation is the only call this screen made.
    expect(prepare).not.toHaveBeenCalled()
  })

  // A host that will not answer the preparation leaves the person with its refusal, not with a
  // start control over an invented scope.
  it('says what the host said when it will not answer, and offers no call', async () => {
    const { controls } = fakeHost()
    controls.setConnected(false)
    render(
      <AppProvider port={fakeUnreachable()}>
        <VoiceRoute surface="desktop" />
      </AppProvider>
    )
    await waitFor(() => {
      expect(screen.getByText('This host cannot be contacted right now.')).toBeInTheDocument()
    })
    expect(screen.queryByRole('button', { name: 'Start voice session' })).not.toBeInTheDocument()
  })
})

/** A host that cannot be contacted at all, which is what an unpaired or sleeping one looks like. */
function fakeUnreachable(): HostPort {
  const { port } = fakeHost()
  const controls = fakeHost()
  void controls
  return {
    ...port,
    voicePrepare: () =>
      Promise.reject({
        code: 'RESOURCE_UNAVAILABLE',
        message: 'This host cannot be contacted right now.',
        user_action: 'retry'
      })
  }
}

describe('starting a call', () => {
  // KR-REQ-15.01: the call the screen draws is the one the host answered with.
  it('draws the session the host answered, with the microphone this device reports', async () => {
    const person = userEvent.setup()
    start()
    await waitForChoice()

    await person.click(screen.getByRole('button', { name: 'Start voice session' }))

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Voice session' })).toBeInTheDocument()
    })
    expect(screen.getByText('Microphone on')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Mute microphone' })).toBeEnabled()
  })

  // An answer that is not a call is shown in the host's own words, and no call screen appears.
  it('shows an unavailable answer and stays on the choice', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    controls.refuseVoiceStart('budget_exhausted')
    await waitForChoice()

    await person.click(screen.getByRole('button', { name: 'Start voice session' }))

    await waitFor(() => {
      expect(screen.getByText('Managed voice cannot be started right now.')).toBeInTheDocument()
    })
    expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
  })
})

describe('while a call is running', () => {
  // KR-REQ-15.17: the mute the screen shows is the one the device reported back.
  it('mutes the microphone only once the device says it is muted', async () => {
    const person = userEvent.setup()
    const { port } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByText('Microphone on')).toBeInTheDocument()
    })

    const muted = vi.spyOn(port, 'voiceSetMuted')
    await person.click(screen.getByRole('button', { name: 'Mute microphone' }))

    expect(muted).toHaveBeenCalledWith('microphone', true)
    await waitFor(() => {
      expect(screen.getByText('Microphone muted')).toBeInTheDocument()
    })
    // KR-REQ-15.36: a muted microphone heard nothing, whoever muted it.
    expect(
      screen.getByText(/Nothing spoken while the microphone was not carrying your voice/)
    ).toBeInTheDocument()
  })

  // KR-REQ-15.22: stopping the voice silences this device and reaches no host.
  it('stops playback without touching the host', async () => {
    const person = userEvent.setup()
    const { port } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Stop the voice' })).toBeInTheDocument()
    })

    const muted = vi.spyOn(port, 'voiceSetMuted')
    const stopped = vi.spyOn(port, 'voiceStop')
    const cancelled = vi.spyOn(port, 'composerInterrupt')
    await person.click(screen.getByRole('button', { name: 'Stop the voice' }))

    expect(muted).toHaveBeenCalledWith('playback', true)
    expect(stopped).not.toHaveBeenCalled()
    expect(cancelled).not.toHaveBeenCalled()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Stop the voice' })).toHaveAttribute(
        'aria-pressed',
        'true'
      )
    })
  })

  // KR-REQ-15.17: transport closure survives a host that cannot be told about it, and the screen
  // says which half happened rather than reporting a revocation it has no answer for.
  it('closes the call locally when the host cannot be told, and says so', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'End session' })).toBeInTheDocument()
    })

    controls.setConnected(false)
    await person.click(screen.getByRole('button', { name: 'End session' }))

    await waitFor(() => {
      expect(screen.getByText(/its grant may still be open/)).toBeInTheDocument()
    })
    expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
  })

  // Section 15 ¶9: a bounded context request goes through the voice service, so a service that has
  // stopped answering takes that control away and leaves every local one working.
  it('takes the context control away when the voice service stops answering', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send what the host selected' })).toBeEnabled()
    })

    controls.setVoiceBrokerReachable(false)
    await person.click(screen.getByRole('button', { name: 'Send what the host selected' }))

    await waitFor(() => {
      expect(screen.getByText('The voice service is not answering.')).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Mute microphone' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'End session' })).toBeEnabled()
  })

  // Section 15 ¶7: a delegation the provider announced is submitted to the host over this device's
  // own connection, and the row says what the host answered rather than what was asked for.
  it('submits an announced delegation to the host and shows what it answered', async () => {
    const person = userEvent.setup()
    const { controls, port } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByText('Nothing yet.')).toBeInTheDocument()
    })

    const delegated = vi.spyOn(port, 'voiceDelegate')
    controls.announceVoiceDelegation('item_a1')

    await waitFor(() => {
      expect(screen.getByText('Sent to the host')).toBeInTheDocument()
    })
    expect(delegated).toHaveBeenCalledTimes(1)
    // KR-REQ-15.17: admission is not execution, and the words beside it say so.
    expect(screen.getByText(/It is not evidence that a host action ran/)).toBeInTheDocument()
  })
})
