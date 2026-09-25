/**
 * The voice screen against a host.
 *
 * The point of every test here is the same one: the screen shows what an answer said. It is the
 * property the rest of section 15 rests on, because a screen that drew a running call from its own
 * state would tell a person their microphone was live while nothing was listening, and would keep
 * saying so after the service stopped answering.
 */

import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { VoiceRoute } from '../../src/voice/VoiceRoute'

/** The voice calls this screen made, watched from before it was rendered. */
type Watched = Record<
  'voicePrepare' | 'voiceStart' | 'voiceContext' | 'voiceDelegate' | 'voiceSetMuted',
  ReturnType<typeof vi.fn>
>

function start(setup?: (controls: FakeHostControls) => void): {
  controls: FakeHostControls
  port: HostPort
  watched: Watched
} {
  const { port, controls } = fakeHost()
  setup?.(controls)
  // The host's own answers, kept before the screen can reach them, so the count is of what the
  // screen asked for rather than of a wrapper calling itself.
  const answers = {
    voicePrepare: port.voicePrepare.bind(port),
    voiceStart: port.voiceStart.bind(port),
    voiceContext: port.voiceContext.bind(port),
    voiceDelegate: port.voiceDelegate.bind(port),
    voiceSetMuted: port.voiceSetMuted.bind(port)
  }
  const watched = {
    voicePrepare: vi.fn((...args: Parameters<HostPort['voicePrepare']>) =>
      answers.voicePrepare(...args)
    ),
    voiceStart: vi.fn((...args: Parameters<HostPort['voiceStart']>) => answers.voiceStart(...args)),
    voiceContext: vi.fn((...args: Parameters<HostPort['voiceContext']>) =>
      answers.voiceContext(...args)
    ),
    voiceDelegate: vi.fn((...args: Parameters<HostPort['voiceDelegate']>) =>
      answers.voiceDelegate(...args)
    ),
    voiceSetMuted: vi.fn((...args: Parameters<HostPort['voiceSetMuted']>) =>
      answers.voiceSetMuted(...args)
    )
  }
  Object.assign(port, watched)
  render(
    <AppProvider port={port}>
      <VoiceRoute surface="desktop" />
    </AppProvider>
  )
  return { controls, port, watched }
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
    const { port, watched } = start()
    expect(screen.queryByText('gpt-live-1')).not.toBeInTheDocument()
    void port

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

    // Asking created nothing. Reading what a call would be must not start one, reserve anything
    // or send any context, so nothing beyond the preparation has been called.
    expect(watched.voiceStart).not.toHaveBeenCalled()
    expect(watched.voiceContext).not.toHaveBeenCalled()
    expect(watched.voiceDelegate).not.toHaveBeenCalled()
    expect(watched.voiceSetMuted).not.toHaveBeenCalled()
    expect(watched.voicePrepare).toHaveBeenCalledTimes(1)
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

  // Section 15 ¶10: whether the voice service is answering is the call's own report about its
  // control channel. A service that stops answering leaves every local control, and every request
  // to the host, working.
  it('reads the voice service from the call and keeps everything else working', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Show what the host selected' })).toBeEnabled()
    })

    controls.setVoiceBrokerReachable(false)

    // KR-REQ-15.17: the banner comes from the call's next report of its own state.
    await waitFor(() => {
      expect(
        screen.getByText(/The voice service is not answering\. Mute, stopping the voice/)
      ).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Show what the host selected' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Mute microphone' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Stop the voice' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'End session' })).toBeEnabled()

    // Reading what the host selected is a read from the host, shown as its selection and nothing
    // more: nothing was sent to the voice service.
    await person.click(screen.getByRole('button', { name: 'Show what the host selected' }))
    await waitFor(() => {
      expect(screen.getByText('Selected by the host')).toBeInTheDocument()
    })
    expect(screen.queryByText('Sent')).not.toBeInTheDocument()
  })

  // KR-REQ-15.22: a cancellation is a typed request to the host naming the turn the agent is on.
  // No host answer names that turn, so the screen says so rather than holding one of its own, and
  // the host going quiet takes the host requests away and nothing local.
  it('says there is no turn to cancel, and what the host going quiet takes away', async () => {
    const person = userEvent.setup()
    const { controls } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Cancel the current turn' })).toBeDisabled()
    })
    expect(screen.getByText(/has not said which turn the agent is on/)).toBeInTheDocument()

    controls.setConnected(false)

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Show what the host selected' })).toBeDisabled()
    })
    expect(
      screen.getByText(/This device is not reaching the host\. Mute, stopping the voice/)
    ).toBeInTheDocument()
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
    // The request is the protocol's own shape, carrying what the announcement named. The scripted
    // host refuses a field the real one does not read, as the real one does.
    const [params] = delegated.mock.calls[0]
    expect(params).toMatchObject({
      delegation_id: 'item_a1',
      action: 'status',
      offset_ms: '1000',
      turn_id: null
    })
  })

  // Section 15 ¶7: what a delegation asks for is the provider's to name and the host's to check.
  // One that named nothing is shown and never turned into a guess.
  it('does not submit a delegation that named no action', async () => {
    const person = userEvent.setup()
    const { controls, port } = start()
    await waitForChoice()
    await person.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByText('Nothing yet.')).toBeInTheDocument()
    })

    const delegated = vi.spyOn(port, 'voiceDelegate')
    controls.announceVoiceDelegation('item_b2', null)

    await waitFor(() => {
      expect(screen.getByText('Not sent to the host')).toBeInTheDocument()
    })
    expect(screen.getByText(/named no action/)).toBeInTheDocument()
    expect(delegated).not.toHaveBeenCalled()
  })
})

describe('the rate a start accepts', () => {
  // KR-REQ-15.19: the start names the version of the rate on screen, and asks for no longer a call
  // than the service authorises.
  it('names the rate the person was shown', async () => {
    const user = userEvent.setup()
    const { controls } = start()
    await waitForChoice()
    await user.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Voice session' })).toBeInTheDocument()
    })
    expect(controls.voiceStarts).toHaveLength(1)
    expect(controls.voiceStarts[0].expectedRateVersion).toBe('2026-09-a')
    expect(controls.voiceStarts[0].durationSeconds).toBe(1800)
    // The start names the preparation the person was shown, and exactly its sessions.
    expect(controls.voiceStarts[0].prepared).toBe('scope-1')
    expect(controls.voiceStarts[0].sessionIds).toEqual(['8a7b6c50-22bb-4c3d-8e4f-000000000101'])
  })

  // KR-REQ-15.19: the sessions a call would reach are shown by the host's own names.
  it('shows the sessions the preparation answered, by the host’s names', async () => {
    start()
    await waitForChoice()
    const sessions = screen.getByRole('region', { name: 'Sessions this call can reach' })
    expect(within(sessions).getByText(/^Session \d+$/)).toBeInTheDocument()
  })

  // KR-REQ-15.19: a scope that changed between the reading and the start stops the start, and the
  // screen reads what a call would be again before anything can start.
  it('reads the preparation again when the scope changed before the start', async () => {
    const user = userEvent.setup()
    const { controls, watched } = start()
    await waitForChoice()
    controls.changeVoiceScope()

    await user.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByText(/changed after you read it, so nothing was started/)).toBeInTheDocument()
    })
    expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
    expect(watched.voicePrepare).toHaveBeenCalledTimes(2)

    await user.click(screen.getByRole('button', { name: 'Start voice session' }))
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Voice session' })).toBeInTheDocument()
    })
    expect(controls.voiceStarts.map((each) => each.prepared)).toEqual(['scope-1', 'scope-2'])
  })

  // A rate that moved on between the reading and the start: nothing starts, the new rate is shown
  // beside the old one, and only a second press, naming the new version, starts the call.
  it('shows a changed rate and starts only when the person accepts it', async () => {
    const user = userEvent.setup()
    const { controls, watched } = start()
    await waitForChoice()
    controls.changeVoiceRate('2026-10-b', '3')

    await user.click(screen.getByRole('button', { name: 'Start voice session' }))
    const accept = await screen.findByRole('button', { name: 'Start at the new rate' })
    const cost = screen.getByRole('region', { name: 'What it costs' })
    expect(within(cost).getByRole('status')).toHaveTextContent(
      /It is now \S*0\.03 a second, and was \S*0\.01\./
    )
    expect(accept).toHaveAccessibleDescription(/0\.03 a second/)
    expect(screen.queryByRole('heading', { name: 'Voice session' })).not.toBeInTheDocument()
    expect(watched.voiceStart).toHaveBeenCalledTimes(1)

    await user.click(accept)
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Voice session' })).toBeInTheDocument()
    })
    expect(controls.voiceStarts.map((each) => each.expectedRateVersion)).toEqual([
      '2026-09-a',
      '2026-10-b'
    ])
  })

  // KR-REQ-15.19: a host that could not read the service's terms offers no start, and says why.
  it('offers no start when the host could not read the service’s terms', async () => {
    const { watched } = start((controls) => {
      controls.setVoiceTerms('unread')
    })
    await waitFor(() => {
      expect(screen.getByText(/could not read the managed service's terms/)).toBeInTheDocument()
    })
    expect(screen.queryByRole('button', { name: /Start/ })).not.toBeInTheDocument()
    expect(watched.voiceStart).not.toHaveBeenCalled()
  })
})

describe('whether this device is reaching the host', () => {
  /** The screen, against a host the test has prepared. */
  function show(port: HostPort): void {
    render(
      <AppProvider port={port}>
        <VoiceRoute surface="desktop" />
      </AppProvider>
    )
  }

  /** Starts a call from the choice the host answered, and waits for the call screen. */
  async function startCall(): Promise<void> {
    await waitForChoice()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Start voice session' }))
    await screen.findByRole('button', { name: 'End session' })
  }

  /** The one control here that asks the host, so it follows whether the host is reached. */
  const askHost = () => screen.getByRole('button', { name: 'Show what the host selected' })

  const OUT_OF_REACH = /This device is not reaching the host\./

  // KR-REQ-13.02: the connection is read only once its listener is registered, so a host lost
  // while the listener registers is shown as lost rather than as the state read before it.
  it('shows a change made while its listener registers', async () => {
    const { port, controls } = fakeHost()
    const complete = controls.holdRegistrations()
    show(port)
    await startCall()
    expect(askHost()).toBeEnabled()

    act(() => {
      controls.setConnected(false)
    })
    await act(async () => {
      complete()
      await Promise.resolve()
    })

    await waitFor(() => {
      expect(askHost()).toBeDisabled()
    })
    expect(screen.getByText(OUT_OF_REACH)).toBeInTheDocument()
  })

  it('keeps a change it heard over a read that answers after it', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('connectionState')
    show(port)
    await startCall()
    await waitFor(() => {
      expect(held.count).toBe(1)
    })

    act(() => {
      controls.setConnected(false)
    })
    await waitFor(() => {
      expect(askHost()).toBeDisabled()
    })
    // The read was made while the host was reached, and its answer arrives only now.
    await act(async () => {
      held.release()
      await Promise.resolve()
    })
    expect(askHost()).toBeDisabled()
    expect(screen.getByText(OUT_OF_REACH)).toBeInTheDocument()
  })

  it('shows what it read when nothing changed in between', async () => {
    const { port } = fakeHost()
    show({
      ...port,
      connectionState: () =>
        Promise.resolve({
          connected: false,
          environment_id: null,
          reason: 'this host cannot be contacted right now'
        })
    })
    await startCall()

    await waitFor(() => {
      expect(askHost()).toBeDisabled()
    })
    expect(screen.getByText(OUT_OF_REACH)).toBeInTheDocument()
  })
})
